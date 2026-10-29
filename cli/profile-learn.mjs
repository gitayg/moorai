// "Watch, then enforce": a DRAFT declared workload profile (cli/workload-profile.mjs) learned from what the
// device already recorded, plus the diff against the profile in force. The draft always carries action
// "report"; an operator adopts it into the signed console policy (or the root-owned machine-wide config),
// watches PROFILE_DRIFT, then flips the one field to "block". Nothing here enforces or sends anything.
//
// SOURCES, one per drift kind, each the record the checker's own subject is derived from:
//   tools       the session ledger (cli/session-ledger.mjs), one `ev: "pre"` row per PreToolUse call, `tool`
//   mcpServers  the same rows: serverOf(tool) for an mcp__<server>__<tool> name, as profileSubject derives it
//   hosts       the destination map (cli/signals.mjs destinations.jsonl), rows of kind "host"
// Names and hosts only: neither record holds a path, argument, command or response, so the draft cannot.
//
// SCOPE. A session-ledger row carries `svc` (server mode's serviceId) and `repo` (the normalised remote, on
// a row whose call a repo-keyed profile already resolved it for; cli/workload-profile.mjs resolvedRepo).
// --service-id / --repo keep the rows whose fields equal the match and drop rows that name another
// workload; a row without the field (written before the hook stamped it, or never resolved) is used as a
// device-wide fallback and counted in `observation.scope`. Destination rows carry the hook's identity, and
// in server mode the device is `svc:<serviceId>` (cli/server-mode.mjs serviceWho), so --service-id narrows
// the hosts; no destination row carries the repository, so a repo-only match learns hosts device-wide.
//
// EXCLUDED. An observation the hook denied, or coached on an unenrolled device, is not learned: it never
// ran as an allowed call, and a draft must not sanction what MoorAI already stopped as a threat. An item
// seen only that way is listed in `excluded` instead.
//
// A kind with nothing observed is OMITTED from the draft (unconstrained), never written as [] (which would
// allow nothing and, once flipped to block, deny every call of that kind).
//
// Pure: rows and the declared profiles in, result out. Every list is sorted, so two runs over the same
// records produce the same bytes.
import { validateProfile, profilesFrom, matchProfile, driftOf, normalizeRepo } from "./workload-profile.mjs";
import { serverOf } from "../data/agent-behavior.js";

export const DEFAULT_DAYS = 14;
export const DEFAULT_MIN_SESSIONS = 5;
export const DEFAULT_MIN_DAYS = 3;
export const COACH_REASON = "COACH_UNENROLLED";
const KINDS = [["tools", "tool"], ["mcpServers", "mcpServer"], ["hosts", "host"]];
const TOOL_RE = /^[A-Za-z0-9_.:-]{1,256}$/; // the checker's TOOL_RE without `*`: an observed name is never a glob
const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const MAX_ENTRIES = 512;
const DAY_MS = 86400000;

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const excludedDecision = (decision, reasonCode) => decision === "deny" || decision === "coach" || reasonCode === COACH_REASON;

// A profile id from the match: `learned-<serviceId or repo>`, folded to the checker's slug.
export function draftId(match) {
  const base = String(match.serviceId || match.repo || "workload").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[^A-Za-z0-9]+/, "");
  return `learned-${base}`.slice(0, 64).replace(/[^A-Za-z0-9]+$/, "");
}

function bump(map, name, row, excluded) {
  let s = map.get(name);
  if (!s) { s = { name, count: 0, denied: 0, firstSeen: row.ts, lastSeen: row.ts }; map.set(name, s); }
  if (excluded) s.denied++; else s.count++;
  if (row.ts < s.firstSeen) s.firstSeen = row.ts;
  if (row.ts > s.lastSeen) s.lastSeen = row.ts;
}

// learnProfile({ destinations, sessionRows, serviceId?, repo?, id?, days?, until?, minSessions?, minDays?, declared? })
//   destinations  destination-map rows ({ ts, tool, kind, name, decision, device })
//   sessionRows   session-ledger rows ({ ts, s, ev, tool, decision, reasonCode })
//   serviceId / repo  the draft's match (at least one)
//   until         window end (ms or ISO; default now); the window is (until - days, until]
//   declared      { policy, system } — the documents the profiles in force come from, for the diff
// → { ok, profile, thin, observation, items, excluded, skipped, diff, warnings } or { ok: false, error }.
export function learnProfile({ destinations = [], sessionRows = [], serviceId, repo, id, days = DEFAULT_DAYS, until = Date.now(), minSessions = DEFAULT_MIN_SESSIONS, minDays = DEFAULT_MIN_DAYS, declared = {}, compareId } = {}) {
  const match = {};
  if (serviceId !== undefined) {
    if (typeof serviceId !== "string" || !serviceId.trim()) return { ok: false, error: "--service-id is empty" };
    match.serviceId = serviceId.trim();
  }
  if (repo !== undefined) {
    const r = normalizeRepo(repo);
    if (!r) return { ok: false, error: "--repo is not a remote (github:owner/name, gitlab:group/name or host:path)" };
    match.repo = r;
  }
  if (!Object.keys(match).length) return { ok: false, error: "a profile needs a match: give --service-id and/or --repo" };
  if (!(Number.isFinite(days) && days > 0)) return { ok: false, error: "--days must be a positive number" };
  const end = typeof until === "number" ? until : Date.parse(until);
  if (!Number.isFinite(end)) return { ok: false, error: "--until is not a date" };
  const start = end - days * DAY_MS;
  const inWindow = (r) => { if (!r || typeof r.ts !== "string") return false; const t = Date.parse(r.ts); return t > start && t <= end; };

  const stats = { tool: new Map(), mcpServer: new Map(), host: new Map() };
  const skipped = { tools: 0, mcpServers: 0, hosts: 0 };
  const sessions = new Set(), dayset = new Set();
  const scope = { sessionRows: { matched: 0, deviceWide: 0 }, hostRows: { matched: 0, deviceWide: 0 } };
  let calls = 0, hostRows = 0;
  for (const r of sessionRows) {
    if (!inWindow(r) || r.ev !== "pre" || typeof r.tool !== "string" || !r.tool) continue;
    const keys = [["serviceId", r.svc], ["repo", r.repo]].filter(([k]) => match[k] !== undefined);
    if (keys.some(([k, v]) => v !== undefined && v !== match[k])) continue; // another workload's row
    if (keys.every(([, v]) => v !== undefined)) scope.sessionRows.matched++; else scope.sessionRows.deviceWide++;
    calls++;
    if (r.s) sessions.add(r.s);
    dayset.add(r.ts.slice(0, 10));
    const ex = excludedDecision(r.decision, r.reasonCode);
    if (TOOL_RE.test(r.tool)) bump(stats.tool, r.tool, r, ex); else skipped.tools++;
    if (r.tool.startsWith("mcp__")) {
      const s = serverOf(r.tool);
      if (TOOL_RE.test(s)) bump(stats.mcpServer, s, r, ex); else skipped.mcpServers++;
    }
  }
  const svcDevice = match.serviceId !== undefined ? `svc:${match.serviceId}` : null;
  for (const r of destinations) {
    if (!inWindow(r) || r.kind !== "host" || typeof r.name !== "string") continue;
    if (svcDevice && r.device !== svcDevice) continue;
    const h = r.name.toLowerCase().replace(/\.$/, "");
    if (LOOPBACK.has(h)) continue; // always in profile
    hostRows++;
    if (svcDevice) scope.hostRows.matched++; else scope.hostRows.deviceWide++;
    dayset.add(r.ts.slice(0, 10));
    if (HOST_RE.test(h)) bump(stats.host, h, r, excludedDecision(r.decision, r.reasonCode)); else skipped.hosts++;
  }

  const items = {}, excluded = [];
  for (const [key, kind] of KINDS) {
    const all = [...stats[kind].values()].sort((a, b) => cmp(a.name, b.name));
    items[key] = all.filter((s) => s.count > 0);
    for (const s of all) if (!s.count) excluded.push({ kind, name: s.name, denied: s.denied, lastSeen: s.lastSeen });
    if (items[key].length > MAX_ENTRIES) return { ok: false, error: `${key}: ${items[key].length} distinct names observed, more than the ${MAX_ENTRIES} a profile list holds` };
  }

  const tsAll = [...items.tools, ...items.hosts].flatMap((s) => [s.firstSeen, s.lastSeen]).sort();
  const observation = {
    window: { days, from: new Date(start).toISOString(), until: new Date(end).toISOString() },
    sessions: sessions.size, days: dayset.size, calls, hostObservations: hostRows, scope,
    firstSeen: tsAll[0] || null, lastSeen: tsAll[tsAll.length - 1] || null,
    minSessions, minDays
  };
  const thin = sessions.size < minSessions || dayset.size < minDays;

  const profile = { id: id || draftId(match) };
  profile.description = `Learned by moorai-profile from ${sessions.size} session(s) on ${dayset.size} day(s), ${observation.window.from.slice(0, 10)} to ${observation.window.until.slice(0, 10)}`;
  profile.match = match;
  profile.action = "report";
  for (const [key] of KINDS) if (items[key].length) profile[key] = items[key].map((s) => s.name);
  // The draft is only useful if the checker takes it as written; anything else is a bug here, not input.
  const v = validateProfile(profile);
  if (v.error) return { ok: false, error: `draft failed the workload-profile validator: ${v.error}` };

  const warnings = [];
  if (scope.sessionRows.deviceWide) warnings.push({ code: "tools-unscoped", text: `${scope.sessionRows.deviceWide} of ${calls} tool call(s) are from rows that name no workload (written before the hook stamped svc/repo, or no repo resolved): learned device-wide` });
  if (scope.hostRows.deviceWide) warnings.push({ code: "hosts-unscoped", text: "destination records name no repository: hosts are learned from every session on this device" });
  // The window reaches further back than the records do (retention cap, or a recent install).
  for (const [label, rows] of [["session ledger", sessionRows], ["destination map", destinations]]) {
    const oldest = rows.reduce((m, r) => (r && typeof r.ts === "string" && Number.isFinite(Date.parse(r.ts)) && (!m || r.ts < m) ? r.ts : m), "");
    if (oldest && Date.parse(oldest) > start) warnings.push({ code: "window-truncated", text: `the ${label}'s oldest retained row is from ${oldest}, after the window start ${observation.window.from}: it covers less than ${days} day(s)` });
  }
  if (thin) warnings.push({ code: "thin-data", text: `observed ${sessions.size} session(s) on ${dayset.size} day(s); at least ${minSessions} session(s) on ${minDays} day(s) are required` });
  for (const [key] of KINDS) if (!items[key].length) warnings.push({ code: `no-${key}`, text: `no ${key} observed in the window: the draft leaves ${key} unconstrained` });
  if (Object.values(skipped).some(Boolean)) warnings.push({ code: "skipped-names", text: "some observed names are not valid profile entries and were left out (counts in skipped)" });

  const diff = diffProfile(profile, items, declared, { serviceId: match.serviceId, repo: match.repo, compareId });
  if (diff.against && diff.against.id === profile.id) warnings.push({ code: "same-id", text: `the profile in force already has id "${profile.id}": adopting the draft replaces it` });
  return { ok: true, profile, thin, observation, items, excluded, skipped, diff, warnings };
}

// The draft against the profile in force for the same match (first match wins, as enforcement picks it),
// or against --compare <id>. Per kind: added (learned, not covered by any declared entry), removed
// (declared entries no learned item matched) and kept (learned and covered), judged by the checker's own
// driftOf so a glob covers here exactly as it does at enforcement.
export function diffProfile(draft, items, declared = {}, { serviceId, repo, compareId } = {}) {
  let profiles = [], rejected = [];
  try { ({ profiles, rejected } = profilesFrom({ policy: declared.policy || null, system: declared.system || null })); } catch { /* none */ }
  const current = compareId ? profiles.find((p) => p.id === compareId) || null : matchProfile(profiles, { serviceId: serviceId || "", repo: () => repo || "" });
  const out = { against: current ? { id: current.id, source: current.source, action: current.action } : null, rejected: rejected.length };
  if (compareId && !current) out.missing = compareId;
  let added = 0;
  for (const [key, kind] of KINDS) {
    const learned = items[key];
    const subject = (name) => ({ tool: kind === "tool" ? name : "", mcpServer: kind === "mcpServer" ? name : "", hosts: kind === "host" ? [name] : [] });
    if (!current) { out[key] = { declared: "none", added: learned.map(stat), removed: [], kept: [] }; added += learned.length; continue; }
    const a = current.allow[kind];
    if (!a) { out[key] = { declared: "unconstrained", added: [], removed: [], kept: learned.map(stat) }; continue; }
    const covered = (s) => !driftOf(current, subject(s.name)).length;
    const one = (i) => ({ id: current.id, allow: { [kind]: { entries: [a.entries[i]], res: [a.res[i]] } } });
    const removed = a.entries.filter((e, i) => !learned.some((s) => !driftOf(one(i), subject(s.name)).length)).sort(cmp);
    const add = learned.filter((s) => !covered(s)).map(stat);
    added += add.length;
    out[key] = { declared: "list", added: add, removed, kept: learned.filter(covered).map(stat) };
  }
  if (current && current.egress) out.carryOver = ["egressRules", "egressDefault"].filter((k) => k === "egressRules" ? current.egress.rules.length : current.egress.default !== undefined);
  // Nothing observed outside the profile in force: the window gives no reason not to flip it to block.
  out.readyToBlock = !!current && added === 0;
  return out;
}
const stat = (s) => ({ name: s.name, count: s.count, lastSeen: s.lastSeen });

// The human-readable report: what was observed, the diff, the warnings and the draft itself.
export function formatLearn(r) {
  const o = r.observation, d = r.diff;
  const lines = [];
  lines.push(`MoorAI workload profile — learned draft "${r.profile.id}" (action: report)`);
  lines.push(`Window ${o.window.from} → ${o.window.until} (${o.window.days} day(s)): ${o.sessions} session(s) on ${o.days} day(s), ${o.calls} tool call(s), ${o.hostObservations} host observation(s)`);
  lines.push(`Rows matched to this workload: ${o.scope.sessionRows.matched} tool call(s), ${o.scope.hostRows.matched} host observation(s); device-wide (no workload field): ${o.scope.sessionRows.deviceWide} and ${o.scope.hostRows.deviceWide}`);
  lines.push(d.against ? `Compared with the profile in force: "${d.against.id}" (${d.against.source}, action ${d.against.action})` : d.missing ? `No profile with id "${d.missing}" is in force: every learned item is new` : "No profile in force matches this workload: every learned item is new");
  for (const [key] of KINDS) {
    const k = d[key];
    lines.push("", `  ${key}${k.declared === "unconstrained" ? " (the profile in force leaves them unconstrained)" : ""}:`);
    const row = (sign, s) => `    ${sign} ${s.name}  ${s.count} call(s), last ${s.lastSeen}`;
    for (const s of k.added) lines.push(row("+", s));
    for (const e of k.removed) lines.push(`    - ${e}  (declared, not observed)`);
    for (const s of k.kept) lines.push(row(" ", s));
    if (!k.added.length && !k.removed.length && !k.kept.length) lines.push("    (none observed)");
  }
  if (r.excluded.length) {
    lines.push("", "  Excluded (only ever denied or coached, so not learned):");
    for (const e of r.excluded) lines.push(`    ${e.kind} ${e.name}  ${e.denied} denied, last ${e.lastSeen}`);
  }
  if (d.carryOver && d.carryOver.length) lines.push("", `  The profile in force also carries ${d.carryOver.join(" and ")}: copy them into the draft before adopting it.`);
  if (d.against) lines.push("", d.readyToBlock ? `  Nothing observed outside "${d.against.id}" in the window: it can be flipped to "action": "block".` : `  Items outside "${d.against.id}" were observed: review them before flipping to "action": "block".`);
  if (r.warnings.length) { lines.push("", "Warnings:"); for (const w of r.warnings) lines.push(`  [${w.code}] ${w.text}`); }
  lines.push("", "Draft profile (an entry for the policy's workloadProfiles list):", JSON.stringify(r.profile, null, 2), "");
  return lines.join("\n");
}
