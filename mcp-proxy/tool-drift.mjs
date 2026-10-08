// "Block until re-approved" for MCP tool drift — policy key `mcpToolDrift: "alert" | "block"`.
//
// tool-baseline.mjs remembers what a server advertised and driftSignals() says what changed. In the
// default "alert" mode that is the whole story, unchanged: the alert is raised and recordTool()
// re-baselines at once, so a rug-pull is reported exactly once and then accepted. This file is the
// "block" half, shared by the stdio proxy and the HTTP gateway:
//
//   * WHAT A TOOL IS COMPARED WITH. An admin's approval in the console pins that server's tool
//     fingerprints (the toolIdentity shape, content-free) and ships them inside the SIGNED policy as
//     `mcpToolBaselines[<server label>] = { version, tools: [{ key, srv, desc, schema }] }`. When a
//     server has one, it is the baseline. When it has none, the device's first-seen baseline
//     (~/.moorai/mcp-tool-baseline.json) is.
//   * WHAT QUARANTINES. Description drift, schema drift, a tool ADDED to a server that already has a
//     baseline, and a tool name owned by another server (shadowing). The tool is taken out of the
//     tools/list the client receives and a tools/call to it is refused. A REMOVED tool only alerts.
//   * THE BASELINE DOES NOT MOVE. Only a tool that passed is recorded; a quarantined one never is, so
//     the next listing is judged against the same BEFORE. Re-approval in the console is the only thing
//     that moves it: the next policy carries the new fingerprints and the tool passes.
//   * A STALE POLICY CANNOT UNBLOCK. Each approved baseline carries a per-server `version` that the
//     console increments on every approval. The device keeps the highest version it has accepted per
//     server (~/.moorai/mcp-tool-approved.json, content-free: the server label is fingerprinted) and
//     ignores an approved baseline older than that, falling back to the local baseline. This is a
//     second layer under the policy envelope's own rollback refusal (policySig.iat against the pin's
//     high-water mark), not a replacement for it: the version file is in the agent's write scope.
//
// Verdicts are kept per tool NAME for the call gate. A call is re-judged against the policy in force
// at call time, so a re-approval releases a quarantined tool without the client listing again. A tool
// listed while the policy was still "alert" is remembered unjudged (observe) and judged on its first
// call after a switch to "block", so the switch does not strand a live session. In block mode a call to
// a tool that was never in a listing MoorAI could check (an over-cap response, a client that never
// listed) is refused: block mode fails closed on what it could not see. That includes a tool an EARLIER
// listing passed: a listing that goes unjudged clears every verdict for that server (invalidate()).
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "../cli/state-dirs.mjs";
import { fileFingerprint } from "../cli/content-hash.mjs";
import { toolIdentity } from "./tool-scan.mjs";
import { loadBaseline, saveBaseline, driftSignals, recordTool } from "./tool-baseline.mjs";

export const TOOL_DRIFT_REASON = "MCP_TOOL_DRIFT";
export const APPROVED_FILE = "mcp-tool-approved.json";
export const MAX_APPROVED_TOOLS = 2048;   // per server baseline in a policy; a larger one is ignored as malformed
const MAX_HWM_ENTRIES = 512;
const FP_RE = /^fp2:[0-9a-f]{16}$/;

export const ADDED_CATEGORY = "MCP: tool added after approval";
export const REMOVED_CATEGORY = "MCP: tool removed after approval";
export const QUARANTINED_CALL_CATEGORY = "MCP: quarantined tool (changed since approval)";
export const UNEVALUATED_CALL_CATEGORY = "MCP: tool not in a checked listing";

// Anything other than the exact string "block" is today's behaviour.
export function toolDriftMode(policy) {
  return policy && policy.mcpToolDrift === "block" ? "block" : "alert";
}

// Before this process has loaded a policy: may the policy it is loading say "block"? Read from the
// device's policy cache and last-known-good copy, UNVERIFIED, and used for one thing only — whether a
// tools/list is worth holding while the verified load finishes. A device whose last policy did not say
// "block" never waits, so the default mode keeps its forward-first timing. Never used to enforce.
const POLICY_COPIES = ["hook-policy.json", "policy-lkg.json"];
export function policyMayBlock(dir = STATE_DIR) {
  for (const f of POLICY_COPIES) {
    try { if (/"mcpToolDrift"\s*:\s*"block"/.test(readFileSync(join(dir, f), "utf8"))) return true; } catch { /* absent */ }
  }
  return false;
}

const hwmPath = (dir) => join(dir, APPROVED_FILE);
function loadHwm(dir) {
  try {
    const j = JSON.parse(readFileSync(hwmPath(dir), "utf8"));
    return j && typeof j.servers === "object" && j.servers ? j.servers : {};
  } catch { return {}; }
}
function saveHwm(servers, dir) {
  try {
    const keys = Object.keys(servers);
    if (keys.length > MAX_HWM_ENTRIES) for (const k of keys.slice(0, keys.length - MAX_HWM_ENTRIES)) delete servers[k];
    mkdirSync(dir, { recursive: true });
    const tmp = hwmPath(dir) + ".tmp";
    writeFileSync(tmp, JSON.stringify({ v: 1, servers }));
    renameSync(tmp, hwmPath(dir));
  } catch { /* the version mark is a second layer; a write failure leaves the envelope's rollback check */ }
}

// One server's approved baseline from the policy, validated. → { version, tools: Map(key → entry) } | null.
function parseApproved(raw) {
  if (!raw || typeof raw !== "object" || !Array.isArray(raw.tools)) return null;
  const version = raw.version;
  if (!Number.isInteger(version) || version < 1) return null; // a number, never a numeric string
  if (raw.tools.length > MAX_APPROVED_TOOLS) return null;
  const tools = new Map();
  for (const t of raw.tools) {
    if (!t || !FP_RE.test(t.key) || !FP_RE.test(t.desc) || !FP_RE.test(t.schema)) return null;
    tools.set(t.key, { desc: t.desc, schema: t.schema });
  }
  return { version, tools };
}

// Every approved baseline in the policy that is not older than the version this device already
// accepted for that server. Accepting one raises the mark. → Map(server label → { version, tools }).
export function approvedBaselines(policy, dir = STATE_DIR) {
  const out = new Map();
  const src = policy && policy.mcpToolBaselines;
  if (!src || typeof src !== "object" || Array.isArray(src)) return out;
  const hwm = loadHwm(dir);
  let dirty = false;
  for (const [label, raw] of Object.entries(src)) {
    const ap = parseApproved(raw);
    if (!ap) continue;
    const k = fileFingerprint("mcp-server:" + label);
    const seen = Number(hwm[k]) || 0;
    if (ap.version < seen) continue; // stale: an older approval cannot override a newer one
    if (ap.version > seen) { hwm[k] = ap.version; dirty = true; }
    out.set(label, ap);
  }
  if (dirty) saveHwm(hwm, dir);
  return out;
}

const DRIFT = {
  shadow: { category: "MCP: tool name shadowed by a second server", riskLevel: "High" },
  schema: { category: "MCP: tool schema changed after approval (capability expansion)", riskLevel: "High" },
  desc: { category: "MCP: tool description changed after approval (possible rug-pull)" }
};

// The block-mode verdict for one tool. Pure. → [] when the tool passes, else its signals (same
// categories and tokens as driftSignals, plus "added").
export function judgeTool(cur, { server, approved, local, serverHasLocal }) {
  const own = approved.get(server);
  const shadowOwner = () => {
    const prev = local[cur.key];
    if (prev && prev.srv !== cur.srv) return true;
    for (const [label, ap] of approved) if (label !== server && ap.tools.has(cur.key)) return true;
    return false;
  };
  const shadow = () => [{ kind: "shadow", ...DRIFT.shadow, token: `mcp:tool:shadow:${cur.key}` }];
  const added = () => [{ kind: "added", category: ADDED_CATEGORY, riskLevel: "High", token: `mcp:tool:added:${cur.key}` }];
  if (own) {
    const e = own.tools.get(cur.key);
    if (!e) return shadowOwner() ? shadow() : added();
    return driftSignals({ srv: cur.srv, desc: e.desc, schema: e.schema }, cur);
  }
  const prev = local[cur.key];
  if (prev) return driftSignals(prev, cur);
  for (const [label, ap] of approved) if (label !== server && ap.tools.has(cur.key)) return shadow();
  return serverHasLocal ? added() : [];
}

// One tracker per guarded server (one per proxy process, one per gateway route).
export function createDriftTracker({ server, dir = STATE_DIR }) {
  const srv = fileFingerprint("mcp-server:" + String(server || ""));
  const verdicts = new Map(); // tool name → { cur, signals }
  const MAX_VERDICTS = 4096;
  const remember = (name, v) => {
    if (verdicts.size >= MAX_VERDICTS && !verdicts.has(name)) verdicts.delete(verdicts.keys().next().value);
    verdicts.set(name, v);
  };

  // A paged first sighting: the server had no baseline when page 1 of this listing arrived, so every
  // later page of the same listing is a first sighting too, not "added after" page 1. It ends with the
  // listing's last page (no nextCursor) or the next listing that starts again from page 1.
  let pagedFirstSighting = false;

  // A block-mode tools/list. `complete` = this listing is the server's whole list (not a page), the
  // only case where an absent tool means a removed one and the fingerprints are worth reporting.
  // `continued` = the request carried a cursor (a later page); `last` = the response has no nextCursor.
  // → { keep, quarantined: [{ name, signals }], removed: [signal], fingerprints | null, changed }.
  function evaluateListing(tools, { policy, complete, continued = false, last = true }) {
    const approved = approvedBaselines(policy, dir);
    const local = loadBaseline(dir);
    let counter = 0;
    let serverHasLocal = false;
    for (const t of Object.values(local)) {
      if ((t.n || 0) > counter) counter = t.n || 0;
      if (t.srv === srv) serverHasLocal = true;
    }
    if (!continued) pagedFirstSighting = !serverHasLocal && !last;
    else if (pagedFirstSighting) serverHasLocal = false;
    if (last) pagedFirstSighting = false;
    const ctx = { server, approved, local, serverHasLocal };
    const keep = [], quarantined = [], seen = new Set(), fingerprints = [];
    for (const tool of tools) {
      const name = String(tool.name);
      const cur = toolIdentity(tool, server);
      seen.add(cur.key);
      fingerprints.push(cur);
      const signals = judgeTool(cur, ctx);
      remember(name, { cur, signals });
      if (signals.length) { quarantined.push({ name, signals }); continue; }
      keep.push(tool);
      recordTool(local, cur, ++counter);
    }
    const removed = [];
    if (complete) {
      const own = approved.get(server);
      const known = own ? [...own.tools.keys()] : Object.keys(local).filter((k) => local[k].srv === srv);
      for (const k of known) if (!seen.has(k)) removed.push({ kind: "removed", category: REMOVED_CATEGORY, riskLevel: "Medium", token: `mcp:tool:removed:${k}` });
    }
    if (keep.length) saveBaseline(local, dir);
    return { keep, quarantined, removed, fingerprints: complete ? fingerprints : null, changed: quarantined.length > 0 };
  }

  // A block-mode tools/call. → null (forward) or { category, reason, signals }.
  function checkCall(name, { policy }) {
    const v = verdicts.get(name);
    if (!v) return { category: UNEVALUATED_CALL_CATEGORY, reason: "this tool was not in a tool listing MoorAI could check against your organization's approved MCP tools", signals: [] };
    if (v.signals && !v.signals.length) return null;
    // Re-judged against the policy in force NOW, so a console re-approval releases the tool without a
    // fresh tools/list. Released tools are recorded, which is the re-approval moving the local baseline.
    const approved = approvedBaselines(policy, dir);
    const local = loadBaseline(dir);
    let serverHasLocal = false, counter = 0;
    for (const t of Object.values(local)) { if ((t.n || 0) > counter) counter = t.n || 0; if (t.srv === srv) serverHasLocal = true; }
    const signals = judgeTool(v.cur, { server, approved, local, serverHasLocal });
    if (!signals.length) {
      verdicts.set(name, { cur: v.cur, signals });
      recordTool(local, v.cur, ++counter);
      saveBaseline(local, dir);
      return null;
    }
    return { category: QUARANTINED_CALL_CATEGORY, reason: `this tool changed since your organization approved this MCP server (${TOOL_DRIFT_REASON}: ${signals.map((s) => s.kind).join(", ")}); it stays quarantined until an admin re-approves it in the MoorAI console`, signals };
  }

  // An alert-mode listing: remember the identity, unjudged (signals: null), for a later switch to block.
  function observe(name, cur) { remember(String(name), { cur, signals: null }); }

  // A tools/list this server sent that could not be judged (over the line cap, unparseable, a judgement
  // that threw). What it advertised is unknown, so no earlier verdict may vouch for any tool: every call
  // is refused as not in a checked listing until a listing is judged again.
  function invalidate() { verdicts.clear(); }

  return { evaluateListing, checkCall, observe, invalidate, has: (name) => verdicts.has(name) };
}

// The content-free fingerprints of a complete listing, posted so the console can pin them on approval
// and show "tools changed since approval". Deduped per process on the set's digest; fire-and-forget.
// `actor` is the reporting device's content-free actor hash (the one every alert carries): the install
// token is per tenant, so it is how the console tells one device's report from another's.
const REPORTED = new Set();
export function reportFingerprints({ config, server, fingerprints, enrolled, actor }) {
  if (!enrolled || !fingerprints || !config || !config.serverUrl) return;
  try {
    const tools = fingerprints.map((f) => ({ key: f.key, srv: f.srv, desc: f.desc, schema: f.schema })).sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    const digest = fileFingerprint(server + "|" + JSON.stringify(tools));
    if (REPORTED.has(digest)) return;
    if (REPORTED.size > 1024) REPORTED.clear();
    REPORTED.add(digest);
    fetch(`${config.serverUrl}/api/mcp/tools`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(config.installToken ? { "X-Install-Token": config.installToken } : {}) },
      body: JSON.stringify({ server, tools, ...(actor ? { actor } : {}) }),
      signal: AbortSignal.timeout(1500)
    }).catch(() => {});
  } catch { /* evidence for the console, never enforcement */ }
}
