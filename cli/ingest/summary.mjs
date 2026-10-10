// The content-free rollup of an ingest run, and its two renderings. Everything here is a count, a
// threat id, a catalogue name (data/threats.json, MoorAI's own text) or a fixed label. No prompt,
// command, path, URL, matched span or session id reaches it: add() takes only the agent, a session
// key it never prints, the event kind and the verdict's decision + (threatId, category) pairs.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const THREAT_NAMES = (() => {
  try {
    const { threats } = JSON.parse(readFileSync(fileURLToPath(new URL("../../data/threats.json", import.meta.url)), "utf8"));
    return new Map(threats.map((t) => [t.id, t.threat]));
  } catch { return new Map(); }
})();
export const threatName = (id, category) => (id > 0 ? THREAT_NAMES.get(id) || category || `threat ${id}` : category || "—");

const DECISIONS = ["deny", "ask", "mask", "allow"];
const blank = () => ({ deny: 0, ask: 0, mask: 0, allow: 0 });

export function createSummary() {
  const s = {
    files: { "claude-code": 0, codex: 0 },
    events: { call: 0, post: 0, prompt: 0, promptScanned: 0, unsupported: 0 },
    decisions: blank(),
    flaggedAllow: 0,
    findings: 0,
    byAgent: {},
    byThreat: new Map(),
    sessions: new Map(),
    skipped: { malformedLines: 0, oversizeLines: 0, partialLines: 0, malformedArgs: 0, unreadableFiles: 0, compressedUnsupported: 0 },
    truncated: { files: false, bytes: false, time: false, walk: false, filesCut: 0 },
    bytesRead: 0
  };
  const agentRow = (a) => (s.byAgent[a] ||= { sessions: 0, events: 0, findings: 0, ...blank() });
  const session = (agent, key) => {
    const k = `${agent}\u0000${key}`;
    let r = s.sessions.get(k);
    if (!r) { r = { agent, findings: 0, worst: "allow", hookEvidence: false, moorai: false, firstTs: "" }; s.sessions.set(k, r); agentRow(agent).sessions++; }
    return r;
  };
  const RANK = { allow: 0, mask: 1, ask: 2, deny: 3 };

  return {
    state: s,
    session,
    // kind: "call" | "post" | "prompt"; verdict: { decision, findings:[{ threatId, category }] }
    add(agent, sessionKey, kind, verdict, ts = "") {
      const row = agentRow(agent);
      const sess = session(agent, sessionKey);
      if (ts && (!sess.firstTs || ts < sess.firstTs)) sess.firstTs = ts;
      s.events[kind]++;
      row.events++;
      const d = DECISIONS.includes(verdict.decision) ? verdict.decision : "allow";
      s.decisions[d]++;
      row[d]++;
      const n = verdict.findings.length;
      if (d === "allow" && n) s.flaggedAllow++;
      s.findings += n;
      row.findings += n;
      sess.findings += n;
      if (RANK[d] > RANK[sess.worst]) sess.worst = d;
      const seen = new Set();
      for (const f of verdict.findings) {
        const key = `${f.threatId}|${f.threatId > 0 ? "" : f.category}`;
        let t = s.byThreat.get(key);
        if (!t) { t = { threatId: f.threatId, name: threatName(f.threatId, f.category), group: f.threatId > 0 ? f.category : "", findings: 0, events: 0, ...blank() }; s.byThreat.set(key, t); }
        t.findings++;
        if (!seen.has(key)) { seen.add(key); t.events++; t[d]++; }
      }
    },
    result({ policyId, policySource, days, bounds, coverage = false }) {
      const sessions = [...s.sessions.values()];
      const byThreat = [...s.byThreat.values()].sort((a, b) => b.findings - a.findings || a.threatId - b.threatId);
      const groups = new Map();
      for (const t of byThreat) if (t.group) groups.set(t.group, (groups.get(t.group) || 0) + t.findings);
      const cov = { covered: 0, uncovered: 0, unknown: 0 };
      for (const r of sessions) cov[r.moorai ? "covered" : r.hookEvidence ? "uncovered" : "unknown"]++;
      return {
        policy: { id: policyId, source: policySource },
        days, bounds,
        files: s.files,
        bytesRead: s.bytesRead,
        sessions: { total: sessions.length, withFindings: sessions.filter((r) => r.findings).length, wouldBlock: sessions.filter((r) => r.worst === "deny").length, wouldAsk: sessions.filter((r) => r.worst === "ask").length },
        events: s.events,
        decisions: s.decisions,
        flaggedAllow: s.flaggedAllow,
        findings: s.findings,
        byAgent: s.byAgent,
        byThreat,
        topThreats: byThreat.slice(0, 10).map((t) => ({ threatId: t.threatId, name: t.name, findings: t.findings })),
        topGroups: [...groups].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([group, findings]) => ({ group, findings })),
        coverage: cov,
        ...(coverage ? { uncoveredSessions: sessions.filter((r) => !r.moorai && r.hookEvidence).length } : {}),
        skipped: s.skipped,
        truncated: s.truncated
      };
    }
  };
}

const C = process.stdout.isTTY && !process.env.NO_COLOR
  ? { r: "\x1b[31m", y: "\x1b[33m", g: "\x1b[32m", c: "\x1b[36m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" }
  : { r: "", y: "", g: "", c: "", dim: "", b: "", off: "" };

export function toText(r) {
  const L = [];
  const files = r.files["claude-code"] + r.files.codex;
  L.push("", `${C.b}MoorAI transcript ingest — what enforce mode would have done in your past agent sessions${C.off}`);
  L.push(`${C.dim}policy: ${r.policy.id} (${r.policy.source}) · window: last ${r.days} day(s) · ${files} transcript file(s): ${r.files["claude-code"]} Claude Code, ${r.files.codex} Codex · ${(r.bytesRead / 1048576).toFixed(1)} MiB read${C.off}`, "");
  L.push(`  sessions        ${r.sessions.total} total · ${r.sessions.withFindings} with findings · ${C.r}${r.sessions.wouldBlock} would have had a call blocked${C.off} · ${C.y}${r.sessions.wouldAsk} would have needed sign-off${C.off}`);
  L.push(`  events          ${r.events.call} tool calls · ${r.events.post} tool results · ${r.events.prompt} prompts (${r.events.promptScanned} scanned under this policy) · ${r.events.unsupported} calls to tools the hook does not judge`);
  L.push(`  decisions       ${C.r}${r.decisions.deny} block${C.off} · ${C.y}${r.decisions.ask} ask${C.off} · ${C.c}${r.decisions.mask} mask${C.off} · ${r.decisions.allow} allow (${r.flaggedAllow} of them reported a finding) · ${r.findings} findings`);
  for (const [a, x] of Object.entries(r.byAgent)) L.push(`  ${a.padEnd(15)} ${x.sessions} sessions · ${x.events} events · ${x.findings} findings · ${x.deny} block · ${x.ask} ask · ${x.mask} mask`);
  if (r.byThreat.length) {
    L.push("", `  ${C.dim}${"threat".padEnd(8)}${"name".padEnd(52)}${"findings".padStart(9)}${"block".padStart(7)}${"ask".padStart(6)}${"mask".padStart(6)}${C.off}`);
    for (const t of r.byThreat.slice(0, 25)) L.push(`  ${(t.threatId ? "#" + t.threatId : "—").padEnd(8)}${t.name.slice(0, 50).padEnd(52)}${String(t.findings).padStart(9)}${String(t.deny).padStart(7)}${String(t.ask).padStart(6)}${String(t.mask).padStart(6)}`);
    if (r.byThreat.length > 25) L.push(`  ${C.dim}… ${r.byThreat.length - 25} more (--json for all)${C.off}`);
    if (r.topGroups.length) L.push("", `  most-flagged categories: ${r.topGroups.map((g) => `${g.group} (${g.findings})`).join(" · ")}`);
  } else L.push("", `  ${C.g}Nothing in these sessions would have been flagged under this policy.${C.off}`);
  L.push("", `  hook coverage   ${r.coverage.covered} session(s) ran with the MoorAI hook · ${r.coverage.uncovered} ran other hooks but not MoorAI · ${r.coverage.unknown} cannot be told from the transcript`);
  const sk = r.skipped;
  L.push(`  ${C.dim}skipped: ${sk.malformedLines} malformed line(s), ${sk.oversizeLines} over-long line(s), ${sk.partialLines} cut by a byte bound, ${sk.malformedArgs} call(s) with unparseable arguments, ${sk.unreadableFiles} unreadable file(s), ${sk.compressedUnsupported} compressed file(s) this Node cannot read${C.off}`);
  const t = r.truncated;
  const cut = [t.files && `file limit (${r.bounds.maxFiles})`, t.bytes && `byte budget (${r.bounds.maxBytes} B)`, t.time && `time limit (${r.bounds.maxSeconds}s)`, t.walk && "directory walk limit", t.filesCut && `${t.filesCut} file(s) longer than ${r.bounds.maxFileBytes} B read in part`].filter(Boolean);
  if (cut.length) L.push(`  ${C.y}bounded: stopped at ${cut.join(", ")} — raise the limit to see more${C.off}`);
  L.push(`  ${C.dim}Content-free: counts and threat names only. Replayed on this machine; nothing was sent anywhere unless --report was given.${C.off}`, "");
  return L.join("\n");
}
