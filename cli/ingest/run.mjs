// The ingest loop: discovered transcripts → bounded lines → per-agent parser → replay → rollup.
// Pure apart from reading the transcript files: no network, no writes. The caller owns policy loading,
// output and --report.
import { discover } from "./discover.mjs";
import { boundedLines, ZSTD_SUPPORTED } from "./lines.mjs";
import { ClaudeCodeParser } from "./claude-code.mjs";
import { CodexParser } from "./codex.mjs";
import { createReplayer } from "./replay.mjs";
import { createSummary } from "./summary.mjs";
import { historicalAlert } from "./report.mjs";

export const DEFAULT_BOUNDS = Object.freeze({
  maxFiles: 200,
  maxBytes: 512 * 1024 * 1024,
  maxFileBytes: 64 * 1024 * 1024,
  maxLineBytes: 8 * 1024 * 1024,
  maxSeconds: 120
});

const MAX_LOCAL = 500;    // --show-local rows kept in memory
const MAX_ALERTS = 5000;  // --report alerts kept in memory

// opts: { policy, policyId, policySource, agents, roots, explicit, days, bounds, clock, collectAlerts,
//         config, collectLocal }
export async function runIngest(opts) {
  const bounds = { ...DEFAULT_BOUNDS, ...(opts.bounds || {}) };
  const clock = opts.clock || Date.now;
  const started = clock();
  const deadline = started + bounds.maxSeconds * 1000;
  const sum = createSummary();
  const S = sum.state;
  const replay = createReplayer(opts.policy);
  const alerts = [];
  const local = [];
  let alertsDropped = 0;

  const disc = discover({ agents: opts.agents, roots: opts.roots, explicit: opts.explicit, days: opts.days ?? 30, maxFiles: bounds.maxFiles, now: opts.now ?? Date.now(), deadline, clock });
  S.truncated.files = disc.found > disc.files.length;
  S.truncated.walk = disc.walkTruncated;
  const budget = { bytesLeft: bounds.maxBytes };

  const keep = (ev, event, tool, v) => {
    if (!v.findings.length) return;
    if (opts.collectAlerts) {
      for (const f of v.findings) {
        if (alerts.length >= MAX_ALERTS) { alertsDropped++; continue; }
        alerts.push(historicalAlert(opts.config || {}, { agent: ev.agent, sessionId: ev.sessionId, toolUseId: ev.toolUseId, event, tool, ts: ev.ts, finding: f, wouldDecision: v.decision, policyId: opts.policyId }));
      }
    }
    if (opts.collectLocal && local.length < MAX_LOCAL) local.push({ agent: ev.agent, sessionId: ev.sessionId, ts: ev.ts, event, tool, decision: v.decision, input: ev.input, findings: v.findings });
  };

  const handle = (ev) => {
    if (ev.kind === "prompt") {
      const v = replay.prompt(ev.input);
      if (v.scanned) S.events.promptScanned++;
      sum.add(ev.agent, ev.sessionId, "prompt", v, ev.ts);
      keep(ev, "prompt", "", v);
      return;
    }
    const mask = ev.agent === "claude-code"; // the Codex hook runs through the shim, which cannot rewrite
    const pre = replay.pre(ev.input, { mask, readText: ev.readText });
    if (pre.unsupported) { S.events.unsupported++; sum.session(ev.agent, ev.sessionId); return; }
    sum.add(ev.agent, ev.sessionId, "call", pre, ev.ts);
    keep(ev, "pre", pre.tool, pre);
    // A call enforce mode would have denied never ran, so it has no result to ingest.
    if (pre.decision === "deny" || ev.isError || ev.response === undefined) return;
    const post = replay.post(pre.tool, ev.response, { mask });
    if (!post) return;
    sum.add(ev.agent, ev.sessionId, "post", post, ev.ts);
    keep(ev, "post", pre.tool, post);
  };

  outer: for (const f of disc.files) {
    if (clock() > deadline) { S.truncated.time = true; break; }
    if (budget.bytesLeft <= 0) { S.truncated.bytes = true; break; }
    if (f.path.endsWith(".zst") && !ZSTD_SUPPORTED) { S.skipped.compressedUnsupported++; continue; }
    const parser = f.agent === "codex" ? new CodexParser() : new ClaudeCodeParser();
    S.files[f.agent]++;
    const st = {};
    try {
      for await (const item of boundedLines(f.path, { maxFileBytes: bounds.maxFileBytes, maxLineBytes: bounds.maxLineBytes, budget, state: st })) {
        if (clock() > deadline) { S.truncated.time = true; S.bytesRead += st.bytes || 0; finish(parser); break outer; }
        if (item.oversize) { S.skipped.oversizeLines++; continue; }
        if (item.partial) { S.skipped.partialLines++; continue; }
        if (!item.line.trim()) continue;
        let rec;
        try { rec = JSON.parse(item.line); } catch { S.skipped.malformedLines++; continue; }
        if (!rec || typeof rec !== "object" || Array.isArray(rec)) { S.skipped.malformedLines++; continue; }
        for (const ev of parser.push(rec)) handle(ev);
      }
    } catch { S.skipped.unreadableFiles++; }
    S.bytesRead += st.bytes || 0;
    if (st.cutByFile) S.truncated.filesCut++;
    if (st.cutByBudget) S.truncated.bytes = true;
    finish(parser);
  }

  function finish(parser) {
    for (const ev of parser.end()) handle(ev);
    if (parser.unsupported) S.events.unsupported += parser.unsupported;
    if (parser.malformedArgs) S.skipped.malformedArgs += parser.malformedArgs;
    parser.unsupported = 0; parser.malformedArgs = 0;
    for (const [sid, e] of parser.sessions) {
      const r = sum.session(parser.agent, sid);
      r.hookEvidence ||= e.hookEvidence;
      r.moorai ||= e.moorai;
      r.sessionId = sid;
    }
  }

  const result = sum.result({ policyId: opts.policyId, policySource: opts.policySource, days: opts.days ?? 30, bounds, coverage: !!opts.coverage });
  result.elapsedMs = clock() - started;
  if (opts.collectAlerts) result.alertsDropped = alertsDropped;
  const sessions = [...S.sessions.values()].map((r) => ({ agent: r.agent, sessionId: r.sessionId || "", firstTs: r.firstTs, status: r.moorai ? "moorai-hook" : r.hookEvidence ? "no-moorai-hook" : "unknown" }));
  return { result, alerts, local, sessions };
}
