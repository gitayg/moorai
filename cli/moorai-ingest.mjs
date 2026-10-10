#!/usr/bin/env node
// moorai-ingest — replay your past agent sessions (Claude Code and Codex transcripts on this machine)
// through the live hook's decision functions, so a new install shows on day one what MoorAI would have
// flagged and what enforce mode would have blocked. The transcript-side twin of moorai-backtest, which
// replays only the content-free action-audit log and therefore cannot score detectors.
//
//   node cli/moorai-ingest.mjs --discover
//   node cli/moorai-ingest.mjs --discover --policy candidate.json --json
//   node cli/moorai-ingest.mjs ~/.claude/projects/<project> --agent claude-code --coverage
//   node cli/moorai-ingest.mjs --discover --report
//
// Exit code: 0 after a run (whatever it found), 2 on a usage error.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.mjs";
import { loadVerifiedPolicy, isEnrolled } from "./hook-core.mjs";
import { policyIdOf } from "./provenance.mjs";
import { exitWhenDrained } from "./exit-drain.mjs";
import { AGENTS, defaultRoots } from "./ingest/discover.mjs";
import { runIngest, DEFAULT_BOUNDS } from "./ingest/run.mjs";
import { NO_POLICY_BASELINE } from "./ingest/replay.mjs";
import { toText, threatName } from "./ingest/summary.mjs";
import { postAlerts } from "./ingest/report.mjs";

const roots = defaultRoots();
export const HELP = `moorai-ingest — what MoorAI would have flagged in your past agent sessions.

Usage:
  moorai-ingest --discover [options]
  moorai-ingest <file-or-dir>... --agent claude-code|codex [options]

Reads the transcripts your agents already keep on this machine and replays every recorded tool call,
tool result and prompt through the same decision functions the live MoorAI hook uses, under the policy
in force (or a candidate with --policy). The result is what enforce mode would have done.

Transcripts read:
  claude-code   ${roots["claude-code"].join(", ")}
                (<project>/<session>.jsonl and <session>/subagents/*.jsonl; $CLAUDE_CONFIG_DIR moves it)
  codex         ${roots.codex.join(", ")}
                (rollout-*.jsonl and rollout-*.jsonl.zst; $CODEX_HOME moves it)

Options:
  --discover            find transcripts in the locations above
  --agent NAME          agent of the explicit paths: claude-code | codex
  --policy FILE         candidate policy JSON (the shape /api/policy returns); default: the policy in force
  --days N              only transcripts modified in the last N days (default 30; 0 = any age)
  --max-files N         newest N transcript files (default ${DEFAULT_BOUNDS.maxFiles})
  --max-bytes N         stop after reading N bytes in total (default ${DEFAULT_BOUNDS.maxBytes})
  --max-file-bytes N    read at most the first N bytes of each file (default ${DEFAULT_BOUNDS.maxFileBytes})
  --max-line-bytes N    skip (and count) any line longer than N bytes (default ${DEFAULT_BOUNDS.maxLineBytes})
  --max-seconds N       stop after N seconds (default ${DEFAULT_BOUNDS.maxSeconds})
  --coverage            list sessions that ran other hooks but not MoorAI's (Claude Code only; Codex
                        does not record hook runs in its transcript, so its sessions show as unknown)
  --json                machine-readable summary
  --show-local          also print each finding WITH its content (prompt, command, path, matched text)
                        to this terminal; refused unless stdout is a terminal
  --report              send content-free alerts for the findings to your MoorAI console, marked
                        replayed: true with the original timestamp (enrolled devices only)

Privacy guarantees:
  * Everything runs on this machine. Transcripts are read, never copied, written or uploaded.
  * The default output is content-free: counts by threat, agent and decision, sessions affected and
    threat names. No prompt, command, path, URL, matched text or session id is printed.
  * --show-local is the only way to see content, and it writes only to an interactive terminal.
  * Nothing is sent anywhere unless you pass --report. Even then each alert carries only the threat id,
    category, risk level, stage, tool name (for an MCP tool its server and tool name, as the live hook
    sends), original timestamp, the same keyed one-way fingerprints the live hook sends (contentHash,
    session) and your device identity — never the prompt, command, path, arguments or matched text.
  * The only network call without --report is the one the live hook makes too: fetching the policy in
    force from your console (skipped with --policy).

Not replayed (needs the state of the moment, not the record): files a command reads, file metadata,
MCP file arguments, local secret-value egress, MCP reputation, cross-call fetch-then-exec, deletion
volume, circuit breaker, learned drift, session escalation, intent alignment, capability tags, model
escalation, and the ask-to-deny settlement of server mode and bypassPermissions.
`;

const NUM_FLAGS = { "--days": "days", "--max-files": "maxFiles", "--max-bytes": "maxBytes", "--max-file-bytes": "maxFileBytes", "--max-line-bytes": "maxLineBytes", "--max-seconds": "maxSeconds" };
const BOOL_FLAGS = new Set(["--discover", "--json", "--show-local", "--report", "--coverage", "--help", "-h"]);

export function parseArgs(argv) {
  const o = { paths: [], bounds: {}, flags: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (BOOL_FLAGS.has(a)) { o.flags.add(a); continue; }
    if (a in NUM_FLAGS) {
      const n = Number(argv[++i]);
      if (!Number.isFinite(n) || n < 0) throw new Error(`${a} needs a non-negative number`);
      if (a === "--days") o.days = n; else o.bounds[NUM_FLAGS[a]] = n;
      continue;
    }
    if (a === "--agent") { o.agent = argv[++i]; continue; }
    if (a === "--policy") { o.policy = argv[++i]; if (!o.policy) throw new Error("--policy needs a file"); continue; }
    if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    o.paths.push(a);
  }
  if (o.flags.has("--help") || o.flags.has("-h")) return o;
  if (!o.flags.has("--discover") && !o.paths.length) throw new Error("pass --discover or a transcript path with --agent");
  if (o.paths.length && !AGENTS.includes(o.agent)) throw new Error(`--agent must be one of ${AGENTS.join(", ")} for an explicit path`);
  return o;
}

// The rows only --show-local prints. Content, on purpose: the user asked to see it on their own screen.
export function showLocalText(rows) {
  const L = ["", "Findings with content (local terminal only, not stored, not sent):"];
  for (const r of rows) {
    const ti = r.input.tool_input || {};
    const what = r.event === "prompt" ? r.input.prompt : ti.command ?? ti.file_path ?? ti.notebook_path ?? ti.url ?? JSON.stringify(ti);
    L.push("", `[${r.ts || "?"}] ${r.agent} session ${String(r.sessionId).slice(0, 8)} · ${r.event}${r.tool ? " " + r.tool : ""} · would ${r.decision}`);
    L.push(`  input: ${String(what).replace(/\s+/g, " ").slice(0, 300)}`);
    for (const f of r.findings) L.push(`  #${f.threatId || "—"} ${threatName(f.threatId, f.category)} — matched: ${JSON.stringify(String(f.match || "").slice(0, 200))}`);
  }
  return L.join("\n") + "\n";
}

export function coverageText(sessions) {
  const rows = sessions.filter((s) => s.status !== "moorai-hook");
  const L = ["", `Sessions without the MoorAI hook (${rows.filter((s) => s.status === "no-moorai-hook").length} confirmed, ${rows.filter((s) => s.status === "unknown").length} unknown):`];
  for (const s of rows.sort((a, b) => (a.firstTs < b.firstTs ? 1 : -1)).slice(0, 200)) {
    L.push(`  ${s.agent.padEnd(12)} ${String(s.sessionId).slice(0, 8).padEnd(9)} ${(s.firstTs || "").slice(0, 10).padEnd(11)} ${s.status === "unknown" ? "unknown — no hook trace in the transcript" : "ran other hooks, not MoorAI"}`);
  }
  return L.join("\n") + "\n";
}

async function main(argv) {
  let o;
  try { o = parseArgs(argv); } catch (e) { process.stderr.write(`moorai-ingest: ${e.message} (see --help)\n`); return 2; }
  if (o.flags.has("--help") || o.flags.has("-h")) { process.stdout.write(HELP); return 0; }
  const showLocal = o.flags.has("--show-local");
  if (showLocal && !process.stdout.isTTY) { process.stderr.write("moorai-ingest: --show-local prints content and only writes to an interactive terminal; stdout is not one\n"); return 2; }

  const config = loadConfig();
  let policy, policySource;
  if (o.policy) {
    try { policy = JSON.parse(readFileSync(o.policy, "utf8")); } catch (e) { process.stderr.write(`moorai-ingest: cannot read candidate policy ${o.policy} — ${e.message}\n`); return 2; }
    policySource = "candidate";
  } else {
    let loaded = null;
    try { loaded = await loadVerifiedPolicy(config); } catch { loaded = null; }
    policy = loaded && loaded.policy ? loaded.policy : NO_POLICY_BASELINE;
    policySource = loaded && loaded.policy ? loaded.source : "builtin";
  }
  const policyId = policyIdOf(policy, { builtin: NO_POLICY_BASELINE });
  const report = o.flags.has("--report");
  const { result, alerts, local, sessions } = await runIngest({
    policy, policyId, policySource, days: o.days ?? 30, bounds: o.bounds,
    explicit: o.paths.length ? o.paths.map((path) => ({ path, agent: o.agent })) : null,
    collectAlerts: report, collectLocal: showLocal, config, coverage: o.flags.has("--coverage")
  });
  if (report) {
    const r = await postAlerts(config, alerts);
    result.report = { alerts: alerts.length, ...r, dropped: result.alertsDropped || 0 };
  }
  const coverage = o.flags.has("--coverage");
  if (o.flags.has("--json")) {
    if (coverage) result.sessionsWithoutHook = sessions.filter((s) => s.status !== "moorai-hook").map((s) => ({ agent: s.agent, session: String(s.sessionId).slice(0, 8), date: (s.firstTs || "").slice(0, 10), status: s.status }));
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    process.stdout.write(toText(result) + "\n");
    if (report) process.stdout.write(isEnrolled(config) ? `  --report: ${result.report.sent} historical alert(s) sent, ${result.report.failed} failed${result.report.dropped ? `, ${result.report.dropped} over the in-memory cap not sent` : ""}\n` : "  --report: this device is not enrolled, so there is no console to send to; nothing was sent\n");
    if (coverage) process.stdout.write(coverageText(sessions));
  }
  if (showLocal) process.stdout.write(showLocalText(local));
  return 0;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const code = await main(process.argv.slice(2));
  // Not process.exit(): on Windows that aborts the process (0xC0000409) after fetch() — see cli/exit-drain.mjs.
  exitWhenDrained(code); // not awaited: a top-level await that never settles exits with code 13
}
