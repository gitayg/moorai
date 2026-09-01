#!/usr/bin/env node
// MoorAI — content-free session/trace replay. Reconstructs an AI agent's ACTION CHAIN for incident
// investigation, entirely from the on-device content-free logs. It answers the one question the other
// viewers don't: "what did this agent do, in order?" — identity → tool → decision → risk → destination
// class, over time. Reads only local files; no server, no account, no writes, nothing leaves.
//
// Sources (both already content-free by construction — see signals.mjs / capture-tiers.js):
//   ~/.moorai/action-audit.jsonl   the searchable per-action timeline (the main replay source)
//   ~/.moorai/agent-events.jsonl   per-tool behavior events (ts, sig, ok, risk, server)
//
// Content-free by construction AND by whitelist: each step pulls ONLY metadata and existing one-way
// hashes — timestamp, actor hash, tool name, decision, risk, stage, destination CLASS (a host or MCP
// server NAME), and the one-way args/content hash. It never reads a prompt, a file path, a command
// argument, a matched span, or a model output — even when a higher capture tier left such a field in
// the row, the normalizer simply doesn't look at it.
//
//   node cli/moorai-trace.mjs                       # aligned timeline (default)
//   node cli/moorai-trace.mjs --json                # structured array for machines
//   node cli/moorai-trace.mjs --limit 50            # cap rows (default 200)
//   node cli/moorai-trace.mjs --agent <sig-or-hash> # one actor only
//   node cli/moorai-trace.mjs --help

import { readFileSync } from "node:fs";
import { AGENT_EVENTS_PATH } from "./signals.mjs";
import { statePath } from "./state-dirs.mjs";
import { boundedParseJsonl } from "./sanitize.mjs";

const ACTION_AUDIT_PATH = statePath("action-audit.jsonl");

const HELP = `MoorAI trace — content-free replay of an agent's action chain, for incident investigation.

Usage:
  moorai-trace [--json] [--limit N] [--agent <sig-or-hash>]

Reads two on-device logs (nothing ever leaves the machine):
  ${ACTION_AUDIT_PATH}   per-action timeline (main source)
  ${AGENT_EVENTS_PATH}      per-tool behavior events

Each step is content-free: time, actor hash, tool, decision (allow/ask/deny), risk, stage, the
destination CLASS (a host or MCP server NAME — never a URL path/query/arg), and a one-way content
hash. No prompt, file path, command argument, matched span, or model output is ever read or shown.

Options:
  --json            structured array instead of the aligned timeline
  --limit N         keep at most N (most-recent) steps (default 200)
  --agent <q>       only steps whose actor hash / user@device contains <q>
  --help, -h        this text
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const asJson = argv.includes("--json");
const limitArg = argv.includes("--limit") ? Number(argv[argv.indexOf("--limit") + 1]) : NaN;
const LIMIT = Number.isFinite(limitArg) && limitArg > 0 ? Math.floor(limitArg) : 200;
const agentQ = argv.includes("--agent") ? String(argv[argv.indexOf("--agent") + 1] || "").trim() : "";

// ts may be an ISO string (action audit) or epoch-ms (agent events); normalize to ms for ordering.
function tsMs(t) { if (typeof t === "number") return t; const p = Date.parse(t); return Number.isNaN(p) ? null : p; }
function stamp(ms) { return ms == null ? "—".padEnd(19) : new Date(ms).toISOString().replace("T", " ").slice(0, 19); }
// A destination is a host or an MCP SERVER NAME only — never a path/query/arg (see recordDestinations).
function destOf(r) { return r.mcpServer || (r.destination && r.destination.name) || ""; }
function cleanTool(t) { return String(t || "").replace(/^(hook|escalate):/, "") || "—"; }

// Normalize the two row shapes into ONE step, reading only the content-free whitelist. Anything a
// higher capture tier may have added (filePath, cmdShape, matchText, argText, toolName) is never touched.
function normAction(r) {
  return {
    ms: tsMs(r.ts),
    actor: String(r.actor ?? "").trim(),
    who: r.user ? `${r.user}@${r.device || ""}` : "",
    tool: cleanTool(r.tool),
    decision: r.decision || (r.riskLevel === "Blocked" ? "deny" : ""),
    risk: r.riskLevel || "",
    stage: r.stage || "",
    dest: destOf(r),
    hash: r.contentHash || "",
    category: r.category || "",
    source: "action"
  };
}
function normEvent(r) {
  const [tool, actor] = String(r.sig || "").split("|");
  return {
    ms: tsMs(r.ts),
    actor: actor || "",
    who: "",
    tool: cleanTool(tool),
    decision: r.ok === false ? "deny" : (r.ok === true ? "allow" : ""),
    risk: r.risk || "",
    stage: "behavior",
    dest: r.server && r.server !== "local" ? r.server : "",
    hash: "",
    category: "agent event",
    source: "event"
  };
}

function matchesAgent(step, q) {
  if (!q) return true;
  return [step.actor, step.who].filter(Boolean).join(" ").toLowerCase().includes(q.toLowerCase());
}

// Read one on-device JSONL log under hard bounds. These logs are written from agent/model-influenced
// events, so a single poisoned line — malformed JSON, or one blown up to gigabytes to hang the parser
// — must surface as a visible TRACE_GAP, never a silent drop and never a crash that erases the whole
// chain. Non-object records (a bare `null`/number line) are simply skipped; only unreadable lines gap.
function readBounded(path, norm, source) {
  let text = "";
  try { text = readFileSync(path, "utf8"); } catch { return { steps: [], gaps: [] }; }
  const { records, gaps } = boundedParseJsonl(text, { maxBytes: 16 * 1024 * 1024, maxLines: 20000, maxLineBytes: 65536 });
  return {
    steps: records.filter((r) => r && typeof r === "object").map(norm),
    gaps: gaps.map((g) => ({ reason: g.reason, index: g.index, source })),
  };
}

function buildChain() {
  const a = readBounded(ACTION_AUDIT_PATH, normAction, "action-audit");
  const e = readBounded(AGENT_EVENTS_PATH, normEvent, "agent-events");
  const ordered = [...a.steps, ...e.steps]
    .filter((s) => s.ms != null)
    .sort((x, y) => x.ms - y.ms)
    .filter((s) => matchesAgent(s, agentQ));
  const steps = ordered.length > LIMIT ? ordered.slice(-LIMIT) : ordered;
  return { steps, gaps: [...a.gaps, ...e.gaps] };
}

// ---- renderers ----
const trunc = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const pad = (s, n) => trunc(s, n).padEnd(n);

function toText(steps) {
  if (!steps.length) {
    const scope = agentQ ? ` for actor "${agentQ}"` : "";
    return `No on-device activity recorded${scope}.\n(${ACTION_AUDIT_PATH})\n`;
  }
  const first = stamp(steps[0].ms), last = stamp(steps[steps.length - 1].ms);
  const head = pad("time (UTC)", 19) + "  " + pad("actor", 12) + "  " + pad("tool", 22) + "  "
    + pad("decision", 8) + "  " + pad("risk", 8) + "  " + pad("destination", 20) + "  " + "args_hash";
  const body = steps.map((s) =>
    pad(stamp(s.ms), 19) + "  " + pad(s.actor || "—", 12) + "  " + pad(s.tool, 22) + "  "
    + pad(s.decision || "—", 8) + "  " + pad(s.risk || "—", 8) + "  " + pad(s.dest || "—", 20) + "  "
    + trunc(s.hash || "—", 22)
  ).join("\n");
  return `MoorAI trace — content-free action chain\n\n`
    + `${steps.length} step(s)  ·  ${first} → ${last}${agentQ ? `  ·  actor "${agentQ}"` : ""}\n`
    + `On-device replay. No prompt, file, argument, matched span, or model output is shown — only metadata and one-way hashes.\n\n`
    + head + "\n" + head.replace(/[^\s]/g, "-") + "\n" + body + "\n";
}

// TRACE_GAP lines make an unreadable/oversize source line VISIBLE in the replay instead of vanishing.
function gapsText(gaps) {
  if (!gaps.length) return "";
  const lines = gaps.map((g) => `  TRACE_GAP  ${g.source} line ${g.index}  —  ${g.reason}`).join("\n");
  return `\n${gaps.length} trace gap(s) — source line(s) skipped as unreadable, NOT silently dropped:\n${lines}\n`;
}

const { steps, gaps } = buildChain();
if (asJson) {
  const gapRows = gaps.map((g) => ({ type: "TRACE_GAP", reason: g.reason, index: g.index, source: g.source }));
  process.stdout.write(JSON.stringify([...steps, ...gapRows], null, 2) + "\n");
} else {
  process.stdout.write(toText(steps) + gapsText(gaps));
}
