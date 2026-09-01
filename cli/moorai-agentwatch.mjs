#!/usr/bin/env node
// moorai-agentwatch — score recent on-device agent activity against the autonomous-agent-behavior
// signature (the 8 behavioral tells the CSA Hugging Face post-mortem used to conclude that incident
// was a fully autonomous attack). Reads only the local content-free agent-events log; reports which
// tells fired and a verdict. With --emit, posts a content-free alert to the server, which forwards it
// to your SIEM/SOC (Splunk HEC / CEF / JSON) and surfaces it on the console timeline.
//
//   node cli/moorai-agentwatch.mjs                 # verdict for the current window
//   node cli/moorai-agentwatch.mjs --format json
//   node cli/moorai-agentwatch.mjs --emit          # also send a content-free alert (→ SIEM/SOC)
//   node cli/moorai-agentwatch.mjs --help
//
// Content-free: input is timestamps, action fingerprints, allow/deny, risk, and boolean content-tell
// flags — never a prompt, file, or matched span. Exit 0 clean/suspicious, 2 on an autonomous signature.

import os from "node:os";
import { assessSession, TELL_DEFS } from "../data/agent-behavior.js";
import { agentBaselineReport } from "../data/agent-baseline.js";
import { readAgentEvents, AGENT_EVENTS_PATH } from "./signals.mjs";
import { loadConfig } from "./config.mjs";

const HELP = `moorai-agentwatch — is a local agent behaving like an autonomous attack?

Usage:
  moorai-agentwatch [--format text|json] [--emit]

Scores the recent on-device agent-events window against the 8 behavioral tells from the CSA/SANS
Hugging Face incident post-mortem (§IV). Reads only ${AGENT_EVENTS_PATH} — content-free
(timestamps, action fingerprints, allow/deny, risk, tell flags; never prompt/file content).

  --emit    send a content-free alert to the configured server → SIEM/SOC + console timeline
  --format  text (default) or json

Exit: 0 = clean/suspicious, 2 = autonomous-agent signature detected.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "text";
const emit = argv.includes("--emit");

const CONFIG = loadConfig();
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant };
const events = readAgentEvents();
const res = assessSession(events);
// Per-agent learned baseline + the three content-free forensic detections (orphan agents, cross-agent
// messaging, trace gaps). Fully fail-open — agentBaselineReport swallows any error into an empty report,
// so this can never change agent-watch's verdict or exit code.
const report = agentBaselineReport(events);

async function emitAlert() {
  const alert = {
    threatId: 0, category: "Autonomous-agent behavior",
    riskLevel: res.level === "autonomous-signature" ? "Critical" : "High",
    stage: "behavior", tool: "moorai-agentwatch", ts: new Date().toISOString(),
    contentHash: "sig:" + res.tells.map((t) => t.id).join("."),
    signature: { level: res.level, score: res.score, tells: res.tells.map((t) => t.id), events: res.events },
    ...IDENTITY
  };
  try {
    await fetch(`${CONFIG.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) }, body: JSON.stringify(alert), signal: AbortSignal.timeout(2000) });
    return true;
  } catch { return false; }
}

const C = { r: "\x1b[31m", y: "\x1b[33m", g: "\x1b[32m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
function toText() {
  const col = res.level === "autonomous-signature" ? C.r : res.level === "suspicious" ? C.y : C.g;
  let out = `\n${C.b}MoorAI agent-watch — autonomous-behavior signature${C.off}\n`;
  out += `${C.dim}events analyzed: ${res.events} · tenant: ${CONFIG.tenant}${C.off}\n\n`;
  out += `  verdict: ${col}${res.level.toUpperCase()}${C.off}  ${C.dim}(score ${res.score}, ${res.tellsFired}/8 tells)${C.off}\n`;
  if (res.tells.length) {
    out += `\n  ${C.dim}Tells fired:${C.off}\n`;
    for (const t of res.tells) out += `    ${col}#${t.id}${C.off}  ${t.label}\n`;
  } else out += `\n  ${C.g}No autonomous-behavior tells in the current window.${C.off}\n`;
  out += baselineText();
  out += `\n  ${C.dim}Reference: CSA/SANS "Hugging Face Incident Initial Post-Mortem", §IV Observations.${C.off}\n`;
  return out;
}

// Per-agent baseline + the three content-free detections. Additive to the verdict above; content-free
// (opaque actor ids shown truncated, counts, and severities — never a prompt, arg, or path).
const short = (id) => { const s = String(id || ""); return s.length > 14 ? s.slice(0, 14) + "…" : s; };
function baselineText() {
  let out = `\n  ${C.b}Per-agent baseline${C.off} ${C.dim}(${report.actorCount} actor${report.actorCount === 1 ? "" : "s"}, ${report.events} events)${C.off}\n`;
  const entries = Object.entries(report.agents);
  if (!entries.length) out += `    ${C.dim}no per-agent history yet${C.off}\n`;
  for (const [actor, a] of entries) {
    const conf = a.lowConfidence ? `${C.y}low-confidence${C.off}` : `${C.dim}conf ${a.confidence.toFixed(2)}${C.off}`;
    out += `    ${short(actor)}  ${C.dim}events=${a.n} tools=${a.tools} servers=${a.servers.length}${C.off}  ${conf}\n`;
  }
  const { orphans, crossAgent, traceGaps } = report.detections;
  const t = report.totals;
  const any = t.orphans + t.crossAgent + t.traceGaps;
  out += `\n  ${C.b}Content-free detections${C.off}\n`;
  if (!any) { out += `    ${C.g}none in the current window${C.off}\n`; return out; }
  const line = (f) => `    ${sevCol(f.severity)}#${f.type}${C.off}  ${C.dim}agent=${short(f.agent)} sev=${f.severity} count=${f.count}${C.off}\n`;
  for (const f of orphans) out += line(f);
  for (const f of crossAgent) out += line(f);
  for (const f of traceGaps) out += `    ${sevCol(f.severity)}#${f.type}${C.off}  ${C.dim}agent=${short(f.agent)} kind=${f.evidence.kind} sev=${f.severity} count=${f.count}${C.off}\n`;
  return out;
}
function sevCol(s) { return s === "high" ? C.r : s === "medium" ? C.y : C.dim; }

if (fmt === "json") process.stdout.write(JSON.stringify({ ...res, baseline: report, tenant: CONFIG.tenant }, null, 2) + "\n");
else process.stdout.write(toText());

if (emit && res.level !== "clean") {
  const ok = await emitAlert();
  if (fmt !== "json") process.stderr.write(ok ? "  → alert sent to server (→ SIEM/SOC + timeline)\n" : "  → emit failed (server unreachable; verdict stands locally)\n");
}
process.exit(res.level === "autonomous-signature" ? 2 : 0);
