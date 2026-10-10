// Per-surface observations for scripts/drop-rate.mjs: what the deterministic layer did with one attack
// on one surface, in the shape scripts/drop-rate-classify.mjs classifies. Each surface is scanned with
// the calls that surface's code makes; where that is approximated, the approximation is named.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { decideText } from "../cli/hook-core.mjs";
import { decideInbound, surfaceOf, inboundText } from "../cli/inbound.mjs";
import { observe } from "./drop-rate-classify.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const STRONG = new Set(["High", "Critical", "Blocked"]);
// scripts/score-inbound.mjs:38 — the no-policy baseline every inbound path is scored under.
export const BASE_POLICY = Object.freeze({ captureTier: "content-free", builtinDefault: true });

export function makeEngine() {
  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  return new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
}

// Which surfaces a text-at-a-stage sample can arrive through. Prompt-stage text has no single delivery
// surface in the corpora, so every surface that scans prompt-stage text is listed.
export const SURFACES_BY_STAGE = Object.freeze({
  prompt: ["harness", "guard:claude-p", "hook:WebFetch-input", "hook:Bash-command", "hook:Task-prompt", "hook:mcp-args", "hook:UserPromptSubmit-untrusted", "hook:UserPromptSubmit-person", "sdk"],
  output: ["harness", "hook:Write", "sdk"],
  file: ["harness", "hook:Read", "mcp-gateway", "sdk"],
  index: ["harness", "hook:index"]
});
// The stage each surface scans at; null = the sample's own stage. UserPromptSubmit scans at "file"
// (cli/moorai-hook.mjs:1874). Approximation: hook/guard/sdk verdicts use engine.scan at that stage
// (the harness scorers' call), not decideText's policy filter or MCP's JSON-serialised arguments.
const SURFACE_STAGE = { "hook:UserPromptSubmit-untrusted": "file", "hook:UserPromptSubmit-person": "file" };

export function observeText(engine, sample, surface) {
  const stage = SURFACE_STAGE[surface] || sample.stage;
  return observe(engine, sample, stage, sample.credited);
}

function obsOf(sample, findings, baseIds, stage, text) {
  return {
    caught: !!sample.credited(findings.map((f) => f.threatId), findings),
    baseIds,
    reported: findings.some((f) => f.riskLevel !== "Info"), // an alert-level finding the surface reports
    strong: findings.some((f) => STRONG.has(f.riskLevel)),
    stage, turns: false, textLength: text && text.trim() ? text.length : 0
  };
}
const ids = (fs) => [...new Set(fs.map((f) => f.threat.id))];
// What the escalation worker gates miss-recovery on: its raw re-scan restricted to the threat ids the
// decision kept (maybeEscalate hands those over as `credited`; cli/moorai-hook.mjs runEscalationWorker).
const creditedIds = (raw, decided) => { const keep = new Set(decided.map((f) => f.threatId)); return ids(raw).filter((id) => keep.has(id)); };

// hook:PostToolUse exactly as scripts/score-inbound.mjs delivers it (WebFetch for web content, an mcp__
// tool otherwise): decision = decideInbound at "output"; the escalation worker's base = engine.scan(text,
// "output") restricted to the ids that decision credited, so an outbound-only threat decideInbound drops
// does not block miss-recovery.
export function observeInboundHook(engine, sample) {
  const web = sample.door === "web";
  const tool = web ? "WebFetch" : "mcp__docs__get_document";
  const text = inboundText(web ? sample.text : [{ type: "text", text: sample.text }]);
  const d = decideInbound(engine, BASE_POLICY, text, { surface: surfaceOf(tool), stage: "output" });
  return obsOf(sample, d.findings, creditedIds(engine.scan(text, "output"), d.findings), "output", text);
}

// mcp-gateway: scripts/score-inbound.mjs gatewayPath (inboundText + decideInbound at "file").
export function observeInboundGateway(engine, sample) {
  const text = inboundText({ content: [{ type: "text", text: sample.text }] });
  const d = decideInbound(engine, BASE_POLICY, text, { surface: "mcp", stage: "file" });
  return obsOf(sample, d.findings, creditedIds(engine.scan(text, "file"), d.findings), "file", text);
}

// sdk: scripts/score-inbound.mjs sdkPath — the Agent SDK's own PostToolUse callback, findings off its reporter.
let SDK = null;
export async function observeInboundSdk(engine, sample) {
  if (!SDK) {
    const { moorAIHooks } = await import("../packages/agent-sdk/src/index.mjs");
    const sink = [];
    const reporter = { post: (a) => { sink.push(a); return null; }, flush: async () => {}, enrolled: true };
    SDK = { hooks: moorAIHooks({ policy: BASE_POLICY, reporter, serviceId: "drop-rate", toolResults: "advise" }), sink };
  }
  SDK.sink.length = 0;
  const web = sample.door === "web";
  await SDK.hooks.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: web ? "WebFetch" : "mcp__docs__get_document", tool_input: {}, tool_response: web ? sample.text : [{ type: "text", text: sample.text }] });
  const findings = SDK.sink.filter((a) => a.threatId > 0).map((a) => ({ threatId: a.threatId, riskLevel: a.riskLevel }));
  return obsOf(sample, findings, [...new Set(findings.map((f) => f.threatId))], "output", sample.text);
}

// The corpus's own stage label routed to the hook surface that handles that stage: output -> PostToolUse
// (same as observeInboundHook), file -> Read (decideText "file", cli/moorai-hook.mjs:2154), index -> the
// index worker (engine.scanForIndex, cli/moorai-hook.mjs:1030), prompt -> a delegated Task prompt
// (decideText "prompt", cli/moorai-hook.mjs:2461; ASSUMPTION — prompt-stage inbound content is a
// cross-agent hand-off in these corpora). Unlabelled -> null (not counted).
export const LABEL_SURFACE = { output: "hook:PostToolUse", file: "hook:Read", index: "hook:index", prompt: "hook:Task-prompt" };
export function observeInboundLabelled(engine, sample) {
  const L = sample.labelledStage;
  if (!L || !LABEL_SURFACE[L]) return null;
  if (L === "output") return { surface: LABEL_SURFACE[L], obs: observeInboundHook(engine, sample) };
  if (L === "index") {
    const fs = engine.scanForIndex(sample.text).map((f) => ({ threatId: f.threat.id, riskLevel: f.threat.riskLevel }));
    return { surface: LABEL_SURFACE[L], obs: obsOf(sample, fs, [...new Set(fs.map((f) => f.threatId))], "index", sample.text) };
  }
  const d = decideText(engine, BASE_POLICY, sample.text, L);
  return { surface: LABEL_SURFACE[L], obs: obsOf(sample, d.findings, creditedIds(engine.scan(sample.text, L), d.findings), L, sample.text) };
}
