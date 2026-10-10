// In-process timings for the benchmark's latency rows. Spawned by scripts/latency-bench.mjs with HOME
// pointed at a throwaway sandbox, so state paths resolved at import time never reach the real home.
// Prints the raw per-call samples (ms) as JSON; the parent computes the percentiles.
//
//   node scripts/latency-worker.mjs '{"proj":"…","home":"…","scanWarmup":50,"scanTexts":0,"decideN":2000,"decideWarmup":200}'
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { toolCalls, sessionFor } from "./latency-workload.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const cfg = JSON.parse(process.argv[2]);
const now = () => process.hrtime.bigint();
const since = (t0) => Number(now() - t0) / 1e6;

const { DETECTORS } = await import("../data/detectors.js");
const { CONTENT_RULES } = await import("../data/content-rules.js");
const { DetectionEngine } = await import("../src/engine.js");
const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const texts = JSON.parse(readFileSync(join(ROOT, "test/redteam/benign-corpus-v2.json"), "utf8")).benign.map((c) => c.text).slice(0, cfg.scanTexts || undefined);
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);

const scan = {};
for (const stage of ["prompt", "file", "output"]) {
  for (let i = 0; i < cfg.scanWarmup; i++) engine.scan(texts[i % texts.length], stage);
  scan[stage] = texts.map((t) => { const t0 = now(); engine.scan(t, stage); return since(t0); });
}

const { createMoorAI, NO_POLICY_BASELINE } = await import("../packages/agent-sdk/src/index.mjs");
const rt = await createMoorAI({ policy: NO_POLICY_BASELINE, systemConfig: null, env: { ...process.env }, reporter: { post: () => null, flush: async () => {}, enrolled: false }, surface: "benchmark" });
const calls = toolCalls(cfg);
const call = (i) => { const p = calls[i % calls.length]; return rt.toolCall({ tool: p.tool_name, input: p.tool_input, cwd: cfg.proj, permissionMode: "default", session: sessionFor(i) }); };
for (let i = 0; i < cfg.decideWarmup; i++) await call(i);
const decide = [];
const decisions = {};
for (let i = 0; i < cfg.decideN; i++) {
  const t0 = now();
  const v = await call(i);
  decide.push(since(t0));
  decisions[v.decision] = (decisions[v.decision] || 0) + 1;
}

process.stdout.write(JSON.stringify({ scan, decide, decisions }));
