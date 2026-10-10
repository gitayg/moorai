// Latency statistics and rendering for the benchmark (scripts/benchmark.mjs). Percentiles are
// nearest-rank over the raw samples: the value at rank ceil(p * n) of the ascending sort, never
// interpolated and never derived from a mean. p95 is published from P95_MIN_N samples and p99 from
// P99_MIN_N, below which the tail is a handful of samples and reads as noise.
import os from "node:os";

export const P95_MIN_N = 20;
export const P99_MIN_N = 1000;

// The `git diff -I` pattern `npm run test:generated` uses to ignore the lines that carry timings or
// the machine they were taken on. test/benchmark-latency.test.mjs holds package.json to this string
// and checks that it matches every timing line and no coverage line.
export const LATENCY_IGNORE_RE = '^(\\| (In process|Process): |> Latency|  "latency": )';

export function percentile(sorted, p) {
  if (!sorted.length) return null;
  const rank = Math.min(sorted.length, Math.max(1, Math.ceil(p * sorted.length)));
  return sorted[rank - 1];
}

export function summarize(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  return {
    n,
    p50: percentile(s, 0.5),
    p95: n >= P95_MIN_N ? percentile(s, 0.95) : null,
    p99: n >= P99_MIN_N ? percentile(s, 0.99) : null,
    max: n ? s[n - 1] : null
  };
}

export function machine() {
  const cpus = os.cpus();
  return { cpu: (cpus[0] && cpus[0].model || "unknown").trim(), cores: cpus.length, os: `${os.platform()} ${os.release()} ${os.arch()}`, node: process.version };
}

const round3 = (x) => (x === null ? null : +x.toFixed(3));
export function latencyRow(def, samples) {
  const s = summarize(samples);
  return { id: def.id, label: def.label, sample: def.sample, warmup: def.warmup, n: s.n, p50Ms: round3(s.p50), p95Ms: round3(s.p95), p99Ms: round3(s.p99), maxMs: round3(s.max) };
}

const fmt = (ms) => (ms === null || ms === undefined ? "—" : `${ms < 10 ? ms.toFixed(2) : ms.toFixed(1)} ms`);

export function renderLatencyMarkdown(lat, defs) {
  const conditions = lat.measured
    ? `> Latency measured on ${lat.machine.cpu} (${lat.machine.cores} logical cores), ${lat.machine.os}, Node ${lat.machine.node}. Hook decisions in the run (unenrolled, so a flagged call is advised, not blocked): ${Object.entries(lat.hookDecisions).map(([k, v]) => `${k} ${v}`).join(", ")}.`
    : "> Latency not measured in this run (`--no-latency`).";
  const byId = new Map((lat.rows || []).map((r) => [r.id, r]));
  const rows = defs.map((d) => {
    const r = byId.get(d.id);
    return `| ${d.label} | ${d.sample} | ${r ? r.n : "—"} | ${d.warmup} | ${fmt(r && r.p50Ms)} | ${fmt(r && r.p95Ms)} | ${fmt(r && r.p99Ms)} | ${fmt(r && r.maxMs)} |`;
  }).join("\n");
  return `## Latency

${conditions}

| Path | One sample | n | Warm-up | p50 | p95 | p99 | max |
|------|------------|--:|--------:|----:|----:|----:|----:|
${rows}

The cost a Claude Code user pays per tool call is the **hook end-to-end** row: one \`node
cli/moorai-hook.mjs\` process spawned per \`PreToolUse\`, timed from spawn to exit, in a throwaway home
with no console (unenrolled, built-in policy). The **Node startup floor** row is \`node -e ""\` spawned
the same way, interleaved call for call with the hook, so the gap between the two rows is the hook's own
module loading and decision. The **in-process** rows are what the Agent SDK and \`moorai-serve\` pay per
call in a long-lived process: \`engine.scan\` per stage over every text in
\`test/redteam/benign-corpus-v2.json\`, and \`createMoorAI().toolCall\` (the decision code the parity test
holds to the hook's verdicts) over a fixed mix of ten \`PreToolUse\` calls, six benign and four attack-shaped.
All rows run sequentially, one call at a time; machine load is not controlled.

Percentiles are nearest-rank over the raw per-call timings, never interpolated and never derived from a
mean. p95 is published from ${P95_MIN_N} samples and p99 from ${P99_MIN_N.toLocaleString("en-US")}; a — means the row has
fewer. Timings vary between runs and machines, so \`npm run test:generated\` regenerates this file with
\`--no-latency\` and ignores only the latency rows and the conditions line; every coverage number above is
still diffed byte for byte.
`;
}
