// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/benchmark-latency.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { percentile, summarize, renderLatencyMarkdown, LATENCY_IGNORE_RE, P95_MIN_N, P99_MIN_N } from "../scripts/latency.mjs";
import { LATENCY_ROWS, measureHook, measureInProcess } from "../scripts/latency-bench.mjs";
import { latencySandbox } from "../scripts/latency-workload.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const shuffled = (xs) => xs.map((x, i) => [((i * 7919) % xs.length), x]).sort((p, q) => p[0] - q[0]).map((p) => p[1]);

test("percentile is nearest-rank: rank ceil(p*n) of the ascending sort", () => {
  const s = range(1, 100);
  assert.equal(percentile(s, 0.5), 50);
  assert.equal(percentile(s, 0.95), 95);
  assert.equal(percentile(s, 0.99), 99);
  assert.equal(percentile(range(1, 1000), 0.99), 990);
  assert.equal(percentile([], 0.5), null);
});

test("summarize reads p95 and p99 from the tail, not the middle", () => {
  const s = summarize(shuffled([...Array(90).fill(1), ...Array(10).fill(100)]));
  assert.deepEqual([s.p50, s.p95, s.max], [1, 100, 100]);
  const t = summarize(shuffled(range(1, 2000)));
  assert.deepEqual([t.n, t.p50, t.p95, t.p99, t.max], [2000, 1000, 1900, 1980, 2000]);
});

test("summarize sorts numerically and leaves the samples untouched", () => {
  const xs = [10, 9, 100, 2];
  assert.equal(summarize(xs).p50, 9);
  assert.deepEqual(xs, [10, 9, 100, 2]);
});

test("p95 needs P95_MIN_N samples and p99 needs P99_MIN_N", () => {
  assert.equal(summarize(range(1, P95_MIN_N - 1)).p95, null);
  assert.notEqual(summarize(range(1, P95_MIN_N)).p95, null);
  assert.equal(summarize(range(1, P99_MIN_N - 1)).p99, null);
  assert.equal(summarize(range(1, P99_MIN_N)).p99, P99_MIN_N - P99_MIN_N / 100);
});

// The generated-docs gate regenerates with --no-latency and ignores the timing lines with this pattern.
const IGNORE = new RegExp(LATENCY_IGNORE_RE);
const FAKE = { measured: true, machine: { cpu: "Test CPU", cores: 4, os: "testos 1 x64", node: "v0.0.0" }, hookDecisions: { allow: 3, advise: 1 },
  rows: LATENCY_ROWS.map((d, i) => ({ id: d.id, n: 1000 + i, p50Ms: 1 + i, p95Ms: 2 + i, p99Ms: 3 + i, maxMs: 40 + i })) };

test("test:generated uses the latency ignore pattern and --no-latency", () => {
  const s = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).scripts["test:generated"];
  assert.ok(s.includes(`-I '${LATENCY_IGNORE_RE}'`), s);
  assert.ok(s.startsWith("node scripts/benchmark.mjs --no-latency "), s);
});

test("a measured and an unmeasured latency section differ only on ignored lines", () => {
  const a = renderLatencyMarkdown(FAKE, LATENCY_ROWS).split("\n");
  const b = renderLatencyMarkdown({ measured: false }, LATENCY_ROWS).split("\n");
  assert.equal(a.length, b.length);
  const changed = a.filter((l, i) => l !== b[i]);
  assert.equal(changed.length, LATENCY_ROWS.length + 1);
  for (const l of [...changed, ...b.filter((l, i) => l !== a[i])]) assert.match(l, IGNORE);
});

test("the ignore pattern hides no coverage line of the published docs", () => {
  const md = readFileSync(join(ROOT, "docs", "BENCHMARK.md"), "utf8").split("\n");
  const cut = md.indexOf("## Latency");
  assert.ok(cut > 0, "BENCHMARK.md has a Latency section");
  assert.deepEqual(md.slice(0, cut).filter((l) => IGNORE.test(l)), []);
  const json = readFileSync(join(ROOT, "docs", "benchmark.json"), "utf8").split("\n").filter((l) => IGNORE.test(l));
  assert.equal(json.length, 1);
  assert.ok(json[0].startsWith('  "latency": {'));
});

test("the hook rows time real hook processes and the in-process rows run the SDK", async () => {
  const sb = latencySandbox();
  try {
    const hk = await measureHook(sb, { n: 3, warmup: 0 });
    assert.equal(hk.hook.length, 3);
    assert.equal(hk.floor.length, 3);
    assert.ok(hk.hook.every((ms) => ms > 0) && hk.floor.every((ms) => ms > 0));
    assert.equal(Object.values(hk.decisions).reduce((a, b) => a + b, 0), 3);
    const ip = await measureInProcess(sb, { scanWarmup: 1, scanTexts: 5, decideN: 10, decideWarmup: 1 });
    for (const st of ["prompt", "file", "output"]) assert.equal(ip.scan[st].length, 5);
    assert.equal(ip.decide.length, 10);
    assert.ok(ip.decisions.deny > 0, "the attack calls in the mix are denied in process");
  } finally { rmTree(sb.home); }
});
