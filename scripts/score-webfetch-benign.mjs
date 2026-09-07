#!/usr/bin/env node
// FALSE-POSITIVE rate of the inbound WebFetch/WebSearch surface, measured THROUGH THE SHIPPED HOOK.
//
// WHY THIS SCRIPT EXISTS.
// v0.79.1 made PostToolUse-scanned web content reachable: output-stage vector-2 attacks went 0/24 to
// 22/24 through the real hook (scripts/measure-webfetch-reachability.mjs). The same run reports that 8
// of 11 benign controls also alert. ELEVEN SAMPLES IS NOT A FALSE-POSITIVE RATE, IT IS AN ANECDOTE.
// Nothing may be published or scoped against it:
//   * AMTSO requires the benign-sample result to appear ALONGSIDE recall, and 8-of-11 is not a
//     publishable benign line.
//   * Scoping a detector on a denominator of 11 is exactly how the main FP gate once went blind to a
//     48-false-positive regression.
// This script prices the surface against test/redteam/benign-web-content.json instead.
//
// WHAT IT MEASURES, AND WHERE EACH NUMBER COMES FROM.
//   ON THE WIRE (authoritative): the real cli/moorai-hook.mjs is spawned as a subprocess with a real
//   PostToolUse payload carrying the fetched page. A false positive is "the shipped hook emitted at
//   least one content-free detection finding for benign content", read off the alert POST, plus the
//   DECISION the hook wrote to stdout. It re-implements none of the hook's logic.
//   IN PROCESS (attribution only): the alert payload carries threatId and category but NOT detectorId
//   (see report() in cli/moorai-hook.mjs), so "FP by detector" cannot be read off the wire at all. For
//   FP rows only, the same engine the hook builds is re-run in-process to recover detectorId. That
//   attribution is CROSS-CHECKED against the wire threat ids on every row and any divergence is
//   reported rather than hidden — see `attributionMismatches` in the output.
//
// THE HARNESS (startServer / sandbox / run / payload / one) is lifted VERBATIM from
// scripts/measure-webfetch-reachability.mjs, minus the --before branch. It is copied rather than
// imported because that script executes its whole measurement at import time and exports nothing, and
// this change does not own it. If it ever grows exports, delete the copy and import them.
//
//   node scripts/score-webfetch-benign.mjs                 # TUNE half (the default; iterate here)
//   node scripts/score-webfetch-benign.mjs --json
//   node scripts/score-webfetch-benign.mjs --split all
//   node scripts/score-webfetch-benign.mjs --split test --i-am-reporting-the-headline
//   node scripts/score-webfetch-benign.mjs --concurrency 8
//
// THE TEST HALF IS LOCKED. It exists to price future detector changes and must never be tuned against.
// Scoring it requires the explicit --i-am-reporting-the-headline flag, and it prints a banner saying so.
//
// Content-free: emits ids, channels, detector ids, threat ids, decisions and counts. Never a sample's
// text, and never a matched substring.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { buildEngine } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const DEFAULT_CORPUS = "test/redteam/benign-web-content.json";

export function parseArgs(argv) {
  const val = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  return {
    json: argv.includes("--json"),
    file: val("--file") || DEFAULT_CORPUS,
    split: val("--split") || "tune",
    unlock: argv.includes("--i-am-reporting-the-headline"),
    concurrency: Number(val("--concurrency") || 6),
    failOver: val("--fail-over") !== undefined ? Number(val("--fail-over")) : null
  };
}

// ---- harness (verbatim from scripts/measure-webfetch-reachability.mjs) ----------------------------

const POLICY = { captureTier: "content-free", threatPolicy: {} };

function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-benign-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "benign", installToken: "tok-benign" }));
  return home;
}

function run(home, stdin) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, [HOOK], { cwd: home, env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", () => {});
    c.on("close", (code) => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, out, code }));
    c.stdin.end(stdin);
  });
}

// The WebSearch path carries its query in tool_input.query; WebFetch carries {url, prompt}. The hook
// reads whichever is present (see handlePostToolUse), so the payload has to match the sample's channel
// or the WebSearch half of the corpus would be measured on the wrong surface.
const payload = (s) => JSON.stringify(
  s.tool === "WebSearch"
    ? { hook_event_name: "PostToolUse", tool_name: "WebSearch", tool_input: { query: "example query" }, tool_use_id: "toolu_benign", tool_response: s.text, session_id: "benign" }
    : { hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://docs.example.com/p", prompt: "Summarise this page" }, tool_use_id: "toolu_benign", tool_response: s.text, session_id: "benign" }
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The hook's PostToolUse stdout contract (emitPost): allow writes NOTHING, ask writes an advisory
// additionalContext envelope, deny writes the top-level block channel. The decision is therefore
// recoverable from stdout alone — an advisory that reaches the model is a different cost from a silent
// notify, so it is counted separately rather than collapsed into "alerted".
export function decisionOf(stdout) {
  const t = (stdout || "").trim();
  if (!t) return "allow";
  try {
    const o = JSON.parse(t);
    if (o.decision === "block") return "deny";
    if (o.hookSpecificOutput?.additionalContext) return "advisory";
  } catch { /* fall through */ }
  return "unknown";
}

async function one(sample) {
  const { srv, port, alerts } = await startServer(POLICY);
  const home = sandbox(port);
  const r = await run(home, payload(sample));
  await sleep(450);
  srv.close();
  const found = alerts.filter((a) => a.stage === "output" && a.threatId);
  return {
    id: sample.id,
    channel: sample.channel,
    tool: sample.tool || "WebFetch",
    hardNegative: !!sample.hard_negative,
    alerted: found.length > 0,
    threats: [...new Set(found.map((a) => a.threatId))].sort((a, b) => a - b),
    decision: decisionOf(r.out),
    ms: r.ms,
    code: r.code
  };
}

// ---- detector attribution (in-process; NOT the wire measurement) ----------------------------------

function attribute(engine, sample) {
  const findings = engine.scan(sample.text, "output") || [];
  return {
    detectors: [...new Set(findings.map((f) => f.detectorId))].sort(),
    threats: [...new Set(findings.map((f) => f.threat?.id))].filter((x) => x != null).sort((a, b) => a - b)
  };
}

// ---- reducers -------------------------------------------------------------------------------------

export function groupFp(rows, key) {
  const m = new Map();
  for (const r of rows) {
    const g = r[key];
    if (g == null) continue;
    if (!m.has(g)) m.set(g, { samples: 0, fp: 0, advisory: 0 });
    const e = m.get(g);
    e.samples++;
    if (r.alerted) e.fp++;
    if (r.decision === "advisory") e.advisory++;
  }
  return [...m.entries()]
    .map(([k, e]) => ({ [key]: k, ...e, fpRate: e.samples ? e.fp / e.samples : 0 }))
    .sort((a, b) => b.fpRate - a.fpRate || String(a[key]).localeCompare(String(b[key])));
}

export function countBy(rows, pick) {
  const m = new Map();
  for (const r of rows) for (const v of pick(r)) m.set(v, (m.get(v) || 0) + 1);
  return [...m.entries()].map(([k, n]) => ({ key: k, samples: n })).sort((a, b) => b.samples - a.samples || String(a.key).localeCompare(String(b.key)));
}

// Bounded-concurrency map. Each unit of work owns its own loopback server and HOME sandbox, so the runs
// share nothing; concurrency changes wall-clock only. Latency figures are reported but are NOT a
// like-for-like comparison with the sequential reachability run — noted in the render.
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return out;
}

export async function runCorpus({ file = DEFAULT_CORPUS, split = "tune", concurrency = 6 } = {}) {
  const data = JSON.parse(readFileSync(join(ROOT, file), "utf8"));
  const all = data.samples || [];
  // A false-positive rate is only meaningful over samples that SHOULD NOT fire. The
  // prompt-injection-tutorial pages carry live payloads as their subject matter, so firing on them is a
  // true positive; counting them here was inflating our own FP rate against us. They are scored
  // separately as recall below rather than dropped, because a page that teaches injection and does NOT
  // trip us is a miss worth seeing.
  const inSplit = split === "all" ? all : all.filter((s) => s.split === split);
  const truePos = inSplit.filter((s) => s.shouldDetect === true);
  const samples = inSplit.filter((s) => s.shouldDetect !== true);
  if (!samples.length) throw new Error(`no samples for split="${split}" in ${file}`);

  const rows = await mapLimit(samples, concurrency, one);
  const tpRows = truePos.length ? await mapLimit(truePos, concurrency, one) : [];

  const engine = buildEngine(POLICY);
  const byId = new Map(samples.map((s) => [s.id, s]));
  const attributionMismatches = [];
  for (const r of rows) {
    const a = attribute(engine, byId.get(r.id));
    r.detectors = a.detectors;
    r.inProcessThreats = a.threats;
    // The wire is authoritative. When in-process attribution disagrees with it, say so on the row
    // rather than quietly reporting a detector breakdown that does not match the measured FPs.
    if (JSON.stringify(a.threats) !== JSON.stringify(r.threats)) {
      attributionMismatches.push({ id: r.id, wire: r.threats, inProcess: a.threats });
    }
  }

  const hn = rows.filter((r) => r.hardNegative);
  const plain = rows.filter((r) => !r.hardNegative);
  const fpRows = rows.filter((r) => r.alerted);
  const decisions = {};
  for (const r of rows) decisions[r.decision] = (decisions[r.decision] || 0) + 1;
  const lat = rows.map((r) => r.ms).sort((x, y) => x - y);

  return {
    file,
    split,
    totals: { samples: rows.length, fp: fpRows.length, hardNegative: hn.length, plainBenign: plain.length },
    fpRate: rows.length ? fpRows.length / rows.length : 0,
    specificity: rows.length ? (rows.length - fpRows.length) / rows.length : 1,
    plain: { samples: plain.length, fp: plain.filter((r) => r.alerted).length },
    hard: { samples: hn.length, fp: hn.filter((r) => r.alerted).length },
    decisions,
    byChannel: groupFp(rows, "channel"),
    byTool: groupFp(rows, "tool"),
    byDetector: countBy(fpRows, (r) => r.detectors),
    byThreat: countBy(fpRows, (r) => r.threats.map((t) => `#${t}`)),
    detectorByClass: {
      plain: countBy(fpRows.filter((r) => !r.hardNegative), (r) => r.detectors),
      hard: countBy(fpRows.filter((r) => r.hardNegative), (r) => r.detectors)
    },
    fps: fpRows.map((r) => ({ id: r.id, channel: r.channel, hardNegative: r.hardNegative, decision: r.decision, threats: r.threats, detectors: r.detectors })),
    attributionMismatches,
    truePositives: { samples: tpRows.length, caught: tpRows.filter((r) => r.alerted).length },
    nonZeroExit: rows.filter((r) => r.code !== 0).length,
    latency: { median: lat[Math.floor(lat.length / 2)], p95: lat[Math.floor(lat.length * 0.95)], n: lat.length },
    rows
  };
}

function render(res) {
  const C = { g: "\x1b[32m", r: "\x1b[31m", y: "\x1b[33m", dim: "\x1b[2m", b: "\x1b[1m", off: "\x1b[0m" };
  const pct = (x) => `${(x * 100).toFixed(2)}%`;
  const col = (rate) => (rate === 0 ? C.g : rate < 0.05 ? C.y : C.r);
  const t = res.totals;
  let out = "";
  if (res.split === "test") out += `\n${C.r}${C.b}*** LOCKED TEST HALF — headline only. Do NOT iterate against this number. ***${C.off}\n`;
  out += `\n${C.b}MoorAI — inbound web content · FALSE-POSITIVE rate through the SHIPPED HOOK${C.off}\n`;
  out += `${C.dim}entry point: spawn cli/moorai-hook.mjs with a real PostToolUse payload; verdict read off the wire${C.off}\n`;
  out += `${C.dim}corpus ${res.file} · split=${res.split} · ${t.samples} samples (${t.plainBenign} plain, ${t.hardNegative} hard negative)${C.off}\n\n`;
  out += `  ${C.b}False positives${C.off}  ${col(res.fpRate)}${t.fp}${C.off} / ${t.samples}   ${C.b}FP rate${C.off} ${col(res.fpRate)}${pct(res.fpRate)}${C.off}   ${C.b}specificity${C.off} ${pct(res.specificity)}\n`;
  out += `    plain benign    ${res.plain.fp}/${res.plain.samples}  ${pct(res.plain.samples ? res.plain.fp / res.plain.samples : 0)}\n`;
  out += `    hard negatives  ${res.hard.fp}/${res.hard.samples}  ${pct(res.hard.samples ? res.hard.fp / res.hard.samples : 0)}\n`;
  out += `\n  ${C.b}Decision distribution${C.off} ${C.dim}(what the hook actually wrote to stdout)${C.off}\n`;
  for (const [k, n] of Object.entries(res.decisions).sort((a, b) => b[1] - a[1])) out += `    ${k.padEnd(10)} ${n}  ${pct(n / t.samples)}\n`;
  out += `\n  ${C.b}FP by detector${C.off} ${C.dim}(in-process attribution — the alert wire carries no detectorId)${C.off}\n`;
  if (!res.byDetector.length) out += `    ${C.dim}none${C.off}\n`;
  for (const d of res.byDetector) out += `    ${String(d.key).padEnd(28)} ${d.samples}\n`;
  out += `\n  ${C.b}FP by threat id${C.off}\n`;
  if (!res.byThreat.length) out += `    ${C.dim}none${C.off}\n`;
  for (const d of res.byThreat) out += `    ${String(d.key).padEnd(28)} ${d.samples}\n`;
  out += `\n  ${C.b}FP by channel (worst first)${C.off}\n`;
  for (const c of res.byChannel) {
    const mark = c.fp ? col(c.fpRate) : C.dim;
    out += `    ${mark}${String(c.channel).padEnd(26)}${C.off} ${String(c.fp).padStart(3)}/${String(c.samples).padEnd(4)} ${mark}${pct(c.fpRate).padStart(7)}${C.off}  ${C.dim}advisory ${c.advisory}${C.off}\n`;
  }
  if (res.truePositives && res.truePositives.samples) { const tp = res.truePositives; out += `  ${C.b}True positives${C.off} (pages whose subject matter IS a live payload)  ${tp.caught}/${tp.samples} caught  ${pct(tp.caught / tp.samples)}${tp.caught < tp.samples ? `  ${C.dim}${tp.samples - tp.caught} missed${C.off}` : ""}\n`; }
  out += `\n  ${C.dim}hook exit codes non-zero: ${res.nonZeroExit} · latency median ${res.latency.median.toFixed(0)}ms p95 ${res.latency.p95.toFixed(0)}ms n=${res.latency.n} (concurrent; not comparable to a sequential run)${C.off}\n`;
  if (res.attributionMismatches.length) {
    out += `  ${C.y}attribution mismatches (wire vs in-process): ${res.attributionMismatches.length}${C.off}\n`;
    for (const m of res.attributionMismatches.slice(0, 15)) out += `    ${C.dim}${m.id}  wire=[${m.wire}] inProcess=[${m.inProcess}]${C.off}\n`;
  } else {
    out += `  ${C.dim}attribution cross-check: in-process threat ids match the wire on all ${res.totals.samples} rows${C.off}\n`;
  }
  return out + "\n";
}

// pathToFileURL, not `file://${argv[1]}`: this repo's checkout path contains a space, which
// import.meta.url percent-encodes and argv[1] does not — the naive comparison is false on every run
// and the script exits 0 having printed nothing, which reads exactly like a clean pass.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = parseArgs(process.argv.slice(2));
  if (args.split === "test" && !args.unlock) {
    console.error("test/redteam/benign-web-content.json's TEST half is LOCKED: it prices future detector changes and must never be tuned against.\nScore it once, as a headline, with --i-am-reporting-the-headline.");
    process.exit(2);
  }
  const res = await runCorpus(args);
  if (args.json) {
    console.log(JSON.stringify(res, null, 2));
  } else {
    console.log(render(res));
  }
  if (args.failOver != null && res.fpRate * 100 > args.failOver) process.exit(1);
}
