#!/usr/bin/env node
// END-TO-END reachability for AMTSO vector 5's EVENT-GRAPH attacks.
//
// WHY THIS EXISTS, AND WHY IT IS NOT scripts/score-vectors.mjs. That scorer calls
// runAgentDetections(sample.events) — the LIBRARY API — and reports 15/15 on the "events" harness.
// That number says the detectors work. It says NOTHING about whether a deployment can see them, and
// before the wiring this script measures, it could not: runAgentDetections/agentBaselineReport had
// exactly one caller outside data/, cli/moorai-agentwatch.mjs, an offline reporting CLI; nothing on
// the PreToolUse enforcement path called them; and agentwatch's --emit payload was built from
// assessSession() alone, so no finding ever left the device.
//
// So this scorer refuses to call the library at all. It drives the two paths a real deployment
// actually has, end to end, and counts what arrives at a stand-in management server:
//
//   --path hook        seed the on-device window (~/.moorai/agent-events.jsonl), then run the REAL
//                      cli/moorai-hook.mjs PreToolUse hook on an ordinary Read. Detected iff a
//                      content-free "Agent behavior: …" alert reaches POST /api/alerts.
//   --path agentwatch  same seeded window, then the REAL `moorai-agentwatch --emit`. Detected iff the
//                      emitted alert's `detections` carries a finding.
//
// A sample is a TP only when the alert names a detection type the corpus EXPECTS (expectDetections),
// not merely when something fired. A benign window is an FP if ANY agent-behavior alert arrives.
//
// The device is ENROLLED (an installToken is written) because the wiring is deliberately NO_KEY-inert:
// on an unenrolled device contentHash() collapses every id to the h2:nokey sentinel and the whole
// event graph becomes one actor, so the layer stays silent by design. Run with --unenrolled to
// measure that inertness instead.
//
//   node scripts/score-vector5-production.mjs
//   node scripts/score-vector5-production.mjs --path hook --json
//   node scripts/score-vector5-production.mjs --unenrolled
//
// Content-free: prints sample ids, detection-bucket names and counts. Never a sample's text.
import http from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const AGENTWATCH = join(ROOT, "cli", "moorai-agentwatch.mjs");
const CORPUS = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector5-memory-crossagent.json"), "utf8"));

// report.totals bucket name → the finding `type` data/agent-detections.js emits.
const BUCKET_TYPE = {
  orphans: "orphan-agent",
  crossAgent: "cross-agent-messaging",
  traceGaps: "trace-gap",
  velocity: "velocity-burst",
  confusedDeputy: "confused-deputy",
  fanOut: "fan-out-anomaly"
};

const argv = process.argv.slice(2);
const arg = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const asJson = argv.includes("--json");
const enrolled = !argv.includes("--unenrolled");
const paths = arg("--path", "hook,agentwatch").split(",").map((s) => s.trim()).filter(Boolean);

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

function sandbox(port, events) {
  const home = mkdtempSync(join(tmpdir(), "moorai-v5prod-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({
    serverUrl: `http://127.0.0.1:${port}`, tenant: "amtso-v5",
    ...(enrolled ? { installToken: "tok-v5-production-harness" } : {})
  }));
  writeFileSync(join(home, ".moorai", "agent-events.jsonl"), (events || []).map((e) => JSON.stringify(e)).join("\n") + "\n");
  const file = join(home, "sample.txt");
  writeFileSync(file, "ordinary project notes\n"); // a Read the engine finds nothing in
  return { home, file };
}

function run(bin, args, home, stdin) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [bin, ...args], {
      cwd: ROOT, stdio: ["pipe", "ignore", "ignore"],
      env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" }
    });
    c.on("close", (code) => resolve(code));
    if (stdin != null) c.stdin.end(stdin); else c.stdin.end();
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Types surfaced by ONE production run over `events`.
async function typesVia(path, port, alerts, events) {
  const before = alerts.length;
  const sb = sandbox(port, events);
  try {
    if (path === "hook") {
      await run(HOOK, [], sb.home, JSON.stringify({ tool_name: "Read", tool_input: { file_path: sb.file }, session_id: "v5-prod" }));
      await sleep(1500); // the scan is DETACHED — give the worker time to run and POST
    } else {
      await run(AGENTWATCH, ["--emit", "--format", "json"], sb.home);
      await sleep(800);
    }
  } finally { try { rmSync(sb.home, { recursive: true, force: true }); } catch { /* best-effort */ } }
  const fresh = alerts.slice(before);
  const types = new Set();
  for (const a of fresh) {
    if (a.detection && a.detection.type) types.add(a.detection.type);           // hook path
    if (a.detections) for (const b of Object.keys(a.detections)) for (const f of a.detections[b]) types.add(f.type); // agentwatch --emit
  }
  return types;
}

async function scorePath(path) {
  const { srv, port, alerts } = await startServer({ agentDetections: true, captureTier: "content-free", threatPolicy: {} });
  const rows = [];
  try {
    const samples = [
      ...CORPUS.attacks.filter((s) => s.harness === "events").map((s) => ({ ...s, shouldDetect: true })),
      ...(CORPUS.benign || []).filter((s) => s.harness === "events").map((s) => ({ ...s, shouldDetect: false }))
    ];
    for (const s of samples) {
      const types = await typesVia(path, port, alerts, s.events || []);
      const want = (s.expectDetections || []).map((b) => BUCKET_TYPE[b]).filter(Boolean);
      const detected = want.length ? want.some((t) => types.has(t)) : types.size > 0;
      rows.push({
        id: s.id, family: s.family || s.subTechnique, shouldDetect: s.shouldDetect,
        want, got: [...types].sort(),
        detected: s.shouldDetect ? detected : types.size > 0,
        rightReason: s.shouldDetect && want.length ? want.every((t) => types.has(t)) : null
      });
    }
  } finally { srv.close(); }
  return rows;
}

const out = {};
for (const p of paths) out[p] = await scorePath(p);

function summarize(rows) {
  const atk = rows.filter((r) => r.shouldDetect), ben = rows.filter((r) => !r.shouldDetect);
  const tp = atk.filter((r) => r.detected).length, fp = ben.filter((r) => r.detected).length;
  return { attacks: atk.length, caught: tp, recall: atk.length ? tp / atk.length : 0, benign: ben.length, fp, rightReason: atk.filter((r) => r.rightReason).length };
}

if (asJson) {
  process.stdout.write(JSON.stringify({ enrolled, paths: Object.fromEntries(Object.entries(out).map(([k, v]) => [k, { summary: summarize(v), rows: v }])) }, null, 2) + "\n");
} else {
  process.stdout.write(`\n=== AMTSO vector 5 — event-graph attacks THROUGH THE PRODUCTION PATH ===\n`);
  process.stdout.write(`device: ${enrolled ? "enrolled (keyed)" : "UNENROLLED (h2:nokey — the layer is inert by design)"}\n`);
  for (const [p, rows] of Object.entries(out)) {
    const s = summarize(rows);
    process.stdout.write(`\n  path: ${p}\n`);
    process.stdout.write(`    reachable end-to-end   ${s.caught}/${s.attacks}   (${(s.recall * 100).toFixed(1)}%)\n`);
    process.stdout.write(`    right reason           ${s.rightReason}/${s.attacks}   (every expected bucket fired)\n`);
    process.stdout.write(`    benign false positives ${s.fp}/${s.benign}\n`);
    const missed = rows.filter((r) => r.shouldDetect && !r.detected);
    if (missed.length) {
      process.stdout.write(`    UNREACHABLE:\n`);
      for (const m of missed) process.stdout.write(`      ${m.id.padEnd(18)} want=${JSON.stringify(m.want)} got=${JSON.stringify(m.got)}\n`);
    }
    const partial = rows.filter((r) => r.shouldDetect && r.detected && r.rightReason === false);
    if (partial.length) {
      process.stdout.write(`    reached, but not every expected bucket fired:\n`);
      for (const m of partial) process.stdout.write(`      ${m.id.padEnd(18)} want=${JSON.stringify(m.want)} got=${JSON.stringify(m.got)}\n`);
    }
    const noisy = rows.filter((r) => !r.shouldDetect && r.detected);
    for (const m of noisy) process.stdout.write(`    FP ${m.id.padEnd(18)} got=${JSON.stringify(m.got)}\n`);
  }
  process.stdout.write(`\n  Note: the hook path appends its OWN event for the Read it is invoked on, so the window\n  under analysis is the corpus sample plus one ordinary local Read — which is what a real\n  deployment would see.\n\n`);
}
