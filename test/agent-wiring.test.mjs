// The six agent/behavioral detections (orphan agents, cross-agent messaging, trace gaps,
// velocity-burst, confused-deputy, subagent fan-out) exist in data/agent-detections.js and are run by
// runAgentDetections/agentBaselineReport — but before this file they were EFFECTIVELY UNREACHABLE:
//
//   * the ONLY caller outside the library was cli/moorai-agentwatch.mjs, an offline reporting CLI;
//   * inside that CLI, text mode rendered only orphans/crossAgent/traceGaps, and the summary guard
//     summed ONLY those three totals — so a window whose only finding was a confused-deputy pivot
//     printed "none in the current window" while --format json reported confusedDeputy:1. MEASURED:
//         {"orphans":0,"crossAgent":0,"traceGaps":0,"velocity":0,"confusedDeputy":1,"fanOut":0}
//         →  "  none in the current window"
//   * the --emit SIEM payload was built from assessSession() alone, so none of the six ever left the
//     device;
//   * nothing on the PreToolUse enforcement path ever called them, so a real deployment could neither
//     see nor act on them.
//
// These tests pin the wiring, and the constraints the wiring must not break:
//   1. agentwatch reports all six (the "none" bug), in text and in --emit.
//   2. The hook puts them on a production path — a finding in the recent window becomes a
//      content-free alert at the server.
//   3. That path is GATED (policy.agentDetections, default OFF — the thresholds are untuned).
//   4. It is OUT-OF-BAND: it must not add latency to, block, or throw into the tool-call decision.
//   5. It is NO_KEY-inert: an unenrolled device hashes every id to the h2:nokey sentinel, which
//      collapses the whole event graph onto one actor. Same trap the honeytoken guard exists for.
//   6. It is content-free: category / risk / hashed actor ids and counts only.
//
//   node --test test/agent-wiring.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const AGENTWATCH = join(ROOT, "cli", "moorai-agentwatch.mjs");
const CORPUS = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector5-memory-crossagent.json"), "utf8"));
const sample = (id) => CORPUS.attacks.find((a) => a.id === id) || CORPUS.benign.find((a) => a.id === id);

// A window whose ONLY finding is a confused-deputy pivot (read → ingest → egress to a fresh sink).
// This is the exact shape that printed "none in the current window".
const DEPUTY_ONLY = sample("v5-deputy-001").events;
// A window with a velocity burst and nothing else: one agent with a steady one-minute cadence (so the
// robust lower fence is positive — a jittery actor is deliberately not flaggable) then a machine-speed run.
const VELOCITY_ONLY = (() => {
  const evs = [];
  let t = 0;
  for (let i = 0; i < 20; i++) { evs.push({ ts: (t += 60000), sig: "Bash|v1", agent: "v1", session: "vs", ok: true, risk: "Low" }); }
  for (let i = 0; i < 3; i++) { evs.push({ ts: (t += 50), sig: "Bash|v1", agent: "v1", session: "vs", ok: true, risk: "Low" }); }
  return evs;
})();
// A parent that spawns 7 distinct children — subagent fan-out, with no population to compare against.
const FANOUT_ONLY = (() => {
  const evs = [];
  for (let i = 0; i < 7; i++) evs.push({ ts: 1000 + i * 1000, sig: `Bash|c${i}`, agent: `c${i}`, parent: "p0", session: "fs", role: "subagent", ok: true, risk: "Low" });
  evs.push({ ts: 500, sig: "Task|p0", agent: "p0", session: "fs", ok: true, risk: "Low" });
  return evs;
})();

// ---- sandbox: a throwaway HOME + a listener that serves a policy and records every alert ----
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

// `enrolled: false` writes NO installToken → contentHash() collapses to the h2:nokey sentinel.
function sandbox({ port, events = [], enrolled = true, fileText = "hello world\n" } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-agentwire-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({
    serverUrl: port ? `http://127.0.0.1:${port}` : "http://127.0.0.1:1",
    tenant: "acme",
    ...(enrolled ? { installToken: "tok-agent-wiring-test" } : {})
  }));
  if (events.length) writeFileSync(join(home, ".moorai", "agent-events.jsonl"), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
  const file = join(home, "sample.txt");
  writeFileSync(file, fileText);
  return { home, file };
}

function run(bin, args, env, stdin) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const c = spawn(process.execPath, [bin, ...args], { cwd: ROOT, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    c.on("close", (code) => resolve({ ms: Number(process.hrtime.bigint() - t0) / 1e6, out, err, code }));
    if (stdin != null) c.stdin.end(stdin); else c.stdin.end();
  });
}
const readPayload = (file) => JSON.stringify({ tool_name: "Read", tool_input: { file_path: file }, session_id: "sess-1" });
const median = (a) => a.slice().sort((x, y) => x - y)[Math.floor(a.length / 2)];
const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
const ON = { agentDetections: true, captureTier: "content-free", threatPolicy: {} };
const OFF = { captureTier: "content-free", threatPolicy: {} };

// ================================================================================================
// 1. THE agentwatch REPORTING BUG — a finding that exists but prints "none" is worse than none
// ================================================================================================

test("BUG: a confused-deputy-only window must NOT report 'none in the current window'", async () => {
  const { home } = sandbox({ events: DEPUTY_ONLY });
  const json = JSON.parse((await run(AGENTWATCH, ["--format", "json"], { HOME: home, USERPROFILE: home })).out);
  assert.deepEqual(json.baseline.totals, { orphans: 0, crossAgent: 0, traceGaps: 0, velocity: 0, confusedDeputy: 1, fanOut: 0 },
    "precondition: this window's only finding is a confused-deputy pivot");
  const text = strip((await run(AGENTWATCH, [], { HOME: home, USERPROFILE: home })).out);
  assert.doesNotMatch(text, /none in the current window/,
    "the summary guard sums only orphans+crossAgent+traceGaps, so a confused-deputy-only window reports 'none'");
  assert.match(text, /#confused-deputy/, "text mode must RENDER the confused-deputy finding, not just count it");
});

test("BUG: text mode must render velocity-burst findings, not only --format json", async () => {
  const { home } = sandbox({ events: VELOCITY_ONLY });
  const json = JSON.parse((await run(AGENTWATCH, ["--format", "json"], { HOME: home, USERPROFILE: home })).out);
  assert.ok(json.baseline.totals.velocity > 0, `precondition: window must contain a velocity burst; got ${JSON.stringify(json.baseline.totals)}`);
  const text = strip((await run(AGENTWATCH, [], { HOME: home, USERPROFILE: home })).out);
  assert.doesNotMatch(text, /none in the current window/);
  assert.match(text, /#velocity-burst/);
});

test("BUG: text mode must render fan-out findings, not only --format json", async () => {
  const { home } = sandbox({ events: FANOUT_ONLY });
  const json = JSON.parse((await run(AGENTWATCH, ["--format", "json"], { HOME: home, USERPROFILE: home })).out);
  assert.ok(json.baseline.totals.fanOut > 0, `precondition: window must contain a fan-out anomaly; got ${JSON.stringify(json.baseline.totals)}`);
  const text = strip((await run(AGENTWATCH, [], { HOME: home, USERPROFILE: home })).out);
  assert.doesNotMatch(text, /none in the current window/);
  assert.match(text, /#fan-out-anomaly/);
});

test("a genuinely empty window still reports 'none in the current window'", async () => {
  const { home } = sandbox({ events: [{ ts: 1000, sig: "Read|q1", agent: "q1", session: "qs", ok: true, risk: "Low" }] });
  const text = strip((await run(AGENTWATCH, [], { HOME: home, USERPROFILE: home })).out);
  assert.match(text, /none in the current window/, "the guard must not be fixed by making it always claim a finding");
});

// ================================================================================================
// 2. --emit MUST CARRY THE SIX TO THE SIEM
// ================================================================================================

test("EMIT: the SIEM payload carries the six detections, not just assessSession", async () => {
  const { srv, port, alerts } = await startServer(OFF);
  try {
    const { home } = sandbox({ port, events: DEPUTY_ONLY });
    await run(AGENTWATCH, ["--emit", "--format", "json"], { HOME: home, USERPROFILE: home });
    await new Promise((r) => setTimeout(r, 600));
    const a = alerts.find((x) => x.detections);
    assert.ok(a, `--emit must send the detections; got categories ${JSON.stringify(alerts.map((x) => x.category))}`);
    const d = a.detections;
    assert.equal(d.confusedDeputy.length, 1, "the confused-deputy finding must reach the SIEM");
    assert.deepEqual(Object.keys(d).sort(), ["confusedDeputy", "crossAgent", "fanOut", "orphans", "traceGaps", "velocity"].sort());
    assert.deepEqual(Object.keys(d.confusedDeputy[0]).sort(), ["agent", "count", "severity", "type"].sort(),
      "the SIEM payload must be the same fixed content-free projection the hook posts, not the raw evidence");
  } finally { srv.close(); }
});

// ================================================================================================
// 3. THE PRODUCTION PATH — the hook must surface a window finding as a content-free alert
// ================================================================================================

async function hookRun(policy, opts) {
  const { srv, port, alerts } = await startServer(policy);
  const sb = sandbox({ port, ...opts });
  const r = await run(HOOK, [], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, readPayload(sb.file));
  await new Promise((rr) => setTimeout(rr, 2000)); // let the out-of-band worker finish and POST
  srv.close();
  return { alerts, ...r, home: sb.home };
}
const agentAlerts = (alerts) => alerts.filter((a) => String(a.category || "").startsWith("Agent behavior:"));

test("PRODUCTION PATH: a confused-deputy pivot in the recent window reaches the server via the hook", async () => {
  const { alerts } = await hookRun(ON, { events: DEPUTY_ONLY });
  const got = agentAlerts(alerts);
  assert.ok(got.length >= 1, `the hook must surface the finding; got ${JSON.stringify(alerts.map((a) => a.category))}`);
  assert.ok(got.some((a) => a.detection && a.detection.type === "confused-deputy"), `expected a confused-deputy alert; got ${JSON.stringify(got.map((a) => a.detection))}`);
});

test("PRODUCTION PATH: orphan-agent and trace-gap windows also reach the server", async () => {
  for (const [id, type] of [["v5-orphan-001", "orphan-agent"], ["v5-gap-001", "trace-gap"]]) {
    const { alerts } = await hookRun(ON, { events: sample(id).events });
    const got = agentAlerts(alerts);
    assert.ok(got.some((a) => a.detection && a.detection.type === type), `${id}: expected a ${type} alert; got ${JSON.stringify(got.map((a) => a.detection))}`);
  }
});

test("CONTENT-FREE: an agent-behavior alert carries only category/risk/ids/counts", async () => {
  const { alerts } = await hookRun(ON, { events: DEPUTY_ONLY });
  const a = agentAlerts(alerts)[0];
  assert.ok(a, "no agent-behavior alert to inspect");
  assert.deepEqual(Object.keys(a.detection).sort(), ["agent", "count", "severity", "type"].sort(),
    "the detection payload must be a fixed, content-free projection — never the raw evidence object");
  assert.match(a.contentHash, /^agentdet:/);
  const blob = JSON.stringify(a);
  for (const leak of ["hello world", "sample.txt", "/var/folders", "/tmp"]) {
    assert.equal(blob.includes(leak), false, `alert leaked ${leak}`);
  }
});

test("GATING: with policy.agentDetections absent (the default) nothing is surfaced", async () => {
  const { alerts } = await hookRun(OFF, { events: DEPUTY_ONLY });
  assert.deepEqual(agentAlerts(alerts), [], "the six are threshold-untuned; they must be opt-in, not on by default");
});

// Driven through the WORKER directly (`moorai-hook.mjs agentscan`) rather than through repeated hook
// invocations, so the hot-path throttle cannot stand in for the seen-set and make these pass vacuously.
const scan = (home) => run(HOOK, ["agentscan", "Read"], { HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" });

test("DEDUP: a standing finding alerts once, not on every scan", async () => {
  const { srv, port, alerts } = await startServer(ON);
  try {
    const sb = sandbox({ port, events: DEPUTY_ONLY });
    for (let i = 0; i < 3; i++) { await scan(sb.home); await new Promise((r) => setTimeout(r, 400)); }
    const got = agentAlerts(alerts).filter((a) => a.detection.type === "confused-deputy");
    assert.equal(got.length, 1, `a standing finding must alert once, not once per scan; got ${got.length}`);
  } finally { srv.close(); }
});

test("THROTTLE: repeated tool calls do not spawn a scanner each time", async () => {
  const { srv, port, alerts } = await startServer(ON);
  try {
    // A window that would alert on EVERY scan if one ran: each hook call appends its own event, and a
    // fresh seen-set would let a new severity through. The throttle is what keeps this to one scan.
    const sb = sandbox({ port, events: DEPUTY_ONLY });
    const env = { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" };
    const stamp = join(sb.home, ".moorai", "agent-scan.stamp");
    await run(HOOK, [], env, readPayload(sb.file));
    assert.ok(existsSync(stamp), "the hot path must record when it last handed off a scan");
    const first = statSync(stamp).mtimeMs;
    for (let i = 0; i < 3; i++) { await new Promise((r) => setTimeout(r, 700)); await run(HOOK, [], env, readPayload(sb.file)); }
    assert.equal(statSync(stamp).mtimeMs, first, "three further tool calls inside the interval must hand off no further scan");
    await new Promise((r) => setTimeout(r, 1500));
    assert.ok(agentAlerts(alerts).length >= 1, "the FIRST call must still scan — the throttle must not suppress the initial hand-off");
  } finally { srv.close(); }
});

test("COLLAPSE: many findings sharing one type|agent|severity produce ONE alert, not one per row", async () => {
  // detectTraceGaps emits one finding PER GAP, so a single choppy trace is dozens of rows for one
  // condition. MEASURED before the collapse: a 400-event window produced 379 trace-gap findings over
  // 8 distinct keys and the layer posted 71 alerts across 7 tool calls (the burst cap draining).
  const { srv, port, alerts } = await startServer(ON);
  try {
    const big = [];
    for (let i = 0; i < 400; i++) big.push({ ts: 1000 + i * 500, sig: `Bash|a${i % 7}`, agent: `a${i % 7}`, session: `s${i % 3}`, ok: true, risk: "Low", legs: { read: i % 3 === 0, ingest: i % 5 === 0, callout: i % 7 === 0 }, server: `srv${i % 4}`, seq: i, ...(i % 11 === 0 ? { role: "subagent", parent: `a${(i + 1) % 7}` } : {}) });
    const sb = sandbox({ port, events: big });
    const per = [];
    for (let i = 0; i < 4; i++) { const b = alerts.length; await scan(sb.home); await new Promise((r) => setTimeout(r, 500)); per.push(agentAlerts(alerts.slice(b)).length); }
    const got = agentAlerts(alerts);
    const keys = new Set(got.map((a) => `${a.detection.type}|${a.detection.agent}|${a.detection.severity}`));
    assert.equal(got.length, keys.size, `one alert per condition, not per row; ${got.length} alerts for ${keys.size} keys (per call: ${JSON.stringify(per)})`);
    assert.ok(per.slice(1).every((n) => n === 0), `the stream must converge, not drain a queue for calls on end; per call: ${JSON.stringify(per)}`);
  } finally { srv.close(); }
});

// ================================================================================================
// 4. OUT-OF-BAND: it must not delay, block, or throw into the tool-call decision
// ================================================================================================

test("HOT PATH: enabling the agent detections must not add measurable latency to the decision", async () => {
  const on = await startServer(ON), off = await startServer(OFF);
  // A full 400-event window (the cap in cli/signals.mjs) in BOTH sandboxes, so the only difference
  // is the flag, not the amount of data on disk.
  const big = [];
  for (let i = 0; i < 400; i++) big.push({ ts: 1000 + i * 500, sig: `Bash|a${i % 7}`, agent: `a${i % 7}`, session: `s${i % 3}`, ok: true, risk: "Low", legs: { read: i % 3 === 0, ingest: i % 5 === 0, callout: i % 7 === 0 }, server: `srv${i % 4}`, seq: i, ...(i % 11 === 0 ? { role: "subagent", parent: `a${(i + 1) % 7}` } : {}) });
  // A FRESH sandbox per iteration on both sides, so the hot-path throttle never suppresses a hand-off:
  // every ON iteration pays the full stat + stamp + spawn, which is the cost under test.
  const once = async (port) => {
    const sb = sandbox({ port, events: big });
    const r = await run(HOOK, [], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, readPayload(sb.file));
    return r.ms;
  };
  try {
    await once(on.port); await once(off.port); // warm node + the policy fetch path
    const onMs = [], offMs = [];
    for (let i = 0; i < 5; i++) { offMs.push(await once(off.port)); onMs.push(await once(on.port)); }
    const delta = median(onMs) - median(offMs);
    assert.ok(delta < 200, `the detections must not gate the tool call: off=${median(offMs).toFixed(0)}ms on=${median(onMs).toFixed(0)}ms delta=${delta.toFixed(0)}ms`);
  } finally { on.srv.close(); off.srv.close(); }
});

test("SEAM: the hot path hands the window analysis off — it must not run it itself", () => {
  const src = readFileSync(HOOK, "utf8");
  const i = src.indexOf("function maybeAgentScan");
  assert.ok(i > 0, "maybeAgentScan (the hot-path seam) not found");
  const body = src.slice(i, src.indexOf("\n}", i));
  assert.doesNotMatch(body, /agentBaselineReport\(/, "the hot path must not build the report itself");
  assert.doesNotMatch(body, /runAgentDetections\(/, "the hot path must not run the detectors itself");
  assert.match(body, /spawn\(/, "the hot path must hand the scan to a detached worker");
});

test("FAIL-OPEN: a corrupt event window and a throwing scan cannot change or block the decision", async () => {
  // A file the policy BLOCKS, so the decision under test is a real deny, not an allow.
  const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  const denyOn = { ...ON, threatPolicy: { 39: "block" } };
  const denyOff = { ...OFF, threatPolicy: { 39: "block" } };
  const s1 = await startServer(denyOn), s2 = await startServer(denyOff);
  try {
    // Garbage on every line of the event log: the scan must swallow it, not take the hook down.
    const junk = [{ ts: "not-a-number", sig: null }, { ts: NaN }, {}, { legs: "nope", flags: 7, agent: {} }];
    const a = sandbox({ port: s1.port, events: junk, fileText: AWS });
    const b = sandbox({ port: s2.port, events: junk, fileText: AWS });
    writeFileSync(join(a.home, ".moorai", "agent-events.jsonl"), "{not json at all\n[]\nnull\n");
    const ra = await run(HOOK, [], { HOME: a.home, USERPROFILE: a.home, MOORAI_OFFLINE_MODE: "" }, readPayload(a.file));
    const rb = await run(HOOK, [], { HOME: b.home, USERPROFILE: b.home, MOORAI_OFFLINE_MODE: "" }, readPayload(b.file));
    assert.equal(ra.code, 0, `the hook must always exit 0 (governance, fail-open); stderr=${ra.err}`);
    assert.match(ra.out, /"permissionDecision":"deny"/, "the deny must still be emitted with the detections on");
    assert.equal(ra.out, rb.out, "the detections layer must not change the enforcement output");
  } finally { s1.srv.close(); s2.srv.close(); }
});

// ================================================================================================
// 5. NO_KEY INERTNESS — an unenrolled device must produce no behavioural noise
// ================================================================================================

test("NO_KEY: an unenrolled device surfaces no agent-behavior alerts", async () => {
  const { srv, port, alerts } = await startServer(ON);
  try {
    // Same window that fires on an enrolled device — but no installToken, so contentHash() collapses
    // every id to h2:nokey and the whole event graph becomes one actor.
    const sb = sandbox({ port, events: DEPUTY_ONLY, enrolled: false });
    await run(HOOK, [], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, readPayload(sb.file));
    await new Promise((r) => setTimeout(r, 2000));
    assert.deepEqual(agentAlerts(alerts), [], "an unenrolled device must be inert, not noisy (see the honeytoken guard)");
  } finally { srv.close(); }
});

test("NO_KEY: a window whose ids ARE the sentinel produces no alert even when enrolled", async () => {
  const { srv, port, alerts } = await startServer(ON);
  try {
    // Events recorded BEFORE enrollment: every id is the sentinel. Enrolling later must not turn that
    // legacy window into a storm of phantom cross-agent / trace-gap findings.
    const nokey = DEPUTY_ONLY.map((e) => ({ ...e, agent: "h2:nokey", session: "h2:nokey", sig: e.sig.split("|")[0] + "|h2:nokey" }));
    const sb = sandbox({ port, events: nokey });
    await run(HOOK, [], { HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "" }, readPayload(sb.file));
    await new Promise((r) => setTimeout(r, 2000));
    assert.deepEqual(agentAlerts(alerts).map((a) => a.detection), [], "sentinel-keyed findings must be dropped");
  } finally { srv.close(); }
});
