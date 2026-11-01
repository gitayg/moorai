// Console back-off (cli/console-backoff.mjs). Measured before the fix: with the console silently
// dropping packets and a policy cache older than 60s, EVERY hook call paid the 1.5s policy-fetch timeout
// plus the 1.5s posture post (allow ~3.2s, deny ~4.6s over 20 calls), because a failed fetch left nothing
// behind and the next call retried. These cases spawn the hook for real against a local console that
// refuses, or accepts and never answers, and count what reaches it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, utimesSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import net from "node:net";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { readConsoleBackoff, backoffDelay, backoffSkipsFetch, BACKOFF_BASE_MS, BACKOFF_CAP_MS, FORCED_FETCH_ONE_IN } from "../cli/console-backoff.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const DENY_INPUT = { tool_name: "mcp__rogue__doThing", tool_input: { x: 1 }, hook_event_name: "PreToolUse" };

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-backoff-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  // A token of its own per sandbox, so a console can count only the requests of THIS sandbox's hooks and
  // not a stray process from another test that was configured with a port the OS has since reused.
  const token = `tok-backoff-${randomBytes(6).toString("hex")}`;
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: token }));
  const cache = join(home, ".moorai", "hook-policy.json");
  writeFileSync(cache, JSON.stringify({ captureTier: "content-free", offlineMode: "fail-closed", mcpAllow: ["approved-only"] }));
  const old = (Date.now() - 2 * 3600 * 1000) / 1000;
  utimesSync(cache, old, old); // outside the 60s fresh window, so the hook wants to fetch
  return { home, token, state: join(home, ".moorai", "hook-console-backoff.json") };
}

async function runHook(home, input = DENY_INPUT) {
  const t0 = Date.now();
  const child = spawn(process.execPath, [HOOK], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let stdout = "";
  child.stdout.on("data", (c) => (stdout += c));
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify(input));
  const code = await new Promise((r) => child.on("exit", r));
  return { code, stdout, ms: Date.now() - t0 };
}

test("UNIT: the window doubles from 60s and is capped at 5 minutes", () => {
  assert.equal(backoffDelay(1), BACKOFF_BASE_MS);
  assert.equal(backoffDelay(2), 2 * BACKOFF_BASE_MS);
  assert.equal(backoffDelay(3), 4 * BACKOFF_BASE_MS);
  assert.equal(backoffDelay(4), BACKOFF_CAP_MS);
  assert.equal(backoffDelay(32), BACKOFF_CAP_MS);
});

test("UNIT: a planted state file cannot extend the back-off beyond the cap", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-backoff-unit-"));
  const f = join(dir, "s.json");
  const now = 1_800_000_000_000;
  writeFileSync(f, JSON.stringify({ failedAt: now + 3600_000, failures: 1 }));
  assert.equal(readConsoleBackoff(now, f).active, false, "a failure time in the future must be ignored");
  writeFileSync(f, JSON.stringify({ failedAt: now - BACKOFF_CAP_MS - 1, failures: 1e9 }));
  assert.equal(readConsoleBackoff(now, f).active, false, "a huge failure count must not stretch the window past the cap");
  writeFileSync(f, JSON.stringify({ failedAt: now - 1000, failures: 1 }));
  assert.equal(readConsoleBackoff(now, f).active, true);
  writeFileSync(f, "{not json");
  assert.equal(readConsoleBackoff(now, f).active, false);
  rmTree(dir);
});

test("UNIT: inside the window the fetch is skipped except on the forced draw; outside it, never", () => {
  assert.equal(backoffSkipsFetch({ active: false, failures: 0 }, () => 5), false);
  assert.equal(backoffSkipsFetch({ active: true, failures: 3 }, () => 5), true);
  assert.equal(backoffSkipsFetch({ active: true, failures: 3 }, () => 0), false, "the forced draw fetches whatever the file says");
  assert.equal(backoffSkipsFetch(null), false);
  // the real draw: over many calls roughly one in FORCED_FETCH_ONE_IN fetches
  let forced = 0;
  for (let i = 0; i < 8000; i++) if (!backoffSkipsFetch({ active: true, failures: 9 })) forced++;
  assert.ok(forced > 8000 / FORCED_FETCH_ONE_IN / 2 && forced < 8000 / FORCED_FETCH_ONE_IN * 2, `forced fetches: ${forced}`);
});

test("E2E: after a console that cannot be connected to, the next call still delivers its alert and keeps its decision", async () => {
  // Nothing listens on the port for the first call (connection refused); then a listener takes the port.
  // The second call either skips the fetch (and its alert goes out through the detached worker) or draws
  // the forced fetch (and posts inline): both deliver the alert.
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const { home, state } = sandbox(port);
  let bh = null;
  try {
    const first = await runHook(home);
    assert.match(first.stdout, /"permissionDecision":"deny"/);
    assert.ok(existsSync(state), "a fetch with no response must record the back-off");
    assert.equal(JSON.parse(readFileSync(state, "utf8")).failures, 1);
    const alerts = [];
    // Only alerts are accepted: the policy route answers 404, so a forced fetch on the second call keeps the
    // cached policy (an empty 200 body would be a new, empty policy and change the decision for that reason).
    bh = http.createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { if (req.url === "/api/alerts") { alerts.push(b); res.writeHead(200); res.end("{}"); } else { res.writeHead(404); res.end(); } }); });
    await new Promise((r) => bh.listen(port, "127.0.0.1", r));
    const second = await runHook(home);
    assert.match(second.stdout, /"permissionDecision":"deny"/, "the decision must not change under back-off");
    for (let i = 0; i < 40 && !alerts.length; i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(alerts.length >= 1, "the second call's alert must reach the console");
  } finally { if (bh) { bh.closeAllConnections?.(); bh.close(); } rmTree(home); }
});

test("QUIET: a console that connects but never answers keeps the latency back-off; alerts still arrive", async () => {
  // Policy requests are counted per hook call (the calls run one after another, and the scan workers never
  // fetch: WORKER below), and only when they carry this sandbox's own install token.
  let policyRequests = 0, token = "";
  const alerts = [];
  const server = http.createServer((req, res) => {
    // A console that connects but never answers anything. Alerts are counted on receipt and never answered
    // either: an answered post would mean the console is reachable again, which rightly ends the back-off.
    if (/^\/api\/policy(\?|$)/.test(req.url)) { if (req.headers["x-install-token"] === token) policyRequests++; return; }
    // The alert outbox's worker posts in batches (POST /api/alerts/batch): each alert in a batch counts.
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      if (req.headers["x-install-token"] !== token) return;
      if (req.url === "/api/alerts") alerts.push(b);
      if (req.url === "/api/alerts/batch") { try { for (const a of JSON.parse(b).alerts) alerts.push(JSON.stringify(a)); } catch { /* ignore */ } }
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const sb = sandbox(server.address().port);
  const { home, state } = sb;
  token = sb.token;
  try {
    await runHook(home);
    assert.ok(policyRequests >= 1, "the first call must have tried the console");
    assert.ok(existsSync(state), "a fetch with no HTTP answer records the back-off");
    const calls = [];
    for (let i = 0; i < 8; i++) {
      const before = policyRequests;
      const r = await runHook(home);
      assert.match(r.stdout, /"permissionDecision":"deny"/);
      calls.push({ fetched: policyRequests > before, ms: r.ms });
    }
    const fetched = calls.filter((c) => c.fetched).length;
    // expected one in eight (the forced draw); more than half would mean the window is not being honoured
    // (p < 0.001). The latency win is this count: a call that fetched waited out the 1.5s timeout (this
    // console never answers), a call that did not fetch had nothing to wait for. Wall-clock time is
    // reported, not asserted: on a loaded runner a bare hook spawn alone has been measured above 1s.
    assert.ok(fetched <= 4, `calls under back-off fetched the policy ${fetched}/8 times (ms: ${calls.map((c) => `${c.ms}${c.fetched ? "F" : ""}`).join(", ")})`);
    // The alerts go out through the outbox's detached worker, whose own budget is 10s per request: its first
    // batch waits that out, then every alert queued meanwhile gets its first attempt. Poll up to that.
    for (let i = 0; i < 150 && alerts.length < 9; i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(alerts.length >= 9, `every deny alert reached the console: ${alerts.length}/9`);
  } finally { server.closeAllConnections?.(); server.close(); rmTree(home); }
});

test("E2E: a future-dated back-off file is ignored, so the hook still fetches the policy", async () => {
  let policyRequests = 0;
  const server = http.createServer((req, res) => { if (req.url.startsWith("/api/policy")) { policyRequests++; return; } res.writeHead(200); res.end("{}"); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { home, state } = sandbox(server.address().port);
  try {
    writeFileSync(state, JSON.stringify({ failedAt: Date.now() + 365 * 86400_000, failures: 1 }));
    await runHook(home);
    assert.ok(policyRequests >= 1, "a planted future failure time must not suppress the policy fetch");
  } finally { server.closeAllConnections?.(); server.close(); rmTree(home); }
});

test("E2E: a console that answers clears the back-off", async () => {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free", mcpAllow: ["approved-only"] })); return; }
    res.writeHead(200); res.end("{}");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { home, state } = sandbox(server.address().port);
  try {
    // An expired window (failures=1 → 60s, failed two minutes ago): the hook fetches, gets an answer.
    writeFileSync(state, JSON.stringify({ failedAt: Date.now() - 120_000, failures: 1 }));
    const r = await runHook(home);
    assert.match(r.stdout, /"permissionDecision":"deny"/);
    assert.equal(existsSync(state), false, `a successful fetch must reset the back-off: ${existsSync(state) ? readFileSync(state, "utf8") : ""}`);
  } finally { server.close(); rmTree(home); }
});

// The back-off file is in ~/.moorai, which the governed agent can write. v1.12.0 skipped BOTH the policy
// fetch and every alert post while it read active with unreachable:true, so an agent that rewrote it every
// few minutes silenced the device's alerts and froze its policy, with the console up the whole time.
test("TRUST: a planted back-off file rewritten before every call silences no alert of a reachable console", async () => {
  let policyRequests = 0;
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy?")) { policyRequests++; res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free", mcpAllow: ["approved-only"] })); return; }
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { if (req.url === "/api/alerts") alerts.push(b); res.writeHead(200); res.end("{}"); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { home, state } = sandbox(server.address().port);
  try {
    for (let i = 0; i < 3; i++) {
      // rewritten before every call, as an agent looping on it would
      writeFileSync(state, JSON.stringify({ failedAt: Date.now() - 1000, failures: 4, unreachable: true }));
      const r = await runHook(home);
      assert.match(r.stdout, /"permissionDecision":"deny"/);
    }
    for (let i = 0; i < 40 && alerts.length < 3; i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(alerts.length >= 3, `the deny alerts reached the console: ${alerts.length}`);
  } finally { server.closeAllConnections?.(); server.close(); rmTree(home); }
});

// In process, with the forced-fetch draw fixed, so the wiring is pinned without depending on the RNG.
test("TRUST: under a planted back-off file, the forced draw fetches the policy; otherwise the fetch waits and alerts are deferred, not dropped", async () => {
  const { loadVerifiedPolicy, POLICY_CACHE } = await import("../cli/hook-core.mjs");
  const { CONSOLE_BACKOFF } = await import("../cli/console-backoff.mjs");
  let policyRequests = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy?")) { policyRequests++; res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free", mcpAllow: ["approved-only"] })); return; }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const config = { serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: "acme", installToken: "tok-inproc" };
  try {
    mkdirSync(dirname(POLICY_CACHE), { recursive: true });
    const plant = () => writeFileSync(CONSOLE_BACKOFF, JSON.stringify({ failedAt: Date.now() - 1000, failures: 4 }));
    plant();
    const skipped = await loadVerifiedPolicy(config, { backoffDraw: () => 5 });
    assert.equal(policyRequests, 0, "a non-forced draw inside the window skips the fetch");
    assert.equal(skipped.deferAlerts, true, "and the call's alerts are handed to the worker, not dropped");
    plant();
    const forced = await loadVerifiedPolicy(config, { backoffDraw: () => 0 });
    assert.equal(policyRequests, 1, "the forced draw fetches whatever the planted file says");
    assert.equal(forced.source, "fresh");
    assert.ok(!forced.deferAlerts, "a call that got its answer posts inline");
    assert.equal(existsSync(CONSOLE_BACKOFF), false, "and the answer clears the planted file");
  } finally { server.closeAllConnections?.(); server.close(); }
});

// WORKER: the detached agentscan/indexscan workers re-read the policy only to re-check their own gate.
// MEASURED under CPU contention (node:22, --cpus=1, --test-concurrency=4, instrumented loadVerifiedPolicy):
// the indexscan worker a hook spawns ran its own policy fetch AFTER the test's console had closed, got
// ECONNREFUSED and recorded a console back-off in that HOME, so the NEXT hook call skipped the fetch that
// would have delivered the new policy and enforced the cached or last-known-good one instead. That is the
// stdout-was-"" / relaxed-policy-must-apply failures CI hit in policy-lkg, policy-pin and
// policy-revocation from v1.13.0 on. The worker is run here directly, so no timing is involved.
async function runWorker(home, args) {
  const child = spawn(process.execPath, [HOOK, ...args], { cwd: ROOT, stdio: ["ignore", "ignore", "ignore"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  return new Promise((r) => child.on("exit", r));
}

test("WORKER: a detached scan worker never fetches the policy and never records a console back-off", async () => {
  // Nothing listens: before the fix the worker's fetch failed and wrote the back-off file.
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const { home, state } = sandbox(port);
  try {
    for (const w of ["indexscan", "agentscan"]) {
      await runWorker(home, [w]);
      assert.equal(existsSync(state), false, `the ${w} worker recorded a console back-off: ${existsSync(state) ? readFileSync(state, "utf8") : ""}`);
    }
  } finally { rmTree(home); }

  // A console that answers: before the fix every worker spawn was a second policy request.
  let policyRequests = 0;
  const server = http.createServer((req, res) => { if (/^\/api\/policy(\?|\/|$)/.test(req.url)) policyRequests++; res.writeHead(404); res.end(); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const sb = sandbox(server.address().port);
  try {
    for (const w of ["indexscan", "agentscan"]) await runWorker(sb.home, [w]);
    assert.equal(policyRequests, 0, `the workers fetched the policy ${policyRequests} times`);
  } finally { server.closeAllConnections?.(); server.close(); rmTree(sb.home); }
});

test("WORKER: network:false resolves from the verified local copies, with no request and no state written", async () => {
  const { loadVerifiedPolicy, POLICY_CACHE } = await import("../cli/hook-core.mjs");
  const { CONSOLE_BACKOFF } = await import("../cli/console-backoff.mjs");
  let requests = 0;
  const server = http.createServer((req, res) => { requests++; res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free", mcpAllow: ["from-the-network"] })); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const config = { serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: "acme", installToken: "tok-worker" };
  try {
    mkdirSync(dirname(POLICY_CACHE), { recursive: true });
    writeFileSync(POLICY_CACHE, JSON.stringify({ captureTier: "content-free", mcpAllow: ["from-the-cache"] }));
    const old = (Date.now() - 2 * 3600 * 1000) / 1000;
    utimesSync(POLICY_CACHE, old, old); // outside the 60s window: the networked path would fetch
    const r = await loadVerifiedPolicy(config, { network: false });
    assert.equal(requests, 0, "no request may reach the console");
    assert.deepEqual(r.policy.mcpAllow, ["from-the-cache"]);
    assert.equal(r.source, "cache-offline");
    assert.equal(existsSync(CONSOLE_BACKOFF), false, "no back-off may be written");
    // The control: the same call with the network fetches and gets the console's policy.
    const live = await loadVerifiedPolicy(config);
    assert.equal(requests >= 1, true);
    assert.deepEqual(live.policy.mcpAllow, ["from-the-network"]);
  } finally { server.closeAllConnections?.(); server.close(); }
});
