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
import http from "node:http";
import { readConsoleBackoff, backoffDelay, backoffSkipsFetch, BACKOFF_BASE_MS, BACKOFF_CAP_MS, FORCED_FETCH_ONE_IN } from "../cli/console-backoff.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const DENY_INPUT = { tool_name: "mcp__rogue__doThing", tool_input: { x: 1 }, hook_event_name: "PreToolUse" };

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-backoff-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-backoff-test" }));
  const cache = join(home, ".moorai", "hook-policy.json");
  writeFileSync(cache, JSON.stringify({ captureTier: "content-free", offlineMode: "fail-closed", mcpAllow: ["approved-only"] }));
  const old = (Date.now() - 2 * 3600 * 1000) / 1000;
  utimesSync(cache, old, old); // outside the 60s fresh window, so the hook wants to fetch
  return { home, state: join(home, ".moorai", "hook-console-backoff.json") };
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
  let policyRequests = 0;
  const alerts = [];
  const server = http.createServer((req, res) => {
    // A console that connects but never answers anything. Alerts are counted on receipt and never answered
    // either: an answered post would mean the console is reachable again, which rightly ends the back-off.
    if (/^\/api\/policy(\?|$)/.test(req.url)) { policyRequests++; return; }
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { if (req.url === "/api/alerts") alerts.push(b); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { home, state } = sandbox(server.address().port);
  try {
    await runHook(home);
    const after1 = policyRequests;
    assert.ok(after1 >= 1, "the first call must have tried the console");
    assert.ok(existsSync(state), "a fetch with no HTTP answer records the back-off");
    const ms = [];
    for (let i = 0; i < 8; i++) {
      const r = await runHook(home);
      assert.match(r.stdout, /"permissionDecision":"deny"/);
      ms.push(r.ms);
    }
    const fetched = policyRequests - after1;
    // expected one in eight; more than half would mean the window is not being honoured (p < 0.001)
    assert.ok(fetched <= 4, `calls under back-off fetched the policy ${fetched}/8 times`);
    const median = [...ms].sort((a, b) => a - b)[4];
    assert.ok(median < 1000, `the median call under back-off took ${median}ms: ${ms.join(", ")}`);
    for (let i = 0; i < 60 && alerts.length < 9; i++) await new Promise((r) => setTimeout(r, 100));
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
