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
import { readConsoleBackoff, backoffDelay, BACKOFF_BASE_MS, BACKOFF_CAP_MS } from "../cli/console-backoff.mjs";
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

test("E2E: a console that cannot be connected to is skipped by the next call: no fetch, no alert post", async () => {
  // Nothing listens on the port for the first call (connection refused); then a listener takes the port,
  // and the second call must open no connection to it at all.
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
    assert.equal(JSON.parse(readFileSync(state, "utf8")).unreachable, true);
    // The daily posture heartbeat is a detached worker the FIRST call spawned (not on the call's path), so
    // it may land here; every other request would come from the second call.
    const seen = [];
    bh = http.createServer((req, res) => { if (req.url !== "/api/agent-posture") seen.push(req.url.split("?")[0]); res.writeHead(200); res.end("{}"); });
    await new Promise((r) => bh.listen(port, "127.0.0.1", r));
    const second = await runHook(home);
    await new Promise((r) => setTimeout(r, 300));
    assert.match(second.stdout, /"permissionDecision":"deny"/, "the decision must not change under back-off");
    assert.deepEqual(seen, [], "the second call must not reach the console (no policy fetch, no alert post)");
  } finally { if (bh) { bh.closeAllConnections?.(); bh.close(); } rmTree(home); }
});

test("E2E: a console that connects but never answers: the next call skips the fetch, alerts are still posted", async () => {
  let policyRequests = 0;
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { policyRequests++; return; } // never answers
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => { if (req.url === "/api/alerts") alerts.push(b); res.writeHead(200); res.end("{}"); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { home, state } = sandbox(server.address().port);
  try {
    await runHook(home);
    const after1 = policyRequests;
    assert.ok(after1 >= 1, "the first call must have tried the console");
    assert.equal(JSON.parse(readFileSync(state, "utf8")).unreachable, false, "a console that accepted the connection is slow, not unreachable");
    const n = alerts.length;
    const second = await runHook(home);
    assert.match(second.stdout, /"permissionDecision":"deny"/);
    assert.equal(policyRequests, after1, "the second call must not fetch the policy");
    assert.ok(second.ms < 1400 + 1700, `the second call waits at most on its posts, took ${second.ms}ms`);
    assert.ok(alerts.length > n, "alert posts to a console that accepts connections keep being sent");
  } finally { server.closeAllConnections?.(); server.close(); rmTree(home); }
});

test("E2E: a future-dated back-off file is ignored, so the hook still fetches the policy", async () => {
  let policyRequests = 0;
  const server = http.createServer((req, res) => { if (req.url.startsWith("/api/policy")) { policyRequests++; return; } res.writeHead(200); res.end("{}"); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { home, state } = sandbox(server.address().port);
  try {
    writeFileSync(state, JSON.stringify({ failedAt: Date.now() + 365 * 86400_000, failures: 1, unreachable: true }));
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
