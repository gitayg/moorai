// FIX 1 — alerts from the main enforcement path must actually REACH the server.
//
// The bug, measured before the fix with exactly the harness below: report() called post() without
// awaiting, and emit() then called process.exit(0), which tore the process down before the HTTP
// request was written. One Bash tool call containing an AWS key produced
//
//     local action-audit.jsonl : 1 line — "Information & Privacy"   (the finding DID fire)
//     ALERTS RECEIVED: 0
//
// so the SOC received nothing at all from Read / Bash / MCP / Task findings. Only the handful of
// AWAITED postPosture() calls survived.
//
// These are deliberately NOT "does post() return a promise" unit tests. A returned promise proves
// nothing about delivery; the assertion that matters is that a real hook invocation, against a real
// listener, leaves an alert on the wire. Every case here spawns cli/moorai-hook.mjs for real.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

// An AWS secret-access-key pair — a shape the built-in detectors classify as "Information & Privacy".
const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Spawn the hook against a throwaway HOME and a listener that records every POST /api/alerts.
// `policy` is served fresh at /api/policy (unsigned — this device holds no anchor and no pin, so it
// is trusted as "unanchored", which is the ordinary un-enrolled install).
async function runHook(input, { policy = { captureTier: "content-free" } } = {}) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(policy)); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  const home = mkdtempSync(join(tmpdir(), "moorai-alert-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme" }));

  const child = spawn(process.execPath, [HOOK], {
    cwd: ROOT,
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" }
  });
  let stdout = "";
  child.stdout.on("data", (c) => (stdout += c));
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify(input));
  const code = await new Promise((r) => child.on("exit", r));

  // Generous grace period AFTER exit. If the process had merely orphaned an in-flight request, this
  // is where it would land — so an empty `alerts` here is a real loss, not a race in the test.
  await new Promise((r) => setTimeout(r, 1200));

  const auditPath = join(home, ".moorai", "action-audit.jsonl");
  const audit = existsSync(auditPath) ? readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  server.close();
  rmSync(home, { recursive: true, force: true });
  return { code, stdout, alerts, audit };
}

test("DELIVERY: a Bash finding reaches the server, not just the local audit log", async () => {
  const r = await runHook({ tool_name: "Bash", tool_input: { command: `echo ${AWS}` } });
  assert.equal(r.code, 0);
  // The local ledger proves the finding fired — this line was present even WITH the bug.
  assert.ok(r.audit.some((a) => a.category === "Information & Privacy"), `no local finding: ${JSON.stringify(r.audit)}`);
  // ...and this is the half that was silently lost.
  assert.ok(r.alerts.length > 0, "the hook exited before any alert reached the server");
  assert.ok(r.alerts.some((a) => a.category === "Information & Privacy"),
    `finding never reached the server: ${JSON.stringify(r.alerts.map((a) => a.category))}`);
});

test("DELIVERY: a Read finding reaches the server", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-read-"));
  const f = join(dir, "creds.txt");
  writeFileSync(f, AWS);
  const r = await runHook({ tool_name: "Read", tool_input: { file_path: f } });
  rmSync(dir, { recursive: true, force: true });
  assert.equal(r.code, 0);
  assert.ok(r.alerts.some((a) => a.category === "Information & Privacy"),
    `finding never reached the server: ${JSON.stringify(r.alerts.map((a) => a.category))}`);
});

test("DELIVERY: an MCP DENY alert survives the emit() exit", async () => {
  // A denied server short-circuits straight into emit("deny") — the tightest race in the file.
  const r = await runHook(
    { tool_name: "mcp__rogue__doThing", tool_input: { x: 1 } },
    { policy: { captureTier: "content-free", mcpAllow: ["approved-only"] } }
  );
  assert.match(r.stdout, /"permissionDecision":"deny"/, r.stdout);
  assert.ok(r.alerts.some((a) => a.category === "MCP: unapproved server"),
    `deny alert never reached the server: ${JSON.stringify(r.alerts.map((a) => a.category))}`);
});

test("DELIVERY: the Task (sub-agent) alert survives emit(\"allow\")'s early exit", async () => {
  // emit("allow") used to exit(0) on its very first line, before even writing stdout — the sub-agent
  // delegation record posted just above it could never have been delivered.
  const r = await runHook({ tool_name: "Task", tool_input: { subagent_type: "general-purpose", prompt: "summarise the repo" } });
  assert.equal(r.code, 0);
  assert.equal(r.stdout, "", "an allow decision must still write nothing to stdout");
  assert.ok(r.alerts.some((a) => a.category === "Sub-agent / A2A delegation"),
    `Task alert never reached the server: ${JSON.stringify(r.alerts.map((a) => a.category))}`);
});

test("DELIVERY: an unreachable server cannot hang or change the decision", async () => {
  // post() carries AbortSignal.timeout(1500) and ends in .catch(() => {}), and the drain uses
  // Promise.allSettled — so awaiting it can neither throw nor outlive the timeout. Point the hook at
  // a black-hole address (TEST-NET-1, RFC 5737: routed nowhere) so the request neither connects nor
  // is refused, and assert the deny still comes out well inside the bound.
  const home = mkdtempSync(join(tmpdir(), "moorai-blackhole-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: "http://192.0.2.1:8787", tenant: "acme" }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", mcpAllow: ["approved-only"] }));

  const t0 = Date.now();
  const child = spawn(process.execPath, [HOOK], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home } });
  let stdout = "";
  child.stdout.on("data", (c) => (stdout += c));
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ tool_name: "mcp__rogue__doThing", tool_input: { x: 1 } }));
  const code = await new Promise((r) => child.on("exit", r));
  const ms = Date.now() - t0;
  rmSync(home, { recursive: true, force: true });

  assert.equal(code, 0);
  assert.match(stdout, /"permissionDecision":"deny"/, "the decision must be unaffected by a dead server");
  // Two bounded waits can stack (the policy fetch, then the alert drain), so the ceiling is ~3s + spawn.
  assert.ok(ms < 8000, `the drain must stay bounded by post()'s 1500ms timeout, took ${ms}ms`);
});
