// PROCESS LIFECYCLE of the stdio guard (mcp-proxy/moorai-mcp-guard.mjs).
//
// THE DEFECT, measured against chroma-mcp 0.2.6 (test/index-real-vector-mcp.test.mjs): when the MCP
// client closed the guard's stdin, the guard only closed the child's stdin and then waited for the
// child to exit; and a SIGTERM to the guard killed the guard alone. chroma-mcp does not exit on stdin
// EOF, so every proxied session left it running with ppid 1 — 7 per run of that file.
//
// What an MCP client expects of a stdio server (and so of the guard standing in for one): on stdin EOF
// it exits; if it does not, the client sends SIGTERM and then SIGKILL. The guard now runs that same
// sequence against its child, and forwards SIGTERM / SIGINT / SIGHUP to it.
//
// Every case checks for an orphan by PID: the fake server writes its pid to a file (FAKE_PID_FILE).
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-guard-lifecycle.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const GRACE_MS = 2000; // the guard's grace period between closing stdin, SIGTERM and SIGKILL

const settle = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

async function waitFor(pred, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (pred()) return true; await settle(20); }
  return pred();
}

// Start the guard over the fake server. Resolves once the child's pid is known.
async function startGuard(fakeEnv = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-lifecycle-"));
  const pidFile = join(home, "child.pid");
  const env = { ...process.env, HOME: home, USERPROFILE: home, FAKE_PID_FILE: pidFile, ...fakeEnv };
  delete env.MoorAI_SERVER; delete env.MoorAI_TENANT;
  const guard = spawn(process.execPath, [GUARD, "--server", "lifecycle", "--", process.execPath, FAKE], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  const st = { guard, home, childPid: 0, exited: false, code: null, signal: null, exitAt: 0, out: "", stderr: "" };
  guard.stdout.on("data", (c) => { st.out += c; });
  guard.stderr.on("data", (c) => { st.stderr += c; });
  guard.on("exit", (code, signal) => { st.exited = true; st.code = code; st.signal = signal; st.exitAt = Date.now(); });
  await waitFor(() => existsSync(pidFile) && readFileSync(pidFile, "utf8").length > 0, 10000);
  st.childPid = Number(readFileSync(pidFile, "utf8"));
  assert.ok(st.childPid > 0, `the fake server never wrote its pid. stderr=${st.stderr}`);
  return st;
}

// Never leave a process behind, whatever the assertion outcome.
function cleanup(st) {
  for (const pid of [st.childPid, st.guard.pid]) if (pid && alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
  rmTree(st.home);
}

function responses(st) {
  return st.out.split("\n").filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}
const send = (st, o) => st.guard.stdin.write(JSON.stringify(o) + "\n");
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "0" } } };

test("(a) closing the guard's stdin ends a child that ignores EOF, and the guard, within the grace window", async () => {
  const st = await startGuard({ FAKE_IGNORE_EOF: "1" });
  try {
    const t0 = Date.now();
    st.guard.stdin.end();
    const done = await waitFor(() => st.exited && !alive(st.childPid), GRACE_MS + 3000);
    assert.ok(done, `after stdin EOF: guard exited=${st.exited}, child ${st.childPid} alive=${alive(st.childPid)}`);
    assert.ok(st.exitAt - t0 >= GRACE_MS - 200, `the child was not given its grace period (${st.exitAt - t0} ms)`);
    assert.equal(st.code, 0, `a shutdown the client asked for exits 0 (code=${st.code} signal=${st.signal})`);
  } finally { cleanup(st); }
});

test("(b) SIGTERM to the guard is forwarded: the child ends and is not orphaned", { skip: process.platform === "win32" && "POSIX signals" }, async () => {
  const st = await startGuard({ FAKE_IGNORE_EOF: "1" });
  try {
    const t0 = Date.now();
    st.guard.kill("SIGTERM");
    const done = await waitFor(() => st.exited && !alive(st.childPid), GRACE_MS + 3000);
    assert.ok(done, `after SIGTERM: guard exited=${st.exited}, child ${st.childPid} alive=${alive(st.childPid)} — orphaned`);
    // Forwarded at once, not merely reached by the grace-period escalation.
    assert.ok(st.exitAt - t0 < GRACE_MS / 2, `the child got SIGTERM only after ${st.exitAt - t0} ms — not forwarded`);
  } finally { cleanup(st); }
});

test("(b2) SIGINT and SIGHUP to the guard are forwarded too", { skip: process.platform === "win32" && "POSIX signals" }, async () => {
  for (const sig of ["SIGINT", "SIGHUP"]) {
    const st = await startGuard({ FAKE_IGNORE_EOF: "1" });
    try {
      const t0 = Date.now();
      st.guard.kill(sig);
      const done = await waitFor(() => st.exited && !alive(st.childPid), GRACE_MS + 3000);
      assert.ok(done, `after ${sig}: guard exited=${st.exited}, child ${st.childPid} alive=${alive(st.childPid)}`);
      assert.ok(st.exitAt - t0 < GRACE_MS / 2, `${sig} reached the child only after ${st.exitAt - t0} ms — not forwarded`);
    } finally { cleanup(st); }
  }
});

test("(b3) a child that ignores SIGTERM as well is SIGKILLed after the second grace period", { skip: process.platform === "win32" && "POSIX signals" }, async () => {
  const st = await startGuard({ FAKE_IGNORE_EOF: "1", FAKE_IGNORE_SIGTERM: "1" });
  try {
    await settle(200); // let the fake install its SIGTERM handler
    const t0 = Date.now();
    st.guard.stdin.end();
    const done = await waitFor(() => st.exited && !alive(st.childPid), 2 * GRACE_MS + 3000);
    assert.ok(done, `guard exited=${st.exited}, child ${st.childPid} alive=${alive(st.childPid)}`);
    assert.ok(st.exitAt - t0 >= 2 * GRACE_MS - 200, `SIGKILL came before stdin-EOF grace + SIGTERM grace (${st.exitAt - t0} ms)`);
  } finally { cleanup(st); }
});

test("(c) normal request/response still works, and the last response before EOF is delivered", async () => {
  const st = await startGuard();
  try {
    send(st, INIT);
    assert.ok(await waitFor(() => responses(st).some((m) => m.id === 1), 10000), `no initialize response. stderr=${st.stderr}`);
    send(st, { jsonrpc: "2.0", id: 2, method: "tools/list" });
    assert.ok(await waitFor(() => responses(st).some((m) => m.id === 2), 10000), "no tools/list response");
    // A call immediately followed by EOF: the child answers then exits, and the answer must not be lost.
    send(st, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo", arguments: { x: "hello" } } });
    st.guard.stdin.end();
    assert.ok(await waitFor(() => st.exited, GRACE_MS + 3000), "guard did not exit");
    const r3 = responses(st).find((m) => m.id === 3);
    assert.ok(r3, `the in-flight tools/call response was dropped on shutdown. out=${st.out}`);
    assert.match(r3.result.content[0].text, /hello/);
    assert.equal(alive(st.childPid), false);
  } finally { cleanup(st); }
});

test("(c2) a response still in the result stage when the child exits is delivered, not dropped", async () => {
  // MOORAI_TEST_RESULT_STALL_MS holds the result in scanResult (under CAPS.resultDeadlineMs) while the
  // well-behaved child answers and exits on EOF — the guard must drain its write queue before exiting.
  const st = await startGuard({ MOORAI_TEST_RESULT_STALL_MS: "500" });
  try {
    send(st, INIT);
    assert.ok(await waitFor(() => responses(st).some((m) => m.id === 1), 10000), `no initialize response. stderr=${st.stderr}`);
    send(st, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "echo", arguments: { x: "in-flight" } } });
    st.guard.stdin.end();
    assert.ok(await waitFor(() => st.exited, GRACE_MS + 3000), "guard did not exit");
    const r4 = responses(st).find((m) => m.id === 4);
    assert.ok(r4, `the response held in the result stage was dropped on exit. out=${st.out}`);
    assert.match(r4.result.content[0].text, /in-flight/);
    assert.equal(alive(st.childPid), false);
  } finally { cleanup(st); }
});

test("(d) a well-behaved child that exits on EOF ends the guard at once, without waiting for the grace period", async () => {
  const st = await startGuard();
  try {
    const t0 = Date.now();
    st.guard.stdin.end();
    assert.ok(await waitFor(() => st.exited, GRACE_MS + 3000), "guard did not exit");
    assert.ok(st.exitAt - t0 < GRACE_MS / 2, `the guard waited ${st.exitAt - t0} ms for a child that had already exited`);
    assert.equal(st.code, 0);
    assert.equal(alive(st.childPid), false);
  } finally { cleanup(st); }
});

test("(e) a child that dies first takes the guard with it, passing on its exit code", { skip: process.platform === "win32" && "POSIX signals" }, async () => {
  const st = await startGuard({ FAKE_IGNORE_EOF: "1" });
  try {
    process.kill(st.childPid, "SIGKILL");
    assert.ok(await waitFor(() => st.exited, 3000), "guard outlived its child");
    assert.equal(st.code, 1, "a child killed by a signal the guard did not send exits the guard non-zero");
  } finally { cleanup(st); }
});
