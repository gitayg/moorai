// The hook's admin-chosen fail mode (cli/hook-fail.mjs, cli/fail-mode.mjs surface "hook"), driven through
// the REAL hook subprocess against a stand-in console. The policy reaches the hook as the cached policy of
// an unanchored device (the same path test/hook-tool-coverage.test.mjs uses); the admin binding is
// root-owned and cannot be planted from a test, so its precedence is covered in test/fail-mode.test.mjs
// and test/fail-mode-hook-unit.test.mjs.
//
// The internal error is REAL and comes from outside the hook: test/fixtures/hook-fault.mjs, loaded with
// `node --import`, makes String.prototype.startsWith throw on any string containing its SENTINEL, which
// the hook calls with no try/catch around it (agentPath() on a Read's file_path; postDispatched() on a
// PostToolUse's tool name). The hook itself has no fault knob and must not get one: under an open fail
// mode, a switch that forces an error is a switch that lets a call through unread. Malformed input is not
// a trigger any more (it is judged or denied as bad input, cli/tool-input.mjs; the last test pins that).
// Every faulted run asserts the fixture's FAULT_MARK on stderr, so a refactor that stops the fault from
// firing fails these tests loudly instead of letting them pass vacuously.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { breakGlassCanonical, BREAK_GLASS_VERSION } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";
import { SENTINEL, FAULT_MARK } from "./fixtures/hook-fault.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const FAULT = pathToFileURL(join(ROOT, "test", "fixtures", "hook-fault.mjs")).href;
// A Read the hook would allow (the file does not exist); with the fixture loaded, evaluating it throws.
const CRASH = { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: `${SENTINEL}/notes.txt` } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function consoleStub(t) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      res.writeHead(500); res.end("offline"); // no live policy: the cached one is used
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts };
}

function sandbox(t, url, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-failmode-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "fm-test", installToken: "tok-failmode" }));
  if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  return home;
}

// fault: false runs the hook exactly as Claude Code does (no preload).
function run(home, payload, extraEnv = {}, { fault = true } = {}) {
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), ...extraEnv };
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...(fault ? ["--import", FAULT] : []), HOOK], { env, cwd: home, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify({ session_id: "s-fm", cwd: home, ...payload }));
  });
}
const decisionOf = (stdout) => { try { return JSON.parse(stdout.trim()).hookSpecificOutput || {}; } catch { return {}; } };
function ledger(home) {
  try { return readFileSync(join(home, ".moorai", "session-ledger.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)); } catch { return []; }
}
async function until(fn, ms = 6000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

test("CLOSED: failMode.hook closed + an internal error on PreToolUse → exit 2, deny JSON, content-free alert FAIL_CLOSED", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: "closed" } });
  const r = await run(home, CRASH);
  assert.ok(r.stderr.includes(FAULT_MARK), `the injected fault did not fire: ${r.stderr.slice(0, 300)}`);
  assert.equal(r.code, 2, `exit 2 blocks the call in Claude Code whatever stdout says; got ${r.code} ${r.stderr}`);
  const d = decisionOf(r.stdout);
  assert.equal(d.hookEventName, "PreToolUse");
  assert.equal(d.permissionDecision, "deny");
  assert.match(d.permissionDecisionReason, /^MoorAI: this tool call was not evaluated \(the MoorAI hook failed while evaluating it\)/);
  assert.match(r.stderr, /MoorAI: this tool call was not evaluated/);
  assert.ok(!/notes\.txt|moorai-fault|injected|startsWith|Error/.test(r.stdout), "the deny names no content and no stack");
  const row = ledger(home).at(-1);
  assert.equal(row.reasonCode, "FAIL_CLOSED");
  assert.equal(row.basisCode, "UNEVALUATED_HOOK_ERROR");
  assert.equal(row.decision, "deny");
  assert.ok(await until(() => c.alerts.some((a) => a.reasonCode === "FAIL_CLOSED")), `alerts: ${JSON.stringify(c.alerts.map((a) => a.category))}`);
  const a = c.alerts.find((x) => x.reasonCode === "FAIL_CLOSED");
  assert.equal(a.category, "Fail-closed: tool call not evaluated");
  assert.equal(a.failModeSource, "policy");
  assert.equal(a.failWhy, "error");
  assert.equal(a.enforcement, "STRENGTHENED");
  assert.ok(!/notes\.txt|moorai-fault/.test(JSON.stringify(a)), "content-free");
});

test("CLOSED via failMode.default: the policy's default applies to the hook", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { default: "closed" } });
  const r = await run(home, CRASH);
  assert.ok(r.stderr.includes(FAULT_MARK), r.stderr.slice(0, 300));
  assert.equal(r.code, 2);
  assert.equal(decisionOf(r.stdout).permissionDecision, "deny");
});

test("OPEN (explicit and absent): the same internal error stays a non-blocking failure, as before", async (t) => {
  const c = await consoleStub(t);
  for (const policy of [{ captureTier: "content-free", failMode: { hook: "open", default: "closed" } }, { captureTier: "content-free" }]) {
    const home = sandbox(t, c.url, policy);
    const r = await run(home, CRASH);
    assert.ok(r.stderr.includes(FAULT_MARK), r.stderr.slice(0, 300));
    assert.notEqual(r.code, 2, `open must not block: ${JSON.stringify(policy)}`);
    assert.notEqual(r.code, 0, "the uncaught error still propagates (Claude Code: non-blocking error)");
    assert.match(r.stderr, /injected test fault/, "the error that propagated is the injected one");
    assert.equal(decisionOf(r.stdout).permissionDecision, undefined);
    assert.equal(ledger(home).at(-1).reasonCode, "UNEVALUATED_HOOK_ERROR");
  }
});

test("CLOSED before the policy is parsed: unreadable PreToolUse input is decided by the cached verified policy", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: "closed" } });
  const trunc = '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"';
  const runRaw = (text) => new Promise((resolve) => {
    const child = spawn(process.execPath, [HOOK], { env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") }, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", (x) => (stdout += x));
    child.on("close", (code) => resolve({ code, stdout }));
    child.stdin.end(text);
  });
  const r = await runRaw(trunc);
  assert.equal(r.code, 2);
  assert.match(decisionOf(r.stdout).permissionDecisionReason, /could not read the call/);
  assert.equal(ledger(home).at(-1).basisCode, "UNEVALUATED_BAD_INPUT");
  const other = await runRaw('{"hook_event_name":"Stop"');
  assert.equal(other.code, 0, "an unreadable non-PreToolUse event is never blocked");
  assert.equal(other.stdout, "");
});

test("CLOSED does not reach other events: a PostToolUse whose evaluation throws, or that the hook cannot read, still fails open", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: "closed" } });
  const r = await run(home, { hook_event_name: "PostToolUse", tool_name: SENTINEL, tool_input: {}, tool_response: "x" });
  assert.ok(r.stderr.includes(FAULT_MARK), r.stderr.slice(0, 300));
  assert.notEqual(r.code, 2, "a PostToolUse exit 2 would only feed stderr to Claude; it is never used");
  assert.equal(r.stdout.trim(), "");
  assert.equal(ledger(home).at(-1).reasonCode, "UNEVALUATED_HOOK_ERROR");
  const bad = await run(home, { hook_event_name: "PostToolUse", tool_name: { x: 1 }, tool_response: "x" }, {}, { fault: false });
  assert.equal(bad.code, 0, bad.stderr.slice(0, 300));
  assert.equal(bad.stdout.trim(), "");
  assert.equal(ledger(home).at(-1).reasonCode, "UNEVALUATED_BAD_INPUT");
});

test("CLOSED: an environment that asserts fail-open does not open it", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: "closed" } });
  const r = await run(home, CRASH, { MOORAI_FAIL_MODE: "open", MOORAI_HOOK_FAIL: "open", MOORAI_OFFLINE_MODE: "fail-open" });
  assert.ok(r.stderr.includes(FAULT_MARK), r.stderr.slice(0, 300));
  assert.equal(r.code, 2);
  assert.equal(decisionOf(r.stdout).permissionDecision, "deny");
});

test("CLOSED + scan cap: a Read past the 256 KiB scan cap is denied; open allows it as before", async (t) => {
  const c = await consoleStub(t);
  for (const [mode, expect] of [["closed", "deny"], ["open", undefined]]) {
    const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: mode } });
    const big = join(home, "big.txt");
    writeFileSync(big, "lorem ipsum dolor sit amet\n".repeat(12000)); // ~324 KB of benign text
    const r = await run(home, { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: big } });
    assert.equal(r.code, 0, "a scan-cap verdict is an ordinary decision, not an error");
    const d = decisionOf(r.stdout);
    assert.equal(d.permissionDecision, expect, `${mode}: ${r.stdout}`);
    const row = ledger(home).at(-1);
    if (mode === "closed") {
      assert.match(d.permissionDecisionReason, /reads more content than MoorAI scans/);
      assert.equal(row.reasonCode, "FAIL_CLOSED");
      assert.equal(row.basisCode, "UNEVALUATED_SIZE_CAP");
    } else assert.equal(row.reasonCode, "UNEVALUATED_SIZE_CAP");
  }
});

test("NO-BRICK: an operator-signed live break-glass marker turns a fail-closed error back into an allow", async (t) => {
  const c = await consoleStub(t);
  const op = generateKeyPairSync("ed25519");
  const pub = op.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const body = { v: BREAK_GLASS_VERSION, tenant: "fm-test", device: hostname(), expires: "2099-01-01T00:00:00.000Z", nonce: "fm" };
  const marker = JSON.stringify({ ...body, sig: edSign(null, Buffer.from(breakGlassCanonical(body)), op.privateKey).toString("base64") });
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: "closed" } });
  writeFileSync(join(home, ".moorai", "break-glass"), marker);
  const r = await run(home, CRASH, { MOORAI_BREAKGLASS_PUBKEY: pub });
  assert.ok(r.stderr.includes(FAULT_MARK), r.stderr.slice(0, 300));
  assert.notEqual(r.code, 2, `break-glass must not deny: ${r.stdout}`);
  assert.equal(decisionOf(r.stdout).permissionDecision, undefined);
  assert.equal(ledger(home).at(-1).reasonCode, "BREAK_GLASS");
});

test("CONTROL: the same call without the fault preload is evaluated and allowed (the hook has no fault knob)", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: "closed" } });
  const r = await run(home, CRASH, {}, { fault: false });
  assert.equal(r.code, 0, `${r.stdout} ${r.stderr.slice(0, 300)}`);
  assert.ok(!r.stderr.includes(FAULT_MARK));
  assert.equal(decisionOf(r.stdout).permissionDecision, undefined);
  assert.notEqual(ledger(home).at(-1).reasonCode, "FAIL_CLOSED");
  assert.notEqual(ledger(home).at(-1).reasonCode, "UNEVALUATED_HOOK_ERROR");
});

test("CLOSED: bad input (an object where a string is read, in tool_input or at the top level) is denied, not crashed; open allows it", async (t) => {
  const c = await consoleStub(t);
  const BAD = [
    { tool_name: "Bash", tool_input: { command: { x: 1 } } },
    { tool_name: { x: 1 }, tool_input: { command: "ls" } }
  ];
  for (const [mode, code, dec] of [["closed", 2, "deny"], ["open", 0, undefined]]) {
    const home = sandbox(t, c.url, { captureTier: "content-free", failMode: { hook: mode } });
    for (const p of BAD) {
      const r = await run(home, { hook_event_name: "PreToolUse", ...p }, {}, { fault: false });
      const what = `${mode} ${JSON.stringify(p)}`;
      assert.doesNotMatch(r.stderr, /TypeError|is not a function|\n {4}at /, `${what}: crashed`);
      assert.equal(r.code, code, `${what}: ${r.stdout} ${r.stderr.slice(0, 200)}`);
      assert.equal(decisionOf(r.stdout).permissionDecision, dec, what);
      const row = ledger(home).at(-1);
      if (mode === "closed") {
        assert.match(decisionOf(r.stdout).permissionDecisionReason, /could not read the call/);
        assert.deepEqual([row.reasonCode, row.basisCode], ["FAIL_CLOSED", "UNEVALUATED_BAD_INPUT"], what);
      } else assert.equal(row.reasonCode, "UNEVALUATED_BAD_INPUT", what);
    }
  }
});
