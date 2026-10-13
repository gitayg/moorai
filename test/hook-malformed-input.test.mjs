// A PreToolUse whose tool_input holds a non-string where the hook reads a string (cli/tool-input.mjs).
// It used to crash the hook (`text.trim is not a function`, `The "path" argument must be of type
// string`): a Node stack on stderr, exit 1, and the call went ahead unread. Now a number / boolean is
// judged as its text, and an object / array there takes the hook's bad-input path (UNEVALUATED_BAD_INPUT;
// denied when the hook's fail mode is closed, cli/hook-fail.mjs). The real hook subprocess, a stand-in
// console that serves no live policy, and the cached policy of an unanchored device.
// The hook's own top-level fields (tool_name, session_id, cwd, agent_id, ..., prompt on UserPromptSubmit,
// last_assistant_message on Stop) get the same treatment, on every event (normalizeHookInput); a numeric
// tool_name used to crash every PostToolUse and SessionStart and fail every PreToolUse open.
//
//   node --test --import ./test/hermetic-env.mjs test/hook-malformed-input.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "cli", "moorai-hook.mjs");
const AWS_ENV = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";

async function consoleStub(t) {
  const srv = http.createServer((req, res) => { req.resume(); req.on("end", () => { if (req.url === "/api/alerts") { res.writeHead(200); return res.end("{}"); } res.writeHead(500); res.end("offline"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return `http://127.0.0.1:${srv.address().port}`;
}
function sandbox(t, url, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-malformed-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "mf-test", installToken: "tok-malformed" }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", ...policy }));
  return home;
}
function run(home, tool_name, tool_input) {
  return runRaw(home, JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-mf", cwd: home, tool_name, tool_input }));
}
function runRaw(home, raw) {
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [HOOK], { env, cwd: home, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => resolve({ code, stdout, stderr, decision: (() => { try { return JSON.parse(stdout.trim()).hookSpecificOutput || {}; } catch { return {}; } })() }));
    child.stdin.end(raw);
  });
}
const lastRow = (home) => { try { return readFileSync(join(home, ".moorai", "session-ledger.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).at(-1) || {}; } catch { return {}; } };
const noCrash = (r, what) => {
  assert.doesNotMatch(r.stderr, /TypeError|at main|is not a function|must be of type string/, `${what}: the hook crashed: ${r.stderr.slice(0, 300)}`);
  assert.ok(r.code === 0 || r.code === 2, `${what}: exit ${r.code} ${r.stderr.slice(0, 200)}`);
};

// Every built-in tool field the hook (or a helper it hands tool_input to) reads as a string.
const NUMERIC = [
  ["Bash", { command: 123 }], ["PowerShell", { command: 123 }], ["Bash", { command: true }],
  ["Read", { file_path: 5 }], ["Write", { file_path: 5, content: "x" }], ["Write", { file_path: "a.txt", content: 5 }],
  ["Write", { notebook_path: 5, content: "x" }], ["Edit", { file_path: 5, old_string: "a", new_string: "b" }],
  ["Edit", { file_path: "a.txt", old_string: "a", new_string: 5 }], ["MultiEdit", { file_path: 5, edits: [{ old_string: "a", new_string: 5 }] }],
  ["NotebookEdit", { notebook_path: 5, new_source: 6 }], ["WebFetch", { url: 5, prompt: 6 }], ["WebSearch", { query: 5 }],
  ["Task", { prompt: 5, subagent_type: 6 }], ["Agent", { prompt: 5 }]
];

test("a number or boolean where a string is expected no longer crashes the hook: it is judged as its text", async (t) => {
  const home = sandbox(t, await consoleStub(t), {});
  for (const [tool, ti] of NUMERIC) {
    const r = await run(home, tool, ti);
    noCrash(r, `${tool} ${JSON.stringify(ti)}`);
    const row = lastRow(home);
    assert.notEqual(row.reasonCode, "UNEVALUATED_HOOK_ERROR", `${tool} ${JSON.stringify(ti)}: ${JSON.stringify(row)}`);
    assert.notEqual(row.reasonCode, "UNEVALUATED_BAD_INPUT", `${tool} ${JSON.stringify(ti)} was not judged: ${JSON.stringify(row)}`);
  }
});

test("the coerced text is what gets judged: a Read whose file_path is the number 5 reads the file named \"5\"", async (t) => {
  const home = sandbox(t, await consoleStub(t), { threatPolicy: { 39: "block" } });
  writeFileSync(join(home, "5"), AWS_ENV);
  const r = await run(home, "Read", { file_path: 5 });
  noCrash(r, "Read 5");
  assert.equal(r.decision.permissionDecision, "deny", `the secret in ./5 was not judged: ${r.stdout} ${r.stderr.slice(0, 200)}`);
});

const OBJECTS = [
  ["Bash", { command: { x: 1 } }], ["Bash", { command: ["ls"] }], ["Read", { file_path: { x: 1 } }], ["Write", { file_path: ["a"], content: "x" }],
  ["Edit", { file_path: "a.txt", new_string: { x: 1 } }], ["MultiEdit", { file_path: "a.txt", edits: [{ new_string: ["b"] }] }],
  ["NotebookEdit", { notebook_path: "n.ipynb", new_source: { x: 1 } }], ["WebFetch", { url: { x: 1 } }], ["WebSearch", { query: [1] }],
  ["Task", { prompt: { x: 1 } }], ["Agent", { subagent_type: { x: 1 }, prompt: "p" }]
];

test("an object or array where a string is expected is unreadable input: open allows it as UNEVALUATED_BAD_INPUT", async (t) => {
  const home = sandbox(t, await consoleStub(t), {});
  for (const [tool, ti] of OBJECTS) {
    const r = await run(home, tool, ti);
    noCrash(r, `${tool} ${JSON.stringify(ti)}`);
    assert.equal(r.code, 0, `${tool} ${JSON.stringify(ti)}`);
    assert.equal(r.decision.permissionDecision, undefined, `${tool} ${JSON.stringify(ti)}: ${r.stdout}`);
    assert.equal(lastRow(home).reasonCode, "UNEVALUATED_BAD_INPUT", `${tool} ${JSON.stringify(ti)}: ${JSON.stringify(lastRow(home))}`);
  }
});

test("an object or array where a string is expected, under failMode.hook closed: denied (exit 2) as bad input", async (t) => {
  const home = sandbox(t, await consoleStub(t), { failMode: { hook: "closed" } });
  for (const [tool, ti] of OBJECTS) {
    const r = await run(home, tool, ti);
    noCrash(r, `${tool} ${JSON.stringify(ti)}`);
    assert.equal(r.code, 2, `${tool} ${JSON.stringify(ti)}: ${r.stdout} ${r.stderr.slice(0, 200)}`);
    assert.equal(r.decision.permissionDecision, "deny");
    assert.match(r.decision.permissionDecisionReason, /not evaluated \(the MoorAI hook could not read the call\)/);
    const row = lastRow(home);
    assert.deepEqual([row.reasonCode, row.basisCode], ["FAIL_CLOSED", "UNEVALUATED_BAD_INPUT"], JSON.stringify(row));
  }
});

test("an MCP tool's arguments are free-form: numbers and objects there are not bad input", async (t) => {
  const home = sandbox(t, await consoleStub(t), { failMode: { hook: "closed" } });
  const r = await run(home, "mcp__srv__do", { command: { x: 1 }, file_path: 5, prompt: ["a"] });
  noCrash(r, "mcp");
  assert.equal(r.code, 0, r.stderr.slice(0, 200));
  assert.notEqual(lastRow(home).reasonCode, "FAIL_CLOSED");
  assert.notEqual(lastRow(home).reasonCode, "UNEVALUATED_BAD_INPUT");
});

// ---- top-level fields ----
// One base payload per event the hook handles, and the fields it reads as strings there.
const EVENTS = {
  PreToolUse: { tool_name: "Bash", tool_input: { command: "ls" } },
  PostToolUse: { tool_name: "Bash", tool_input: { command: "ls" }, tool_response: { stdout: "hello", stderr: "" } },
  PostToolUseFailure: { tool_name: "Bash", tool_input: { command: "ls" }, error: "Exit code 1" },
  UserPromptSubmit: { prompt: "please list the files", source: "user" },
  Stop: { stop_hook_active: false, last_assistant_message: "All tests pass." },
  SubagentStop: { agent_id: "a1", agent_type: "x", last_assistant_message: "Done." },
  SessionStart: { source: "startup" },
  PreCompact: { trigger: "manual" }
};
const TOP = ["hook_event_name", "tool_name", "session_id", "cwd", "transcript_path", "agent_id", "agent_type", "permission_mode", "tool_use_id", "prompt", "last_assistant_message", "source", "trigger"];
const envelope = (home, ev, extra) => ({ hook_event_name: ev, session_id: "s-mf", cwd: home, transcript_path: join(home, "t.jsonl"), ...EVENTS[ev], ...extra });
async function pool(items, n, fn) { const q = [...items]; await Promise.all(Array.from({ length: n }, async () => { while (q.length) await fn(q.shift()); })); }

test("a non-string top-level field never crashes the hook, on any event, open or closed", async (t) => {
  const url = await consoleStub(t);
  for (const mode of ["open", "closed"]) {
    const home = sandbox(t, url, { promptScan: "all", failMode: { hook: mode } });
    const cases = [];
    for (const ev of Object.keys(EVENTS)) for (const f of TOP) for (const v of [5, { x: 1 }]) cases.push([`${mode} ${ev} ${f}=${JSON.stringify(v)}`, JSON.stringify(envelope(home, ev, { [f]: v }))]);
    for (const tn of ["__proto__", "constructor", "toString"]) for (const ev of ["PreToolUse", "PostToolUse"]) cases.push([`${mode} ${ev} tool_name ${tn}`, JSON.stringify(envelope(home, ev, { tool_name: tn }))]);
    for (const raw of ["5", "null", "[]", '"x"']) cases.push([`${mode} payload ${raw}`, raw]);
    await pool(cases, 6, async ([what, raw]) => noCrash(await runRaw(home, raw), what));
  }
});

test("a number in a top-level string field is judged as its text: cwd 5 resolves a Read against the directory \"5\"", async (t) => {
  const home = sandbox(t, await consoleStub(t), { threatPolicy: { 39: "block" } });
  mkdirSync(join(home, "5"));
  writeFileSync(join(home, "5", "creds.env"), AWS_ENV);
  const r = await runRaw(home, JSON.stringify({ hook_event_name: "PreToolUse", session_id: 7, cwd: 5, tool_name: "Read", tool_input: { file_path: "creds.env" } }));
  noCrash(r, "cwd 5");
  assert.equal(r.decision.permissionDecision, "deny", `the secret in ./5/creds.env was not judged: ${r.stdout} ${r.stderr.slice(0, 200)}`);
});

const TOP_OBJECTS = [["tool_name", { x: 1 }], ["tool_name", ["Bash"]]];
const ENVELOPE_OBJECTS = [["session_id", { x: 1 }], ["cwd", ["a"]], ["agent_id", { x: 1 }], ["agent_type", ["a"]], ["permission_mode", { x: 1 }], ["tool_use_id", [1]]];

test("an object or array in an envelope field (session_id, cwd, agent_id, ...) is dropped and the call is still judged, even in open mode", async (t) => {
  const home = sandbox(t, await consoleStub(t), { threatPolicy: { 39: "block" }, failMode: { hook: "open" } });
  writeFileSync(join(home, "creds.env"), AWS_ENV);
  for (const [f, v] of ENVELOPE_OBJECTS) {
    const what = `${f}=${JSON.stringify(v)}`;
    const r = await runRaw(home, JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s-env", cwd: home, tool_name: "Read", tool_input: { file_path: join(home, "creds.env") }, [f]: v }));
    noCrash(r, what);
    assert.equal(r.decision.permissionDecision, "deny", `${what}: ${r.stdout} ${r.stderr.slice(0, 200)}`);
  }
});

test("an object or array in a top-level string field is unreadable input: PreToolUse open allows, closed denies", async (t) => {
  const url = await consoleStub(t);
  for (const [mode, code, dec] of [["open", 0, undefined], ["closed", 2, "deny"]]) {
    const home = sandbox(t, url, { failMode: { hook: mode } });
    for (const [f, v] of TOP_OBJECTS) {
      const what = `${mode} ${f}=${JSON.stringify(v)}`;
      const r = await runRaw(home, JSON.stringify(envelope(home, "PreToolUse", { [f]: v })));
      noCrash(r, what);
      assert.equal(r.code, code, `${what}: ${r.stdout} ${r.stderr.slice(0, 200)}`);
      assert.equal(r.decision.permissionDecision, dec, what);
      const row = lastRow(home);
      if (mode === "closed") assert.deepEqual([row.reasonCode, row.basisCode], ["FAIL_CLOSED", "UNEVALUATED_BAD_INPUT"], `${what}: ${JSON.stringify(row)}`);
      else assert.equal(row.reasonCode, "UNEVALUATED_BAD_INPUT", `${what}: ${JSON.stringify(row)}`);
    }
    // A payload that is not an object: bad input, and a PreToolUse one (by its raw text) is denied when closed.
    const r = await runRaw(home, JSON.stringify([{ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }]));
    noCrash(r, `${mode} array payload`);
    assert.equal(r.code, code, `${mode} array payload: ${r.stdout}`);
    assert.equal(lastRow(home).basisCode || lastRow(home).reasonCode, "UNEVALUATED_BAD_INPUT");
  }
});

test("bad top-level input on any other event fails open, even when the hook's fail mode is closed", async (t) => {
  const home = sandbox(t, await consoleStub(t), { promptScan: "all", failMode: { hook: "closed" } });
  for (const [ev, extra] of [["UserPromptSubmit", { prompt: { x: 1 } }], ["Stop", { last_assistant_message: ["a"] }], ["SubagentStop", { last_assistant_message: { x: 1 } }], ["PostToolUse", { tool_name: { x: 1 } }], ["PostToolUseFailure", { tool_name: ["a"] }], ["SessionStart", { tool_name: ["a"] }]]) {
    const what = `${ev} ${JSON.stringify(extra)}`;
    const r = await runRaw(home, JSON.stringify(envelope(home, ev, extra)));
    noCrash(r, what);
    assert.equal(r.code, 0, `${what}: ${r.stdout}`);
    assert.equal(r.stdout.trim(), "", what);
    assert.equal(lastRow(home).reasonCode, "UNEVALUATED_BAD_INPUT", `${what}: ${JSON.stringify(lastRow(home))}`);
  }
});

test("a hook_event_name that is not a string is dropped, not bad input: the call is still judged, as before", async (t) => {
  const home = sandbox(t, await consoleStub(t), { threatPolicy: { 39: "block" }, failMode: { hook: "closed" } });
  writeFileSync(join(home, "creds.env"), AWS_ENV);
  for (const ev of [["PreToolUse"], { x: 1 }]) {
    const r = await runRaw(home, JSON.stringify({ hook_event_name: ev, session_id: "s-mf", cwd: home, tool_name: "Read", tool_input: { file_path: "creds.env" } }));
    noCrash(r, JSON.stringify(ev));
    assert.equal(r.decision.permissionDecision, "deny", `${JSON.stringify(ev)}: ${r.stdout}`);
    assert.notEqual(lastRow(home).basisCode, "UNEVALUATED_BAD_INPUT");
  }
});

test("a tool named like an Object.prototype member is an unknown tool, not an alias and not a crash", async (t) => {
  const home = sandbox(t, await consoleStub(t), { failMode: { hook: "closed" } });
  for (const tn of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    const r = await run(home, tn, { command: "ls" });
    noCrash(r, tn);
    assert.equal(r.code, 0, `${tn}: ${r.stdout}`);
    assert.equal(lastRow(home).reasonCode, "UNEVALUATED_UNSUPPORTED_TOOL", `${tn}: ${JSON.stringify(lastRow(home))}`);
  }
});

test("a number in UserPromptSubmit's prompt is scanned as its text, not skipped", async (t) => {
  const home = sandbox(t, await consoleStub(t), { promptScan: "all" });
  const r = await runRaw(home, JSON.stringify(envelope(home, "UserPromptSubmit", { prompt: 12345 })));
  noCrash(r, "prompt 12345");
  assert.notEqual(lastRow(home).reasonCode, "OBSERVATION_ONLY", `a numeric prompt was skipped: ${JSON.stringify(lastRow(home))}`);
});
