// cli/hook-fail.mjs: the hook's fail-mode decision and its content-free outputs, in process. The admin
// binding is root-owned and cannot be planted for the real hook subprocess, so its precedence over the
// signed policy (in both directions) is pinned here; test/fail-mode-hook.test.mjs drives the real hook.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-hook-unit.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { hookFailMode, failClosedApplies, failClosedOutput, failClosedAlert, failClosedVerdict, HOOK_DECISION_BUDGET_MS } from "../cli/hook-fail.mjs";
import { REASON } from "../cli/provenance.mjs";

const quiet = () => {};

test("hook fail mode: admin binding > signed policy > open", () => {
  assert.deepEqual(hookFailMode({ warn: quiet }), { mode: "open", source: "default" });
  assert.deepEqual(hookFailMode({ policy: { failMode: { hook: "closed" } }, warn: quiet }), { mode: "closed", source: "policy" });
  assert.deepEqual(hookFailMode({ policy: { failMode: { hook: "closed" } }, admin: { failMode: { hook: "open" } }, warn: quiet }), { mode: "open", source: "admin" });
  assert.deepEqual(hookFailMode({ policy: { failMode: { hook: "open" } }, admin: { failMode: { default: "closed" } }, warn: quiet }), { mode: "closed", source: "admin" });
  // before the policy is verified only the admin binding can close it
  assert.deepEqual(hookFailMode({ policy: null, admin: { serverUrl: "https://c.example", failMode: { hook: "closed" } }, warn: quiet }), { mode: "closed", source: "admin" });
});

test("only PreToolUse is refused; unreadable input is sniffed for the event name", () => {
  assert.equal(failClosedApplies({ event: "PreToolUse" }), true);
  for (const e of ["PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop", "PreCompact", "PostToolUseFailure"]) assert.equal(failClosedApplies({ event: e }), false, e);
  assert.equal(failClosedApplies({ raw: '{"hook_event_name": "PreToolUse", "tool_na' }), true);
  assert.equal(failClosedApplies({ raw: '{"hook_event_name":"Stop"' }), false);
  assert.equal(failClosedApplies({ raw: "" }), false);
  assert.equal(failClosedApplies({}), false);
});

test("the deny: exit 2, the hook's PreToolUse deny JSON, the same reason on stderr, content-free", () => {
  for (const why of ["error", "budget", "bad-input", "size-cap"]) {
    const o = failClosedOutput(why);
    assert.equal(o.code, 2);
    const j = JSON.parse(o.stdout);
    assert.deepEqual(Object.keys(j), ["hookSpecificOutput"]);
    assert.equal(j.hookSpecificOutput.hookEventName, "PreToolUse");
    assert.equal(j.hookSpecificOutput.permissionDecision, "deny");
    assert.match(j.hookSpecificOutput.permissionDecisionReason, /^MoorAI: this tool call was not evaluated \(/);
    assert.equal(o.stderr, `${j.hookSpecificOutput.permissionDecisionReason}\n`);
  }
});

test("the alert and ledger fields: reasonCode FAIL_CLOSED, the cause as basisCode, the mode's source", () => {
  assert.equal(REASON.FAIL_CLOSED, "FAIL_CLOSED");
  const a = failClosedAlert("budget", "admin");
  assert.equal(a.reasonCode, "FAIL_CLOSED");
  assert.equal(a.basisCode, "UNEVALUATED_EARLY_EXIT");
  assert.equal(a.enforcement, "STRENGTHENED");
  assert.equal(a.failModeSource, "admin");
  assert.equal(a.failWhy, "budget");
  assert.equal(a.riskLevel, "Blocked");
  assert.equal(a.contentHash, "fail-closed:budget");
  assert.equal(failClosedVerdict("size-cap").basisCode, "UNEVALUATED_SIZE_CAP");
  assert.equal(failClosedAlert("weird", "policy").failWhy, "error", "an unknown cause never leaves the device verbatim");
});

test("the decision budget sits under the shim's 20 s child timeout", () => {
  assert.ok(HOOK_DECISION_BUDGET_MS < 20000 && HOOK_DECISION_BUDGET_MS >= 5000);
});
