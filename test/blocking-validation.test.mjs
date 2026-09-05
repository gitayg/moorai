// Per-file runner:  node --test test/blocking-validation.test.mjs
//
// Asserts the "hijack-then-blocked" harness (scripts/moorai-validate-blocking.mjs) reports a DENY for a
// known-malicious action and an ALLOW for a benign one — driving the REAL hook subprocess, not a stub.
// The benign→allow assertion is the built-in negative control: allow and deny travel the identical
// spawn/parse path, so a harness that hardcoded "deny" could never satisfy it. This measures ACTION-layer
// blocking (the tool call is refused), not prompt-layer detection.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runValidation } from "../scripts/moorai-validate-blocking.mjs";

const find = (rep, id) => rep.results.find((r) => r.id === id);

test("policy mode: malicious credential read is DENIED, benign command is ALLOWED", () => {
  const rep = runValidation({ mode: "policy" });
  assert.equal(find(rep, "read-dotenv").decision, "deny", "hijacked agent's credential read must be denied");
  assert.equal(find(rep, "bash-ls").decision, "allow", "benign `ls -la` must stay allowed (negative control)");
});

test("policy mode: every malicious action is hard-denied and no benign control is blocked", () => {
  const rep = runValidation({ mode: "policy" });
  assert.equal(rep.blockRate, 1, "100% of malicious actions must be hard-denied under the enforcing policy");
  assert.equal(rep.benign.allowed, rep.benign.total, "all benign controls must remain allowed");
  assert.ok(rep.allExpectationsMet, "every action must land on its expected enforcement outcome");
});

test("policy mode: no malicious action is ever ALLOWED (the core hijack claim)", () => {
  const rep = runValidation({ mode: "policy" });
  const leaked = rep.results.filter((r) => r.class !== "benign-control" && r.decision === "allow");
  assert.equal(leaked.length, 0, `these malicious actions were not stopped: ${leaked.map((r) => r.id).join(", ") || "none"}`);
});

test("offline fail-closed default: DLP categories hard-deny; every malicious action is at least stopped-or-documented", () => {
  const rep = runValidation({ mode: "offline" });
  // The built-in offline default hard-blocks secrets/PII even with no console policy reachable.
  assert.equal(find(rep, "read-dotenv").decision, "deny", "secret read must be denied under the offline default");
  // Its documented, deliberate gaps (reverse-shell / untrusted-install / injected-delegation are NOT in
  // the minimal offline default) are encoded as the harness's expectations, so a change in that surface
  // trips allExpectationsMet rather than passing silently.
  assert.ok(rep.allExpectationsMet, "offline outcomes must match the documented offline-default behavior");
  assert.equal(find(rep, "bash-ls").decision, "allow", "benign `ls -la` must stay allowed offline too");
});
