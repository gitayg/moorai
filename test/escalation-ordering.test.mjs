// F-301 — model escalation ran BEFORE the checks that can still deny, so content the policy was about
// to block had already been POSTed to the agent's provider (data/device-inference.mjs → api.anthropic.com,
// up to 4000 raw characters). Opt-in (policy.semanticEscalation === "provider" + a device key), but it
// contradicts the content-free contract for exactly the material the tool exists to withhold.
//
// The mcp__/Task branches already denied before any external call; Read and Bash did not. These tests
// assert the ORDER of effects, which is the whole bug — a test that only checked the final decision
// would have passed before the fix.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "cli", "moorai-hook.mjs");
const src = readFileSync(HOOK, "utf8");

// Index of each call within a branch, so "which runs first" is checked structurally.
const idx = (needle, from = 0) => src.indexOf(needle, from);

test("ORDER/Read: maybeEscalate runs AFTER the envelope check that can deny", () => {
  const branch = idx('if (tool === "Read")');
  const envelope = idx('reportEnvelope(policy, "Read"', branch);
  const escalate = idx('maybeEscalate(policy, text', branch);
  assert.ok(branch > -1 && envelope > -1 && escalate > -1, "branch shape changed — update this test");
  assert.ok(escalate > envelope, "escalation must not precede the envelope check");
});

test("ORDER/Bash: maybeEscalate runs AFTER secret-egress and envelope checks", () => {
  const branch = idx('if (tool === "Bash")');
  const secret = idx('checkSecretEgress(policy, ti.command', branch);
  const envelope = idx('reportEnvelope(policy, "Bash"', branch);
  const escalate = idx('maybeEscalate(policy, btext', branch);
  assert.ok([branch, secret, envelope, escalate].every((i) => i > -1), "branch shape changed — update this test");
  assert.ok(escalate > secret, "escalation must not precede the local-secret-egress check");
  assert.ok(escalate > envelope, "escalation must not precede the envelope check");
});

test("ORDER: escalation is skipped entirely once the decision is deny", () => {
  // The guard is what actually stops the egress; ordering alone would still escalate a denied call.
  for (const guard of ['if (rdec !== "deny") await maybeEscalate', 'if (dec !== "deny") await maybeEscalate']) {
    assert.ok(src.includes(guard), `missing deny-guard: ${guard}`);
  }
});

test("ORDER: escalation remains advisory — it must never set a decision", () => {
  // Moving the call is only safe because maybeEscalate cannot change enforcement. If that ever changes,
  // the reordering silently drops a deny, so pin the property here.
  const body = src.slice(idx("async function maybeEscalate"), idx("function reportSkillFile"));
  assert.ok(body.length > 0, "maybeEscalate not found");
  assert.ok(!/\breturn\s+(true|false|"deny"|'deny')/.test(body), "maybeEscalate must not return a decision");
  assert.ok(!/\bdec\s*=/.test(body), "maybeEscalate must not assign a decision");
});
