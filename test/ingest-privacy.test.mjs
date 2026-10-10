// moorai-ingest privacy: no transcript content in the default output, text or JSON. The needle list is
// every distinctive string in the fixtures (test/fixtures/ingest/helpers.mjs NEEDLES); the positive
// control below proves the same check DOES see content when content is printed, so a pass is not
// vacuous.
//
//   node --test --import ./test/hermetic-env.mjs test/ingest-privacy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { CC, CODEX, load, leaks, runCli, tempHome, writePolicy } from "./fixtures/ingest/helpers.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { runIngest } = await load("cli/ingest/run.mjs");
const { NO_POLICY_BASELINE } = await load("cli/ingest/replay.mjs");
const { showLocalText } = await load("cli/moorai-ingest.mjs");

// deny = what the candidate policy below makes enforce mode block (see test/ingest.test.mjs), so a CLI that
// ignored --policy would show here.
for (const [agent, path, deny] of [["claude-code", CC, 3], ["codex", CODEX, 3]]) {
  test(`${agent}: default text and --json output carry no transcript content`, async () => {
    const home = tempHome();
    try {
      // promptScan "all" so the prompt is scanned too and its findings are in the rollup.
      const policy = writePolicy(home, { promptScan: "all", threatPolicy: { 39: "block" } });
      const text = await runCli([path, "--agent", agent, "--days", "0", "--policy", policy], { home });
      assert.equal(text.code, 0, text.err);
      assert.match(text.out, /would have/, "the summary was printed");
      assert.ok(/\d+ findings/.test(text.out) && !/ 0 findings/.test(text.out), "the run found something, so there was content to leak");
      assert.deepEqual(leaks(text.out), []);
      assert.deepEqual(leaks(text.err), []);
      const json = await runCli([path, "--agent", agent, "--days", "0", "--policy", policy, "--json"], { home });
      assert.equal(json.code, 0, json.err);
      const j = JSON.parse(json.out);
      assert.ok(j.findings > 0);
      assert.equal(j.policy.source, "candidate");
      assert.equal(j.decisions.deny, deny, "the candidate policy from --policy decided");
      assert.deepEqual(leaks(json.out), []);
    } finally { rmTree(home); }
  });
}

test("positive control: the content that --show-local prints is caught by the same needle check", async () => {
  const { local } = await runIngest({ policy: NO_POLICY_BASELINE, policyId: "t", policySource: "t", days: 0, explicit: [{ path: CC, agent: "claude-code" }], collectLocal: true });
  assert.ok(local.length > 0);
  const out = showLocalText(local);
  assert.ok(leaks(out).length >= 3, `expected content in --show-local output, saw ${leaks(out)}`);
});

test("--show-local refuses to print content when stdout is not a terminal", async () => {
  const home = tempHome();
  try {
    const policy = writePolicy(home, {});
    const r = await runCli([CC, "--agent", "claude-code", "--days", "0", "--policy", policy, "--show-local"], { home });
    assert.equal(r.code, 2);
    assert.equal(r.out, "");
    assert.match(r.err, /only writes to an interactive terminal/);
  } finally { rmTree(home); }
});
