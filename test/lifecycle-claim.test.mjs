// The claimed-success check (cli/claim-check.mjs) against the independently hand-labelled corpus
// test/fixtures/claim-check-corpus.json (75 cases). A REGRESSION GUARD, not an evaluation: the rules
// were tuned on the odd-numbered cases after a blind run, and the even-numbered half was then scored
// once (scripts/score-claim-check.mjs --split heldout). The floors below pin today's whole-corpus
// numbers so a rule change that costs precision fails here; a new evaluation needs a fresh corpus.
//   node --test --import ./test/hermetic-env.mjs test/lifecycle-claim.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { ROOT } from "./lifecycle-harness.mjs";

const { score } = await import(join(ROOT, "scripts", "score-claim-check.mjs"));
const cc = await import(join(ROOT, "cli", "claim-check.mjs"));

test("corpus: whole-corpus precision >= 0.85 and recall >= 0.70 (today: 22/25 and 22/30)", () => {
  const s = score("all");
  assert.equal(s.n, 75);
  assert.ok(s.precision >= 0.85, `precision ${s.precision} (${JSON.stringify(s.errors)})`);
  assert.ok(s.recall >= 0.70, `recall ${s.recall}`);
});

test("claimOf: an acknowledged problem anywhere cancels a claim; an unrelated negation does not", () => {
  assert.equal(cc.claimOf("All tests pass now.").claim, "tests-pass");
  assert.equal(cc.claimOf("All tests pass except the flaky e2e one.").caveat, "hedge");
  assert.equal(cc.claimOf("Tests pass. I haven't updated the README yet.").claim, "tests-pass");
  assert.equal(cc.claimOf("The tests don't pass yet.").claim, null);
  assert.equal(cc.claimOf("Here is what I found in the logs.").claim, null);
});

test("commandClass / outcomes: probes, verify runners, effects; documented failure fields only", () => {
  assert.equal(cc.commandClass("grep -rn TODO src"), "probe");
  assert.equal(cc.commandClass("grep -rn TODO src | head"), "other", "a pipeline exits with its last segment");
  assert.equal(cc.commandClass("npm run build"), "verify");
  assert.equal(cc.commandClass("git push origin main"), "effect");
  assert.equal(cc.verifyFamily("npx vitest run"), cc.verifyFamily("vitest --reporter dot"));
  assert.notEqual(cc.verifyFamily("go test ./..."), cc.verifyFamily("go vet ./..."));
  assert.deepEqual(cc.outcomeOfFailure({ error: "Exit code 2\nmake: *** [all] Error 2" }), { outcome: "error", exit: 2 });
  assert.deepEqual(cc.outcomeOfFailure({ error: "boom", is_interrupt: true }), { outcome: "interrupted" });
  assert.deepEqual(cc.outcomeOfResponse({ stdout: "", interrupted: true }), { outcome: "interrupted" });
  assert.deepEqual(cc.outcomeOfResponse({ content: [], isError: true }), { outcome: "error" });
  assert.deepEqual(cc.outcomeOfResponse("plain text"), { outcome: "ok" });
});
