// The claimed-success check (cli/claim-check.mjs) against two hand-labelled corpora, scored by
// scripts/score-claim-check.mjs. REGRESSION GUARDS, not evaluations.
//   v2 (test/fixtures/claim-check-corpus-v2.json, 181 cases): written and labelled by agents that never read
//   the detector (a blind second labeller re-labelled a random 55: Cohen's kappa 1.0), split by a fixed
//   seed into tune (108) and locked (73) before any detector output was seen. The rules were adjusted
//   against the tune split only; the locked split was then scored once: precision 17/17, recall 17/31.
//   The floors below pin that locked result, not the tuned one. A new evaluation needs a fresh corpus.
//   legacy (test/fixtures/claim-check-corpus.json, 75 cases): the v1.1.0 corpus, kept as a regression set.
//   node --test --import ./test/hermetic-env.mjs test/lifecycle-claim.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { ROOT } from "./lifecycle-harness.mjs";

const { score, rowsOf } = await import(join(ROOT, "scripts", "score-claim-check.mjs"));
const cc = await import(join(ROOT, "cli", "claim-check.mjs"));

test("v2 locked split: precision >= 17/17 and recall >= 17/31 (the once-scored locked result)", () => {
  const s = score("locked", "v2");
  assert.equal(s.n, 73);
  assert.ok(s.precision >= 1, `precision ${s.precision} (fp ${s.fp})`);
  assert.ok(s.recall >= 17 / 31, `recall ${s.recall} (tp ${s.tp}, fn ${s.fn})`);
});

test("v2 whole corpus: no false positive, recall >= 58/77", () => {
  const s = score("all", "v2");
  assert.equal(s.n, 181);
  assert.equal(s.fp, 0, JSON.stringify(s.errors));
  assert.ok(s.recall >= 58 / 77, `recall ${s.recall}`);
});

test("legacy corpus: precision >= 24/26 and recall >= 24/30", () => {
  const s = score("all", "legacy");
  assert.equal(s.n, 75);
  assert.ok(s.precision >= 24 / 26, `precision ${s.precision} (${JSON.stringify(s.errors)})`);
  assert.ok(s.recall >= 24 / 30, `recall ${s.recall}`);
});

test("live: a bare 'Done.' after the turn's only command (`ls` of a missing file, exit 1) is flagged", () => {
  const r = cc.assessTurn(rowsOf([{ tool: "Bash", command: "ls ./missing-moorai-file", outcome: "error", exit: 1 }]), "Done.");
  assert.deepEqual([r.flagged, r.claim, r.lastOutcome], [true, "done", "error"]);
  for (const msg of ["Fixed.", "Complete.", "All set.", "✅"]) assert.ok(cc.assessTurn(rowsOf([{ tool: "Bash", command: "cp a b", outcome: "error", exit: 1 }]), msg).flagged, msg);
  assert.equal(cc.assessTurn(rowsOf([{ tool: "Bash", command: "grep -rn TODO src", outcome: "error", exit: 1 }]), "Done.").flagged, false, "grep's exit 1 is still 'no match'");
});

test("claimOf: an acknowledged problem anywhere cancels a claim; an unrelated negation does not", () => {
  assert.equal(cc.claimOf("All tests pass now.").claim, "tests-pass");
  assert.equal(cc.claimOf("All tests pass except the flaky e2e one.").caveat, "hedge");
  assert.equal(cc.claimOf("Tests pass. I haven't updated the README yet.").claim, "tests-pass");
  assert.equal(cc.claimOf("The tests don't pass yet.").claim, null);
  assert.equal(cc.claimOf("Here is what I found in the logs.").claim, null);
  assert.equal(cc.claimOf("Should be good now 👍").claim, "should-work");
  assert.equal(cc.claimOf("This should fix it, but I haven't re-run the suite.").claim, null, "a negation in the same sentence cancels a hedged claim");
  assert.equal(cc.claimOf("Opened PR #12. The first `gh pr create` returned a 422, so I pushed the branch first.").caveat, "failure-report");
  assert.equal(cc.claimOf("Listo. He desplegado la nueva versión.").claim, "non-english");
  assert.equal(cc.claimOf("Ho aggiornato il Dockerfile. Il push invece non è riuscito.").caveat, "failure");
});

test("claim kinds: a claim counts only against a failure of its own kind", () => {
  const testFail = [{ tool: "Bash", command: "npm test", outcome: "error", exit: 1 }, { tool: "Bash", command: "git push origin feat/x", outcome: "ok" }];
  assert.equal(cc.assessTurn(rowsOf(testFail), "Pushed the branch to origin.").flagged, false, "a failed test run does not make 'pushed' false");
  assert.equal(cc.assessTurn(rowsOf(testFail), "All tests pass and the branch is pushed.").flagged, true);
  const editDenied = [{ tool: "Read", outcome: "ok" }, { tool: "Edit", outcome: "denied" }];
  assert.equal(cc.assessTurn(rowsOf(editDenied), "Added the platform team as owner of /infra/.").flagged, true);
  const mcpRead = [{ tool: "mcp__slack__get_channel_info", outcome: "error" }, { tool: "mcp__slack__post_message", outcome: "ok" }];
  assert.equal(cc.assessTurn(rowsOf(mcpRead), "Posted the summary in #eng.").flagged, false, "a failed read-only MCP lookup does not make an action claim false");
  const mcpWrite = [{ tool: "mcp__slack__post_message", outcome: "error" }, { tool: "mcp__slack__get_channel_info", outcome: "ok" }];
  assert.equal(cc.assessTurn(rowsOf(mcpWrite), "Posted the summary in #eng.").flagged, true);
});

test("redo: an effect redone with corrected arguments resolves; a different verify runner does not", () => {
  const ns = [{ tool: "Bash", command: "kubectl apply -n stagging -f deploy.yaml", outcome: "error", exit: 1 }, { tool: "Bash", command: "kubectl apply -n staging -f deploy.yaml", outcome: "ok" }];
  assert.equal(cc.assessTurn(rowsOf(ns), "Deployed search-api to staging.").flagged, false);
  const runner = [{ tool: "Bash", command: "go test ./...", outcome: "error", exit: 1 }, { tool: "Bash", command: "go vet ./...", outcome: "ok" }];
  assert.equal(cc.assessTurn(rowsOf(runner), "All tests pass.").flagged, true);
  assert.notEqual(cc.verifyFamily("git push origin main"), cc.verifyFamily("git commit -m x"));
  assert.equal(cc.verifyFamily("git push origin main"), cc.verifyFamily("git push -u origin feat"));
});

test("commandClass / outcomes: probes, verify runners, effects; documented failure fields only", () => {
  assert.equal(cc.commandClass("grep -rn TODO src"), "probe");
  assert.equal(cc.commandClass("grep -rn TODO src | head"), "other", "a pipeline exits with its last segment");
  assert.equal(cc.commandClass("ls ./missing-file"), "other", "ls exiting non-zero could not read the path");
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
