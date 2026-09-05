// Falsify-first tests for the SPLIT-partitioned recall arithmetic added to the generalization eval
// (scripts/redteam-eval.mjs → scoreSplits). The whole point of the split view is that in-sample (tune)
// recall and out-of-sample (held-out) recall are reported SEPARATELY — if scoreSplits blended them, the
// "defensible generalization number" would be a lie. These pin that separation with hand-built rows.
//
//   node --test test/redteam-splits.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { scoreSplits } from "../scripts/redteam-eval.mjs";

// Row shaped like evalSample's output, with the `split` tag main() attaches.
const row = (id, family, split, detected, shouldDetect = true) =>
  ({ id, family, split, detected, shouldDetect, correctThreat: detected, firedThreats: detected ? [2] : [], outcome: shouldDetect ? (detected ? "TP" : "FN") : (detected ? "FP" : "TN") });

test("scoreSplits reports tune and held-out recall SEPARATELY, not blended", () => {
  const rows = [
    row("t1", "DAN", "tune", true),
    row("t2", "DAN", "tune", true),      // tune: 2/2 = 100%
    row("h1", "DAN", "heldout", true),
    row("h2", "DAN", "heldout", false),  // heldout: 1/2 = 50%
    row("b1", "benign", undefined, false, false) // benign row ignored by split recall
  ];
  const s = scoreSplits(rows);
  assert.equal(s.tune.attacks, 2);
  assert.equal(s.tune.recall, 1, "tune recall = 2/2");
  assert.equal(s.heldout.attacks, 2);
  assert.equal(s.heldout.recall, 0.5, "held-out recall = 1/2 — NOT blended with tune");
  // If they were blended the overall would be 3/4 = 0.75; assert neither split equals that.
  assert.notEqual(s.tune.recall, 0.75);
  assert.notEqual(s.heldout.recall, 0.75);
});

test("held-out misses are enumerated for the honest gap report", () => {
  const rows = [
    row("h-caught", "PAP", "heldout", true),
    row("h-missed", "AdvPrefix", "heldout", false)
  ];
  const s = scoreSplits(rows);
  assert.deepEqual(s.heldout.misses, [{ id: "h-missed", family: "AdvPrefix" }]);
  assert.equal(s.heldout.caught, 1);
});

test("untagged attack rows default to the tune split (back-compat with corpus.json)", () => {
  const rows = [row("u1", "DAN", undefined, true)];
  const s = scoreSplits(rows);
  assert.equal(s.tune.attacks, 1, "an attack row with no split is counted as tune");
  assert.equal(s.heldout.attacks, 0);
});

test("per-family recall within a split is correct and sorted worst-first", () => {
  const rows = [
    row("h1", "BoN", "heldout", true),
    row("h2", "BoN", "heldout", true),        // BoN 2/2 = 100%
    row("h3", "AdvPrefix", "heldout", false)  // AdvPrefix 0/1 = 0%
  ];
  const s = scoreSplits(rows);
  assert.equal(s.heldout.families[0].family, "AdvPrefix", "worst family sorts first");
  assert.equal(s.heldout.families[0].recall, 0);
  const bon = s.heldout.families.find((f) => f.family === "BoN");
  assert.equal(bon.recall, 1);
});
