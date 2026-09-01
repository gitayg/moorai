import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { nextLink, verifyChain, recordRhash, genesis } from "../cli/record-chain.mjs";

const dir = () => mkdtempSync(join(tmpdir(), "moorai-chain-"));

// Build a valid, chained log the way signals.mjs append() does: fingerprint the record, take a link,
// stamp it on. Sequential nextLink calls against one temp dir advance the persisted head.
function chainedLog(entries, { logKey = "log", tenant } = {}) {
  const d = dir();
  return entries.map((e) => {
    const rhash = recordRhash(e);
    const link = nextLink(logKey, rhash, { tenant, dir: d });
    return { ...e, rhash, seq: link.seq, prev: link.prev, chash: link.chash };
  });
}

test("recordRhash is deterministic, key-order stable, and ignores chain fields", () => {
  const a = recordRhash({ ts: 1, category: "x" });
  const b = recordRhash({ category: "x", ts: 1 });
  assert.equal(a, b, "same content in different key order must hash identically");
  const withChain = recordRhash({ ts: 1, category: "x", seq: 9, prev: "p", chash: "c", rhash: "r" });
  assert.equal(a, withChain, "chain fields must not affect the content fingerprint");
  assert.notEqual(a, recordRhash({ ts: 1, category: "y" }), "a changed field must change the fingerprint");
});

test("genesis is deterministic and distinct per log and per tenant", () => {
  assert.equal(genesis("a"), genesis("a"));
  assert.notEqual(genesis("a"), genesis("b"));
  assert.notEqual(genesis("a", "t1"), genesis("a", "t2"));
});

test("nextLink advances a monotonic, back-linked sequence from genesis", () => {
  const d = dir();
  const l1 = nextLink("s", "ra", { dir: d });
  const l2 = nextLink("s", "rb", { dir: d });
  const l3 = nextLink("s", "rc", { dir: d });
  assert.deepEqual([l1.seq, l2.seq, l3.seq], [1, 2, 3]);
  assert.equal(l1.prev, genesis("s"), "first record links to genesis");
  assert.equal(l2.prev, l1.chash, "each record links to the previous chash");
  assert.equal(l3.prev, l2.chash);
});

test("a well-formed chain verifies ok, with and without the genesis anchor", () => {
  const recs = chainedLog([{ ts: 1, category: "a" }, { ts: 2, category: "b" }, { ts: 3, category: "c" }]);
  assert.deepEqual(verifyChain(recs, { rhashOf: recordRhash }), { ok: true, count: 3, breaks: [] });
  assert.equal(verifyChain(recs, { logKey: "log", rhashOf: recordRhash }).ok, true);
});

test("an in-place field edit is caught as content_altered (chash still matches the stale rhash)", () => {
  const recs = chainedLog([{ ts: 1, category: "a" }, { ts: 2, category: "b" }, { ts: 3, category: "c" }]);
  recs[1] = { ...recs[1], category: "TAMPERED" }; // rhash/chash left stale
  const v = verifyChain(recs, { rhashOf: recordRhash });
  assert.equal(v.ok, false);
  assert.ok(v.breaks.some((b) => b.index === 1 && b.reason === "content_altered"));
});

test("editing a record and recomputing its chash breaks the NEXT record's prev link", () => {
  const recs = chainedLog([{ ts: 1 }, { ts: 2 }, { ts: 3 }]);
  recs[1] = { ...recs[1], chash: "deadbeef" };
  const v = verifyChain(recs, { rhashOf: recordRhash });
  assert.equal(v.ok, false);
  assert.ok(v.breaks.some((b) => b.reason === "chash_mismatch"));
  assert.ok(v.breaks.some((b) => b.index === 2 && b.reason === "prev_mismatch"));
});

test("deleting a middle record is caught as a seq gap + broken link", () => {
  const recs = chainedLog([{ ts: 1 }, { ts: 2 }, { ts: 3 }]);
  const pruned = [recs[0], recs[2]];
  const v = verifyChain(pruned, { rhashOf: recordRhash });
  assert.equal(v.ok, false);
  assert.ok(v.breaks.some((b) => b.reason === "seq_gap"));
  assert.ok(v.breaks.some((b) => b.reason === "prev_mismatch"));
});

test("reordering records breaks the chain", () => {
  const recs = chainedLog([{ ts: 1 }, { ts: 2 }, { ts: 3 }]);
  const swapped = [recs[0], recs[2], recs[1]];
  assert.equal(verifyChain(swapped, { rhashOf: recordRhash }).ok, false);
});

test("a duplicated record is caught as non-monotonic seq", () => {
  const recs = chainedLog([{ ts: 1 }, { ts: 2 }]);
  const dup = [recs[0], recs[1], recs[1]];
  const v = verifyChain(dup, { rhashOf: recordRhash });
  assert.equal(v.ok, false);
  assert.ok(v.breaks.some((b) => b.reason === "seq_nonmonotonic"));
});

test("a record with no chain stamp is reported as unchained", () => {
  const v = verifyChain([{ ts: 1, category: "a" }], { rhashOf: recordRhash });
  assert.equal(v.ok, false);
  assert.ok(v.breaks.some((b) => b.reason === "unchained"));
});
