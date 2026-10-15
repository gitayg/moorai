// seenOnce (cli/seen-once.mjs) decides whether a once-only alert posts: a local exception granted or
// ignored (ttl = Infinity), a transit override, a rejected tag policy, a containment alert (ttl = 1 day).
// The inline version read a key with no record as recorded at time 0, and 0 is less than Infinity ago,
// so with the default ttl every new key read as seen and those alerts never posted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { seenOnce, SEEN_KEEP_MS, SEEN_MAX } from "../cli/seen-once.mjs";

const store = (init = null) => { let v = init; return { read: () => v, write: (o) => { v = o; }, get: () => v }; };
const DAY = 86400000;

test("seenOnce: a new key is not seen with the default ttl, and is seen after", () => {
  const s = store();
  assert.equal(seenOnce("grant:ex-1", undefined, { ...s, now: 1_000_000 }), false, "first sight posts");
  assert.equal(seenOnce("grant:ex-1", undefined, { ...s, now: 1_000_000 + DAY }), true, "once only");
  assert.equal(seenOnce("ignored:ex-2", Infinity, { ...s, now: 1_000_000 + DAY }), false, "another key posts");
});

test("seenOnce: a finite ttl lets the key through again once it has passed", () => {
  const s = store();
  assert.equal(seenOnce("transit:a", DAY, { ...s, now: 10 * DAY }), false);
  assert.equal(seenOnce("transit:a", DAY, { ...s, now: 10 * DAY + DAY - 1 }), true);
  assert.equal(seenOnce("transit:a", DAY, { ...s, now: 10 * DAY + DAY }), false);
});

test("seenOnce: records older than 7 days are dropped and at most 400 kept, so a once-only key can come back", () => {
  const s = store();
  seenOnce("grant:old", Infinity, { ...s, now: 1 });
  seenOnce("grant:new", Infinity, { ...s, now: 1 + SEEN_KEEP_MS });
  assert.ok(!("grant:old" in s.get()), "pruned on the next write");
  assert.equal(seenOnce("grant:old", Infinity, { ...s, now: 2 + SEEN_KEEP_MS }), false);
  const big = store(Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`k${i}`, 5 * DAY])));
  seenOnce("fresh", Infinity, { ...big, now: 5 * DAY + 1 });
  assert.equal(Object.keys(big.get()).length, SEEN_MAX + 1);
});

test("seenOnce: a junk or zero record is no record; a broken store counts as seen", () => {
  assert.equal(seenOnce("k", Infinity, { ...store({ k: "junk" }), now: DAY }), false);
  assert.equal(seenOnce("k", Infinity, { ...store({ k: 0 }), now: DAY }), false);
  assert.equal(seenOnce("k", Infinity, { read: () => { throw new Error("EIO"); }, write: () => {}, now: DAY }), true);
});
