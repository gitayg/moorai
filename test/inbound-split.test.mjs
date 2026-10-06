// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/inbound-split.test.mjs
//
// The inbound evaluation split (scripts/inbound-corpus.mjs) is fixed: 60% tune / 40% locked by
// sha256(SEED:corpus:id), with benign-web-content's and atlas-2026-09's own locked halves kept locked.
// Its manifest hash is pinned so the split cannot drift under a later corpus or rule edit without this
// test saying so — a moved sample would silently turn locked rows into tunable ones.
import { test } from "node:test";
import assert from "node:assert/strict";
import { repoSamples, splitHash, hashSplit, TUNE_SHARE } from "../scripts/inbound-corpus.mjs";

const PINNED = "c776db3f74b15c8956a7339aab0073a0a0bab15f3201c51eb5bb41d2eade6f11";

test("the inbound split manifest hash is pinned", () => {
  const s = repoSamples();
  assert.equal(s.length, 1155);
  assert.equal(splitHash(s), PINNED);
});

test("corpora with their own locked half keep it locked", () => {
  for (const r of repoSamples().filter((x) => x.corpus === "web" || x.corpus === "atlas")) {
    assert.ok(r.split === "tune" || r.split === "locked");
  }
  const web = repoSamples().filter((x) => x.corpus === "web");
  assert.equal(web.filter((x) => x.split === "locked").length, 153);
});

test("the hash split is deterministic and near its share", () => {
  assert.equal(hashSplit("vector2", "v2-web-001"), hashSplit("vector2", "v2-web-001"));
  const ids = Array.from({ length: 2000 }, (_, i) => `x-${i}`);
  const share = ids.filter((id) => hashSplit("probe", id) === "tune").length / ids.length;
  assert.ok(Math.abs(share - TUNE_SHARE) < 0.04, String(share));
});
