// guardd derives the actor of an IPC peer itself (guardd/src/policy.rs derive_actor) and refuses a policy
// request naming any other actor, so its derivation must equal the hook's actorHash byte for byte.
// guardd/tests/fixtures/actor-vectors.json is generated from cli/content-hash.mjs and read by this test and by
// guardd's `cargo test` (policy::tests::derive_actor_matches_the_hooks_vectors).
//
//   node --test test/guardd-actor-parity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { actorHash, contentHash, hashWithKey, deriveKey, KEY_LABEL, NO_KEY } from "../cli/content-hash.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FILE = join(ROOT, "guardd", "tests", "fixtures", "actor-vectors.json");
const FX = JSON.parse(readFileSync(FILE, "utf8"));

test("the hook's actor formula reproduces every vector guardd's derive_actor is tested against", () => {
  assert.equal(FX.keyLabel, KEY_LABEL);
  assert.equal(FX.noKey, NO_KEY);
  assert.ok(FX.vectors.length >= 4);
  for (const { installToken, user, host, actor } of FX.vectors) {
    assert.match(actor, /^h2:[0-9a-f]{16}$/);
    assert.equal(hashWithKey(deriveKey(installToken), `${user}@${host}`), actor, `${user}@${host}`);
  }
});

test("actorHash is exactly the keyed content hash of user@host (no normalisation)", () => {
  for (const [u, h] of [["alice", "Alices-MacBook-Pro.local"], ["JOSÉ-ñ", "host-ü"], ["a@b", "c"]]) assert.equal(actorHash(u, h), contentHash(`${u}@${h}`));
  assert.equal(hashWithKey(deriveKey(""), "a@b"), NO_KEY, "no install token: no keyed actor");
});

test("the fixture is what the generator prints today", () => {
  const r = spawnSync(process.execPath, [join(ROOT, "guardd", "tests", "fixtures", "gen-actor-vectors.mjs"), ROOT], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout), FX);
});
