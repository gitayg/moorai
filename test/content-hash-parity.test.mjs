// Cross-language parity for the keyed content hash. test/fixtures/content-hash-parity.json is read by
// THIS test (Node: cli/content-hash.mjs and the renderer twin src/content-hash.js) and by the Rust
// host's `cargo test` (src-tauri/src/content_hash.rs). Both sides assert the same expected values, so
// a key-at-rest hash the desktop host reports equals the one the Node agent / an alert would carry.
//
//   node --test test/content-hash-parity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { hashWithKey, deriveKey } from "../cli/content-hash.mjs";
import * as browserHash from "../src/content-hash.js";

const FX = JSON.parse(readFileSync(new URL("./fixtures/content-hash-parity.json", import.meta.url), "utf8"));

test("Node agent reproduces every shared vector the Rust host is tested against", () => {
  assert.ok(FX.sets.length >= 2);
  for (const { token, vectors } of FX.sets)
    for (const { input, hash } of vectors) assert.equal(hashWithKey(deriveKey(token), input), hash, `token=${token.slice(0, 12)}… input=${JSON.stringify(input)}`);
});

test("desktop renderer twin (src/content-hash.js) reproduces the same vectors", () => {
  for (const { token, vectors } of FX.sets)
    for (const { input, hash } of vectors) assert.equal(browserHash.hashWithKey(browserHash.deriveKey(token), input), hash);
});
