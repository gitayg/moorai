// The single most damaging way this harness could lie: serve an 8B llama3 verdict to a run that
// believes it is measuring a frontier model (or the reverse). Both numbers would look plausible, the
// blend would be invisible in the report, and the published figure would be corrupt.
//
// These tests pin the three independent layers that make that impossible. No model calls.
//   node --test test/refusal-backend-isolation.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  BACKENDS, PROBE_VERSION, PROBE_VERSIONS, probeVersionFor, cacheKeyFor, readCacheEntry,
} from "../scripts/measure-refusal-baseline.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("every backend has its OWN probe version, and none is shared", () => {
  const versions = BACKENDS.map(probeVersionFor);
  assert.equal(new Set(versions).size, BACKENDS.length, `probe versions collide: ${versions}`);
  // The exported PROBE_VERSION is the ollama one, unchanged, so the existing baseline cache and the
  // published "probe v2-ollama" provenance string keep meaning exactly what they meant.
  assert.equal(PROBE_VERSION, PROBE_VERSIONS.ollama);
  assert.equal(PROBE_VERSION, "v2-ollama");
});

test("an unknown backend throws instead of silently keying into someone else's namespace", () => {
  assert.throws(() => probeVersionFor("gpt4"), /unknown backend/i);
  assert.throws(() => cacheKeyFor("m", "refusal", "x", 0, "gpt4"), /unknown backend/i);
});

// LAYER 1 — the key. Same model string, same probe, same sample, same run index: the ONLY difference
// is the backend, and the keys must still be disjoint. This is the case a shared cache file would hit.
test("backend alone makes cache keys disjoint, even with an identical model string", () => {
  const o = cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0, "ollama");
  const c = cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0, "claude");
  assert.notEqual(o, c);
  assert.ok(o.startsWith("v2-ollama|"), o);
  assert.ok(c.startsWith("v3-claude|"), c);
});

test("the ollama key shape is byte-identical to the one the existing baseline cache was written with", () => {
  assert.equal(cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0), "v2-ollama|llama3:latest|refusal|hv2-x-001|0");
  assert.equal(cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0, "ollama"),
    cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0));
});

// LAYER 2 — the entry guard. Even if a key somehow collided (hand-edited cache, a future backend whose
// probe version was set carelessly), the entry itself declares which backend produced it and a read
// under the wrong backend returns nothing rather than a wrong verdict.
test("an entry stamped with another backend is unreadable even when the key matches", () => {
  const k = cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0, "claude");
  const poisoned = { [k]: { backend: "ollama", outcome: "refusal", raw: "I cannot help with that." } };
  assert.equal(readCacheEntry(poisoned, k, "claude"), null);
  assert.equal(readCacheEntry(poisoned, k, "ollama").outcome, "refusal");
});

test("a legacy entry with no backend stamp reads as ollama only — never as a frontier verdict", () => {
  const k = cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0, "ollama");
  const legacy = { [k]: { outcome: "refusal", raw: "I cannot help with that." } };
  assert.equal(readCacheEntry(legacy, k, "ollama").outcome, "refusal");
  const kc = cacheKeyFor("llama3:latest", "refusal", "hv2-x-001", 0, "claude");
  assert.equal(readCacheEntry({ [kc]: { outcome: "refusal" } }, kc, "claude"), null);
});

// LAYER 3 — the real artifact. Not a synthetic key: every key actually present in the committed
// llama3 baseline cache must be unreachable from a claude-backend lookup of the same sample.
test("no key in the committed llama3 baseline cache is reachable from a claude-backend lookup", () => {
  const cache = JSON.parse(readFileSync(join(ROOT, "test/redteam/refusal-baseline-runs.json"), "utf8"));
  const keys = Object.keys(cache);
  assert.ok(keys.length > 100, `expected a populated baseline cache, got ${keys.length} keys`);
  let checked = 0;
  for (const k of keys) {
    const [, model, probe, id, run] = k.split("|");
    const claudeKey = cacheKeyFor(model, probe, id, Number(run), "claude");
    assert.notEqual(claudeKey, k);
    assert.equal(readCacheEntry(cache, claudeKey, "claude"), null, `${k} leaked into the claude namespace`);
    checked++;
  }
  assert.equal(checked, keys.length);
});
