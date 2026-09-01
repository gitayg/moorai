// Honeytoken canary tests. Two things are pinned:
//   1. HASH-ONLY — registering a honeytoken persists ONLY its one-way hash (+ ts + optional label);
//      the token VALUE never lands on disk. Proven end-to-end through the CLI in a throwaway HOME
//      provisioned with an install token, so contentHash produces a real keyed h2: hash.
//   2. checkHoneytokens is a PURE hash-set intersection: it matches a registered hash that was
//      observed (a hit) and ignores one that was not (a miss).
//
//   node --test test/honeytokens.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { checkHoneytokens } from "../cli/moorai-honeytokens.mjs";
import { deriveKey, hashWithKey, NO_KEY } from "../cli/content-hash.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-honeytokens.mjs");

const TOKEN = "hunter2-CANARY-do-not-touch-sk-live-tripwire";
const INSTALL_TOKEN = "it_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY = deriveKey(INSTALL_TOKEN);

function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), "moorai-honey-"));
  const dir = join(home, ".moorai");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "config.json"), JSON.stringify({ tenant: "acme", installToken: INSTALL_TOKEN }));
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  const run = (...args) => execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8", env, maxBuffer: 8 * 1024 * 1024 });
  try { return fn(run, dir); } finally { rmSync(home, { recursive: true, force: true }); }
}

test("register persists ONLY the hash — the token value never reaches disk", () => {
  withHome((run, dir) => {
    run("register", TOKEN, "--label", "aws-decoy");
    const raw = readFileSync(join(dir, "honeytokens.json"), "utf8");
    assert.ok(!raw.includes(TOKEN), "the honeytoken VALUE was written to disk");

    const store = JSON.parse(raw);
    assert.equal(store.tokens.length, 1);
    const rec = store.tokens[0];
    // record is hash-only metadata: exactly {hash, ts, label} and nothing that could be the value.
    assert.deepEqual(Object.keys(rec).sort(), ["hash", "label", "ts"]);
    assert.notEqual(rec.hash, TOKEN);
    // it is the real per-tenant keyed hash of the value, computed independently.
    const expected = hashWithKey(KEY, TOKEN);
    assert.equal(rec.hash, expected);
    assert.match(rec.hash, /^h2:[0-9a-f]{16}$/);
    assert.notEqual(rec.hash, NO_KEY);
  });
});

test("register is idempotent on the hash — no duplicate records", () => {
  withHome((run, dir) => {
    run("register", TOKEN);
    run("register", TOKEN);
    const store = JSON.parse(readFileSync(join(dir, "honeytokens.json"), "utf8"));
    assert.equal(store.tokens.length, 1);
  });
});

test("check reports a HIT for a registered hash and a MISS for an unknown one", () => {
  withHome((run) => {
    run("register", TOKEN);
    const hit = run("check", "--value", TOKEN, "--json");
    const hitJson = JSON.parse(hit);
    assert.equal(hitJson.hits.length, 1);
    assert.equal(hitJson.hits[0].hash, hashWithKey(KEY, TOKEN));

    const miss = run("check", "--value", "some-value-nobody-registered", "--json");
    assert.equal(JSON.parse(miss).hits.length, 0);
  });
});

test("list never emits a token value", () => {
  withHome((run) => {
    run("register", TOKEN, "--label", "decoy");
    const out = run("list");
    assert.ok(!out.includes(TOKEN));
    assert.match(out, /h2:[0-9a-f]{16}/);
    assert.match(out, /decoy/);
  });
});

// ---- the pure match function: no disk, no key, just set intersection ----
test("checkHoneytokens (PURE): matches an observed hit, ignores a miss", () => {
  const registered = [
    { hash: "h2:1111111111111111", ts: "t", label: "a" },
    { hash: "h2:2222222222222222", ts: "t" }
  ];
  // a value nobody should touch (its hash) shows up in observed I/O → a hit.
  const hits = checkHoneytokens(["h2:2222222222222222", "h2:9999999999999999"], registered);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].hash, "h2:2222222222222222");

  // nothing registered was observed → no hit.
  assert.deepEqual(checkHoneytokens(["h2:9999999999999999"], registered), []);
  // empty inputs are safe.
  assert.deepEqual(checkHoneytokens([], registered), []);
  assert.deepEqual(checkHoneytokens(["h2:1111111111111111"], []), []);
});

test("checkHoneytokens accepts a single hash (not just an array)", () => {
  const registered = [{ hash: "h2:abcabcabcabcabca", ts: "t" }];
  assert.equal(checkHoneytokens("h2:abcabcabcabcabca", registered).length, 1);
});
