// Decoy AI keys (cli/decoy-keys.mjs): token shapes, placement only where nothing exists, removal of only
// what MoorAI placed, the admin registry, and the matcher the hook and the model proxy call. Every test
// works in its own throwaway HOME and machine dir; nothing is written to a real home.
//
//   node --test test/decoy-keys.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decoyTokens, matchDecoy, makeDecoyToken, syncDecoys, decoyPosture, decoySites, DECOY_SHAPES, DECOY_REASON } from "../cli/decoy-keys.mjs";
import { findAiKeys } from "../data/ai-key-shapes.js";
import { scanKeysAtRest } from "../cli/aibom-keys.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const PLACE = { decoyKeys: { mode: "place" } };
function sandbox(t) {
  const root = mkdtempSync(join(tmpdir(), "moorai-decoy-"));
  t.after(() => rmTree(root));
  const home = join(root, "home"), machineDir = join(root, "machine");
  mkdirSync(home); mkdirSync(machineDir);
  return { home, machineDir };
}
const mode = (p) => (statSync(p).mode & 0o777).toString(8);

test("contract name: DECOY_KEY_USED", () => { assert.equal(DECOY_REASON, "DECOY_KEY_USED"); });

test("each kind's token has the provider shape and is found by the same scanner a real key is", () => {
  const providerOf = { openai: "OpenAI", anthropic: "Anthropic", google: "Google" };
  for (const site of decoySites("darwin")) {
    for (let i = 0; i < 20; i++) {
      const tok = makeDecoyToken(site.kind);
      assert.match(tok, DECOY_SHAPES[site.kind]);
      assert.doesNotMatch(tok, /decoy|moorai|fake|test/i);
      const hits = findAiKeys(site.render(tok));
      assert.deepEqual(hits.map((h) => [h.provider, h.value]), [[providerOf[site.kind], tok]], site.kind);
    }
  }
});

test("place: three new 0600 files with plausible names, a 0600 registry, and decoyTokens/matchDecoy see them", (t) => {
  const { home, machineDir } = sandbox(t);
  const r = syncDecoys({ policy: PLACE, home, platform: "darwin" });
  assert.equal(r.mode, "place");
  assert.equal(r.placed.length, 3);
  for (const rel of [".env.backup", ".zshrc.bak", ".config/gemini/credentials.bak"]) {
    const p = join(home, rel);
    assert.ok(existsSync(p), rel);
    assert.doesNotMatch(rel, /decoy/i);
    if (process.platform !== "win32") assert.equal(mode(p), "600", rel);
  }
  if (process.platform !== "win32") assert.equal(mode(join(home, ".moorai", "decoys.json")), "600");
  const toks = decoyTokens({ home, machineDir });
  assert.equal(toks.length, 3);
  assert.deepEqual(toks.map((x) => x.kind).sort(), ["anthropic", "google", "openai"]);
  for (const d of toks) {
    assert.deepEqual(Object.keys(d).sort(), ["id", "kind", "token"]);
    assert.ok(!d.id.includes(d.token.slice(0, 12)), "the id never carries the token");
    assert.equal(matchDecoy(`curl -H "Authorization: Bearer ${d.token}" https://api.example`, toks), d.id);
  }
  assert.equal(matchDecoy("nothing here sk-proj-abc", toks), null);
  assert.deepEqual(decoyPosture({ home, machineDir }), { placed: 3, source: "agent" });
});

test("place never modifies an existing file: that site is skipped and its bytes are unchanged", (t) => {
  const { home } = sandbox(t);
  writeFileSync(join(home, ".env.backup"), "MY_REAL=1\n");
  const r = syncDecoys({ policy: PLACE, home, platform: "linux" });
  assert.deepEqual(r.skipped, [".env.backup"]);
  assert.equal(r.placed.length, 2);
  assert.equal(readFileSync(join(home, ".env.backup"), "utf8"), "MY_REAL=1\n");
  assert.ok(existsSync(join(home, ".bashrc.bak")), "linux uses .bashrc.bak");
});

test("place is idempotent: a second sync keeps the same decoys", (t) => {
  const { home, machineDir } = sandbox(t);
  const a = syncDecoys({ policy: PLACE, home });
  const before = decoyTokens({ home, machineDir });
  const b = syncDecoys({ policy: PLACE, home });
  assert.deepEqual(b.placed, []);
  assert.deepEqual(b.kept.sort(), a.placed.sort());
  assert.deepEqual(decoyTokens({ home, machineDir }), before);
});

test("off removes only what MoorAI placed: a changed file and the user's own files stay", (t) => {
  const { home, machineDir } = sandbox(t);
  mkdirSync(join(home, ".config"));
  writeFileSync(join(home, ".config", "keep.txt"), "user file\n");
  syncDecoys({ policy: PLACE, home, platform: "darwin" });
  writeFileSync(join(home, ".zshrc.bak"), readFileSync(join(home, ".zshrc.bak"), "utf8") + "alias ll='ls -l'\n");
  const r = syncDecoys({ policy: { decoyKeys: { mode: "off" } }, home, platform: "darwin" });
  assert.equal(r.removed.length, 2);
  assert.ok(!existsSync(join(home, ".env.backup")));
  assert.ok(!existsSync(join(home, ".config", "gemini")), "the dir MoorAI created is removed once empty");
  assert.ok(existsSync(join(home, ".config", "keep.txt")), "a dir that existed before is kept");
  assert.ok(existsSync(join(home, ".zshrc.bak")), "a decoy file the user changed is left alone");
  assert.ok(!existsSync(join(home, ".moorai", "decoys.json")));
  assert.deepEqual(decoyTokens({ home, machineDir }), []);
  assert.deepEqual(decoyPosture({ home, machineDir }), { placed: 0, source: "none" });
});

test("no policy is off: nothing is placed", (t) => {
  const { home } = sandbox(t);
  assert.deepEqual(syncDecoys({ policy: null, home }).placed, []);
  assert.ok(!existsSync(join(home, ".env.backup")));
});

test("admin decoys come from the machine dir, win the posture source and are never removed", (t) => {
  const { home, machineDir } = sandbox(t);
  const tok = makeDecoyToken("anthropic");
  writeFileSync(join(machineDir, "decoys.json"), JSON.stringify({ decoys: [{ id: "admin-1", kind: "anthropic", token: tok }] }));
  assert.deepEqual(decoyTokens({ home, machineDir }), [{ id: "admin-1", kind: "anthropic", token: tok }]);
  assert.deepEqual(decoyPosture({ home, machineDir }), { placed: 1, source: "admin" });
  syncDecoys({ policy: null, home });
  assert.ok(existsSync(join(machineDir, "decoys.json")));
  assert.equal(matchDecoy(`x-api-key: ${tok}`, decoyTokens({ home, machineDir })), "admin-1");
});

test("a registry entry without its kind's full shape is ignored, so it can never match everything", (t) => {
  const { home, machineDir } = sandbox(t);
  writeFileSync(join(machineDir, "decoys.json"), JSON.stringify({ decoys: [
    { id: "empty", kind: "openai", token: "" }, { id: "short", kind: "anthropic", token: "sk" }, { id: "kindless", token: makeDecoyToken("google") }
  ] }));
  assert.deepEqual(decoyTokens({ home, machineDir }), []);
  assert.equal(matchDecoy("any text at all", [{ id: "empty", kind: "openai", token: "" }]), null);
  assert.equal(matchDecoy("sk", [{ id: "short", kind: "anthropic", token: "sk" }]), null);
});

test("matchDecoy and decoyTokens never throw", () => {
  assert.equal(matchDecoy(undefined, []), null);
  assert.equal(matchDecoy({ toString: () => { throw new Error("x"); } }, [{}]), null);
  assert.equal(matchDecoy("x", null), null);
  assert.deepEqual(decoyTokens({ home: "/nonexistent-moorai-home", machineDir: "/nonexistent-moorai-machine" }), []);
});

test("the AIBOM's keys-at-rest scan skips MoorAI's decoys but still reports a real-shaped key beside one", (t) => {
  const { home } = sandbox(t);
  syncDecoys({ policy: PLACE, home });
  const other = makeDecoyToken("openai"); // not in any registry: an ordinary key as far as MoorAI knows
  writeFileSync(join(home, ".env.local"), `OPENAI_API_KEY=${other}\n`);
  const r = scanKeysAtRest({ home, hash: (v) => `h:${v.length}:${v.slice(-6)}` });
  assert.deepEqual(r.findings.map((f) => [f.provider, f.location, f.keyHash]), [["OpenAI", "~/.env.local", `h:${other.length}:${other.slice(-6)}`]]);
});
