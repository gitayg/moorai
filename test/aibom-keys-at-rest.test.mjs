// AI-provider API keys AT REST — the AIBOM finds provider keys stored in a bounded, documented set of
// places (shell startup files, known AI-CLI config dirs, top-level .env files of a few dev dirs) and
// reports ONLY provider + location class + a KEYED one-way hash. Same harness as shadow.test.mjs: a
// throwaway HOME seeded with the exact files the collector reads, the REAL CLI run end-to-end.
//
// The load-bearing assertion is the negative one: the raw key, any prefix/suffix of it, and the file
// contents never appear anywhere in the output (json, md, and the shadow report).
//
//   node --test test/aibom-keys-at-rest.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { hashWithKey, deriveKey, NO_KEY } from "../cli/content-hash.mjs";
import { findAiKeys } from "../data/ai-key-shapes.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");
const SHADOW = join(ROOT, "cli", "moorai-shadow.mjs");
const TOKEN = "test-install-token-aibom-keys";

// Obviously fake values that still satisfy the provider shapes (gitleaks-derived, data/ai-key-shapes.js).
const fill = (n, seed) => seed.repeat(Math.ceil(n / seed.length)).slice(0, n);
const KEYS = {
  anthropic: "sk-ant-api03-" + fill(93, "FAKEtestKEY0") + "AA",
  openai: "sk-proj-" + fill(74, "FAKEtestOpenAI0") + "T3BlbkFJ" + fill(74, "TESTfakeKEY9"),
  googleCli: "AIza" + fill(35, "FAKEtestGemini1"),
  googleDotenv: "AIza" + fill(35, "FAKEtestGemini2"),
  hf: "hf_" + fill(34, "fakehuggingfacetest"),
  pplx: "pplx-" + fill(48, "FAKEtestPplx0"),
  // must NOT be reported
  maps: "AIza" + fill(35, "FAKEtestMapsKey"),
  big: "sk-ant-api03-" + fill(93, "FAKEbigFILE00") + "AA",
  bin: "sk-ant-api03-" + fill(93, "FAKEbinFILE00") + "AA",
  deep: "sk-ant-api03-" + fill(93, "FAKEdeepDIR00") + "AA",
  example: "sk-ant-api03-" + fill(93, "FAKEexample00") + "AA",
  unreadable: "sk-ant-api03-" + fill(93, "FAKEunread000") + "AA"
};
const SENTINELS = ["SENTINEL_RC_CONTENT", "SENTINEL_ENV_CONTENT", "SENTINEL_CLI_CONTENT"];
const H = (k) => hashWithKey(deriveKey(TOKEN), k);

function seedHome({ enrolled = true, sanctioned } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-keys-"));
  const w = (rel, body) => { const p = join(home, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); return p; };
  w(".zshrc", `alias ll='ls -la' # SENTINEL_RC_CONTENT\nexport ANTHROPIC_API_KEY="${KEYS.anthropic}"\n`);
  w(".config/fish/config.fish", `set -gx OPENAI_API_KEY ${KEYS.openai}\n`);
  w(".config/aichat/config.yaml", `# SENTINEL_CLI_CONTENT\nclients:\n  - type: gemini\n    api_key: ${KEYS.googleCli}\n`);
  w(".env", `GEMINI_API_KEY=${KEYS.googleDotenv}\n`);
  w("code/myproj/.env", `HF_TOKEN=${KEYS.hf}\nPPLX_KEY='${KEYS.pplx}'\nDB_HOST=SENTINEL_ENV_CONTENT\n`);
  w("code/maps/.env", `MAPS_API_KEY=${KEYS.maps}\n`);                       // Google shape, not an AI variable
  w("code/big/.env", `ANTHROPIC_API_KEY=${KEYS.big}\n` + "#".repeat(1024 * 1024 + 10)); // > 1 MB
  w("code/bin/.env", Buffer.concat([Buffer.from(`K=${KEYS.bin}\n`), Buffer.from([0, 1, 2, 0])])); // binary
  w("code/a/b/.env", `ANTHROPIC_API_KEY=${KEYS.deep}\n`);                   // depth 2 — never walked
  w("code/myproj/.env.example", `ANTHROPIC_API_KEY=${KEYS.example}\n`);     // template — skipped
  const unread = w(".bashrc", `export ANTHROPIC_API_KEY=${KEYS.unreadable}\n`);
  chmodSync(unread, 0o000);                                                 // fail-open
  const cfg = { serverUrl: "http://localhost:1", tenant: "t" };
  if (enrolled) cfg.installToken = TOKEN;
  if (sanctioned) cfg.sanctioned = sanctioned;
  w(".moorai/config.json", JSON.stringify(cfg));
  const fixture = w("probe-fixture.json", "{}"); // no listeners / processes — hermetic
  return { home, fixture };
}

function run(cli, { home, fixture }, args = []) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture };
  delete env.MOORAI_SANCTIONED; delete env.MOORAI_AIBOM_JSON;
  return execFileSync(process.execPath, [cli, ...args], { env, encoding: "utf8" });
}
const cleanup = (h) => { try { chmodSync(join(h.home, ".bashrc"), 0o600); } catch {} rmSync(h.home, { recursive: true, force: true }); };

function assertNoLeak(out, label) {
  for (const [name, k] of Object.entries(KEYS)) {
    assert.ok(!out.includes(k), `${label}: raw ${name} key leaked`);
    // no distinguishing prefix/suffix either: the first 8 chars AFTER the public shape prefix, and the tail
    const body = k.replace(/^(sk-ant-api03-|sk-proj-|AIza|hf_|pplx-)/, "");
    assert.ok(!out.includes(body.slice(0, 8)), `${label}: ${name} key prefix leaked`);
    assert.ok(!out.includes(k.slice(-10)), `${label}: ${name} key suffix leaked`);
  }
  for (const s of SENTINELS) assert.ok(!out.includes(s), `${label}: file content ${s} leaked`);
}

test("shape table: each fake key is classified to its provider; Google needs an AI context", () => {
  assert.deepEqual(findAiKeys(`X=${KEYS.anthropic}`).map((f) => f.provider), ["Anthropic"]);
  assert.deepEqual(findAiKeys(`X=${KEYS.openai}`).map((f) => f.provider), ["OpenAI"]);
  assert.deepEqual(findAiKeys(`HF_TOKEN=${KEYS.hf}`).map((f) => f.provider), ["Hugging Face"]);
  assert.deepEqual(findAiKeys(`P=${KEYS.pplx}`).map((f) => f.provider), ["Perplexity"]);
  assert.deepEqual(findAiKeys(`GEMINI_API_KEY=${KEYS.googleDotenv}`).map((f) => f.provider), ["Google"]);
  assert.deepEqual(findAiKeys(`MAPS_API_KEY=${KEYS.maps}`), [], "a bare Google API key is not an AI key");
  assert.deepEqual(findAiKeys(`api_key: ${KEYS.maps}`, { aiContext: true }).map((f) => f.provider), ["Google"]);
  assert.deepEqual(findAiKeys("sk-ant-api03-short"), [], "truncated shape does not match");
});

test("AIBOM reports provider + location class + keyed hash for each key at rest, nothing else", () => {
  const h = seedHome();
  try {
    const out = run(AIBOM, h);
    const d = JSON.parse(out);
    const f = d.apiKeysAtRest;
    assert.ok(Array.isArray(f), "apiKeysAtRest present");
    const has = (provider, locationClass, location, key) =>
      f.some((x) => x.provider === provider && x.locationClass === locationClass && x.location === location && x.keyHash === H(key));
    assert.ok(has("Anthropic", "shell-rc", "~/.zshrc", KEYS.anthropic), "zshrc Anthropic key");
    assert.ok(has("OpenAI", "shell-rc", "~/.config/fish/config.fish", KEYS.openai), "fish OpenAI key");
    assert.ok(has("Google", "ai-cli-config", "~/.config/aichat", KEYS.googleCli), "aichat Google key");
    assert.ok(has("Google", "dotenv", "~/.env", KEYS.googleDotenv), "~/.env Google key");
    assert.ok(has("Hugging Face", "dotenv", null, KEYS.hf), "project .env HF key — no path");
    assert.ok(has("Perplexity", "dotenv", null, KEYS.pplx), "project .env Perplexity key — no path");
    assert.equal(f.length, 6, `exactly the six in-scope keys: ${JSON.stringify(f)}`);
    for (const x of f) assert.deepEqual(Object.keys(x).sort(), ["keyHash", "location", "locationClass", "provider"]);
    for (const k of ["maps", "big", "bin", "deep", "example", "unreadable"])
      assert.ok(!f.some((x) => x.keyHash === H(KEYS[k])), `${k} key must not be reported`);
    assert.equal(d.summary.apiKeysAtRest, 6);
    assertNoLeak(out, "json");
    assertNoLeak(run(AIBOM, h, ["--format", "md"]), "md");
    assertNoLeak(run(AIBOM, h, ["--format", "csv"]), "csv");
  } finally { cleanup(h); }
});

test("unenrolled device: every key hashes to the NO_KEY sentinel, never a reversible value", () => {
  const h = seedHome({ enrolled: false });
  try {
    const out = run(AIBOM, h);
    const f = JSON.parse(out).apiKeysAtRest;
    assert.ok(f.length > 0);
    for (const x of f) assert.equal(x.keyHash, NO_KEY);
    assertNoLeak(out, "json-nokey");
  } finally { cleanup(h); }
});

test("shadow: an approved key hash is sanctioned, every other key is shadow — still content-free", () => {
  const h = seedHome({ sanctioned: { models: [], mcpServers: [], extensions: [], apiKeyHashes: [H(KEYS.anthropic)] } });
  try {
    const out = run(SHADOW, h, ["--json"]);
    const d = JSON.parse(out);
    assert.equal(d.allowlistConfigured, true);
    const keys = d.shadow.filter((x) => x.kind === "api-key");
    assert.equal(keys.length, 5, "5 unapproved keys");
    assert.ok(!keys.some((x) => x.keyHash === H(KEYS.anthropic)), "approved key excluded");
    assert.ok(keys.some((x) => x.provider === "OpenAI" && x.locationClass === "shell-rc" && x.keyHash === H(KEYS.openai)));
    assert.equal(d.summary.byKind["api-key"], 5);
    assertNoLeak(out, "shadow-json");
    assertNoLeak(run(SHADOW, h), "shadow-human");
  } finally { cleanup(h); }
});

test("shadow: the NO_KEY sentinel on an allow-list never sanctions a key", () => {
  const h = seedHome({ enrolled: false, sanctioned: { apiKeyHashes: [NO_KEY] } });
  try {
    const d = JSON.parse(run(SHADOW, h, ["--json"]));
    assert.equal(d.shadow.filter((x) => x.kind === "api-key").length, 6);
  } finally { cleanup(h); }
});
