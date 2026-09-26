// The desktop host (Rust) reports the same two AIBOM signals as the Node CLI — keys at rest and running
// local AI — into the console's device inventory. Two implementations of one contract drift unless
// something pins them: this test reads the Rust tables straight out of src-tauri/src/ai_keys.rs and
// ai_runtime.rs and asserts they equal the JS source of truth (data/ai-key-shapes.js,
// cli/aibom-keys.mjs, cli/aibom-runtime.mjs). The keyed hash is pinned separately by
// test/content-hash-parity.test.mjs + the Rust `cargo test` over the same fixture.
//
//   node --test test/aibom-rust-parity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AI_KEY_SHAPES } from "../data/ai-key-shapes.js";
import { SHELL_RC, AI_CLI_DIRS, DEV_ROOTS, MAX_FILE_BYTES } from "../cli/aibom-keys.mjs";
import { RUNTIMES } from "../cli/aibom-runtime.mjs";

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");
const RS_KEYS = read("src-tauri/src/ai_keys.rs");
const RS_RT = read("src-tauri/src/ai_runtime.rs");
const JS_SHAPES = read("data/ai-key-shapes.js");
const JS_KEYS = read("cli/aibom-keys.mjs");
const JS_RT = read("cli/aibom-runtime.mjs");

// the `pub const NAME ... = &[ ... ];` block of a Rust file
function rsBlock(src, name) {
  const i = src.indexOf(`pub const ${name}`);
  assert.ok(i >= 0, `Rust const ${name} not found`);
  const j = src.indexOf("];", i);
  return src.slice(src.indexOf("&[", i) + 2, j);
}
const rsStrings = (block) => [...block.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
function rsNum(src, name) {
  const m = src.match(new RegExp(`pub const ${name}: \\w+ = ([0-9 *_]+);`));
  assert.ok(m, `Rust const ${name} not found`);
  return Function(`return (${m[1].replace(/_/g, "")})`)();
}
function jsNum(src, name) {
  const m = src.match(new RegExp(`const ${name} = ([0-9 *]+);`));
  assert.ok(m, `JS const ${name} not found`);
  return Function(`return (${m[1]})`)();
}

test("key shapes: every Rust row is the JS regex source (minus the END lookahead Rust applies itself)", () => {
  const END = "(?![A-Za-z0-9_-])";
  const rows = [...rsBlock(RS_KEYS, "AI_KEY_SHAPES").matchAll(/\(\s*"([^"]+)",\s*r"([^"]*)",\s*(true|false)\s*\)/g)]
    .map((m) => ({ provider: m[1], src: m[2], ctx: m[3] === "true" }));
  assert.equal(rows.length, AI_KEY_SHAPES.length, "same number of shapes");
  AI_KEY_SHAPES.forEach((s, i) => {
    assert.equal(rows[i].provider, s.provider, `row ${i} provider`);
    assert.equal(rows[i].src + END, s.re.source, `row ${i} (${s.provider}) pattern`);
    assert.equal(rows[i].ctx, !!s.needsAiContext, `row ${i} needsAiContext`);
    assert.equal(s.re.flags, "g", "a JS flag Rust does not mirror would change semantics");
  });
  const jsGoogle = JS_SHAPES.match(/const GOOGLE_AI_NAME = \/(.+)\/i;/)[1];
  const rsGoogle = RS_KEYS.match(/pub const GOOGLE_AI_NAME: &str = r"([^"]+)";/)[1];
  assert.equal(rsGoogle, jsGoogle);
});

test("keys-at-rest scope: same files, dirs, roots and caps", () => {
  assert.deepEqual(rsStrings(rsBlock(RS_KEYS, "SHELL_RC")), SHELL_RC);
  assert.deepEqual(rsStrings(rsBlock(RS_KEYS, "AI_CLI_DIRS")), AI_CLI_DIRS.flat());
  assert.deepEqual(rsStrings(rsBlock(RS_KEYS, "DEV_ROOTS")), DEV_ROOTS);
  assert.equal(rsNum(RS_KEYS, "MAX_FILE_BYTES"), MAX_FILE_BYTES);
  for (const n of ["MAX_CLI_FILES_PER_DIR", "MAX_DEV_CHILDREN", "MAX_DOTENV_FILES"]) assert.equal(rsNum(RS_KEYS, n), jsNum(JS_KEYS, n), n);
  // dotenv name rules: the JS regexes the Rust is_dotenv_name hand-codes
  assert.match(JS_KEYS, /const DOTENV_NAME = \/\^\\\.env\(\?:\\\.\[A-Za-z0-9_-\]\+\)\?\$\/;/);
  assert.match(JS_KEYS, /const DOTENV_TEMPLATE = \/example\|sample\|template\|dist\/i;/);
});

test("running local AI: same runtimes table, same probe commands, same timeout", () => {
  const rows = [...rsBlock(RS_RT, "RUNTIMES").matchAll(/\(\s*"([^"]+)",\s*&\[([^\]]*)\],\s*&\[([^\]]*)\],\s*(true|false)\s*\)/g)]
    .map((m) => ({ runtime: m[1], names: rsStrings(m[2]), ports: m[3].split(",").map((x) => x.trim()).filter(Boolean).map(Number), portAlone: m[4] === "true" }));
  assert.deepEqual(rows, RUNTIMES);
  for (const argv of [`"lsof", &["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"]`, `"ps", &["-A", "-o", "comm="]`, `"netstat", &["-ano"]`, `"tasklist", &["/FO", "CSV", "/NH"]`])
    assert.ok(RS_RT.includes(argv), `Rust probe ${argv}`);
  for (const argv of [`"lsof", ["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"]`, `"ps", ["-A", "-o", "comm="]`, `"netstat", ["-ano"]`, `"tasklist", ["/FO", "CSV", "/NH"]`])
    assert.ok(JS_RT.includes(argv), `JS probe ${argv}`);
  assert.match(JS_RT, /timeout: 5000/);
  assert.match(RS_RT, /pub const TIMEOUT: Duration = Duration::from_secs\(5\);/);
  const jsHosts = JS_RT.match(/const LOCAL_HOSTS = new Set\(\[(.*)\]\);/)[1];
  const rsHosts = RS_RT.match(/const LOCAL_HOSTS: &\[&str\] = &\[(.*)\];/)[1];
  assert.deepEqual(rsStrings(rsHosts), rsStrings(jsHosts));
});

// Behavioural half of the key-shape parity: the same cases, asserted here against findAiKeys and in
// src-tauri/src/ai_keys.rs against find_ai_keys (see `shared_fixture_cases_match_node`).
test("key shapes: the shared fixture's expected findings hold for the JS matcher", async () => {
  const { findAiKeys } = await import("../data/ai-key-shapes.js");
  const FX = JSON.parse(read("test/fixtures/ai-key-shapes-parity.json"));
  const fill = (n, seed) => seed.repeat(Math.ceil(n / seed.length)).slice(0, n);
  const key = (name) => { const [p, n, seed, s] = FX.keys[name]; const t = FX.suffixes[name]; return p + fill(n, seed) + s + (t ? t[0] + fill(t[1], t[2]) : ""); };
  assert.ok(FX.cases.length >= 15);
  for (const c of FX.cases) {
    const text = c.text.replace(/\{(\w+)\}/g, (_, n) => key(n));
    assert.deepEqual(findAiKeys(text, { aiContext: c.ctx }).map((f) => [f.provider, f.value]), c.expect.map(([p, n]) => [p, key(n)]), c.text);
  }
});
