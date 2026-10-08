// The desktop host (Rust) reports the same AIBOM signals as the Node CLI — keys at rest, running and
// installed local AI, the Windows AI platform and the ODR agent connectors — into the console's device
// inventory. Two implementations of one contract drift unless
// something pins them: this test reads the Rust tables straight out of src-tauri/src/ai_keys.rs and
// ai_runtime.rs and asserts they equal the JS source of truth (data/ai-key-shapes.js,
// cli/aibom-keys.mjs, cli/aibom-runtime.mjs, cli/local-ai-inventory.mjs, cli/listen-sockets.mjs,
// cli/local-ai-windows.mjs). The keyed hash is pinned separately by test/content-hash-parity.test.mjs
// + the Rust `cargo test` over the same fixture; the local-AI parsers by test/local-ai-shared-fixtures
// .test.mjs + the Rust tests over test/fixtures/local-ai/*.json.
//
//   node --test test/aibom-rust-parity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { AI_KEY_SHAPES } from "../data/ai-key-shapes.js";
import { SHELL_RC, AI_CLI_DIRS, DEV_ROOTS, MAX_FILE_BYTES } from "../cli/aibom-keys.mjs";
import { RUNTIMES } from "../cli/aibom-runtime.mjs";
import { LOCAL_AI_RUNTIMES, LOCAL_AI_INSTALLS } from "../cli/local-ai-inventory.mjs";
import { WIN_AI_PS, ODR_ARGV } from "../cli/local-ai-windows.mjs";

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");
const RS_KEYS = read("src-tauri/src/ai_keys.rs");
const RS_RT = read("src-tauri/src/ai_runtime.rs");
const JS_SHAPES = read("data/ai-key-shapes.js");
const JS_KEYS = read("cli/aibom-keys.mjs");
const JS_RT = read("cli/aibom-runtime.mjs");
const RS_LAI = read("src-tauri/src/local_ai.rs");
const RS_SOCK = read("src-tauri/src/listen_sockets.rs");
const RS_WIN = read("src-tauri/src/local_ai_windows.rs");
const JS_LAI = read("cli/local-ai-inventory.mjs");
const JS_SOCK = read("cli/listen-sockets.mjs");
const JS_WIN = read("cli/local-ai-windows.mjs");

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

const rsList = (x) => rsStrings(x);
const rsPorts = (x) => x.split(",").map((v) => v.trim()).filter(Boolean).map(Number);
const rsPairs = (x) => [...x.matchAll(/\(\s*"([^"]*)",\s*"([^"]*)"\s*\)/g)].map((m) => [m[1], m[2]]);
const count = (block, word) => block.split(`${word} {`).length - 1;

test("running local AI: the Rust runtime table is cli/local-ai-inventory.mjs's, row for row", () => {
  const block = rsBlock(RS_LAI, "LOCAL_AI_RUNTIMES");
  const rows = [...block.matchAll(/RuntimeRule \{ runtime: "([^"]+)", names: &\[([^\]]*)\], prefixes: &\[([^\]]*)\], suffixes: &\[([^\]]*)\], ports: &\[([^\]]*)\], port_alone: (true|false) \}/g)]
    .map((m) => ({ runtime: m[1], names: rsList(m[2]), prefixes: rsList(m[3]), suffixes: rsList(m[4]), ports: rsPorts(m[5]), portAlone: m[6] === "true" }));
  assert.equal(rows.length, count(block, "RuntimeRule"), "every Rust row is in the parseable shape");
  const js = LOCAL_AI_RUNTIMES.map((r) => ({ runtime: r.runtime, names: r.names, prefixes: r.prefixes || [], suffixes: r.suffixes || [], ports: r.ports, portAlone: r.portAlone }));
  for (const r of LOCAL_AI_RUNTIMES) assert.deepEqual(Object.keys(r).filter((k) => !["runtime", "names", "prefixes", "suffixes", "ports", "portAlone"].includes(k)), [], `${r.runtime}: a JS rule key Rust does not mirror`);
  assert.deepEqual(rows, js);
  // The four rows cli/aibom-runtime.mjs (and the Rust host before the local-AI port) shipped are still
  // there with the same ids, names and port-alone rules, so a device report stays a superset of the old one.
  for (const old of RUNTIMES) {
    const neu = rows.find((r) => r.runtime === old.runtime);
    assert.ok(neu, `${old.runtime} kept`);
    for (const n of old.names) assert.ok(neu.names.includes(n), `${old.runtime} keeps name ${n}`);
    assert.equal(neu.portAlone, old.portAlone, `${old.runtime} portAlone`);
    if (old.portAlone) assert.deepEqual(neu.ports, old.ports, `${old.runtime} ports`);
  }
});

test("installed local AI: the Rust install table is cli/local-ai-inventory.mjs's, row for row", () => {
  const block = rsBlock(RS_LAI, "LOCAL_AI_INSTALLS");
  const rows = [...block.matchAll(/InstallRule \{ runtime: "([^"]+)", bins: &\[([^\]]*)\], apps: &\[([^\]]*)\], files_all: &\[([^\]]*)\], files_win32: &\[([^\]]*)\], plugins: &\[([^\]]*)\], dirs: &\[([^\]]*)\], only: (?:None|Some\("([^"]+)"\)) \}/g)]
    .map((m) => ({ runtime: m[1], bins: rsList(m[2]), apps: rsList(m[3]), filesAll: rsPairs(m[4]), filesWin32: rsPairs(m[5]), plugins: rsList(m[6]), dirs: rsList(m[7]), only: m[8] || null }));
  assert.equal(rows.length, count(block, "InstallRule"), "every Rust row is in the parseable shape");
  for (const r of LOCAL_AI_INSTALLS) {
    assert.deepEqual(Object.keys(r.files || {}).filter((k) => k !== "all" && k !== "win32"), [], `${r.runtime}: a files platform Rust does not mirror`);
    assert.deepEqual(Object.keys(r).filter((k) => !["runtime", "bins", "apps", "files", "plugins", "dirs", "only"].includes(k)), [], `${r.runtime}: a JS rule key Rust does not mirror`);
  }
  const js = LOCAL_AI_INSTALLS.map((r) => ({ runtime: r.runtime, bins: r.bins || [], apps: r.apps || [], filesAll: (r.files || {}).all || [], filesWin32: (r.files || {}).win32 || [], plugins: r.plugins || [], dirs: r.dirs || [], only: r.only || null }));
  assert.deepEqual(rows, js);
  // the extra bin dirs and the plist rule the two sides hand-code
  for (const d of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]) { assert.ok(JS_LAI.includes(`"${d}"`), `JS ${d}`); assert.ok(RS_LAI.includes(`"${d}"`), `Rust ${d}`); }
  assert.ok(JS_LAI.includes(String.raw`/^[0-9][0-9A-Za-z.+-]{0,31}$/`) && RS_LAI.includes(String.raw`r"^[0-9][0-9A-Za-z.+-]{0,31}$"`), "same version shape");
});

test("local AI probes: same argv, same /proc files, same timeouts on both sides", () => {
  for (const [cmd, args] of [["lsof", ["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"]], ["ps", ["-A", "-o", "pid=,comm="]], ["ss", ["-ltnp"]], ["netstat", ["-ano"]], ["tasklist", ["/FO", "CSV", "/NH"]]]) {
    const q = args.map((a) => `"${a}"`).join(", ");
    assert.ok(JS_SOCK.includes(`runner("${cmd}", [${q}])`), `JS probe ${cmd}`);
    assert.ok(RS_SOCK.includes(`runner("${cmd}", &[${q}], TIMEOUT)`), `Rust probe ${cmd}`);
  }
  for (const f of ["/proc/net/tcp", "/proc/net/tcp6"]) { assert.ok(JS_SOCK.includes(`"${f}"`)); assert.ok(RS_SOCK.includes(`read_file("${f}")`), f); }
  assert.match(JS_LAI, /export function runCmd\(cmd, args, timeout = 5000\)/);
  assert.match(RS_RT, /pub const TIMEOUT: Duration = Duration::from_secs\(5\);/);
  assert.match(JS_WIN, /runner\("powershell", \["-NoProfile", "-NonInteractive", "-Command", WIN_AI_PS\], 10000\)/);
  assert.ok(RS_WIN.includes(`runner("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script], WIN_AI_TIMEOUT)`));
  assert.match(RS_WIN, /pub const WIN_AI_TIMEOUT: Duration = Duration::from_secs\(10\);/);
  assert.equal(rsStrings(rsBlock(RS_WIN, "WIN_AI_PS")).join("; "), WIN_AI_PS, "the Rust PowerShell script is the JS one");
  assert.deepEqual([RS_WIN.match(/pub const ODR_EXE: &str = "([^"]+)";/)[1], rsStrings(rsBlock(RS_WIN, "ODR_ARGS"))], ODR_ARGV);
  assert.match(JS_WIN, /runner\(ODR_ARGV\[0\], ODR_ARGV\[1\], 5000\)/);
  assert.match(RS_WIN, /pub const ODR_TIMEOUT: Duration = Duration::from_secs\(5\);/);
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
