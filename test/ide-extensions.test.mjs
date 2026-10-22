// F20 — installed IDE-extension scanning: the extensions already on disk in VS Code, Cursor, Windsurf,
// Kiro, VSCodium and JetBrains IDEs, checked for published malicious ids, typosquats, invisible-Unicode
// code (the GlassWorm technique) and side-loaded installs, and fed into the AIBOM. Report-only. Every
// test builds a throwaway HOME; nothing reads the developer's real editors.
//
//   node --test --import ./test/hermetic-env.mjs test/ide-extensions.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { crc32 } from "node:zlib";
import { scanIdeExtensions, ideExtensionRoots, classifyExtensionId, invisibleRun } from "../cli/ide-extensions.mjs";
import { KNOWN_BAD_IDE_EXTENSIONS } from "../data/ide-extension-advisories.js";
import { POPULAR_IDE_EXTENSIONS } from "../data/popular-ide-extensions.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const tmp = (p) => mkdtempSync(join(tmpdir(), `moorai-ide-${p}-`));

function vsext(home, rel, publisher, name, version, files = {}) {
  const dir = join(home, rel, `${publisher.toLowerCase()}.${name}-${version}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ publisher, name, version, main: "./extension.js" }));
  writeFileSync(join(dir, "extension.js"), files["extension.js"] ?? "module.exports = { activate() {} };\n");
  for (const [f, c] of Object.entries(files)) if (f !== "extension.js") { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), c); }
  return dir;
}

// A stored (uncompressed) zip, enough for a JetBrains plugin jar with META-INF/plugin.xml.
function storedZip(files) {
  const locals = [], centrals = [];
  let off = 0;
  for (const [n, s] of Object.entries(files)) {
    const name = Buffer.from(n), data = Buffer.from(s), crc = crc32(data) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, data); centrals.push(ch, name);
    off += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(Object.keys(files).length, 8); end.writeUInt16LE(Object.keys(files).length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

const byId = (r) => Object.fromEntries(r.extensions.map((x) => [`${x.editor}:${x.id}@${x.version}`, x]));

test("enumerates the VS Code family: VS Code, Insiders, VSCodium, Cursor, Windsurf, Kiro (ids and versions from package.json)", () => {
  const home = tmp("fam");
  vsext(home, ".vscode/extensions", "ms-python", "python", "2025.1.0");
  vsext(home, ".vscode-insiders/extensions", "esbenp", "prettier-vscode", "11.0.0");
  vsext(home, ".vscode-oss/extensions", "redhat", "vscode-yaml", "1.15.0");
  vsext(home, ".cursor/extensions", "GitHub", "copilot-chat", "0.30.0");
  vsext(home, ".windsurf/extensions", "Codeium", "codeium", "1.9.0");
  vsext(home, ".kiro/extensions", "dbaeumer", "vscode-eslint", "3.0.10");
  mkdirSync(join(home, ".cursor/extensions/broken.thing-1.0.0"), { recursive: true });
  const r = scanIdeExtensions({ home, platform: "darwin" });
  const ids = r.extensions.map((x) => `${x.editor}:${x.id}@${x.version}`).sort();
  assert.deepEqual(ids, ["cursor:broken.thing@1.0.0", "cursor:github.copilot-chat@0.30.0", "kiro:dbaeumer.vscode-eslint@3.0.10", "vscode-insiders:esbenp.prettier-vscode@11.0.0", "vscode:ms-python.python@2025.1.0", "vscodium:redhat.vscode-yaml@1.15.0", "windsurf:codeium.codeium@1.9.0"]);
  assert.equal(r.scanned, 7);
  const m = byId(r);
  assert.equal(m["cursor:github.copilot-chat@0.30.0"].ai, true);
  assert.equal(m["windsurf:codeium.codeium@1.9.0"].ai, true);
  assert.equal(m["vscode:ms-python.python@2025.1.0"].ai, false);
  assert.deepEqual(m["vscode:ms-python.python@2025.1.0"].codes, []);
  assert.equal(m["vscode:ms-python.python@2025.1.0"].risk, "none");
});

test("known-malicious: a published malicious id+version is critical; an unaffected version of the same id is not", () => {
  const home = tmp("bad");
  vsext(home, ".vscode/extensions", "codejoy", "codejoy-vscode-extension", "1.8.3");
  vsext(home, ".cursor/extensions", "codejoy", "codejoy-vscode-extension", "1.8.2");
  vsext(home, ".vscode/extensions", "AmazonWebServices", "amazon-q-vscode", "1.84.0");
  vsext(home, ".windsurf/extensions", "AmazonWebServices", "amazon-q-vscode", "1.85.0");
  vsext(home, ".kiro/extensions", "CodeInKlingon", "git-worktree-menu", "1.0.91");
  const m = byId(scanIdeExtensions({ home, platform: "linux" }));
  assert.deepEqual(m["vscode:codejoy.codejoy-vscode-extension@1.8.3"].codes, ["ide-ext-known-malicious"]);
  assert.equal(m["vscode:codejoy.codejoy-vscode-extension@1.8.3"].risk, "critical");
  assert.deepEqual(m["vscode:codejoy.codejoy-vscode-extension@1.8.3"].advisories, ["MAL-2025-191159"]);
  assert.deepEqual(m["cursor:codejoy.codejoy-vscode-extension@1.8.2"].codes, []);
  assert.deepEqual(m["vscode:amazonwebservices.amazon-q-vscode@1.84.0"].codes, ["ide-ext-known-malicious"]);
  assert.deepEqual(m["windsurf:amazonwebservices.amazon-q-vscode@1.85.0"].codes, []);
  assert.deepEqual(m["kiro:codeinklingon.git-worktree-menu@1.0.91"].codes, ["ide-ext-known-malicious"]);
});

test("the advisory list: every entry names an advisory and a lower-case publisher.name id", () => {
  assert.ok(KNOWN_BAD_IDE_EXTENSIONS.length >= 15);
  for (const e of KNOWN_BAD_IDE_EXTENSIONS) {
    assert.match(e.id, /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$/, e.id);
    assert.ok(typeof e.advisory === "string" && e.advisory.length > 3, e.id);
    assert.ok(e.versions === null || (Array.isArray(e.versions) && e.versions.length), e.id);
  }
});

test("typosquat: a near-miss of a popular id, and a popular name under another publisher; the real ones stay silent", () => {
  assert.deepEqual(classifyExtensionId("esbenp.prettier-vscode"), []);
  assert.deepEqual(classifyExtensionId("esbenp.prettier-vscod"), ["ide-ext-typosquat"]);
  assert.deepEqual(classifyExtensionId("ms-pythom.python"), ["ide-ext-typosquat"]);
  assert.deepEqual(classifyExtensionId("prettier.prettier-vscode"), ["ide-ext-publisher-impersonation"]);
  assert.deepEqual(classifyExtensionId("github-copilot.copilot-chat"), ["ide-ext-publisher-impersonation"]);
  assert.deepEqual(classifyExtensionId("someone.my-own-tool"), []);
  assert.deepEqual(classifyExtensionId("acme.python"), [], "a short generic name is not an impersonation on its own");
});

test("the popular reference list has no internal near-collisions (so a listed id is never flagged as another's typosquat)", () => {
  for (const id of POPULAR_IDE_EXTENSIONS) assert.deepEqual(classifyExtensionId(id), [], id);
});

test("invisible code: a long run of Unicode variation selectors (the GlassWorm technique) is flagged; ordinary emoji are not", () => {
  const vs = Array.from({ length: 40 }, (_, i) => String.fromCodePoint(0xfe00 + (i % 16))).join("");
  const supp = Array.from({ length: 40 }, (_, i) => String.fromCodePoint(0xe0100 + i)).join("");
  assert.ok(invisibleRun(`const s = "${vs}"; eval(decode(s));`) >= 40);
  assert.ok(invisibleRun(`x("${supp}")`) >= 40);
  assert.ok(invisibleRun("const hearts = '❤️ ❤️ ❤️ ✔️ ☀️';".repeat(50)) < 16);
  const home = tmp("inv");
  vsext(home, ".cursor/extensions", "someone", "theme-pack", "1.0.0", { "extension.js": `const s = "${vs}";\n` });
  vsext(home, ".cursor/extensions", "someone", "emoji-pack", "1.0.0", { "extension.js": "const e = '❤️';\n".repeat(200), "out/deep/x.js": `const t = "${supp}";` });
  const m = byId(scanIdeExtensions({ home, platform: "darwin" }));
  assert.deepEqual(m["cursor:someone.theme-pack@1.0.0"].codes, ["ide-ext-invisible-code"]);
  assert.equal(m["cursor:someone.theme-pack@1.0.0"].risk, "high");
  assert.deepEqual(m["cursor:someone.emoji-pack@1.0.0"].codes, ["ide-ext-invisible-code"], "a run in any bundled script counts, not only the entry file");
});

test("side-loaded: extensions.json metadata source 'vsix' is reported (low)", () => {
  const home = tmp("vsix");
  vsext(home, ".vscode/extensions", "someone", "local-tool", "0.0.1");
  vsext(home, ".vscode/extensions", "esbenp", "prettier-vscode", "11.0.0");
  writeFileSync(join(home, ".vscode/extensions/extensions.json"), JSON.stringify([
    { identifier: { id: "someone.local-tool" }, version: "0.0.1", relativeLocation: "someone.local-tool-0.0.1", metadata: { source: "vsix" } },
    { identifier: { id: "esbenp.prettier-vscode" }, version: "11.0.0", relativeLocation: "esbenp.prettier-vscode-11.0.0", metadata: { source: "gallery" } }
  ]));
  const m = byId(scanIdeExtensions({ home, platform: "darwin" }));
  assert.deepEqual(m["vscode:someone.local-tool@0.0.1"].codes, ["ide-ext-sideloaded"]);
  assert.equal(m["vscode:someone.local-tool@0.0.1"].source, "vsix");
  assert.equal(m["vscode:someone.local-tool@0.0.1"].risk, "low");
  assert.deepEqual(m["vscode:esbenp.prettier-vscode@11.0.0"].codes, []);
});

test("JetBrains plugins: id and version from META-INF/plugin.xml inside the plugin jar, per-platform plugin roots", () => {
  const xml = (id, name, ver) => `<idea-plugin><id>${id}</id><name>${name}</name><version>${ver}</version></idea-plugin>`;
  const cases = {
    darwin: (h) => join(h, "Library", "Application Support", "JetBrains", "IntelliJIdea2025.2", "plugins"),
    linux: (h) => join(h, ".local", "share", "JetBrains", "PyCharm2025.1"),
    win32: (h) => join(h, "AppData", "Roaming", "JetBrains", "WebStorm2025.2", "plugins")
  };
  for (const [platform, at] of Object.entries(cases)) {
    const home = tmp(`jb-${platform}`);
    const plugins = at(home);
    mkdirSync(join(plugins, "github-copilot-intellij", "lib"), { recursive: true });
    writeFileSync(join(plugins, "github-copilot-intellij", "lib", "core.jar"), storedZip({ "META-INF/plugin.xml": xml("com.github.copilot", "GitHub Copilot", "1.5.40") }));
    mkdirSync(join(plugins, "some-plugin", "lib"), { recursive: true });
    const r = scanIdeExtensions({ home, platform, env: platform === "win32" ? { APPDATA: join(home, "AppData", "Roaming") } : {} });
    const jb = r.extensions.filter((x) => x.editor.startsWith("jetbrains"));
    assert.deepEqual(jb.map((x) => `${x.id}@${x.version}`).sort(), ["com.github.copilot@1.5.40", "some-plugin@null"], platform);
    assert.equal(jb.find((x) => x.id === "com.github.copilot").ai, true, platform);
  }
});

test("roots: every editor family is listed for each platform", () => {
  const editors = (p) => new Set(ideExtensionRoots({ home: "/h", platform: p, env: { APPDATA: "C:\\A" } }).map((r) => r.editor.replace(/:.*/, "")));
  for (const p of ["darwin", "linux", "win32"]) for (const e of ["vscode", "vscode-insiders", "vscodium", "cursor", "windsurf", "kiro", "jetbrains"]) assert.ok(editors(p).has(e), `${p} ${e}`);
});

test("content-free: no path and no file content in the result", () => {
  const home = tmp("cf");
  vsext(home, ".vscode/extensions", "someone", "x", "1.0.0", { "extension.js": "const SECRET_MARKER = 1;\n" });
  const s = JSON.stringify(scanIdeExtensions({ home, platform: "darwin" }));
  assert.ok(!s.includes(home));
  assert.ok(!s.includes("SECRET_MARKER"));
});

test("bounds: a file past the per-file cap is skipped and the scan says it was truncated", () => {
  const home = tmp("cap");
  const vs = Array.from({ length: 40 }, () => "\uFE01").join("");
  vsext(home, ".vscode/extensions", "someone", "big", "1.0.0", { "extension.js": "x".repeat(2048) + vs });
  const r = scanIdeExtensions({ home, platform: "darwin", limits: { maxFileBytes: 1024 } });
  assert.equal(r.truncated, true);
  assert.deepEqual(byId(r)["vscode:someone.big@1.0.0"].codes, []);
});

test("AIBOM: the IDE-extension scan is in the JSON, the summary counts and the Markdown report", () => {
  const home = tmp("aibom");
  vsext(home, ".vscode/extensions", "codejoy", "codejoy-vscode-extension", "1.8.4");
  vsext(home, ".cursor/extensions", "GitHub", "copilot", "1.300.0");
  const probe = join(home, "probe.json");
  writeFileSync(probe, "{}"); // no listeners / processes: hermetic
  const run = (fmt) => spawnSync(process.execPath, [join(ROOT, "cli", "moorai-aibom.mjs"), "--format", fmt], { encoding: "utf8", env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: probe } });
  const r = run("json");
  assert.equal(r.status, 0, r.stderr);
  const bom = JSON.parse(r.stdout);
  assert.equal(bom.summary.ideExtensionsScanned, 2);
  assert.equal(bom.summary.ideExtensionsFlagged, 1);
  const flagged = bom.ideExtensionScan.extensions.find((x) => x.id === "codejoy.codejoy-vscode-extension");
  assert.deepEqual(flagged.codes, ["ide-ext-known-malicious"]);
  const md = run("md");
  assert.match(md.stdout, /## IDE extension scan/);
  assert.match(md.stdout, /codejoy\.codejoy-vscode-extension/);
});

test("moorai-ide-extensions CLI: JSON by default, exit 0 even with findings (report-only)", () => {
  const home = tmp("cli");
  vsext(home, ".vscode/extensions", "codejoy", "codejoy-vscode-extension", "1.8.4");
  const r = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-ide-extensions.mjs")], { encoding: "utf8", env: { ...process.env, HOME: home, USERPROFILE: home } });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).flagged, 1);
});
