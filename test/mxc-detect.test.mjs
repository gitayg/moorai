// cli/mxc-detect.mjs through cli/agent-posture.mjs: per-host MXC containment on Windows and the device's
// mxcCapable, from the hosts' real config shapes in a throwaway HOME. No Windows machine is involved:
// platform, os.release() and the registry's UBR are injected.
//
//   node --test test/mxc-detect.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { agentPosture } from "../cli/agent-posture.mjs";
import { mxcCapable, mxcCapableFrom, parseBuild, parseRegUbr, hostContainment, CONTAINMENT_KINDS, CONTAINMENT_SCOPES, CONTAINMENT_SOURCES } from "../cli/mxc-detect.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const NO_SYSTEM = { gemini: "/nonexistent/moorai-test/gemini-system.json" };
const WIN_OK = "10.0.26200"; // 25H2

function sandbox(t) {
  const base = mkdtempSync(join(tmpdir(), "moorai-mxc-"));
  t.after(() => rmTree(base));
  const home = join(base, "home"), proj = join(base, "proj"), state = join(base, "state");
  mkdirSync(home, { recursive: true }); mkdirSync(proj, { recursive: true });
  const env = { HOME: home };
  const write = (p, body) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body)); };
  // A session log makes each host "on this device" without running any installer.
  const use = (...ids) => {
    const dirs = { "claude-code": [".claude", "projects", "p", "s.jsonl"], codex: [".codex", "sessions", "2026", "10", "07", "r.jsonl"], copilot: [".copilot", "session-state", "s", "e.jsonl"], gemini: [".gemini", "tmp", "x", "c.json"] };
    for (const id of ids) write(join(home, ...dirs[id]), "{}");
  };
  let ubrCalls = 0;
  const posture = (o = {}) => agentPosture({ home, env, cwd: proj, managedSources: [], systemFiles: NO_SYSTEM, hookCheck: false, versions: false, stateDir: state,
    platform: "win32", release: WIN_OK, readUbr: () => { ubrCalls++; return 9300; }, ...o });
  return { home, proj, state, env, write, use, posture, ubrCalls: () => ubrCalls };
}
const hostOf = (p, id) => p.hosts.find((h) => h.host === id);

test("CODEX: windows.sandbox = \"mxc\" (in a [windows] table or dotted) is MXC, commands scope", (t) => {
  const s = sandbox(t);
  s.use("codex");
  s.write(join(s.home, ".codex", "config.toml"), "model = \"gpt-5\"\n\n[windows]\nsandbox = \"mxc\" # contained\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "mxc", scope: "commands", source: "codex:windows.sandbox" });
  s.write(join(s.home, ".codex", "config.toml"), "windows.sandbox = 'mxc'\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "mxc", scope: "commands", source: "codex:windows.sandbox" });
});

test("CODEX: no Windows sandbox configured is none; elevated/unelevated is a non-MXC sandbox", (t) => {
  const s = sandbox(t);
  s.use("codex");
  s.write(join(s.home, ".codex", "config.toml"), "approval_policy = \"on-request\"\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "none", scope: null, source: "codex:unset" });
  s.write(join(s.home, ".codex", "config.toml"), "[windows]\nsandbox = \"elevated\"\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "other", scope: "commands", source: "codex:windows.sandbox" });
  s.write(join(s.home, ".codex", "config.toml"), "[features]\nexperimental_windows_sandbox = true\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "other", scope: "commands", source: "codex:legacy-feature" });
});

test("CODEX: full access overrides mxc; allow_mxc=false blocks it; prefer_mxc is unknown; a profile's windows table is not the default", (t) => {
  const s = sandbox(t);
  s.use("codex");
  s.write(join(s.home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n[windows]\nsandbox = \"mxc\"\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "none", scope: null, source: "codex:full-access" });
  s.write(join(s.home, ".codex", "config.toml"), "[windows]\nsandbox = \"mxc\"\nallow_mxc = false\n");
  assert.equal(hostOf(s.posture(), "codex").containment.kind, "none");
  s.write(join(s.home, ".codex", "config.toml"), "[features]\nprefer_mxc = true\n");
  assert.deepEqual(hostOf(s.posture(), "codex").containment, { kind: "unknown", scope: null, source: "codex:prefer-mxc" });
  s.write(join(s.home, ".codex", "config.toml"), "[profiles.safe.windows]\nsandbox = \"mxc\"\n");
  assert.equal(hostOf(s.posture(), "codex").containment.kind, "none", "a profile is chosen per run; it is not what Codex runs by default");
});

test("CODEX: the project file overrides the user file, and CODEX_HOME is honoured", (t) => {
  const s = sandbox(t);
  s.use("codex");
  s.write(join(s.home, ".codex", "config.toml"), "[windows]\nsandbox = \"mxc\"\n");
  s.write(join(s.proj, ".codex", "config.toml"), "[windows]\nsandbox = \"unelevated\"\n");
  assert.equal(hostOf(s.posture(), "codex").containment.kind, "other");
  const alt = join(s.home, "alt-codex");
  s.write(join(alt, "config.toml"), "[windows]\nsandbox = \"mxc\"\n");
  assert.equal(hostContainment("codex", { home: s.home, env: { CODEX_HOME: alt }, cwd: null }).kind, "mxc");
});

test("COPILOT: sandbox.enabled true is MXC (commands); false is none; unset or unreadable is unknown, never a guess", (t) => {
  const s = sandbox(t);
  s.use("copilot");
  const f = join(s.home, ".copilot", "settings.json");
  s.write(f, { sandbox: { enabled: true } });
  assert.deepEqual(hostOf(s.posture(), "copilot").containment, { kind: "mxc", scope: "commands", source: "copilot:sandbox.enabled" });
  s.write(f, { sandbox: { enabled: false } });
  assert.deepEqual(hostOf(s.posture(), "copilot").containment, { kind: "none", scope: null, source: "copilot:sandbox.enabled" });
  s.write(f, { model: "x" });
  assert.deepEqual(hostOf(s.posture(), "copilot").containment, { kind: "unknown", scope: null, source: "copilot:unset" });
  s.write(f, "{ not json");
  assert.deepEqual(hostOf(s.posture(), "copilot").containment, { kind: "unknown", scope: null, source: "copilot:unreadable" });
});

test("CLAUDE CODE on win32: none, whatever sandbox.enabled says (no MXC support on native Windows)", (t) => {
  const s = sandbox(t);
  s.use("claude-code");
  s.write(join(s.home, ".claude", "settings.json"), { sandbox: { enabled: true } });
  assert.deepEqual(hostOf(s.posture(), "claude-code").containment, { kind: "none", scope: null, source: "claude-code:no-mxc" });
});

test("GEMINI on win32: no documented MXC story, so no containment field at all", (t) => {
  const s = sandbox(t);
  s.use("gemini");
  assert.ok(!("containment" in hostOf(s.posture(), "gemini")));
});

test("NON-WINDOWS: neither containment nor mxcCapable is reported, and the registry is never read", (t) => {
  const s = sandbox(t);
  s.use("claude-code", "codex", "copilot");
  s.write(join(s.home, ".codex", "config.toml"), "[windows]\nsandbox = \"mxc\"\n");
  for (const platform of ["darwin", "linux"]) {
    const p = s.posture({ platform, release: "25.0.0" });
    assert.ok(!("mxcCapable" in p), platform);
    for (const h of p.hosts) assert.ok(!("containment" in h), `${platform} ${h.host}`);
  }
  assert.equal(s.ubrCalls(), 0);
});

test("BUILD THRESHOLD: 26100/26200.9278 is the line; either side of it, older builds, unlisted builds", () => {
  assert.equal(parseBuild("10.0.26200"), 26200);
  assert.equal(parseBuild("25.0.0"), null);
  assert.equal(mxcCapableFrom(26100, 9278), true);
  assert.equal(mxcCapableFrom(26200, 9278), true);
  assert.equal(mxcCapableFrom(26100, 9277), false);
  assert.equal(mxcCapableFrom(26200, 9106), false, "the 25H2 build from github/copilot-cli#4652, before KB5120998");
  assert.equal(mxcCapableFrom(26300, 9549), false);
  assert.equal(mxcCapableFrom(26300, 9550), true);
  assert.equal(mxcCapableFrom(28000, 2804), true);
  assert.equal(mxcCapableFrom(19045, 6000), false, "Windows 10");
  assert.equal(mxcCapableFrom(22631, 9999), false, "Windows 11 23H2");
  assert.equal(mxcCapableFrom(26100, null), null, "missing UBR");
  assert.equal(mxcCapableFrom(27950, 100), null, "an unlisted (Insider) build is unknown, not guessed");
});

test("MXC CAPABLE via the posture: below, at and above the line, and a missing registry value", (t) => {
  const s = sandbox(t);
  s.use("claude-code");
  const at = (release, ubr, sub) => s.posture({ release, readUbr: () => ubr, stateDir: join(s.state, sub) }).mxcCapable;
  assert.equal(at("10.0.26200", 9277, "a"), false);
  assert.equal(at("10.0.26200", 9278, "b"), true);
  assert.equal(at("10.0.26100", 9550, "c"), true);
  assert.equal(at("10.0.26100", null, "d"), null, "no UBR value in the registry");
});

test("REGISTRY: the UBR is read from reg.exe's REG_DWORD line; anything else is null", () => {
  const out = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    UBR    REG_DWORD    0x2446\r\n\r\n";
  assert.equal(parseRegUbr(out), 9286);
  assert.equal(parseRegUbr(""), null, "missing value: reg exits 1 with nothing on stdout");
  assert.equal(parseRegUbr("    UBR    REG_SZ    9300\r\n"), null);
});

test("MXC CAPABLE: a throwing registry reader is fail-open (null), and older builds never read the registry", () => {
  let calls = 0;
  assert.equal(mxcCapable({ release: "10.0.26200", readUbr: () => { calls++; throw new Error("denied"); } }), null);
  assert.equal(mxcCapable({ release: "10.0.19045", readUbr: () => { calls++; return 1; } }), false);
  assert.equal(calls, 1);
});

test("MXC CAPABLE: the registry read is cached per release, and a new release re-reads it", (t) => {
  const s = sandbox(t);
  s.use("claude-code");
  assert.equal(s.posture().mxcCapable, true);
  assert.equal(s.posture().mxcCapable, true);
  assert.equal(s.ubrCalls(), 1, "second beat served from the cache");
  const cache = JSON.parse(readFileSync(join(s.state, "mxc-capable.json"), "utf8"));
  assert.deepEqual(Object.keys(cache).sort(), ["at", "release", "ubr"]);
  s.posture({ release: "10.0.26100" });
  assert.equal(s.ubrCalls(), 2);
  assert.equal(mxcCapable({ release: "10.0.26100", stateDir: s.state, readUbr: () => 1, now: Date.now() + 21 * 3600 * 1000 }), false, "a stale cache is re-read");
});

test("CONTENT-FREE: every emitted value is from the fixed vocabularies", (t) => {
  const s = sandbox(t);
  s.use("claude-code", "codex", "copilot");
  s.write(join(s.home, ".codex", "config.toml"), "[windows]\nsandbox = \"mxc\"\n");
  s.write(join(s.home, ".copilot", "settings.json"), { sandbox: { enabled: true }, secret: "s3cr3t-value" });
  const p = s.posture();
  assert.equal(p.hosts.length, 3);
  for (const h of p.hosts) {
    assert.deepEqual(Object.keys(h.containment).sort(), ["kind", "scope", "source"]);
    assert.ok(CONTAINMENT_KINDS.includes(h.containment.kind));
    assert.ok(h.containment.scope === null || CONTAINMENT_SCOPES.includes(h.containment.scope));
    assert.ok(CONTAINMENT_SOURCES.includes(h.containment.source));
  }
  assert.ok(!JSON.stringify(p).includes("s3cr3t") && !JSON.stringify(p).includes(s.home));
});
