// cli/agent-posture.mjs — content-free per-host posture flags, hook registration state and last use.
// Every case builds a throwaway HOME (and project dir) with the hosts' real config shapes; hook
// registration is written by MoorAI's own installers, the same way `moorai doctor` computes "current".
//
//   node --test test/agent-posture.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, utimesSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { agentPosture, tomlKeys, lastActive, POSTURE_FLAGS, HOOK_STATES } from "../cli/agent-posture.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const NO_SYSTEM = { gemini: "/nonexistent/moorai-test/gemini-system.json" };

function sandbox(t) {
  const base = mkdtempSync(join(tmpdir(), "moorai-posture-"));
  t.after(() => rmTree(base));
  const home = join(base, "home"), proj = join(base, "proj");
  mkdirSync(home, { recursive: true }); mkdirSync(proj, { recursive: true });
  const env = { HOME: home };
  const write = (p, body) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body)); };
  const posture = (o = {}) => agentPosture({ home, env, cwd: proj, managedSources: [], systemFiles: NO_SYSTEM, ...o });
  const install = (...args) => {
    const r = spawnSync(process.execPath, args, { env: { ...process.env, HOME: home, USERPROFILE: home, CODEX_HOME: "", COPILOT_HOME: "" }, encoding: "utf8", input: "", timeout: 20000 });
    assert.equal(r.status, 0, r.stderr);
  };
  return { home, proj, env, write, posture, install };
}
const hostOf = (p, id) => p.hosts.find((h) => h.host === id);

test("CLEAN DEVICE: a HOME with no agent hosts reports no hosts at all", (t) => {
  const s = sandbox(t);
  assert.deepEqual(s.posture(), { v: 1, hosts: [] });
});

test("CLAUDE CODE: disableAllHooks and bypassPermissions are reported per scope; sandbox on clears sandboxOff", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".claude", "settings.json"), { disableAllHooks: true, permissions: { defaultMode: "bypassPermissions" } });
  s.write(join(s.proj, ".claude", "settings.local.json"), { disableAllHooks: true });
  let c = hostOf(s.posture(), "claude-code");
  assert.deepEqual(c.flags, { hooksDisabled: ["local", "user"], bypassPermissionsDefault: ["user"], sandboxOff: ["user"] });
  assert.equal(c.present, true);
  assert.equal(c.hook, "missing");

  s.write(join(s.home, ".claude", "settings.json"), { permissions: { defaultMode: "acceptEdits" }, sandbox: { enabled: true } });
  s.write(join(s.proj, ".claude", "settings.local.json"), {});
  c = hostOf(s.posture(), "claude-code");
  assert.deepEqual(c.flags, {}, "a hardened config carries no flags");
});

test("CLAUDE CODE: the hook's permission_mode=bypassPermissions is a session-scoped flag; other modes are not", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".claude", "settings.json"), { sandbox: { enabled: true } });
  assert.deepEqual(hostOf(s.posture({ permissionMode: "bypassPermissions" }), "claude-code").flags, { sessionBypassPermissions: ["session"] });
  assert.deepEqual(hostOf(s.posture({ permissionMode: "auto" }), "claude-code").flags, {});
});

test("CALLER: the host whose hook asks is always reported, even with no config dir or session logs", (t) => {
  const s = sandbox(t);
  assert.deepEqual(s.posture(), { v: 1, hosts: [] });
  const c = hostOf(s.posture({ caller: "claude-code", permissionMode: "bypassPermissions" }), "claude-code");
  assert.equal(c.present, true);
  assert.deepEqual(c.flags, { sandboxOff: ["user"], sessionBypassPermissions: ["session"] });
});

test("CLAUDE CODE: a project file that turns the sandbox on does not clear sandboxOff (device-wide scopes only)", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".claude", "settings.json"), {});
  s.write(join(s.proj, ".claude", "settings.json"), { sandbox: { enabled: true } });
  assert.deepEqual(hostOf(s.posture(), "claude-code").flags, { sandboxOff: ["user"] });
});

test("CLAUDE CODE MANAGED: allowManagedHooksOnly without MoorAI among the managed hooks is flagged; with the plugin force-enabled it is not", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".claude", "settings.json"), { sandbox: { enabled: true } });
  const src = (data) => [{ source: "managed-settings.json", data }];
  assert.deepEqual(hostOf(s.posture({ managedSources: src({ allowManagedHooksOnly: true }) }), "claude-code").flags, { managedHooksOnly: ["managed"] });
  assert.deepEqual(hostOf(s.posture({ managedSources: src({ allowManagedHooksOnly: true, enabledPlugins: { "moorai@moorai": true } }) }), "claude-code").flags, {});
  assert.deepEqual(hostOf(s.posture({ managedSources: src({ disableAllHooks: true, allowManagedHooksOnly: false }) }), "claude-code").flags, { hooksDisabled: ["managed"] });
});

test("CODEX: approval_policy=never, sandbox_mode=danger-full-access and [features] hooks=false, user / project / profile", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".codex", "config.toml"), 'model = "gpt-5"\napproval_policy = "never"   # yolo\nsandbox_mode = "danger-full-access"\n\n[features]\nhooks = false\n\n[profiles.fast]\napproval_policy = "never"\n');
  s.write(join(s.proj, ".codex", "config.toml"), "[features]\ncodex_hooks = false\n");
  assert.deepEqual(hostOf(s.posture(), "codex").flags, { approvalNever: ["profile", "user"], sandboxFullAccess: ["user"], hooksDisabled: ["project", "user"] });
  s.write(join(s.home, ".codex", "config.toml"), 'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n[features]\nhooks = true\n');
  s.write(join(s.proj, ".codex", "config.toml"), "");
  assert.deepEqual(hostOf(s.posture(), "codex").flags, {});
});

test("GEMINI: hooksConfig.enabled=false, MoorAI in hooksConfig.disabled, auto_edit and tools.sandbox=false", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".gemini", "settings.json"), '{ // comments are legal here\n "hooksConfig": { "enabled": false, "disabled": ["moorai"] }, "general": { "defaultApprovalMode": "auto_edit" }, "tools": { "sandbox": false } }');
  assert.deepEqual(hostOf(s.posture(), "gemini").flags, { hooksDisabled: ["user"], mooraiHookDisabled: ["user"], autoEditDefault: ["user"], sandboxOff: ["user"] });
  const sys = join(s.home, "system-gemini.json");
  s.write(join(s.home, ".gemini", "settings.json"), { general: { defaultApprovalMode: "default" } });
  s.write(sys, { hooksConfig: { enabled: false } });
  assert.deepEqual(hostOf(s.posture({ systemFiles: { gemini: sys } }), "gemini").flags, { hooksDisabled: ["system"] });
});

test("CURSOR CLI: approvalMode=unrestricted and sandbox.mode=disabled; allowlist is clean", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".cursor", "cli-config.json"), { version: 1, approvalMode: "unrestricted", sandbox: { mode: "disabled" } });
  assert.deepEqual(hostOf(s.posture(), "cursor").flags, { approvalUnrestricted: ["user"], sandboxOff: ["user"] });
  s.write(join(s.home, ".cursor", "cli-config.json"), { version: 1, approvalMode: "allowlist", sandbox: { mode: "enabled" } });
  assert.deepEqual(hostOf(s.posture(), "cursor").flags, {});
});

test("HOOK STATE: installed by MoorAI's own installer is ok; a dropped event is stale; a moved script is broken; bad JSON is unreadable", (t) => {
  const s = sandbox(t);
  s.install(join(ROOT, "cli", "moorai-hook.mjs"), "install");
  s.install(join(ROOT, "cli", "moorai-agent-hook.mjs"), "codex", "install");
  let p = s.posture();
  assert.equal(hostOf(p, "claude-code").hook, "ok");
  // Codex runs user hooks only after the user trusts them ([hooks.state] in config.toml).
  assert.equal(hostOf(p, "codex").hook, "untrusted");

  const file = join(s.home, ".claude", "settings.json");
  const cfg = JSON.parse(readFileSync(file, "utf8"));
  delete cfg.hooks.UserPromptSubmit;
  s.write(file, cfg);
  assert.equal(hostOf(s.posture(), "claude-code").hook, "stale");

  s.install(join(ROOT, "cli", "moorai-hook.mjs"), "install");
  const full = readFileSync(file, "utf8");
  writeFileSync(file, full.split(join(ROOT, "cli", "moorai-hook.mjs")).join("/nonexistent/moorai-hook.mjs"));
  assert.equal(hostOf(s.posture(), "claude-code").hook, "broken");

  writeFileSync(file, "{ not json");
  assert.equal(hostOf(s.posture(), "claude-code").hook, "unreadable");
});

test("LAST ACTIVE: newest session-log mtime per host, rounded down to the hour; none when the host never ran", (t) => {
  const s = sandbox(t);
  const at = (p, iso) => { s.write(p, "{}"); const d = new Date(iso); utimesSync(p, d, d); };
  at(join(s.home, ".claude", "projects", "-proj-a", "s1.jsonl"), "2026-09-28T10:20:00Z");
  at(join(s.home, ".claude", "projects", "-proj-b", "s2.jsonl"), "2026-09-30T08:59:59Z");
  at(join(s.home, ".codex", "sessions", "2026", "09", "29", "rollout-1.jsonl"), "2026-09-29T23:30:00Z");
  assert.equal(lastActive("claude-code", { home: s.home, env: s.env }), "2026-09-30T08:00:00.000Z");
  assert.equal(lastActive("codex", { home: s.home, env: s.env }), "2026-09-29T23:00:00.000Z");
  assert.equal(lastActive("gemini", { home: s.home, env: s.env }), null);
  const p = s.posture();
  assert.equal(hostOf(p, "codex").lastActive, "2026-09-29T23:00:00.000Z");
  assert.equal(hostOf(p, "codex").present, true);
});

test("CONTENT-FREE: no path, project name, login or setting value outside the fixed vocabulary leaves the module", (t) => {
  const s = sandbox(t);
  s.write(join(s.home, ".claude", "settings.json"), { disableAllHooks: true, env: { SECRET_TOKEN: "sk-live-abc" }, model: "secret-model" });
  s.write(join(s.proj, ".claude", "settings.json"), { permissions: { defaultMode: "bypassPermissions" } });
  s.write(join(s.home, ".codex", "config.toml"), 'approval_policy = "never"\nmodel = "secret-model"\n');
  s.write(join(s.home, ".claude", "projects", "-Users-alice-secret-project", "s.jsonl"), "{\"prompt\":\"secret\"}");
  s.install(join(ROOT, "cli", "moorai-hook.mjs"), "install");
  const p = s.posture({ permissionMode: "bypassPermissions" });
  const out = JSON.stringify(p);
  for (const bad of [s.home, s.proj, "secret", "sk-live", "alice", "moorai-hook.mjs"]) assert.ok(!out.includes(bad), `leaked ${bad}: ${out}`);
  const SCOPES = ["user", "project", "local", "managed", "system", "profile", "session"];
  for (const h of p.hosts) {
    assert.ok(HOOK_STATES.includes(h.hook));
    for (const [k, v] of Object.entries(h.flags)) { assert.ok(POSTURE_FLAGS.includes(k), k); for (const sc of v) assert.ok(SCOPES.includes(sc), sc); }
    assert.ok(h.lastActive === null || /^\d{4}-\d\d-\d\dT\d\d:00:00\.000Z$/.test(h.lastActive));
  }
});

test("TOML: keys are read under their section, quoted and bare values, comments dropped", () => {
  assert.deepEqual(tomlKeys('a = "x" # c\n[features]\nhooks = false\n[ profiles.p ]\nb = \'y\''), [
    { section: "", key: "a", value: "x" }, { section: "features", key: "hooks", value: false }, { section: "profiles.p", key: "b", value: "y" }]);
});
