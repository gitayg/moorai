// moorai-doctor's fail-mode line: the effective fail mode per surface (cli/fail-mode.mjs), from the admin
// binding and the policy the hook would enforce. The CLI in a sandbox HOME for the policy path; the check
// function in process for the admin binding, which is root-owned and cannot be planted from a test.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-doctor.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { checkFailMode } from "../cli/doctor-checks.mjs";
import { resolveEffective } from "../cli/doctor-policy.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DOCTOR = join(ROOT, "cli", "moorai-doctor.mjs");

test("doctor CLI: one fail-mode row naming each surface's mode and source", (t) => {
  const home = mkdtempSync(join(tmpdir(), "moorai-fm-doctor-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "fm", installToken: "tok-fm-doc" }), { mode: 0o600 });
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", failMode: { hook: "closed", default: "open" } }));
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
  const r = spawnSync(process.execPath, [DOCTOR, "--offline", "--no-selftest", "--json"], { env, encoding: "utf8", timeout: 60000 });
  const c = JSON.parse(r.stdout).checks.find((x) => x.id === "fail-mode");
  assert.ok(c, "a fail-mode check exists");
  assert.equal(c.group, "policy");
  assert.equal(c.status, "ok");
  assert.deepEqual(c.details.failMode, {
    hook: { mode: "closed", source: "policy" }, modelProxy: { mode: "open", source: "policy" },
    mcpGateway: { mode: "open", source: "policy" }, inferenceHook: { mode: "open", source: "policy" }
  });
  assert.match(c.summary, /hook closed \(policy\)/);
  const human = spawnSync(process.execPath, [DOCTOR, "--offline", "--no-selftest"], { env, encoding: "utf8", timeout: 60000 }).stdout;
  assert.match(human, /Fail mode: hook closed \(policy\) · modelProxy open \(policy\) · mcpGateway open \(policy\) · inferenceHook open \(policy\)/);
});

test("checkFailMode: the admin binding wins and is named; an invalid value warns", () => {
  const c = checkFailMode({ policy: { failMode: { hook: "open" } } }, { failMode: { hook: "closed" } });
  assert.deepEqual(c.details.failMode.hook, { mode: "closed", source: "admin" });
  assert.equal(c.status, "ok");
  const w = checkFailMode({ policy: { failMode: { mcpGateway: "shut" } } }, null);
  assert.equal(w.status, "warn");
  assert.match(w.fix, /"open" or "closed"/);
  const none = checkFailMode({ policy: null }, null);
  assert.match(none.summary, /inferenceHook open \(default: the server's --fail flag decides\)/);
});

test("resolveEffective mirrors the hook: no policy + an admin binding that closes the hook → the fail-closed default", () => {
  const eff = resolveEffective(null, { tenant: "t", installToken: "tok" }, { admin: { failMode: { hook: "closed" } } });
  assert.equal(eff.policy, OFFLINE_DEFAULT_POLICY);
  assert.match(eff.basis, /fail mode closed \(admin\)/);
  assert.equal(eff.coach, false, "an admin binding that closes the hook is management evidence");
  const open = resolveEffective(null, { tenant: "t" }, { admin: { failMode: { hook: "open" } } });
  assert.notEqual(open.policy, OFFLINE_DEFAULT_POLICY);
});
