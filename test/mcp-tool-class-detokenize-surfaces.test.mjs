// The detokenize tool class (cli/mcp-tool-class.mjs) on every surface that decides it, each against a fake
// console: the stdio guard (real stdio, the fake MCP server), the HTTP gateway (real HTTP, the fake upstream),
// the Claude Code hook (its built-in ask, the admin's allow, and an approvalRouting rule matching toolClass),
// and the model proxy (a detokenize function tool, built-in ask settled headless in enforce mode).
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-class-detokenize-surfaces.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { scenario as gwScenario, makeHome as gwHome, serverModeEnv, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";
import { startFakeProvider, sendJson } from "../model-proxy/test/fake-provider.mjs";
import { chatResponse, MODEL } from "../model-proxy/test/fake-ollama.mjs";
import { sandbox as pxSandbox, startConsole as pxConsole, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

const obj = { type: "object" };
const DETOK = { name: "detokenize_card", description: "Returns the card number for a token.", inputSchema: obj };
// The server says its decrypt tool is read-only: an annotation never demotes a detokenize name.
const DECRYPT = { name: "decrypt_field", description: "Decrypts a field.", inputSchema: obj, annotations: { readOnlyHint: true } };
const LIST = { name: "list_rows", description: "Lists rows.", inputSchema: obj };
const TOOLS = [DETOK, DECRYPT, LIST];
const PLAIN = { captureTier: "content-free" };

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
function sign(policy) {
  const iat = new Date(Date.now() - 1000).toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
async function startConsole(initial) {
  const st = { policy: initial, alerts: [] };
  const server = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); res.end(pubkeyBody); return; }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(sign(st.policy)); return; }
    if (req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => {
        try { if (req.url === "/api/alerts") st.alerts.push(JSON.parse(b)); else if (req.url === "/api/alerts/batch") st.alerts.push(...(JSON.parse(b).alerts || [])); } catch { /* ignore */ }
        res.writeHead(201); res.end("{}");
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  st.url = `http://127.0.0.1:${server.address().port}`;
  st.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); });
  return st;
}
const classAlerts = (con) => con.alerts.filter((a) => a.reasonCode === "MCP_TOOL_CLASS");
const classOf = (con, tool) => classAlerts(con).filter((a) => a.tool === tool).map((a) => [a.decision, a.toolClass, a.toolClassSource]);

// ---- the stdio guard ----
function startGuard({ home, url, recvLog }) {
  const toolsFile = join(home, "tools.json");
  writeFileSync(toolsFile, JSON.stringify([TOOLS]));
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: TENANT, FAKE_TOOLS_FILE: toolsFile, MOORAI_TEST_POLICY_REFRESH_MS: "0" };
  const child = spawn(process.execPath, [GUARD, "--server", "pay", "--", process.execPath, FAKE, recvLog], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  const byId = new Map();
  let pending = "", stderr = "", nextId = 1;
  child.stderr.on("data", (c) => { stderr += c; });
  child.stdout.on("data", (c) => {
    pending += c.toString();
    let nl;
    while ((nl = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* not a response */ }
    }
  });
  async function send(method, params = {}) {
    const id = nextId++;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    const deadline = Date.now() + 15000;
    while (!byId.has(id) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 15));
    assert.ok(byId.has(id), `no response to ${method} id=${id}; stderr=${stderr}`);
    return byId.get(id);
  }
  return {
    list: async () => (await send("tools/list")).result.tools.map((t) => t.name),
    call: async (name) => (await send("tools/call", { name, arguments: { token: "tok_1" } })).result,
    close: () => new Promise((r) => { child.once("exit", () => r()); try { child.stdin.end(); child.kill(); } catch { r(); } })
  };
}
const blocked = (r) => r && r.isError === true && /MoorAI blocked this MCP tool call/.test(r.content[0].text);
const called = (log) => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l).name) : []);
async function guardRun(policy, fn) {
  const con = await startConsole(policy);
  const home = mkdtempSync(join(tmpdir(), "moorai-detok-guard-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: con.url, tenant: TENANT, installToken: "tok" }));
  const log = join(home, "recv.log");
  const g = startGuard({ home, url: con.url, recvLog: log });
  try { await g.list(); await fn({ con, g, log }); } finally { await g.close(); await con.close(); rmTree(home); }
}

test("GUARD: with mcpToolClassDefaults unset a detokenize tool is held by class (ask: forwarded and recorded); readOnlyHint does not demote it", async () => {
  await guardRun(PLAIN, async ({ con, g, log }) => {
    for (const t of TOOLS) assert.ok(!blocked(await g.call(t.name)), `${t.name}: the guard has no approver, an ask is forwarded`);
    assert.deepEqual(called(log), TOOLS.map((t) => t.name));
    await settle();
    assert.deepEqual(classOf(con, "desktop:detokenize_card"), [["ask", "detokenize", "heuristic"]]);
    assert.deepEqual(classOf(con, "desktop:decrypt_field"), [["ask", "detokenize", "heuristic"]]);
    assert.deepEqual(classOf(con, "desktop:list_rows"), [], "no other class has a built-in verdict");
  });
});

test("GUARD: mcpToolClassDefaults.detokenize block refuses the detokenize tools; allow silences them", async () => {
  await guardRun({ ...PLAIN, mcpToolClassDefaults: { detokenize: "block" } }, async ({ con, g, log }) => {
    assert.ok(blocked(await g.call("detokenize_card")));
    assert.ok(blocked(await g.call("decrypt_field")));
    assert.ok(!blocked(await g.call("list_rows")));
    assert.deepEqual(called(log), ["list_rows"]);
    await settle();
    assert.deepEqual(classOf(con, "desktop:detokenize_card"), [["deny", "detokenize", "heuristic"]]);
  });
  await guardRun({ ...PLAIN, mcpToolClassDefaults: { detokenize: "allow" } }, async ({ con, g }) => {
    assert.ok(!blocked(await g.call("detokenize_card")));
    await settle();
    assert.deepEqual(classAlerts(con), []);
  });
});

// ---- the HTTP gateway ----
const listReply = (m) => JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: TOOLS } });
const refused = (r) => r.json && r.json.result && r.json.result.isError === true && /MoorAI blocked this MCP tool call/.test(r.json.result.content[0].text);
const upCalls = (up) => up.calls().map((c) => c.json.params.name);
const gwEnv = { MOORAI_TEST_POLICY_REFRESH_MS: "0" };
async function gwRun(policy, fn, env = () => gwEnv) {
  const con = await startConsole(policy);
  const home = gwHome(con.url);
  try { await gwScenario({ con, home, upstream: { listReply }, env: env(con.url) }, (ctx) => fn({ ...ctx, con })); }
  finally { await con.close(); rmTree(home); }
}

test("GATEWAY: unset → a detokenize tool asks (forwarded and recorded); server mode settles the ask as a deny; admin allow silences it", async () => {
  await gwRun(PLAIN, async ({ base, up, con }) => {
    await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    assert.ok(!refused(await rpc(base, call(2, "detokenize_card"))));
    assert.ok(!refused(await rpc(base, call(3, "decrypt_field"))));
    assert.deepEqual(upCalls(up), ["detokenize_card", "decrypt_field"]);
    await settle();
    assert.deepEqual(classOf(con, "gateway:detokenize_card"), [["ask", "detokenize", "heuristic"]]);
    assert.deepEqual(classOf(con, "gateway:decrypt_field"), [["ask", "detokenize", "heuristic"]]);
  });
  await gwRun(PLAIN, async ({ base, up, con }) => {
    await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    assert.ok(refused(await rpc(base, call(2, "detokenize_card"))));
    assert.ok(!refused(await rpc(base, call(3, "list_rows"))));
    assert.deepEqual(upCalls(up), ["list_rows"]);
    await settle();
    assert.deepEqual(classOf(con, "gateway:detokenize_card"), [["deny", "detokenize", "heuristic"]]);
  }, (url) => ({ ...gwEnv, ...serverModeEnv(url) }));
  await gwRun({ ...PLAIN, mcpToolClassDefaults: { detokenize: "allow" } }, async ({ base, con }) => {
    await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    assert.ok(!refused(await rpc(base, call(2, "detokenize_card"))));
    await settle();
    assert.deepEqual(classAlerts(con), []);
  }, (url) => ({ ...gwEnv, ...serverModeEnv(url) }));
});

// ---- the Claude Code hook ----
function runHook(home, tool) {
  const proj = join(home, "proj");
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_OFFLINE_MODE: "" };
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => {
      assert.equal(status, 0, err);
      const o = out.trim() ? JSON.parse(out) : {};
      res({ decision: (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || "allow", reason: (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecisionReason) || "" });
    });
    c.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, tool_input: { token: "tok_4111" }, tool_use_id: "tu-1", session_id: "detok", transcript_path: "", cwd: proj, permission_mode: "default" }));
  });
}
async function hookRun(policy, fn) {
  const con = await startConsole(policy);
  const home = mkdtempSync(join(tmpdir(), "moorai-detok-hook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: con.url, tenant: TENANT, installToken: "tok-detok" }));
  try {
    // Pin the console's key on first contact, then drop the 60 s policy cache so each test reads the console.
    await runHook(home, "mcp__github__list_issues");
    rmSync(join(home, ".moorai", "hook-policy.json"), { force: true });
    con.alerts.length = 0;
    await fn({ con, home, run: (tool) => runHook(home, tool) });
  } finally { await con.close(); rmTree(home); }
}

test("HOOK: with mcpToolClassDefaults unset a detokenize MCP tool asks, by name and by the vault server label; others are unchanged", async () => {
  await hookRun(PLAIN, async ({ con, run }) => {
    const d = await run("mcp__pay__detokenize_card");
    assert.equal(d.decision, "ask");
    assert.match(d.reason, /detokenize_card is a detokenize MCP tool \(heuristic\); the built-in default for detokenize tools is ask/);
    assert.equal((await run("mcp__vault__get")).decision, "ask");
    for (const t of ["mcp__github__delete_repository", "mcp__github__create_issue", "mcp__github__list_secrets"]) assert.equal((await run(t)).decision, "allow", t);
    await settle(300);
    assert.deepEqual(classOf(con, "hook:mcp__pay__detokenize_card"), [["ask", "detokenize", "heuristic"]]);
    assert.deepEqual(classOf(con, "hook:mcp__vault__get"), [["ask", "detokenize", "heuristic"]]);
    assert.equal(classAlerts(con).length, 2);
  });
});

test("HOOK: the admin's mcpToolClassDefaults.detokenize allow, or an override out of the class, lets the call through", async () => {
  await hookRun({ ...PLAIN, mcpToolClassDefaults: { detokenize: "allow" } }, async ({ con, run }) => {
    assert.equal((await run("mcp__pay__detokenize_card")).decision, "allow");
    await settle(300);
    assert.deepEqual(classAlerts(con), []);
  });
  await hookRun({ ...PLAIN, mcpToolClasses: { pay: { detokenize_card: "read" } } }, async ({ run }) => {
    assert.equal((await run("mcp__pay__detokenize_card")).decision, "allow");
    assert.equal((await run("mcp__pay__decrypt_field")).decision, "ask", "the override names one tool");
  });
});

const RULE = { id: "detok-review", label: "Detokenize needs a reviewer", match: { toolClass: ["detokenize"] }, holds: ["ask"], group: "secops", timeoutSec: 60 };
test("HOOK, approval routing: a toolClass rule holds every detokenize call; the request alert carries the class; other classes are not held", async () => {
  await hookRun({ ...PLAIN, mcpToolClassDefaults: { write: "ask" }, approvalRouting: { v: 1, rules: [RULE] } }, async ({ con, run }) => {
    const h = await run("mcp__pay__detokenize_card");
    assert.equal(h.decision, "deny");
    assert.match(h.reason, /Held for approval: Detokenize needs a reviewer \(request apr_[0-9A-HJKMNP-TV-Z]{26}\)\./);
    assert.equal((await run("mcp__vault__read_secret")).decision, "deny", "a second detokenize tool on another server, same rule");
    assert.equal((await run("mcp__github__create_issue")).decision, "ask", "a write tool's class ask is not held by a detokenize rule");
    await settle(400);
    const req = con.alerts.filter((a) => a.reasonCode === "APPROVAL_REQUESTED");
    assert.deepEqual(req.map((a) => [a.tool, a.toolClass, a.approval.ruleId, a.approval.verdict]), [["hook:mcp__pay__detokenize_card", "detokenize", "detok-review", "ask"], ["hook:mcp__vault__read_secret", "detokenize", "detok-review", "ask"]]);
    for (const a of con.alerts) assert.ok(!JSON.stringify(a).includes("tok_4111"), `content-free: ${JSON.stringify(a)}`);
  });
});

// ---- the model proxy ----
test("MODEL PROXY: a detokenize function asks by default (enforce settles it headless: refused); mcpToolClassDefaults.detokenize allow lets it run", async () => {
  const fp = await startFakeProvider();
  const con = await pxConsole();
  const home = pxSandbox();
  const plain = join(home, "plain.json"), allow = join(home, "allow.json");
  writeFileSync(plain, JSON.stringify(PLAIN));
  writeFileSync(allow, JSON.stringify({ ...PLAIN, mcpToolClassDefaults: { detokenize: "allow" } }));
  const env = { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-proxy-detok-1", MOORAI_TENANT: "t-mp-detok" };
  const routes = ["--route", `/ollama=${fp.url}`];
  const pxD = await startProxy(home, ["--mode", "enforce", "--policy-file", plain, ...routes], env);
  const pxA = await startProxy(home, ["--mode", "enforce", "--policy-file", allow, ...routes], env);
  const ollama = (px, name) => { fp.on((r, res) => sendJson(res, chatResponse({ tools: [{ name, input: { token: "tok_4111" } }] }))); return request(px.listening, "/ollama/api/chat", { body: { model: MODEL, stream: false, messages: [{ role: "user", content: "pay" }] } }); };
  try {
    const n0 = con.alerts.length;
    const r = await ollama(pxD, "detokenize_card");
    assert.equal(r.status, 403, r.raw);
    assert.match(r.json.error, /function detokenize_card requires approval \(businessToolActions: detokenize\)/);
    assert.ok(await waitFor(() => con.parsed().slice(n0).some((x) => x.tool === "model-proxy:detokenize_card" && x.businessClass === "detokenize" && x.decision === "ask")), JSON.stringify(con.parsed().slice(n0)));
    assert.ok(!con.alerts.slice(n0).join("\n").includes("tok_4111"), "an argument left");
    assert.equal((await ollama(pxA, "detokenize_card")).status, 200);
  } finally { await pxD.stop(); await pxA.stop(); await fp.close(); await con.close(); rmTree(home); }
});
