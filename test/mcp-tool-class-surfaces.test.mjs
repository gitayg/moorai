// Default MCP tool policy by class (policy mcpToolClassDefaults, cli/mcp-tool-class.mjs) on the three
// surfaces that decide MCP calls: the stdio guard (mcp-proxy/moorai-mcp-guard.mjs, over real stdio with the
// fake MCP server), the HTTP gateway (mcp-gateway/, over real HTTP with the fake upstream) and the Claude
// Code hook (cli/moorai-hook.mjs). Each against a fake console serving the policy and collecting alerts.
// Covers the verdict per class, annotations that tighten (and one that tries to loosen), a tool added after
// approval (alert mode, and block-mode drift then re-approval), server mode's ask, and the field absent.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-class-surfaces.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { toolIdentity } from "../mcp-proxy/tool-scan.mjs";
import { scenario as gwScenario, makeHome as gwHome, serverModeEnv, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";

const DEFAULTS = { read: "allow", write: "ask", destructive: "block", unknown: "ask" };
const CLASSED = { mcpToolClassDefaults: DEFAULTS };
const obj = { type: "object" };
const LIST = { name: "list_rows", description: "Lists rows.", inputSchema: obj };
const CREATE = { name: "create_row", description: "Creates a row.", inputSchema: obj };
const PURGE = { name: "purge_cache", description: "Purges the cache.", inputSchema: obj };
// The server says this read-named tool is destructive: an annotation may tighten.
const REPORT = { name: "get_report", description: "Builds a report.", inputSchema: obj, annotations: { destructiveHint: true } };
// The server says this delete is read-only: an annotation may never loosen.
const DELTMP = { name: "delete_tmp", description: "Deletes temp files.", inputSchema: obj, annotations: { readOnlyHint: true } };
const DROP = { name: "drop_table", description: "Drops a table.", inputSchema: obj };
const APPEND = { name: "append_row", description: "Appends a row.", inputSchema: obj };
const TOOLS = [LIST, CREATE, PURGE, REPORT, DELTMP];

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
let iatTick = 0;
function sign(policy) {
  const iat = new Date(Math.max(Date.now() - 60000 + iatTick++, (sign.last || 0) + 1)).toISOString();
  sign.last = Date.parse(iat);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
async function startConsole(initial, { signed = true } = {}) {
  const st = { policy: initial, alerts: [], toolReports: [] };
  const server = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { if (!signed) { res.writeHead(404); res.end(); return; } res.writeHead(200, { "Content-Type": "application/json" }); res.end(pubkeyBody); return; }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(signed ? sign(st.policy) : JSON.stringify(st.policy)); return; }
    if (req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { if (req.url === "/api/alerts") st.alerts.push(JSON.parse(b)); else if (req.url === "/api/mcp/tools") st.toolReports.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(201); res.end("{}"); });
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
function guardHome(url) {
  const home = mkdtempSync(join(tmpdir(), "moorai-toolclass-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok" }));
  return home;
}
function startGuard({ home, url, toolBatches, recvLog, label = "rows" }) {
  const toolsFile = join(home, `tools-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(toolsFile, JSON.stringify(toolBatches));
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: TENANT, FAKE_TOOLS_FILE: toolsFile, MOORAI_TEST_POLICY_REFRESH_MS: "0" };
  const child = spawn(process.execPath, [GUARD, "--server", label, "--", process.execPath, FAKE, recvLog], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  const byId = new Map();
  let pending = "", stderr = "";
  child.stderr.on("data", (c) => { stderr += c; });
  child.stdout.on("data", (c) => {
    pending += c.toString();
    let nl;
    while ((nl = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* not a response */ }
    }
  });
  let nextId = 1;
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
    call: async (name, args = {}) => (await send("tools/call", { name, arguments: args })).result,
    close: () => new Promise((r) => { child.once("exit", () => r()); try { child.stdin.end(); child.kill(); } catch { r(); } })
  };
}
const blocked = (r) => r && r.isError === true && /MoorAI blocked this MCP tool call/.test(r.content[0].text);
const called = (log) => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l).name) : []);
async function guardScenario(policy, fn) {
  const con = await startConsole(policy);
  const home = guardHome(con.url);
  try { await fn({ con, home, log: join(home, "recv.log") }); } finally { await con.close(); rmTree(home); }
}

test("GUARD: read allows, write asks (forwarded and recorded), destructive blocks; an annotation tightens but cannot loosen", async () => {
  await guardScenario(CLASSED, async ({ con, home, log }) => {
    const g = startGuard({ home, url: con.url, toolBatches: [TOOLS], recvLog: log });
    try {
      await g.list();
      assert.ok(!blocked(await g.call("list_rows")));
      assert.ok(!blocked(await g.call("create_row")), "the guard has no approver: an ask is forwarded");
      assert.ok(blocked(await g.call("purge_cache")));
      assert.ok(blocked(await g.call("get_report")), "destructiveHint true must make a read-named tool destructive");
      assert.ok(blocked(await g.call("delete_tmp")), "readOnlyHint true must not loosen a destructive name");
      assert.deepEqual(called(log), ["list_rows", "create_row"]);
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(classOf(con, "desktop:list_rows"), []);
    assert.deepEqual(classOf(con, "desktop:create_row"), [["ask", "write", "heuristic"]]);
    assert.deepEqual(classOf(con, "desktop:purge_cache"), [["deny", "destructive", "heuristic"]]);
    assert.deepEqual(classOf(con, "desktop:get_report"), [["deny", "destructive", "annotation"]]);
    assert.deepEqual(classOf(con, "desktop:delete_tmp"), [["deny", "destructive", "heuristic"]]);
    const deny = classAlerts(con).find((a) => a.tool === "desktop:purge_cache");
    assert.equal(deny.category, "MCP: tool blocked by class default");
    assert.equal(deny.riskLevel, "Blocked");
    assert.equal(deny.mcpServer, "rows");
  });
});

test("GUARD: without mcpToolClassDefaults nothing changes — every tool is forwarded and no class alert is raised", async () => {
  await guardScenario({ captureTier: "content-free" }, async ({ con, home, log }) => {
    const g = startGuard({ home, url: con.url, toolBatches: [TOOLS], recvLog: log });
    try {
      await g.list();
      for (const t of TOOLS) assert.ok(!blocked(await g.call(t.name)), t.name);
      assert.deepEqual(called(log), TOOLS.map((t) => t.name));
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(classAlerts(con), []);
  });
});

test("GUARD: a tool added after approval gets its class verdict (alert mode)", async () => {
  await guardScenario({ ...CLASSED, mcpToolBaselines: { rows: { version: 1, tools: [toolIdentity(LIST, "rows")] } } }, async ({ con, home, log }) => {
    const g = startGuard({ home, url: con.url, toolBatches: [[LIST], [LIST, DROP, APPEND]], recvLog: log });
    try {
      await g.list();
      assert.deepEqual(await g.list(), ["list_rows", "drop_table", "append_row"], "alert mode: the listing is not altered");
      assert.ok(blocked(await g.call("drop_table")));
      assert.ok(!blocked(await g.call("append_row")));
      assert.deepEqual(called(log), ["append_row"]);
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(classOf(con, "desktop:drop_table"), [["deny", "destructive", "heuristic"]]);
    assert.deepEqual(classOf(con, "desktop:append_row"), [["ask", "write", "heuristic"]]);
  });
});

test("GUARD: block-mode drift quarantines an added tool first; once re-approved, its class verdict still applies", async () => {
  const policy = { mcpToolDrift: "block", ...CLASSED, mcpToolBaselines: { rows: { version: 1, tools: [toolIdentity(LIST, "rows")] } } };
  await guardScenario(policy, async ({ con, home, log }) => {
    const g = startGuard({ home, url: con.url, toolBatches: [[LIST, DROP, APPEND]], recvLog: log });
    try {
      assert.ok(blocked(await g.call("__prime__")), "block mode refuses a tool never listed (loads the policy)");
      assert.deepEqual(await g.list(), ["list_rows"], "the added tools are quarantined");
      assert.ok(blocked(await g.call("drop_table")));
      assert.ok(blocked(await g.call("append_row")));
      await settle();
      assert.ok(con.alerts.some((a) => a.reasonCode === "MCP_TOOL_DRIFT" && a.tool === "desktop:drop_table" && a.decision === "deny"), "drift handling is unchanged");
      assert.deepEqual(classAlerts(con), [], "a quarantined tool is refused by drift before its class is consulted");
      con.policy = { ...policy, mcpToolBaselines: { rows: { version: 2, tools: [LIST, DROP, APPEND].map((t) => toolIdentity(t, "rows")) } } };
      const p = join(home, ".moorai", "hook-policy.json");
      if (existsSync(p)) { const t = new Date(Date.now() - 3600_000); utimesSync(p, t, t); }
      assert.ok(blocked(await g.call("drop_table")), "re-approval releases the drift quarantine, but the class default still blocks a destructive tool");
      assert.ok(!blocked(await g.call("append_row")), "re-approved write tool: the class ask forwards");
      assert.deepEqual(called(log), ["append_row"]);
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(classOf(con, "desktop:drop_table"), [["deny", "destructive", "heuristic"]]);
    assert.deepEqual(classOf(con, "desktop:append_row"), [["ask", "write", "heuristic"]]);
  });
});

// ---- the HTTP gateway ----
const listReply = (batches) => { let i = 0; return (m) => JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: batches[Math.min(i++, batches.length - 1)] } }); };
const refused = (r) => r.json && r.json.result && r.json.result.isError === true && /MoorAI blocked this MCP tool call/.test(r.json.result.content[0].text);
const upCalls = (up) => up.calls().map((c) => c.json.params.name);
const gwEnv = { MOORAI_TEST_POLICY_REFRESH_MS: "0" };
async function gwRun(policy, upstream, fn, { env = gwEnv } = {}) {
  const con = await startConsole(policy);
  const home = gwHome(con.url);
  try { await gwScenario({ con, home, upstream, env: typeof env === "function" ? env(con.url) : env }, (ctx) => fn({ ...ctx, con })); }
  finally { await con.close(); rmTree(home); }
}
const listOnce = (base, id) => rpc(base, { jsonrpc: "2.0", id, method: "tools/list", params: {} });

test("GATEWAY: read allows, write asks (forwarded and recorded), destructive blocks; an annotation tightens but cannot loosen", async () => {
  await gwRun(CLASSED, { listReply: listReply([TOOLS]) }, async ({ base, up, con }) => {
    await listOnce(base, 1);
    assert.ok(!refused(await rpc(base, call(2, "list_rows"))));
    assert.ok(!refused(await rpc(base, call(3, "create_row"))), "outside server mode the gateway forwards an ask");
    assert.ok(refused(await rpc(base, call(4, "purge_cache"))));
    assert.ok(refused(await rpc(base, call(5, "get_report"))));
    assert.ok(refused(await rpc(base, call(6, "delete_tmp"))));
    assert.deepEqual(upCalls(up), ["list_rows", "create_row"]);
    await settle();
    assert.deepEqual(classOf(con, "gateway:list_rows"), []);
    assert.deepEqual(classOf(con, "gateway:create_row"), [["ask", "write", "heuristic"]]);
    assert.deepEqual(classOf(con, "gateway:purge_cache"), [["deny", "destructive", "heuristic"]]);
    assert.deepEqual(classOf(con, "gateway:get_report"), [["deny", "destructive", "annotation"]]);
    assert.deepEqual(classOf(con, "gateway:delete_tmp"), [["deny", "destructive", "heuristic"]]);
    assert.ok(classAlerts(con).every((a) => a.mcpServer === "remote"));
  });
});

test("GATEWAY, server mode: a write tool's ask has no approver and is denied (headlessAsk default)", async () => {
  await gwRun(CLASSED, { listReply: listReply([TOOLS]) }, async ({ base, up, con }) => {
    await listOnce(base, 1);
    assert.ok(refused(await rpc(base, call(2, "create_row"))));
    assert.ok(!refused(await rpc(base, call(3, "list_rows"))));
    assert.deepEqual(upCalls(up), ["list_rows"]);
    await settle();
    assert.deepEqual(classOf(con, "gateway:create_row"), [["deny", "write", "heuristic"]]);
  }, { env: (url) => ({ ...gwEnv, ...serverModeEnv(url) }) });
});

test("GATEWAY: a tool added after approval gets its class verdict; without the field nothing changes", async () => {
  await gwRun({ ...CLASSED, mcpToolBaselines: { remote: { version: 1, tools: [toolIdentity(LIST, "remote")] } } }, { listReply: listReply([[LIST], [LIST, DROP, APPEND]]) }, async ({ base, up, con }) => {
    await listOnce(base, 1);
    await listOnce(base, 2);
    assert.ok(refused(await rpc(base, call(3, "drop_table"))));
    assert.ok(!refused(await rpc(base, call(4, "append_row"))));
    assert.deepEqual(upCalls(up), ["append_row"]);
    await settle();
    assert.deepEqual(classOf(con, "gateway:drop_table"), [["deny", "destructive", "heuristic"]]);
  });
  await gwRun({ captureTier: "content-free" }, { listReply: listReply([TOOLS]) }, async ({ base, up, con }) => {
    await listOnce(base, 1);
    for (const [i, t] of TOOLS.entries()) assert.ok(!refused(await rpc(base, call(10 + i, t.name))), t.name);
    assert.deepEqual(upCalls(up), TOOLS.map((t) => t.name));
    await settle();
    assert.deepEqual(classAlerts(con), []);
  });
});

// ---- the Claude Code hook ----
function hookSandbox(url, serverMode) {
  const home = mkdtempSync(join(tmpdir(), "moorai-toolclass-hook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  if (!serverMode) writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok-class" }));
  return home;
}
function runHook(home, url, tool, serverMode) {
  const base = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_OFFLINE_MODE: "" };
  const env = serverMode ? { ...base, MOORAI_MODE: "server", MOORAI_SERVER_URL: url, MOORAI_TENANT: TENANT, MOORAI_INSTALL_TOKEN: "tok-class", MOORAI_SERVICE_ID: "class-bot" } : base;
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: home, env });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => { if (status !== 0) return rej(new Error(`hook exit ${status}: ${err}`)); const t = out.trim(); res(t ? JSON.parse(t) : {}); });
    c.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, tool_input: { name: "x" }, tool_use_id: "tu-1", session_id: "class", transcript_path: "", cwd: home, permission_mode: "default" }));
  });
}
const decisionOf = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || "allow";
async function hookRun(policy, serverMode, fn) {
  const con = await startConsole(policy, { signed: false });
  const home = hookSandbox(con.url, serverMode);
  try { await fn({ con, run: (tool) => runHook(home, con.url, tool, serverMode) }); } finally { await con.close(); rmTree(home); }
}

test("HOOK: mcp__ calls get the class verdict by override or name; the alert names class, verdict and source", async () => {
  await hookRun({ captureTier: "content-free", ...CLASSED, mcpToolClasses: { github: { merge_pull_request: "destructive" } } }, false, async ({ con, run }) => {
    assert.equal(decisionOf(await run("mcp__github__list_issues")), "allow");
    assert.equal(decisionOf(await run("mcp__github__create_issue")), "ask");
    const d = await run("mcp__github__delete_repository");
    assert.equal(decisionOf(d), "deny");
    assert.match(d.hookSpecificOutput.permissionDecisionReason, /delete_repository is a destructive MCP tool \(heuristic\)/);
    assert.equal(decisionOf(await run("mcp__github__merge_pull_request")), "deny", "the admin override decides");
    await settle(300);
    assert.deepEqual(classOf(con, "hook:mcp__github__list_issues"), []);
    assert.deepEqual(classOf(con, "hook:mcp__github__create_issue"), [["ask", "write", "heuristic"]]);
    assert.deepEqual(classOf(con, "hook:mcp__github__delete_repository"), [["deny", "destructive", "heuristic"]]);
    assert.deepEqual(classOf(con, "hook:mcp__github__merge_pull_request"), [["deny", "destructive", "override"]]);
    assert.ok(classAlerts(con).every((a) => a.mcpServer === "github"));
  });
});

test("HOOK, server mode: a write tool's ask is settled as a deny; without the field the same calls are allowed", async () => {
  await hookRun({ captureTier: "content-free", ...CLASSED }, true, async ({ run }) => {
    assert.equal(decisionOf(await run("mcp__github__create_issue")), "deny");
    assert.equal(decisionOf(await run("mcp__github__list_issues")), "allow");
  });
  await hookRun({ captureTier: "content-free" }, false, async ({ con, run }) => {
    for (const t of ["mcp__github__delete_repository", "mcp__github__create_issue", "mcp__github__frobnicate"]) assert.equal(decisionOf(await run(t)), "allow", t);
    await settle(300);
    assert.deepEqual(classAlerts(con), []);
  });
});
