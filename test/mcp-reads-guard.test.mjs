// MCP data harvesting and MCP path scope through the stdio guard (mcp-proxy/read-gate.mjs), over real stdio with
// the fake MCP server and a fake console serving a signed policy: tools/call reads and resources/read requests
// count toward the server's budget, result sizes toward its byte budget, and a filesystem server's path
// arguments are judged against its launch arguments or, once the client answers roots/list, its roots.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-reads-guard.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const TENANT = "acme";
const settle = (ms = 600) => new Promise((r) => setTimeout(r, ms));

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
function sign(policy) {
  const iat = new Date(Date.now() - 60000).toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
async function startConsole(policy) {
  const st = { alerts: [] };
  const server = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); res.end(pubkeyBody); return; }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(sign(policy)); return; }
    if (req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { if (req.url === "/api/alerts") st.alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(201); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  st.url = `http://127.0.0.1:${server.address().port}`;
  st.close = () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); });
  return st;
}
function guardHome(url) {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "moorai-mcpreads-guard-")));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok" }));
  return home;
}
// serverArgv: the real server's command line after "--".
function startGuard({ home, url, label, serverArgv, env = {} }) {
  const child = spawn(process.execPath, [GUARD, "--server", label, "--", ...serverArgv], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: TENANT, MOORAI_TEST_POLICY_REFRESH_MS: "0", ...env } });
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
    send,
    raw: (o) => child.stdin.write(JSON.stringify(o) + "\n"),
    call: async (name, args = {}) => (await send("tools/call", { name, arguments: args })).result,
    close: () => new Promise((r) => { child.once("exit", () => r()); try { child.stdin.end(); child.kill(); } catch { r(); } })
  };
}
const blocked = (r) => r && r.isError === true && /MoorAI blocked this MCP tool call/.test(r.content[0].text);
const HARVEST = "MCP: data harvesting from one server";
async function scenario(policy, fn) {
  const con = await startConsole(policy);
  const home = guardHome(con.url);
  try { await fn({ con, home }); } finally { await con.close(); rmTree(home); }
}

test("GUARD: distinct read calls cross the budget once (report): forwarded, alerted with the server and tool", async () => {
  await scenario({ captureTier: "content-free", mcpHarvest: { reads: 3 } }, async ({ con, home }) => {
    const g = startGuard({ home, url: con.url, label: "crm", serverArgv: [process.execPath, FAKE, join(home, "recv.log")] });
    try {
      for (const id of [1, 2, 2, 3]) assert.ok(!blocked(await g.call("get_customer", { id })));
      assert.ok(!blocked(await g.call("update_customer", { id: 4 })));
      await settle();
    } finally { await g.close(); }
    const hits = con.alerts.filter((a) => a.category === HARVEST);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].tool, "desktop:get_customer");
    assert.equal(hits[0].mcpServer, "crm");
    assert.equal(hits[0].threatId, 59);
    assert.equal(hits[0].signature.reads, 3);
  });
});

test("GUARD: block mode refuses resources/read over budget with a JSON-RPC error, then read calls; writes pass", async () => {
  await scenario({ captureTier: "content-free", mcpHarvest: { mode: "block", reads: 2 } }, async ({ con, home }) => {
    const g = startGuard({ home, url: con.url, label: "docs", serverArgv: [process.execPath, FAKE, join(home, "recv.log")] });
    try {
      const first = await g.send("resources/read", { uri: "docs://page/1" });
      assert.deepEqual(first.result, {}, "under budget: forwarded to the server");
      const second = await g.send("resources/read", { uri: "docs://page/2" });
      assert.equal(second.result, undefined, "over budget: not forwarded");
      assert.equal(second.error.code, -32001);
      assert.match(second.error.message, /MoorAI blocked this MCP resource read: MCP data harvesting/);
      assert.ok(blocked(await g.call("list_pages", { cursor: "c3" })));
      assert.ok(!blocked(await g.call("create_page", { title: "t" })));
      await settle();
    } finally { await g.close(); }
    const hits = con.alerts.filter((a) => a.category === HARVEST);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].tool, "desktop:resources/read");
    assert.equal(hits[0].riskLevel, "Blocked");
    assert.ok(!JSON.stringify(hits).includes("page/2"));
  });
});

test("GUARD: result sizes of read calls cross the byte budget", async () => {
  await scenario({ captureTier: "content-free", mcpHarvest: { bytes: 50000 } }, async ({ con, home }) => {
    const file = join(home, "result.txt");
    writeFileSync(file, "x".repeat(30000));
    const g = startGuard({ home, url: con.url, label: "crm", serverArgv: [process.execPath, FAKE, join(home, "recv.log")], env: { FAKE_RESULT_FILE: file } });
    try {
      await g.call("export_rows", { page: 1 });
      await settle(200);
      assert.equal(con.alerts.filter((a) => a.category === HARVEST).length, 0);
      await g.call("export_rows", { page: 2 });
      await settle();
    } finally { await g.close(); }
    const hits = con.alerts.filter((a) => a.category === HARVEST);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].signature.kind, "bytes");
    assert.equal(hits[0].tool, "desktop:export_rows");
  });
});

test("GUARD: a filesystem server's launch roots, then the client's roots, decide the scope (block)", async () => {
  await scenario({ captureTier: "content-free", mcpScope: { mode: "block" } }, async ({ con, home }) => {
    const fsServer = join(home, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js");
    mkdirSync(dirname(fsServer), { recursive: true });
    copyFileSync(FAKE, fsServer);
    const a = join(home, "a"), b = join(home, "b");
    mkdirSync(a); mkdirSync(b);
    const g = startGuard({ home, url: con.url, label: "fs", serverArgv: [process.execPath, fsServer, a] });
    try {
      assert.ok(!blocked(await g.call("read_text_file", { path: join(a, "x.txt") })));
      assert.ok(blocked(await g.call("read_text_file", { path: `${a}/../b/x.txt` })));
      assert.ok(blocked(await g.call("directory_tree", { path: b })));
      // The client answers the server's roots/list: its roots replace the launch directories.
      g.raw({ jsonrpc: "2.0", id: "roots-1", result: { roots: [{ uri: pathToFileURL(b).href, name: "b" }] } });
      await settle(200);
      assert.ok(!blocked(await g.call("read_text_file", { path: join(b, "x.txt") })));
      assert.ok(blocked(await g.call("read_text_file", { path: join(a, "x.txt") })));
      await settle();
    } finally { await g.close(); }
    const sc = con.alerts.filter((x) => x.threatId === 64 && x.reasonCode === "ENVELOPE");
    assert.deepEqual(sc.map((x) => [x.tool, x.category, x.signature.scope]), [
      ["desktop:read_text_file", "MCP: path traversal outside the server's scope", "args"],
      ["desktop:directory_tree", "MCP: directory listing outside the server's scope", "args"],
      ["desktop:read_text_file", "MCP: path outside the server's scope", "roots"]
    ]);
    assert.ok(!JSON.stringify(sc).includes(home), "no path in an alert");
  });
});

test("GUARD: a response line over the 1 MB scan cap still counts toward the byte budget", async () => {
  await scenario({ captureTier: "content-free", mcpHarvest: { bytes: 1048576 } }, async ({ con, home }) => {
    const file = join(home, "result.txt");
    writeFileSync(file, "x".repeat(1200000));
    const g = startGuard({ home, url: con.url, label: "crm", serverArgv: [process.execPath, FAKE, join(home, "recv.log")], env: { FAKE_RESULT_FILE: file } });
    try {
      const r = await g.call("export_rows", { page: 1 });
      assert.equal(r.content[0].text.length, 1200000, "forwarded unchanged");
      await settle();
    } finally { await g.close(); }
    const hits = con.alerts.filter((a) => a.category === HARVEST);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].signature.kind, "bytes");
    assert.ok(hits[0].signature.bytes > 1048576, "at least the bytes buffered before the line was streamed");
  });
});

test("GUARD: path arguments padded past the scope check's caps are refused under block; 64 paths inside the root pass", async () => {
  await scenario({ captureTier: "content-free", mcpScope: { mode: "block" } }, async ({ con, home }) => {
    const fsServer = join(home, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist", "index.js");
    mkdirSync(dirname(fsServer), { recursive: true });
    copyFileSync(FAKE, fsServer);
    const a = join(home, "a");
    mkdirSync(a);
    const inside = join(a, "x.txt");
    const g = startGuard({ home, url: con.url, label: "fs", serverArgv: [process.execPath, fsServer, a] });
    try {
      assert.ok(!blocked(await g.call("read_multiple_files", { paths: Array(64).fill(inside) })));
      assert.ok(blocked(await g.call("read_text_file", { path: "/etc/passwd", files: Array(64).fill(inside) })), "a path hidden behind 64 padding paths");
      assert.ok(blocked(await g.call("read_multiple_files", { paths: [...Array(64).fill(inside), "/etc/passwd"] })), "the 65th path");
      assert.ok(blocked(await g.call("read_text_file", { path: `${a}/${"./".repeat(2100)}../../etc/passwd` })), "a path over 4096 characters");
      await settle();
    } finally { await g.close(); }
    const sc = con.alerts.filter((x) => x.threatId === 64 && x.reasonCode === "ENVELOPE");
    assert.ok(sc.length >= 1 && sc.every((x) => x.category === "MCP: path arguments the scope check could not read in full" && x.decision === "deny"), JSON.stringify(sc.map((x) => x.category)));
    assert.ok(!JSON.stringify(sc).includes(home), "no path in an alert");
  });
});
