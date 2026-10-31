// MCP server package policy, END TO END through the real Claude Desktop proxy (mcp-proxy/moorai-mcp-guard.mjs)
// over real stdio. The wrapped launch is `npx -y <package>`; a fake `npx` first on PATH runs the fake MCP
// server, so the guard judges the registry identity while the server it talks to is local.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-package-proxy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { MCP_PACKAGE_CATEGORY, MCP_PACKAGE_HELD_CATEGORY } from "../cli/mcp-package-policy.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const TENANT = "acme";
const skip = process.platform === "win32" ? "the fake npx is a POSIX shell script" : false;

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
function sign(policy) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat: "2026-09-01T00:00:00.000Z", digest })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat: "2026-09-01T00:00:00.000Z", sig } });
}

const CLEAN = { name: "add", description: "Adds two numbers and returns the sum.", inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } } } };

async function startConsole(policyBody) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); res.end(pubkeyBody); return; }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(policyBody); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

function makeHome(url) {
  const home = mkdtempSync(join(tmpdir(), "moorai-pkgproxy-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, installToken: "tok" }));
  const bin = join(home, "bin");
  mkdirSync(bin);
  const recv = join(home, "recv.log");
  writeFileSync(join(bin, "npx"), `#!/bin/sh\nexec "${process.execPath}" "${FAKE}" "${recv}"\n`);
  chmodSync(join(bin, "npx"), 0o755);
  const tools = join(home, "tools.json");
  writeFileSync(tools, JSON.stringify([CLEAN]));
  return { home, bin, recv, tools };
}

async function driveGuard({ home, bin, tools, url, spec, requests, waitMs = 700 }) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: TENANT, FAKE_TOOLS_FILE: tools, PATH: `${bin}${delimiter}${process.env.PATH}` };
  const child = spawn(process.execPath, [GUARD, "--server", "files", "--", "npx", "-y", spec], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  let pending = "", stderr = "";
  const byId = new Map();
  child.stderr.on("data", (c) => { stderr += c.toString(); });
  child.stdout.on("data", (c) => {
    pending += c.toString();
    let nl;
    while ((nl = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* not a response */ }
    }
  });
  for (const step of requests) {
    if (typeof step === "number") { await new Promise((r) => setTimeout(r, step)); continue; }
    child.stdin.write(JSON.stringify(step) + "\n");
    const deadline = Date.now() + 15000;
    while (!byId.has(step.id) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
  }
  await new Promise((r) => setTimeout(r, waitMs));
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  await new Promise((r) => setTimeout(r, 120));
  return { byId, stderr };
}

async function scenario(policy, fn) {
  const con = await startConsole(sign(policy));
  const sb = makeHome(con.url);
  try { await fn({ con, ...sb }); } finally { await con.close(); rmTree(sb.home); }
}

const LIST = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
const CALL = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "add", arguments: { a: 1, b: 2 } } };
const pkgAlerts = (con) => con.alerts.filter((a) => a.category === MCP_PACKAGE_CATEGORY || a.category === MCP_PACKAGE_HELD_CATEGORY);
const received = (recv) => existsSync(recv) && readFileSync(recv, "utf8").includes('"add"');

test("PROXY: mcpPackagePolicy block refuses calls to an unpinned npx server; the server never receives them", { skip }, async () => {
  await scenario({ mcpPackagePolicy: "block" }, async ({ con, home, bin, tools, recv }) => {
    const r = await driveGuard({ home, bin, tools, url: con.url, spec: "@modelcontextprotocol/server-filesystem", requests: [LIST, 400, CALL] });
    const res = r.byId.get(2);
    assert.ok(res && res.result && res.result.isError, `expected a refused call, got ${JSON.stringify(res)} ${r.stderr}`);
    assert.match(res.result.content[0].text, /package is held .*unpinned-version/);
    assert.equal(received(recv), false, "a held call never reaches the server");
    const held = pkgAlerts(con).filter((a) => a.decision === "block");
    assert.ok(held.length >= 1, JSON.stringify(con.alerts.map((a) => [a.category, a.decision])));
    assert.equal(JSON.stringify(pkgAlerts(con)).includes("server-filesystem"), false, "the package name never leaves");
  });
});

test("PROXY: the same server pinned to an exact version is forwarded", { skip }, async () => {
  await scenario({ mcpPackagePolicy: "block" }, async ({ con, home, bin, tools, recv }) => {
    const r = await driveGuard({ home, bin, tools, url: con.url, spec: "@modelcontextprotocol/server-filesystem@2025.8.21", requests: [LIST, 400, CALL] });
    assert.ok(r.byId.get(2) && !r.byId.get(2).result.isError, JSON.stringify(r.byId.get(2)));
    assert.equal(received(recv), true);
    assert.deepEqual(pkgAlerts(con), []);
  });
});

test("PROXY: default report forwards an unpinned server and reports it on first sight", { skip }, async () => {
  await scenario({}, async ({ con, home, bin, tools, recv }) => {
    const r = await driveGuard({ home, bin, tools, url: con.url, spec: "@modelcontextprotocol/server-filesystem", requests: [LIST, 400, CALL] });
    assert.ok(r.byId.get(2) && !r.byId.get(2).result.isError);
    assert.equal(received(recv), true);
    const a = pkgAlerts(con);
    assert.equal(a.length, 1, JSON.stringify(a));
    assert.equal(a[0].decision, "alert");
    assert.deepEqual(a[0].packageSignals, ["unpinned-version"]);
  });
});

test("PROXY: a server launched from a known-compromised release is refused with no mcpPackagePolicy", { skip }, async () => {
  await scenario({}, async ({ con, home, bin, tools, recv }) => {
    const r = await driveGuard({ home, bin, tools, url: con.url, spec: "chalk@5.6.1", requests: [LIST, 400, CALL] });
    const res = r.byId.get(2);
    assert.ok(res && res.result && res.result.isError, JSON.stringify(res));
    assert.match(res.result.content[0].text, /known-bad-release/);
    assert.equal(received(recv), false);
  });
});

test("PROXY: a call to a server off the mcpAllow list is refused and reported under #25", { skip }, async () => {
  await scenario({ mcpAllow: ["github"] }, async ({ con, home, bin, tools, recv }) => {
    const r = await driveGuard({ home, bin, tools, url: con.url, spec: "@modelcontextprotocol/server-filesystem@2025.8.21", requests: [LIST, 400, CALL] });
    const res = r.byId.get(2);
    assert.ok(res && res.result && res.result.isError, `expected a refused call, got ${JSON.stringify(res)} ${r.stderr}`);
    assert.equal(received(recv), false);
    const a = con.alerts.find((x) => x.category === "MCP: unapproved server");
    assert.ok(a, JSON.stringify(con.alerts.map((x) => x.category)));
    assert.equal(a.threatId, 25);
  });
});
