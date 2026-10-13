// The MCP guard's admin-chosen fail mode (cli/fail-mode.mjs surface "mcpGateway"), driven through the
// real stdio proxy (mcp-proxy/moorai-mcp-guard.mjs) and the fake MCP server.
//
// Call side: a tools/call whose arguments nest deeper than JSON.stringify can walk (the gate's own
// serialisation throws RangeError). Today the gate's catch forwards it unscanned; closed refuses it with
// an isError result and the real server never receives it. Result side: the existing scan-fault and
// async-stall test hooks (MOORAI_TEST_RESULTSCAN_THROW, MOORAI_TEST_RESULT_STALL_MS).
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-mcp-guard.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const DEPTH = 200000;
const deepArgs = () => { let v = {}; const root = v; for (let i = 0; i < DEPTH; i++) { v.n = {}; v = v.n; } return root; };
// JSON.stringify(deepArgs()) itself overflows, so the line is built by hand.
const DEEP_LINE = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":${'{"n":'.repeat(DEPTH)}{}${"}".repeat(DEPTH)}}}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function consoleStub(t) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      res.writeHead(500); res.end("offline");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts };
}

async function drive(t, { url, policy, env = {}, lines }) {
  const home = mkdtempSync(join(tmpdir(), "moorai-fm-guard-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "fm", installToken: "tok-fm-guard" }));
  if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  const recv = join(home, "recv.log");
  const resultFile = join(home, "result.txt");
  writeFileSync(resultFile, "plain tool output, nothing sensitive");
  const childEnv = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, FAKE_RESULT_FILE: resultFile, ...env };
  const child = spawn(process.execPath, [GUARD, "--server", "testsrv", "--", process.execPath, FAKE, recv], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: childEnv });
  child.stderr.on("data", () => {});
  const byId = new Map();
  const all = [];
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) { byId.set(m.id, m); all.push(m); } } catch { /* ignore */ }
    }
  });
  for (const l of lines) child.stdin.write(l + "\n");
  const want = lines.length;
  const deadline = Date.now() + 10000;
  while (byId.size < want && Date.now() < deadline) await sleep(25);
  await sleep(500); // a late second answer for the same id (the real server's) would land here
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  await sleep(300);
  return { byId, all, received: existsSync(recv) ? readFileSync(recv, "utf8") : "" };
}
const isFailBlock = (m) => Boolean(m && m.result && m.result.isError === true && /not evaluated/.test(String(m.result.content?.[0]?.text)));
const call = (id, msg = "hello") => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "echo", arguments: { msg } } });
async function until(fn, ms = 5000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

test("CALL, closed: a tools/call the gate cannot evaluate is refused and never reaches the server", async (t) => {
  assert.throws(() => JSON.stringify(deepArgs()), RangeError, "the trigger still overflows the serialiser");
  const c = await consoleStub(t);
  for (const policy of [{ captureTier: "content-free", failMode: { mcpGateway: "closed" } }, { captureTier: "content-free", failMode: { default: "closed" } }]) {
    const r = await drive(t, { url: c.url, policy, lines: [call(1), DEEP_LINE] });
    assert.equal(r.byId.get(1)?.result?.isError, false, "a normal call still goes through");
    assert.ok(isFailBlock(r.byId.get(7)), `refused with a fail-closed tool error: ${JSON.stringify(r.byId.get(7))?.slice(0, 200)}`);
    assert.equal(r.all.filter((m) => m.id === 7).length, 1, "one answer only: the real server never received the unevaluated call");
  }
  assert.ok(await until(() => c.alerts.some((a) => a.reasonCode === "FAIL_CLOSED" && a.stage === "mcp")), `alerts: ${JSON.stringify(c.alerts.map((a) => a.category))}`);
  const a = c.alerts.find((x) => x.reasonCode === "FAIL_CLOSED" && x.stage === "mcp");
  assert.equal(a.category, "Fail-closed: MCP call not evaluated");
  assert.equal(a.failModeSource, "policy");
  assert.equal(a.failWhy, "error");
  assert.equal(a.enforcement, "STRENGTHENED");
});

test("CALL, open (explicit and absent): the same call is forwarded as before", async (t) => {
  const c = await consoleStub(t);
  for (const policy of [{ captureTier: "content-free", failMode: { mcpGateway: "open", default: "closed" } }, { captureTier: "content-free" }]) {
    const r = await drive(t, { url: c.url, policy, lines: [DEEP_LINE] });
    assert.equal(r.byId.get(7)?.result?.isError, false, `forwarded: ${JSON.stringify(policy)}`);
    assert.match(r.byId.get(7).result.content[0].text, /plain tool output/, "the real server answered it");
  }
});

test("RESULT, closed: a result the scan failed on, or did not finish in time, is replaced; open forwards it", async (t) => {
  const c = await consoleStub(t);
  for (const env of [{ MOORAI_TEST_RESULTSCAN_THROW: "1" }, { MOORAI_TEST_RESULT_STALL_MS: "1500" }]) {
    const closed = await drive(t, { url: c.url, policy: { captureTier: "content-free", failMode: { mcpGateway: "closed" } }, env, lines: [call(3)] });
    assert.ok(isFailBlock(closed.byId.get(3)), `closed ${JSON.stringify(env)}: ${JSON.stringify(closed.byId.get(3))?.slice(0, 200)}`);
    assert.match(closed.byId.get(3).result.content[0].text, /^MoorAI blocked this MCP tool result: /);
    const open = await drive(t, { url: c.url, policy: { captureTier: "content-free" }, env, lines: [call(3)] });
    assert.equal(open.byId.get(3)?.result?.isError, false, `open ${JSON.stringify(env)}`);
    assert.match(open.byId.get(3).result.content[0].text, /plain tool output/);
  }
  assert.ok(await until(() => c.alerts.some((a) => a.reasonCode === "FAIL_CLOSED" && a.stage === "result")));
});
