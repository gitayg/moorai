// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/sensitivity-labels-proxy.test.mjs
//
// labelPolicy through the Claude Desktop stdio proxy (mcp-proxy/moorai-mcp-guard.mjs), over real stdio
// against the real fake MCP server with a real HTTP alert sink. "Blocked" means the real server never
// received the call. Generated fixture files only (test/fixtures/label-files.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { docx, LABEL_ID } from "./fixtures/label-files.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const RULES = { rules: [{ match: { id: LABEL_ID }, onRead: "notify", onSend: "block" }] };

async function withSink(fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(503); res.end(""); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(`http://127.0.0.1:${server.address().port}`, alerts); } finally { await new Promise((r) => server.close(r)); }
}

function sandbox(url, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-label-proxy-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "lblp", installToken: "tok" }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", ...policy }));
  const proj = join(home, "proj");
  mkdirSync(proj);
  writeFileSync(join(proj, "board-deck.docx"), docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] }));
  writeFileSync(join(proj, "broken.docx"), docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] }).subarray(0, 150));
  return { home, proj };
}

async function drive(home, cwd, url, messages) {
  const recv = join(home, "recv.log");
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: "lblp" };
  const child = spawn(process.execPath, [GUARD, "--server", "files", "--", process.execPath, FAKE, recv], { cwd, stdio: ["pipe", "pipe", "pipe"], env });
  child.stderr.on("data", () => {});
  const byId = new Map();
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* ignore */ }
    }
  });
  for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n");
  const want = messages.map((m) => m.id);
  const deadline = Date.now() + 10000;
  while (!want.every((id) => byId.has(id)) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
  await new Promise((r) => setTimeout(r, 300));
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  return { byId, received: existsSync(recv) ? readFileSync(recv, "utf8") : "" };
}

const call = (id, args, name) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const isBlocked = (m) => Boolean(m && m.result && m.result.isError === true && /MoorAI blocked/i.test(String(m.result.content?.[0]?.text)));

test("PROXY: an upload of a labelled file is a send → refused; a read_file of it is a read → forwarded and reported", async () => {
  await withSink(async (url, alerts) => {
    const { home, proj } = sandbox(url, { labelPolicy: RULES });
    try {
      const r = await drive(home, proj, url, [call(1, { path: join(proj, "board-deck.docx") }, "upload_file"), call(2, { path: join(proj, "board-deck.docx") }, "read_file")]);
      assert.ok(isBlocked(r.byId.get(1)), JSON.stringify(r.byId.get(1)));
      assert.ok(!isBlocked(r.byId.get(2)), JSON.stringify(r.byId.get(2)));
      assert.ok(!r.received.includes("upload_file"), "the real server never received the upload");
      const la = alerts.filter((a) => a.sensitivityLabel);
      assert.deepEqual(la.map((a) => [a.tool, a.sensitivityLabel.action, a.sensitivityLabel.verdict, a.riskLevel === "Blocked"]).sort(), [["desktop:read_file", "read", "notify", false], ["desktop:upload_file", "send", "block", true]]);
      assert.ok(la.every((a) => a.threatId === 1 && a.sensitivityLabel.labelId === LABEL_ID && /^h2:/.test(a.contentHash)));
      assert.ok(!JSON.stringify(la).includes("board-deck"), "content-free");
    } finally { rmTree(home); }
  });
});

test("PROXY: an unreadable label under failMode.mcpGateway closed refuses the call; open forwards it", async () => {
  await withSink(async (url, alerts) => {
    const { home, proj } = sandbox(url, { labelPolicy: RULES, failMode: { mcpGateway: "closed" } });
    try {
      const r = await drive(home, proj, url, [call(1, { path: join(proj, "broken.docx") }, "upload_file")]);
      assert.ok(isBlocked(r.byId.get(1)), JSON.stringify(r.byId.get(1)));
      assert.match(r.byId.get(1).result.content[0].text, /could not read the sensitivity label of a file it names/);
      assert.ok(alerts.some((a) => a.reasonCode === "FAIL_CLOSED" && a.failWhy === "label"), JSON.stringify(alerts.map((a) => [a.category, a.failWhy])));
    } finally { rmTree(home); }
  });
  await withSink(async (url) => {
    const { home, proj } = sandbox(url, { labelPolicy: RULES });
    try {
      const r = await drive(home, proj, url, [call(1, { path: join(proj, "broken.docx") }, "upload_file")]);
      assert.ok(!isBlocked(r.byId.get(1)), JSON.stringify(r.byId.get(1)));
    } finally { rmTree(home); }
  });
});
