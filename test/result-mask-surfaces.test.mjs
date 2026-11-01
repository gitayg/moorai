// The default #39 result mask on the surfaces that hold a result before the model reads it (cli/result-mask.mjs):
// the HTTP MCP gateway (a tools/call result, JSON and SSE) and the model proxy (a tool result a request sends
// upstream, --mode enforce). The stdio guard is covered in test/mcp-result-stage.test.mjs (REPORT-FIRST).
//
//   node --test --import ./test/hermetic-env.mjs test/result-mask-surfaces.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { startUpstream } from "../mcp-gateway/test/fake-upstream.mjs";
import { startFakeProvider, sendJson, anthropicMessage, openaiCompletion } from "../model-proxy/test/fake-provider.mjs";
import { sandbox, startConsole as startProxyConsole, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";
import { resultSlots, createResultMasker } from "../model-proxy/result-mask.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { rmTree, stopChild } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GATEWAY = join(ROOT, "mcp-gateway", "moorai-mcp-gateway.mjs");
const TENANT = "acme";
const KEY = "AKIAQ3EGUXWN5TLMRZ7P"; // secret-aws-akia shape (#39), not a real key
const TEXT = `deploy notes\naws_access_key_id = ${KEY}\nregion = eu-west-1`;
const TAG = /\[MOORAI:secret:[a-p]{8}\]/;

// ---- the HTTP MCP gateway ----

const consoleKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) });
function sign(policy) {
  const digest = policyDigest(policy);
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat: "2026-09-01T00:00:00.000Z", digest })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat: "2026-09-01T00:00:00.000Z", sig } });
}
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
  return { alerts, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
function startGateway({ home, consoleUrl, args }) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: consoleUrl, MoorAI_TENANT: TENANT };
  delete env.MOORAI_MODE;
  const child = spawn(process.execPath, [GATEWAY, ...args], { cwd: home, stdio: ["ignore", "pipe", "pipe"], env });
  let stderr = "";
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ child, url: null }), 10000);
    child.stderr.on("data", (c) => { stderr += c.toString(); const m = stderr.match(/listening on (http:\/\/[^\s]+)/); if (m) { clearTimeout(timer); resolve({ child, url: m[1].replace(/\/$/, "") }); } });
    child.on("exit", () => { clearTimeout(timer); resolve({ child, url: null }); });
  });
}
async function gateway(policy, upstream, fn) {
  const con = await startConsole(sign(policy));
  const home = mkdtempSync(join(tmpdir(), "moorai-rmask-gw-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: con.url, tenant: TENANT, installToken: "tok" }));
  const up = await startUpstream(upstream);
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`] });
  try { assert.ok(gw.url, "gateway did not start"); await fn({ con, base: `${gw.url}/remote` }); }
  finally { await stopChild(gw.child); await up.close(); await con.close(); rmTree(home); }
}
const H = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
async function rpc(url, msg) {
  const r = await fetch(url, { method: "POST", headers: H, body: JSON.stringify(msg) });
  return { status: r.status, text: await r.text() };
}
const call = (id, name, args = {}) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const settle = () => new Promise((r) => setTimeout(r, 600));
const replyOf = (text) => {
  try { return JSON.parse(text); } catch { /* sse */ }
  const d = text.split(/\n\n/).flatMap((ev) => ev.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart())).map((x) => JSON.parse(x));
  return d.find((m) => m.id != null && m.result);
};

for (const mode of ["json", "sse"]) {
  test(`gateway (${mode}) DEFAULT: a key in a tools/call result is masked, the rest delivered, the model told, the mask recorded`, async () => {
    await gateway({ captureTier: "content-free" }, { mode, resultText: TEXT }, async ({ con, base }) => {
      const r = await rpc(base, call(1, "get_notes", { id: 7 }));
      assert.equal(r.status, 200);
      assert.ok(!r.text.includes(KEY), "the key reached the client");
      const reply = replyOf(r.text);
      assert.equal(reply.id, 1);
      assert.notEqual(reply.result.isError, true, "a mask is not a block");
      assert.match(reply.result.content[0].text, TAG);
      assert.match(reply.result.content[0].text, /region = eu-west-1/);
      assert.match(reply.result.content.at(-1).text, /masked 1 sensitive span \(#39\)/);
      await settle();
      assert.ok(con.alerts.some((a) => a.threatId === 39 && a.stage === "result"), "the finding is still reported");
      assert.ok(con.alerts.some((a) => a.category === "Sensitive span masked" && a.decision === "mask" && a.tool === "gateway:get_notes"));
      assert.ok(!JSON.stringify(con.alerts).includes(KEY));
    });
  });
}

test("gateway OPT-OUT: threatPolicy[39] notify forwards the result unaltered", async () => {
  await gateway({ captureTier: "content-free", threatPolicy: { 39: "notify" } }, { mode: "json", resultText: TEXT }, async ({ con, base }) => {
    const r = await rpc(base, call(1, "get_notes", { id: 7 }));
    assert.equal(JSON.parse(r.text).result.content[0].text, TEXT);
    await settle();
    assert.ok(!con.alerts.some((a) => a.category === "Sensitive span masked"));
  });
});

// ---- the model proxy ----

const anthropicReq = (result) => ({ model: "claude-fake", max_tokens: 64, messages: [
  { role: "user", content: "read the deploy notes" },
  { role: "assistant", content: [{ type: "tool_use", id: "toolu_n1", name: "Read", input: { file_path: "notes.md" } }] },
  { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_n1", content: result }] }] });
const openaiReq = (result) => ({ model: "gpt-fake", messages: [
  { role: "user", content: "read the deploy notes" },
  { role: "assistant", content: null, tool_calls: [{ id: "call_n1", type: "function", function: { name: "Read", arguments: "{\"file_path\":\"notes.md\"}" } }] },
  { role: "tool", tool_call_id: "call_n1", content: result }] });

async function proxy(mode, policy, fn) {
  const fp = await startFakeProvider();
  const con = await startProxyConsole();
  const home = sandbox();
  const pf = join(home, "policy.json");
  writeFileSync(pf, JSON.stringify(policy));
  const px = await startProxy(home, ["--mode", mode, "--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, "--policy-file", pf],
    { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-rmask-proxy", MOORAI_TENANT: "t-rmask" });
  try { await fn({ fp, con, px }); } finally { await px.stop(); await fp.close(); await con.close(); rmTree(home); }
}
const upstreamBody = (fp) => JSON.parse(fp.requests.at(-1).body.toString("utf8"));

test("model proxy (enforce) DEFAULT: Anthropic tool_result text is masked before it goes upstream; the rest of the request is unchanged", async () => {
  await proxy("enforce", {}, async ({ fp, con, px }) => {
    fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
    const sent = anthropicReq([{ type: "text", text: TEXT }]);
    const r = await request(px.listening, "/anthropic/v1/messages", { body: sent, headers: { "anthropic-version": "2023-06-01" } });
    assert.equal(r.status, 200);
    const up = upstreamBody(fp);
    assert.ok(!JSON.stringify(up).includes(KEY), "the key went upstream");
    assert.match(up.messages[2].content[0].content[0].text, TAG);
    assert.match(up.messages[2].content[0].content[0].text, /region = eu-west-1/);
    assert.deepEqual(up.messages.slice(0, 2), sent.messages.slice(0, 2));
    assert.equal(up.messages[2].content[0].tool_use_id, "toolu_n1");
    await waitFor(() => con.parsed().some((a) => a.category === "Sensitive span masked"));
    assert.ok(con.parsed().some((a) => a.threatId === 39), "the finding is still reported");
    assert.ok(!con.alerts.join("").includes(KEY));
    // The same conversation re-sent: the same masked bytes (the provider's prompt cache still matches), one mask alert.
    await request(px.listening, "/anthropic/v1/messages", { body: sent, headers: { "anthropic-version": "2023-06-01" } });
    assert.equal(upstreamBody(fp).messages[2].content[0].content[0].text, up.messages[2].content[0].content[0].text);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(con.parsed().filter((a) => a.category === "Sensitive span masked").length, 1);
  });
});

test("model proxy (enforce) DEFAULT: an OpenAI tool message (string content) is masked upstream", async () => {
  await proxy("enforce", {}, async ({ fp, px }) => {
    fp.on((r, res) => sendJson(res, openaiCompletion({ text: "ok" })));
    const r = await request(px.listening, "/openai/chat/completions", { body: openaiReq(TEXT) });
    assert.equal(r.status, 200);
    const up = upstreamBody(fp);
    assert.match(up.messages[2].content, TAG);
    assert.ok(!JSON.stringify(up).includes(KEY));
  });
});

test("model proxy REPORT mode: the client's bytes go upstream unaltered (the mask needs --mode enforce)", async () => {
  await proxy("report", {}, async ({ fp, px }) => {
    fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
    const sent = JSON.stringify(anthropicReq(TEXT));
    await request(px.listening, "/anthropic/v1/messages", { body: JSON.parse(sent), headers: { "anthropic-version": "2023-06-01" } });
    assert.equal(fp.requests.at(-1).body.toString("utf8"), sent);
  });
});

test("model proxy (enforce) OPT-OUT: threatPolicy[39] notify forwards the tool result unaltered", async () => {
  await proxy("enforce", { threatPolicy: { 39: "notify" } }, async ({ fp, px }) => {
    fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
    await request(px.listening, "/anthropic/v1/messages", { body: anthropicReq(TEXT), headers: { "anthropic-version": "2023-06-01" } });
    assert.equal(upstreamBody(fp).messages[2].content[0].content, TEXT);
  });
});

test("model proxy resultSlots: the tool-result fields of each API, nothing else", () => {
  const a = anthropicReq([{ type: "text", text: "x" }, { type: "image", source: {} }]);
  assert.equal(resultSlots("anthropic", a).flat().length, 1);
  assert.equal(resultSlots("openai-chat", openaiReq("x")).flat()[0].key, "content");
  assert.equal(resultSlots("ollama", { messages: [{ role: "tool", content: "x" }, { role: "user", content: "y" }] }).flat().length, 1);
  assert.equal(resultSlots("openai-responses", { input: [{ type: "function_call_output", call_id: "c", output: "x" }, { type: "shell_call_output", output: [{ stdout: "o", stderr: "e" }] }, { role: "user", content: "y" }] }).flat().length, 3);
  assert.equal(resultSlots("gemini", { contents: [{ role: "user", parts: [{ functionResponse: { name: "f", response: { r: "x" } } }] }, { role: "model", parts: [{ functionResponse: { response: {} } }] }] }).flat().length, 1);
  const m = createResultMasker({ hash: (s) => "h2:" + Buffer.from(s).toString("hex").slice(0, 16) });
  const g = { contents: [{ role: "user", parts: [{ functionResponse: { name: "f", response: { out: TEXT, n: 3 } } }] }] };
  const r = m.mask("gemini", g, { engine: buildEngine({}), policy: {}, policyId: "p" });
  assert.equal(r.changed, true);
  assert.match(g.contents[0].parts[0].functionResponse.response.out, TAG);
  assert.equal(g.contents[0].parts[0].functionResponse.response.n, 3);
});
