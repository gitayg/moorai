// The client's answer to a server's sampling / elicitation request, and the per-session sampling budget, at the
// stdio guard and the HTTP gateway (mcp-proxy/sampling-response.mjs). Before this, a model completion or a user's
// elicitation input went back to the server unchecked, and a server could send any number of sampling requests.
// Made-up values only.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-sampling-response.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { buildEngine } from "../cli/hook-core.mjs";
import { clientAnswersOf, judgeClientAnswers, budgetConfig, createSamplingBudget, BUDGET_DEFAULTS } from "../mcp-proxy/sampling-response.mjs";
import { sign, startConsole, makeHome, startGateway, stopGateway, rpc, call } from "../mcp-gateway/test/harness.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test", "fake-sampling-mcp-server.mjs");

const TOKEN = "ghp_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa";
const CARD = "4111 1111 1111 1111";
const ASK = { messages: [{ role: "user", content: { type: "text", text: "Summarize what you know so far." } }], maxTokens: 400 };
const LEAK = { role: "assistant", content: { type: "text", text: `Sure. The deploy token in the config is ${TOKEN} and it expires Friday.` }, model: "m-1", stopReason: "endTurn" };
const LEAK64 = { role: "assistant", content: [{ type: "text", text: Buffer.from(`notes\nthe token is ${TOKEN}\nend of notes, nothing else here to see\n`).toString("base64") }], model: "m-1", stopReason: "endTurn" };
const CLEAN = { role: "assistant", content: { type: "text", text: "Paris." }, model: "m-1", stopReason: "endTurn" };
const ELICIT_LEAK = { action: "accept", content: { name: "octocat", card: CARD } };
const BASE = { captureTier: "content-free" };
const answerAlerts = (alerts) => alerts.filter((a) => a.stage === "sampling-response");
const budgetAlerts = (alerts) => alerts.filter((a) => a.category === "MCP: sampling budget exceeded");
const contentFree = (alerts) => { const s = JSON.stringify(alerts); return !s.includes(TOKEN) && !s.includes(CARD) && !s.includes("deploy token") && !s.includes("octocat"); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (pred, ms = 8000) => { const end = Date.now() + ms; while (!pred() && Date.now() < end) await sleep(25); return pred(); };

// ---------------------------------------------------------------------------------------------------
// The pure module
// ---------------------------------------------------------------------------------------------------
test("clientAnswersOf: a 2025-11-25 response and a 2026-07-28 retry with inputResponses, nothing else", () => {
  assert.deepEqual(clientAnswersOf({ jsonrpc: "2.0", id: "srv-1", result: LEAK }).answers.map((a) => a.kind), ["sampling"]);
  assert.equal(clientAnswersOf({ jsonrpc: "2.0", id: "srv-1", result: LEAK }).shape, "response");
  assert.deepEqual(clientAnswersOf({ jsonrpc: "2.0", id: 9, result: ELICIT_LEAK }).answers.map((a) => a.kind), ["elicitation"]);
  assert.equal(clientAnswersOf({ jsonrpc: "2.0", id: 9, result: { roots: [{ uri: "file:///x" }] } }), null, "a roots answer");
  assert.equal(clientAnswersOf({ jsonrpc: "2.0", id: 9, result: {} }), null, "a ping answer");
  assert.equal(clientAnswersOf({ jsonrpc: "2.0", id: 9, error: { code: -1, message: "no" } }), null);
  const retry = clientAnswersOf({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "t", arguments: {}, inputResponses: { a: LEAK, b: ELICIT_LEAK, c: { roots: [] }, d: { other: "x" } }, requestState: "s" } });
  assert.equal(retry.shape, "retry");
  assert.deepEqual(retry.answers.map((a) => a.kind), ["sampling", "elicitation", "input"]);
  assert.ok(clientAnswersOf({ jsonrpc: "2.0", id: 3, method: "resources/read", params: { uri: "x://y", inputResponses: { a: LEAK } } }));
  assert.ok(clientAnswersOf({ jsonrpc: "2.0", id: 3, method: "prompts/get", params: { name: "p", inputResponses: { a: LEAK } } }));
  assert.equal(clientAnswersOf({ jsonrpc: "2.0", id: 3, method: "tools/list", params: { inputResponses: { a: LEAK } } }), null, "not a retry method");
  assert.equal(clientAnswersOf({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "t", arguments: { x: TOKEN } } }), null, "arguments are the call gate's");
});

test("judgeClientAnswers: the data-loss set on the answer; report forwards, samplingResponseAction block refuses", () => {
  const e = buildEngine({});
  const r = judgeClientAnswers(e, {}, [{ kind: "sampling", value: LEAK }]);
  assert.ok(r.findings.some((f) => f.threatId === 39), JSON.stringify(r.findings));
  assert.equal(r.refuse, false);
  const b = judgeClientAnswers(e, { samplingResponseAction: "block" }, [{ kind: "sampling", value: LEAK }]);
  assert.equal(b.refuse, true);
  assert.ok(b.reasons.some((x) => x.startsWith("#39 ")), b.reasons.join());
  assert.equal(judgeClientAnswers(e, { samplingResponseAction: "block" }, [{ kind: "sampling", value: CLEAN }]).refuse, false);
  assert.ok(judgeClientAnswers(e, {}, [{ kind: "sampling", value: LEAK64 }]).findings.some((f) => f.threatId === 39), "base64 content is decoded");
  assert.equal(judgeClientAnswers(e, { threatPolicy: { 90: "block" } }, [{ kind: "elicitation", value: ELICIT_LEAK }]).refuse, true, "a threat's own block refuses under report");
  const convo = Array.from({ length: 6 }, (_, i) => `${i % 2 ? "assistant" : "user"}: turn ${i} of the earlier conversation with some words`).join("\n");
  const o = judgeClientAnswers(e, {}, [{ kind: "sampling", value: { role: "assistant", content: { type: "text", text: convo }, model: "m" } }]);
  assert.ok(o.findings.some((f) => f.threatId === 92 && f.oversharing.signals.includes("conversation")), JSON.stringify(o.findings));
});

test("budgetConfig and the per-session window", () => {
  assert.deepEqual(budgetConfig({}), BUDGET_DEFAULTS);
  assert.equal(budgetConfig({ samplingBudget: false }).action, "off");
  assert.deepEqual(budgetConfig({ samplingBudget: { action: "block", maxRequests: 2, maxTokens: -1, windowMin: 0 } }), { ...BUDGET_DEFAULTS, action: "block", maxRequests: 2 });
  const b = createSamplingBudget();
  const cfg = { ...BUDGET_DEFAULTS, maxRequests: 2, maxTokens: 1000 };
  const req = (n) => ({ kind: "sampling", params: { maxTokens: n } });
  assert.deepEqual(b.add("s1", [req(100)], cfg, 0).over, []);
  assert.deepEqual(b.add("s1", [req(100)], cfg, 1).over, []);
  const third = b.add("s1", [req(100)], cfg, 2);
  assert.deepEqual(third.over, ["requests"]);
  assert.deepEqual(third.fresh, ["requests"]);
  assert.deepEqual(b.add("s1", [req(100)], cfg, 3).fresh, [], "reported once per session");
  assert.deepEqual(b.add("s2", [req(5000)], cfg, 3).over, ["tokens"], "another session, its own counts");
  assert.deepEqual(b.add("s1", [req(1)], cfg, 61 * 60_000).over, [], "the window slides");
});

// ---------------------------------------------------------------------------------------------------
// The stdio guard, with a real child server
// ---------------------------------------------------------------------------------------------------
async function guardSession({ policy, params = ASK, env = {}, method, mrtr = false, count = 1 }, fn) {
  const con = await startConsole(policy ? sign(policy) : null);
  const home = makeHome(con.url);
  const pfile = join(home, "params.json");
  writeFileSync(pfile, JSON.stringify(params));
  const log = join(home, "server-recv.log");
  const childEnv = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: con.url, MoorAI_TENANT: "acme", FAKE_SR_PARAMS: pfile, FAKE_SR_COUNT: String(count), ...(method ? { FAKE_SR_METHOD: method } : {}), ...(mrtr ? { FAKE_SR_MRTR: "1" } : {}), ...env };
  delete childEnv.XDG_CONFIG_HOME; delete childEnv.XDG_STATE_HOME;
  const child = spawn(process.execPath, [GUARD, "--server", "samp", "--", process.execPath, FAKE, log], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: childEnv });
  const msgs = [];
  let pending = "";
  child.stdout.on("data", (c) => {
    pending += c.toString();
    let nl;
    while ((nl = pending.indexOf("\n")) >= 0) { const l = pending.slice(0, nl); pending = pending.slice(nl + 1); if (l.trim()) { try { msgs.push(JSON.parse(l)); } catch { /* not JSON */ } } }
  });
  child.stderr.on("data", () => {});
  const recv = () => (existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  const send = (o) => child.stdin.write(JSON.stringify(o) + "\n");
  try {
    await fn({ con, msgs, recv, send });
  } finally {
    try { child.stdin.end(); } catch { /* gone */ }
    try { child.kill(); } catch { /* gone */ }
    await con.close();
    rmTree(home);
  }
}
// The call, the server's request reaching the client, then the client's answer to it.
async function answerLegacy(s, result) {
  s.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "summarize", arguments: {} } });
  assert.ok(await waitFor(() => s.msgs.some((m) => m.id === "srv-1" && m.method)), `no request reached the client: ${JSON.stringify(s.msgs)}`);
  s.send({ jsonrpc: "2.0", id: "srv-1", result });
}
const RETRY = (inputResponses) => ({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "summarize", arguments: {}, inputResponses, requestState: "opaque-state" } });

test("GUARD report (default): a completion carrying a token reaches the server unchanged and is reported, content-free", async () => {
  await guardSession({ policy: BASE }, async (s) => {
    await answerLegacy(s, LEAK);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    assert.deepEqual(s.recv().find((m) => m.id === "srv-1").result, LEAK);
    assert.ok(await waitFor(() => answerAlerts(s.con.alerts).length > 0));
    const a = answerAlerts(s.con.alerts);
    assert.ok(a.some((x) => x.threatId === 39 && x.decision === "notify" && x.tool === "desktop:sampling" && x.mcpServer === "samp" && x.samplingShape === "response"), JSON.stringify(a));
    assert.ok(contentFree(s.con.alerts));
  });
});

test("GUARD samplingResponseAction block: the server gets JSON-RPC error -1 in place of the completion; the client a notice", async () => {
  await guardSession({ policy: { ...BASE, samplingResponseAction: "block" } }, async (s) => {
    await answerLegacy(s, LEAK);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    const ans = s.recv().find((m) => m.id === "srv-1");
    assert.ok(ans.error && ans.error.code === -1 && !ans.result, JSON.stringify(ans));
    assert.ok(!JSON.stringify(s.recv()).includes(TOKEN), "the token reached the server");
    assert.ok(await waitFor(() => s.msgs.some((m) => m.method === "notifications/message" && /did not return a sampling answer/.test(m.params.data))), JSON.stringify(s.msgs));
    assert.ok(await waitFor(() => answerAlerts(s.con.alerts).some((x) => x.riskLevel === "Blocked")));
    assert.ok(answerAlerts(s.con.alerts).some((x) => x.threatId === 39 && x.decision === "deny"));
    assert.ok(contentFree(s.con.alerts));
  });
});

test("GUARD block: a clean completion is forwarded; base64 in a completion and an elicitation's card are refused", async () => {
  await guardSession({ policy: { ...BASE, samplingResponseAction: "block" } }, async (s) => {
    await answerLegacy(s, CLEAN);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    assert.deepEqual(s.recv().find((m) => m.id === "srv-1").result, CLEAN);
  });
  await guardSession({ policy: { ...BASE, samplingResponseAction: "block" } }, async (s) => {
    await answerLegacy(s, LEAK64);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    assert.equal(s.recv().find((m) => m.id === "srv-1").error.code, -1);
  });
  await guardSession({ policy: { ...BASE, threatPolicy: { 90: "block" } }, method: "elicitation/create", params: { mode: "form", message: "Your details", requestedSchema: { type: "object", properties: { name: { type: "string" } } } } }, async (s) => {
    await answerLegacy(s, ELICIT_LEAK);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    assert.equal(s.recv().find((m) => m.id === "srv-1").error.code, -1, "a threat set to block refuses under report");
    assert.ok(await waitFor(() => answerAlerts(s.con.alerts).some((x) => x.samplingKind === "elicitation" && x.threatId === 90 && x.riskLevel === "Blocked")), JSON.stringify(s.con.alerts));
    assert.ok(contentFree(s.con.alerts));
  });
});

test("GUARD 2026-07-28 retry: inputResponses carrying a token is refused as an isError result and never sent; report sends it", async () => {
  await guardSession({ policy: { ...BASE, samplingResponseAction: "block" }, mrtr: true }, async (s) => {
    s.send(RETRY({ ask: LEAK }));
    assert.ok(await waitFor(() => s.msgs.some((m) => m.id === 2)));
    const reply = s.msgs.find((m) => m.id === 2);
    assert.equal(reply.result.isError, true, JSON.stringify(reply));
    assert.match(reply.result.content[0].text, /sampling answer it carries was refused: #39 /);
    await sleep(300);
    assert.equal(s.recv().length, 0, "the server received the retried call");
    assert.ok(answerAlerts(s.con.alerts).some((x) => x.tool === "desktop:summarize" && x.samplingShape === "retry" && x.riskLevel === "Blocked"));
  });
  await guardSession({ policy: BASE, mrtr: true }, async (s) => {
    s.send(RETRY({ ask: LEAK }));
    assert.ok(await waitFor(() => s.msgs.some((m) => m.id === 2)));
    assert.equal(s.msgs.find((m) => m.id === 2).result.content[0].text, "retried");
    assert.deepEqual(s.recv()[0].params.inputResponses.ask, LEAK);
  });
});

test("GUARD fail mode: an answer whose scan throws is forwarded when open and refused when closed", async () => {
  const env = { MOORAI_TEST_SAMPLINGRESPONSE_THROW: "1" };
  await guardSession({ policy: BASE, env }, async (s) => {
    await answerLegacy(s, CLEAN);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    assert.deepEqual(s.recv().find((m) => m.id === "srv-1").result, CLEAN);
  });
  await guardSession({ policy: { ...BASE, failMode: { mcpGateway: "closed" } }, env }, async (s) => {
    await answerLegacy(s, CLEAN);
    assert.ok(await waitFor(() => s.recv().some((m) => m.id === "srv-1")));
    assert.equal(s.recv().find((m) => m.id === "srv-1").error.code, -1);
    assert.ok(await waitFor(() => s.con.alerts.some((a) => a.stage === "sampling-response" && a.failMode === "closed")), JSON.stringify(s.con.alerts));
  });
});

test("GUARD samplingBudget: report forwards every request with one alert; block refuses the ones past the limit", async () => {
  await guardSession({ policy: { ...BASE, samplingBudget: { maxRequests: 2 } }, count: 4 }, async (s) => {
    s.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "summarize", arguments: {} } });
    assert.ok(await waitFor(() => s.msgs.some((m) => m.id === 1)));
    assert.equal(s.msgs.filter((m) => m.method === "sampling/createMessage").length, 4);
    assert.ok(await waitFor(() => budgetAlerts(s.con.alerts).length > 0));
    await sleep(300);
    const b = budgetAlerts(s.con.alerts);
    assert.equal(b.length, 1, JSON.stringify(b));
    assert.ok(b[0].decision === "notify" && b[0].budgetKind === "requests" && b[0].samplingRequests === 3 && b[0].budgetLimit === 2 && b[0].stage === "sampling" && b[0].threatId === 97 && b[0].riskLevel === "Low", JSON.stringify(b[0]));
  });
  await guardSession({ policy: { ...BASE, samplingBudget: { action: "block", maxRequests: 0, maxTokens: 1000 } }, count: 4 }, async (s) => {
    s.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "summarize", arguments: {} } });
    assert.ok(await waitFor(() => s.msgs.some((m) => m.id === 1)));
    assert.deepEqual(s.msgs.filter((m) => m.method === "sampling/createMessage").map((m) => m.id), ["srv-1", "srv-2"], "400 + 400 tokens fit, the third does not");
    assert.ok(await waitFor(() => s.recv().filter((m) => m.error).length === 2));
    assert.deepEqual(s.recv().filter((m) => m.error && m.error.code === -1).map((m) => m.id), ["srv-3", "srv-4"]);
    assert.ok(budgetAlerts(s.con.alerts).every((a) => a.budgetKind === "tokens" && a.decision === "deny"));
  });
});

// ---------------------------------------------------------------------------------------------------
// The HTTP gateway, with a real upstream speaking Streamable HTTP
// ---------------------------------------------------------------------------------------------------
async function startUpstream({ params = ASK, mrtr = false, count = 1 }) {
  const received = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      let m = null;
      try { m = JSON.parse(body); } catch { /* none */ }
      received.push({ headers: req.headers, json: m });
      if (!m || m.id == null || m.method == null) { res.writeHead(202); res.end(); return; }
      const json = (o) => { const out = JSON.stringify(o); res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(out) }); res.end(out); };
      if (m.method !== "tools/call") return json({ jsonrpc: "2.0", id: m.id, result: {} });
      if (m.params.inputResponses) return json({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "retried" }], isError: false } });
      if (mrtr) return json({ jsonrpc: "2.0", id: m.id, result: { resultType: "input_required", inputRequests: { ask: { method: "sampling/createMessage", params } }, requestState: "opaque" } });
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      let out = "";
      for (let i = 1; i <= count; i++) out += `id: e${i}\nevent: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: `srv-${i}`, method: "sampling/createMessage", params })}\n\n`;
      out += `id: done\nevent: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "done" }], isError: false } })}\n\n`;
      res.end(out);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, received, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
async function gatewayScenario({ policy, mrtr = false, count = 1 }, fn) {
  const con = await startConsole(sign(policy));
  const home = makeHome(con.url);
  const up = await startUpstream({ mrtr, count });
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`] });
  try {
    if (!gw.url) throw new Error(`gateway did not start: ${gw.stderr}`);
    await fn({ con, up, base: `${gw.url}/remote` });
  } finally {
    await stopGateway(gw); await up.close(); await con.close(); rmTree(home);
  }
}
const sseMessages = (text) => text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6)));
const upAnswer = (up, id) => up.received.find((x) => x.json && x.json.id === id && x.json.method == null);

test("GATEWAY report: a completion carrying a token is POSTed upstream unchanged and reported", async () => {
  await gatewayScenario({ policy: BASE }, async ({ con, up, base }) => {
    const r = await rpc(base, { jsonrpc: "2.0", id: "srv-1", result: LEAK }, { "Mcp-Session-Id": "sess-1" });
    assert.equal(r.status, 202);
    assert.deepEqual(upAnswer(up, "srv-1").json.result, LEAK);
    assert.ok(await waitFor(() => answerAlerts(con.alerts).length > 0));
    assert.ok(answerAlerts(con.alerts).some((a) => a.threatId === 39 && a.decision === "notify" && a.tool === "gateway:sampling" && a.mcpServer === "remote"), JSON.stringify(con.alerts));
    assert.ok(contentFree(con.alerts));
  });
});

test("GATEWAY samplingResponseAction block: the upstream gets JSON-RPC error -1 in place of the completion, on the client's session", async () => {
  await gatewayScenario({ policy: { ...BASE, samplingResponseAction: "block" } }, async ({ con, up, base }) => {
    const r = await rpc(base, { jsonrpc: "2.0", id: "srv-1", result: LEAK }, { "Mcp-Session-Id": "sess-1" });
    assert.equal(r.status, 202);
    const ans = upAnswer(up, "srv-1");
    assert.ok(ans && ans.json.error && ans.json.error.code === -1 && !ans.json.result, JSON.stringify(up.received.map((x) => x.json)));
    assert.equal(ans.headers["mcp-session-id"], "sess-1");
    assert.ok(!JSON.stringify(up.received.map((x) => x.json)).includes(TOKEN));
    assert.ok(await waitFor(() => answerAlerts(con.alerts).some((a) => a.riskLevel === "Blocked" && a.threatId === 39)));
    assert.ok(contentFree(con.alerts));
    const clean = await rpc(base, { jsonrpc: "2.0", id: "srv-2", result: CLEAN }, { "Mcp-Session-Id": "sess-1" });
    assert.equal(clean.status, 202);
    assert.deepEqual(upAnswer(up, "srv-2").json.result, CLEAN);
  });
});

test("GATEWAY 2026-07-28 retry: inputResponses carrying a token is refused to the client and never sent upstream; report sends it", async () => {
  await gatewayScenario({ policy: { ...BASE, samplingResponseAction: "block" } }, async ({ con, up, base }) => {
    const r = await rpc(base, RETRY({ ask: LEAK }));
    assert.equal(r.json.id, 2);
    assert.equal(r.json.result.isError, true, r.text);
    assert.match(r.json.result.content[0].text, /sampling answer it carries was refused: #39 /);
    assert.ok(!up.received.some((x) => x.json && x.json.id === 2), "the upstream received the retried call");
    assert.ok(await waitFor(() => answerAlerts(con.alerts).some((a) => a.tool === "gateway:summarize" && a.samplingShape === "retry" && a.riskLevel === "Blocked")));
  });
  await gatewayScenario({ policy: BASE }, async ({ up, base }) => {
    const r = await rpc(base, RETRY({ ask: LEAK }));
    assert.equal(r.json.result.content[0].text, "retried", r.text);
    assert.deepEqual(up.received.find((x) => x.json && x.json.id === 2).json.params.inputResponses.ask, LEAK);
  });
});

test("GATEWAY samplingBudget block: a sampling request past the limit is replaced by a notice and the upstream gets error -1", async () => {
  await gatewayScenario({ policy: { ...BASE, samplingBudget: { action: "block", maxRequests: 2 } }, count: 3 }, async ({ con, up, base }) => {
    const r = await rpc(base, call(1, "summarize"), { "Mcp-Session-Id": "sess-1" });
    const msgs = sseMessages(r.text);
    assert.deepEqual(msgs.filter((m) => m.method === "sampling/createMessage").map((m) => m.id), ["srv-1", "srv-2"], r.text);
    assert.ok(msgs.some((m) => m.method === "notifications/message" && /sampling budget is used up/.test(m.params.data)), r.text);
    assert.ok(await waitFor(() => !!upAnswer(up, "srv-3")));
    assert.equal(upAnswer(up, "srv-3").json.error.code, -1);
    assert.ok(await waitFor(() => budgetAlerts(con.alerts).some((a) => a.decision === "deny" && a.tool === "gateway:sampling" && a.samplingRequests === 3)), JSON.stringify(con.alerts));
    const other = await rpc(base, call(2, "summarize"), { "Mcp-Session-Id": "sess-2" });
    assert.equal(sseMessages(other.text).filter((m) => m.method === "sampling/createMessage").length, 2, "another session has its own budget");
  });
});
