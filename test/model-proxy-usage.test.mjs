// F15 in the real model proxy process: token usage from each provider's response reaches the console as
// content-free cumulative buckets (POST /api/token-usage), and a signed usage budget in state "exceeded"
// with action "block" is answered 429 budget_exceeded in enforce mode, never forwarded, with a
// BUDGET_EXCEEDED alert. A stale or unsigned budget state never blocks.
//
//   node --test test/model-proxy-usage.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { startFakeProvider, sendJson, sendSse, anthropicMessage, anthropicStream, openaiStream } from "../model-proxy/test/fake-provider.mjs";
import { geminiResponse } from "../model-proxy/test/fake-gemini.mjs";
import { chatResponse, MODEL } from "../model-proxy/test/fake-ollama.mjs";
import { sandbox, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";
import { budgetBlock, BUDGET_STALE_MS } from "../model-proxy/budget.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const TENANT = "t-mp-usage";
const key = generateKeyPairSync("ed25519");
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
async function signingConsole(policy) {
  const alerts = [], usage = [];
  const srv = http.createServer((q, r) => {
    let b = "";
    q.on("data", (d) => (b += d));
    q.on("end", () => {
      if (q.url === "/api/alerts") { alerts.push(JSON.parse(b)); r.writeHead(201); return r.end("{}"); }
      if (q.url === "/api/token-usage") { usage.push({ token: q.headers["x-install-token"], body: JSON.parse(b), raw: b }); r.writeHead(200); return r.end("{}"); }
      if (q.url.startsWith("/api/policy/pubkey")) { r.writeHead(200, { "Content-Type": "application/json" }); return r.end(JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) })); }
      if (q.url.startsWith("/api/policy")) { r.writeHead(200, { "Content-Type": "application/json" }); return r.end(signed(policy)); }
      r.writeHead(404); r.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, usage, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}
const iso = (ms) => new Date(ms).toISOString();
const budgetPolicy = (asOf, action = "block") => ({
  usageBudgets: [{ id: "eng-monthly", scope: "tenant", match: {}, period: "month", limitUsd: 10, limitTokens: null, warnAt: 0.8, action }],
  budgetState: [{ budgetId: "eng-monthly", state: "exceeded", periodStart: iso(Date.now() - 86400_000), until: iso(Date.now() + 86400_000), asOf: iso(asOf) }]
});

let fp, homes = [];
before(async () => { fp = await startFakeProvider(); });
after(async () => { await fp?.close(); for (const h of homes) rmTree(h); });
async function proxyWith(con, mode = "enforce", n = 1) {
  const h = sandbox(); homes.push(h);
  const routes = ["--route", `/anthropic=${fp.url}`, "--route", `/openai=${fp.url}/v1`, "--route", `/gemini=${fp.url}`, "--route", `/ollama=${fp.url}`];
  return startProxy(h, ["--mode", mode, ...routes], { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: `tok-usage-${n}`, MOORAI_TENANT: TENANT });
}
const ANT = "/anthropic/v1/messages";

test("USAGE: each provider's token counts reach /api/token-usage as cumulative, content-free buckets", async () => {
  const con = await signingConsole({});
  const px = await proxyWith(con);
  try {
    fp.on((r, res) => sendJson(res, anthropicMessage({ text: "PRIVATE-REPLY" })));
    assert.equal((await request(px.listening, ANT, { body: { model: "claude-fake", max_tokens: 8, messages: [{ role: "user", content: "PRIVATE-PROMPT" }] } })).status, 200);
    fp.on((r, res) => sendSse(res, anthropicStream()));
    assert.equal((await request(px.listening, ANT, { body: { model: "claude-fake", max_tokens: 8, stream: true, messages: [{ role: "user", content: "hi" }] }, headers: { "x-claude-code-session-id": "sess-1" } })).status, 200);
    fp.on((r, res) => sendSse(res, openaiStream()));
    assert.equal((await request(px.listening, "/openai/chat/completions", { body: { model: "gpt-fake", stream: true, messages: [{ role: "user", content: "hi" }] } })).status, 200);
    fp.on((r, res) => sendJson(res, geminiResponse({ text: "ok" })));
    assert.equal((await request(px.listening, "/gemini/v1beta/models/gemini-fake:generateContent", { body: { contents: [{ role: "user", parts: [{ text: "hi" }] }] } })).status, 200);
    fp.on((r, res) => sendJson(res, chatResponse({ text: "ok" })));
    assert.equal((await request(px.listening, "/ollama/api/chat", { body: { model: MODEL, stream: false, messages: [{ role: "user", content: "hi" }] } })).status, 200);
  } finally { await px.stop(); }
  try {
    assert.ok(con.usage.length >= 1, "usage posted at close");
    const { token, body, raw } = con.usage[0];
    assert.equal(token, "tok-usage-1");
    assert.equal(body.v, 1); assert.equal(body.source, "model-proxy"); assert.match(body.instance, /^mp-[0-9a-f]{8}$/);
    const by = (p, m, a) => body.buckets.find((b) => b.provider === p && b.model === m && (!a || b.agentName === a));
    assert.deepEqual([by("anthropic", "claude-fake", "model-proxy").in, by("anthropic", "claude-fake", "model-proxy").out], [10, 20]);
    assert.deepEqual([by("anthropic", "claude-fake", "claude-code").in, by("anthropic", "claude-fake", "claude-code").out], [10, 42], "message_delta output_tokens is cumulative");
    const o = by("openai", "gpt-fake");
    assert.deepEqual([o.requests, o.requestsNoUsage], [1, 1], "a stream sent without include_usage has no usage chunk");
    assert.deepEqual([by("google", "gemini-fake").in, by("google", "gemini-fake").out], [10, 20]);
    assert.deepEqual([by("ollama", MODEL).in, by("ollama", MODEL).out], [169, 15]);
    for (const b of body.buckets) { assert.match(b.hour, /^\d{4}-\d\d-\d\dT\d\d:00:00Z$/); assert.equal(b.projectKey, null); }
    for (const leak of ["PRIVATE-PROMPT", "PRIVATE-REPLY", "sess-1", "Let me check"]) assert.ok(!raw.includes(leak), leak);
  } finally { await con.close(); }
});

test("BUDGET: an exceeded, fresh, signed block budget is answered 429 budget_exceeded and never forwarded", async () => {
  const con = await signingConsole(budgetPolicy(Date.now()));
  const px = await proxyWith(con, "enforce", 2);
  const before = fp.requests.length;
  try {
    fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
    const r = await request(px.listening, ANT, { body: { model: "claude-fake", max_tokens: 8, messages: [{ role: "user", content: "hi" }] } });
    assert.equal(r.status, 429);
    assert.equal(r.json.error.type, "budget_exceeded");
    assert.equal(r.json.error.budgetId, "eng-monthly");
    assert.equal(r.headers["x-should-retry"], "false");
    assert.equal(fp.requests.length, before, "not forwarded");
    assert.ok(await waitFor(() => con.alerts.some((a) => a.reasonCode === "BUDGET_EXCEEDED")), "alert posted");
    const a = con.alerts.find((x) => x.reasonCode === "BUDGET_EXCEEDED");
    assert.equal(a.budgetId, "eng-monthly"); assert.equal(a.decision, "deny"); assert.equal(a.riskLevel, "Medium");
  } finally { await px.stop(); await con.close(); }
});

test("BUDGET: a stale budget state, an alert-only budget and report mode never block", async () => {
  for (const [policy, mode] of [[budgetPolicy(Date.now() - 2 * 3600_000), "enforce"], [budgetPolicy(Date.now(), "alert"), "enforce"], [budgetPolicy(Date.now()), "report"]]) {
    const con = await signingConsole(policy);
    const px = await proxyWith(con, mode, 3);
    try {
      fp.on((r, res) => sendJson(res, anthropicMessage({ text: "ok" })));
      const r = await request(px.listening, ANT, { body: { model: "claude-fake", max_tokens: 8, messages: [{ role: "user", content: "hi" }] } });
      assert.equal(r.status, 200, `${mode} ${policy.usageBudgets[0].action} ${policy.budgetState[0].asOf}`);
    } finally { await px.stop(); await con.close(); }
  }
});

test("budgetBlock: only a verified signed policy, only state exceeded, only action block, only fresh and inside its period", () => {
  const now = Date.now();
  const p = budgetPolicy(now);
  assert.deepEqual(budgetBlock(p, { source: "fresh", now }), { budgetId: "eng-monthly", periodStart: p.budgetState[0].periodStart });
  for (const source of ["options", "file", "builtin", "offline-default", ""]) assert.equal(budgetBlock(p, { source, now }), null, source);
  assert.equal(budgetBlock(budgetPolicy(now - BUDGET_STALE_MS - 1000), { source: "cache", now }), null, "stale");
  assert.equal(budgetBlock({ ...p, budgetState: [{ ...p.budgetState[0], state: "warn" }] }, { source: "fresh", now }), null);
  assert.equal(budgetBlock({ ...p, budgetState: [{ ...p.budgetState[0], until: iso(now - 1) }] }, { source: "fresh", now }), null, "period over");
  assert.equal(budgetBlock({ ...p, budgetState: [{ ...p.budgetState[0], asOf: iso(now + 3600_000) }] }, { source: "fresh", now }), null, "asOf in the future");
  assert.equal(budgetBlock({ ...p, usageBudgets: [] }, { source: "fresh", now }), null, "no matching budget");
  assert.equal(budgetBlock(budgetPolicy(now, "alert"), { source: "fresh", now }), null);
  assert.equal(budgetBlock(null, { source: "fresh", now }), null);
  assert.equal(budgetBlock({ usageBudgets: "x", budgetState: {} }, { source: "fresh", now }), null);
});
