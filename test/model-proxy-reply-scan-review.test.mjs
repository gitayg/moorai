// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-reply-scan-review.test.mjs
//
// Response text scanning in the model proxy, the v1.33.0 security review's findings (model-proxy/server.mjs,
// response-scan.mjs, text-guard.mjs, text-codecs.mjs):
//   M3  a payment card or personal data (#90, #15) is low-entropy: its alert's contentHash is keyed with a
//       random per-process key, so the install-token key cannot enumerate it back to the value.
//   M4  mask / block also remove the token log-probabilities (`logprobs`, `top_logprobs`, `logprobsResult`)
//       that repeat the reply text token by token.
//   L3  mask / block past MAX_CHANNELS text channels fail closed (no shared overflow channel mixing text).
//   L4  report mode keeps a fixed 256-character tail: a match with a space in it across a batch boundary.
//   L8  re-serializing a masked event or body keeps every number's source text (an integer past 2^53 in a
//       function call's arguments beside the text is not rounded).
// In process, fake upstream, no real provider and no real key.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createProxy } from "../model-proxy/server.mjs";
import { startFakeProvider, sendJson, sendSse } from "../model-proxy/test/fake-provider.mjs";
import { sendNdjson, MODEL } from "../model-proxy/test/fake-ollama.mjs";
import { request } from "../model-proxy/test/harness.mjs";
import { createFakeIntentLib } from "../model-proxy/test/fake-intent.mjs";
import { createScanner, responseDetectors, MAX_CHANNELS, BATCH, TAIL } from "../model-proxy/response-scan.mjs";
import { createTextGuard } from "../model-proxy/text-guard.mjs";
import * as codecs from "../model-proxy/text-codecs.mjs";
import { buildEngine } from "../cli/hook-core.mjs";

const SECRET = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const CARD = "4111 1111 1111 1111";
const PHONE = "+1 415 555 0132";
const EMAIL = "jane.doe@example.com";
const BIG = "12345678901234567890";
const reply = (x) => `Here is what you asked for: ${x}. Let me know if you need anything else.`;
const pieces = (text, step = 7) => { const out = []; for (let i = 0; i < text.length; i += step) out.push(text.slice(i, i + step)); return out; };
const sse = (type, d) => `${type ? `event: ${type}\n` : ""}data: ${JSON.stringify(d)}\n\n`;
const lp = (t) => ({ token: t, logprob: -0.01, bytes: [...Buffer.from(t)], top_logprobs: [{ token: t, logprob: -0.01, bytes: [...Buffer.from(t)] }] });
// No 7-character run of the secret anywhere in what the client received.
const leaked = (raw, x = SECRET) => pieces(x).filter((p) => p.length === 7).some((p) => raw.includes(p));

let fp;
const proxies = {};
async function start(name, mode, policy, extra = {}) {
  const px = await createProxy({ port: 0, mode, policy, routes: { "/anthropic": fp.url, "/openai": `${fp.url}/v1`, "/gemini": fp.url, "/ollama": fp.url }, systemConfig: null, env: {}, intentLib: createFakeIntentLib(), ...extra });
  const alerts = [];
  const post = px.runtime.reporter.post;
  px.runtime.reporter.post = (a, o) => { alerts.push(a); return post(a, o); };
  proxies[name] = { px, alerts };
}
before(async () => {
  fp = await startFakeProvider();
  // Enrolled (an install token), so the runtime's hash is the tenant-keyed one an attacker holding the token
  // could enumerate with; the console address is never reached (fetch is a stub).
  const enrolled = { console: { serverUrl: "http://127.0.0.1:9", tenant: "acme", installToken: "tok-review-0123456789" }, fetch: async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }) };
  await start("report", "report", {}, enrolled);
  await start("report2", "report", {}, enrolled);
  await start("mask", "enforce", { responseScan: "mask" });
  await start("block", "enforce", { responseScan: "block" });
});
after(async () => { for (const p of Object.values(proxies)) await p.px.close(); await fp?.close(); });

async function call(name, path, body, upstream) {
  const p = proxies[name];
  fp.on((r, res) => upstream(res));
  const n = p.alerts.length;
  const r = await request(p.px.url, path, { body, headers: path.startsWith("/anthropic") ? { "anthropic-version": "2023-06-01" } : {} });
  await new Promise((res) => setTimeout(res, 60));
  return { ...r, text: r.raw.toString("utf8"), alerts: p.alerts.slice(n).filter((a) => a.responseScan) };
}
const CHAT = (stream) => ({ model: "gpt-fake", ...(stream ? { stream: true, logprobs: true, top_logprobs: 1 } : { logprobs: true, top_logprobs: 1 }), messages: [{ role: "user", content: "Hi" }] });

// ---- M3 ----

test("M3: a card number's and personal data's contentHash is not the install-token-keyed hash of the value (nor of its digits)", async () => {
  const text = `Card ${CARD} phone ${PHONE} mail ${EMAIL} and ${SECRET}.`;
  const body = { id: "c1", object: "chat.completion", created: 1, model: "gpt-fake", choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }] };
  const a = await call("report", "/openai/chat/completions", CHAT(false), (res) => sendJson(res, body));
  const rt = proxies.report.px.runtime;
  const forms = (x) => [x, `${x} `, x.replace(/\D/g, ""), x.toLowerCase(), `${x}.`];
  const card = a.alerts.filter((x) => x.threatId === 90), personal = a.alerts.filter((x) => x.threatId === 15);
  assert.equal(card.length, 1, JSON.stringify(a.alerts.map((x) => x.threatId)));
  assert.equal(personal.length, 2);
  for (const al of [...card, ...personal]) for (const v of [CARD, PHONE, EMAIL]) for (const f of forms(v)) assert.notEqual(al.contentHash, rt.hash(f), `#${al.threatId}: reversible with the install-token key`);
  // A secret (high entropy) keeps the tenant-keyed hash, so the console still correlates it across devices.
  assert.equal(a.alerts.find((x) => x.threatId === 39).contentHash, rt.hash(SECRET));
  // Correlation within one process only: the same card again in this proxy has the same hash; another proxy differs.
  const again = await call("report", "/openai/chat/completions", CHAT(false), (res) => sendJson(res, body));
  assert.equal(again.alerts.find((x) => x.threatId === 90).contentHash, card[0].contentHash);
  const other = await call("report2", "/openai/chat/completions", CHAT(false), (res) => sendJson(res, body));
  assert.notEqual(other.alerts.find((x) => x.threatId === 90).contentHash, card[0].contentHash);
});

// ---- M4 ----

const LOGPROB_CASES = {
  "openai chat, non-streaming": { path: "/openai/chat/completions", body: CHAT(false), up: (text) => (res) => sendJson(res, { id: "c1", object: "chat.completion", created: 1, model: "gpt-fake", choices: [{ index: 0, message: { role: "assistant", content: text }, logprobs: { content: pieces(text).map(lp), refusal: null }, finish_reason: "stop" }] }) },
  "openai chat, streaming": { path: "/openai/chat/completions", body: CHAT(true), up: (text) => (res) => sendSse(res, [...pieces(text).map((p) => sse(null, { id: "c1", object: "chat.completion.chunk", created: 1, model: "gpt-fake", choices: [{ index: 0, delta: { content: p }, logprobs: { content: [lp(p)], refusal: null }, finish_reason: null }] })), sse(null, { id: "c1", object: "chat.completion.chunk", created: 1, model: "gpt-fake", choices: [{ index: 0, delta: {}, logprobs: null, finish_reason: "stop" }] }), "data: [DONE]\n\n"]) },
  "responses, streaming": { path: "/openai/responses", body: { model: "gpt-fake", stream: true, input: "Hi", include: ["message.output_text.logprobs"] }, up: (text) => (res) => {
    let n = 0;
    const e = (d) => sse(d.type, { ...d, sequence_number: n++ });
    const part = (t) => ({ type: "output_text", text: t, annotations: [], logprobs: pieces(t).map(lp) });
    const msg = (t) => ({ type: "message", id: "msg_t", status: "completed", role: "assistant", content: [part(t)] });
    sendSse(res, [e({ type: "response.created", response: { id: "r", object: "response", status: "in_progress", output: [] } }),
      ...pieces(text).map((p) => e({ type: "response.output_text.delta", item_id: "msg_t", output_index: 0, content_index: 0, delta: p, logprobs: [lp(p)] })),
      e({ type: "response.output_text.done", item_id: "msg_t", output_index: 0, content_index: 0, text, logprobs: pieces(text).map(lp) }),
      e({ type: "response.output_item.done", output_index: 0, item: msg(text) }),
      e({ type: "response.completed", response: { id: "r", object: "response", status: "completed", output: [msg(text)] } })]);
  } },
  "responses, non-streaming": { path: "/openai/responses", body: { model: "gpt-fake", input: "Hi" }, up: (text) => (res) => sendJson(res, { id: "r", object: "response", status: "completed", model: "gpt-fake", output: [{ type: "message", id: "m", status: "completed", role: "assistant", content: [{ type: "output_text", text, annotations: [], logprobs: pieces(text).map(lp) }] }] }) },
  "gemini, non-streaming": { path: "/gemini/v1beta/models/gemini-fake:generateContent", body: { contents: [{ role: "user", parts: [{ text: "Hi" }] }], generationConfig: { responseLogprobs: true, logprobs: 1 } }, up: (text) => (res) => sendJson(res, { candidates: [{ content: { role: "model", parts: [{ text }] }, finishReason: "STOP", index: 0, avgLogprobs: -0.1, logprobsResult: { chosenCandidates: pieces(text).map((t) => ({ token: t, logProbability: -0.01 })), topCandidates: pieces(text).map((t) => ({ candidates: [{ token: t, logProbability: -0.01 }] })) } }], modelVersion: "gemini-fake-001" }) },
  "gemini, streaming": { path: "/gemini/v1beta/models/gemini-fake:streamGenerateContent?alt=sse", body: { contents: [{ role: "user", parts: [{ text: "Hi" }] }], generationConfig: { responseLogprobs: true } }, up: (text) => (res) => sendSse(res, [...pieces(text).map((p) => `data: ${JSON.stringify({ candidates: [{ content: { role: "model", parts: [{ text: p }] }, index: 0, logprobsResult: { chosenCandidates: [{ token: p, logProbability: -0.01 }], topCandidates: [{ candidates: [{ token: p, logProbability: -0.01 }] }] } }], modelVersion: "gemini-fake-001" })}\r\n\r\n`), `data: ${JSON.stringify({ candidates: [{ content: { role: "model", parts: [{ text: "" }] }, index: 0, finishReason: "STOP" }] })}\r\n\r\n`]) },
  "ollama chat, streaming": { path: "/ollama/api/chat", body: { model: MODEL, stream: true, logprobs: true, messages: [{ role: "user", content: "Hi" }] }, up: (text) => (res) => sendNdjson(res, [...pieces(text).map((p) => `${JSON.stringify({ model: MODEL, created_at: "t", message: { role: "assistant", content: p }, logprobs: [{ token: p, logprob: -0.01, top_logprobs: [{ token: p, logprob: -0.01 }] }], done: false })}\n`), `${JSON.stringify({ model: MODEL, created_at: "t", message: { role: "assistant", content: "" }, done: true, done_reason: "stop" })}\n`]) },
  "ollama generate, non-streaming": { path: "/ollama/api/generate", body: { model: MODEL, stream: false, logprobs: true, prompt: "Hi" }, up: (text) => (res) => sendJson(res, { model: MODEL, created_at: "t", response: text, logprobs: pieces(text).map((t) => ({ token: t, logprob: -0.01 })), done: true, done_reason: "stop" }) }
};

for (const [label, c] of Object.entries(LOGPROB_CASES)) {
  test(`M4: ${label} — mask removes the token log-probabilities, so a masked secret does not survive in them`, async () => {
    const r = await call("mask", c.path, c.body, c.up(reply(SECRET)));
    assert.equal(r.status, 200, r.text.slice(0, 200));
    assert.match(r.text, /\[REDACTED:#39\]/);
    assert.ok(!leaked(r.text), `no piece of the secret in the bytes: ${r.text.slice(0, 600)}`);
  });
  if (/streaming/.test(label) && !/non-streaming/.test(label)) {
    test(`M4: ${label} — block: not even the secret's first piece reaches the client through the log-probabilities before the refusal`, async () => {
      const r = await call("block", c.path, c.body, c.up(reply(SECRET)));
      assert.match(r.text, /responseScan block/);
      assert.ok(!r.text.includes(SECRET.slice(0, 7)), `the first piece leaked: ${r.text.slice(0, 600)}`);
    });
  }
}

// ---- L3 ----

const dets = responseDetectors(buildEngine({}));

test("L3: mask / block past MAX_CHANNELS channels fail closed instead of sharing one channel; held text is never dropped", () => {
  const s = createScanner({ dets, policy: {}, hold: true, onFind: () => {} });
  for (let i = 0; i < MAX_CHANNELS; i++) s.push(`c${i}`, `channel ${i} `.repeat(30), false);
  assert.throws(() => s.push("one-too-many", "x", false), /channel/i);
  const out = new Map(s.finish());
  for (let i = 0; i < MAX_CHANNELS; i++) assert.ok((out.get(`c${i}`) || "").endsWith(`channel ${i} `), `channel ${i}'s held text is released at the end`);
  // The guard refuses the event before anything of it is taken: no channel's text is mixed into another's.
  const g = createTextGuard({ codec: codecs.openaiChat, scanner: createScanner({ dets, policy: {}, hold: true, onFind: () => {} }), hold: true });
  const choices = Array.from({ length: MAX_CHANNELS + 1 }, (_, i) => ({ index: i, delta: { content: `choice ${i}` }, finish_reason: null }));
  assert.throws(() => g.event(Buffer.from(`data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", choices })}\n\n`)), /channel/i);
  // Report mode reads only: past the cap it still scans (one shared channel), nothing is held or rewritten.
  const r = createScanner({ dets, policy: {}, hold: false, onFind: () => {} });
  for (let i = 0; i <= MAX_CHANNELS; i++) assert.equal(r.push(`c${i}`, "text", false), "text");
});

test("L3: through the proxy, a masked stream with more than MAX_CHANNELS choices is stopped (closed), never mixed", async () => {
  const many = Array.from({ length: MAX_CHANNELS + 2 }, (_, i) => ({ index: i, delta: { content: `choice-${i}-text ` }, logprobs: null, finish_reason: null }));
  const r = await call("mask", "/openai/chat/completions", { model: "gpt-fake", stream: true, n: MAX_CHANNELS + 2, messages: [{ role: "user", content: "Hi" }] }, (res) => sendSse(res, [sse(null, { id: "c", object: "chat.completion.chunk", created: 1, model: "gpt-fake", choices: many }), "data: [DONE]\n\n"]));
  assert.match(r.text, /could not be scanned; the stream was stopped/);
  assert.ok(!/choice-\d+-text/.test(r.text), "no choice text was released");
});

// ---- L4 ----

test("L4: report mode finds a card with spaces in it across the 4096-character batch boundary", () => {
  // Pushed 7 characters at a time, the first scan runs at 4102 characters; the card starts at 4095, so its first
  // space (4099) is the first whitespace in the last 256 characters before the scan point.
  const head = "word ".repeat(800).slice(0, 3700);
  const text = `${head}${"z".repeat(4094 - head.length)}-${CARD} and then some more words after it.`;
  assert.equal(text.indexOf(CARD), 4095);
  const found = [];
  const s = createScanner({ dets, policy: {}, hold: false, onFind: (f) => found.push(f) });
  for (let i = 0; i < text.length; i += 7) s.push("c", text.slice(i, i + 7), false);
  s.push("c", "", true);
  assert.deepEqual(found.map((f) => f.id), [90], "the card was found");
  // The tail stays bounded.
  assert.ok(BATCH + TAIL > 0);
});

// ---- L8 ----

test("L8: masking a Gemini chunk that also carries a function call keeps an integer past 2^53 in its arguments as sent", async () => {
  const chunk = (parts, extra = {}) => `data: {"candidates":[{"content":{"role":"model","parts":${parts}},"index":0${extra.finish ? ',"finishReason":"STOP"' : ""}}],"modelVersion":"gemini-fake-001"}\r\n\r\n`;
  const text = reply(SECRET);
  const stream = [...pieces(text, 20).map((p) => chunk(`[{"text":${JSON.stringify(p)}}]`)), chunk(`[{"text":"."},{"functionCall":{"name":"lookup_account","args":{"account":${BIG}}}}]`, { finish: true })];
  const r = await call("mask", "/gemini/v1beta/models/gemini-fake:streamGenerateContent?alt=sse", { contents: [{ role: "user", parts: [{ text: "Hi" }] }] }, (res) => sendSse(res, stream));
  assert.equal(r.status, 200);
  assert.match(r.text, /\[REDACTED:#39\]/);
  assert.ok(r.text.includes(`"account":${BIG}`), `the digits as sent: ${r.text.slice(-400)}`);
});

test("L8: masking a non-streaming body keeps an integer past 2^53 (Ollama tool call beside the text)", async () => {
  const raw = `{"model":"${MODEL}","created_at":"t","message":{"role":"assistant","content":${JSON.stringify(reply(SECRET))},"tool_calls":[{"function":{"name":"lookup_account","arguments":{"account":${BIG}}}}]},"done":true,"done_reason":"stop"}`;
  const r = await call("mask", "/ollama/api/chat", { model: MODEL, stream: false, messages: [{ role: "user", content: "Hi" }] }, (res) => sendJson(res, raw));
  assert.equal(r.status, 200, r.text.slice(0, 300));
  assert.match(r.text, /\[REDACTED:#39\]/);
  assert.ok(r.text.includes(`"account":${BIG}`), r.text);
});
