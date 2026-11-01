// F15 token usage (cli/token-usage.mjs, model-proxy/token-usage.mjs): the token counts each provider returns,
// normalised to { in, out, cacheRead, cacheWrite }, rolled into CUMULATIVE hourly buckets per
// (hour, agentName, provider, model, projectKey) and posted to POST /api/token-usage. Metadata only.
//
//   node --test test/token-usage.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeUsage, hourStart, packBodies, createBuckets, MAX_BUCKETS, MAX_BODY_BYTES, INSTANCE_RE } from "../cli/token-usage.mjs";
import { createUsageMeter } from "../model-proxy/token-usage.mjs";

test("NORMALISE: each provider's documented usage fields; cached input is not counted twice", () => {
  assert.deepEqual(normalizeUsage("anthropic", { input_tokens: 100, output_tokens: 20, cache_read_input_tokens: 900, cache_creation_input_tokens: 50 }), { in: 100, out: 20, cacheRead: 900, cacheWrite: 50 });
  assert.deepEqual(normalizeUsage("openai", { prompt_tokens: 1000, completion_tokens: 30, prompt_tokens_details: { cached_tokens: 600 } }), { in: 400, out: 30, cacheRead: 600, cacheWrite: 0 });
  assert.deepEqual(normalizeUsage("google", { promptTokenCount: 500, candidatesTokenCount: 40, cachedContentTokenCount: 100, thoughtsTokenCount: 10 }), { in: 400, out: 50, cacheRead: 100, cacheWrite: 0 });
  assert.deepEqual(normalizeUsage("ollama", { prompt_eval_count: 169, eval_count: 15 }), { in: 169, out: 15, cacheRead: 0, cacheWrite: 0 });
  assert.equal(normalizeUsage("openai", null), null);
  assert.equal(normalizeUsage("anthropic", { foo: 1 }), null, "no known field: no usage");
  assert.deepEqual(normalizeUsage("anthropic", { input_tokens: -5, output_tokens: 1.5e300 }), { in: 0, out: 0, cacheRead: 0, cacheWrite: 0 }, "bad numbers are zero");
});

test("HOUR: UTC hour start, no milliseconds", () => {
  assert.equal(hourStart(Date.parse("2026-10-21T10:59:59.999Z")), "2026-10-21T10:00:00Z");
});

test("BUCKETS: cumulative per key; dirty until marked sent", () => {
  const b = createBuckets();
  const k = { hour: "2026-10-21T10:00:00Z", agentName: "claude-code", provider: "anthropic", model: "claude-opus-5-5", projectKey: null };
  b.add(k, { in: 1, out: 2, cacheRead: 3, cacheWrite: 4 });
  b.add(k, null);
  const [one] = b.dirty();
  assert.deepEqual(one, { ...k, requests: 2, requestsNoUsage: 1, in: 1, out: 2, cacheRead: 3, cacheWrite: 4 });
  b.markSent([one]);
  assert.equal(b.dirty().length, 0);
  b.add(k, { in: 10, out: 0, cacheRead: 0, cacheWrite: 0 });
  assert.deepEqual(b.dirty()[0].in, 11, "the next post carries the running total, so a MAX upsert never double-counts");
});

test("PACK: at most 500 buckets and 64 KiB per body", () => {
  const header = { v: 1, user: "u", device: "d", platform: "darwin", source: "transcript", instance: "tr-0123abcd" };
  const buckets = Array.from({ length: 1200 }, (_, i) => ({ hour: hourStart(Date.UTC(2026, 9, 1) + i * 3600_000), agentName: "claude-code", provider: "anthropic", model: "claude-opus-5-5", projectKey: `h2:${"a".repeat(64)}`, requests: 1, requestsNoUsage: 0, in: 1, out: 1, cacheRead: 1, cacheWrite: 1 }));
  const bodies = packBodies(header, buckets);
  assert.ok(bodies.length >= 3);
  assert.equal(bodies.reduce((n, x) => n + x.buckets.length, 0), 1200);
  for (const x of bodies) { assert.ok(x.buckets.length <= MAX_BUCKETS); assert.ok(Buffer.byteLength(JSON.stringify(x)) <= MAX_BODY_BYTES); assert.equal(x.instance, "tr-0123abcd"); }
});

function fakeFetch(statuses) {
  const calls = [];
  const f = async (url, init) => { calls.push({ url, headers: init.headers, body: JSON.parse(init.body) }); const s = statuses.length > 1 ? statuses.shift() : statuses[0]; return { ok: s >= 200 && s < 300, status: s }; };
  f.calls = calls;
  return f;
}
const CFG = { serverUrl: "http://console.test", installToken: "tok-1" };
const ID = { user: "alice", device: "mac-1", platform: "darwin" };

test("METER: Anthropic stream usage (message_start, then cumulative message_delta) and a stream without usage", async () => {
  let now = Date.parse("2026-10-21T10:15:00Z");
  const fetch = fakeFetch([201]);
  const m = createUsageMeter({ config: CFG, identity: ID, enrolled: true, fetch, now: () => now, flushMs: 0 });
  const c = m.begin({ provider: "anthropic", model: "claude-opus-5-5", agentName: "claude-code" });
  c.event({ data: JSON.stringify({ type: "message_start", message: { usage: { input_tokens: 2679, cache_read_input_tokens: 5, cache_creation_input_tokens: 0, output_tokens: 3 } } }) });
  c.event({ data: JSON.stringify({ type: "content_block_delta", delta: { text: "secret words" } }) });
  c.event({ data: JSON.stringify({ type: "message_delta", usage: { input_tokens: 10682, output_tokens: 510 } }) });
  c.end(); c.end();
  const o = m.begin({ provider: "openai", model: "gpt-x", agentName: "model-proxy" });
  o.event({ data: JSON.stringify({ choices: [{ delta: { content: "hi" } }] }) });
  o.event({ data: "[DONE]" });
  o.end();
  now += 60_000;
  await m.flush();
  assert.equal(fetch.calls.length, 1);
  const { url, headers, body } = fetch.calls[0];
  assert.equal(url, "http://console.test/api/token-usage");
  assert.equal(headers["X-Install-Token"], "tok-1");
  assert.equal(body.v, 1); assert.equal(body.source, "model-proxy"); assert.match(body.instance, /^mp-[0-9a-f]{8}$/); assert.match(body.instance, INSTANCE_RE);
  assert.equal(body.user, "alice"); assert.equal(body.device, "mac-1"); assert.equal(body.platform, "darwin");
  const a = body.buckets.find((x) => x.provider === "anthropic");
  assert.deepEqual(a, { hour: "2026-10-21T10:00:00Z", agentName: "claude-code", provider: "anthropic", model: "claude-opus-5-5", projectKey: null, requests: 1, requestsNoUsage: 0, in: 10682, out: 510, cacheRead: 5, cacheWrite: 0 });
  const op = body.buckets.find((x) => x.provider === "openai");
  assert.equal(op.requests, 1); assert.equal(op.requestsNoUsage, 1); assert.equal(op.in, 0);
  assert.ok(!JSON.stringify(body).includes("secret words"));
});

test("METER: JSON bodies for each provider, a Gemini array stream, an Ollama final line, an unknown model is \"other\"", async () => {
  const fetch = fakeFetch([201]);
  const m = createUsageMeter({ config: CFG, identity: ID, enrolled: true, fetch, now: () => Date.parse("2026-10-21T11:00:00Z"), flushMs: 0 });
  const one = (provider, model, f) => { const c = m.begin({ provider, model, agentName: "model-proxy" }); f(c); c.end(); };
  one("anthropic", "claude-fake", (c) => c.body({ usage: { input_tokens: 10, output_tokens: 20 } }));
  one("openai", "gpt-fake", (c) => c.body({ usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 } }));
  one("google", "gemini-fake", (c) => c.body([{ candidates: [] }, { usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 20 } }]));
  one("ollama", "llama-fake:1b", (c) => { c.event({ data: JSON.stringify({ message: { content: "x" }, done: false }) }); c.event({ data: JSON.stringify({ done: true, prompt_eval_count: 169, eval_count: 15 }) }); });
  one("openai", "bad model name with spaces", (c) => c.body({ usage: { prompt_tokens: 1, completion_tokens: 1 } }));
  await m.flush();
  const bs = fetch.calls[0].body.buckets;
  const by = (p, mdl) => bs.find((x) => x.provider === p && x.model === mdl);
  assert.equal(by("anthropic", "claude-fake").out, 20);
  assert.equal(by("openai", "gpt-fake").in, 10);
  assert.equal(by("google", "gemini-fake").out, 20);
  assert.deepEqual([by("ollama", "llama-fake:1b").in, by("ollama", "llama-fake:1b").out], [169, 15]);
  assert.equal(by("openai", "other").requests, 1);
});

test("METER: a failed post is resent with the running total; a 404 (an older console) pauses posting for a day", async () => {
  let now = Date.parse("2026-10-21T10:00:00Z");
  const fetch = fakeFetch([503, 201]);
  const m = createUsageMeter({ config: CFG, identity: ID, enrolled: true, fetch, now: () => now, flushMs: 0 });
  const add = () => { const c = m.begin({ provider: "anthropic", model: "claude-fake", agentName: "model-proxy" }); c.body({ usage: { input_tokens: 5, output_tokens: 1 } }); c.end(); };
  add(); await m.flush();
  add(); await m.flush();
  assert.equal(fetch.calls.length, 2);
  assert.equal(fetch.calls[1].body.buckets[0].in, 10, "the resend carries both requests");
  await m.flush();
  assert.equal(fetch.calls.length, 2, "nothing new, nothing sent");

  const f404 = fakeFetch([404]);
  const m2 = createUsageMeter({ config: CFG, identity: ID, enrolled: true, fetch: f404, now: () => now, flushMs: 0 });
  const c = m2.begin({ provider: "anthropic", model: "claude-fake", agentName: "model-proxy" }); c.body({ usage: { input_tokens: 1, output_tokens: 1 } }); c.end();
  await m2.flush(); await m2.flush();
  assert.equal(f404.calls.length, 1, "no retry while paused");
  now += 25 * 3600_000;
  const c2 = m2.begin({ provider: "anthropic", model: "claude-fake", agentName: "model-proxy" }); c2.body({ usage: { input_tokens: 1, output_tokens: 1 } }); c2.end();
  await m2.flush();
  assert.equal(f404.calls.length, 2, "tried again after a day");
});

test("METER: an unenrolled proxy never posts", async () => {
  const fetch = fakeFetch([201]);
  const m = createUsageMeter({ config: { serverUrl: "http://console.test" }, identity: ID, enrolled: false, fetch, flushMs: 0 });
  const c = m.begin({ provider: "anthropic", model: "claude-fake", agentName: "model-proxy" }); c.body({ usage: { input_tokens: 1, output_tokens: 1 } }); c.end();
  await m.flush(); await m.close();
  assert.equal(fetch.calls.length, 0);
});
