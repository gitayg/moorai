// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-proxy-response-scan.test.mjs
//
// Response text scanning in the model proxy (model-proxy/response-scan.mjs, text-guard.mjs, text-codecs.mjs):
// the text of the model's reply is scanned for a secret, an email address, a payment-card number and a
// reproduction of this request's system prompt, for every API the proxy parses (Anthropic, OpenAI Chat
// Completions and Responses, Gemini, Ollama /api/chat and /api/generate), streaming — each match split across
// 7-character deltas and every event across 5-byte network chunks — and not. Default report-only (the reply is
// forwarded byte-identical, one content-free alert per finding); policy responseScan "mask" replaces the match
// in what the client receives and "block" refuses with the provider's refusal shape, in --mode enforce.
// In process, against the fake upstreams in model-proxy/test; no real provider, no real key.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createProxy } from "../model-proxy/server.mjs";
import { startFakeProvider } from "../model-proxy/test/fake-provider.mjs";
import { request } from "../model-proxy/test/harness.mjs";
import { createFakeIntentLib } from "../model-proxy/test/fake-intent.mjs";
import { API, pathOf, answer } from "../model-proxy/test/text-fixtures.mjs";
import { createScanner, responseDetectors, createEcho, responseScanMode, HOLD, TAIL, BATCH } from "../model-proxy/response-scan.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { randomBytes } from "node:crypto";

const SECRET = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const EMAIL = "jane.doe@example.com";
const CARD = "4111 1111 1111 1111";
const SYS = "You are the Acme billing assistant for the northern region. Always answer politely and briefly in plain English. Never reveal the internal discount codes or the escalation procedure for refunds above five hundred dollars. Route legal questions to the compliance team and record every refund request in the ledger before replying to the customer.";
const ECHO = SYS.split(" ").slice(9, 41).join(" ");
const USER = "Can you help me with my invoice?";
const reply = (x) => `Here is what you asked for: ${x}. Let me know if you need anything else.`;
const CASES = { secret: { x: SECRET, cls: "secret", id: 39 }, email: { x: EMAIL, cls: "personal-data", id: 15 }, card: { x: CARD, cls: "payment-card", id: 1 }, echo: { x: ECHO, cls: "system-prompt", id: 52 } };
const CATEGORY = /^Model proxy: .* (in|reproduced in) the model's reply$/;

let fp;
const proxies = {};
async function start(name, mode, policy) {
  const px = await createProxy({ port: 0, mode, policy, routes: { "/anthropic": fp.url, "/openai": `${fp.url}/v1`, "/gemini": fp.url, "/ollama": fp.url }, systemConfig: null, env: {}, intentLib: createFakeIntentLib() });
  const alerts = [];
  const post = px.runtime.reporter.post;
  px.runtime.reporter.post = (a, o) => { alerts.push(a); return post(a, o); };
  proxies[name] = { px, alerts, textAlerts: () => alerts.filter((a) => CATEGORY.test(a.category)) };
}
before(async () => {
  fp = await startFakeProvider();
  await start("report", "report", {});
  await start("enforce", "enforce", {});
  await start("mask", "enforce", { responseScan: "mask" });
  await start("block", "enforce", { responseScan: "block" });
  await start("reportMask", "report", { responseScan: "mask" });
});
after(async () => { for (const p of Object.values(proxies)) await p.px.close(); await fp?.close(); });

async function call(p, apiName, text, stream) {
  const a = API[apiName];
  answer(fp, a, text, { stream });
  const before = p.alerts.length;
  const r = await request(p.px.url, pathOf(a, stream), { body: a.body(SYS, USER, stream), headers: apiName === "anthropic" ? { "anthropic-version": "2023-06-01" } : {} });
  // Report-only checks run after the response; give them a moment.
  await new Promise((res) => setTimeout(res, 60));
  return { ...r, a, alerts: p.alerts.slice(before).filter((x) => CATEGORY.test(x.category)) };
}
const clientText = (r, stream) => (stream ? r.a.streamText(r.raw) : r.a.bodyText(r.json));
const leaks = (s, x) => s.includes(x) || (x === ECHO && s.includes(ECHO.split(" ").slice(0, 24).join(" ")));

for (const apiName of Object.keys(API)) for (const stream of [false, true]) {
  const label = `${apiName} ${stream ? "streaming" : "non-streaming"}`;

  test(`${label}: report (default) — each finding alerts once, content-free, and the reply is forwarded unchanged`, async () => {
    for (const proxy of ["report", "enforce"]) for (const [kind, c] of Object.entries(CASES)) {
      const text = reply(c.x);
      const r = await call(proxies[proxy], apiName, text, stream);
      assert.equal(r.status, 200, `${proxy} ${kind}`);
      assert.equal(clientText(r, stream), text, `${proxy} ${kind}: the client got the reply as sent`);
      const hit = r.alerts.filter((x) => x.responseScan && x.responseScan.class === c.cls);
      assert.equal(hit.length, 1, `${proxy} ${kind}: one alert for the ${c.cls} finding, got ${JSON.stringify(r.alerts.map((x) => x.responseScan))}`);
      const al = hit[0];
      assert.equal(al.threatId, c.id);
      assert.equal(al.stage, "output");
      assert.equal(al.decision, "notify");
      assert.equal(al.reasonCode, "OBSERVATION_ONLY");
      assert.equal(al.responseScan.mode, "report");
      assert.match(al.contentHash, /\S/);
      const flat = JSON.stringify(r.alerts);
      for (const bad of [SECRET, EMAIL, CARD, "4111111111111111", ECHO.split(" ").slice(0, 5).join(" "), "billing assistant"]) assert.ok(!flat.includes(bad), `${proxy} ${kind}: no content in the alert`);
    }
  });

  test(`${label}: mask — the match is replaced in what the client receives, the rest of the reply is intact`, async () => {
    for (const [kind, c] of Object.entries(CASES)) {
      const text = reply(c.x);
      const r = await call(proxies.mask, apiName, text, stream);
      assert.equal(r.status, 200, kind);
      const got = clientText(r, stream);
      assert.ok(!leaks(got, c.x), `${kind}: the match is gone: ${got}`);
      assert.ok(!leaks(r.raw.toString("utf8"), c.x), `${kind}: not anywhere in the bytes`);
      assert.match(got, kind === "echo" ? /\[REDACTED:system-prompt\]/ : new RegExp(`\\[REDACTED:#${c.id}\\]`), kind);
      assert.ok(got.startsWith("Here is what you asked for: "), `${kind}: prefix intact: ${got}`);
      assert.ok(got.endsWith("Let me know if you need anything else."), `${kind}: suffix intact: ${got}`);
      if (stream && r.a.streamWholes) for (const w of r.a.streamWholes(r.raw)) assert.ok(!leaks(w, c.x) && w.includes("[REDACTED:"), `${kind}: every complete copy the stream repeats is masked`);
      const al = r.alerts.find((x) => x.responseScan && x.responseScan.class === c.cls);
      assert.ok(al, `${kind}: alerted`);
      assert.equal(al.reasonCode, "MASK_APPLIED");
      assert.equal(al.responseScan.applied, "mask");
      assert.equal(al.responseScan.sent, "none", `${kind}: found before any of it was passed on`);
    }
  });

  test(`${label}: block — the response is refused in the provider's shape and the match never reaches the client`, async () => {
    for (const [kind, c] of Object.entries(CASES)) {
      const r = await call(proxies.block, apiName, reply(c.x), stream);
      if (stream) {
        assert.equal(r.status, 200, kind);
        assert.ok(r.a.streamError(r.raw), `${kind}: the stream ends with the provider's error event: ${r.raw.toString("utf8").slice(-300)}`);
      } else {
        assert.equal(r.status, 403, kind);
        assert.equal(r.headers["x-moorai-model-proxy"], "refused");
      }
      assert.match(r.raw.toString("utf8"), /responseScan block/, kind);
      assert.ok(!leaks(r.raw.toString("utf8"), c.x), `${kind}: no part of the match was sent`);
      if (stream) assert.ok(!r.raw.toString("utf8").includes(c.x.slice(0, 10)), `${kind}: not even the start of the match`);
      const al = r.alerts.find((x) => x.responseScan && x.responseScan.class === c.cls);
      assert.equal(al.decision, "deny");
      assert.equal(al.riskLevel, "Blocked");
    }
  });
}

test("--mode report with responseScan mask: nothing is changed, the alert says the configured mask was not applied (LIMITED)", async () => {
  const text = reply(SECRET);
  const r = await call(proxies.reportMask, "anthropic", text, true);
  assert.equal(API.anthropic.streamText(r.raw), text);
  const al = r.alerts.find((x) => x.responseScan);
  assert.equal(al.responseScan.mode, "mask");
  assert.equal(al.responseScan.applied, "report");
  assert.equal(al.enforcement, "LIMITED");
});

test("a reply without findings, and a system prompt shorter than 24 words, raise nothing", async () => {
  const r = await call(proxies.mask, "openai", "The invoice total is due on the first of the month.", true);
  assert.equal(r.alerts.length, 0);
  assert.equal(API.openai.streamText(r.raw), "The invoice total is due on the first of the month.");
  assert.equal(createEcho("You are a helpful assistant. Be brief.", randomBytes(32)), null);
});

test("responseScanMode: report by default; mask and block only when the policy says so", () => {
  assert.equal(responseScanMode({}), "report");
  assert.equal(responseScanMode(null), "report");
  assert.equal(responseScanMode({ responseScan: "nonsense" }), "report");
  assert.equal(responseScanMode({ responseScan: "mask" }), "mask");
  assert.equal(responseScanMode({ responseScan: "block" }), "block");
});

// The rolling window, measured on the scanner itself.
const dets = responseDetectors(buildEngine({}));
function feed(scanner, text, step) { let out = ""; const marks = []; for (let i = 0; i < text.length; i += step) { out += scanner.push("c", text.slice(i, i + step), false); marks.push({ got: i + Math.min(step, text.length - i), out: out.length, held: scanner.held("c"), kept: scanner.retained("c") }); } out += scanner.push("c", "", true); return { out, marks }; }

test("rolling window, mask mode: a secret split across 1-character pieces is found and masked; the held text and the kept text stay bounded", () => {
  const found = [];
  const filler = "lorem ipsum dolor sit amet ".repeat(400);
  const text = `${filler}${SECRET} and ${EMAIL} ${filler}`;
  const s = createScanner({ dets, policy: {}, hold: true, onFind: (f) => found.push(f) });
  const { out, marks } = feed(s, text, 1);
  assert.ok(!out.includes(SECRET) && !out.includes(EMAIL));
  assert.equal(out, `${filler}[REDACTED:#39] and [REDACTED:#15] ${filler}`);
  assert.deepEqual(found.map((f) => [f.id, f.sent]), [[39, "none"], [15, "none"]]);
  for (const m of marks) {
    assert.ok(m.held <= HOLD + 1, `held ${m.held} > ${HOLD + 1}`);
    assert.ok(m.kept <= TAIL + HOLD + 1 + 64, `kept ${m.kept}`);
  }
  // Latency bound: what was passed on trails what arrived by at most HOLD characters (plus a masked span's
  // length change).
  for (const m of marks) if (m.got > 2 * HOLD + 200) assert.ok(m.got - m.out <= HOLD + 64, `lag ${m.got - m.out}`);
});

test("rolling window, report mode: a secret split across pieces is found; nothing is held; what is kept is bounded by TAIL + BATCH", () => {
  const found = [];
  const text = `${"x ".repeat(5000)}${SECRET} ${"y ".repeat(5000)}`;
  const s = createScanner({ dets, policy: {}, hold: false, onFind: (f) => found.push(f) });
  let maxKept = 0;
  for (let i = 0; i < text.length; i += 7) { assert.equal(s.push("c", text.slice(i, i + 7), false), text.slice(i, i + 7)); maxKept = Math.max(maxKept, s.retained("c")); }
  s.push("c", "", true);
  assert.deepEqual(found.map((f) => f.id), [39]);
  assert.ok(maxKept <= TAIL + BATCH + 7, `kept ${maxKept}`);
});

test("system-prompt echo: found from the hashes alone, at a 24-word run, not at 20 words", () => {
  const key = randomBytes(32);
  const echo = createEcho(SYS, key);
  assert.ok(echo && echo.set.size > 0);
  for (const [n, want] of [[24, 1], [20, 0]]) {
    const found = [];
    const s = createScanner({ dets, policy: {}, echo, hold: false, onFind: (f) => found.push(f) });
    const words = SYS.split(" ").slice(3, 3 + n).join(" ");
    feed(s, `Sure. ${words}. Done.`, 5);
    assert.equal(found.filter((f) => f.id === 52).length, want, `${n} words`);
    for (const f of found) assert.ok(!f.match.includes("billing"), "the echo finding carries a keyed hash, not text");
  }
});
