// F22 — the on-device escalation verdict cache and the model-presence check.
//
// The escalation worker is a fresh detached process per tool call (cli/moorai-hook.mjs maybeEscalate),
// so an in-memory cache would never hit: the same text re-scanned on the next call paid a full local
// model call again. data/escalation-cache.mjs keeps verdicts on disk, keyed by a per-device HMAC of the
// text (no text at rest), bounded in age and size, and only for verdicts a model actually returned.
//
// Model presence: before this, an Ollama that was running WITHOUT the configured model (the default
// llama3:latest is not installed on every machine) passed the liveness probe, and every escalation then
// paid a /api/generate round trip that failed with "model not found" and was recorded as "error".
//
// Everything runs against a fake Ollama on 127.0.0.1 and a temporary HOME; nothing touches ~/.moorai.
//
//   node --test test/escalation-cache.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readFileSync, writeFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HOME = mkdtempSync(join(tmpdir(), "moorai-esccache-"));
process.env.HOME = HOME;
process.env.USERPROFILE = HOME;
process.env.MOORAI_LOCAL_MODEL = "fake-model:latest";

// ---- fake Ollama ----
const state = { generate: 0, tags: ["fake-model:latest"], status: 200, risk: true };
const srv = http.createServer((req, res) => {
  let b = "";
  req.on("data", (c) => (b += c));
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/api/tags") return res.end(JSON.stringify({ models: state.tags.map((name) => ({ name, model: name })) }));
    if (req.url === "/api/generate") {
      state.generate++;
      if (state.status !== 200) { res.statusCode = state.status; return res.end(JSON.stringify({ error: "boom" })); }
      return res.end(JSON.stringify({ response: JSON.stringify({ risk: state.risk, category: "jailbreak", confidence: 0.9 }) }));
    }
    res.statusCode = 404; res.end("{}");
  });
});

let cache, esc;
before(async () => {
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  process.env.MOORAI_LOCAL_HOST = `http://127.0.0.1:${srv.address().port}`;
  cache = await import("../data/escalation-cache.mjs");
  esc = await import("../data/model-escalation.mjs");
});
after(() => srv.close());

const CANARY = "CANARY-7f3a escalate this exact sentence for the cache test";

test("put then get returns the verdict; the file holds no text and is 0600", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  assert.equal(cache.getCachedVerdict(CANARY, "m1", { dir }), null);
  cache.putCachedVerdict(CANARY, "m1", { flagged: true, category: "jailbreak", confidence: 0.8 }, { dir });
  assert.deepEqual(cache.getCachedVerdict(CANARY, "m1", { dir }), { flagged: true, category: "jailbreak", confidence: 0.8 });
  const raw = readFileSync(join(dir, cache.CACHE_FILE), "utf8");
  assert.ok(!raw.includes("CANARY"), "cache file must not contain the scanned text");
  if (process.platform !== "win32") assert.equal(statSync(join(dir, cache.CACHE_FILE)).mode & 0o777, 0o600);
});

test("a different model, or a changed text, misses", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  cache.putCachedVerdict(CANARY, "m1", { flagged: false, category: "none", confidence: 0.9 }, { dir });
  assert.equal(cache.getCachedVerdict(CANARY, "m2", { dir }), null);
  assert.equal(cache.getCachedVerdict(CANARY + " ", "m1", { dir }), null);
});

test("entries expire after the TTL", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  const t0 = 1_700_000_000_000;
  cache.putCachedVerdict(CANARY, "m1", { flagged: true, category: "x", confidence: 0.9 }, { dir, now: t0 });
  assert.ok(cache.getCachedVerdict(CANARY, "m1", { dir, now: t0 + cache.CACHE_TTL_MS - 1 }));
  assert.equal(cache.getCachedVerdict(CANARY, "m1", { dir, now: t0 + cache.CACHE_TTL_MS + 1 }), null);
});

test("the cache is bounded: the oldest entries are evicted past maxEntries", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  for (let i = 0; i < 5; i++) cache.putCachedVerdict(`text ${i}`, "m1", { flagged: true, category: "x", confidence: 0.9 }, { dir, now: 1000 + i, maxEntries: 3 });
  assert.equal(cache.getCachedVerdict("text 0", "m1", { dir, now: 2000 }), null);
  assert.equal(cache.getCachedVerdict("text 1", "m1", { dir, now: 2000 }), null);
  assert.ok(cache.getCachedVerdict("text 4", "m1", { dir, now: 2000 }));
  const j = JSON.parse(readFileSync(join(dir, cache.CACHE_FILE), "utf8"));
  assert.equal(Object.keys(j.entries).length, 3);
});

test("a corrupt cache file fails open (miss, and a later put still works)", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  writeFileSync(join(dir, cache.CACHE_FILE), "{not json");
  assert.equal(cache.getCachedVerdict(CANARY, "m1", { dir }), null);
  cache.putCachedVerdict(CANARY, "m1", { flagged: true, category: "x", confidence: 0.9 }, { dir });
  assert.ok(cache.getCachedVerdict(CANARY, "m1", { dir }));
});

test("classifyLocal: the second call for the same text is served from the cache (one model call)", async () => {
  state.generate = 0; state.status = 200; state.risk = true;
  esc.takeEscalationOutcomes();
  const text = "cache integration sample one";
  const a = await esc.classifyLocal(text);
  const b = await esc.classifyLocal(text);
  assert.equal(state.generate, 1, "the model must be called once");
  assert.deepEqual(a, b);
  assert.equal(a.flagged, true);
  const outs = esc.takeEscalationOutcomes();
  assert.deepEqual(outs.map((o) => `${o.outcome}/${o.backend}`), ["answered/local", "answered/local-cache"]);
  assert.ok(existsSync(join(HOME, ".moorai", cache.CACHE_FILE)), "cache lives under the (temporary) STATE_DIR");
});

test("classifyLocal: a failed model call is never cached", async () => {
  state.generate = 0; state.status = 500;
  const text = "cache integration sample two";
  assert.equal(await esc.classifyLocal(text), null);
  assert.equal(await esc.classifyLocal(text), null);
  assert.equal(state.generate, 2);
  state.status = 200;
});

test("an Ollama without the configured model is unavailable: no generate call, outcome 'unavailable'", async () => {
  state.generate = 0; state.tags = ["some-other-model:latest"];
  esc.takeEscalationOutcomes();
  assert.equal(await esc.localModelAvailable(), false);
  const v = await esc.classifyOpportunistic("presence sample never seen before", { semanticEscalation: "local" });
  assert.equal(v, null);
  assert.equal(state.generate, 0, "no /api/generate round trip for a model that is not installed");
  assert.deepEqual(esc.takeEscalationOutcomes().map((o) => o.outcome), ["unavailable"]);
  state.tags = ["fake-model:latest"];
});

test("model presence: a bare name matches its :latest tag", async () => {
  state.tags = ["fake-model:latest"];
  assert.equal(await esc.localModelAvailable(), true);
  assert.equal(esc.modelListed(["llama3:latest"], "llama3"), true);
  assert.equal(esc.modelListed(["llama3:latest"], "llama3:latest"), true);
  assert.equal(esc.modelListed(["llama3.2:latest"], "llama3:latest"), false);
});

// ---- review fixes: the classifier prompt is part of the key, and measurement can turn the cache off ----

test("a verdict stored under one prompt version misses under another", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  cache.putCachedVerdict(CANARY, "m1", { flagged: true, category: "x", confidence: 0.9 }, { dir, promptId: "p1" });
  assert.ok(cache.getCachedVerdict(CANARY, "m1", { dir, promptId: "p1" }));
  assert.equal(cache.getCachedVerdict(CANARY, "m1", { dir, promptId: "p2" }), null);
});

test("classifyLocal keys the cache on the shipped prompt: an entry from a different prompt is not reused", async () => {
  state.generate = 0; state.status = 200; state.risk = false;
  const dir = join(HOME, ".moorai");
  const text = "prompt version sample never classified before";
  assert.match(String(esc.CLASSIFIER_PROMPT_ID), /^[0-9a-f]{16}$/);
  cache.putCachedVerdict(text, "fake-model:latest", { flagged: true, category: "stale", confidence: 1 }, { dir, promptId: "an-older-prompt" });
  const v = await esc.classifyLocal(text);
  assert.equal(state.generate, 1, "a verdict from another prompt must not be served");
  assert.equal(v.flagged, false);
  const text2 = "prompt version sample two never classified before";
  cache.putCachedVerdict(text2, "fake-model:latest", { flagged: true, category: "same", confidence: 1 }, { dir, promptId: esc.CLASSIFIER_PROMPT_ID });
  assert.equal((await esc.classifyLocal(text2)).category, "same");
  assert.equal(state.generate, 1, "a verdict from the shipped prompt is served from the cache");
  state.risk = true;
});

test("MOORAI_ESCALATION_CACHE=off: every call asks the model and nothing is read or written", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-esccache-u-"));
  process.env.MOORAI_ESCALATION_CACHE = "off";
  try {
    cache.putCachedVerdict(CANARY, "m1", { flagged: true, category: "x", confidence: 0.9 }, { dir });
    assert.equal(existsSync(join(dir, cache.CACHE_FILE)), false, "no write while off");
    state.generate = 0; state.status = 200;
    const text = "cache off sample";
    await esc.classifyLocal(text);
    await esc.classifyLocal(text);
    assert.equal(state.generate, 2, "both calls reach the model");
  } finally {
    delete process.env.MOORAI_ESCALATION_CACHE;
  }
  cache.putCachedVerdict(CANARY, "m1", { flagged: true, category: "x", confidence: 0.9 }, { dir });
  process.env.MOORAI_ESCALATION_CACHE = "0";
  try {
    assert.equal(cache.getCachedVerdict(CANARY, "m1", { dir }), null, "no read while off");
  } finally {
    delete process.env.MOORAI_ESCALATION_CACHE;
  }
  assert.ok(cache.getCachedVerdict(CANARY, "m1", { dir }), "on again once the variable is unset");
});
