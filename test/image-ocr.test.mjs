// #23 — image inspection must be on-device by default, and must never silently egress.
//
// Two things are pinned here, because both were previously violated by the same code path: the raw
// image used to be POSTed to the MoorAI console (/api/ocr), which then forwarded it to a vision
// vendor. So the tests assert (a) no image endpoint survives in the client's HTTP module, (b) the
// extraction path makes no network call at all, and (c) the provider fallback is structurally
// unreachable whenever the OS has its own engine.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const SRC = new URL("../src/", import.meta.url);
const read = (f) => readFileSync(new URL(f, SRC), "utf8");

// src/ocr.js touches window.__TAURI__ only inside functions, so it imports cleanly under node.
const { decideImageInspection, ocrCapability, ocrImage, engineLabel, providerOptIn, providerChoice, setProviderChoice } = await import("../src/ocr.js");

const NATIVE = { native: true, engine: "macos-vision", providerFallback: false, maxBytes: 4194304 };
const NO_ENGINE_WITH_KEY = { native: false, engine: null, providerFallback: true, maxBytes: 4194304 };
const NOTHING = { native: false, engine: null, providerFallback: false, maxBytes: 4194304 };

test("IMAGE-OCR: the console's image endpoint is gone from the client's HTTP module", () => {
  const api = read("api.js");
  assert.ok(!api.includes("/api/ocr"), "src/api.js still references the console OCR endpoint");
  assert.ok(!/export\s+async\s+function\s+ocrImage/.test(api), "src/api.js still exports an HTTP ocrImage");
});

test("IMAGE-OCR: the extraction module contains no HTTP at all", () => {
  const ocr = read("ocr.js");
  assert.ok(!/\bfetch\s*\(/.test(ocr), "src/ocr.js performs a fetch — the image path must be native-only");
  assert.ok(!ocr.includes("http://") && !ocr.includes("https://"), "src/ocr.js names a network destination");
});

test("IMAGE-OCR: a native engine always wins — the provider is unreachable when the OS can do it", () => {
  // Even with a device key present, a native engine must take the on-device branch.
  const both = { ...NATIVE, providerFallback: true };
  assert.equal(decideImageInspection(both).mode, "native");
  assert.equal(decideImageInspection(NATIVE).mode, "native");
});

test("IMAGE-OCR: the provider branch requires no native engine, a key already on the device AND an opt-in", () => {
  assert.equal(decideImageInspection(NO_ENGINE_WITH_KEY, { providerOptIn: true }).mode, "provider");
  assert.equal(decideImageInspection(NOTHING, { providerOptIn: true }).mode, "skip", "an opt-in without a key sends nothing");
  assert.equal(decideImageInspection(NOTHING).mode, "skip");
  assert.match(decideImageInspection(NOTHING).hint, /not inspected/);
});

test("IMAGE-OCR: a provider key alone never sends the image: off by default, and the user is told how to turn it on", () => {
  const plan = decideImageInspection(NO_ENGINE_WITH_KEY);
  assert.equal(plan.mode, "skip", "the image was sent to the provider just because a key exists");
  assert.equal(decideImageInspection(NO_ENGINE_WITH_KEY, { providerOptIn: false }).mode, "skip");
  assert.doesNotMatch(plan.hint, /will be sent/);
  assert.match(plan.hint, /off/);
  assert.match(plan.hint, /Settings/);
});

test("IMAGE-OCR: the opt-in comes from the console's policy or the user's own choice on this device, never from a key", () => {
  assert.equal(providerOptIn(null, false), false, "default: off");
  assert.equal(providerOptIn(undefined, undefined), false);
  assert.equal(providerOptIn({ imageInspection: { enabled: true } }, false), false, "image inspection on is not the provider fallback on");
  assert.equal(providerOptIn({ imageInspection: { providerFallback: true } }, false), true, "the policy turns it on");
  assert.equal(providerOptIn(null, true), true, "the user turns it on for this device");
  assert.equal(providerOptIn({ imageInspection: { providerFallback: false } }, true), false, "a policy that says no wins over the device choice");
  assert.equal(providerOptIn({ imageInspection: { providerFallback: "yes" } }, false), false, "only true turns it on");
});

test("IMAGE-OCR: the device choice is stored only when the user sets it, and reads back off when storage fails", () => {
  const kv = new Map();
  const saved = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, writable: true, value: { getItem: (k) => (kv.has(k) ? kv.get(k) : null), setItem: (k, v) => kv.set(k, String(v)), removeItem: (k) => kv.delete(k) } });
  try {
    assert.equal(providerChoice(), false);
    setProviderChoice(true);
    assert.equal(providerChoice(), true);
    setProviderChoice(false);
    assert.equal(providerChoice(), false);
    assert.equal(kv.size, 0, "turning it off leaves nothing stored");
    globalThis.localStorage = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => {} };
    assert.equal(providerChoice(), false);
  } finally { if (saved) Object.defineProperty(globalThis, "localStorage", saved); else delete globalThis.localStorage; }
});

test("IMAGE-OCR: the app passes the opt-in to the decision (src/app.js)", () => {
  const app = read("app.js");
  assert.match(app, /decideImageInspection\(cap, \{[^}]*providerOptIn: providerOptIn\(policy, providerChoice\(\)\)/s);
});

test("IMAGE-OCR: the provider hint discloses the egress and names whose token is used", () => {
  const hint = decideImageInspection(NO_ENGINE_WITH_KEY, { providerOptIn: true }).hint;
  assert.match(hint, /sent to your AI provider/);
  assert.match(hint, /token already on this device/);
  assert.match(hint, /not to MoorAI/);
});

test("IMAGE-OCR: oversize and policy-disabled skip before any engine is consulted", () => {
  assert.equal(decideImageInspection(NATIVE, { sizeBytes: 5 * 1024 * 1024 }).mode, "skip");
  assert.equal(decideImageInspection(NATIVE, { policyDisabled: true }).mode, "skip");
});

test("IMAGE-OCR: extraction recovers the canary and makes ZERO network calls", async () => {
  // The exact text macOS Vision recovers from src-tauri/tests/fixtures/ocr-canary.png.
  const CANARY = "MOORAI-CANARY-7Q4Z\nAKIAIOSFODNN7EXAMPLE\nSSN 123-45-6789\nalice@acme.com";
  const calls = [];
  const invoked = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (...a) => { calls.push(String(a[0])); throw new Error("network call attempted"); };
  globalThis.window = {
    __TAURI__: { core: { invoke: async (cmd, args) => { invoked.push([cmd, args]); return { text: CANARY, engine: "macos-vision", leftDevice: false }; } } }
  };
  try {
    const cap = await ocrCapability();
    const plan = decideImageInspection({ ...cap, native: true, engine: "macos-vision" });
    const res = await ocrImage("aGVsbG8=", "image/png", plan.mode === "provider");
    assert.equal(res.text, CANARY);
    assert.equal(res.leftDevice, false);
    assert.ok(res.text.includes("AKIAIOSFODNN7EXAMPLE"), "the AWS key shape was not recovered");
    assert.ok(res.text.includes("123-45-6789"), "the SSN shape was not recovered");
  } finally {
    globalThis.fetch = realFetch;
    delete globalThis.window;
  }
  assert.deepEqual(calls, [], `image path made network calls: ${calls.join(", ")}`);
  // ...and the host was told NOT to use the provider, because a native engine exists.
  assert.deepEqual(invoked.map(([c]) => c), ["ocr_capability", "ocr_image"]);
  assert.equal(invoked[1][1].allowProvider, false);
});

test("IMAGE-OCR: outside the native host the feature is skipped, never degraded to HTTP", async () => {
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = (...a) => { calls.push(String(a[0])); throw new Error("network call attempted"); };
  globalThis.window = {};
  try {
    assert.deepEqual(await ocrCapability(), { native: false, engine: null, providerFallback: false });
    await assert.rejects(() => ocrImage("aGVsbG8=", "image/png", true), /native host unavailable/);
  } finally {
    globalThis.fetch = realFetch;
    delete globalThis.window;
  }
  assert.deepEqual(calls, [], "the fallback reached for the network instead of skipping");
});

test("IMAGE-OCR: the engine label names the OS engine, so the user can see where OCR ran", () => {
  assert.equal(engineLabel("macos-vision"), "macOS Vision");
  assert.equal(engineLabel("windows-ocr"), "Windows OCR");
  assert.equal(engineLabel("provider"), "your AI provider");
});
