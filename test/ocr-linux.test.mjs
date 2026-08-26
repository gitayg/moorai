// #39 — Linux on-device OCR (Tesseract) dispatch, Node side. Linux is a native tier like macOS/
// Windows: when the host reports a Tesseract engine, image inspection runs ON-DEVICE and the
// provider fallback stays structurally unreachable. These tests pin the Node-side contract only —
// engineLabel naming, the ordering guarantee, and that no image/text egress leaks in the native
// case. The Rust leptess path is compile-guarded and validated separately on a real Linux host.
//
//   node --test test/ocr-linux.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const { decideImageInspection, ocrCapability, ocrImage, engineLabel } = await import("../src/ocr.js");

const LINUX_NATIVE = { native: true, engine: "linux-tesseract", providerFallback: false, maxBytes: 4194304 };

test("OCR-LINUX: engineLabel names the Linux Tesseract tier for the user", () => {
  assert.equal(engineLabel("linux-tesseract"), "Tesseract (Linux)");
  // Regression guard: the other tiers keep their existing labels.
  assert.equal(engineLabel("macos-vision"), "macOS Vision");
  assert.equal(engineLabel("windows-ocr"), "Windows OCR");
  assert.equal(engineLabel("provider"), "your AI provider");
});

test("OCR-LINUX: a Tesseract engine takes the native branch and names itself in the hint", () => {
  const plan = decideImageInspection(LINUX_NATIVE);
  assert.equal(plan.mode, "native");
  assert.match(plan.hint, /on-device/);
  assert.match(plan.hint, /Tesseract \(Linux\)/);
});

test("OCR-LINUX: a native Linux engine wins even when a provider key is present", () => {
  // Ordering guarantee: provider fallback is reachable ONLY when there is no native engine.
  const both = { ...LINUX_NATIVE, providerFallback: true };
  assert.equal(decideImageInspection(both).mode, "native");
});

test("OCR-LINUX: with no Tesseract engine and no key, the feature skips — never silent egress", () => {
  const nothing = { native: false, engine: null, providerFallback: false, maxBytes: 4194304 };
  const plan = decideImageInspection(nothing);
  assert.equal(plan.mode, "skip");
  assert.match(plan.hint, /not inspected/);
});

test("OCR-LINUX: native extraction stays on-device and makes ZERO network calls", async () => {
  // The exact text a Linux host's Tesseract tier would hand back for the canary render.
  const CANARY = "MOORAI-CANARY-7Q4Z\nAKIAIOSFODNN7EXAMPLE\nSSN 123-45-6789\nalice@acme.com";
  const calls = [];
  const invoked = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (...a) => { calls.push(String(a[0])); throw new Error("network call attempted"); };
  globalThis.window = {
    __TAURI__: { core: { invoke: async (cmd, args) => {
      invoked.push([cmd, args]);
      if (cmd === "ocr_capability") return LINUX_NATIVE;
      return { text: CANARY, engine: "linux-tesseract", leftDevice: false };
    } } }
  };
  try {
    const cap = await ocrCapability();
    assert.equal(cap.engine, "linux-tesseract");
    const plan = decideImageInspection(cap);
    const res = await ocrImage("aGVsbG8=", "image/png", plan.mode === "provider");
    assert.equal(res.text, CANARY);
    assert.equal(res.leftDevice, false);
    assert.ok(res.text.includes("AKIAIOSFODNN7EXAMPLE"), "the AWS key shape was not recovered");
    assert.ok(res.text.includes("123-45-6789"), "the SSN shape was not recovered");
  } finally {
    globalThis.fetch = realFetch;
    delete globalThis.window;
  }
  assert.deepEqual(calls, [], `Linux image path made network calls: ${calls.join(", ")}`);
  // The host was told NOT to use the provider, because a native engine exists.
  assert.deepEqual(invoked.map(([c]) => c), ["ocr_capability", "ocr_image"]);
  assert.equal(invoked[1][1].allowProvider, false);
});
