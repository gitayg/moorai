// Wire-format pins for the hook-side moorai-guardd client (cli/guardd-client.mjs) against the shared golden
// fixture, which guardd/tests/golden.rs and the console's test/device-keys.test.js check byte for byte.
// Contract: docs/proposals/guardd-contract.md §11.1.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "../cli/hook-core.mjs";
import {
  wireCanonical, parseCanonical, encodeFrame, decodeFrame, FrameDecoder, buildRequest, helloProofInput,
  devreqSigningInput, keyIdOfSpki, verifyHelloProof, fallbackMode, endpointFor, runDirFor, devicePubPathFor,
  connect, verifyEndpointOwnership, MAX_FRAME, HOOK_OPS, STAMPS
} from "../cli/guardd-client.mjs";

const RAW = readFileSync(fileURLToPath(new URL("./fixtures/guardd/golden.json", import.meta.url)));
// Same constant in guardd/tests/golden.rs and RAISEME-server/test/device-keys.test.js.
const FIXTURE_SHA256 = "6371d6615f0b9d40bd48b1923b0fd2a5a8e16c7a0baca6bb82b2fa8f737589b6";
const G = JSON.parse(RAW.toString("utf8"));
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const devPriv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(G.keys.deviceSeedHex, "hex")]), format: "der", type: "pkcs8" });

test("the fixture is the pinned one", () => {
  assert.equal(createHash("sha256").update(RAW).digest("hex"), FIXTURE_SHA256);
});

test("canonical JSON cases, and parity with hook-core canonicalJson", () => {
  for (const c of G.canonical) {
    assert.equal(wireCanonical(c.value), c.canonical);
    assert.equal(canonicalJson(c.value), c.canonical);
    assert.deepEqual(parseCanonical(Buffer.from(c.canonical, "utf8")), c.value);
  }
  assert.throws(() => wireCanonical({ a: 1.5 }));
  assert.throws(() => wireCanonical({ a: 2 ** 53 }));
  assert.throws(() => wireCanonical({ a: undefined }));
});

test("every golden frame encodes and decodes byte for byte; request builders reproduce them", () => {
  for (const f of G.frames) {
    assert.equal(encodeFrame(f.message).toString("hex"), f.frameHex, f.name);
    assert.deepEqual(decodeFrame(Buffer.from(f.frameHex, "hex")), f.message, f.name);
    if (f.name.endsWith("-request") && f.message.op !== "release") {
      const { v, id, op, ...fields } = f.message;
      assert.equal(v, 1);
      assert.equal(encodeFrame(buildRequest(op, id, fields)).toString("hex"), f.frameHex, `${f.name} via buildRequest`);
    }
  }
});

test("decoder: split delivery, and every malformed frame is refused", () => {
  const frames = G.frames.map((f) => Buffer.from(f.frameHex, "hex"));
  const all = Buffer.concat(frames);
  const d = new FrameDecoder();
  const out = [];
  for (let i = 0; i < all.length; i += 7) { d.push(all.subarray(i, i + 7)); for (let m; (m = d.next());) out.push(m); }
  assert.deepEqual(out, G.frames.map((f) => f.message));

  const frame = (s) => { const p = Buffer.from(s, "utf8"); const l = Buffer.alloc(4); l.writeUInt32BE(p.length); return Buffer.concat([l, p]); };
  const code = (buf) => { try { decodeFrame(buf); return "ok"; } catch (e) { return e.code; } };
  assert.equal(code(Buffer.from([0, 0, 0, 0])), "bad_frame");
  const big = Buffer.alloc(4); big.writeUInt32BE(MAX_FRAME + 1);
  assert.equal(code(big), "frame_too_large");
  assert.equal(code(frame('{"id":1, "v":1}')), "bad_frame", "whitespace");
  assert.equal(code(frame('{"v":1,"id":1}')), "bad_frame", "key order");
  assert.equal(code(frame('{"id":1,"id":1,"v":1}')), "bad_frame", "duplicate key");
  assert.equal(code(frame('{"id":1,"v":9007199254740993}')), "bad_frame", "unsafe integer");
  assert.equal(code(frame('\ufeff{"id":1,"v":1}')), "bad_frame", "BOM");
  assert.equal(code(frame("[1]")), "bad_frame", "not an object");
  assert.equal(code(Buffer.concat([Buffer.from([0, 0, 0, 3]), Buffer.from([0x7b, 0xff, 0x7d])])), "bad_frame", "invalid UTF-8");
  assert.equal(new FrameDecoder().next(), null);
});

function checkDevreq(c) {
  assert.equal(c.body === null ? "" : wireCanonical(c.body), c.bodyCanonical);
  assert.equal(createHash("sha256").update(c.bodyCanonical, "utf8").digest("hex"), c.bodySha256);
  const input = devreqSigningInput({ ...c, body: c.body === null ? null : c.bodyCanonical });
  assert.equal(input, c.signingInput);
  assert.equal(sign(null, Buffer.from(input), devPriv).toString("base64"), c.signatureB64);
  assert.ok(verifyHelloProof(G.keys.devicePublicKeySpkiB64, input, c.signatureB64));
}

test("signed beat, alert batch, registration and command poll: canonical body, signing input, signature", () => {
  for (const k of ["beat", "alertBatch", "register", "commandsPoll"]) checkDevreq(G[k]);
});

test("hello proof verifies against the device key and nothing else", () => {
  const h = G.helloProof;
  assert.equal(keyIdOfSpki(G.keys.devicePublicKeySpkiB64), G.keys.deviceKeyId);
  assert.equal(helloProofInput(h.nonce, h.keyId, h.helperVersion), h.input);
  assert.ok(verifyHelloProof(G.keys.devicePublicKeySpkiB64, h.input, h.signatureB64));
  assert.equal(verifyHelloProof(G.keys.consolePublicKeySpkiB64, h.input, h.signatureB64), false, "other key");
  assert.equal(verifyHelloProof(G.keys.devicePublicKeySpkiB64, h.input.replace("|v1|", "|v2|"), h.signatureB64), false, "other input");
  assert.equal(verifyHelloProof("AAAA", h.input, h.signatureB64), false, "junk key");
});

test("the hook client never builds release", () => {
  assert.ok(!HOOK_OPS.includes("release"));
  assert.throws(() => buildRequest("release", 1, { quarantineId: "*" }), /does not send op release/);
  assert.throws(() => buildRequest("submit", 1, { alerts: [] }));
});

test("fallback table (contract §10.3)", () => {
  assert.deepEqual(fallbackMode({ helper: "off", reachable: true }), { useHelper: false, stamps: [], mode: "legacy" });
  assert.deepEqual(fallbackMode({ helper: "optional", reachable: true }), { useHelper: true, stamps: [], mode: "helper" });
  assert.deepEqual(fallbackMode({ helper: "optional", reachable: false }), { useHelper: false, stamps: [], mode: "legacy" });
  assert.deepEqual(fallbackMode({ helper: "junk", reachable: false }), { useHelper: false, stamps: [], mode: "legacy" });
  assert.deepEqual(fallbackMode({ helper: "required", reachable: false }), { useHelper: false, stamps: [STAMPS.unreachable], mode: "posture" });
  assert.deepEqual(fallbackMode({ helper: "required", reachable: true, outdated: true }), { useHelper: false, stamps: [STAMPS.outdated], mode: "posture" });
  assert.deepEqual(fallbackMode({ helper: "required", reachable: true }), { useHelper: true, stamps: [], mode: "helper" });
});

test("endpoint paths are constants, never taken from the environment", () => {
  const saved = { ...process.env };
  try {
    Object.assign(process.env, { ProgramData: "C:\\evil", TMPDIR: "/evil", XDG_RUNTIME_DIR: "/evil", MOORAI_GUARDD_SOCKET: "/evil.sock" });
    assert.equal(endpointFor("darwin"), "/private/var/run/moorai/hook.sock");
    assert.equal(endpointFor("linux"), "/run/moorai/hook.sock");
    assert.equal(endpointFor("win32"), "\\\\.\\pipe\\MoorAI.Hook");
    assert.equal(devicePubPathFor("linux"), "/run/moorai/device.pub");
    assert.equal(runDirFor("win32", { programData: "C:\\ProgramData", systemRoot: "C:\\Windows" }), "C:\\ProgramData\\MoorAI\\run");
  } finally { process.env = saved; }
});

test("transport and ownership are stubs until implemented", async () => {
  await assert.rejects(connect(), /not implemented/);
  await assert.rejects(verifyEndpointOwnership(endpointFor()), /not implemented/);
});
