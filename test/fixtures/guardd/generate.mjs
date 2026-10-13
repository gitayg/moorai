// Regenerates golden.json, the wire-format fixture shared by the guardd crate (Rust), the hook client
// (cli/guardd-client.mjs) and the console (RAISEME-server/server/device-keys.js). See
// docs/proposals/guardd-contract.md §11.
//
// NOT run by any test. Run it by hand only when the contract changes, then update the fixture hash
// pinned in guardd/tests/golden.rs, test/guardd-client.test.mjs and the console's
// test/device-keys.test.js, and copy the file to RAISEME-server/test/fixtures/guardd/golden.json.
//
//   node test/fixtures/guardd/generate.mjs > test/fixtures/guardd/golden.json
//
// Deliberately written against node:crypto only, not against any of the three implementations, so the
// fixture is an independent reference rather than one implementation's output checked against itself.
// The two seeds are public TEST values and must never be used as real keys.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";

const sha256hex = (s) => createHash("sha256").update(s).digest("hex");
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

function canon(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) throw new Error(`not a wire integer: ${v}`);
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`;
  throw new Error(`not a wire value: ${typeof v}`);
}

function keyFromSeed(label) {
  const seed = createHash("sha256").update(label).digest();
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
  const spki = createPublicKey(priv).export({ type: "spki", format: "der" });
  const raw = spki.subarray(12);
  return { seed, priv, spkiB64: spki.toString("base64"), keyId: sha256hex(raw).slice(0, 32) };
}
const sig = (priv, s) => sign(null, Buffer.from(s, "utf8"), priv).toString("base64");

const dev = keyFromSeed("moorai-guardd golden device seed (TEST ONLY)");
const con = keyFromSeed("moorai-guardd golden console seed (TEST ONLY)");
const tenant = "acme";
const deviceId = sha256hex("moorai-device|v1|GOLDEN-MACHINE-ID-0001").slice(0, 32);
const ts = "2026-10-12T09:30:00.000Z";
const nonce = "00112233445566778899aabbccddeeff";
const chainHead = sha256hex("golden chain head");

function devreq({ method, path, body }) {
  const bodyCanonical = body === null ? "" : canon(body);
  const bodySha256 = sha256hex(Buffer.from(bodyCanonical, "utf8"));
  const signingInput = `moorai-devreq|v1|${method}|${path}|${tenant}|${deviceId}|${dev.keyId}|${ts}|${nonce}|${bodySha256}`;
  return { method, path, tenant, deviceId, keyId: dev.keyId, ts, nonce, body, bodyCanonical, bodySha256, signingInput, signatureB64: sig(dev.priv, signingInput) };
}

const canonicalCases = [
  { value: { b: 1, a: [true, false, null, 0, -7, 9007199254740991] }, },
  { value: { s: "line\nbreak\ttab \u0001 \u001f quote\" backslash\\ slash/ \u007f é 😀  " } },
  { value: { "😀": 1, "": 2, "é": 3, z: 4, Z: 5, "": 6 } },
  { value: { nested: { y: [{ b: 2, a: 1 }], x: {} }, empty: [] } }
].map((c) => ({ ...c, canonical: canon(c.value) }));

const sessionHash = "a1b2c3d4e5f60718";
const helloProofInput = `moorai-guardd-hello|v1|${nonce}|${dev.keyId}|0.1.0`;
const messages = [
  { name: "hello-request", message: { v: 1, id: 1, op: "hello", proto: [1], client: "moorai-hook", clientVersion: "1.13.6", host: "claude-code", nonce } },
  { name: "hello-response", message: { v: 1, id: 1, op: "hello", proto: 1, helperVersion: "0.1.0", tenant, deviceId, keyId: dev.keyId, caps: ["call", "kill", "policy", "quarantine", "submit"], proof: sig(dev.priv, helloProofInput) } },
  { name: "policy-request", message: { v: 1, id: 2, op: "policy", ifIat: "2026-10-12T09:28:41.512Z" } },
  { name: "policy-response", message: { v: 1, id: 2, op: "policy", source: "fresh", iat: "2026-10-12T09:29:41.512Z", fetchedAt: "2026-10-12T09:29:42.004Z", ageSec: 18, policy: "{\"policySig\":{\"alg\":\"ed25519\",\"iat\":\"2026-10-12T09:29:41.512Z\",\"sig\":\"AAAA\",\"tenant\":\"acme\",\"v\":1},\"posture\":\"fail-closed\"}" } },
  { name: "submit-request", message: { v: 1, id: 3, op: "submit", alerts: [{ threatId: 21, severity: "high", action: "block", host: "claude-code", sessionHash, appVersion: "1.13.6", ts: "2026-10-12T09:29:59.120Z" }] } },
  { name: "submit-response", message: { v: 1, id: 3, op: "submit", acks: [{ seq: 1338 }], chainHead } },
  { name: "call-request", message: { v: 1, id: 4, op: "call", event: "PreToolUse", host: "claude-code", sessionHash, agentPid: 4242 } },
  { name: "call-response", message: { v: 1, id: 4, op: "call" } },
  { name: "kill-request", message: { v: 1, id: 5, op: "kill", sessionHash } },
  { name: "kill-response", message: { v: 1, id: 5, op: "kill", kill: false } },
  { name: "quarantine-request", message: { v: 1, id: 6, op: "quarantine", agentPid: 4242, pgid: 4242, sid: 4100, host: "claude-code", threatId: 21, reasonCode: "policy-quarantine", sessionHash, decidedAtMs: 1791797399120 } },
  { name: "quarantine-response", message: { v: 1, id: 6, op: "quarantine", quarantineId: "q-0000000000000001", suspendedPids: 3, suspendedAtMs: 1791797399131, network: "pending" } },
  { name: "release-request", message: { v: 1, id: 7, op: "release", quarantineId: "q-0000000000000001" } },
  { name: "release-response", message: { v: 1, id: 7, op: "release", released: 1 } },
  { name: "error-response", message: { v: 1, id: 7, op: "error", code: "forbidden", message: "release requires an administrator peer", reqOp: "release" } }
];
const frames = messages.map(({ name, message }) => {
  const payload = Buffer.from(canon(message), "utf8");
  const len = Buffer.alloc(4); len.writeUInt32BE(payload.length);
  return { name, message, frameHex: Buffer.concat([len, payload]).toString("hex") };
});

const beatBody = {
  v: 1, tenant, deviceId, device: "laptop-17", platform: "darwin", keyId: dev.keyId,
  bootId: "6f1c0b9e-2d4a-4c55-9b1e-7d3f0a8c1e22", awakeSec: 86000, uptimeSec: 90061,
  beatSeq: 42, chainSeq: 1337, chainHead,
  policyIat: "2026-10-12T09:28:41.512Z", policyFetchedAt: "2026-10-12T09:29:00.004Z", policySource: "fresh",
  hookCalls: { "claude-code": 17, codex: 0 }, agentProcs: { "claude-code": 2, codex: 1 },
  hookSilent: [{ host: "codex", sinceSec: 240 }], quarantinesActive: 0,
  versions: { helper: "0.1.0", hook: "1.13.6", app: "1.13.6" },
  clockOffsetMs: -12, helperStartedAt: "2026-10-11T08:00:00.000Z"
};
const alertBody = {
  v: 1, tenant, deviceId, batchId: "b7e1c2d3a4f5061728394a5b6c7d8e9f", firstSeq: 1338, lastSeq: 1339, chainHead,
  alerts: [
    { threatId: 21, severity: "high", action: "block", host: "claude-code", sessionHash, appVersion: "1.13.6", ts: "2026-10-12T09:29:59.120Z", seq: 1338 },
    { kind: "quarantine", quarantineId: "q-0000000000000001", origin: "hook", host: "claude-code", threatId: 21, reasonCode: "policy-quarantine", sessionHash, suspendedPids: 3, network: "applied", ts: "2026-10-12T09:29:59.140Z", seq: 1339 }
  ]
};
const registerBody = {
  v: 1, tenant, deviceId, device: "laptop-17", platform: "darwin", arch: "arm64", helperVersion: "0.1.0",
  publicKey: dev.spkiB64, keyId: dev.keyId
};
const rotateInput = `moorai-rotate|v1|${tenant}|${deviceId}|${con.keyId}|${dev.keyId}`;

const cmd = { tenant, deviceId, cmdId: "c-00000000000000000000000000000007", cmdSeq: 7, action: "quarantine", scope: "session", sessionHash, quarantineId: "", iat: "2026-10-12T09:31:00.000Z" };
const cmdInput = `moorai-cmd|v1|${cmd.tenant}|${cmd.deviceId}|${cmd.cmdId}|${cmd.cmdSeq}|${cmd.action}|${cmd.scope}|${cmd.sessionHash}|${cmd.quarantineId}|${cmd.iat}`;

const out = {
  _comment: "Golden wire fixture for moorai-guardd (docs/proposals/guardd-contract.md). Generated by generate.mjs. Both seeds are PUBLIC TEST VALUES: never use them as real keys.",
  fixtureVersion: 1,
  keys: {
    deviceSeedHex: dev.seed.toString("hex"), devicePublicKeySpkiB64: dev.spkiB64, deviceKeyId: dev.keyId,
    consoleSeedHex: con.seed.toString("hex"), consolePublicKeySpkiB64: con.spkiB64, consoleKeyId: con.keyId
  },
  deviceIdInput: "moorai-device|v1|GOLDEN-MACHINE-ID-0001", deviceId,
  canonical: canonicalCases,
  frames,
  helloProof: { nonce, keyId: dev.keyId, helperVersion: "0.1.0", input: helloProofInput, signatureB64: sig(dev.priv, helloProofInput) },
  beat: devreq({ method: "POST", path: "/api/devices/beat", body: beatBody }),
  alertBatch: devreq({ method: "POST", path: "/api/devices/alerts", body: alertBody }),
  register: { ...devreq({ method: "POST", path: "/api/devices/register", body: registerBody }), rotateInput, rotateSignatureB64ByConsoleSeedAsOldKey: sig(con.priv, rotateInput) },
  commandsPoll: devreq({ method: "GET", path: "/api/devices/commands?after=6&wait=25", body: null }),
  command: { fields: cmd, input: cmdInput, signatureB64: sig(con.priv, cmdInput) }
};
process.stdout.write(JSON.stringify(out, null, 2) + "\n");
