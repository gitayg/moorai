// Hook-side client for moorai-guardd, the privileged helper of the trust-anchor design phase 2.
// Wire contract: docs/proposals/guardd-contract.md. Pinned by test/fixtures/guardd/golden.json, the same
// fixture guardd/tests/golden.rs (Rust) and RAISEME-server test/device-keys.test.js check.
//
// REAL here: constants, the strict canonical JSON, framing encode/decode, request builders, the signed-byte
// forms, hello-proof verification and the fallback table. STUBBED (throw "not implemented"): connect, the
// endpoint ownership check and the client's ops. Nothing in this file reads the environment for a path,
// and nothing ever will (contract §3.1).
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { win32 } from "node:path";
import { machineDir } from "./machine-dir.mjs";

export const PROTO_VERSION = 1;
export const MAX_FRAME = 1024 * 1024;
export const MAX_SUBMIT_ALERTS = 64;
export const CONNECT_BUDGET_MS = 50;
export const OP_TIMEOUT_MS = Object.freeze({ policy: 50, submit: 250, call: 20, kill: 50, quarantine: 100 });
export const OPS = Object.freeze(["hello", "policy", "submit", "call", "kill", "quarantine", "release"]);
// What the hook may send. `release` is administrator-only and never comes from the hook (contract §3.6).
export const HOOK_OPS = Object.freeze(OPS.filter((op) => op !== "release"));
export const ERROR_CODES = Object.freeze([
  "bad_frame", "frame_too_large", "unsupported_version", "unknown_op", "bad_request", "forbidden",
  "not_ready", "busy", "target_not_agent_ancestor", "quarantine_failed", "unknown_quarantine", "internal"
]);
// Stamps the hook puts on alerts when the helper is not usable (contract §10.3, §8.8).
export const STAMPS = Object.freeze({ unreachable: "helperUnreachable", outdated: "helperOutdated", quarantineUnavailable: "quarantineUnavailable" });

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// ---- endpoint and public files (contract §3.1, §4) ----
export function endpointFor(platform = process.platform) {
  if (platform === "darwin") return "/private/var/run/moorai/hook.sock";
  if (platform === "win32") return "\\\\.\\pipe\\MoorAI.Hook";
  return "/run/moorai/hook.sock";
}
export function runDirFor(platform = process.platform, dirs = null) {
  if (platform === "darwin") return "/private/var/run/moorai";
  if (platform === "win32") return win32.join(machineDir(platform, dirs), "run");
  return "/run/moorai";
}
export function devicePubPathFor(platform = process.platform, dirs = null) {
  return platform === "win32" ? win32.join(runDirFor(platform, dirs), "device.pub") : `${runDirFor(platform)}/device.pub`;
}

// ---- strict canonical JSON (contract §3.3) ----
// Byte-identical to canonicalJson in cli/hook-core.mjs over the wire value set, and stricter: only
// null, booleans, strings, safe integers, arrays and plain objects. Anything else throws.
export function wireCanonical(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) throw new TypeError(`not a wire integer: ${v}`);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(wireCanonical).join(",")}]`;
  if (typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${wireCanonical(v[k])}`).join(",")}}`;
  }
  throw new TypeError(`not a wire value: ${typeof v}`);
}

// Parse and require the bytes to be their own canonical form (duplicate keys, whitespace, escape variants,
// unsafe integers and floats are all refused this way).
export function parseCanonical(buf) {
  let text;
  try { text = typeof buf === "string" ? buf : UTF8.decode(buf); } catch { throw new FrameError("bad_frame", "not UTF-8"); }
  let v;
  try { v = JSON.parse(text); } catch { throw new FrameError("bad_frame", "not JSON"); }
  let c;
  try { c = wireCanonical(v); } catch (e) { throw new FrameError("bad_frame", e.message); }
  if (c !== text) throw new FrameError("bad_frame", "not canonical JSON");
  return v;
}

// ---- framing (contract §3.2) ----
export class FrameError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export function encodeFrame(msg) {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) throw new FrameError("bad_frame", "a frame is one JSON object");
  const payload = Buffer.from(wireCanonical(msg), "utf8");
  if (payload.length > MAX_FRAME) throw new FrameError("frame_too_large", `${payload.length} > ${MAX_FRAME}`);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(payload.length);
  return Buffer.concat([len, payload]);
}

export class FrameDecoder {
  constructor() { this.buf = Buffer.alloc(0); }
  push(chunk) { this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : Buffer.from(chunk); }
  // The next complete message, or null when more bytes are needed. Throws FrameError on a bad frame; the
  // caller then closes the connection.
  next() {
    if (this.buf.length < 4) return null;
    const n = this.buf.readUInt32BE(0);
    if (n === 0) throw new FrameError("bad_frame", "empty frame");
    if (n > MAX_FRAME) throw new FrameError("frame_too_large", `${n} > ${MAX_FRAME}`);
    if (this.buf.length < 4 + n) return null;
    const payload = this.buf.subarray(4, 4 + n);
    this.buf = this.buf.subarray(4 + n);
    const v = parseCanonical(payload);
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new FrameError("bad_frame", "a frame is one JSON object");
    return v;
  }
}

export function decodeFrame(buf) {
  const d = new FrameDecoder();
  d.push(buf);
  const m = d.next();
  if (!m || d.buf.length) throw new FrameError("bad_frame", "expected exactly one frame");
  return m;
}

// ---- requests (contract §3.4) ----
// Optional fields that are undefined are omitted, never sent as null.
export function buildRequest(op, id, fields = {}) {
  if (!HOOK_OPS.includes(op)) throw new TypeError(`the hook client does not send op ${op}`);
  if (!Number.isInteger(id) || id < 1 || id > 0xffffffff) throw new TypeError("id is a u32 >= 1");
  const out = { v: PROTO_VERSION, id, op };
  for (const [k, val] of Object.entries(fields)) if (val !== undefined) out[k] = val;
  if (op === "submit" && (!Array.isArray(out.alerts) || out.alerts.length < 1 || out.alerts.length > MAX_SUBMIT_ALERTS)) {
    throw new TypeError(`submit carries 1..${MAX_SUBMIT_ALERTS} alerts`);
  }
  return out;
}

// ---- signed-byte forms (contract §3.6, §6.2, §9.4) ----
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");
export function helloProofInput(nonce, keyId, helperVersion) {
  return `moorai-guardd-hello|v1|${nonce}|${keyId}|${helperVersion}`;
}
export function devreqSigningInput({ method, path, tenant, deviceId, keyId, ts, nonce, body }) {
  const bytes = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  return `moorai-devreq|v1|${method}|${path}|${tenant}|${deviceId}|${keyId}|${ts}|${nonce}|${sha256hex(bytes)}`;
}
export function keyIdOfSpki(spkiB64) {
  const der = Buffer.from(String(spkiB64), "base64");
  if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_ED25519_PREFIX)) throw new TypeError("not an ed25519 SPKI key");
  return sha256hex(der.subarray(12)).slice(0, 32);
}
// True only for a valid ed25519 signature by `spkiB64` over `input`.
export function verifyHelloProof(spkiB64, input, sigB64) {
  try {
    keyIdOfSpki(spkiB64);
    const key = createPublicKey({ key: Buffer.from(spkiB64, "base64"), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(input, "utf8"), key, Buffer.from(String(sigB64), "base64"));
  } catch { return false; }
}

// ---- fallback table (contract §10.3) ----
// helper: the machine config's `helper` ("required" | "optional" | "off"; anything else = "optional").
// reachable: connect + ownership check + hello proof all passed within CONNECT_BUDGET_MS.
// outdated: hello.helperVersion < helperMinVersion.
// Returns { useHelper, stamps, mode } where mode is "helper" | "legacy" | "posture".
//   legacy  = exactly today's behaviour (user-scope cache, direct posts, deferred job files);
//   posture = enforce with the posture ratchet (never coach), alerts stamped, best-effort local queue.
export function fallbackMode({ helper = "optional", reachable = false, outdated = false } = {}) {
  const h = helper === "required" || helper === "off" ? helper : "optional";
  if (h === "off") return { useHelper: false, stamps: [], mode: "legacy" };
  if (reachable && !outdated) return { useHelper: true, stamps: [], mode: "helper" };
  if (h === "optional") return { useHelper: false, stamps: [], mode: "legacy" };
  return { useHelper: false, stamps: [outdated && reachable ? STAMPS.outdated : STAMPS.unreachable], mode: "posture" };
}

// ---- stubs: transport and ownership (contract §3.1, §3.6) ----
const notImplemented = (what) => { throw new Error(`guardd-client: ${what} not implemented (contract only)`); };

// Unix: lstat every directory from / to the socket's directory and the socket itself: no symlinks, owner
// uid 0 (or the helper's own uid on Linux, from /etc/passwd "moorai"), not group- or world-writable
// (the socket itself is 0666). Windows: the device.pub hello-proof check is the server check (Node has no
// GetNamedPipeServerProcessId). Resolves to { ok, reason }.
export async function verifyEndpointOwnership(_endpoint, _opts = {}) { return notImplemented("verifyEndpointOwnership"); }
// Reads device.pub from runDirFor() through readRootOwned (cli/hook-core.mjs). Resolves to base64 SPKI or null.
export async function readDevicePub(_opts = {}) { return notImplemented("readDevicePub"); }
// Connect within CONNECT_BUDGET_MS, check ownership, send hello, verify the proof. Resolves to a
// GuarddClient, or null when the helper is not usable (the caller then applies fallbackMode).
export async function connect(_opts = {}) { return notImplemented("connect"); }

export class GuarddClient {
  async hello() { return notImplemented("hello"); }
  async policy(_ifIat) { return notImplemented("policy"); }
  async submit(_alerts) { return notImplemented("submit"); }
  async call(_fields) { return notImplemented("call"); }
  async kill(_sessionHash) { return notImplemented("kill"); }
  async quarantine(_fields) { return notImplemented("quarantine"); }
  close() { return notImplemented("close"); }
}
