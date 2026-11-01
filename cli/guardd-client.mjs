// Hook-side client for moorai-guardd, the privileged helper of the trust-anchor design phase 2.
// Wire contract: docs/proposals/guardd-contract.md. Pinned by test/fixtures/guardd/golden.json, the same
// fixture guardd/tests/golden.rs (Rust) and RAISEME-server test/device-keys.test.js check.
//
// REAL here: constants, the strict canonical JSON, framing encode/decode, request builders, the signed-byte
// forms, hello-proof verification, the fallback table, the endpoint ownership check, readDevicePub, connect
// and the client's `policy` op (cli/guardd-policy.mjs reads the policy through it). STUBBED (throw "not
// implemented"): the `submit`, `call`, `kill` and `quarantine` ops. Nothing in this file reads the
// environment for a path, and nothing ever will (contract §3.1).
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { createConnection } from "node:net";
import { randomBytes } from "node:crypto";
import { win32, posix, join } from "node:path";
import { machineDir } from "./machine-dir.mjs";

export const PROTO_VERSION = 1;
export const MAX_FRAME = 1024 * 1024;
export const MAX_SUBMIT_ALERTS = 64;
export const CONNECT_BUDGET_MS = 50;
export const OP_TIMEOUT_MS = Object.freeze({ policy: 50, submit: 250, call: 20, kill: 50, quarantine: 100 });
// A `policy` request whose held answer is stale for the hook's actor makes the helper fetch on demand
// (guardd ON_DEMAND_FETCH_MS = 1000); the hook waits at most this long for that answer (guardd
// ipc::OP_TIMEOUT_POLICY_FETCH_MS), well inside the hook's 15 s decision budget.
export const POLICY_FETCH_TIMEOUT_MS = 1300;
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

const isLooseMode = (st, platform) => {
  if (st.mode & 0o002) return true;
  if (!(st.mode & 0o020)) return false;
  // macOS /private/var/run is root:daemon 0775 (contract §13.3 item 2): group-writable is accepted only
  // for gid 0, or gid 1 (daemon) on macOS.
  return !(st.gid === 0 || (platform === "darwin" && st.gid === 1));
};

// Contract §3.6 step 1, the one implementation (cli/guardd-install.mjs uses it too). Walks from the trust
// root to `target`'s directory: no symlinks, every directory owned by uid 0 and not writable by group or
// others; then the target itself: owned by uid 0, a socket (kind "socket") or a regular file not writable
// by group or others (kind "file"). Returns "ok", "absent" or "untrusted". `root`, `trustUid` and `lstat`
// exist for tests only (an injected root accepts `trustUid` as well as 0); no CLI flag reaches them.
export function checkOwnedPath(target, { root = "/", trustUid = 0, platform = process.platform, kind = "socket", lstat = lstatSync } = {}) {
  const okUid = (uid) => uid === 0 || uid === trustUid;
  const parts = posix.relative("/", target).split("/").filter(Boolean);
  let cur = root;
  const dirs = [cur];
  for (const p of parts.slice(0, -1)) { cur = join(cur, p); dirs.push(cur); }
  for (const d of dirs) {
    let st;
    try { st = lstat(d); } catch { return "absent"; }
    if (st.isSymbolicLink() || !st.isDirectory()) return "untrusted";
    if (!okUid(st.uid) || isLooseMode(st, platform)) return "untrusted";
  }
  let st;
  try { st = lstat(join(cur, parts[parts.length - 1])); } catch { return "absent"; }
  if (st.isSymbolicLink() || !okUid(st.uid)) return "untrusted";
  if (kind === "socket") return st.isSocket() ? "ok" : "untrusted";
  if (!st.isFile() || (st.mode & 0o022)) return "untrusted";
  return "ok";
}

// Unix: checkOwnedPath over the endpoint (uid 0 only; the helper runs as root on both Unix OSes, §4.2).
// Windows: no owner walk exists for the pipe namespace (§3.6), so this step is skipped and the device.pub
// hello-proof check is the server check. Resolves to { ok, reason } with reason "ok", "absent",
// "untrusted" or "skipped".
export async function verifyEndpointOwnership(endpoint, { platform = process.platform, lstat = lstatSync } = {}) {
  if (platform === "win32") return { ok: true, reason: "skipped" };
  const reason = checkOwnedPath(endpoint, { platform, kind: "socket", lstat });
  return { ok: reason === "ok", reason };
}
// device.pub (§4.2): Unix, through the same ownership walk as the endpoint (root-owned, not writable by
// group or others, no symlink) and then read; Windows, through hook-core readRootOwned (the icacls check).
// Resolves to the base64 SPKI of an ed25519 key, or null. `root`, `trustUid`, `path` and `lstat` exist for
// tests only (an injected tree, as guardd's Paths::under); no CLI flag or environment reaches them.
export async function readDevicePub({ platform = process.platform, root = "/", trustUid = 0, path = null, lstat = lstatSync } = {}) {
  const p = path || devicePubPathFor(platform);
  try {
    let text;
    if (platform === "win32") {
      const { readRootOwned } = await import("./hook-core.mjs");
      text = readRootOwned(p);
    } else {
      if (checkOwnedPath(p, { root, trustUid, platform, kind: "file", lstat }) !== "ok") return null;
      text = readFileSync(root === "/" ? p : join(root, posix.relative("/", p)), "utf8");
    }
    const spki = String(text || "").trim();
    keyIdOfSpki(spki);
    return spki;
  } catch { return null; }
}

// Connect, check endpoint ownership, send `hello`, verify the proof, all within `budgetMs`
// (CONNECT_BUDGET_MS). Resolves to { client, hello } or { client: null, reason } with reason one of
// "absent" (no endpoint), "untrusted" (ownership walk or device.pub failed: a squatter is possible),
// "bad-proof" / "key-mismatch" (the answer was not signed by device.pub's key), "not-ready", "timeout",
// "error". Never throws. `endpoint`, `devicePubPath`, `root` and `trustUid` exist for tests only.
export async function connect({ platform = process.platform, root = "/", trustUid = 0, endpoint = null, devicePubPath = null, budgetMs = CONNECT_BUDGET_MS, clientVersion = "0.0.0", host } = {}) {
  const started = Date.now();
  const ep = endpoint || endpointFor(platform);
  if (platform !== "win32") {
    const own = checkOwnedPath(ep, { root, trustUid, platform, kind: "socket" });
    if (own !== "ok") return { client: null, reason: own };
  }
  const spki = await readDevicePub({ platform, root, trustUid, path: devicePubPath });
  if (!spki) return { client: null, reason: "untrusted" };
  const sockPath = platform === "win32" || root === "/" ? ep : join(root, posix.relative("/", ep));
  const client = new GuarddClient(sockPath);
  const left = budgetMs - (Date.now() - started);
  if (left <= 0) { client.close(); return { client: null, reason: "timeout" }; }
  const nonce = randomBytes(16).toString("hex");
  let h;
  try {
    h = await client.request("hello", { proto: [PROTO_VERSION], client: "moorai-hook", clientVersion, nonce, ...(host ? { host } : {}) }, left);
  } catch (e) {
    client.close();
    return { client: null, reason: e && e.code === "not_ready" ? "not-ready" : e && e.code === "timeout" ? "timeout" : e && e.code === "absent" ? "absent" : "error" };
  }
  if (typeof h.keyId !== "string" || typeof h.helperVersion !== "string" || typeof h.proof !== "string" || typeof h.tenant !== "string") { client.close(); return { client: null, reason: "error" }; }
  if (h.keyId !== keyIdOfSpki(spki)) { client.close(); return { client: null, reason: "key-mismatch" }; }
  if (!verifyHelloProof(spki, helloProofInput(nonce, h.keyId, h.helperVersion), h.proof)) { client.close(); return { client: null, reason: "bad-proof" }; }
  return { client, hello: h };
}

class IpcError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

// One connection to the helper; requests are strictly sequential (contract §3.1). A request that times
// out closes the connection: a late answer can never be read as the answer to a later request.
export class GuarddClient {
  constructor(path) {
    this.nextId = 1;
    this.dec = new FrameDecoder();
    this.waiter = null;
    this.closed = false;
    this.sock = createConnection(path);
    this.sock.on("data", (chunk) => this.onData(chunk));
    this.sock.on("error", (e) => this.fail(new IpcError(e && (e.code === "ENOENT" || e.code === "ECONNREFUSED") ? "absent" : "error", "connection error")));
    this.sock.on("close", () => this.fail(new IpcError("error", "connection closed")));
  }
  onData(chunk) {
    let m;
    try { this.dec.push(chunk); m = this.dec.next(); } catch (e) { this.fail(new IpcError("error", e.message)); this.close(); return; }
    if (!m || !this.waiter) return;
    const w = this.waiter;
    this.waiter = null;
    clearTimeout(w.timer);
    if (m.id !== w.id) { w.reject(new IpcError("error", "reply id mismatch")); this.close(); return; }
    if (m.op === "error") { w.reject(new IpcError(typeof m.code === "string" ? m.code : "error", "helper error")); return; }
    if (m.op !== w.op) { w.reject(new IpcError("error", "reply op mismatch")); this.close(); return; }
    w.resolve(m);
  }
  fail(err) {
    if (!this.waiter) return;
    const w = this.waiter;
    this.waiter = null;
    clearTimeout(w.timer);
    w.reject(err);
  }
  request(op, fields, timeoutMs) {
    if (this.closed) return Promise.reject(new IpcError("error", "closed"));
    if (this.waiter) return Promise.reject(new IpcError("error", "a request is in flight"));
    const id = this.nextId++;
    let frame;
    try { frame = encodeFrame(buildRequest(op, id, fields)); } catch (e) { return Promise.reject(new IpcError("bad_request", e.message)); }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.waiter = null; reject(new IpcError("timeout", `${op} timed out`)); this.close(); }, Math.max(1, timeoutMs));
      this.waiter = { id, op, resolve, reject, timer };
      this.sock.write(frame);
    });
  }
  hello(fields, timeoutMs = CONNECT_BUDGET_MS) { return this.request("hello", fields, timeoutMs); }
  // { ifIat?, actor? } → the helper's policy reply ({ source, policy?, iat?, fetchedAt?, ageSec? }).
  policy({ ifIat, actor } = {}, timeoutMs = POLICY_FETCH_TIMEOUT_MS) { return this.request("policy", { ifIat, actor }, timeoutMs); }
  async submit(_alerts) { return notImplemented("submit"); }
  async call(_fields) { return notImplemented("call"); }
  async kill(_sessionHash) { return notImplemented("kill"); }
  async quarantine(_fields) { return notImplemented("quarantine"); }
  close() {
    if (this.closed) return;
    this.closed = true;
    try { this.sock.destroy(); } catch { /* already gone */ }
  }
}
