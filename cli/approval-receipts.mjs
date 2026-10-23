// Approval receipts (docs/approval-receipts.md): a short-lived, signed statement that MoorAI allowed or a person
// approved one exact MCP call, attached to the call's input as `_moorai: { receipt }` so the MCP server (a
// remote-administration hub) can skip its own approval queue for a receipt it can verify, and queue the call
// otherwise.
//
// Payload (canonical JSON, cli/canonical-json.mjs):
//   { v: 1, typ: "moorai.receipt", aud, tool (the bare MCP tool name), argsSha256, device, session, nonce (32 hex),
//     iat, exp (exp - iat <= 120), basis: "approved" | "allowed", approvalId? (approved only), approver? (console
//     only), keyId, keySource: "console" | "helper" | "device" }
// Signature: ed25519 over the UTF-8 bytes of "moorai-receipt|v1|" + canonicalJson(payload).
// Wire: base64url(canonicalJson(payload)) + "." + base64url(signature), no padding.
//
// Content-free: a receipt carries a SHA-256 of the arguments, never the arguments.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { canonicalJson } from "./canonical-json.mjs";
import { keyIdOfSpki } from "./guardd-client.mjs";

export const RECEIPT_V = 1;
export const RECEIPT_TYP = "moorai.receipt";
export const SIGN_PREFIX = "moorai-receipt|v1|";
export const MAX_TTL_SEC = 120;
export const DEFAULT_TTL_SEC = 60;
export const RESERVED_KEY = "_moorai";
export const KEY_SOURCES = Object.freeze(["console", "helper", "device"]);
export const BASES = Object.freeze(["approved", "allowed"]);
export const AUDIENCES_MAX = 16;
export const TOOLS_MAX = 64;
export const WIRE_MAX = 8192;
// The hub's tolerance for a receipt issued slightly in its future (clock skew between device and hub).
export const IAT_SKEW_SEC = 30;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const AUD_RE = /^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,127}$/;
const SERVER_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const TOOL_GLOB_RE = /^[A-Za-z0-9_.:*-]{1,128}$/;
const BARE_TOOL_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const KEY_ID_RE = /^[0-9a-f]{32}$/;
const APPROVAL_ID_RE = /^apr_[0-9A-HJKMNP-TV-Z]{26}$/;
const PSEUDONYM_RE = /^[A-Za-z0-9:_-]{1,128}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
export const WIRE_RE = /^[A-Za-z0-9_-]{1,8000}\.[A-Za-z0-9_-]{86}$/;
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const stderrWarn = (m) => { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* best effort */ } };

// The signed policy's approvalReceipts, validated: { v: 1, audiences: [{ aud, mcpServer, tools? }], ttlSec } or
// null (absent or unusable: nothing changes). ttlSec defaults to 60 and is capped at 120. A malformed audience is
// dropped with a warning that names its index, never a value.
export function receiptPolicy(policy, { warn = stderrWarn } = {}) {
  const ar = isObj(policy) ? policy.approvalReceipts : undefined;
  if (ar === undefined || ar === null) return null;
  if (!isObj(ar) || ar.v !== 1 || !Array.isArray(ar.audiences)) { warn("approvalReceipts ignored: not { v: 1, audiences: [...] }"); return null; }
  const audiences = [];
  ar.audiences.slice(0, AUDIENCES_MAX).forEach((a, i) => {
    if (!isObj(a) || typeof a.aud !== "string" || !AUD_RE.test(a.aud)) { warn(`approvalReceipts audience #${i} dropped: aud`); return; }
    if (typeof a.mcpServer !== "string" || !SERVER_RE.test(a.mcpServer)) { warn(`approvalReceipts audience #${i} dropped: mcpServer`); return; }
    const out = { aud: a.aud, mcpServer: a.mcpServer };
    if (a.tools !== undefined) {
      if (!Array.isArray(a.tools) || !a.tools.length || a.tools.length > TOOLS_MAX || !a.tools.every((t) => typeof t === "string" && TOOL_GLOB_RE.test(t))) { warn(`approvalReceipts audience #${i} dropped: tools`); return; }
      out.tools = [...new Set(a.tools)];
    }
    audiences.push(out);
  });
  if (ar.audiences.length > AUDIENCES_MAX) warn(`approvalReceipts: at most ${AUDIENCES_MAX} audiences`);
  if (!audiences.length) return null;
  let ttlSec = DEFAULT_TTL_SEC;
  if (ar.ttlSec !== undefined) {
    if (Number.isInteger(ar.ttlSec) && ar.ttlSec >= 1) ttlSec = Math.min(ar.ttlSec, MAX_TTL_SEC);
    else warn("approvalReceipts.ttlSec ignored: not a positive integer");
  }
  return { v: 1, audiences, ttlSec };
}

// "mcp__<server>__<tool>" → { server, tool } (the tool as the MCP server names it), else null. The server segment
// is everything up to the first "__" after the prefix, as Claude Code builds the name (a plugin server's segment is
// "plugin_<plugin>_<server>").
export function splitMcpTool(name) {
  const m = /^mcp__(.+?)__(.+)$/.exec(String(name || ""));
  if (!m || !BARE_TOOL_RE.test(m[2])) return null;
  return { server: m[1], tool: m[2] };
}

// A tool glob: "*" matches any run of characters, everything else literally; anchored at both ends.
function globMatch(glob, s) {
  const re = new RegExp(`^${glob.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return re.test(s);
}

// The audience an MCP call gets a receipt for: its server equals an audience's mcpServer (exactly) and, when the
// audience lists tools, the bare tool name matches one glob; with no list, every tool of the server. A tool in
// HUB_EXCLUDED_TOOLS never gets one (as the console refuses them). → { aud, mcpServer, tool } or null.
export function matchAudience(rp, mcpToolName) {
  if (!rp || !Array.isArray(rp.audiences)) return null;
  const t = splitMcpTool(mcpToolName);
  if (!t || HUB_EXCLUDED_TOOLS.includes(t.tool)) return null;
  for (const a of rp.audiences) {
    if (a.mcpServer !== t.server) continue;
    if (a.tools && !a.tools.some((g) => globMatch(g, t.tool))) continue;
    return { aud: a.aud, mcpServer: a.mcpServer, tool: t.tool };
  }
  return null;
}

// The input without its top-level `_moorai` key (a copy; the caller's object is untouched). had: the key was there.
export function stripReserved(input) {
  if (!isObj(input) || !Object.prototype.hasOwnProperty.call(input, RESERVED_KEY)) return { value: input, had: false };
  const { [RESERVED_KEY]: _drop, ...rest } = input;
  return { value: rest, had: true };
}

// Lowercase hex SHA-256 of the canonical JSON of the PARSED arguments with `_moorai` removed. Never raw bytes: the
// MCP server sees parsed arguments only, and re-serializes them the same way.
export function argsSha256(input) {
  return createHash("sha256").update(canonicalJson(stripReserved(input ?? {}).value), "utf8").digest("hex");
}

export function b64url(buf) { return Buffer.from(buf).toString("base64url"); }
export function fromB64url(s) { return Buffer.from(String(s), "base64url"); }

export function signingInput(payload) { return Buffer.from(SIGN_PREFIX + canonicalJson(payload), "utf8"); }

// The receipt payload, validated, or null. ttlSec 1..120 sets exp = iat + ttlSec. Rules: tool is a bare name (no
// mcp__ prefix); basis approved needs keySource console and an approvalId; approvalId only with approved; approver
// only on a console receipt; a device receipt is always basis allowed.
export function buildPayload({ aud, tool, input, argsHash, device = "", session = "", nonce, iat, ttlSec = DEFAULT_TTL_SEC, basis, approvalId, approver, keyId = "", keySource }) {
  if (typeof aud !== "string" || !AUD_RE.test(aud)) return null;
  if (typeof tool !== "string" || !BARE_TOOL_RE.test(tool) || tool.startsWith("mcp__")) return null;
  if (typeof nonce !== "string" || !NONCE_RE.test(nonce)) return null;
  if (!Number.isInteger(iat) || iat < 0) return null;
  if (!Number.isInteger(ttlSec) || ttlSec < 1 || ttlSec > MAX_TTL_SEC) return null;
  if (!KEY_SOURCES.includes(keySource) || !BASES.includes(basis)) return null;
  if (basis === "approved" && (keySource !== "console" || typeof approvalId !== "string" || !APPROVAL_ID_RE.test(approvalId))) return null;
  if (basis !== "approved" && approvalId !== undefined) return null;
  if (approver !== undefined && (keySource !== "console" || typeof approver !== "string" || !PSEUDONYM_RE.test(approver))) return null;
  const h = argsHash !== undefined ? argsHash : argsSha256(input);
  if (typeof h !== "string" || !HEX64_RE.test(h)) return null;
  const p = { v: RECEIPT_V, typ: RECEIPT_TYP, aud, tool, argsSha256: h, device: String(device), session: String(session), nonce, iat, exp: iat + ttlSec, basis };
  if (approvalId !== undefined) p.approvalId = approvalId;
  if (approver !== undefined) p.approver = approver;
  p.keyId = String(keyId);
  p.keySource = keySource;
  return p;
}

export function encodeWire(payload, sig) { return `${b64url(Buffer.from(canonicalJson(payload), "utf8"))}.${b64url(sig)}`; }

// → { payload, payloadBytes, sig } or null (not two base64url parts, or a payload that is not a JSON object).
export function decodeWire(wire) {
  if (typeof wire !== "string" || wire.length > WIRE_MAX) return null;
  const parts = wire.split(".");
  if (parts.length !== 2 || !B64URL_RE.test(parts[0]) || !B64URL_RE.test(parts[1])) return null;
  const payloadBytes = fromB64url(parts[0]);
  const sig = fromB64url(parts[1]);
  let payload;
  try { payload = JSON.parse(payloadBytes.toString("utf8")); } catch { return null; }
  if (!isObj(payload)) return null;
  return { payload, payloadBytes, sig };
}

// A public key as the raw 32-byte ed25519 key in base64url without padding. Accepts a KeyObject, a base64 SPKI DER
// string, or an already-raw base64url key.
export function rawPublicKey(key) {
  try {
    if (key && typeof key === "object" && key.type) {
      const k = key.type === "public" ? key : createPublicKey(key);
      return k.export({ type: "spki", format: "der" }).subarray(12).toString("base64url");
    }
    const s = String(key || "");
    if (/^[A-Za-z0-9_-]{43}$/.test(s)) return s;
    const der = Buffer.from(s, "base64");
    if (der.length === 44 && der.subarray(0, 12).equals(SPKI_ED25519_PREFIX)) return der.subarray(12).toString("base64url");
  } catch { /* fall through */ }
  return "";
}

// keyId: the first 32 lowercase hex characters of SHA-256 over the raw 32-byte public key — the convention of the
// console's policy-signing key id and the device key id (cli/guardd-client.mjs keyIdOfSpki).
export function receiptKeyId(key) {
  const raw = rawPublicKey(key);
  if (!raw) return "";
  try { return keyIdOfSpki(Buffer.concat([SPKI_ED25519_PREFIX, fromB64url(raw)]).toString("base64")); } catch { return ""; }
}

const keyObjOf = (raw) => createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, fromB64url(raw)]), format: "der", type: "spki" });

// Mint a receipt. signer: { sign(bytes) → Buffer (64-byte ed25519 signature), publicKey (KeyObject or base64 SPKI
// or raw base64url) }. → the wire string, or null when the payload is refused or signing fails.
export function mintReceipt({ signer, ...fields }) {
  try {
    const keyId = receiptKeyId(signer.publicKey);
    if (!keyId) return null;
    const p = buildPayload({ ...fields, keyId });
    if (!p) return null;
    const sig = signer.sign(signingInput(p));
    if (!sig || sig.length !== 64) return null;
    return encodeWire(p, sig);
  } catch { return null; }
}

// True when every number in the value is an integer within ±(2^53 - 1): the only numbers a hub canonicalizer can
// render byte-for-byte as JSON.stringify does without a float formatter.
export function portableNumbers(v) {
  if (typeof v === "number") return Number.isSafeInteger(v);
  if (Array.isArray(v)) return v.every(portableNumbers);
  if (isObj(v)) return Object.values(v).every(portableNumbers);
  return true;
}

const ALLOWED_FIELDS = new Set(["v", "typ", "aud", "tool", "argsSha256", "device", "session", "nonce", "iat", "exp", "basis", "approvalId", "approver", "keyId", "keySource"]);

// The reference verifier: the hub's steps (docs/approval-receipts.md §6), in order. keys: [{ keyId, publicKey (raw
// base64url), keySource }] pinned from the hub's config — the key's keySource, never the payload's, decides trust; aud: the hub's own audience id; tool: the called tool's bare name;
// input: the parsed arguments as received (with or without _moorai); seen: replay cache holding "nonce:<nonce>" and
// "approvalId:<approvalId>" — each is single-use on its own (one approval runs exactly one action).
// → { ok, reason, skipQueue, queueReason }. Only ok from a key pinned as console with basis approved + approvalId, or
// a key pinned as helper, AND arguments whose numbers are all safe integers, skips the queue.
export function verifyReceipt(wire, { keys = [], aud, tool, input, nowSec, seen } = {}) {
  const no = (reason) => ({ ok: false, reason, skipQueue: false, queueReason: "invalid receipt" });
  const d = decodeWire(wire);
  if (!d) return no("malformed");
  const p = d.payload;
  if (canonicalJson(p) !== d.payloadBytes.toString("utf8")) return no("not_canonical");
  if (Object.keys(p).some((k) => !ALLOWED_FIELDS.has(k))) return no("unknown_field");
  if (p.v !== RECEIPT_V || p.typ !== RECEIPT_TYP) return no("bad_version");
  if (typeof p.keyId !== "string" || !KEY_ID_RE.test(p.keyId)) return no("unknown_key");
  const k = keys.find((x) => x && x.keyId === p.keyId);
  if (!k) return no("unknown_key");
  let good = false;
  try { good = d.sig.length === 64 && edVerify(null, Buffer.concat([Buffer.from(SIGN_PREFIX, "utf8"), d.payloadBytes]), keyObjOf(k.publicKey), d.sig); } catch { good = false; }
  if (!good) return no("bad_signature");
  if (p.aud !== aud) return no("wrong_aud");
  if (p.tool !== tool) return no("wrong_tool");
  if (p.argsSha256 !== argsSha256(input)) return no("args_mismatch");
  if (!Number.isInteger(p.iat) || !Number.isInteger(p.exp) || p.exp <= p.iat) return no("bad_time");
  if (p.exp - p.iat > MAX_TTL_SEC) return no("ttl_too_long");
  if (p.iat > nowSec + IAT_SKEW_SEC) return no("not_yet_valid");
  if (nowSec >= p.exp) return no("expired");
  if (typeof p.nonce !== "string" || !NONCE_RE.test(p.nonce)) return no("malformed");
  if (!KEY_SOURCES.includes(p.keySource) || !BASES.includes(p.basis)) return no("bad_basis");
  // Trust is bound to the PINNED key: a payload claiming a source its key was not pinned for is refused.
  if (!KEY_SOURCES.includes(k.keySource) || p.keySource !== k.keySource) return no("bad_basis");
  if (p.basis === "approved" && (p.keySource !== "console" || typeof p.approvalId !== "string" || !APPROVAL_ID_RE.test(p.approvalId))) return no("bad_basis");
  if (p.basis !== "approved" && p.approvalId !== undefined) return no("bad_basis");
  if (p.approver !== undefined && p.keySource !== "console") return no("bad_basis");
  const nk = `nonce:${p.nonce}`, ak = p.approvalId ? `approvalId:${p.approvalId}` : null;
  if (seen && seen.has(nk)) return no("replay");
  if (seen && ak && seen.has(ak)) return no("replay");
  if (seen) { seen.add(nk); if (ak) seen.add(ak); }
  const src = k.keySource;
  if (src === "device") return { ok: true, reason: null, skipQueue: false, queueReason: "keySource device" };
  if (src === "console" && !(p.basis === "approved" && p.approvalId)) return { ok: true, reason: null, skipQueue: false, queueReason: "basis allowed" };
  if (!portableNumbers(input)) return { ok: true, reason: null, skipQueue: false, queueReason: "non-integer number" };
  return { ok: true, reason: null, skipQueue: true, queueReason: null };
}

// The approval request's actionHash for an MCP call covered by approvalReceipts, bound to what the receipt will
// carry so the console can check the two agree before it mints (docs/approval-receipts.md §5):
//   actionHash = contentHash("approval" + "\u0000" + canonicalJson({ argsSha256, aud, tool: <bare tool name> }))
// contentHash is the tenant-keyed h2 HMAC of cli/content-hash.mjs. aud is inside it so the audience the console mints
// for is bound by the chained actionHash. This returns the string that is hashed.
export function receiptActionHashInput(bareTool, argsHash, aud) {
  return `approval\u0000${canonicalJson({ argsSha256: argsHash, aud, tool: bareTool })}`;
}

// The tools a remote-administration hub binds receipts to, for policy examples and editors (docs/approval-receipts.md
// §4). Receipts are single-use per hub request.
export const HUB_RECEIPT_TOOLS = Object.freeze(["run_command", "job_start", "job_stop", "update_agent", "dissolve_agent", "device_action", "message_user", "install_package", "uninstall_package", "run_plugin", "system_report", "check_updates", "compliance_posture", "run_script", "fleet_run", "fleet_report", "run_script_fleet", "screenshot", "camera_snapshot"]);
// Never in an example or default list: the hub never accepts a receipt for them (input events, file transfer, and
// push_file, whose staged bytes a receipt cannot cover).
export const HUB_EXCLUDED_TOOLS = Object.freeze(["click", "type_text", "press_key", "upload_file", "download_file", "push_file"]);
