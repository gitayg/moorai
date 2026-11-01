// A faithful copy of the console's device-signed request check, for the agent's guardd policy tests. Copied
// VERBATIM from RAISEME-server branch integ/console3 (commit 2c999ca), imports reduced to node:crypto:
//   server/device-keys.js:14-15   DEVICE_SIG_VERSION, SKEW_MS
//   server/device-keys.js:43-71   constants, wireCanonical, parseCanonicalBody
//   server/device-keys.js:73-91   keyIdOfSpki, verifyEd, devreqSigningInput
//   server/device-keys.js:102-133 header, verifySignedRequest
//   server/approval-receipts.js:179 receiptTokenFp
// and receiptAuthFor (server/approval-receipts.js:183-189) with its two store reads injected. The console
// calls receiptAuthFor from /api/policy with url = req.url (the raw path and query as sent) and the request's
// headers (server/server.js:1132), and serves a receipt only when receiptAuth.device equals the request's
// device and receiptAuth.tokenFp the posting token's (server/approvals.js:195). Re-copy when the console
// changes; do not edit the copied lines by hand.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

export const DEVICE_SIG_VERSION = 1;
export const SKEW_MS = 300_000;

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const HEX32 = /^[0-9a-f]{32}$/;
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const sha256hex = (b) => createHash("sha256").update(b).digest("hex");

// Strict canonical JSON: byte-identical to policy-sign.js canonicalJson over the wire value set (null,
// booleans, strings, safe integers, arrays, plain objects); anything else throws.
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

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// The parsed body, or null when the bytes are not UTF-8 JSON that is exactly its own canonical form.
export function parseCanonicalBody(buf) {
  try {
    const text = UTF8.decode(buf);
    const v = JSON.parse(text);
    return wireCanonical(v) === text ? v : null;
  } catch { return null; }
}

export function keyIdOfSpki(spkiB64) {
  const der = Buffer.from(String(spkiB64 || ""), "base64");
  if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_ED25519_PREFIX)) return null;
  return sha256hex(der.subarray(12)).slice(0, 32);
}

export function verifyEd(spkiB64, input, sigB64) {
  try {
    if (!keyIdOfSpki(spkiB64)) return false;
    const key = createPublicKey({ key: Buffer.from(spkiB64, "base64"), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(input, "utf8"), key, Buffer.from(String(sigB64), "base64"));
  } catch { return false; }
}

// ---- signed-byte forms (contract §5.3, §6.2, §9.4) ----
export function devreqSigningInput({ method, path, tenant, deviceId, keyId, ts, nonce, body }) {
  const bytes = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  return `moorai-devreq|v${DEVICE_SIG_VERSION}|${method}|${path}|${tenant}|${deviceId}|${keyId}|${ts}|${nonce}|${sha256hex(bytes)}`;
}

const header = (headers, name) => {
  const v = headers[name.toLowerCase()];
  return typeof v === "string" ? v : "";
};

// Verify one device-signed request (contract §6.2–§6.5). Pure: the store is reached only through
//   lookupKey(tenant, deviceId, keyId) -> { publicKey } | null   (the CURRENT key for that device)
//   seenNonce(keyId, nonce, tsMs) -> boolean                      (true = replay; otherwise records it)
// `tenant` is the install-token tenant (or, for register, the enrol-secret tenant). `publicKey` lets register
// verify proof of possession against the key in its own body. The order is fixed: shape, skew, key,
// signature, then replay (so unauthenticated junk never fills the nonce cache), then the body.
// Returns { ok: true, body, deviceId, keyId, tsMs } or { ok: false, status, error, serverTime? }.
export function verifySignedRequest({ method, path, headers = {}, rawBody, tenant, lookupKey, seenNonce, publicKey = null, now = Date.now() }) {
  const deviceId = header(headers, "X-Device-Id"), keyId = header(headers, "X-Device-Key");
  const ts = header(headers, "X-Device-Ts"), nonce = header(headers, "X-Device-Nonce"), sig = header(headers, "X-Device-Sig");
  if (!HEX32.test(deviceId) || !HEX32.test(keyId) || !TS_RE.test(ts) || !HEX32.test(nonce) || !sig) return { ok: false, status: 401, error: "bad_signature_headers" };
  const tsMs = Date.parse(ts);
  if (!Number.isFinite(tsMs)) return { ok: false, status: 401, error: "bad_signature_headers" };
  if (Math.abs(now - tsMs) > SKEW_MS) return { ok: false, status: 401, error: "clock_skew", serverTime: new Date(now).toISOString() };
  const pub = publicKey ?? lookupKey?.(tenant, deviceId, keyId)?.publicKey;
  if (!pub || keyIdOfSpki(pub) !== keyId) return { ok: false, status: 401, error: "unknown_key" };
  const body = rawBody == null ? Buffer.alloc(0) : Buffer.from(rawBody);
  const input = devreqSigningInput({ method, path, tenant, deviceId, keyId, ts, nonce, body });
  if (!verifyEd(pub, input, sig)) return { ok: false, status: 401, error: "bad_signature" };
  if (seenNonce(keyId, nonce, tsMs)) return { ok: false, status: 409, error: "replay" };
  if (method === "GET") return body.length ? { ok: false, status: 400, error: "non_canonical" } : { ok: true, body: null, deviceId, keyId, tsMs };
  const parsed = parseCanonicalBody(body);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { ok: false, status: 400, error: "non_canonical" };
  if (parsed.tenant !== tenant || parsed.deviceId !== deviceId) return { ok: false, status: 400, error: "binding_mismatch" };
  return { ok: true, body: parsed, deviceId, keyId, tsMs };
}


export const receiptTokenFp = (token) => (token ? createHash("sha256").update("moorai-receipt-token|v1|" + String(token), "utf8").digest("hex").slice(0, 32) : null);

// server/approval-receipts.js:183-189 with `lookupDeviceKey(store)`, `nonceStore(store, now)` and the
// device_keys row read passed in: lookupKey(tenant, deviceId, keyId) -> { publicKey } | null;
// seenNonce(keyId, nonce, tsMs) -> bool; boundRow(tenant, deviceId, keyId) -> { device, bound } | null.
export function receiptAuthFor({ lookupKey, seenNonce, boundRow }, tenant, { method = "GET", url, headers = {}, installToken, now = Date.now() } = {}) {
  if (!installToken || !tenant || !headers["x-device-sig"]) return null;
  const v = verifySignedRequest({ method, path: url, headers, rawBody: null, tenant, lookupKey, seenNonce, now });
  if (!v.ok) return null;
  const row = boundRow(tenant, v.deviceId, v.keyId);
  return row && row.bound && row.device ? { device: row.device, tokenFp: receiptTokenFp(installToken) } : null;
}
