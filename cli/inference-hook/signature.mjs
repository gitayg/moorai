// Standard Webhooks verification for Anthropic's Inference hooks requests, as documented at
// platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint ("Verify the signature"):
//
//   webhook-id         unique per delivery, equals the body's request_id; the first signed component
//   webhook-timestamp  Unix seconds as a decimal string; rejected more than five minutes from our clock
//   webhook-signature  one or more space-separated `v1,<base64>` values, each an HMAC-SHA256 over
//                      `{webhook-id}.{webhook-timestamp}.{raw body bytes}`; any match accepts
//
// The secret is the value after `whsec_`, standard base64 (a URL-safe decoder derives the wrong key).
// Several secrets may be configured at once, so the previous one keeps verifying through a rotation.
import { createHmac, timingSafeEqual } from "node:crypto";

export const TOLERANCE_SECONDS = 300;
export const MAX_ID_LENGTH = 256;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const ID_RE = /^[\x21-\x7e]+$/;
const TS_RE = /^\d{1,12}$/;

// "whsec_…" tokens separated by whitespace → key buffers. Throws on anything that is not standard base64
// of at least 16 bytes, so a mangled secret stops the server at start instead of rejecting every request.
export function parseSecrets(text) {
  const tokens = String(text || "").split(/\s+/).filter(Boolean);
  if (!tokens.length) throw new Error("no signing secret");
  return tokens.map((t, i) => {
    const b = t.startsWith("whsec_") ? t.slice(6) : t;
    if (!B64.test(b) || b.length % 4 !== 0) throw new Error(`signing secret ${i + 1} is not standard base64 after the whsec_ prefix`);
    const key = Buffer.from(b, "base64");
    if (key.length < 16) throw new Error(`signing secret ${i + 1} decodes to fewer than 16 bytes`);
    return key;
  });
}

export function signatureFor(key, id, timestamp, raw) {
  return "v1," + createHmac("sha256", key).update(`${id}.${timestamp}.`, "utf8").update(raw).digest("base64");
}

// Sign a body the way Anthropic does (the `test` command and the tests use it).
export function signHeaders(secret, raw, { id, timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const [key] = parseSecrets(secret);
  const ts = String(timestamp);
  return { "webhook-id": id, "webhook-timestamp": ts, "webhook-signature": signatureFor(key, id, ts, Buffer.isBuffer(raw) ? raw : Buffer.from(raw)) };
}

const header = (headers, name) => { const v = headers[name]; return typeof v === "string" ? v : undefined; };

// headers: Node's lower-cased IncomingHttpHeaders. → { ok: true, id, timestamp } | { ok: false, reason }
export function verify(keys, headers, raw, nowSeconds = Date.now() / 1000) {
  const id = header(headers, "webhook-id"), ts = header(headers, "webhook-timestamp"), sigs = header(headers, "webhook-signature");
  if (id === undefined || ts === undefined || sigs === undefined) return { ok: false, reason: "unsigned" };
  if (!id || id.length > MAX_ID_LENGTH || !ID_RE.test(id)) return { ok: false, reason: "bad-id" };
  if (!TS_RE.test(ts)) return { ok: false, reason: "bad-timestamp" };
  const timestamp = Number(ts);
  if (Math.abs(nowSeconds - timestamp) > TOLERANCE_SECONDS) return { ok: false, reason: "stale-timestamp" };
  const candidates = sigs.split(" ").filter(Boolean).map((c) => Buffer.from(c, "utf8"));
  for (const key of keys) {
    const expected = Buffer.from(signatureFor(key, id, ts, raw), "utf8");
    for (const c of candidates) if (c.length === expected.length && timingSafeEqual(c, expected)) return { ok: true, id, timestamp };
  }
  return { ok: false, reason: "bad-signature" };
}

// webhook-ids accepted within the timestamp tolerance. An id only needs remembering until its timestamp
// leaves the window (after that the timestamp check rejects it anyway). Bounded: past `max` entries the
// expired ones are swept, then the soonest-to-expire are evicted.
export function createReplayCache({ max = 200000, toleranceSeconds = TOLERANCE_SECONDS } = {}) {
  const seen = new Map();
  const sweep = (now) => { for (const [id, exp] of seen) if (exp <= now) seen.delete(id); };
  return {
    // true when this id was not seen in its window (and records it); false for a replay.
    claim(id, timestamp, nowSeconds = Date.now() / 1000) {
      const exp = seen.get(id);
      if (exp !== undefined && exp > nowSeconds) return false;
      if (seen.size >= max) {
        sweep(nowSeconds);
        if (seen.size >= max) {
          const victims = [...seen.entries()].sort((a, b) => a[1] - b[1]).slice(0, Math.max(1, Math.floor(max / 10)));
          for (const [v] of victims) seen.delete(v);
        }
      }
      seen.set(id, timestamp + toleranceSeconds + 1);
      return true;
    },
    size: () => seen.size
  };
}
