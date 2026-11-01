// F15 token usage records, shared by the model proxy (model-proxy/token-usage.mjs) and the Claude Code
// transcript reader (cli/transcript-usage.mjs). Contract F28 §4.1: POST /api/token-usage, body
//   { v: 1, user, device, platform, source: "model-proxy" | "transcript", instance, buckets: [...] }
// where each bucket is CUMULATIVE for (hour, agentName, provider, model, projectKey) within one instance:
// the console upserts MAX(old, new) per counter, so a resend never double-counts.
//
// Metadata only. A bucket holds an hour, an agent name, a provider enum, a model id (MODEL_RE, else
// "other"), a keyed project hash or null, and six counters. Never a prompt, a response, a path or a key.
//
// NORMALISED FIELDS (each provider's documented usage object; `in` never includes cached input, so a
// price per input token is not applied to cached tokens twice):
//   anthropic  usage.input_tokens → in, output_tokens → out, cache_read_input_tokens → cacheRead,
//              cache_creation_input_tokens → cacheWrite. Anthropic reports the three input kinds apart.
//   openai     usage.prompt_tokens − prompt_tokens_details.cached_tokens → in, completion_tokens → out,
//              cached_tokens → cacheRead ("Cached tokens present in the prompt": part of prompt_tokens).
//   google     usageMetadata.promptTokenCount − cachedContentTokenCount → in, candidatesTokenCount +
//              thoughtsTokenCount → out (thinking tokens are reported apart from the candidates),
//              cachedContentTokenCount → cacheRead.
//   ollama     prompt_eval_count → in, eval_count → out (on the final, done: true object).
import { PROVIDERS, MODEL_RE } from "./action-trail.mjs";

export const USAGE_PATH = "/api/token-usage";
export const SOURCES = Object.freeze(["model-proxy", "transcript"]);
export const INSTANCE_RE = /^[a-z]{2}-[0-9a-f]{8}$/;
export const MAX_BUCKETS = 500;
export const MAX_BODY_BYTES = 65536;
const PACK_BYTES = 60000;                  // headroom under the console's 64 KiB body cap
const COUNTERS = ["requests", "requestsNoUsage", "in", "out", "cacheRead", "cacheWrite"];
const MAX_COUNT = 1e15;

const num = (v) => (typeof v === "number" && Number.isFinite(v) && v > 0 && v < MAX_COUNT ? Math.floor(v) : 0);
const has = (o, ...keys) => o && typeof o === "object" && keys.some((k) => typeof o[k] === "number");

// The provider's usage object → { in, out, cacheRead, cacheWrite }, or null when it carries none.
export function normalizeUsage(provider, u) {
  if (!u || typeof u !== "object") return null;
  if (provider === "anthropic") {
    if (!has(u, "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")) return null;
    return { in: num(u.input_tokens), out: num(u.output_tokens), cacheRead: num(u.cache_read_input_tokens), cacheWrite: num(u.cache_creation_input_tokens) };
  }
  if (provider === "openai") {
    if (!has(u, "prompt_tokens", "completion_tokens")) return null;
    const cached = num(u.prompt_tokens_details && u.prompt_tokens_details.cached_tokens);
    return { in: Math.max(0, num(u.prompt_tokens) - cached), out: num(u.completion_tokens), cacheRead: cached, cacheWrite: 0 };
  }
  if (provider === "google") {
    if (!has(u, "promptTokenCount", "candidatesTokenCount")) return null;
    const cached = num(u.cachedContentTokenCount);
    return { in: Math.max(0, num(u.promptTokenCount) - cached), out: num(u.candidatesTokenCount) + num(u.thoughtsTokenCount), cacheRead: cached, cacheWrite: 0 };
  }
  if (provider === "ollama") {
    if (!has(u, "prompt_eval_count", "eval_count")) return null;
    return { in: num(u.prompt_eval_count), out: num(u.eval_count), cacheRead: 0, cacheWrite: 0 };
  }
  return null;
}
// Field-wise max: a stream reports cumulative counts, so the largest seen is the total.
export function mergeUsage(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  return { in: Math.max(a.in, b.in), out: Math.max(a.out, b.out), cacheRead: Math.max(a.cacheRead, b.cacheRead), cacheWrite: Math.max(a.cacheWrite, b.cacheWrite) };
}

export const hourStart = (ms) => new Date(Math.floor(ms / 3600_000) * 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
export const cleanModel = (m) => (typeof m === "string" && MODEL_RE.test(m) ? m : "other");
export const cleanProvider = (p) => (PROVIDERS.includes(p) ? p : "other");

// Cumulative buckets with a dirty set: add() grows a bucket and marks it; markSent(list) clears the mark
// only when the bucket has not grown since that list was taken.
export function createBuckets({ max = 20000 } = {}) {
  const map = new Map();
  const keyOf = (k) => JSON.stringify([k.hour, k.agentName ?? null, k.provider, k.model, k.projectKey ?? null]);
  return {
    add(k, usage, n = 1) {
      const key = keyOf(k);
      let b = map.get(key);
      if (!b) {
        if (map.size >= max) return false;
        b = { hour: k.hour, agentName: k.agentName ?? null, provider: k.provider, model: k.model, projectKey: k.projectKey ?? null, requests: 0, requestsNoUsage: 0, in: 0, out: 0, cacheRead: 0, cacheWrite: 0, rev: 0, sent: -1 };
        map.set(key, b);
      }
      b.requests += n;
      if (!usage) b.requestsNoUsage += n;
      else { b.in += usage.in; b.out += usage.out; b.cacheRead += usage.cacheRead; b.cacheWrite += usage.cacheWrite; }
      b.rev++;
      return true;
    },
    // Copies of the unsent buckets; each carries its revision (not enumerable, so never serialized).
    dirty() {
      const out = [];
      for (const b of map.values()) if (b.rev !== b.sent) { const { rev, sent: _s, ...rest } = b; out.push(Object.defineProperty(rest, "_rev", { value: rev, enumerable: false })); }
      return out;
    },
    markSent(list) { for (const x of list) { const b = map.get(keyOf(x)); if (b) b.sent = x._rev ?? b.rev; } },
    prune(beforeHour) { for (const [k, b] of map) if (b.hour < beforeHour && b.rev === b.sent) map.delete(k); },
    size: () => map.size,
    toJSON() { return [...map.values()]; },
    load(list) { for (const b of Array.isArray(list) ? list : []) { if (!b || typeof b.hour !== "string") continue; const x = { hour: b.hour, agentName: b.agentName ?? null, provider: cleanProvider(b.provider), model: cleanModel(b.model), projectKey: typeof b.projectKey === "string" ? b.projectKey : null, rev: num(b.rev), sent: Number.isInteger(b.sent) ? b.sent : -1 }; for (const c of COUNTERS) x[c] = num(b[c]); map.set(keyOf(x), x); } }
  };
}

// Bodies of at most MAX_BUCKETS buckets and PACK_BYTES bytes each. Buckets keep their order.
export function packBodies(header, buckets) {
  const out = [];
  let cur = [], bytes = Buffer.byteLength(JSON.stringify({ ...header, buckets: [] }));
  const base = bytes;
  for (const b of buckets) {
    const n = Buffer.byteLength(JSON.stringify(b)) + 1;
    if (cur.length && (cur.length >= MAX_BUCKETS || bytes + n > PACK_BYTES)) { out.push({ ...header, buckets: cur }); cur = []; bytes = base; }
    cur.push(b); bytes += n;
  }
  if (cur.length) out.push({ ...header, buckets: cur });
  return out;
}

// One POST. → { ok, status } (status 0: no answer). Never throws.
export async function postTokenUsage({ config, body, fetchImpl = globalThis.fetch, timeoutMs = 5000 }) {
  try {
    const r = await fetchImpl(`${config.serverUrl}${USAGE_PATH}`, { method: "POST", headers: { "Content-Type": "application/json", ...(config.installToken ? { "X-Install-Token": config.installToken } : {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
    return { ok: !!(r && r.ok), status: r ? r.status : 0 };
  } catch { return { ok: false, status: 0 }; }
}

// Posts every dirty bucket. A 404 or 405 means a console without the route: the caller pauses for a day.
// → { sent, failed, unsupported }
export async function flushBuckets({ buckets, header, config, fetchImpl }) {
  const dirty = buckets.dirty();
  let sent = 0, failed = 0, unsupported = false;
  for (const body of packBodies(header, dirty)) {
    const r = await postTokenUsage({ config, body, fetchImpl });
    if (r.ok) { buckets.markSent(body.buckets); sent += body.buckets.length; continue; }
    failed += body.buckets.length;
    if (r.status === 404 || r.status === 405) { unsupported = true; break; }
  }
  return { sent, failed, unsupported };
}
