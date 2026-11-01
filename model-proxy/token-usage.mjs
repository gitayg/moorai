// F15 token usage in the model proxy: the token counts each provider returns, read from the response the
// proxy already parses (a JSON body, SSE events, NDJSON lines), added to cumulative hourly buckets and
// posted to the console every FLUSH_MS (5 minutes) and at close. Source "model-proxy", instance
// "mp-<8 hex>", random per process start (cli/token-usage.mjs has the shape and the field mapping).
//
// The proxy never changes a request to get usage: an OpenAI stream sent without
// stream_options.include_usage has no usage chunk, and counts as a request in requestsNoUsage, as does a
// response that ended early or an error answer. Only usage fields are read from an event; the event text is
// parsed only when it can hold one (a cheap substring test first). Enrolled proxies only.
import { randomBytes } from "node:crypto";
import { normalizeUsage, mergeUsage, hourStart, cleanModel, cleanProvider, createBuckets, flushBuckets } from "../cli/token-usage.mjs";

export const FLUSH_MS = 5 * 60_000;
const PAUSE_MS = 24 * 3600_000;
const HINT = /usage|eval_count/;

// The usage object one parsed payload carries for this provider, or undefined.
function usageIn(provider, v) {
  if (!v || typeof v !== "object") return undefined;
  if (Array.isArray(v)) { let u = null; for (const x of v.slice(0, 4096)) u = mergeUsage(u, usageIn(provider, x) || null); return u || undefined; }
  if (provider === "anthropic") return normalizeUsage(provider, (v.type === "message_start" && v.message ? v.message.usage : v.usage)) || undefined;
  if (provider === "openai") return normalizeUsage(provider, v.usage) || undefined;
  if (provider === "google") return normalizeUsage(provider, v.usageMetadata) || undefined;
  if (provider === "ollama") return normalizeUsage(provider, v) || undefined;
  return undefined;
}

// config: { serverUrl, installToken }; identity: { user, device, platform } (the runtime's).
export function createUsageMeter({ config, identity, enrolled, fetch: fetchImpl = globalThis.fetch, flushMs = FLUSH_MS, now = Date.now, instance = `mp-${randomBytes(4).toString("hex")}` } = {}) {
  const buckets = createBuckets();
  const header = { v: 1, user: identity && identity.user, device: identity && identity.device, platform: identity && identity.platform, source: "model-proxy", instance };
  let pausedUntil = 0, flushing = null;
  const flush = () => {
    if (!enrolled || !config || !config.serverUrl) return Promise.resolve();
    if (now() < pausedUntil) return Promise.resolve();
    return (flushing ||= flushBuckets({ buckets, header, config, fetchImpl }).then((r) => {
      if (r.unsupported) pausedUntil = now() + PAUSE_MS;
      buckets.prune(hourStart(now() - 2 * 3600_000));
    }).catch(() => {}).finally(() => { flushing = null; }));
  };
  const timer = enrolled && flushMs > 0 ? setInterval(flush, flushMs) : null;
  if (timer) timer.unref();
  return {
    instance,
    // One model request: the collector the response side feeds. Its bucket hour is the request's start.
    begin({ provider, model, agentName }) {
      const p = cleanProvider(provider), k = { hour: hourStart(now()), agentName: agentName || null, provider: p, model: cleanModel(model), projectKey: null };
      let usage = null, done = false;
      return {
        body(json) { if (!done) usage = mergeUsage(usage, usageIn(p, json) || null); },
        event(ev) {
          if (done || !ev || typeof ev.data !== "string" || !HINT.test(ev.data)) return;
          let v; try { v = JSON.parse(ev.data); } catch { return; }
          usage = mergeUsage(usage, usageIn(p, v) || null);
        },
        end() { if (done) return; done = true; if (enrolled) buckets.add(k, usage); }
      };
    },
    flush,
    async close() { if (timer) clearInterval(timer); if (flushing) await flushing; await flush(); },
    stats: () => ({ buckets: buckets.size(), pausedUntil })
  };
}
