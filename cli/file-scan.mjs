// Cloud file scanning before a file reaches a model (MoorAI for AI Servers): the model proxy scans every
// inline file, document or image part of a request (model-proxy/file-parts.mjs) and moorai-serve answers
// POST /v1/file-scan, both through this module. The policy is cli/file-scan-policy.mjs, the keys
// cli/file-scan-keys.mjs, the providers cli/file-scan-metadefender.mjs (OPSWAT MetaDefender Cloud) and
// cli/file-scan-virustotal.mjs (VirusTotal) behind one interface: lookup(sha256), upload(bytes), poll(id).
//
//   scan(bytes, cfg)     hash -> lookup; in "upload" mode a hash the provider does not know (and no larger than
//                        cfg.maxBytes) is uploaded and polled to a verdict
//   scanHash(sha, cfg)   lookup only (a caller that has the hash, not the file)
// -> { verdict: "malicious" | "clean" | "unknown" | "error", provider, sha256, mode, detections?, engines?,
//      threat?, uploaded, cached, why? }  why: unknown "not-found" | "suspicious" | "incomplete" | "too-large";
//      error "no-key" | "timeout" | "rate-limit" | "auth" | "provider" | "network" | "budget".
//
// CACHE. Per process, LRU of (provider, hash-or-upload, sha256) -> verdict: malicious and clean for
// cacheTtlMs (default 1 h), unknown for unknownTtlMs (default 5 min, so an upload elsewhere or a new
// signature is seen), errors never. Concurrent scans of one file share one provider query. A conversation
// re-sends its earlier images and documents with every turn; they are looked up once.
//
// RATE LIMIT. Per provider, a token bucket of cfg.ratePerMinute requests (every lookup, upload and poll is
// one). A request with no token waits for one only if it comes before the scan's deadline and fewer than
// queueMax requests already wait; otherwise it is error/rate-limit at once. A provider 429 (or MetaDefender's
// 253) pauses that provider until the reset it names (X-RateLimit-Reset-In / Retry-After), else 60 s.
//
// DEADLINE. cfg.timeoutMs bounds the whole scan, including waits and polls; past it, error/timeout. The
// surface decides an error by its admin-chosen fail mode (fileScanDecision): closed refuses (one
// content-free FAIL_CLOSED alert), open treats the file as unknown (onUnknown decides).
import { createHash } from "node:crypto";
import { createMetaDefender, DEFAULT_BASE as MD_BASE, REGIONS } from "./file-scan-metadefender.mjs";
import { createVirusTotal, DEFAULT_BASE as VT_BASE } from "./file-scan-virustotal.mjs";
import { FileScanError } from "./file-scan-http.mjs";
import { REASON } from "./provenance.mjs";
export { FileScanError } from "./file-scan-http.mjs";

export const THREAT_ID = 17;
export const PROVIDER_LABEL = Object.freeze({ metadefender: "OPSWAT MetaDefender Cloud", virustotal: "VirusTotal" });
const DEFAULT_PAUSE_MS = 60000;
const ERROR_WHY = new Set(["timeout", "rate-limit", "auth", "provider", "network"]);

const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
const sleep = (ms, signal) => new Promise((resolve) => {
  if (signal && signal.aborted) return resolve();
  const t = setTimeout(done, Math.max(0, ms));
  function done() { clearTimeout(t); if (signal) signal.removeEventListener("abort", done); resolve(); }
  if (signal) signal.addEventListener("abort", done, { once: true });
});

function createLimiter(rate, queueMax) {
  const perMs = rate / 60000;
  let tokens = rate, last = Date.now(), pausedUntil = 0, waiting = 0;
  const refill = () => { const t = Date.now(); tokens = Math.min(rate, tokens + (t - last) * perMs); last = t; };
  return {
    rate,
    pause(ms) { pausedUntil = Math.max(pausedUntil, Date.now() + (ms || DEFAULT_PAUSE_MS)); },
    async acquire(deadline, signal) {
      for (;;) {
        if (signal && signal.aborted) throw new FileScanError("timeout");
        refill();
        const now = Date.now();
        let at = now;
        if (pausedUntil > now) at = pausedUntil;
        else if (tokens >= 1) { tokens -= 1; return; }
        else at = now + Math.ceil((1 - tokens) / perMs);
        if (at > deadline || waiting >= queueMax) throw Object.assign(new FileScanError("rate-limit"), { local: true });
        waiting++;
        try { await sleep(at - now, signal); } finally { waiting--; }
      }
    }
  };
}

export function createFileScanner({ keys = {}, fetch: fetchImpl = globalThis.fetch, endpoints = {}, now = Date.now, cacheMax = 4096, cacheTtlMs = 3600000, unknownTtlMs = 300000, queueMax = 32, pollMs = 1000, providers = null } = {}) {
  const cache = new Map();
  const inflight = new Map();
  const limiters = new Map();
  const stats = { lookups: 0, uploads: 0, polls: 0, cacheHits: 0, errors: 0 };

  function providerFor(cfg) {
    const key = keys[cfg.provider];
    if (!key) return null;
    if (providers && providers[cfg.provider]) return providers[cfg.provider];
    if (cfg.provider === "virustotal") return createVirusTotal({ key, base: endpoints.virustotal || VT_BASE, fetch: fetchImpl });
    return createMetaDefender({ key, base: endpoints.metadefender || (cfg.region && REGIONS[cfg.region]) || MD_BASE, fetch: fetchImpl, privateScan: cfg.privateScan === true });
  }
  function limiterFor(cfg) {
    const l = limiters.get(cfg.provider);
    if (l && l.rate === cfg.ratePerMinute) return l;
    const n = createLimiter(cfg.ratePerMinute || 4, queueMax);
    limiters.set(cfg.provider, n);
    return n;
  }
  function remember(k, v) {
    const ttl = v.verdict === "unknown" ? unknownTtlMs : cacheTtlMs;
    cache.delete(k);
    cache.set(k, { v, until: now() + ttl });
    while (cache.size > cacheMax) cache.delete(cache.keys().next().value);
  }

  async function query(sha, bytes, cfg, upload) {
    const base = { provider: cfg.provider, sha256: sha, mode: cfg.mode, uploaded: false, cached: false };
    const p = providerFor(cfg);
    if (!p) return { ...base, verdict: "error", why: "no-key" };
    const lim = limiterFor(cfg);
    const ac = new AbortController();
    const deadline = Date.now() + cfg.timeoutMs;
    const timer = setTimeout(() => ac.abort(), cfg.timeoutMs);
    const signal = ac.signal;
    const step = async (f) => { await lim.acquire(deadline, signal); return f(); };
    const pollTo = async (id) => {
      for (;;) {
        await sleep(pollMs, signal);
        if (signal.aborted) throw new FileScanError("timeout");
        stats.polls++;
        const r = await step(() => p.poll(id, { signal }));
        if (r.state !== "pending") return r;
      }
    };
    try {
      stats.lookups++;
      let r = await step(() => p.lookup(sha, { signal }));
      let uploaded = false;
      if (r.state === "pending") r = await pollTo(r.id);
      if (r.state === "unknown" && r.why === "not-found" && upload) {
        if (bytes.length > cfg.maxBytes) return { ...base, verdict: "unknown", why: "too-large" };
        stats.uploads++;
        const { id } = await step(() => p.upload(bytes, { signal }));
        uploaded = true;
        r = await pollTo(id);
      }
      const out = { ...base, uploaded, verdict: r.state === "found" ? r.verdict : "unknown" };
      for (const k of ["detections", "engines", "threat"]) if (r[k] !== undefined) out[k] = r[k];
      if (r.state !== "found") out.why = r.why || "incomplete";
      return out;
    } catch (e) {
      stats.errors++;
      let why = e instanceof FileScanError && ERROR_WHY.has(e.kind) ? e.kind : "provider";
      if (signal.aborted && why !== "rate-limit") why = "timeout";
      // The provider said so (429, or MetaDefender's 253): pause it. This process's own bucket being empty does not.
      if (why === "rate-limit" && !e.local) lim.pause(e.retryAfterMs || DEFAULT_PAUSE_MS);
      return { ...base, verdict: "error", why };
    } finally { clearTimeout(timer); }
  }

  // A clean verdict from fewer engines than cfg.minEngines is unknown (applied on every answer, cached or not).
  const thin = (v, cfg) => (v.verdict === "clean" && (v.engines ?? 0) < (cfg.minEngines ?? 3) ? { ...v, verdict: "unknown", why: "few-engines" } : v);
  async function run(sha, bytes, cfg) {
    return thin(await answer(sha, bytes, cfg), cfg);
  }
  async function answer(sha, bytes, cfg) {
    if (!cfg || cfg.mode === "off") return { verdict: "not-scanned", provider: cfg ? cfg.provider : undefined, sha256: sha, mode: "off", uploaded: false, cached: false };
    const upload = cfg.mode === "upload" && bytes !== null;
    const k = `${cfg.provider}|${upload ? "upload" : "hash"}|${sha}`;
    const hit = cache.get(k);
    if (hit && hit.until > now()) { cache.delete(k); cache.set(k, hit); stats.cacheHits++; return { ...hit.v, mode: cfg.mode, cached: true }; }
    if (hit) cache.delete(k);
    if (inflight.has(k)) return { ...(await inflight.get(k)) };
    const pr = query(sha, bytes, cfg, upload).then((v) => { if (v.verdict !== "error") remember(k, v); return v; }).finally(() => inflight.delete(k));
    inflight.set(k, pr);
    return { ...(await pr) };
  }

  return {
    scan: (bytes, cfg) => run(sha256Hex(bytes), bytes, cfg),
    scanHash: (sha, cfg) => run(String(sha).toLowerCase(), null, cfg),
    stats: () => ({ ...stats, cached: cache.size })
  };
}

// What the surface does with a result. failMode: the surface's resolved fail mode ("open" | "closed");
// headless: how an "ask" settles with no approver ("deny" | "allow-with-report"; cli/server-mode.mjs
// headlessAskMode). -> { action: "allow" | "deny", decision: "allow" | "deny" | "notify", failClosed, alert }
export function fileScanDecision(result, cfg, { failMode = "open", headless = "deny" } = {}) {
  const v = result && result.verdict;
  if (v === "clean" || v === "not-scanned") return { action: "allow", decision: "allow", failClosed: false, alert: false };
  if (v === "malicious") return cfg.onMalicious === "report" ? { action: "allow", decision: "notify", failClosed: false, alert: true } : { action: "deny", decision: "deny", failClosed: false, alert: true };
  if (v === "error" && failMode === "closed") return { action: "deny", decision: "deny", failClosed: true, alert: true };
  // unknown, or an error under an open fail mode: onUnknown decides.
  if (cfg.onUnknown === "block") return { action: "deny", decision: "deny", failClosed: false, alert: true };
  if (cfg.onUnknown === "ask") return headless === "allow-with-report" ? { action: "allow", decision: "notify", failClosed: false, alert: true, headlessAsk: "allow-with-report" } : { action: "deny", decision: "deny", failClosed: false, alert: true, headlessAsk: "deny" };
  return { action: "allow", decision: "notify", failClosed: false, alert: true };
}

export function mimeClass(mt) {
  const m = String(mt || "").toLowerCase().split(";")[0].trim();
  if (!m) return "other";
  if (m.startsWith("image/")) return "image";
  if (m === "application/pdf") return "pdf";
  if (m.startsWith("text/")) return "text";
  if (m.startsWith("audio/")) return "audio";
  if (m.startsWith("video/")) return "video";
  if (/(zip|x-7z|x-rar|gzip|x-tar|x-bzip|x-xz|java-archive)/.test(m)) return "archive";
  if (/(msword|officedocument|vnd\.ms-|opendocument|rtf|epub)/.test(m)) return "document";
  return "other";
}
export function sizeBucket(n) {
  if (n < 65536) return "<64KB";
  if (n < 1048576) return "64KB-1MB";
  if (n <= 10485760) return "1-10MB";
  return ">10MB";
}

// The content-free alert: provider, verdict, detection count, the provider's threat name when it gives one,
// the MIME class and size bucket, the keyed hash of the file's SHA-256 (hash: the runtime's keyed hash). The
// raw SHA-256 only for a malicious file under fileScan.iocHash (a public indicator of compromise).
// tool: the surface's label ("model-proxy:file-scan", "serve:file-scan").
export function fileScanAlert({ result, cfg, decision, hash, tool, mime, size }) {
  const v = result.verdict;
  const fs = { provider: result.provider, verdict: v, mode: cfg.mode };
  for (const k of ["detections", "engines", "threat"]) if (result[k] !== undefined) fs[k] = result[k];
  fs.mimeClass = mimeClass(mime);
  fs.sizeBucket = sizeBucket(Number(size) || 0);
  fs.uploaded = result.uploaded === true;
  if (result.why) fs.why = result.why;
  const deny = decision.action === "deny";
  const base = { stage: "prompt", tool, fileScan: fs, contentHash: hash(`file-scan:${result.sha256}`) };
  if (decision.failClosed) {
    return { ...base, threatId: 0, category: "Fail-closed: file not scanned", riskLevel: "Blocked", decision: "deny", reasonCode: REASON.FAIL_CLOSED, basisCode: REASON.UNEVALUATED_HOOK_ERROR, enforcement: "STRENGTHENED", failMode: "closed", failWhy: result.why || "error" };
  }
  const category = v === "malicious" ? "File scan: malicious file" : v === "unknown" ? "File scan: unknown file" : "File scan: file not scanned";
  const riskLevel = deny ? "Blocked" : v === "malicious" ? "High" : v === "unknown" ? "Medium" : "Info";
  return { ...base, threatId: v === "malicious" ? THREAT_ID : 0, category, riskLevel, decision: decision.decision, reasonCode: REASON.FILE_SCAN, ...(decision.headlessAsk ? { headlessAsk: decision.headlessAsk } : {}), ...(v === "malicious" && cfg.iocHash === true ? { sha256: result.sha256 } : {}) };
}
