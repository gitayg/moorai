// The one HTTP call both cloud file-scanning providers make (cli/file-scan-metadefender.mjs,
// cli/file-scan-virustotal.mjs). The API key travels only in the header the provider documents, to the
// provider's own base URL; it is never put in an error, a message or a log line. Errors carry a kind
// and, for a rate limit, how long the provider asked to wait:
//   rate-limit  HTTP 429 (both providers), or MetaDefender's scan result 253 "Not Scanned. Rate Limit Exceeded"
//   auth        HTTP 401 / 403 (a missing, wrong or inactive key)
//   timeout     the caller's deadline (an aborted signal)
//   network     the provider could not be reached
//   provider    any other non-2xx answer, a body that is not JSON, or an answer that breaks the documented shape
export class FileScanError extends Error {
  constructor(kind, { status, retryAfterMs } = {}) {
    super(`file scan provider error: ${kind}${status ? ` (HTTP ${status})` : ""}`);
    this.kind = kind;
    if (status) this.status = status;
    if (retryAfterMs) this.retryAfterMs = retryAfterMs;
  }
}

const MAX_WAIT_MS = 3600000;
// MetaDefender: X-RateLimit-Reset-In "The number of seconds remaining in the current time window" ("60s" in
// its example); Retry-After (seconds) as HTTP defines it. Capped at an hour.
export function retryAfterMs(headers) {
  for (const name of ["x-ratelimit-reset-in", "retry-after"]) {
    const v = headers && typeof headers.get === "function" ? headers.get(name) : null;
    const n = v == null ? NaN : Number(String(v).trim().replace(/s$/i, ""));
    if (Number.isFinite(n) && n > 0) return Math.min(MAX_WAIT_MS, Math.round(n * 1000));
  }
  return 0;
}

// Returns { status, body } for a 2xx JSON answer or a 404 (the caller decides what a 404 means); throws a
// FileScanError otherwise.
export async function call(fetchImpl, url, { method = "GET", headers = {}, body, signal } = {}) {
  let res;
  try {
    res = await fetchImpl(url, { method, headers, body, signal, redirect: "error" });
  } catch {
    if (signal && signal.aborted) throw new FileScanError("timeout");
    throw new FileScanError("network");
  }
  let text = "";
  try { text = await res.text(); } catch {
    if (signal && signal.aborted) throw new FileScanError("timeout");
    throw new FileScanError("network");
  }
  if (res.status === 429) throw new FileScanError("rate-limit", { status: 429, retryAfterMs: retryAfterMs(res.headers) });
  if (res.status === 401 || res.status === 403) throw new FileScanError("auth", { status: res.status });
  if (res.status === 404) return { status: 404, body: null };
  if (res.status < 200 || res.status > 299) throw new FileScanError("provider", { status: res.status });
  try { return { status: res.status, body: JSON.parse(text) }; } catch { throw new FileScanError("provider", { status: res.status }); }
}

// A threat or family name a provider returns, as it may appear in an alert: printable, short, no markup.
export function cleanThreat(s) {
  if (typeof s !== "string") return undefined;
  const t = s.replace(/[^A-Za-z0-9._:/!@#+\-]/g, "_").slice(0, 64);
  return /[A-Za-z0-9]/.test(t) ? t : undefined;
}
const int = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
export { int };
