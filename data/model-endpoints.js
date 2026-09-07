// T1-1 (#63) — model-endpoint awareness for rogue-LLM-egress control. Content-free: everything here
// operates on HOSTS and env-var NAMES, never on prompt/response content. Known LLM/AI provider API
// hosts (the legitimate destinations) + the base-URL override env vars agents honor. The detection
// engine flags any base-URL override or direct LLM-endpoint reference; hook-core then enforces the
// org's allow-list (deny a host that isn't approved) when policy.endpointAllow is set.

// Well-known first-party LLM/inference API hosts. Presence of one of these in a command/arg/prompt is
// an outbound-model-call signal; whether it's ALLOWED is a policy question (endpointAllow).
export const LLM_ENDPOINT_HOSTS = [
  "api.anthropic.com", "api.openai.com", "openai.azure.com", "generativelanguage.googleapis.com",
  "api.groq.com", "api.mistral.ai", "api.together.xyz", "api.together.ai", "openrouter.ai",
  "api.cohere.ai", "api.cohere.com", "api.perplexity.ai", "api.deepseek.com", "api.x.ai",
  "api.fireworks.ai", "api.replicate.com", "api-inference.huggingface.co", "api.endpoints.anyscale.com",
  "bedrock-runtime", "aiplatform.googleapis.com"
];

// Env vars agents read to redirect their model traffic — a base-URL override is the classic
// exfil-via-rogue-endpoint vector (point the agent at an attacker proxy that logs everything).
export const BASE_URL_ENV_VARS = [
  "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "AZURE_OPENAI_ENDPOINT",
  "OLLAMA_HOST", "OLLAMA_BASE_URL", "HF_ENDPOINT", "GROQ_BASE_URL", "MISTRAL_BASE_URL",
  "TOGETHER_BASE_URL", "OPENROUTER_BASE_URL", "COHERE_BASE_URL", "GOOGLE_VERTEX_BASE_URL",
  "LITELLM_PROXY_URL", "OPENAI_PROXY", "ANTHROPIC_API_URL"
];

// T1-1 (#67) — TRANSIT overrides. #63 asks "where is the agent sending?"; these ask "what is the
// traffic passing THROUGH on the way?". The distinction is the whole threat: a proxy override leaves
// the destination untouched, so the agent still connects to api.anthropic.com, endpointApproved()
// still returns true, and #63's allow-list passes it. Measured: with HTTPS_PROXY + NODE_EXTRA_CA_CERTS
// set on a real Claude Code session, the prompt body, the model field and the x-api-key header were
// all readable in plaintext by the interceptor, and the client reported the TLS as AUTHORIZED.
//
// The CA vars are the reason this is quiet rather than loud. NODE_TLS_REJECT_UNAUTHORIZED=0 (already
// a detector) DISABLES verification; adding a CA makes the forged certificate legitimately trusted,
// so nothing looks wrong from inside the agent.
export const PROXY_ENV_VARS = [
  "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy",
  "NPM_CONFIG_PROXY", "NPM_CONFIG_HTTPS_PROXY"
];
export const CA_ENV_VARS = [
  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE", "AWS_CA_BUNDLE", "GIT_SSL_CAINFO"
];

// The optional userinfo group is the enforcement half of #63, not a nicety. The capture group used to
// start immediately after `://`, and its character class excludes `@` and `:`, so a userinfo-bearing
// URL matched NOTHING AT ALL: `curl https://alice:hunter2@api.openai.com/v1` yielded no hosts, and an
// empty host list is an ALLOW — appending a username to a rogue endpoint defeated policy.endpointAllow
// outright. Userinfo is SKIPPED, never captured (a non-capturing group), so no credential fragment can
// reach the host list. The class stops at `/ ? # " ' ;` and whitespace so an `@` in a path or query
// (`/users/me@example.com`) cannot be mistaken for userinfo, and the {0,256} bound keeps the optional
// group from scanning an unbounded run before failing — this text is free-form agent input and every
// `https://` in it is a match start, so an unbounded scan is quadratic. Past that bound the direct-URL
// sweep behaves as it did before the fix; that residual is pinned as a LIMIT test in
// test/endpoint-userinfo.test.mjs rather than left silent. The base-URL-override branch goes through
// hostOf, which has no such bound.
const HOST_RE = /\bhttps?:\/\/(?:[^\s/?#@"';]{0,256}@)?([a-z0-9.-]+\.[a-z]{2,}|localhost|127\.0\.0\.1|\[::1\])(?::\d+)?/gi;

// Transit overrides present in the text: { proxies:[host], caVars:[NAME] }. Content-free — the proxy
// HOST and the env-var NAME, never the CA file's path or contents.
export function extractTransitOverrides(text) {
  const t = String(text || "");
  const proxies = new Set(), caVars = new Set();
  for (const v of PROXY_ENV_VARS) {
    const m = t.match(new RegExp(`\\b${v}\\s*[=:]\\s*["']?\\s*([a-z0-9+.-]+:\\/\\/[^\\s"';]+|[^\\s"';]+)`, "i"));
    if (!m) continue;
    const h = proxyHostOf(m[1]);
    if (h) proxies.add(h);
  }
  for (const v of CA_ENV_VARS) {
    if (new RegExp(`\\b${v}\\s*[=:]\\s*\\S`, "i").test(t)) caVars.add(v);
  }
  return { proxies: [...proxies], caVars: [...caVars] };
}

// Is a proxy host sanctioned? Same shape and same label-boundary rule as endpointApproved: an unset
// allow-list is report-only, because a corporate egress proxy is legitimate and common — this must
// not fire on every managed laptop. Loopback is NOT auto-approved here (unlike a local model): a
// loopback proxy is exactly what a local interceptor looks like.
export function proxyApproved(host, allow) {
  const h = String(host || "").toLowerCase();
  if (!h) return true;
  if (!Array.isArray(allow) || !allow.length) return true;
  return allow.some((a) => { const s = String(a).toLowerCase().trim(); return s && (h === s || h.endsWith("." + s)); });
}

// Pull candidate endpoint hosts from text: any base-URL override target + any direct LLM-host mention.
// Returns lowercased host strings (deduped). Content-free — hosts only, never the surrounding content.
export function extractEndpointHosts(text) {
  const t = String(text || "");
  const hosts = new Set();
  // base-URL override → capture the host it points at
  for (const v of BASE_URL_ENV_VARS) {
    const re = new RegExp(`\\b${v}\\s*[=:]\\s*["']?\\s*(https?:\\/\\/[^\\s"';]+)`, "i");
    const m = t.match(re);
    if (m) { const h = hostOf(m[1]); if (h) hosts.add(h); }
  }
  // direct URLs to known LLM hosts anywhere in the text
  let m;
  HOST_RE.lastIndex = 0;
  while ((m = HOST_RE.exec(t)) !== null) {
    const h = m[1].toLowerCase();
    if (LLM_ENDPOINT_HOSTS.some((k) => h === k || h.includes(k))) hosts.add(h);
  }
  return [...hosts];
}

// EVERY host the text points at, not just the LLM ones — the input to the per-agent destination map
// ("where did this agent actually reach?"). Same HOST_RE, same content-free contract: the HOST leaves,
// the URL path and query string never do, because they are never captured in the first place.
export function extractHosts(text) {
  const t = String(text || "");
  const hosts = new Set();
  let m;
  HOST_RE.lastIndex = 0;
  while ((m = HOST_RE.exec(t)) !== null) hosts.add(m[1].toLowerCase());
  for (const v of BASE_URL_ENV_VARS) {
    const re = new RegExp(`\\b${v}\\s*[=:]\\s*["']?\\s*(https?:\\/\\/[^\\s"';]+)`, "i");
    const mm = t.match(re);
    if (mm) { const h = hostOf(mm[1]); if (h) hosts.add(h); }
  }
  return [...hosts];
}

// Host of a base-URL override value. Scheme is REQUIRED here (the callers' own regexes only capture
// `https?://…`), which is the one thing that separates this from proxyHostOf below — see that
// function's note, which described this exact userinfo flaw and worked around it locally while the
// version here stayed broken. The old body was `/^https?:\/\/([^/:\s"';]+)/i`: it stopped at the first
// colon, so `https://bob:pw@api.groq.com/v1` yielded "bob" — the wrong host AND a credential fragment
// on a path that hashes its output into telemetry. Userinfo is dropped, the port is dropped, and the
// authority is cut at `/ ? #` so no path or query string can ride along.
function hostOf(url) {
  const m = String(url).match(/^https?:\/\/([^\s"';]*)/i);
  if (!m) return null;
  let s = m[1].split(/[/?#]/)[0];
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  if (s.startsWith("[")) return (s.slice(0, s.indexOf("]") + 1) || s).toLowerCase();  // [::1]:8080
  return s.split(":")[0].toLowerCase() || null;
}

// A proxy value is not a plain URL: the scheme is often absent or non-http (socks5://), and it may
// carry userinfo. `hostOf` cannot be reused — it REQUIRES an http(s) scheme and would return null for
// `socks5://…` and for a bare `evil.example:3128`. Userinfo is dropped, never captured, and the port
// is dropped so the value compares cleanly against an allow-list of hostnames.
//
// Worth recording: this comment used to justify itself by noting that `hostOf` "stops at the first
// colon, so http://user:pw@evil.example:8080 yields user" — the flaw was known, written down, and
// worked around HERE, while `hostOf` itself was left broken for the whole of #63's enforcement path.
// Documenting a defect at the one call site that dodges it is not fixing it.
function proxyHostOf(raw) {
  let s = String(raw).trim().replace(/^["']|["']$/g, "").replace(/^[a-z0-9+.-]+:\/\//i, "");
  s = s.split("/")[0];
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  if (s.startsWith("[")) return (s.slice(0, s.indexOf("]") + 1) || s).toLowerCase();  // [::1]:8080
  return s.split(":")[0].toLowerCase() || null;
}

// Is a host approved by the org's allow-list? Loopback (local models) is always allowed — a local
// Ollama/LM Studio can't exfiltrate. A host matches an allow-list entry by exact or suffix match.
export function endpointApproved(host, allow) {
  const h = String(host || "").toLowerCase();
  if (!h) return true;
  if (h === "localhost" || h === "127.0.0.1" || h === "[::1]") return true;
  if (!Array.isArray(allow) || !allow.length) return true; // no allow-list set → report-only
  // Exact host, or a subdomain of the entry. The match MUST stop at a label boundary: a bare
  // `h.endsWith(s)` also approved `evilanthropic.com` against an `anthropic.com` entry, which let an
  // attacker-registered lookalike pass the very control meant to stop redirected model egress.
  return allow.some((a) => { const s = String(a).toLowerCase().trim(); return s && (h === s || h.endsWith("." + s)); });
}
