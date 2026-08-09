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

const HOST_RE = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,}|localhost|127\.0\.0\.1|\[::1\])(?::\d+)?/gi;

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

function hostOf(url) {
  const m = String(url).match(/^https?:\/\/([^/:\s"';]+)/i);
  return m ? m[1].toLowerCase() : null;
}

// Is a host approved by the org's allow-list? Loopback (local models) is always allowed — a local
// Ollama/LM Studio can't exfiltrate. A host matches an allow-list entry by exact or suffix match.
export function endpointApproved(host, allow) {
  const h = String(host || "").toLowerCase();
  if (!h) return true;
  if (h === "localhost" || h === "127.0.0.1" || h === "[::1]") return true;
  if (!Array.isArray(allow) || !allow.length) return true; // no allow-list set → report-only
  return allow.some((a) => { const s = String(a).toLowerCase().trim(); return s && (h === s || h.endsWith("." + s) || h.endsWith(s)); });
}
