// AML.T0131 — Crafted AI Assistant Links. A link that opens someone's assistant with the attacker's
// prompt already in the box (`?q=`, `?prompt=`, …), usually dressed as a "Summarize with AI" button.
// The prompt runs unsupervised, and when the assistant has cross-session memory it can write a DURABLE
// entry that biases every later answer.
//
// Three conditions, all structural, because any one of them alone is ordinary:
//   1. the host is an assistant that accepts a prefilled prompt — a `?q=` on a search engine or a repo
//      host is not this technique;
//   2. a prompt-bearing parameter is present and carries a real payload, not a word or two;
//   3. the decoded payload asks for PERSISTENCE (memory, "from now on", future sessions) or issues a
//      directive. A bare `https://claude.ai/new?q=hello` is a convenience link, not an attack.
//
// Content-free: the caller gets a boolean. Nothing decoded here is returned or logged.

const ASSISTANT_HOST = /(?:^|\.)(?:chatgpt\.com|openai\.com|claude\.ai|anthropic\.com|gemini\.google\.com|bard\.google\.com|copilot\.microsoft\.com|m365\.cloud\.microsoft|perplexity\.ai|grok\.com|x\.ai|you\.com|poe\.com|chat\.mistral\.ai|chat\.deepseek\.com|chat\.qwen\.ai|kimi\.com|meta\.ai|duck\.ai)$/i;

const PROMPT_PARAM = /^(?:q|prompt|query|text|message|msg|input|ask|question|p)$/i;

// The payload has to be doing something durable or directive. "Remember", "from now on" and the
// future-session phrasings are the memory-write half the technique is named for; the second group is
// the ordinary directive half.
const PERSISTENCE = /\b(?:remember(?:\s+(?:that|this|for))?|memoris|memoriz|keep\s+(?:this|that|it)\s+in\s+mind|from\s+now\s+on|going\s+forward|for\s+(?:all\s+)?(?:future|later|subsequent)\s+(?:sessions?|conversations?|chats?)|future\s+(?:sessions?|conversations?)|rest\s+of\s+this\s+session|permanent(?:ly)?|persist(?:ent)?|lasting|for\s+good|save\s+(?:this|that|it)?\s*(?:as|to|in)?\s*(?:your\s+)?(?:memory|preference|note)|stor(?:e|ing)\s+(?:this|that|it)?\s*in\s+(?:your\s+)?(?:memory|long-term)|commit\s+(?:this|that|it)?\s*to\s+memory|write\s+(?:this\s+)?to\s+your\s+(?:long-term\s+)?memory|add\s+a\s+(?:permanent\s+)?note)\b/i;

const DIRECTIVE = /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,30}\b(?:previous|prior|above|earlier|all|your|the)\b|\b(?:you\s+(?:must|should|shall|will)|do\s+not\s+(?:tell|mention|warn|ask)|never\s+(?:warn|mention|ask))\b/i;

const MAX = 200_000;
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]{1,2000}/gi;
const MIN_PAYLOAD = 24;

// Percent- and plus-decoding, tolerant: a malformed escape must not throw and must not mask the rest of
// the value, so an undecodable payload is judged on its raw form.
function decodeLoose(v) {
  const plus = v.replace(/\+/g, " ");
  try { return decodeURIComponent(plus); } catch { return plus; }
}

// A prefilled prompt is frequently base64'd to keep it out of sight in the address bar. One bounded
// pass, only for a value that is entirely base64 alphabet and long enough to carry a sentence. `atob`
// rather than Buffer, for the same reason data/normalize.js gives: engine.js is bundled for the browser.
function unb64(v) {
  if (typeof atob !== "function") return "";
  if (!/^[A-Za-z0-9+/_-]{32,4000}={0,2}$/.test(v) || !/[a-z]/.test(v) || !/[A-Z]/.test(v)) return "";
  try {
    const s = atob(v.replace(/-/g, "+").replace(/_/g, "/"));
    return /[\x20-\x7E]{16,}/.test(s) ? s : "";
  } catch { return ""; }
}

function scanCraftedAssistantLink(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(text)) !== null) {
    let u;
    try { u = new URL(m[0].replace(/[.,;]+$/, "")); } catch { continue; }
    if (!ASSISTANT_HOST.test(u.hostname)) continue;
    for (const [key, raw] of u.searchParams) {
      if (!PROMPT_PARAM.test(key)) continue;
      // Both forms, not one or the other: searchParams has already percent-decoded the value, so a
      // base64 prefill arrives as a long printable string that passes the length gate and then matches
      // nothing. Judging only the longer of the two is what let that through.
      for (const payload of [decodeLoose(raw), unb64(raw)]) {
        if (payload.length < MIN_PAYLOAD) continue;
        if (PERSISTENCE.test(payload) || DIRECTIVE.test(payload)) return true;
      }
    }
  }
  return false;
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence, and the prefilter here is deliberately cheap and broad.
let lastText = null, lastHit = false;
export function craftedAssistantLink(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanCraftedAssistantLink(text);
  return lastHit;
}
