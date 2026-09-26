// AI-provider API key SHAPES — used by the AIBOM's keys-at-rest collector (cli/aibom-keys.mjs) to say
// WHICH provider a stored key belongs to. The matched value is only ever handed to the keyed one-way
// hash; nothing here returns, logs or stores it beyond the caller's in-memory use.
//
// Every shape is taken from gitleaks' published rule set (config/gitleaks.toml, rules
// anthropic-api-key, anthropic-admin-api-key, openai-api-key, gcp-api-key, huggingface-access-token,
// perplexity-api-key) so a "provider" label rests on a shape someone else also relies on. Providers
// with no published shape there (Groq, xAI, OpenRouter, DeepSeek, Cohere's context-only rule) are
// deliberately absent rather than guessed. Every quantifier is bounded.
//
// Google API keys (AIza…) are shared by every Google API — Maps, Firebase, YouTube as much as Gemini —
// so the shape alone does not make one an AI key. It counts only in an AI context: a file that belongs
// to an AI CLI, or a line whose variable name is a Gemini / Google-AI one.
const END = "(?![A-Za-z0-9_-])";
export const AI_KEY_SHAPES = [
  { provider: "Anthropic", re: new RegExp(`\\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA${END}`, "g") },
  { provider: "OpenAI", re: new RegExp(`\\bsk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})${END}`, "g") },
  { provider: "OpenAI", re: new RegExp(`\\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}${END}`, "g") },
  { provider: "Hugging Face", re: new RegExp(`\\bhf_[A-Za-z]{34}${END}`, "g") },
  { provider: "Perplexity", re: new RegExp(`\\bpplx-[a-zA-Z0-9]{48}${END}`, "g") },
  { provider: "Google", re: new RegExp(`\\bAIza[A-Za-z0-9_-]{35}${END}`, "g"), needsAiContext: true }
];

const GOOGLE_AI_NAME = /GEMINI|GOOGLE_(?:GENAI_|AI_)?API_KEY|GOOGLE_AI|GENAI|VERTEX|PALM/i;

// → [{ provider, value }] for one text. `aiContext` = the text belongs to an AI tool's own config.
// Scans line by line so the Google gate looks only at the variable on the SAME line.
export function findAiKeys(text, { aiContext = false } = {}) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    for (const s of AI_KEY_SHAPES) {
      if (s.needsAiContext && !aiContext && !GOOGLE_AI_NAME.test(line)) continue;
      s.re.lastIndex = 0;
      for (const m of line.matchAll(s.re)) out.push({ provider: s.provider, value: m[0] });
    }
  }
  return out;
}
