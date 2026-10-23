// The turns a PERSON wrote in a model request, for intent alignment (intent.mjs): the task is the first such
// turn, and the latest one adds to it. Only real user turns count. Never a system prompt or developer message
// (operator text), never a tool result, a function response or a document fed back to the model (content an
// agent fetched, which an attacker can write), and never the model's own earlier turns.
//
//   Anthropic  messages[] role "user": a string, or its text blocks. A user message that carries any
//              tool_result block is the agent returning results; its text blocks travel with them (an agent
//              framework adds its own notes there) and are not the person's.
//   OpenAI     Chat Completions messages[] role "user" (string or text parts); Responses `input` as a string,
//              or its items {type: "message" or absent, role: "user"} with input_text / text parts.
//   Gemini     contents[] role "user" (or no role) text parts, except a content that carries a
//              functionResponse part (results, as above); `thought` parts are the model's.
//   Ollama     /api/chat messages[] role "user"; /api/generate `prompt`.
//
// Returns the turns in order, each at most MAX_TURN characters (the intent store reads at most 20,000).
export const MAX_TURN = 20000;

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const cut = (s) => (s.length > MAX_TURN ? s.slice(0, MAX_TURN) : s);
const partsText = (content, types) => (typeof content === "string" ? content
  : Array.isArray(content) ? content.filter((p) => isObj(p) && types.has(p.type) && typeof p.text === "string").map((p) => p.text).join("\n") : "");
const TEXT = new Set(["text"]);
const RESP_TEXT = new Set(["input_text", "text"]);

function anthropic(body) {
  const out = [];
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!isObj(m) || m.role !== "user") continue;
    if (Array.isArray(m.content) && m.content.some((b) => isObj(b) && b.type === "tool_result")) continue;
    const t = partsText(m.content, TEXT);
    if (t.trim()) out.push(cut(t));
  }
  return out;
}
function openaiChat(body) {
  const out = [];
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!isObj(m) || m.role !== "user") continue;
    const t = partsText(m.content, TEXT);
    if (t.trim()) out.push(cut(t));
  }
  return out;
}
function openaiResponses(body) {
  if (typeof body.input === "string") return body.input.trim() ? [cut(body.input)] : [];
  const out = [];
  for (const m of Array.isArray(body.input) ? body.input : []) {
    if (!isObj(m) || (m.type !== undefined && m.type !== "message") || m.role !== "user") continue;
    const t = partsText(m.content, RESP_TEXT);
    if (t.trim()) out.push(cut(t));
  }
  return out;
}
function gemini(body) {
  const out = [];
  const contents = Array.isArray(body.contents) ? body.contents : isObj(body.contents) ? [body.contents] : [];
  for (const c of contents) {
    if (!isObj(c) || !(c.role == null || c.role === "user") || !Array.isArray(c.parts)) continue;
    if (c.parts.some((p) => isObj(p) && (p.functionResponse !== undefined || p.function_response !== undefined))) continue;
    const t = c.parts.filter((p) => isObj(p) && typeof p.text === "string" && p.thought !== true).map((p) => p.text).join("\n");
    if (t.trim()) out.push(cut(t));
  }
  return out;
}
function ollama(body) {
  if (typeof body.prompt === "string") return body.prompt.trim() ? [cut(body.prompt)] : [];
  const out = [];
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!isObj(m) || m.role !== "user") continue;
    const t = typeof m.content === "string" ? m.content : partsText(m.content, TEXT);
    if (t.trim()) out.push(cut(t));
  }
  return out;
}

// kind: "anthropic" | "openai-chat" | "openai-responses" | "gemini" | "ollama" (server.mjs apiKind).
const BY_KIND = { anthropic, "openai-chat": openaiChat, "openai-responses": openaiResponses, gemini, ollama };
export function userTurns(kind, body) {
  const f = BY_KIND[kind];
  return f && isObj(body) ? f(body) : [];
}
