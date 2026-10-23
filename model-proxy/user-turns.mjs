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
// HARNESS BLOCKS. An agent harness puts text of its own into the user role. Claude Code 2.1.295 (measured in
// its bundle, versions/2.1.295): CLAUDE.md, memory and the session context go to the model as user-role text
// "<system-reminder>\nAs you answer the user's questions, you can use the following context: … Contents of
// <path> (…)" (its own parser: /^<system-reminder>\n?([\s\S]*?)\n?<\/system-reminder>$/); background worker
// results arrive "as user-role messages containing `<task-notification>` XML"; a `!` command's output is
// "<bash-stdout>…</bash-stdout><bash-stderr>…</bash-stderr>"; a local slash command's output is
// <local-command-stdout> / <local-command-stderr>; hook output is <user-prompt-submit-hook>. None of it is the
// person's request, and all of it can carry text someone else wrote (a cloned repository's CLAUDE.md, a page a
// worker read). stripHarness removes each such block from every text before anything is taken from it, so a
// host, a path or a label word that appears only inside one never counts. Per text (a block, a string), each
// tag is cut from its FIRST opening to its LAST closing, and an opening never closed runs to the end of that
// text: a file quoted inside a reminder that carries its own `</system-reminder>` cannot end the cut early and
// put the words after it in scope. The cost is the other way: a person's words between two harness blocks of
// the same tag, in one text, are dropped, which can only make an action look LESS aligned. <bash-input> (the
// command a person typed) is kept. Linear: indexOf / lastIndexOf, at most two cuts per tag per text.
//
// NOT IDENTIFIABLE HERE (judged as the person's turn): a sub-agent's prompt (Claude Code's Task / Agent tool:
// the sub-agent's first user turn is text the PARENT MODEL wrote, so in an agent-to-agent call the "task" this
// proxy judges against is model-written), a custom slash command's expanded body (a file in the repository),
// and any other harness's own wrapping. For a guarantee that the task is the person's, name the session
// (X-MoorAI-Session-Id) and set the task over the explicit channel: moorai-serve's POST /v1/task, or the Agent
// SDK's capture (README "Intent alignment").
//
// Returns the turns in order, each at most MAX_TURN characters (the intent store reads at most 20,000).
export const MAX_TURN = 20000;

export const HARNESS_TAGS = Object.freeze(["system-reminder", "task-notification", "bash-stdout", "bash-stderr", "local-command-stdout", "local-command-stderr", "user-prompt-submit-hook"]);
export function stripHarness(text) {
  let s = String(text);
  for (const tag of HARNESS_TAGS) {
    const open = `<${tag}>`, close = `</${tag}>`;
    let i = s.indexOf(open);
    if (i < 0) continue;
    const j = s.lastIndexOf(close);
    if (j > i) { s = s.slice(0, i) + s.slice(j + close.length); i = s.indexOf(open); }
    if (i >= 0) s = s.slice(0, i);
  }
  return s;
}

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const cut = (s) => (s.length > MAX_TURN ? s.slice(0, MAX_TURN) : s);
const partsText = (content, types) => (typeof content === "string" ? stripHarness(content)
  : Array.isArray(content) ? content.filter((p) => isObj(p) && types.has(p.type) && typeof p.text === "string").map((p) => stripHarness(p.text)).join("\n") : "");
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
  if (typeof body.input === "string") { const t = stripHarness(body.input); return t.trim() ? [cut(t)] : []; }
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
    const t = c.parts.filter((p) => isObj(p) && typeof p.text === "string" && p.thought !== true).map((p) => stripHarness(p.text)).join("\n");
    if (t.trim()) out.push(cut(t));
  }
  return out;
}
function ollama(body) {
  if (typeof body.prompt === "string") { const t = stripHarness(body.prompt); return t.trim() ? [cut(t)] : []; }
  const out = [];
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!isObj(m) || m.role !== "user") continue;
    const t = partsText(m.content, TEXT);
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

// Whether a request declares tools the model can call: a non-empty `tools` (or OpenAI Chat's legacy
// `functions`). A request without them is a side request — Claude Code's WebFetch summariser (the fetched page
// is its user turn), compaction, a title — and its turns are never the task: the model cannot answer it with a
// tool call to judge, and its "user" text is often content the agent fetched.
export function carriesTools(kind, body) {
  if (!isObj(body)) return false;
  const any = (v) => Array.isArray(v) && v.length > 0;
  return any(body.tools) || (kind === "openai-chat" && any(body.functions));
}
