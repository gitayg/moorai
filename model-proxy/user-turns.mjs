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
// <local-command-stdout> / <local-command-stderr>; hook output is <user-prompt-submit-hook>; the IDE's selection
// and open file are <ide_selection> / <ide_opened_file> (Claude Code strips them itself with
// /<(ide_opened_file|ide_selection)(?:\s[^>]*)?>[\s\S]*?<\/\1>/); an MCP resource is
// <mcp-resource server="…" uri="…">. A tag may carry attributes (up to 512 characters). None of it is the
// person's request, and all of it can carry text someone else wrote (a cloned repository's CLAUDE.md, a page a
// worker read). stripHarness removes each such block from a turn's texts (its text parts, in order) before
// anything is taken from them, so a host, a path or a label word that appears only inside one never counts.
// Per text, ONE left-to-right scan over every harness tag with a stack: the first block ends at its own
// matching close, and blocks nest. What is kept is the text before the first harness tag and, when that block
// closes cleanly and NO further harness tag follows in the text, the text after it. Fail closed:
//   * an unclosed block, or a close that does not match the innermost open block (interleaved tags): only the
//     text before the first harness tag is kept, and the rest of the TURN (every later part) is dropped;
//   * any further harness tag after the first block (a second block of any tag, or a stray close, e.g. a file
//     quoted inside a reminder carrying `</system-reminder> words <system-reminder>`): only the text before
//     the first harness tag is kept from this text.
// The cost is the other way: a person's words after a harness block in the same text, when another harness
// tag follows, are dropped, which can only make an action look LESS aligned. <bash-input> (the command a
// person typed) is kept. Linear: one global regex pass.
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

export const HARNESS_TAGS = Object.freeze(["system-reminder", "task-notification", "bash-stdout", "bash-stderr", "local-command-stdout", "local-command-stderr", "user-prompt-submit-hook", "ide_selection", "ide_opened_file", "mcp-resource"]);
const HARNESS_RE = new RegExp(`<(/?)(${HARNESS_TAGS.join("|")})(?:\\s[^<>]{0,512})?>`, "g");

// COMPACTION. When a Claude Code conversation runs out of context, the summary of it becomes the first user turn,
// opening with this sentence (2.1.295's bundle; its Remote Control variant opens the same way). The summary is
// model-written and repeats whatever the earlier turns quoted (a fetched page, a file), so a turn that opens with
// it is never a person's turn.
export const COMPACTION_PREAMBLE = "This session is being continued from a previous conversation that ran out of context.";
export const isCompactionSummary = (t) => String(t).trimStart().startsWith(COMPACTION_PREAMBLE);
// One text → { text, malformed }.
function scan(text) {
  const s = String(text);
  HARNESS_RE.lastIndex = 0;
  let m, first = -1, end = -1;
  const stack = [];
  while ((m = HARNESS_RE.exec(s)) !== null) {
    const closing = m[1] === "/", tag = m[2];
    if (end >= 0) return { text: s.slice(0, first), malformed: false };          // a further harness tag
    if (first < 0) { if (closing) continue; first = m.index; }                 // a close before any block is text
    if (!closing) { stack.push(tag); continue; }
    if (stack[stack.length - 1] !== tag) return { text: s.slice(0, first), malformed: true };   // interleaved
    stack.pop();
    if (!stack.length) end = HARNESS_RE.lastIndex;
  }
  if (first < 0) return { text: s, malformed: false };
  if (end < 0) return { text: s.slice(0, first), malformed: true };             // unclosed
  return { text: s.slice(0, first) + s.slice(end), malformed: false };
}
// A turn's texts → the person's text, joined by newlines; a malformed text ends the turn there.
export function stripTurn(texts) {
  const out = [];
  for (const t of texts) {
    const r = scan(t);
    out.push(r.text);
    if (r.malformed) break;
  }
  return out.join("\n");
}
export const stripHarness = (text) => stripTurn([text]);

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const cut = (s) => (s.length > MAX_TURN ? s.slice(0, MAX_TURN) : s);
const partsText = (content, types) => (typeof content === "string" ? stripHarness(content)
  : Array.isArray(content) ? stripTurn(content.filter((p) => isObj(p) && types.has(p.type) && typeof p.text === "string").map((p) => p.text)) : "");
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
    const t = stripTurn(c.parts.filter((p) => isObj(p) && typeof p.text === "string" && p.thought !== true).map((p) => p.text));
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
  return f && isObj(body) ? f(body).filter((t) => !isCompactionSummary(t)) : [];
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
