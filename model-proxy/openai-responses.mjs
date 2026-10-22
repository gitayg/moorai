// OpenAI Responses API (POST …/responses), from the official SDK's type definitions (github.com/openai/
// openai-node src/resources/responses/responses.ts, read 2026-10-21; platform.openai.com refuses non-browser
// fetches). What this file knows:
//   request   `instructions` "A system (or developer) message inserted into the model's context" (string);
//             `input` "Text, image, or file inputs to the model": a string, or a list of items:
//               message  {role: 'user' | 'assistant' | 'system' | 'developer', content: string | parts},
//                        parts {type: 'input_text', text} (images and files are not text);
//               function_call_output {call_id, output: string | parts} and custom_tool_call_output
//                        {call_id, output}: a tool's result fed back to the model; so are
//                        local_shell_call_output {id, output: "A JSON string of the output"},
//                        shell_call_output {call_id, output: [{stdout, stderr, outcome}]} and
//                        apply_patch_call_output {call_id, output?}. computer_call_output's output is a
//                        screenshot (image_url or file_id), not text, and is not scanned;
//               function_call / custom_tool_call / assistant messages: the model's own earlier output,
//                        already judged when it was produced, not re-scanned.
//   response  `output[]` items. Decided like any tool call:
//               function_call {call_id, name, arguments} — "A JSON string of the arguments to pass to the
//                        function";
//               custom_tool_call {call_id, name, input} — free text, scanned as {input};
//               mcp_approval_request {id, server_label, name, arguments} — the provider asks the client to
//                        approve a remote MCP call; named mcp__<server_label>__<name> as the hook names it.
//             The provider's built-in tools that the CLIENT runs are decided too, mapped to the hook's tools:
//               local_shell_call {call_id, action: {type: 'exec', command: string[], env, working_directory?}}
//                        — "A tool call to run a command on the local shell": Bash, command = the env
//                        assignments then the argv, joined by spaces;
//               shell_call {call_id, action: {commands: string[]}, environment} — "A tool call that executes
//                        one or more shell commands": Bash, the commands joined by newlines (decided whatever
//                        the environment, a local one or a container);
//               apply_patch_call {call_id, operation: {type: 'create_file' | 'update_file' | 'delete_file',
//                        path, diff?}}: create_file and delete_file as Write {file_path, content: diff or ""},
//                        update_file as Edit {file_path, new_string: diff};
//               computer_call {call_id, action | actions} — "A tool call to a computer use tool": named
//                        computer, its action JSON content-scanned (no hook tool reads clicks and keys).
//             A shell call with no list of command strings, or a patch with an operation not listed here, is
//             kept raw (refused in enforce mode). Other item types (message, reasoning, web_search_call,
//             file_search_call, code_interpreter_call, image_generation_call, and mcp_call, which the
//             provider runs itself) are not run by the client and pass unparsed.
//   stream    server-sent events, `event: <type>` and data {type, sequence_number, …}. A call appears in
//             'response.output_item.added' / '.done' {item, output_index}, in
//             'response.function_call_arguments.delta' {item_id, delta} / '.done' {item_id, arguments}, in
//             'response.custom_tool_call_input.delta' / '.done', in 'response.shell_call_command.added' /
//             '.delta' / '.done' {output_index, command_index, command | delta}, and in the terminal 'response.completed' /
//             'response.incomplete' / 'response.failed' {response}. Every reading of a call is decided, so a
//             client that builds the call from the deltas and one that reads response.completed are judged
//             on what each would run.
//   errors    the Chat Completions error body (openai.mjs errorBody); mid-stream an 'error' event {type:
//             'error', code, message, param, sequence_number}.
export { errorBody } from "./openai.mjs";
import { errorBody as openaiError } from "./openai.mjs";
import { parseArgs } from "./json-strict.mjs";
import { replacementText } from "./report.mjs";
export const NAME = "openai";

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const TEXT_PARTS = new Set(["input_text", "text"]);
const texts = (content) => {
  if (typeof content === "string") return [content];
  if (!Array.isArray(content)) return [];
  return content.filter((p) => isObj(p) && TEXT_PARTS.has(p.type) && typeof p.text === "string").map((p) => p.text);
};
// shell_call_output's output: [{stdout, stderr, outcome}].
const shellTexts = (output) => (Array.isArray(output) ? output.filter(isObj).flatMap((o) => [o.stdout, o.stderr].filter((t) => typeof t === "string" && t)) : []);
const RESULT_TYPES = new Set(["function_call_output", "custom_tool_call_output", "local_shell_call_output", "shell_call_output", "apply_patch_call_output"]);

export function outboundItems(body) {
  const out = [];
  if (!isObj(body)) return out;
  if (typeof body.instructions === "string" && body.instructions) out.push({ kind: "system", stage: "prompt", ctx: {}, context: true, text: body.instructions });
  if (typeof body.input === "string") { if (body.input) out.push({ kind: "prompt", stage: "prompt", ctx: {}, text: body.input }); return out; }
  for (const m of Array.isArray(body.input) ? body.input : []) {
    if (!isObj(m)) continue;
    if (RESULT_TYPES.has(m.type)) {
      const t = (m.type === "shell_call_output" ? shellTexts(m.output) : texts(m.output)).join("\n");
      if (t) out.push({ kind: "tool_result", stage: "output", ctx: { inbound: true }, text: t });
      continue;
    }
    if (m.type !== undefined && m.type !== "message") continue;
    const t = texts(m.content).join("\n");
    if (!t) continue;
    if (m.role === "user") out.push({ kind: "prompt", stage: "prompt", ctx: {}, text: t });
    else if (m.role === "system" || m.role === "developer") out.push({ kind: "system", stage: "prompt", ctx: {}, context: true, text: t });
  }
  return out;
}

// One call → the shape check.mjs decides. A string that is not strict JSON is kept raw (refused in enforce
// mode), as for Chat Completions.
function fromArgs(id, name, args, over = false) {
  const a = typeof args === "string" ? parseArgs(args) : null;
  const ok = Boolean(a && a.ok);
  return { id: String(id || ""), name: String(name || ""), input: ok ? a.value : {}, raw: ok || !args ? null : String(args), ...(a && a.rawReason ? { rawReason: a.rawReason } : {}), ...(a && a.large.length ? { numbers: a.large } : {}), over };
}
const CALL_TYPES = new Set(["function_call", "custom_tool_call", "mcp_approval_request", "local_shell_call", "shell_call", "apply_patch_call", "computer_call"]);
const mcpName = (it) => `mcp__${String(it.server_label || "")}__${String(it.name || "")}`;
const strList = (v) => Array.isArray(v) && v.every((x) => typeof x === "string") ? v : null;
// A client-run built-in tool → kind "tool" (an input object in the hook's vocabulary), or kind "raw" (a
// shape this file cannot read: kept raw, refused in enforce mode).
const raw = (id, name, v, why) => ({ kind: "raw", id, name, raw: JSON.stringify(v ?? null), why });
const shellCmd = (id, cmd) => ({ kind: "tool", id, name: "Bash", tool: { command: cmd } });
function builtIn(it) {
  const id = it.call_id || it.id;
  const a = isObj(it.action) ? it.action : {};
  if (it.type === "local_shell_call") {
    const argv = strList(a.command);
    if (!argv) return raw(id, "Bash", it.action, "local shell call without a list of command strings");
    const env = isObj(a.env) ? Object.entries(a.env).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`) : [];
    return shellCmd(id, [...env, ...argv].join(" "));
  }
  if (it.type === "shell_call") {
    const cmds = strList(a.commands);
    return cmds ? shellCmd(id, cmds.join("\n")) : raw(id, "Bash", it.action, "shell call without a list of command strings");
  }
  if (it.type === "apply_patch_call") {
    const op = isObj(it.operation) ? it.operation : {};
    const path = typeof op.path === "string" && op.path ? op.path : "";
    const diff = typeof op.diff === "string" ? op.diff : "";
    if (path && op.type === "create_file") return { kind: "tool", id, name: "Write", tool: { file_path: path, content: diff } };
    if (path && op.type === "delete_file") return { kind: "tool", id, name: "Write", tool: { file_path: path, content: "" } };
    if (path && op.type === "update_file") return { kind: "tool", id, name: "Edit", tool: { file_path: path, new_string: diff } };
    return raw(id, "apply_patch", it.operation, "apply_patch call with an operation the proxy cannot read");
  }
  const tool = {};
  if (it.action !== undefined) tool.action = it.action;
  if (it.actions !== undefined) tool.actions = it.actions;
  return { kind: "tool", id, name: "computer", tool };
}
// An output item → { id, name, kind: args | input | tool | raw, … } or null.
function callOf(it) {
  if (!isObj(it) || !CALL_TYPES.has(it.type)) return null;
  if (it.type === "function_call") return { kind: "args", id: it.call_id || it.id, name: it.name, args: typeof it.arguments === "string" ? it.arguments : "" };
  if (it.type === "custom_tool_call") return { kind: "input", id: it.call_id || it.id, name: it.name, input: typeof it.input === "string" ? it.input : "" };
  if (it.type === "mcp_approval_request") return { kind: "args", id: it.id, name: mcpName(it), args: typeof it.arguments === "string" ? it.arguments : "" };
  return builtIn(it);
}
function decided(c, over = false) {
  const base = { id: String(c.id || ""), name: String(c.name || "") };
  if (c.kind === "input") return { ...base, input: { input: c.input }, raw: null, over };
  if (c.kind === "tool") return { ...base, input: c.tool, raw: null, over };
  if (c.kind === "raw") return { ...base, input: {}, raw: c.raw, rawReason: c.why, over };
  return fromArgs(c.id, c.name, c.args, over);
}
const variantText = (c) => (c.kind === "input" ? c.input : c.kind === "tool" ? JSON.stringify(c.tool) : c.kind === "raw" ? c.raw : c.args);

export function responseToolCalls(body) {
  const out = [];
  for (const it of isObj(body) && Array.isArray(body.output) ? body.output : []) { const c = callOf(it); if (c) out.push(decided(c)); }
  return out;
}

// Mid-stream refusal: an 'error' event, as the SDK reads ResponseErrorEvent.
export function streamError(status, message) {
  const e = openaiError(status, message).error;
  return Buffer.from(`event: error\ndata: ${JSON.stringify({ type: "error", code: e.code, message, param: null, sequence_number: 0 })}\n\n`);
}

const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };
const TERMINAL = new Set(["response.completed", "response.incomplete", "response.failed"]);
const ARG_EVENTS = { "response.function_call_arguments.delta": ["args", "delta"], "response.function_call_arguments.done": ["args", "arguments"], "response.custom_tool_call_input.delta": ["input", "delta"], "response.custom_tool_call_input.done": ["input", "input"] };
// shell_call commands as streamed: {output_index, command_index} with `command` (added / done) or `delta`.
const SHELL_EVENTS = new Set(["response.shell_call_command.added", "response.shell_call_command.delta", "response.shell_call_command.done"]);
function startsCall(d) {
  if (!isObj(d)) return false;
  if (callOf(d.item)) return true;
  if (typeof d.type === "string" && (ARG_EVENTS[d.type] || SHELL_EVENTS.has(d.type))) return true;
  return isObj(d.response) && Array.isArray(d.response.output) && d.response.output.some((it) => callOf(it));
}

// The streaming state machine. Events are released as they arrive until the first event that carries a
// call (an output item of a call type, an argument or shell-command delta, or a terminal response with a call in its
// output); from there every event is held, in order, until the terminal event (response.completed /
// .incomplete / .failed, or a stray [DONE]). Every distinct reading of each call — the item as added and
// as done, the concatenated deltas, the .done arguments, a shell_call's commands as built from its
// shell_call_command events and as their .done values, the terminal response's output — is decided
// together: all allowed → the held events are released byte-identical; any denied → refused. Observe mode
// (report-only) never holds and never awaits a decision.
export function createStream({ enforce, decide, maxHold }) {
  let hold = null;
  const variant = (h, c) => {
    if (h.variants.size >= 256) { h.over = true; return; }
    h.variants.set(`${c.kind}|${c.id}|${c.name}|${variantText(c)}`, c);
  };
  async function release(extra = []) {
    const h = hold; hold = null;
    for (const it of h.items.values()) if (it.text) variant(h, { kind: it.kind, id: it.id, name: it.name, [it.kind]: it.text });
    for (const [oi, sc] of h.shell) {
      const id = h.outIds.get(oi) || "";
      const idx = [...new Set([...sc.added.keys(), ...sc.delta.keys(), ...sc.done.keys()])].sort((a, b) => a - b);
      const built = idx.map((i) => (sc.added.get(i) || "") + (sc.delta.get(i) || ""));
      if (built.some(Boolean)) variant(h, shellCmd(id, built.join("\n")));
      if (sc.done.size) variant(h, shellCmd(id, idx.map((i, n) => (sc.done.has(i) ? sc.done.get(i) : built[n])).join("\n")));
    }
    const list = [...h.variants.values()].map((c) => decided(c, h.over));
    if (!enforce) { decide(list).catch(() => {}); return { out: [] }; }
    const v = await decide(list);
    return v.decision === "deny" ? { refuse: v } : { out: [...h.raw, ...extra] };
  }
  async function onEvent(ev) {
    if (ev.data === "[DONE]") return hold ? release([ev.raw]) : { out: [ev.raw] };
    const d = parse(ev.data);
    if (!hold && !startsCall(d)) return { out: [ev.raw] };
    if (!hold) hold = { raw: [], bytes: 0, over: false, variants: new Map(), items: new Map(), shell: new Map(), outIds: new Map(), shellBytes: 0 };
    if (enforce) {
      hold.raw.push(ev.raw);
      hold.bytes += ev.raw.length;
      if (hold.bytes > maxHold) { hold.over = true; return release(); }
    }
    if (isObj(d)) {
      const c = callOf(d.item);
      if (c) {
        variant(hold, c);
        if (typeof d.item.id === "string" && !hold.items.has(d.item.id)) hold.items.set(d.item.id, { kind: c.kind, id: c.id, name: c.name, text: "" });
        if (Number.isInteger(d.output_index) && c.id && !hold.outIds.has(d.output_index)) hold.outIds.set(d.output_index, String(c.id));
      }
      if (typeof d.type === "string" && SHELL_EVENTS.has(d.type)) {
        const oi = Number.isInteger(d.output_index) ? d.output_index : -1;
        const ci = Number.isInteger(d.command_index) ? d.command_index : 0;
        const sc = hold.shell.get(oi) || { added: new Map(), delta: new Map(), done: new Map() };
        hold.shell.set(oi, sc);
        const piece = d.type.endsWith(".delta") ? d.delta : d.command;
        if (typeof piece === "string") {
          hold.shellBytes += piece.length;
          if (hold.shellBytes > maxHold) hold.over = true;
          else if (d.type.endsWith(".delta")) sc.delta.set(ci, (sc.delta.get(ci) || "") + piece);
          else (d.type.endsWith(".added") ? sc.added : sc.done).set(ci, piece);
        }
      }
      const ae = typeof d.type === "string" ? ARG_EVENTS[d.type] : null;
      if (ae) {
        const key = String(d.item_id || "");
        const it = hold.items.get(key) || { kind: ae[0], id: key, name: "", text: "" };
        hold.items.set(key, it);
        const piece = d[ae[1]];
        if (typeof piece === "string") {
          if (ae[1] === "delta") { if (it.text.length + piece.length > maxHold) hold.over = true; else it.text += piece; }
          else variant(hold, { kind: it.kind, id: it.id, name: it.name, [it.kind]: piece });
        }
      }
      if (isObj(d.response) && Array.isArray(d.response.output)) for (const it of d.response.output) { const rc = callOf(it); if (rc) variant(hold, rc); }
      if (typeof d.type === "string" && TERMINAL.has(d.type)) return release();
    }
    return { out: [] };
  }
  // The upstream ended while a call was held: decided for the report, never released in enforce mode.
  async function onEnd() {
    if (!hold) return { out: [] };
    const name = [...hold.variants.values()].map((c) => c.name).find(Boolean) || "";
    const r = await release();
    return enforce ? { refuse: { decision: "deny", denied: [{ name, reasons: ["the stream ended inside the tool call"] }] } } : r;
  }
  return { onEvent, onEnd, get holding() { return hold !== null; } };
}

// --denied-tool-call replace, non-streaming: every call item of the response is withheld and the refusal
// is added as an assistant message, so no call_id is left without its call and the SDK reads a plain text
// turn. A stream in replace mode is refused (createReplaceStream is the refusing machine): rewriting the
// Responses event sequence (output indexes, sequence numbers, item ids) is not implemented.
export function replaceResponse(body, verdict) {
  const output = Array.isArray(body.output) ? body.output : [];
  const total = output.filter((it) => callOf(it)).length;
  const text = replacementText(verdict, total);
  return { ...body, output: [...output.filter((it) => !callOf(it)), { type: "message", id: "msg_moorai_withheld", status: "completed", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] }] };
}
export const createReplaceStream = (o) => createStream({ ...o, enforce: true });
