// The string fields of a built-in tool's tool_input, made safe to read before the hook judges the call.
// A field the hook (or a helper it hands tool_input to) reads as a string, holding something else, used
// to throw (`text.trim is not a function`, `The "path" argument must be of type string`) and the call
// went ahead unread. Now:
//   * a number, boolean or bigint is coerced with String() and judged as that text (a command 123 is
//     the command "123");
//   * null / absent is left as it was (every reader already treats it as empty);
//   * an object or array where a string is expected is unreadable input: `bad` names the fields and the
//     hook takes its bad-input path (UNEVALUATED_BAD_INPUT, denied under a closed fail mode;
//     cli/hook-fail.mjs).
// Only the built-in tools the hook dispatches on are touched; an MCP tool's arguments are free-form
// (numbers are legitimate there) and are read through JSON.stringify, as before. Never throws.
const FIELDS = {
  Bash: ["command"],
  PowerShell: ["command"],
  Read: ["file_path"],
  Write: ["file_path", "notebook_path", "content"],
  Edit: ["file_path", "notebook_path", "new_string"],
  MultiEdit: ["file_path", "notebook_path"],
  NotebookEdit: ["file_path", "notebook_path", "new_source"],
  WebFetch: ["url", "prompt"],
  WebSearch: ["query"],
  Task: ["prompt", "subagent_type"],
  Agent: ["prompt", "subagent_type"]
};
// MultiEdit: each edit's new_string is the text written.
const EDIT_FIELDS = ["new_string"];

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// → { ok: true, value } (a string, or the original null / undefined) or { ok: false }.
function asText(v) {
  if (v == null || typeof v === "string") return { ok: true, value: v };
  if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return { ok: true, value: String(v) };
  return { ok: false };
}

// → { value, bad: [field, ...], coerced: [field, ...] }. `value` is the original object when nothing
// changed, else a shallow copy with the coerced fields.
export function normalizeToolInput(tool, toolInput) {
  const fields = typeof tool === "string" && own(FIELDS, tool) ? FIELDS[tool] : null;
  if (!fields || !isObj(toolInput)) return { value: toolInput, bad: [], coerced: [] };
  const bad = [], coerced = [];
  let value = toolInput;
  const set = (k, v) => { if (value === toolInput) value = { ...toolInput }; value[k] = v; };
  try {
    for (const k of fields) {
      if (!own(toolInput, k)) continue;
      const t = asText(toolInput[k]);
      if (!t.ok) bad.push(k);
      else if (t.value !== toolInput[k]) { coerced.push(k); set(k, t.value); }
    }
    if (tool === "MultiEdit" && Array.isArray(toolInput.edits)) {
      let edits = null;
      toolInput.edits.forEach((e, i) => {
        if (!isObj(e)) return;
        for (const k of EDIT_FIELDS) {
          if (!own(e, k)) continue;
          const t = asText(e[k]);
          if (!t.ok) bad.push(`edits[${i}].${k}`);
          else if (t.value !== e[k]) {
            coerced.push(`edits[${i}].${k}`);
            if (!edits) edits = toolInput.edits.slice();
            edits[i] = { ...edits[i], [k]: t.value };
          }
        }
      });
      if (edits) set("edits", edits);
    }
  } catch { return { value: toolInput, bad: ["tool_input"], coerced: [] }; }
  return { value, bad, coerced };
}

// The hook's own top-level fields, the same way. Claude Code's envelope types these as strings; one
// holding something else used to throw (`tool.startsWith is not a function` for a numeric tool_name)
// and the call went ahead unread. A number / boolean is judged as its text; an object / array is
// unreadable input (`bad`), and is dropped from `value` so nothing downstream reads it. A payload that
// is not a JSON object at all is unreadable input too (`bad: ["input"]`, `value` {}).
// hook_event_name is the exception: one that is not a string is dropped but NOT bad input. The hook has
// always judged an event it cannot name as a tool call; calling it bad input instead would turn a judged
// call into one allowed unread, with no event to apply a closed fail mode to.
// Only fields the hook reads as strings, and only on the events that read them: `source` (an unknown
// value already means the strictest origin, cli/prompt-scan.mjs), `trigger` (compared to two literals)
// and transcript_path (never read) are left as they are.
const HOOK_FIELDS = ["tool_name", "session_id", "cwd", "agent_id", "agent_type", "permission_mode", "tool_use_id"];
const HOOK_EVENT_FIELDS = { UserPromptSubmit: ["prompt"], Stop: ["last_assistant_message"], SubagentStop: ["last_assistant_message"] };
// The fields whose text is judged. An object there is unreadable input; anywhere else in the envelope it is
// dropped and the call is still judged, so a malformed session_id or cwd never lets a call through unread.
const JUDGED_FIELDS = new Set(["tool_name", "prompt", "last_assistant_message"]);

// → { value, bad: [field, ...], coerced: [field, ...] }. `value` is the original object when nothing
// changed, else a shallow copy. Never throws.
export function normalizeHookInput(input) {
  if (!isObj(input)) return { value: {}, bad: ["input"], coerced: [] };
  const bad = [], coerced = [];
  let value = input;
  const copy = () => { if (value === input) value = { ...input }; return value; };
  try {
    if (own(input, "hook_event_name")) {
      const t = asText(input.hook_event_name);
      if (!t.ok) { delete copy().hook_event_name; coerced.push("hook_event_name"); }
      else if (t.value !== input.hook_event_name) { copy().hook_event_name = t.value; coerced.push("hook_event_name"); }
    }
    const ev = typeof value.hook_event_name === "string" && own(HOOK_EVENT_FIELDS, value.hook_event_name) ? HOOK_EVENT_FIELDS[value.hook_event_name] : [];
    for (const k of [...HOOK_FIELDS, ...ev]) {
      if (!own(input, k)) continue;
      const t = asText(input[k]);
      if (!t.ok) { (JUDGED_FIELDS.has(k) ? bad : coerced).push(k); delete copy()[k]; }
      else if (t.value !== input[k]) { coerced.push(k); copy()[k] = t.value; }
    }
  } catch { return { value: {}, bad: ["input"], coerced: [] }; }
  return { value, bad, coerced };
}
