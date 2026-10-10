// What MoorAI reads from an Inference hooks frame (platform.claude.com/docs/en/manage-claude/
// inference-hooks-endpoint, "The prompt frame", "Content blocks", "The tool call frame").
//
//   prompt frame     every `user` message's blocks, the stages the model proxy uses for the same content:
//                      text         → stage "prompt"
//                      tool_result  → stage "output", ctx {inbound: true} (content fed back to the model)
//                      attachment   → stage "file" (a document the user put into the conversation; its
//                                     extracted `text`, never bytes)
//                    Assistant turns are the model's own output and are not judged here; their tool calls
//                    were judged on the tool call frame that carried them.
//   tool call frame  the last message's `tool_use` blocks, one item per call.
// Unknown block types, roles and fields are skipped, never rejected (the documented forward-compatibility
// rule).
const WEB = { web_fetch: "WebFetch", webfetch: "WebFetch", web_search: "WebSearch", websearch: "WebSearch" };
// The inbound rule set keys on the hook's tool names; claude.ai's own web tools arrive as web_fetch / web_search.
export function inboundTool(name) {
  const n = typeof name === "string" ? name : "";
  return WEB[n.toLowerCase()] || n || "tool_result";
}

const textOf = (content) => {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text).join("\n");
  return "";
};

export function promptItems(frame) {
  const out = [];
  for (const m of Array.isArray(frame && frame.messages) ? frame.messages : []) {
    if (!m || typeof m !== "object" || m.role !== "user") continue;
    const blocks = typeof m.content === "string" ? [{ type: "text", text: m.content }] : Array.isArray(m.content) ? m.content : [];
    for (const b of blocks) {
      if (!b || typeof b !== "object") continue;
      if (b.type === "text" && typeof b.text === "string") out.push({ kind: "prompt", stage: "prompt", ctx: {}, text: b.text });
      else if (b.type === "tool_result") {
        const t = textOf(b.content);
        if (t) out.push({ kind: "tool_result", stage: "output", ctx: { inbound: true, tool: inboundTool(b.tool_name) }, text: t });
      } else if (b.type === "attachment" && typeof b.text === "string" && b.text) out.push({ kind: "attachment", stage: "file", ctx: {}, text: b.text });
    }
  }
  return out;
}

export function toolCalls(frame) {
  const msgs = Array.isArray(frame && frame.messages) ? frame.messages : [];
  const last = msgs[msgs.length - 1];
  if (!last || typeof last !== "object" || !Array.isArray(last.content)) return [];
  return last.content
    .filter((b) => b && typeof b === "object" && b.type === "tool_use")
    .map((b) => ({ name: typeof b.tool_name === "string" ? b.tool_name : "", input: b.input && typeof b.input === "object" && !Array.isArray(b.input) ? b.input : {}, raw: b.input && typeof b.input === "object" && !Array.isArray(b.input) ? null : b.input }));
}
