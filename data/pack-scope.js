// Where a detector-pack detector runs (data/detector-packs.js), for rules written against a named surface
// (Project Quarry's user_messages, tool_responses and call.arguments.command). Each call site that scans
// one of these kinds names it as ctx.scope, and the engine runs a scoped detector only at a call site whose
// ctx.scope is in the detector's list, whatever its stage (src/engine.js _runs):
//   user-prompt  the text a person typed: UserPromptSubmit and each surface's user turn
//   tool-result  the text a tool returned to the agent, and the content of a file a tool reads
//   command      a shell command the agent runs (Bash, PowerShell and the shell calls mapped to them)
export const PACK_SCOPES = Object.freeze(["user-prompt", "tool-result", "command"]);

// undefined: no scope (the detector runs by stage, as before scope existed). An array: the known kinds,
// once each. null: a scope was given and none of its kinds is known here, so the detector is dropped.
export function packScope(v) {
  if (!Array.isArray(v)) return undefined;
  const kinds = PACK_SCOPES.filter((k) => v.includes(k));
  return kinds.length ? kinds : null;
}
