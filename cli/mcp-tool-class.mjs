// Default MCP tool policy by class — policy `mcpToolClassDefaults`, with admin overrides in `mcpToolClasses`.
//
//   mcpToolClassDefaults: { read?: V, write?: V, destructive?: V, unknown?: V }    V = "allow" | "ask" | "block"
//   mcpToolClasses:       { "<server label>": { "<tool name>": "read" | "write" | "destructive" } }
//
// Every MCP tool call is put in one of four classes, from the first source that names one:
//   1. override    the admin's mcpToolClasses[server][tool] (signed policy, so trusted: it wins outright);
//   2. annotation  the tool's MCP ToolAnnotations from the server's tools/list (destructiveHint true →
//                  destructive; readOnlyHint false → write; readOnlyHint true → read). Only the explicit
//                  values count: the spec's defaults (readOnlyHint false, destructiveHint true) would make
//                  every unannotated tool destructive. Only the stdio guard and the gateway see a listing,
//                  so the hook classifies by override and name;
//   3. heuristic   the verbs in the tool's name (NAME_VERBS below: any destructive verb → destructive, else
//                  any write verb → write, else any read verb → read);
//   4. unknown.
//
// ANNOTATIONS ARE UNTRUSTED SERVER CLAIMS. The server being governed writes them, so an annotation can only
// make a tool MORE restricted than the name heuristic says, never less: it is used when the verdict its
// class gets is stricter than the heuristic class's verdict (on a tie, when its class is: read < unknown <
// write < destructive), and otherwise the heuristic class stands. A `delete_repo` that says readOnlyHint
// true stays destructive; a `get_report` that says destructiveHint true becomes destructive. The guard and
// the gateway keep the strictest annotation class each tool name has shown in this process, so a server
// cannot loosen a tool by listing it again (a changed annotation is also schema drift, #25).
//
// The class verdict is the LAST word only where nothing more specific spoke: it is merged by rank with the
// surface's own verdict (the stricter wins), so a server allow-list, entitlement, argument-rule, profile or
// detector deny still denies, and a class "block" still blocks a call a detector only asked about. One
// explicit allow outranks it: a tool with an mcpToolRules allow-list (the call reached here, so its
// arguments matched one) is the admin's own rule for that tool and gets no class verdict. "ask" follows each
// surface's ask: the hook asks the user (server mode settles it, deny by default); the stdio guard forwards
// and records; the gateway forwards and records, and in server mode settles it like the hook.
//
// Field absent, not an object, or naming no valid verdict → off: no surface behaves differently. A class
// whose verdict is missing or not one of the three values gets no verdict (allow, as today).
// Content-free: the alert names the server label, the tool, the class, the verdict and the source.

export const TOOL_CLASSES = ["read", "write", "destructive", "unknown"];
const VERDICTS = { allow: "allow", ask: "ask", block: "deny" };
const RANK = { allow: 1, ask: 2, deny: 3 };
const CLASS_RANK = { read: 0, unknown: 1, write: 2, destructive: 3 };
export const TOOL_CLASS_REASON = "MCP_TOOL_CLASS";

// Exact tokens of the tool name (split on _ - . / space and camelCase), lower-cased.
export const NAME_VERBS = {
  destructive: ["delete", "del", "drop", "remove", "rm", "destroy", "purge", "truncate", "revoke", "force", "wipe", "erase", "unlink", "kill", "terminate"],
  write: ["create", "update", "write", "send", "post", "set", "put", "add", "insert", "edit", "patch", "upload", "push", "move", "rename", "replace", "modify", "append"],
  read: ["get", "list", "read", "search", "describe", "find", "view", "show"]
};
const VERB_SET = Object.fromEntries(Object.entries(NAME_VERBS).map(([k, v]) => [k, new Set(v)]));

// The validated class → verdict map, or null when the policy does not set one (off).
export function toolClassDefaults(policy) {
  const raw = policy && policy.mcpToolClassDefaults;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const out = {};
  for (const c of TOOL_CLASSES) if (typeof raw[c] === "string" && Object.prototype.hasOwnProperty.call(VERDICTS, raw[c])) out[c] = raw[c];
  return Object.keys(out).length ? out : null;
}

export function nameTokens(name) {
  return String(name || "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

export function heuristicClass(name) {
  const toks = nameTokens(name);
  for (const c of ["destructive", "write", "read"]) if (toks.some((t) => VERB_SET[c].has(t))) return c;
  return "unknown";
}

// One tool's ToolAnnotations → its class, or null when it states none.
export function annotationClass(a) {
  if (!a || typeof a !== "object" || Array.isArray(a)) return null;
  if (a.destructiveHint === true) return "destructive";
  if (a.readOnlyHint === false) return "write";
  if (a.readOnlyHint === true) return "read";
  return null;
}

function overrideClass(policy, server, tool) {
  const m = policy && policy.mcpToolClasses;
  const per = m && typeof m === "object" && !Array.isArray(m) ? m[server] : null;
  if (!per || typeof per !== "object" || Array.isArray(per) || !Object.prototype.hasOwnProperty.call(per, tool)) return null;
  const c = per[tool];
  return c === "read" || c === "write" || c === "destructive" ? c : null;
}

// The hook names a call mcp__<server>__<tool>; the guard and the gateway pass the bare tool name.
export function bareToolName(tool, server) {
  const t = String(tool || ""), p = `mcp__${server}__`;
  return t.startsWith(p) ? t.slice(p.length) : t;
}

// → { toolClass, source: "override" | "annotation" | "heuristic" }. `annotation`: the class from the tool's
// annotations (annotationClass, or a tracker's strictest), or null.
export function classifyMcpTool(policy, { server, tool, annotation = null, defaults = toolClassDefaults(policy) }) {
  const name = bareToolName(tool, server);
  const ov = overrideClass(policy, server, name);
  if (ov) return { toolClass: ov, source: "override" };
  const h = heuristicClass(name);
  if (annotation && CLASS_RANK[annotation] !== undefined && stricter(annotation, h, defaults || {})) return { toolClass: annotation, source: "annotation" };
  return { toolClass: h, source: "heuristic" };
}

function stricter(a, b, defaults) {
  const ra = RANK[VERDICTS[defaults[a]] || "allow"], rb = RANK[VERDICTS[defaults[b]] || "allow"];
  return ra !== rb ? ra > rb : CLASS_RANK[a] > CLASS_RANK[b];
}

// The class verdict for one MCP call → null (off, an explicit argument allow-list for the tool, or no
// verdict for its class) or { toolClass, source, configured, decision: "allow"|"ask"|"deny", reason }.
// `tool` is the name the surface passes to mcpGateway (so the mcpToolRules key matches).
export function decideMcpToolClass(policy, { tool, server, annotation = null }) {
  const defaults = toolClassDefaults(policy);
  if (!defaults) return null;
  const rules = policy.mcpToolRules && policy.mcpToolRules[tool];
  if (rules && Array.isArray(rules.allow) && rules.allow.length) return null;
  const { toolClass, source } = classifyMcpTool(policy, { server, tool, annotation, defaults });
  const configured = defaults[toolClass];
  if (!configured) return null;
  const decision = VERDICTS[configured];
  return { toolClass, source, configured, decision, reason: `${bareToolName(tool, server)} is a ${toolClass} MCP tool (${source}); your organization's default for ${toolClass} tools is ${configured}` };
}

// The content-free alert for a call the class verdict decided. `decision`: what the call finally got
// (deny, ask, coach, or allow when server mode's headlessAsk allowed it with a report).
export function toolClassAlert(tc, { tool, server, toolPrefix, decision }) {
  return {
    threatId: 0, category: tc.decision === "deny" ? "MCP: tool blocked by class default" : "MCP: tool held by class default",
    riskLevel: decision === "deny" ? "Blocked" : "Medium", stage: "mcp", tool: `${toolPrefix}:${tool}`, decision,
    reasonCode: TOOL_CLASS_REASON, toolClass: tc.toolClass, toolClassSource: tc.source,
    ...(server ? { mcpServer: server } : {}), contentHash: `mcp:tool-class:${tc.toolClass}:${tc.configured}`
  };
}

// Per guarded server: the strictest annotation class each tool name has advertised (bounded, in memory).
export function createAnnotationClasses(max = 4096) {
  const m = new Map();
  function observe(tools) {
    for (const t of tools || []) {
      if (!t || typeof t !== "object" || typeof t.name !== "string") continue;
      const c = annotationClass(t.annotations);
      if (!c) continue;
      const prev = m.get(t.name);
      if (prev && CLASS_RANK[prev] >= CLASS_RANK[c]) continue;
      if (!prev && m.size >= max) m.delete(m.keys().next().value);
      m.set(t.name, c);
    }
  }
  return { observe, get: (name) => m.get(String(name)) || null };
}
