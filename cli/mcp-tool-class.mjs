// Default MCP tool policy by class — policy `mcpToolClassDefaults`, with admin overrides in `mcpToolClasses`.
//
//   mcpToolClassDefaults: { read?: V, write?: V, destructive?: V, detokenize?: V, unknown?: V }    V = "allow" | "ask" | "block"
//   mcpToolClasses:       { "<server label>": { "<tool name>": "read" | "write" | "destructive" | "detokenize" } }
//
// Every MCP tool call is put in one of five classes, from the first source that names one:
//   1. override    the admin's mcpToolClasses[server][tool] (signed policy, so trusted: it wins outright);
//   2. annotation  the tool's MCP ToolAnnotations from the server's tools/list (destructiveHint true →
//                  destructive; readOnlyHint false → write; readOnlyHint true → read). Only the explicit
//                  values count: the spec's defaults (readOnlyHint false, destructiveHint true) would make
//                  every unannotated tool destructive. Only the stdio guard and the gateway see a listing,
//                  so the hook classifies by override and name;
//   3. heuristic   the verbs in the tool's name (NAME_VERBS below: any destructive verb → destructive, else
//                  any write verb → write, else any read verb → read), and the detokenize names
//                  (detokenizeName below). A detokenize name is classed detokenize unless its verb class has a
//                  strictly stricter verdict (decrypt_and_delete under destructive "block" stays destructive);
//   4. unknown.
//
// DETOKENIZE. A tool that turns protected data readable: detokenize, decrypt, unseal, unmask, de-anonymize, a
// secret or vault read of a value, a card number read. Access to tokenized or encrypted data together with such
// a tool is access to the readable data, so this class has a BUILT-IN verdict, "ask", that applies with
// mcpToolClassDefaults unset; mcpToolClassDefaults.detokenize replaces it (allow / ask / block), and an
// mcpToolClasses override moves a tool into or out of the class. Annotations never move a detokenize name to a
// class with a looser verdict (on a tie the tool stays detokenize). No other class has a built-in verdict.
//
// ANNOTATIONS ARE UNTRUSTED SERVER CLAIMS. The server being governed writes them, so an annotation can only
// make a tool MORE restricted than the name heuristic says, never less: it is used when the verdict its
// class gets is stricter than the heuristic class's verdict (on a tie, when its class is: read < unknown <
// write < destructive < detokenize), and otherwise the heuristic class stands. A `delete_repo` that says readOnlyHint
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
// Field absent, not an object, or naming no valid verdict → off for read / write / destructive / unknown: no
// surface behaves differently for them. A class whose verdict is missing or not one of the three values gets no
// verdict (allow, as today), except detokenize, which then keeps its built-in "ask".
// Content-free: the alert names the server label, the tool, the class, the verdict and the source.

export const TOOL_CLASSES = ["read", "write", "destructive", "detokenize", "unknown"];
export const BUILT_IN_DEFAULTS = Object.freeze({ detokenize: "ask" });
const VERDICTS = { allow: "allow", ask: "ask", block: "deny" };
const RANK = { allow: 1, ask: 2, deny: 3 };
const CLASS_RANK = { read: 0, unknown: 1, write: 2, destructive: 3, detokenize: 4 };
export const TOOL_CLASS_REASON = "MCP_TOOL_CLASS";

// Exact tokens of the tool name (split on _ - . / space and camelCase), lower-cased.
export const NAME_VERBS = {
  destructive: ["delete", "del", "drop", "remove", "rm", "destroy", "purge", "truncate", "revoke", "force", "wipe", "erase", "unlink", "kill", "terminate"],
  write: ["create", "update", "write", "send", "post", "set", "put", "add", "insert", "edit", "patch", "upload", "push", "move", "rename", "replace", "modify", "append"],
  read: ["get", "list", "read", "search", "describe", "find", "view", "show"]
};
const VERB_SET = Object.fromEntries(Object.entries(NAME_VERBS).map(([k, v]) => [k, new Set(v)]));

// Detokenize names, on the same exact tokens. A verb that makes protected data readable fires alone (also split:
// de_tokenize, re-identify, un_mask). A protected value (secret, password, credential) or a card number (pan, cvv,
// card + number, credit + card) fires only beside a value-read verb, and not when the name asks for a listing or
// metadata (list_secrets, get_secret_metadata) — nor does a bare get_card (a board card, not a payment card).
// vault needs a stronger read verb than get / show / view (get_vault describes a vault). A server label naming a
// secret store (vault, keychain, a password manager) makes a value-read tool of it detokenize (vault/get).
export const DETOKENIZE_NAMES = {
  verbs: ["detokenize", "detokenise", "decrypt", "unseal", "unmask", "unredact", "deanonymize", "deanonymise", "reidentify", "decipher", "unprotect"],
  split: [["de", "tokenize"], ["de", "tokenise"], ["de", "anonymize"], ["de", "anonymise"], ["re", "identify"], ["un", "mask"], ["un", "seal"], ["un", "redact"], ["un", "protect"]],
  valueRead: ["get", "read", "fetch", "retrieve", "reveal", "show", "view", "access", "export", "dump", "copy", "print", "display", "peek", "lookup", "load", "resolve"],
  secret: ["secret", "secrets", "password", "passwords", "passwd", "passphrase", "credential", "credentials"],
  vaultRead: ["read", "fetch", "retrieve", "reveal", "access", "export", "dump"],
  card: ["pan", "cvv", "cvc", "cvv2", "cardnumber", "ccnumber"],
  cardPair: [["card", "number"], ["card", "num"], ["card", "pan"], ["credit", "card"]],
  notValue: ["list", "metadata", "meta", "info", "status", "policy", "policies", "names", "count", "exists", "rotation", "tags"],
  store: ["vault", "secret", "secrets", "secretsmanager", "keyvault", "keychain", "keyring", "password", "passwords", "onepassword", "1password", "bitwarden", "lastpass"]
};
const DT = Object.fromEntries(Object.entries(DETOKENIZE_NAMES).map(([k, v]) => [k, Array.isArray(v[0]) ? v : new Set(v)]));
const hasPair = (toks, pairs) => toks.some((t, i) => pairs.some(([a, b]) => t === a && toks[i + 1] === b));

export function detokenizeName(name, server = "") {
  const toks = nameTokens(name);
  if (toks.some((t) => DT.verbs.has(t)) || hasPair(toks, DT.split)) return true;
  if (!toks.some((t) => DT.valueRead.has(t)) || toks.some((t) => DT.notValue.has(t))) return false;
  if (toks.some((t) => DT.secret.has(t) || DT.card.has(t)) || hasPair(toks, DT.cardPair)) return true;
  if (toks.includes("vault") && toks.some((t) => DT.vaultRead.has(t))) return true;
  return nameTokens(server).some((t) => DT.store.has(t));
}

// The validated class → verdict map the policy sets, or null when it sets none (built-in verdicts not included).
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
  return c === "read" || c === "write" || c === "destructive" || c === "detokenize" ? c : null;
}

// The verdict map every surface applies: the built-in detokenize "ask", then what the policy sets.
export function effectiveClassDefaults(policy) {
  return { ...BUILT_IN_DEFAULTS, ...(toolClassDefaults(policy) || {}) };
}

// The hook names a call mcp__<server>__<tool>; the guard and the gateway pass the bare tool name.
export function bareToolName(tool, server) {
  const t = String(tool || ""), p = `mcp__${server}__`;
  return t.startsWith(p) ? t.slice(p.length) : t;
}

// → { toolClass, source: "override" | "annotation" | "heuristic" }. `annotation`: the class from the tool's
// annotations (annotationClass, or a tracker's strictest), or null.
export function classifyMcpTool(policy, { server, tool, annotation = null, defaults = effectiveClassDefaults(policy) }) {
  const name = bareToolName(tool, server);
  const ov = overrideClass(policy, server, name);
  if (ov) return { toolClass: ov, source: "override" };
  const verb = heuristicClass(name);
  const h = detokenizeName(name, server) && !stricter(verb, "detokenize", defaults || {}) ? "detokenize" : verb;
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
  const defaults = effectiveClassDefaults(policy);
  const rules = policy && policy.mcpToolRules && policy.mcpToolRules[tool];
  if (rules && Array.isArray(rules.allow) && rules.allow.length) return null;
  const { toolClass, source } = classifyMcpTool(policy, { server, tool, annotation, defaults });
  const configured = defaults[toolClass];
  if (!configured) return null;
  const decision = VERDICTS[configured];
  const whose = (toolClassDefaults(policy) || {})[toolClass] ? "your organization's default" : "the built-in default";
  return { toolClass, source, configured, decision, reason: `${bareToolName(tool, server)} is a ${toolClass} MCP tool (${source}); ${whose} for ${toolClass} tools is ${configured}` };
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
