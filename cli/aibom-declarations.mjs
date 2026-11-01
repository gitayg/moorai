// Declared governance for AIBOM items — signed policy `aibomDeclarations` (cli/moorai-aibom.mjs). The admin
// enters, per inventory item, who answers for it, what it is for, what data it may use, how long that data
// is kept and who it is meant for; the AIBOM shows each declaration on the matching entry and flags every
// entry with none, so the gaps are visible. Admin-entered governance metadata, never user or agent content:
// it is read from the policy only and goes into the AIBOM only, never into an alert.
//
// aibomDeclarations: {
//   "<kind>:<name>": { owner?, purpose?, dataUse?, retention?, intendedUsers? }, ...
// }
// kind/name are the console's ownership item identity (RAISEME-server server/ownership.js), plus models:
//   agent  the agent kind, one of cli/agent-names.mjs AGENT_NAMES (claude-code, codex, cursor, ...)
//   mcp    the MCP server label: 1-64 characters, no control or invisible characters, no outer spaces
//   key    <provider>:<h2: fingerprint>, as apiKeysAtRest lists it (provider + keyHash)
//   model  the model id as the AIBOM lists it: 1-256 characters, no control characters
// Each field is a string; owner <= 254, purpose <= 200, dataUse <= 200, retention <= 100, intendedUsers
// <= 200 characters, trimmed, no control characters or line breaks. A field that is absent, null or
// blank declares nothing; an unknown field is ignored. An entry with a bad key, a bad field or no field
// at all is dropped and counted; the rest still apply.
import { AGENT_NAMES } from "./agent-names.mjs";

export const DECLARATION_LIMITS = Object.freeze({ owner: 254, purpose: 200, dataUse: 200, retention: 100, intendedUsers: 200 });
export const DECLARATION_FIELDS = Object.freeze(Object.keys(DECLARATION_LIMITS));
export const DECLARATION_KINDS = Object.freeze(["agent", "mcp", "key", "model"]);
export const DECLARATION_STATUSES = Object.freeze(["declared", "undeclared", "not-declarable"]);
const MCP_LABEL_MAX = 64, MODEL_NAME_MAX = 256;
const CONTROL_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const KEY_ITEM_RE = /^([\w .()+-]{1,64}):(h2:(?:[0-9a-f]{16}|nokey))$/;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const plain = (s, max) => typeof s === "string" && s.length > 0 && [...s].length <= max && !CONTROL_RE.test(s);

export function validItemName(kind, name) {
  if (kind === "agent") return AGENT_NAMES.includes(name);
  if (kind === "mcp") return plain(name, MCP_LABEL_MAX) && name.trim() === name;
  if (kind === "key") return typeof name === "string" && KEY_ITEM_RE.test(name);
  if (kind === "model") return plain(name, MODEL_NAME_MAX);
  return false;
}

// One declaration value → { owner?, ... } with only the fields it sets, or { error }.
export function cleanDeclaration(v) {
  if (!isObj(v)) return { error: "not an object" };
  const out = {};
  for (const f of DECLARATION_FIELDS) {
    const x = v[f];
    if (x === undefined || x === null) continue;
    if (typeof x !== "string") return { error: `${f}: not a string` };
    const t = x.trim();
    if (!t) continue;
    if ([...t].length > DECLARATION_LIMITS[f]) return { error: `${f}: at most ${DECLARATION_LIMITS[f]} characters` };
    if (CONTROL_RE.test(t)) return { error: `${f}: no control characters or line breaks` };
    out[f] = t;
  }
  return Object.keys(out).length ? { declaration: out } : { error: "no field set" };
}

function stderrWarn(m) { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* a warning only */ } }

// → { entries: Map<"<kind>:<name>", declaration>, dropped }. Absent = no declarations, nothing dropped.
export function aibomDeclarations(policy, warn = stderrWarn) {
  const entries = new Map();
  const ad = isObj(policy) ? policy.aibomDeclarations : undefined;
  if (ad === undefined || ad === null) return { entries, dropped: 0 };
  if (!isObj(ad)) { warn("aibomDeclarations ignored: not an object"); return { entries, dropped: 0 }; }
  let dropped = 0, i = -1;
  for (const [k, v] of Object.entries(ad)) {
    i++;
    const sep = k.indexOf(":");
    const kind = sep > 0 ? k.slice(0, sep) : "", name = sep > 0 ? k.slice(sep + 1) : "";
    if (!DECLARATION_KINDS.includes(kind)) { dropped++; warn(`aibomDeclarations entry ${i} dropped: the key is <kind>:<name>, kind one of ${DECLARATION_KINDS.join(", ")}`); continue; }
    if (!validItemName(kind, name)) { dropped++; warn(`aibomDeclarations entry ${i} dropped: not a valid ${kind} name`); continue; }
    const d = cleanDeclaration(v);
    if (d.error) { dropped++; warn(`aibomDeclarations entry ${i} dropped: ${d.error}`); continue; }
    entries.set(k, d.declaration);
  }
  return { entries, dropped };
}

// The AIBOM agent names that have a console agent kind. aider, antigravity, windsurf, kiro and cline have
// none (cli/agent-names.mjs), so the console has no item to declare them under.
const AGENT_KIND = { claude: "claude-code", codex: "codex" };

// The declaration key an AIBOM component would be declared under, or null when the console has no item
// for it (editor extensions, skills, agents with no console agent kind, an MCP name it cannot carry).
export function declarationKey(c) {
  if (!c) return null;
  const k = c.type === "model" ? `model:${c.name}` : c.type === "agent" && AGENT_KIND[c.name] ? `agent:${AGENT_KIND[c.name]}`
    : c.type === "mcp-server" ? `mcp:${c.name}` : null;
  if (!k) return null;
  const sep = k.indexOf(":");
  return validItemName(k.slice(0, sep), k.slice(sep + 1)) ? k : null;
}
export const keyDeclarationKey = (k) => (k && validItemName("key", `${k.provider}:${k.keyHash}`) ? `key:${k.provider}:${k.keyHash}` : null);

function annotate(x, key, entries) {
  if (!key) { x.declarationStatus = "not-declarable"; return; }
  x.declarationKey = key;
  const d = entries.get(key);
  x.declarationStatus = d ? "declared" : "undeclared";
  if (d) x.declared = { ...d };
}

// Sets declarationStatus (+ declarationKey, + declared) on every component and MCP server entry. Keys at
// rest keep their collector shape (cli/aibom-keys.mjs): their declarations are a list of their own,
// one row per distinct key. → { summary: the counts (components; keys on their own), keys }.
export function annotateDeclarations(bom, { entries, dropped }) {
  for (const c of bom.components || []) annotate(c, declarationKey(c), entries);
  for (const s of bom.mcpServers || []) annotate(s, declarationKey({ type: "mcp-server", name: s.name }), entries);
  const keys = [...new Set((bom.apiKeysAtRest || []).map(keyDeclarationKey).filter(Boolean))].map((key) => { const x = {}; annotate(x, key, entries); return x; });
  const n = (list, st) => (list || []).filter((x) => x.declarationStatus === st).length;
  return {
    summary: {
      declared: n(bom.components, "declared"), undeclared: n(bom.components, "undeclared"), notDeclarable: n(bom.components, "not-declarable"),
      apiKeysAtRestDeclared: n(keys, "declared"), apiKeysAtRestUndeclared: n(keys, "undeclared"),
      declarationsInPolicy: entries.size, declarationsDropped: dropped
    },
    keys
  };
}
