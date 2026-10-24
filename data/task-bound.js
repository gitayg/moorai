// Task-bound tool calls — pure part. Two checks on a tool call, both against the task a person gave:
//
//   1. OBJECT CHECK (policy.intentArgs). For a HIGH-IMPACT call, the object of the action — the value of the
//      argument fields that name what the action is done to or sent to — must be named in the task. The task
//      "cut the apple" allows cut({target:"apple"}) and holds cut({target:"hand"}). Class "object-not-in-task".
//   2. TASK ALLOWLISTS (policy.taskAllowlists). When a session's task matches an entry, any tool, or argument
//      value, outside that entry is held at the entry's default ("deny" or "ask"). Class
//      "outside-task-allowlist". The strict mode for physical or high-stakes systems.
//
// Deterministic and lexical: no model guards a model. The caller (data/intent-server.mjs in memory,
// cli/task-bound-hook.mjs on the device) holds the task only as keyed hashes of the terms taskTerms() derives
// — every word, every two- to five-word phrase, every whitespace-delimited token (an address, a path, a URL),
// the host / site / file name inside such a token, and every number — and asks `has(term)` here. The prompt
// and the argument values are never stored or reported.
//
// HIGH-IMPACT (the object check runs only for these):
//   * a tool the policy names in intentArgs (it marks the tool);
//   * an MCP write (mcp__<server>__<tool> whose tool part carries a write verb, data/intent-alignment.js MCP_WRITE);
//   * a function in a business-impact class (model-proxy/business-tools.mjs: money, bulk-data, identity,
//     destructive, delegation);
//   * any other function (not the hook's own tool vocabulary) whose name carries a write verb (send_email,
//     transfer, move_to, create_issue …).
//   The hook's own tools (Bash, Read, Write, WebFetch …) are judged by the existing intent classes (egress,
//   credentials, destructive, moorai-control): never re-judged here unless a policy names them.
//
// OBJECT FIELDS: the keys intentArgs lists for the tool (a dotted key reads a nested field), else the
// built-in DEFAULT_OBJECT_KEYS (recipients, accounts, destinations, paths, URLs, repositories), matched on the
// key with case, `_` and `-` folded. A field the call does not carry is not checked.
//
// MATCHING. Both sides are folded the same way: Unicode NFKC, lower case, punctuation split, the articles
// a / an / the dropped, simple plurals made singular. A text value is named in the task when its whole token
// (an address or path as typed), its word phrase (up to five words), the host or site of a URL, or the file
// name / stem of a path appears in the task, or when a member of its intentArgs.synonyms group does. An e-mail
// address must appear whole. A number (a JSON number, or a string that is only a number with an optional
// currency sign) is named when the same number appears in the task, and is also allowed at or under
// intentArgs.caps["<tool>.<key>"] or intentArgs.caps["<key>"].
//
// POLICY SHAPES (the signed policy, or the root-owned admin binding, which wins key by key; never user state):
//   intentArgs: { "<tool>": ["<key>", …], synonyms: { "<term>": ["<term>", …] }, caps: { "<tool>.<key>" | "<key>": <number> } }
//   taskAllowlists: [{ task: "<name>", match: { keywords: ["…"] } | { taskId: "<id>" },
//                      tools: { "<tool>": true | {} | { args: { "<key>": [<value> | "<glob>" | <number> | { min?, max? }, …] } } },
//                      default: "deny" | "ask" }]
//   Tool names are compared after model-proxy/function-rules.mjs foldName on both sides; for an MCP tool
//   (mcp__<server>__<tool>) the full name is tried first, then the tool part.
//
// TASK ALLOWLIST MATCHING. A keyword entry matches when ANY of its keywords is named in the task (a broader
// match only ever restricts more). A taskId entry matches the session's explicit task id (moorai-serve
// POST /v1/task, the SDK's setTaskId). An explicit task id beats keywords: when an entry names the session's
// task id, only those entries apply; when none does, the keyword entries apply. When several entries apply,
// each judges the call and the strictest outcome wins (deny over ask over allow). An argument value is allowed
// when it equals a listed value (folded), matches a listed glob (`*` any run, `?` one character), equals a
// listed number, or lies in a listed { min, max }; an array value needs every element allowed; an object value
// is never allowed for a listed key. A key the entry does not list is not constrained.
//
// FAIL CLOSED. taskAllowlists that is not an array, or an entry that cannot be read, denies everything it
// would have covered: an entry whose match is unreadable applies to every session, an entry whose tools,
// arguments or default are unreadable denies every call in the sessions it matches. resolveTaskBound reports
// each problem as a fixed token (never a value) so the caller raises an alert. An unreadable intentArgs tool
// entry checks every top-level string or number argument of that tool; an unreadable synonym or cap is
// dropped, which can only hold more.
//
// LIMITS. Token matching is not semantics: "the apple" names "apple" and nothing about what the action does
// to it; a value the user typed is in scope even when the agent was steered into using it; a field the policy
// does not name (and no default covers) is not checked. Browser-safe (no node: imports).
import { siteOf, MCP_WRITE } from "./intent-alignment.js";
import { classifyBusinessTool } from "../model-proxy/business-tools.mjs";
import { foldName } from "../model-proxy/function-rules.mjs";

export const OBJECT_CLASS = "object-not-in-task";
export const ALLOWLIST_CLASS = "outside-task-allowlist";
export const MAX_NGRAM = 5;
export const MAX_VALUE = 512;
export const DEFAULT_OBJECT_KEYS = Object.freeze(["to", "cc", "bcc", "recipient", "recipients", "email", "emails", "phone", "phonenumber",
  "account", "accountid", "accountnumber", "toaccount", "iban", "destination", "path", "filepath", "url", "uri", "webhook", "webhookurl",
  "repo", "repository", "bucket"]);
// The hook's own tool vocabulary: judged by the existing intent classes, not here (unless a policy names one).
const HOOK_TOOLS = new Set(["bash", "powershell", "read", "write", "edit", "multiedit", "notebookedit", "webfetch", "websearch", "glob", "grep",
  "ls", "task", "agent", "todowrite", "monitor", "shell", "exitplanmode", "notebookread", "skill"]);
const RESERVED = new Set(["synonyms", "caps"]);
const ARTICLES = new Set(["a", "an", "the"]);
const DEFAULTS = new Set(["deny", "ask"]);
const RANK = { allow: 0, ask: 1, deny: 2 };
const TASK_ID_RE = /^[A-Za-z0-9._:\-]{1,128}$/;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => isObj(o) && Object.prototype.hasOwnProperty.call(o, k);
const fold = (s) => String(s).normalize("NFKC").toLowerCase();
const foldKey = (k) => fold(k).replace(/[_\-\s]/g, "");

export function singular(w) {
  if (w.length <= 3 || /\d/.test(w)) return w;
  if (w.endsWith("ies") && w.length > 4) return `${w.slice(0, -3)}y`;
  if (/(?:ss|sh|ch|x|z)es$/.test(w)) return w.slice(0, -2);
  if (w.endsWith("s") && !/(?:ss|us|is)$/.test(w)) return w.slice(0, -1);
  return w;
}
export function wordsOf(s) {
  return (fold(s).match(/[\p{L}\p{N}]+/gu) || []).map(singular).filter((w) => !ARTICLES.has(w));
}
const EDGE = /^[\s"'`(\[{<]+|[\s"'`)\]}>.,;:!?]+$/g;
const stripEdge = (s) => s.replace(EDGE, "");
function atomsOf(text) {
  const out = [];
  for (const raw of fold(text).split(/\s+/)) {
    const a = stripEdge(raw);
    if (a && a.length <= MAX_VALUE) out.push(a);
  }
  return out;
}
const URL_RE = /^[a-z][a-z0-9+.-]{0,15}:\/\/(?:[^@\/\s]*@)?(\[[^\]]{1,64}\]|[^\/:?#\s]{1,253})/;
const DOTTED_HOST = /^(?:[a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{0,62}$/;
const EMAIL = /^[^@\s\/]{1,64}@[^@\s\/]{1,253}$/;
const isPathish = (a) => /[\\/]/.test(a) && !URL_RE.test(a);
const baseOf = (a) => a.replace(/[\\/]+$/, "").split(/[\\/]/).pop();
// The host / site / file-name terms inside one token. An e-mail address yields none: it must match whole.
function atomExtras(a) {
  const out = [];
  if (!a || EMAIL.test(a)) return out;
  const u = URL_RE.exec(a);
  const host = u ? u[1] : DOTTED_HOST.test(a) ? a : null;
  if (host) { out.push(`a:${host}`); out.push(`a:${siteOf(host)}`); }
  if (isPathish(a)) {
    const b = baseOf(a);
    if (b) {
      out.push(`a:${b}`);
      const stem = wordsOf(b.replace(/\.[^.]{1,8}$/, ""));
      if (stem.length && stem.length <= MAX_NGRAM) out.push(`w:${stem.join(" ")}`);
    }
  }
  return out;
}
export function canonNumber(s) {
  const t = String(s).replace(/[$€£¥\s]/g, "");
  if (!/^-?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?$/.test(t)) return null;
  const n = Number(t.replace(/,/g, ""));
  return Number.isFinite(n) ? String(n) : null;
}
function numbersIn(text) {
  const out = [];
  for (const m of String(text).matchAll(/\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?/g)) {
    const c = canonNumber(m[0]);
    if (c !== null) out.push(c);
  }
  return out;
}

// The plain terms of a task, most useful first (words, then tokens and numbers, then longer phrases), so a cap
// on how many a caller keeps drops the long phrases first. The caller hashes every term before keeping it.
export function taskTerms(prompt) {
  const text = String(prompt || "").slice(0, 20000);
  const out = [], seen = new Set();
  const add = (t) => { if (!seen.has(t)) { seen.add(t); out.push(t); } };
  const ws = wordsOf(text);
  for (const w of ws) add(`w:${w}`);
  for (const a of atomsOf(text)) { add(`a:${a}`); for (const x of atomExtras(a)) add(x); }
  for (const n of numbersIn(text)) add(`n:${n}`);
  for (let k = 2; k <= MAX_NGRAM; k++) for (let i = 0; i + k <= ws.length; i++) add(`w:${ws.slice(i, i + k).join(" ")}`);
  return out;
}
export const termKey = (term, h) => h(`tb:${term}`);
export const taskIdKey = (id, h) => h(`tb-taskid:${id}`);
export const validTaskId = (id) => typeof id === "string" && TASK_ID_RE.test(id);

// The terms that would name a text value in a task.
export function valueTerms(v) {
  const s = fold(v).trim();
  const out = new Set();
  const a = stripEdge(s);
  if (a && a.length <= MAX_VALUE && !/\s/.test(a)) out.add(`a:${a}`);
  for (const x of atomExtras(a)) out.add(x);
  if (!EMAIL.test(a) && !URL_RE.test(a)) {
    const ws = wordsOf(s);
    if (ws.length && ws.length <= MAX_NGRAM) out.add(`w:${ws.join(" ")}`);
  }
  return [...out];
}
const numberOf = (v) => (typeof v === "number" && Number.isFinite(v) ? String(v) : typeof v === "string" ? canonNumber(v.trim()) : null);

// ---- policy ----

function parseIntentArgs(src, problems) {
  const cfg = { tools: new Map(), groups: [], index: new Map(), caps: new Map() };
  if (src === undefined) return cfg;
  if (!isObj(src)) { problems.push("intentArgs-not-object"); return cfg; }
  for (const [k, v] of Object.entries(src)) {
    if (RESERVED.has(k)) continue;
    const name = foldName(k);
    if (!name) { problems.push("intentArgs-tool-name"); continue; }
    if (Array.isArray(v) && v.length && v.every((x) => typeof x === "string" && x && x.length <= 128)) cfg.tools.set(name, v.slice(0, 64));
    else { problems.push("intentArgs-tool-keys"); cfg.tools.set(name, null); }
  }
  if (src.synonyms !== undefined) {
    if (!isObj(src.synonyms)) problems.push("intentArgs-synonyms");
    else for (const [k, v] of Object.entries(src.synonyms)) {
      if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x && x.length <= MAX_VALUE)) { problems.push("intentArgs-synonyms"); continue; }
      const terms = [...new Set([k, ...v].flatMap(valueTerms))];
      const gi = cfg.groups.push(terms) - 1;
      for (const t of terms) { if (!cfg.index.has(t)) cfg.index.set(t, []); cfg.index.get(t).push(gi); }
    }
  }
  if (src.caps !== undefined) {
    if (!isObj(src.caps)) problems.push("intentArgs-caps");
    else for (const [k, v] of Object.entries(src.caps)) {
      if (typeof v === "number" && Number.isFinite(v) && v >= 0) cfg.caps.set(fold(k), v); else problems.push("intentArgs-caps");
    }
  }
  return cfg;
}

function parseAllowed(list) {
  if (!Array.isArray(list) || !list.length || list.length > 256) return null;
  const out = [];
  for (const x of list) {
    if (typeof x === "number" && Number.isFinite(x)) out.push({ n: x });
    else if (typeof x === "string" && x.length && x.length <= MAX_VALUE) out.push(/[*?]/.test(x) ? { g: fold(x).trim() } : { s: fold(x).trim() });
    else if (isObj(x) && (own(x, "min") || own(x, "max")) && Object.keys(x).every((k) => k === "min" || k === "max")
      && (!own(x, "min") || (typeof x.min === "number" && Number.isFinite(x.min))) && (!own(x, "max") || (typeof x.max === "number" && Number.isFinite(x.max)))) out.push({ min: own(x, "min") ? x.min : -Infinity, max: own(x, "max") ? x.max : Infinity });
    else return null;
  }
  return out;
}
function parseTools(tools) {
  if (!isObj(tools)) return null;
  const out = new Map();
  for (const [k, spec] of Object.entries(tools)) {
    const name = foldName(k);
    if (!name) return null;
    if (spec === true || (isObj(spec) && !Object.keys(spec).length)) { out.set(name, new Map()); continue; }
    if (!isObj(spec) || Object.keys(spec).some((x) => x !== "args") || !isObj(spec.args)) return null;
    const args = new Map();
    for (const [ak, av] of Object.entries(spec.args)) {
      const allowed = parseAllowed(av);
      if (!ak || !allowed) return null;
      args.set(ak, allowed);
    }
    out.set(name, args);
  }
  return out;
}
function parseMatch(m) {
  if (!isObj(m)) return null;
  const keys = Object.keys(m);
  if (keys.length !== 1) return null;
  if (keys[0] === "taskId") return validTaskId(m.taskId) ? { taskId: m.taskId } : null;
  if (keys[0] === "keywords" && Array.isArray(m.keywords) && m.keywords.length && m.keywords.length <= 64 && m.keywords.every((k) => typeof k === "string" && k.trim() && k.length <= 128)) {
    return { keywords: m.keywords.map(valueTerms) };
  }
  return null;
}
const label = (t) => (typeof t === "string" ? t.replace(/[^A-Za-z0-9_.:\- ]/g, "_").slice(0, 64) : "");

function parseAllowlists(src, problems) {
  if (src === undefined || src === null) return [];
  if (!Array.isArray(src)) { problems.push("taskAllowlists-not-array"); return [{ index: 0, task: "", invalid: true, always: true, match: null, tools: null, default: "deny" }]; }
  return src.slice(0, 256).map((e, index) => {
    const match = isObj(e) ? parseMatch(e.match) : null;
    const tools = isObj(e) ? parseTools(e.tools) : null;
    const dflt = isObj(e) && e.default === undefined ? "deny" : isObj(e) && DEFAULTS.has(e.default) ? e.default : null;
    const name = isObj(e) && typeof e.task === "string" && e.task.trim() && e.task.length <= 128 ? label(e.task) : null;
    if (!match) problems.push("taskAllowlists-match");
    if (!tools) problems.push("taskAllowlists-tools");
    if (!dflt) problems.push("taskAllowlists-default");
    if (!name) problems.push("taskAllowlists-task");
    const invalid = !match || !tools || !dflt || !name;
    return { index, task: name || "", invalid, always: !match, match, tools: invalid ? null : tools, default: invalid ? "deny" : dflt };
  });
}

// The effective configuration: the admin binding's key wins over the signed policy's, key by key.
// -> { args, lists, problems: [fixed tokens], configured: { args: bool, lists: bool } }. Cached per object pair.
const CACHE = new WeakMap();
const NONE = {};
export function resolveTaskBound(policy, admin) {
  const p = isObj(policy) ? policy : NONE, a = isObj(admin) ? admin : NONE;
  let byAdmin = CACHE.get(p);
  if (!byAdmin) { byAdmin = new WeakMap(); CACHE.set(p, byAdmin); }
  const hit = byAdmin.get(a);
  if (hit) return hit;
  const problems = [];
  const argsSrc = own(a, "intentArgs") ? a.intentArgs : p.intentArgs;
  const listSrc = own(a, "taskAllowlists") ? a.taskAllowlists : p.taskAllowlists;
  const out = { args: parseIntentArgs(argsSrc, problems), lists: parseAllowlists(listSrc, problems), problems: [...new Set(problems)], configured: { args: argsSrc !== undefined, lists: listSrc !== undefined && listSrc !== null } };
  byAdmin.set(a, out);
  return out;
}

// ---- object check ----

const toolParts = (tool) => {
  const t = String(tool || "");
  if (t.startsWith("mcp__")) { const parts = t.split("__"); return { full: foldName(t), bare: foldName(parts.slice(2).join("__")), mcp: true }; }
  return { full: foldName(t), bare: null, mcp: false };
};
const lookup = (map, tp) => (map.has(tp.full) ? map.get(tp.full) : tp.bare !== null && map.has(tp.bare) ? map.get(tp.bare) : undefined);

export function highImpact(tool, cfg) {
  const tp = toolParts(tool);
  if (cfg && lookup(cfg.tools, tp) !== undefined) return true;
  if (tp.mcp) return Boolean(tp.bare) && MCP_WRITE.test(tp.bare);
  if (!tp.full || HOOK_TOOLS.has(tp.full)) return false;
  return MCP_WRITE.test(tp.full) || classifyBusinessTool(tp.full).length > 0;
}

function getPath(input, key) {
  if (own(input, key)) return input[key];
  if (!key.includes(".")) return undefined;
  let cur = input;
  for (const part of key.split(".")) { if (!own(cur, part)) return undefined; cur = cur[part]; }
  return cur;
}
function fieldsOf(input, keys) {
  const out = [];
  if (keys === null) { // an unreadable intentArgs entry: every top-level string or number argument
    for (const [k, v] of Object.entries(input)) if (typeof v === "string" || typeof v === "number" || Array.isArray(v)) out.push([k, v]);
    return out;
  }
  const folded = new Map(Object.keys(input).map((k) => [foldKey(k), k]));
  for (const key of keys) {
    const v = getPath(input, key);
    if (v !== undefined) { out.push([key, v]); continue; }
    const k = folded.get(foldKey(key));
    if (k !== undefined) out.push([k, input[k]]);
  }
  return out;
}

// The object checks a call needs: null when it is not high-impact or names no object field. Each check:
// { key, kind: "text" | "number", terms: [..], cap?: number, opaque?: true }.
export function objectChecks(tool, input, cfg) {
  if (!isObj(input) || !highImpact(tool, cfg)) return null;
  const tp = toolParts(tool);
  const named = cfg ? lookup(cfg.tools, tp) : undefined;
  const fields = fieldsOf(input, named === undefined ? DEFAULT_OBJECT_KEYS : named);
  const checks = [];
  for (const [key, raw] of fields) {
    for (const v of Array.isArray(raw) ? raw.slice(0, 64) : [raw]) {
      if (v === null || v === undefined || v === "" || typeof v === "boolean") continue;
      const n = numberOf(v);
      if (n !== null) {
        const cap = cfg ? (cfg.caps.get(`${tp.full}.${fold(key)}`) ?? (tp.bare !== null ? cfg.caps.get(`${tp.bare}.${fold(key)}`) : undefined) ?? cfg.caps.get(fold(key))) : undefined;
        checks.push({ key, kind: "number", terms: [`n:${n}`], value: Number(n), ...(cap !== undefined ? { cap } : {}) });
        continue;
      }
      if (typeof v !== "string") { checks.push({ key, kind: "text", terms: [], opaque: true }); continue; }
      let terms = valueTerms(v);
      if (cfg && cfg.groups.length) {
        const gs = new Set(terms.flatMap((t) => cfg.index.get(t) || []));
        for (const g of gs) terms = [...terms, ...cfg.groups[g]];
      }
      checks.push({ key, kind: "text", terms: [...new Set(terms)] });
    }
  }
  return checks.length ? checks : null;
}

// has(term) -> boolean, over the session's task. -> { aligned, unmatched, fields, target }
// target: a stable plain string naming the first unmatched field, for the caller to hash (never reported).
export function judgeObjects(checks, has) {
  let unmatched = 0, target = "";
  for (const c of checks) {
    const named = c.terms.some((t) => has(t));
    const ok = named || (c.kind === "number" && c.cap !== undefined && c.value <= c.cap);
    if (!ok) { unmatched++; if (!target) target = `${c.key}\0${c.terms[0] || "opaque"}`; }
  }
  return { aligned: unmatched === 0, unmatched, fields: checks.length, target };
}

// ---- task allowlists ----

function globMatch(p, s) {
  let i = 0, j = 0, star = -1, mark = 0;
  while (j < s.length) {
    if (i < p.length && (p[i] === "?" || p[i] === s[j])) { i++; j++; }
    else if (i < p.length && p[i] === "*") { star = i++; mark = j; }
    else if (star >= 0) { i = star + 1; j = ++mark; }
    else return false;
  }
  while (i < p.length && p[i] === "*") i++;
  return i === p.length;
}
function scalarAllowed(v, allowed) {
  if (typeof v === "boolean") v = String(v);
  if (typeof v !== "string" && typeof v !== "number") return false;
  const n = numberOf(v);
  const s = typeof v === "string" ? fold(v).trim() : String(v);
  if (s.length > MAX_VALUE * 8) return false;
  return allowed.some((a) => (a.s !== undefined ? a.s === s : a.g !== undefined ? globMatch(a.g, s) : a.n !== undefined ? n !== null && Number(n) === a.n : n !== null && Number(n) >= a.min && Number(n) <= a.max));
}
function valueAllowed(v, allowed) {
  if (v === undefined || v === null) return true;
  if (Array.isArray(v)) return v.length <= 1024 && v.every((x) => !Array.isArray(x) && !isObj(x) && scalarAllowed(x, allowed));
  if (isObj(v)) return false;
  return scalarAllowed(v, allowed);
}
// The outcome of one entry for one call: "allow" or the entry's default, with a fixed reason token.
export function entryOutcome(entry, tool, input) {
  if (entry.invalid) return { outcome: "deny", reason: "invalid-policy" };
  const spec = lookup(entry.tools, toolParts(tool));
  if (spec === undefined) return { outcome: entry.default, reason: "tool-not-listed" };
  const inp = isObj(input) ? input : {};
  for (const [key, allowed] of spec) if (!valueAllowed(getPath(inp, key), allowed)) return { outcome: entry.default, reason: "argument-not-allowed" };
  return { outcome: "allow", reason: "" };
}

// The entries that apply to a session. has(term): the session's task terms (null: no task). hasTaskId(id):
// whether the session's explicit task id is `id` (null: none set).
export function applicableEntries(lists, has, hasTaskId) {
  const always = lists.filter((e) => e.always);
  const byId = hasTaskId ? lists.filter((e) => !e.always && e.match.taskId !== undefined && hasTaskId(e.match.taskId)) : [];
  if (byId.length) return [...always, ...byId];
  const byWord = has ? lists.filter((e) => !e.always && e.match.keywords && e.match.keywords.some((terms) => terms.some((t) => has(t)))) : [];
  return [...always, ...byWord];
}
// Strictest wins. -> null (nothing applies, or every entry allows) | { outcome, reason, task, index, invalid }
export function judgeAllowlists(entries, tool, input) {
  let best = null;
  for (const e of entries) {
    const r = entryOutcome(e, tool, input);
    if (r.outcome === "allow") continue;
    if (!best || RANK[r.outcome] > RANK[best.outcome]) best = { ...r, task: e.task, index: e.index, invalid: e.invalid };
    if (best.outcome === "deny") break;
  }
  return best;
}
export const hasAllowlists = (cfg) => Boolean(cfg && cfg.lists.length);
