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
// OBJECT FIELDS: the keys intentArgs lists for the tool, else the built-in DEFAULT_OBJECT_KEYS (recipients,
// accounts, destinations, paths, URLs, repositories). Every argument key that equals a listed key after
// folding case, `_`, `-` and spaces is read (`to` and `To` both), and a dotted key is read both as the
// literal key ("a.b") and as the nested field (a → b), with the same folding at each level: every value
// found must be named. A field the call does not carry is not checked.
//
// MATCHING. Both sides are folded the same way: Unicode NFKC, lower case, punctuation split, the articles
// a / an / the dropped, simple plurals made singular. A text value is named in the task when its whole token
// (an address or path as typed), its word phrase (up to five words, never across `. ! ? ; : ,` or a line break
// in the task), the host or site of a URL, or the file name / stem of a path appears in the task, or when a
// member of its intentArgs.synonyms group does (a group is keyed and expanded on whole values only, never on a
// host, site or file name inside one). An e-mail address must appear whole. A URL's host is WHATWG URL
// parsing's (`new URL().hostname`, punycode for an IDN), read from the raw value, and only when the token
// reading (userinfo stopping at `\`, `#`, `?`) gives the same host; a URL the parser refuses or reads otherwise
// names nothing, and a scheme-less value led by a dotted host (`evil.com/apple`, `//evil.com/x`) is a URL, not a
// path. A value with a control or format character names nothing; a path with a `..` segment (raw or
// percent-encoded) names only itself, never by its file name. A number (a JSON number, or a string that is only
// a number with an optional currency sign and no leading zeros) is named when the same number appears in the
// task, and a non-negative one is also allowed at or under intentArgs.caps["<tool>.<key>"] or
// intentArgs.caps["<key>"]; a negative amount is never under a cap.
//
// POLICY SHAPES (the signed policy, or the root-owned admin binding, which wins key by key; never user state):
//   intentArgs: { "<tool>": ["<key>", …], synonyms: { "<term>": ["<term>", …] }, caps: { "<tool>.<key>" | "<key>": <number> } }
//   taskAllowlists: [{ task: "<name>", match: { keywords: ["…"] } | { taskId: "<id>" },
//                      tools: { "<tool>": true | {} | { args: { "<key>": [<value> | "<glob>" | <number> | { min?, max? }, …] } } },
//                      default: "deny" | "ask", unlistedArgs: "deny" | "allow", foldArgs: ["<key>", …] }]
//   intentArgs tool names are compared after model-proxy/function-rules.mjs foldName on both sides; for an MCP
//   tool the full name is tried first, then the tool part (marking more tools only checks more). taskAllowlists
//   tool names are EXACT: as written, case-sensitive, and an MCP tool only by its full mcp__<server>__<tool>
//   name, so another server's tool of the same name, or another casing, is not listed.
//
// TASK ALLOWLIST MATCHING. A keyword entry matches when ANY of its keywords is named in the task (a broader
// match only ever restricts more). A taskId entry matches the session's explicit task id (moorai-serve
// POST /v1/task, the SDK's setTaskId). A task id only ADDS entries: the entries it selects apply together with
// the keyword-matched ones, so whoever sets an id cannot pick a weaker entry in place of a stricter one. When
// several entries apply, each judges the call and the strictest outcome wins (deny over ask over allow). An
// argument value is allowed when it equals a listed value exactly as the tool receives it (raw: no case or
// Unicode folding, no trimming; only keys the entry lists in foldArgs compare folded), matches a listed glob
// (`?` one character and `*` any run, neither crossing `/` or `\`; `**` any run across segments), equals a
// listed number, or lies in a listed { min, max } (min defaults to 0, so a negative needs an explicit min). A
// number is a JSON number or a string that is exactly a plain decimal (no spaces, grouping, currency, exponent,
// hex or leading zeros). A string with a `..` segment (on `/` or `\`, raw or percent-decoded up to three
// rounds), or a control or format character (raw or decoded, NUL included), is never allowed. An array value
// needs every element allowed; an object value is never allowed for a listed key. ARGUMENT KEYS: a listed dotted key is read both as the literal key
// ("a.b") and as the nested field (a → b); each one present must be allowed. A call carrying a key that
// equals a listed key (or, inside a listed dotted path, a segment) only after folding case, `_`, `-` and
// spaces is held ("argument-key-collision"): a tool could read `Target` where the entry checked `target`.
// unlistedArgs (per entry, "deny" default | "allow"): with "deny", an argument the entry's tool spec does not
// list (top level, or under a listed dotted path) is held ("argument-not-listed"); a tool listed as true or
// {} still takes any arguments.
//
// MATCHED ENTRIES are recorded at capture (entriesNamedIn, over the WHOLE prompt, not the capped term set)
// by the entry's own text (entry.key), so a long prompt cannot push a selecting keyword out of the term cap.
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
const UNLISTED = new Set(["deny", "allow"]);
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
// Whitespace-delimited tokens AS TYPED (not folded): a URL is parsed from the raw text, since NFKC folding can
// turn a character the URL parser does not treat as a separator (a fullwidth solidus) into one that it does.
function atomsOf(text) {
  const out = [];
  for (const raw of String(text).split(/\s+/)) {
    const a = stripEdge(raw);
    if (a && a.length <= MAX_VALUE) out.push(a);
  }
  return out;
}
// A URL's host is what WHATWG URL parsing (fetch, and most tools) says, and only when this regex reads the same
// host: the userinfo stops at `\`, `#` and `?`, and the host stops at `\` and `@` too, so the two can only agree on
// the host the request really goes to. Disagreement, or a value the parser refuses, names nothing.
const URL_RE = /^([a-z][a-z0-9+.-]{0,15}):\/\/(?:[^@\/\\\s#?]*@)?(\[[^\]\/\\]{1,64}\]|[^\/\\:?#@\s]{1,253})/i;
const DOTTED_HOST = /^(?:[\p{L}\p{N}_-]{1,63}\.)+[\p{L}][\p{L}\p{N}-]{0,62}$/u;
// A scheme-less value led by a dotted host and a path, query or fragment (`evil.com/apple`): read as a URL.
const HOST_LED = /^((?:[\p{L}\p{N}_-]{1,63}\.)+[\p{L}][\p{L}\p{N}-]{0,62})(?::\d{1,5})?(?=[\/?#])/u;
const EMAIL = /^[^@\s\/\\]{1,64}@[^@\s\/\\]{1,253}$/;
const CONTROL = /[\p{Cc}\p{Cf}]/u;
function canonHost(h) { try { return new URL(`http://${h}/`).hostname || null; } catch { return null; } }
// -> null (not URL-shaped) | { host } | { refuse: true }
function urlOf(raw) {
  const s = raw.startsWith("//") ? `https:${raw}` : raw;
  const m = URL_RE.exec(s);
  const led = m ? null : HOST_LED.exec(s);
  if (!m && !led) return null;
  let parsed;
  try { parsed = new URL(m ? s : `http://${s}`); } catch { return { refuse: true }; }
  const host = canonHost(m ? m[2] : led[1]);
  return host && parsed.hostname === host ? { host } : { refuse: true };
}
// The percent-decoded forms of a value (up to three rounds), so `%2e%2e` and `%252e%252e` are seen as `..`.
function decodedForms(s) {
  const out = [s];
  let cur = s;
  for (let i = 0; i < 3; i++) {
    let d;
    try { d = decodeURIComponent(cur); } catch { break; }
    if (d === cur) break;
    out.push(d);
    cur = d;
  }
  return out;
}
// A `..` path segment (on `/` or `\`), or a control or format character, in the value or a decoded form of it.
export const unsafeValue = (s) => decodedForms(String(s)).some((x) => CONTROL.test(x) || x.split(/[\\/]/).includes(".."));
const isPathish = (a) => /[\\/]/.test(a);
const baseOf = (a) => a.replace(/[\\/]+$/, "").split(/[\\/]/).pop();
// The host / site / file-name terms inside one raw token. An e-mail address yields none: it must match whole.
// refuse: a URL-shaped token whose host the parser and this reading do not agree on (or that does not parse).
function atomExtras(a) {
  const out = [];
  if (!a || EMAIL.test(a)) return { terms: out, url: false };
  const u = urlOf(a);
  if (u && u.refuse) return { terms: out, url: true, refuse: true };
  const host = u ? u.host : DOTTED_HOST.test(a) ? canonHost(a) : null;
  if (host) { out.push(`a:${host}`); out.push(`a:${siteOf(host)}`); }
  if (!u && isPathish(a) && !unsafeValue(a)) {
    const b = baseOf(a);
    if (b) {
      out.push(`a:${fold(b)}`);
      const stem = wordsOf(b.replace(/\.[^.]{1,8}$/, ""));
      if (stem.length && stem.length <= MAX_NGRAM) out.push(`w:${stem.join(" ")}`);
    }
  }
  return { terms: out, url: Boolean(u) };
}
// Sentences and clauses: phrases are never formed across `. ! ? ; : ,` (followed by a space or the end) or a line break.
const segmentsOf = (text) => String(text).split(/[.!?;:,]+(?=\s|$)|[\r\n]+/);
export function canonNumber(s) {
  const t = String(s).replace(/[$€£¥\s]/g, "");
  if (!/^-?(?:[1-9]\d{0,2}(?:,\d{3})+|0|[1-9]\d*)(?:\.\d+)?$/.test(t)) return null;
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
  for (const w of wordsOf(text)) add(`w:${w}`);
  for (const a of atomsOf(text)) { add(`a:${fold(a)}`); for (const x of atomExtras(a).terms) add(x); }
  for (const n of numbersIn(text)) add(`n:${n}`);
  const segs = segmentsOf(text).map(wordsOf);
  for (let k = 2; k <= MAX_NGRAM; k++) for (const ws of segs) for (let i = 0; i + k <= ws.length; i++) add(`w:${ws.slice(i, i + k).join(" ")}`);
  return out;
}
export const termKey = (term, h) => h(`tb:${term}`);
export const taskIdKey = (id, h) => h(`tb-taskid:${id}`);
export const validTaskId = (id) => typeof id === "string" && TASK_ID_RE.test(id);

// The terms that would name a text value in a task. None for a value carrying a control or format character,
// or a URL whose host the parser and the token reading disagree on; only the whole token for a path with a
// `..` segment (raw or percent-encoded).
export function valueTerms(v) {
  const raw = String(v).trim();
  if (CONTROL.test(raw) || decodedForms(raw).some((x) => CONTROL.test(x))) return [];
  const out = new Set();
  const a = stripEdge(raw);
  const x = atomExtras(a);
  if (x.refuse) return [];
  if (a && a.length <= MAX_VALUE && !/\s/.test(a)) out.add(`a:${fold(a)}`);
  for (const t of x.terms) out.add(t);
  if (!EMAIL.test(a) && !x.url && !unsafeValue(raw)) {
    const ws = wordsOf(raw);
    if (ws.length && ws.length <= MAX_NGRAM) out.add(`w:${ws.join(" ")}`);
  }
  return [...out];
}
// The terms that name a value as a whole (its token and its phrase): what a synonym group is keyed and expanded on.
const wholeTerms = (v) => valueTerms(v).filter((t) => t === `a:${fold(stripEdge(String(v).trim()))}` || t === `w:${wordsOf(String(v).trim()).join(" ")}`);
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
      const terms = [...new Set([k, ...v].flatMap(wholeTerms))];
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

// A listed value: a number { n }, a { min, max } range (min defaults to 0, so a negative amount needs an explicit
// min), an exact string { s } or a glob { g }. Strings are kept raw and folded, each compiled once.
function parseAllowed(list) {
  if (!Array.isArray(list) || !list.length || list.length > 256) return null;
  const out = [];
  for (const x of list) {
    if (typeof x === "number" && Number.isFinite(x)) out.push({ n: x });
    else if (typeof x === "string" && x.length && x.length <= MAX_VALUE) out.push(/[*?]/.test(x) ? { g: compileGlob(x), gf: compileGlob(fold(x)) } : { s: x, sf: fold(x) });
    else if (isObj(x) && (own(x, "min") || own(x, "max")) && Object.keys(x).every((k) => k === "min" || k === "max")
      && (!own(x, "min") || (typeof x.min === "number" && Number.isFinite(x.min))) && (!own(x, "max") || (typeof x.max === "number" && Number.isFinite(x.max)))) out.push({ min: own(x, "min") ? x.min : 0, max: own(x, "max") ? x.max : Infinity });
    else return null;
  }
  return out;
}
function parseTools(tools) {
  if (!isObj(tools)) return null;
  const out = new Map();
  for (const [k, spec] of Object.entries(tools)) {
    const name = k; // exact: a tool name is matched as written, never folded or by its bare MCP part
    if (!name || name.length > 256) return null;
    if (spec === true || (isObj(spec) && !Object.keys(spec).length)) { out.set(name, { any: true, args: new Map() }); continue; }
    if (!isObj(spec) || Object.keys(spec).some((x) => x !== "args") || !isObj(spec.args)) return null;
    const args = new Map();
    for (const [ak, av] of Object.entries(spec.args)) {
      const allowed = parseAllowed(av);
      if (!ak || !allowed) return null;
      args.set(ak, allowed);
    }
    out.set(name, { any: false, args, tree: keyTree([...args.keys()]) });
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
  if (!Array.isArray(src)) { problems.push("taskAllowlists-not-array"); return [{ index: 0, key: "", task: "", invalid: true, always: true, match: null, tools: null, default: "deny", unlisted: "deny", foldArgs: new Set() }]; }
  return src.slice(0, 256).map((e, index) => {
    const match = isObj(e) ? parseMatch(e.match) : null;
    const tools = isObj(e) ? parseTools(e.tools) : null;
    const dflt = isObj(e) && e.default === undefined ? "deny" : isObj(e) && DEFAULTS.has(e.default) ? e.default : null;
    const name = isObj(e) && typeof e.task === "string" && e.task.trim() && e.task.length <= 128 ? label(e.task) : null;
    const unlisted = isObj(e) && e.unlistedArgs === undefined ? "deny" : isObj(e) && UNLISTED.has(e.unlistedArgs) ? e.unlistedArgs : null;
    if (!unlisted) problems.push("taskAllowlists-unlistedArgs");
    const foldArgs = isObj(e) && e.foldArgs === undefined ? new Set() : isObj(e) && Array.isArray(e.foldArgs) && e.foldArgs.length <= 64 && e.foldArgs.every((k) => typeof k === "string" && k) ? new Set(e.foldArgs) : null;
    if (!foldArgs) problems.push("taskAllowlists-foldArgs");
    if (!match) problems.push("taskAllowlists-match");
    if (!tools) problems.push("taskAllowlists-tools");
    if (!dflt) problems.push("taskAllowlists-default");
    if (!name) problems.push("taskAllowlists-task");
    const invalid = !match || !tools || !dflt || !name || !unlisted || !foldArgs;
    let key = "";
    try { key = JSON.stringify(e) || ""; } catch { key = ""; }
    return { index, key, task: name || "", invalid, always: !match, match, tools: invalid ? null : tools, default: invalid ? "deny" : dflt, unlisted: unlisted || "deny", foldArgs: foldArgs || new Set() };
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

// Every value an argument key can name: the key itself and every key equal to it after folding, at the top
// level; for a dotted key also the nested field, segment by segment, with the same folding at each level.
// -> { values, collision } (collision: some key matched only after folding).
export function collectKey(input, key) {
  const values = [];
  let collision = false;
  const take = (obj, k0) => {
    const out = [];
    if (!isObj(obj)) return out;
    const f = foldKey(k0);
    for (const k of Object.keys(obj)) {
      if (k === k0) out.push(obj[k]);
      else if (foldKey(k) === f) { collision = true; out.push(obj[k]); }
    }
    return out;
  };
  values.push(...take(input, key));
  if (key.includes(".")) {
    let level = [input];
    for (const seg of key.split(".")) level = level.flatMap((o) => take(o, seg));
    values.push(...level);
  }
  return { values: values.filter((v) => v !== undefined), collision };
}
// The listed keys as a tree: a literal key at the top level, and each dotted key as nested segments. A listed
// key is always a leaf (whatever the order): a dotted key that runs below a leaf is cut off there, and none of
// its later segments is attached anywhere.
const LEAF = Symbol("leaf");
function keyTree(keys) {
  const root = new Map();
  for (const k of keys) root.set(k, LEAF);
  for (const k of keys) {
    if (!k.includes(".")) continue;
    const segs = k.split(".");
    let node = root;
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      if (i === segs.length - 1) { node.set(seg, LEAF); break; }
      const next = node.get(seg);
      if (next === LEAF) break;
      if (next) { node = next; continue; }
      const made = new Map();
      node.set(seg, made);
      node = made;
    }
  }
  return root;
}
// "argument-key-collision" | "argument-not-listed" | "" for the keys of input against the tree.
function walkKeys(obj, node, unlistedDeny) {
  const folded = new Map([...node.keys()].map((k) => [foldKey(k), k]));
  for (const [k, v] of Object.entries(obj)) {
    if (!node.has(k)) {
      if (folded.has(foldKey(k))) return "argument-key-collision";
      if (unlistedDeny) return "argument-not-listed";
      continue;
    }
    const child = node.get(k);
    if (child === LEAF || v === undefined || v === null) continue;
    if (!isObj(v)) { if (unlistedDeny) return "argument-not-listed"; continue; }
    const r = walkKeys(v, child, unlistedDeny);
    if (r) return r;
  }
  return "";
}
function fieldsOf(input, keys) {
  const out = [];
  if (keys === null) { // an unreadable intentArgs entry: every top-level string or number argument
    for (const [k, v] of Object.entries(input)) if (typeof v === "string" || typeof v === "number" || Array.isArray(v)) out.push([k, v]);
    return out;
  }
  for (const key of keys) for (const v of collectKey(input, key).values) out.push([key, v]);
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
      if (cfg && cfg.groups.length && terms.length) {
        const gs = new Set(wholeTerms(v).flatMap((t) => cfg.index.get(t) || []));
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
    const ok = named || (c.kind === "number" && c.cap !== undefined && c.value >= 0 && c.value <= c.cap);
    if (!ok) { unmatched++; if (!target) target = `${c.key}\0${c.terms[0] || "opaque"}`; }
  }
  return { aligned: unmatched === 0, unmatched, fields: checks.length, target };
}

// ---- task allowlists ----

// Globs: `?` one character and `*` any run, neither crossing `/` or `\`; `**` any run across segments. Matched
// position by position over the compiled tokens: linear in the value for each token, no backtracking.
const isSep = (c) => c === "/" || c === "\\";
function compileGlob(p) {
  const t = [];
  for (let i = 0; i < p.length; i++) {
    if (p[i] === "*") { if (p[i + 1] === "*") { t.push("**"); while (p[i + 1] === "*") i++; } else t.push("*"); }
    else if (p[i] === "?") t.push("?");
    else t.push({ c: p[i] });
  }
  return t;
}
function globMatch(tokens, s) {
  let cur = new Uint8Array(s.length + 1);
  cur[0] = 1;
  for (const tk of tokens) {
    const next = new Uint8Array(s.length + 1);
    if (tk === "**" || tk === "*") {
      let on = 0;
      for (let j = 0; j <= s.length; j++) {
        if (cur[j]) on = 1;
        if (on) next[j] = 1;
        if (tk === "*" && j < s.length && isSep(s[j])) on = 0;
      }
    } else {
      for (let j = 0; j < s.length; j++) if (cur[j] && (tk === "?" ? !isSep(s[j]) : s[j] === tk.c)) next[j + 1] = 1;
    }
    cur = next;
  }
  return cur[s.length] === 1;
}
// A number as a tool receives it: a JSON number, or a string that is exactly a plain decimal (no sign but `-`, no
// spaces, grouping, currency, exponent, hex or leading zeros).
const strictNumber = (v) => (typeof v === "number" ? (Number.isFinite(v) ? v : null) : typeof v === "string" && /^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(v) ? Number(v) : null);
// folded: the entry marks this key (foldArgs) as compared case- and Unicode-folded; otherwise values match raw.
function scalarAllowed(v, allowed, folded) {
  if (typeof v === "boolean") v = String(v);
  if (typeof v !== "string" && typeof v !== "number") return false;
  if (typeof v === "number" && !Number.isFinite(v)) return false;
  if (typeof v === "string" && (v.length > MAX_VALUE * 8 || unsafeValue(v))) return false;
  const n = strictNumber(v);
  const s = typeof v === "string" ? (folded ? fold(v) : v) : String(v);
  return allowed.some((a) => (a.s !== undefined ? (folded ? a.sf : a.s) === s : a.g !== undefined ? globMatch(folded ? a.gf : a.g, s) : a.n !== undefined ? n !== null && n === a.n : n !== null && n >= a.min && n <= a.max));
}
function valueAllowed(v, allowed, folded) {
  if (v === undefined || v === null) return true;
  if (Array.isArray(v)) return v.length <= 1024 && v.every((x) => !Array.isArray(x) && !isObj(x) && scalarAllowed(x, allowed, folded));
  if (isObj(v)) return false;
  return scalarAllowed(v, allowed, folded);
}
// The outcome of one entry for one call: "allow" or the entry's default, with a fixed reason token.
export function entryOutcome(entry, tool, input) {
  if (entry.invalid) return { outcome: "deny", reason: "invalid-policy" };
  const spec = entry.tools.get(String(tool ?? ""));
  if (spec === undefined) return { outcome: entry.default, reason: "tool-not-listed" };
  if (spec.any) return { outcome: "allow", reason: "" };
  const inp = isObj(input) ? input : {};
  const shape = walkKeys(inp, spec.tree, entry.unlisted === "deny");
  if (shape) return { outcome: entry.default, reason: shape };
  // walkKeys has already held every key that collides with a listed key or segment.
  for (const [key, allowed] of spec.args) if (!collectKey(inp, key).values.every((v) => valueAllowed(v, allowed, entry.foldArgs.has(key)))) return { outcome: entry.default, reason: "argument-not-allowed" };
  return { outcome: "allow", reason: "" };
}

// The entries that apply to a session. has(term): the session's task terms (null: no task). hasTaskId(id):
// whether the session's explicit task id is `id` (null: none set). recorded(entry): whether the entry was
// recorded as matched at capture (entriesNamedIn), null: none recorded.
export function applicableEntries(lists, has, hasTaskId, recorded = null) {
  const always = lists.filter((e) => e.always);
  const byId = hasTaskId ? lists.filter((e) => !e.always && e.match.taskId !== undefined && hasTaskId(e.match.taskId)) : [];
  const byWord = lists.filter((e) => !e.always && e.match.keywords && ((recorded && recorded(e)) || (has && e.match.keywords.some((terms) => terms.some((t) => has(t))))));
  return [...always, ...byId, ...byWord];
}
// The keyword entries a whole prompt names — every word and phrase of it, however long, not a capped set.
export function entriesNamedIn(lists, text) {
  const kw = lists.filter((e) => !e.always && e.match && e.match.keywords);
  if (!kw.length || typeof text !== "string") return [];
  const need = new Set(kw.flatMap((e) => e.match.keywords.flat()));
  const found = new Set();
  const lens = new Set([...need].filter((t) => t.startsWith("w:")).map((t) => t.slice(2).split(" ").length));
  if (lens.size) {
    const ws = wordsOf(text);
    for (const k of lens) for (let i = 0; i + k <= ws.length; i++) { const t = `w:${k === 1 ? ws[i] : ws.slice(i, i + k).join(" ")}`; if (need.has(t)) found.add(t); }
  }
  if ([...need].some((t) => t.startsWith("a:"))) {
    for (const a of atomsOf(text)) {
      if (need.has(`a:${fold(a)}`)) found.add(`a:${fold(a)}`);
      for (const x of atomExtras(a).terms) if (need.has(x)) found.add(x);
    }
  }
  return kw.filter((e) => e.match.keywords.some((terms) => terms.some((t) => found.has(t))));
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
