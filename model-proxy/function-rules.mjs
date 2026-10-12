// policy.functionToolActions — an action per function NAME, for a tool call the model asks a
// function-calling client to run (the model proxy sees the raw function name; no hook vocabulary is involved):
//
//   "functionToolActions": { "delete_project_files": "block", "send_*": "ask", "notify_team": "alert" }
//
// The action vocabulary is tagActions' (data/tool-tags.js): block | ask | alert | allow. "block" denies the
// call; "ask" requires approval, settled by server mode's headless rule in enforce mode (no approver → deny,
// unless the system file or the org policy says allow-with-report); "alert" reports it and changes nothing;
// "allow" is accepted and does nothing (nothing here loosens a verdict). Names are matched after foldName
// (below) on both sides, so a name a lenient client would still resolve to the rule's function (another
// case, `-` for `_`, a `functions.` prefix, padding, zero-width or full-width characters) is matched too; a
// key ending in `*` matches every folded name with that prefix (egress-rule path style: the `*` only at the
// end, and not alone). When several keys match, the strictest action wins. A key that is not 1-128 of
// A-Z a-z 0-9 _ . : - (plus the trailing `*`), or an action outside the vocabulary, is ignored.
//
// SOURCE. The policy the runtime loaded (the verified console policy, --policy-file, or options) — never a
// header, the request body or the model's output.
export const ACTION_RANK = Object.freeze({ allow: 0, alert: 1, ask: 2, block: 3 });
const NAME_RE = /^[A-Za-z0-9_.:\-]{1,128}$/;
const PREFIX_RE = /^(?:functions|function|tools|default_api)\./i;

// The name a lenient client could dispatch on: Unicode NFKC (full-width and compatibility forms become
// ASCII), control and format characters (zero-width space, joiners, BOM) removed, surrounding whitespace
// trimmed, and a namespace prefix some serving stacks put in front of a function name (`functions.` in the
// harmony format, `default_api.` in Gemini's) removed. Look-alike letters from other scripts (Cyrillic `е`)
// are not mapped: no client resolves them to the Latin name.
export function normalizeName(name) {
  let n = String(name ?? "").normalize("NFKC").replace(/[\p{Cc}\p{Cf}]/gu, "").trim();
  for (let i = 0; i < 4 && PREFIX_RE.test(n); i++) n = n.replace(PREFIX_RE, "").trim();
  return n;
}
// For rule matching: normalizeName, case-folded, `-` read as `_`.
export const foldName = (name) => normalizeName(name).toLowerCase().replace(/-/g, "_");
const EMPTY = Object.freeze({ exact: new Map(), prefix: [] });
const cache = new WeakMap();

export function functionRulesFrom(policy) {
  const m = policy && typeof policy === "object" ? policy.functionToolActions : undefined;
  if (!m || typeof m !== "object" || Array.isArray(m)) return { exact: new Map(), prefix: [] };
  const exact = new Map(), prefix = [];
  for (const [key, act] of Object.entries(m)) {
    if (!(act in ACTION_RANK) || act === "allow") continue;
    const star = key.endsWith("*");
    const base = star ? key.slice(0, -1) : key;
    if (!NAME_RE.test(base)) continue;
    const k = foldName(base);
    if (star) prefix.push([k, act]);
    else if (!exact.has(k) || ACTION_RANK[act] > ACTION_RANK[exact.get(k)]) exact.set(k, act);
  }
  return { exact, prefix };
}

export function rulesOf(policy) {
  if (!policy || typeof policy !== "object") return EMPTY;
  let r = cache.get(policy);
  if (!r) { r = functionRulesFrom(policy); cache.set(policy, r); }
  return r;
}

// The strictest action ("block" | "ask" | "alert") whose key matches `name` (both folded), or null.
export function functionActionFor(rules, name) {
  const n = typeof name === "string" ? foldName(name) : "";
  if (!n) return null;
  let best = rules.exact.get(n) || null;
  for (const [p, act] of rules.prefix) if (n.startsWith(p) && (!best || ACTION_RANK[act] > ACTION_RANK[best])) best = act;
  return best;
}
