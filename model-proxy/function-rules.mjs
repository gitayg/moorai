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
// key ending in `*` matches every name with that prefix (egress-rule path style: the `*` only at the end,
// and not alone, nor after a namespace alone such as `tools.*`, which is ignored with a warning). Raw,
// case-folded and fully folded forms are all matched (formsOf), so folding never removes a match the raw
// name had. When several keys match, the strictest action wins. A key that is not 1-128 of
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
// Folding must only ever ADD matches. The full fold strips a namespace prefix, so `tools.delete_all` folds to
// `delete_all` and no longer starts with a `tools*` key: every rule key and every name is matched in each of
// its forms — as written, case/`-` folded without the prefix strip, and fully folded — and the strictest
// action over every form that matches wins.
const lightFold = (name) => String(name ?? "").normalize("NFKC").replace(/[\p{Cc}\p{Cf}]/gu, "").trim().toLowerCase().replace(/-/g, "_");
const formsOf = (name) => [...new Set([String(name ?? ""), lightFold(name), foldName(name)])];
const EMPTY = Object.freeze({ exact: new Map(), prefix: [], ignored: [], broad: [] });
const cache = new WeakMap();

// A wildcard whose prefix folds to nothing (`tools.*`, `functions.*`: a namespace and nothing else) matches
// every function: the admin meant a whole namespace, and ignoring the key would leave every tool unchecked
// (fail-open), so it fails closed instead, is listed in `broad`, and is reported once per loaded policy through
// `warn` (stderr by default). A key that is not a valid name is ignored, listed in `ignored`, and reported too.
const stderrWarn = (msg) => { try { process.stderr.write(`moorai-model-proxy: ${msg}\n`); } catch {} };
export function functionRulesFrom(policy, { warn = stderrWarn } = {}) {
  const m = policy && typeof policy === "object" ? policy.functionToolActions : undefined;
  if (!m || typeof m !== "object" || Array.isArray(m)) return { exact: new Map(), prefix: [], ignored: [], broad: [] };
  const exact = new Map(), prefix = [], ignored = [], broad = [];
  for (const [key, act] of Object.entries(m)) {
    if (!(act in ACTION_RANK) || act === "allow") continue;
    const star = key.endsWith("*");
    const base = star ? key.slice(0, -1) : key;
    if (!NAME_RE.test(base)) {
      ignored.push(key);
      warn(`functionToolActions key ${JSON.stringify(key)} ignored: it is not a valid function name`);
      continue;
    }
    if (star && !foldName(base)) {
      broad.push(key);
      warn(`functionToolActions key ${JSON.stringify(key)} matches every function: its prefix is only a namespace`);
      prefix.push(["", act]);
      continue;
    }
    for (const k of formsOf(base)) {
      if (star) prefix.push([k, act]);
      else if (!exact.has(k) || ACTION_RANK[act] > ACTION_RANK[exact.get(k)]) exact.set(k, act);
    }
  }
  return { exact, prefix, ignored, broad };
}

export function rulesOf(policy) {
  if (!policy || typeof policy !== "object") return EMPTY;
  let r = cache.get(policy);
  if (!r) { r = functionRulesFrom(policy); cache.set(policy, r); }
  return r;
}

// The strictest action ("block" | "ask" | "alert") whose key matches `name`, in any form of either, or null.
export function functionActionFor(rules, name) {
  if (typeof name !== "string" || !foldName(name)) return null;
  let best = null;
  const take = (act) => { if (act && (!best || ACTION_RANK[act] > ACTION_RANK[best])) best = act; };
  for (const n of formsOf(name)) {
    if (!n) continue;
    take(rules.exact.get(n));
    for (const [p, act] of rules.prefix) if (n.startsWith(p)) take(act);
  }
  return best;
}

// For the business-tool catalogue (business-tools.mjs): the strictest action of the functionToolActions keys
// that name THIS function — an exact key, or a wildcard with a real prefix — "allow" included, or null when no
// such key matches. A namespace-only wildcard (`tools.*`, listed in `broad`) is not specific. Keys are read
// as functionRulesFrom reads them (the same validation, the same forms on both sides).
const specificCache = new WeakMap();
function specificRulesOf(policy) {
  let r = specificCache.get(policy);
  if (r) return r;
  r = { exact: new Map(), prefix: [] };
  const m = policy.functionToolActions;
  if (m && typeof m === "object" && !Array.isArray(m)) {
    for (const [key, act] of Object.entries(m)) {
      if (!(act in ACTION_RANK)) continue;
      const star = key.endsWith("*");
      const base = star ? key.slice(0, -1) : key;
      if (!NAME_RE.test(base) || (star && !foldName(base))) continue;
      for (const k of formsOf(base)) {
        if (star) r.prefix.push([k, act]);
        else if (!r.exact.has(k) || ACTION_RANK[act] > ACTION_RANK[r.exact.get(k)]) r.exact.set(k, act);
      }
    }
  }
  specificCache.set(policy, r);
  return r;
}
export function specificActionFor(policy, name) {
  if (!policy || typeof policy !== "object" || typeof name !== "string" || !foldName(name)) return null;
  const rules = specificRulesOf(policy);
  let best = null;
  const take = (act) => { if (act && (!best || ACTION_RANK[act] > ACTION_RANK[best])) best = act; };
  for (const n of formsOf(name)) {
    if (!n) continue;
    take(rules.exact.get(n));
    for (const [p, act] of rules.prefix) if (n.startsWith(p)) take(act);
  }
  return best;
}
