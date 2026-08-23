// Shared ReDoS guard for patterns that arrive as DATA from the policy server — MCP argument rules
// (#18, cli/hook-core.mjs) and org detector packs (#22, data/detector-packs.js).
//
// It lives here, in its own module with NO imports, because both consumers need it and
// cli/hook-core.mjs already imports compilePacks from data/detector-packs.js: having detector-packs
// import the guard back from hook-core would close an import cycle.

export const MAX_PATTERN_LEN = 400;

// Count unbounded quantifiers (`+`, `*`, `{n,}`) that actually apply, skipping escapes (`\*`) and
// character-class contents (`[*+]`). `?` and `{n,m}` are bounded and do not count.
export function unboundedQuantifiers(src) {
  let n = 0, inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "\\") { i++; continue; }
    if (inClass) { if (c === "]") inClass = false; continue; }
    if (c === "[") { inClass = true; continue; }
    if (c === "+" || c === "*") { n++; continue; }
    if (c === "{") {
      const close = src.indexOf("}", i);
      if (close > i && /^\{\d+,\s*\}$/.test(src.slice(i, close + 1))) n++;
      if (close > i) i = close;
    }
  }
  return n;
}

// A quantified group whose alternation branches can match the same input is the `(a|a)+` family.
// Provably-disjoint branches (plain literals with pairwise-distinct first characters, e.g.
// `(foo|bar)+`, measured at 0 ms) stay allowed; anything else is refused, because deciding real
// disjointness is not something a cheap syntactic check can do.
export function ambiguousQuantifiedAlternation(src) {
  for (const m of src.matchAll(/\((\?:)?([^()]*)\)\s*(?:[+*]|\{\d+,\s*\})/g)) {
    const body = m[2];
    if (!body.includes("|")) continue;
    const branches = body.split("|");
    const firsts = new Set();
    for (const b of branches) {
      // A character class counts as NOT a plain literal: `([a-z]|x)+` has one unbounded quantifier and
      // no nesting, yet its branches overlap on every letter — measured at 1892 ms against 24 x's.
      if (!b.length || /[\\^$.|?*+{}[\]]/.test(b)) return true;
      if (firsts.has(b[0].toLowerCase())) return true;         // shared first char → branches overlap
      firsts.add(b[0].toLowerCase());
    }
  }
  return false;
}

// Reject the catastrophic-backtracking shapes; returns a reason string, or "" when acceptable.
export function redosReason(src) {
  if (typeof src !== "string" || !src.length) return "empty";
  if (src.length > MAX_PATTERN_LEN) return "too-long";
  if (ambiguousQuantifiedAlternation(src)) return "ambiguous-alternation";
  // Strictly stronger than the two shape rules detector-packs used to carry: `(a+)+`, `(a*)*` and
  // `a+*` all carry TWO unbounded quantifiers, so the count catches every shape they did — and, unlike
  // their regexes, this one is character-class aware, so `[*+]{3}x` is no longer refused for a `*+`
  // that is data.
  if (unboundedQuantifiers(src) > 1) return "multiple-unbounded-quantifiers";
  return "";
}

// Compile a policy-supplied pattern, or null if it is unsafe or uncompilable.
export function safeRegex(src, flags = "i") {
  if (redosReason(src)) return null;
  try { return new RegExp(src, flags); } catch { return null; }
}
