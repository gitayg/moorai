// A "restart" variant for a detector pattern made linear with a run-start lookbehind.
//
// THE GAP. A lookbehind such as dlp-email's `(?<!\w[.+-]*)` lets a match start only at the first
// character of a run, which keeps the FIRST match identical and the search linear. Under /g it is not
// identical: a global search resumes at the previous match's end, and the pre-lookbehind pattern could
// start a new match right there, inside a run that began before it ("a@b.com+c@d.com": the old pattern
// redacted "+c@d.com", the lookbehind refuses it, because "m+" precedes "c").
//
// THE MECHANISM. A pattern may carry `restart`, the pre-lookbehind pattern. After each match, the
// restart pattern is tried STICKY at the match's end — only there — and every match it chains is taken
// before the main /g search resumes. That is the one position the old pattern could use that the
// lookbehind refuses; every other position is the main pattern's own leftmost search. Each sticky try
// is one anchored attempt, so the search stays linear. Same technique as the console's replaceEmails()
// (RAISEME-server/server/pseudonym.js). A restart pattern must not match the empty string.
//
// Browser-safe and import-free: src/engine.js is bundled for the browser.

export function withRestart(re, restart) {
  Object.defineProperty(re, "restart", { value: restart, enumerable: false });
  return re;
}

const sticky = (re) => new RegExp(re.source, re.flags.replace(/[gy]/g, "") + "y");

// Every match of `g` (a /g regex compiled from pattern `p`) in s, in order. Without `p.restart` this is
// exactly the usual exec loop (an empty match advances lastIndex by one).
export function* globalMatches(p, g, s) {
  const r = p.restart ? sticky(p.restart) : null;
  g.lastIndex = 0;
  let m;
  while ((m = g.exec(s)) !== null) {
    yield m;
    let end = m.index + m[0].length;
    if (!m[0]) { g.lastIndex = end + 1; continue; }
    if (r) for (r.lastIndex = end; (m = r.exec(s)) !== null && m[0]; end = r.lastIndex) yield m;
    g.lastIndex = end;
  }
}

// `s.replace(g, fn)` for a pattern with a restart variant. Callers keep String.prototype.replace for
// every pattern without one.
export function replaceWithRestart(s, p, g, fn) {
  let out = "", from = 0;
  for (const m of globalMatches(p, g, s)) {
    out += s.slice(from, m.index) + fn(m[0]);
    from = m.index + m[0].length;
  }
  return out + s.slice(from);
}
