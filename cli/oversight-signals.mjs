// Weakening oversight (#84): does a write CHANGE the project's own monitoring, alerting, audit logging or
// safety tests for the worse? Judged on the difference between the file before and after the write, never on
// a mention: a doc, a README, a fixture or a comment that names these is not a finding, and neither is a
// suppression flag that was already set.
//
// Signals (content-free enums; the alert carries these, never a key, path or value):
//   suppression-flag      an alert / notification / paging suppression flag set on, an alerting switch set
//                         off, or suppression made a requirement (a raise / assert on the flag);
//   recipients-emptied    an alert recipient list or on-call / pager route emptied or deleted;
//   wiring-removed        monitor, alerting, audit-log or telemetry wiring removed or commented out;
//   safety-test-weakened  a test that guards oversight deleted, skipped, or changed to assert absence;
//   monitoring-off        a key or env var that turns monitoring, audit logging or tracing off, or empties
//                         a monitoring sink (SENTRY_DSN, an OTLP endpoint);
//   protected-surface     the write touches a path or key the signed policy declares protected;
//   analysis-incomplete   the write was not read whole (before or after over MAX, or an existing file too large
//                         for the hook to read under a Write): never cut and judged clean, it fails closed
//                         (cli/hook-core.mjs decideOversight asks on it).
//
// Path handling: docs, fixtures and examples are never judged (only protected surfaces are); test files are
// judged only for the test signal; repository tooling (.github, .gitlab, ...) and UI component files are not
// judged; runtime code and config get the rest. cli/mcp-package/paths.mjs notRuntimeReason decides "test".
//
// A new file (no "before") is judged only for protected surfaces: creating a config with alerting off is
// scaffolding as often as it is suppression, and nothing was weakened that existed.
//
// Linear time: every pattern here is free of overlapping quantifiers (the quote scanner below replaces a
// backtracking regex), so with the MAX size bound the analysis of one write is bounded in time too.
import { notRuntimeReason, TOOLING_PATH } from "./mcp-package/paths.mjs";
import { protectedPathHit, protectedKeyChanged } from "./oversight-surfaces.mjs";
import { words, switchKind, listKind, wiringFamily, TEST_GUARD_WORDS, valueKind } from "./oversight-vocab.mjs";

export const OVERSIGHT_SIGNALS = Object.freeze(["suppression-flag", "recipients-emptied", "wiring-removed", "safety-test-weakened", "monitoring-off", "protected-surface", "analysis-incomplete"]);
export const INCOMPLETE = "analysis-incomplete";
const MAX = 1_048_576;
const order = (set) => OVERSIGHT_SIGNALS.filter((s) => set.has(s));

// ---- path class ----
const DOC_EXT = /\.(?:md|mdx|markdown|rst|txt|adoc|asciidoc|org|rtf)$/i;
const DOC_BASE = /^(?:readme|changelog|changes|history|license|licence|notice|authors|contributing|code_of_conduct)(?:\.|$)/i;
const DOC_DIR = /(?:^|\/)docs?\//i;
const FIXTURE_DIR = /(?:^|\/)(?:fixtures?|__fixtures__|testdata|test[-_]data|__snapshots__|__mocks__|mocks?|examples?|samples?|demos?)\//i;
const TEST_EXTRA = /(?:^|\/)(?:conftest\.py|pytest\.ini|jest\.config\.[cm]?[jt]s|vitest\.config\.[cm]?[jt]s|setupTests\.[jt]sx?)$|_test\.go$|Tests?\.(?:java|cs|kt|scala)$|_spec\.rb$|(?:^|\/)\.env\.(?:test|testing|ci)$|(?:^|\/)(?:docker-)?compose\.(?:test|ci)\.ya?ml$|(?:^|\/)docker-compose\.(?:test|ci)\.ya?ml$/i;
const UI_EXT = /\.(?:jsx|tsx|vue|svelte|html?|css|scss|sass|less)$/i;

const trimSlashes = (s) => { let e = s.length; while (e > 0 && s.charCodeAt(e - 1) === 47) e--; return s.slice(0, e); };
export function relPath(path, cwd = "") {
  let p = String(path || "").replace(/\\/g, "/");
  const c = trimSlashes(String(cwd || "").replace(/\\/g, "/"));
  if (c && p.startsWith(c + "/")) p = p.slice(c.length + 1);
  return p.replace(/^\.\//, "");
}
// → "doc" | "fixture" | "tooling" | "test" | "ui" | "code"
export function pathClass(path, cwd = "") {
  const rel = relPath(path, cwd);
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  if (DOC_EXT.test(base) || DOC_BASE.test(base) || DOC_DIR.test(rel)) return "doc";
  if (FIXTURE_DIR.test(rel) || /\.snap$/i.test(base)) return "fixture";
  if (TOOLING_PATH.test(rel)) return "tooling";
  if (notRuntimeReason(rel) === "test-code" || TEST_EXTRA.test(rel)) return "test";
  if (UI_EXT.test(base)) return "ui";
  return "code";
}

// ---- before / after of a write ----
export function applyEdits(file, edits) {
  let cur = file;
  for (const e of edits) {
    if (!e.old_string || !cur.includes(e.old_string)) return null;
    cur = e.replace_all ? cur.split(e.old_string).join(e.new_string) : cur.replace(e.old_string, () => e.new_string);
  }
  return cur;
}
// file: the target's current text, or null when it does not exist or could not be read. An Edit whose
// old_string is not in the file is judged on the snippets alone.
export function beforeAfter({ tool, input, file } = {}) {
  const ti = input && typeof input === "object" ? input : {};
  const str = (v) => (typeof v === "string" ? v : "");
  if (tool === "Write") return { before: typeof file === "string" ? file : null, after: str(ti.content) };
  if (tool === "NotebookEdit") return { before: null, after: str(ti.new_source) };
  const edits = (tool === "MultiEdit" ? (Array.isArray(ti.edits) ? ti.edits : []) : [ti]).filter((e) => e && typeof e.old_string === "string" && typeof e.new_string === "string");
  if (typeof file === "string") { const after = applyEdits(file, edits); if (after !== null) return { before: file, after }; }
  return { before: edits.map((e) => e.old_string).join("\n"), after: edits.map((e) => e.new_string).join("\n") };
}

// ---- code lines: comments and docstrings dropped ----
function codeLines(text) {
  const out = [];
  let block = null; // "*/" | '"""' | "'''" | "-->"
  for (const raw of String(text).slice(0, MAX).split(/\r?\n/)) {
    let line = raw;
    if (block) {
      const i = line.indexOf(block);
      if (i < 0) { out.push({ code: "", indent: 0 }); continue; }
      line = line.slice(i + block.length); block = null;
    }
    const t = line.trim();
    if (/^(?:"""|''')/.test(t)) {
      const q = t.slice(0, 3);
      if (t.length < 6 || !t.slice(3).includes(q)) block = q;
      out.push({ code: "", indent: 0 }); continue;
    }
    if (/^(?:#(?!\s*(?:include|import|define|if|pragma)\b)|\/\/|--|;|%|\*)/.test(t) || t === "") { out.push({ code: "", indent: 0 }); continue; }
    let code = line;
    const open = code.search(/\/\*|<!--/);
    if (open >= 0) {
      const closer = code.slice(open, open + 2) === "/*" ? "*/" : "-->";
      const close = code.indexOf(closer, open + 2);
      if (close < 0) { block = closer; code = code.slice(0, open); }
      else code = code.slice(0, open) + code.slice(close + closer.length);
    }
    code = code.replace(/(?<!\s)\s+#\s.*$/, "").replace(/(^|[^:"'\\/])\/\/.*$/, "$1");
    out.push({ code, indent: (code.match(/^\s*/) || [""])[0].length });
  }
  return out;
}
// A quoted string that holds whitespace is prose, not code: it becomes "". The same strings the regex
// /(["'`])(?:(?!\1)[^\\\n]|\\.)*\s(?:(?!\1)[^\\\n]|\\.)*\1/g replaced, found by a linear scan: from an
// opening quote, a backslash takes the next character (not a line terminator), the first unescaped same quote
// closes, a newline or a dangling backslash fails. A scan that fails moves on one character, as the regex did;
// every position a scan passes is remembered per quote kind, so no later scan re-reads it (O(3n)).
const WS_CH = /\s/;
const LINE_TERM = /[\n\r\u2028\u2029]/;
function proselessLine(s) {
  const n = s.length;
  if (!/["'`]/.test(s)) return s;
  const memo = { '"': null, "'": null, "`": null };
  const scan = (q, from) => {
    if (!memo[q]) memo[q] = { end: new Int32Array(n + 1).fill(-2), ws: new Uint8Array(n + 1) };
    const m = memo[q];
    const path = [];
    let j = from, end = -1, ws = 0;
    for (;;) {
      if (m.end[j] !== -2) { end = m.end[j]; ws = m.ws[j]; break; }
      if (j >= n) break;
      const c = s[j];
      if (c === q) { end = j; break; }
      path.push(j);
      if (c === "\\") { if (j + 1 >= n || LINE_TERM.test(s[j + 1])) break; j += 2; } else j += 1;
    }
    for (let k = path.length - 1; k >= 0; k--) {
      const p = path[k];
      if (s[p] !== "\\" && WS_CH.test(s[p])) ws = 1;
      m.end[p] = end; m.ws[p] = ws;
    }
    return { end, ws };
  };
  let out = "", i = 0, last = 0;
  while (i < n) {
    const c = s[i];
    if (c === '"' || c === "'" || c === "`") {
      const r = scan(c, i + 1);
      if (r.end >= 0 && r.ws) { out += s.slice(last, i) + '""'; i = r.end + 1; last = i; continue; }
    }
    i += 1;
  }
  return last ? out + s.slice(last) : s;
}
export const proseless = (s) => String(s).split("\n").map(proselessLine).join("\n");

// ---- assignments, with the enclosing YAML / TOML / JSON block ----
const VALUE = String.raw`(\[\s*\]|\{\s*\}|\(\s*\)|(?:set|list|dict|frozenset|tuple)\(\s*\)|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;)}\]#]*)`;
const ASSIGN = new RegExp(String.raw`(?:^|[\s,{(;\[])(?:\[\s*)?(["'\x60]?)([A-Za-z_][\w.\-]{0,80})\1\s*(?:\]\s*)?(=>|:=|:(?![:\/])|=(?![=~>]))[ \t]*` + VALUE, "g");
const CALL = new RegExp(String.raw`\(\s*["']([A-Za-z_][\w.\-]{0,80})["']\s*,\s*` + VALUE, "g");
const BLOCK_KEY = /^\s*(?:-\s+)?["']?([A-Za-z_][\w.\-]*)["']?\s*:\s*(?:(?:\{|\[|&[\w-]+)\s*)?$/;
const SECTION = /^\s*\[\[?\s*([A-Za-z_][\w.\-]*)\s*\]\]?\s*$/;

function* assignments(lines) {
  const stack = [];
  let section = "";
  for (let i = 0; i < lines.length; i++) {
    const { code, indent } = lines[i];
    if (!code.trim()) continue;
    const sec = SECTION.exec(code);
    if (sec) { section = sec[1]; stack.length = 0; continue; }
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack.length ? stack[stack.length - 1].key : section;
    const next = () => { for (let j = i + 1; j < lines.length; j++) if (lines[j].code.trim()) return lines[j]; return null; };
    for (const re of [ASSIGN, CALL]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(code)) !== null) {
        const key = re === ASSIGN ? m[2] : m[1];
        let value = re === ASSIGN ? m[4] : m[2];
        // A YAML key with nothing after it, or an opener at the end of the line: look at the next line.
        if (re === ASSIGN && (value === "" || value === "[" || value === "{")) {
          const n = next();
          if (value === "") value = n && (n.indent > indent || (n.indent === indent && /^\s*-\s/.test(n.code))) ? "<block>" : "";
          else value = n && /^\s*[\]}]/.test(n.code) ? "[]" : "<block>";
        }
        yield { key, value, parent, line: i };
        if (m[0].length === 0) re.lastIndex++;
      }
    }
    const bk = BLOCK_KEY.exec(code);
    if (bk) stack.push({ indent, key: bk[1] });
  }
}

const RAISE = /\b(?:raise|throw|assert|panic|abort|sys\.exit|process\.exit|require)\b/;
const IDENT = /[A-Za-z_][A-Za-z0-9_]*/g;

function analyse(text, path) {
  const lines = codeLines(text);
  const flags = new Set();
  const lists = new Map(); // key -> { kind, states:Set }
  for (const a of assignments(lines)) {
    const sw = switchKind(a.key, a.parent, a.value);
    if (sw) flags.add(`${sw}|${a.parent ? a.parent + "." : ""}${a.key}`);
    const lk = listKind(a.key, `${a.parent} ${path}`);
    if (lk) {
      const k = `${a.parent ? a.parent + "." : ""}${a.key}`;
      const e = lists.get(k) || { kind: lk, states: new Set() };
      e.states.add(valueKind(a.value) === "empty" ? "empty" : "nonempty");
      lists.set(k, e);
    }
  }
  // Suppression made a requirement: a raise / assert / exit on (or right after) a line that reads the flag.
  for (let i = 0; i < lines.length; i++) {
    const c = lines[i].code;
    if (!c.trim()) continue;
    const ids = (c.match(/[A-Za-z_][\w]*/g) || []).filter((id) => switchKind(id, "", "true") === "suppression-flag");
    if (!ids.length) continue;
    const nxt = lines.slice(i + 1).find((l) => l.code.trim());
    if (RAISE.test(c) || (nxt && nxt.indent > lines[i].indent && RAISE.test(nxt.code))) for (const id of ids) flags.add(`suppression-flag|require:${id}`);
  }
  const idents = new Map();
  for (const { code } of lines) {
    if (!code.trim()) continue;
    for (const id of proseless(code).match(IDENT) || []) { const f = wiringFamily(id); if (f) idents.set(id, f); }
  }
  return { flags, lists, idents, lines };
}

function runtimeSignals(before, after, path, out) {
  const b = analyse(before, path), a = analyse(after, path);
  for (const f of a.flags) if (!b.flags.has(f)) out.add(f.slice(0, f.indexOf("|")));
  const newNonEmpty = [...a.lists].some(([k, e]) => e.states.has("nonempty") && !(b.lists.get(k) && b.lists.get(k).states.has("nonempty")));
  for (const [k, e] of b.lists) {
    if (!e.states.has("nonempty")) continue;
    const now = a.lists.get(k);
    if (now ? !now.states.has("nonempty") : !newNonEmpty) out.add(e.kind === "sink" ? "monitoring-off" : "recipients-emptied");
  }
  const removed = new Map(), added = new Map();
  for (const [id, fam] of b.idents) if (!a.idents.has(id)) removed.set(fam, (removed.get(fam) || 0) + 1);
  for (const [id, fam] of a.idents) if (!b.idents.has(id)) added.set(fam, (added.get(fam) || 0) + 1);
  const totalRemoved = [...removed.values()].reduce((n, x) => n + x, 0), totalAdded = [...added.values()].reduce((n, x) => n + x, 0);
  // A rename keeps the family (alert_mgr -> alert_manager), or replaces as many oversight names as it drops.
  if (totalRemoved > totalAdded && [...removed.keys()].some((fam) => !added.get(fam))) out.add("wiring-removed");
}

// ---- tests that guard oversight ----
const ASSERTION = /\b(?:assert\w*|expect|require\.\w+|refute|should|verify)\b/;
const ABSENCE = /\bnot\s+in\b|\bassertNotIn\b|\bassertIsNone\b|\bassertFalse\b|\bassertNull\b|\bis\s+None\b|\.not\.to\w*|\.toBe(?:Undefined|Null|Falsy)\(|\bassert\s+not\b|\bassert\.(?:equal|strictEqual|deepEqual)\([^)]*,\s*(?:undefined|null|false)\s*\)|\bassert\.ok\(\s*!|\b(?:assert|require)\.(?:Nil|False|NotContains|Empty)\(|\brefute\b|\bto\s+be_nil\b|\bnot_to\b|\bdoes\s*not\s*exist|\bis\s+absent\b/;
const TEST_NAME = /\bdef\s+(test\w*)|\bfunc\s+(Test\w*)|\b(?:it|test|describe|context)\s*\(\s*["'`]([^"'`\n]{1,200})["'`]|\bvoid\s+(test\w*)\s*\(/g;
const SKIP = /@pytest\.mark\.(?:skip|xfail)\b|@unittest\.skip|\b(?:it|test|describe)\.(?:skip|todo)\s*\(|\bx(?:it|describe|test)\s*\(|\bt\.Skip(?:Now|f)?\(|@Disabled\b|@Ignore\b|\bskip\s*:\s*true\b|\{\s*skip\s*:/g;
const guardWord = (s) => words(s).some((w) => TEST_GUARD_WORDS.test(w));
const oversightToken = (line) => (line.match(/[A-Za-z_][\w]*/g) || []).some((id) => wiringFamily(id) || guardWord(id));

function testSignals(path, before, after) {
  const b = codeLines(before), a = codeLines(after);
  const guards = guardWord(path) || b.some((l) => l.code && oversightToken(l.code));
  if (!guards) return false;
  const absence = (ls) => new Set(ls.map((l) => l.code.trim().replace(/\s+/g, " ")).filter((c) => c && ASSERTION.test(c) && ABSENCE.test(c) && oversightToken(c)));
  const bAbs = absence(b);
  for (const c of absence(a)) if (!bAbs.has(c)) return true;
  const names = (ls) => { const s = new Set(); const t = ls.map((l) => l.code).join("\n"); TEST_NAME.lastIndex = 0; let m; while ((m = TEST_NAME.exec(t)) !== null) { const n = m[1] || m[2] || m[3] || m[4]; if (guardWord(n)) s.add(n); } return s; };
  const an = names(a);
  for (const n of names(b)) if (!an.has(n)) return true;
  const skips = (ls) => (ls.map((l) => l.code).join("\n").match(SKIP) || []).length;
  return skips(a) > skips(b);
}

// ---- the entry point ----
// before: the file before the write (null: a new file); after: the file after it. surfaces: the parsed
// policy.oversight (cli/oversight-surfaces.mjs). → the signals, in OVERSIGHT_SIGNALS order.
// beforeUnread: the target exists but was not read (too large); a Write over it cannot be compared, so it is
// incomplete. Over MAX on either side is incomplete too: nothing is cut and then judged clean.
export function oversightEditSignals({ path = "", before = null, after = "", surfaces = null, cwd = "", beforeUnread = false } = {}) {
  const out = new Set();
  const cls = pathClass(path, cwd);
  const judged = cls === "test" || cls === "code";
  const over = (typeof after === "string" && after.length > MAX) || (typeof before === "string" && before.length > MAX);
  const aft = typeof after === "string" ? after.slice(0, MAX) : "";
  const bef = typeof before === "string" ? before.slice(0, MAX) : null;
  if (surfaces && (protectedPathHit(path, surfaces, { cwd, real: true }) || protectedKeyChanged(bef ?? "", aft, surfaces))) out.add("protected-surface");
  if (judged && (bef === null ? beforeUnread : over)) { out.add(INCOMPLETE); return order(out); }
  if (bef === null) return order(out);
  if (cls === "test") { if (testSignals(relPath(path, cwd), bef, aft)) out.add("safety-test-weakened"); }
  else if (cls === "code") runtimeSignals(bef, aft, relPath(path, cwd), out);
  return order(out);
}

// Direct classification of assignments a command writes (no "before" to diff against): a suppression switch
// set, a recipient list or monitoring sink set empty. Runtime code and config paths only.
export function assignedSignals(text, path = "", cwd = "") {
  const out = new Set();
  if (pathClass(path, cwd) !== "code") return [];
  for (const a of assignments(codeLines(text))) {
    const sw = switchKind(a.key, a.parent, a.value);
    if (sw) out.add(sw);
    const lk = listKind(a.key, `${a.parent} ${relPath(path, cwd)}`);
    if (lk && valueKind(a.value) === "empty") out.add(lk === "sink" ? "monitoring-off" : "recipients-emptied");
  }
  return order(out);
}
