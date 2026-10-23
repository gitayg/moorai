// Policy-declared protected oversight surfaces for the weakening-oversight threat (#84).
//
// The signed policy may carry `oversight` ({ v: 1, protectedPaths, protectedKeys, stopDisclosure }):
//   protectedPaths  up to 64 globs (`**` any depth, `*` within one path segment, `?` one character), matched
//                   against the path relative to the session's working directory; a relative glob also matches
//                   at any directory boundary of an absolute path ("**/monitor_*.py", "ops/alerting/**",
//                   "src/audit_logger.py"). "dir/**" also matches the directory itself.
//   protectedKeys   up to 64 config keys or env var names ("no_notify", "ALERTS_ENABLED", "alerts.route"),
//                   matched as a whole word, exactly as written (a dotted key is not resolved through YAML nesting).
//   stopDisclosure  "alert" (default) or "block": what Stop / SubagentStop does when an allowed oversight change
//                   is not disclosed in the agent's final message (cli/oversight-disclosure.mjs).
// Any Write / Edit / MultiEdit / NotebookEdit of a protected path, a write that changes a line naming a
// protected key, and a shell command that deletes, moves or writes a protected path or writes a protected key,
// is judged under #84 with the signal "protected-surface". An older agent ignores the key.
//
// A path is matched as written, as resolved against cwd (path.resolve: "ops/x/../alerting/a.yaml" and a
// relative path from a subdirectory), and, with { real: true }, through realpath: the target's real path, or
// for a file that does not exist yet the real path of its nearest existing ancestor plus the rest, so a
// symlinked file or directory cannot dodge a protected surface. Each form is matched relative to cwd and as an
// absolute path (a relative glob matches at any directory boundary of it, so cwd's own real path is not needed).
//
// A malformed entry is dropped with a warning that names its position, never its value. Pure apart from the
// warning sink and the realpath lookups of protectedPathHit({ real: true }).
import { realpathSync } from "node:fs";
import { resolve, dirname, basename, join } from "node:path";


const MAX_ENTRIES = 64, MAX_LEN = 256;
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_.\-]{0,127}$/;
const CONTROL_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const KNOWN = new Set(["v", "protectedPaths", "protectedKeys", "stopDisclosure"]);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const stderrWarn = (m) => { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* best effort */ } };
const esc = (s) => s.replace(/[.+^${}()|[\]\\]/g, "\\$&");

export function globRe(glob) {
  const g = glob.replace(/\\/g, "/");
  const abs = g.startsWith("/");
  let body = "";
  for (let i = abs ? 1 : 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*" && g[i + 1] === "*") {
      if (g[i + 2] === "/") { body += "(?:.*/)?"; i += 2; } else { body += ".*"; i += 1; }
    } else if (c === "*") body += "[^/]*";
    else if (c === "?") body += "[^/]";
    else body += esc(c);
  }
  if (g.endsWith("/**")) body = `${body.slice(0, -"/.*".length)}(?:/.*)?`;
  return new RegExp(`${abs ? "^/" : "(?:^|/)"}${body}$`);
}

export function oversightPolicy(policy, warn = stderrWarn) {
  const none = { paths: [], keys: [], stopDisclosure: "alert" };
  const o = isObj(policy) ? policy.oversight : undefined;
  if (o === undefined || o === null) return none;
  if (!isObj(o) || o.v !== 1) { warn("oversight ignored: not { v: 1, ... }"); return none; }
  if (Object.keys(o).some((k) => !KNOWN.has(k))) warn("oversight: unknown key ignored");
  const paths = [], keys = [];
  const list = (v, name) => {
    if (v === undefined) return [];
    if (!Array.isArray(v)) { warn(`oversight.${name} ignored: not a list`); return []; }
    if (v.length > MAX_ENTRIES) warn(`oversight.${name}: at most ${MAX_ENTRIES} entries, the rest dropped`);
    return v.slice(0, MAX_ENTRIES);
  };
  list(o.protectedPaths, "protectedPaths").forEach((p, i) => {
    if (typeof p !== "string" || !p.trim() || p.length > MAX_LEN || CONTROL_RE.test(p)) { warn(`oversight.protectedPaths entry ${i} dropped: 1-${MAX_LEN} characters of plain text`); return; }
    try { paths.push({ glob: p.trim(), re: globRe(p.trim()) }); } catch { warn(`oversight.protectedPaths entry ${i} dropped: not a valid glob`); }
  });
  list(o.protectedKeys, "protectedKeys").forEach((k, i) => {
    if (typeof k !== "string" || !KEY_RE.test(k)) { warn(`oversight.protectedKeys entry ${i} dropped: not a key name`); return; }
    keys.push(k);
  });
  let stopDisclosure = "alert";
  if (o.stopDisclosure !== undefined) {
    if (o.stopDisclosure === "alert" || o.stopDisclosure === "block") stopDisclosure = o.stopDisclosure;
    else warn("oversight.stopDisclosure ignored: alert or block");
  }
  return { paths, keys: [...new Set(keys)], stopDisclosure };
}

const slashes = (s) => String(s || "").replace(/\\/g, "/");
const trimSlashes = (s) => { let e = s.length; while (e > 0 && s.charCodeAt(e - 1) === 47) e--; return s.slice(0, e); };
function norm(path, cwd) {
  let p = trimSlashes(slashes(path));
  const c = trimSlashes(slashes(cwd));
  if (c && p.startsWith(c + "/")) p = p.slice(c.length + 1);
  return p.replace(/^\.\//, "");
}
const real = (p) => { try { return realpathSync(p); } catch { return null; } };
// The real path of p, or of its nearest existing ancestor joined with the part that does not exist yet.
export function realOf(abs) {
  let cur = abs, rest = "";
  for (let i = 0; i < 64; i++) {
    const r = real(cur);
    if (r) return rest ? join(r, rest) : r;
    const up = dirname(cur);
    if (up === cur) return null;
    rest = rest ? join(basename(cur), rest) : basename(cur);
    cur = up;
  }
  return null;
}
export function pathForms(path, { cwd = "", real: useReal = false } = {}) {
  const base = typeof cwd === "string" && cwd ? cwd : process.cwd();
  const forms = new Set([path]);
  let resolved = null;
  try { resolved = resolve(base, path); forms.add(resolved); } catch { resolved = null; }
  if (useReal && resolved) { const r = realOf(resolved); if (r) forms.add(r); }
  const out = new Set();
  for (const f of forms) { out.add(slashes(f)); out.add(norm(f, cwd)); }
  return [...out];
}
export function protectedPathHit(path, surfaces, { cwd = "", real: useReal = false } = {}) {
  if (!surfaces || !surfaces.paths || !surfaces.paths.length || typeof path !== "string" || !path || /[\r\n\0]/.test(path)) return false;
  const forms = pathForms(path, { cwd, real: useReal });
  return surfaces.paths.some((p) => forms.some((f) => p.re.test(f)));
}

const keyRe = (k) => new RegExp(`(?<![\\w\\-])${esc(k)}(?![\\w\\-])`);
const linesWith = (text, re) => String(text || "").split(/\r?\n/).map((l) => l.trim()).filter((l) => re.test(l)).sort().join("\n");
// A write changes a protected key when the lines naming it differ before and after (added, removed or edited).
export function protectedKeyChanged(before, after, surfaces) {
  if (!surfaces || !surfaces.keys || !surfaces.keys.length) return false;
  return surfaces.keys.some((k) => { const re = keyRe(k); return linesWith(before, re) !== linesWith(after, re); });
}

// A command that writes (in-place edit, redirect, tee, persistent env, platform config) and names a protected key.
const WRITE_VERB = /(?:^|[\s;&|(])(?:sed|gsed|perl)\b[^\n;|&]*\s-[A-Za-z]*i|\byq\b[^\n;|&]*\s-i\b|\btee\b|(?<![0-9&>])>>?\s*(?!&|\/dev\/null\b)[^\s>]|\bsetx\b|\blaunchctl\s+setenv\b|\bkubectl\s+(?:set\s+env|patch|edit|apply)\b|\bheroku\s+config:set\b|\b(?:Set|Add|Clear)-Content\b|\bOut-File\b|\bhelm\s+(?:upgrade|install)\b[^\n]*--set\b|\bfly\s+secrets\s+set\b|SetEnvironmentVariable/i;
export function protectedKeyInCommand(command, surfaces) {
  if (!surfaces || !surfaces.keys || !surfaces.keys.length || typeof command !== "string") return false;
  return WRITE_VERB.test(command) && surfaces.keys.some((k) => keyRe(k).test(command));
}
