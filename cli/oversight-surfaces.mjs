// Policy-declared protected oversight surfaces for the weakening-oversight threat (#84).
//
// The signed policy may carry `oversight` ({ v: 1, protectedPaths, protectedKeys, stopDisclosure, memoryFiles }):
//   protectedPaths  up to 64 globs (`**` any depth, `*` within one path segment, `?` one character), matched
//                   against the path relative to the session's working directory; a relative glob also matches
//                   at any directory boundary of an absolute path ("**/monitor_*.py", "ops/alerting/**",
//                   "src/audit_logger.py"). "dir/**" also matches the directory itself.
//   protectedKeys   up to 64 config keys or env var names ("no_notify", "ALERTS_ENABLED", "alerts.route"),
//                   matched as a whole word, exactly as written (a dotted key is not resolved through YAML nesting).
//   stopDisclosure  "alert" (default) or "block": what Stop / SubagentStop does when an allowed oversight change
//                   is not disclosed in the agent's final message (cli/oversight-disclosure.mjs).
//   memoryFiles     "notify" (default), "ask", "block" or "off". The agent's PERSISTENT-INSTRUCTION files —
//                   CLAUDE.md, CLAUDE.local.md, AGENTS.md, GEMINI.md, .cursorrules and the other rules files,
//                   Claude Code's auto memory (.claude/projects/<p>/memory/), OpenClaw's SOUL.md / MEMORY.md /
//                   memory/ (data/skill-surface.js PERSISTENT_INSTRUCTION_KINDS), the agent and editor settings that
//                   skip an approval or run a command (.claude/settings.json, .vscode/settings.json, .vscode/mcp.json,
//                   .vscode/tasks.json, .cursor/mcp.json, .codex/config.toml, .gemini/settings.json, .mcp.json,
//                   settings.VisualStudio.json, hook files …: data/skill-surface.js AGENT_SETTINGS_KINDS), and git's
//                   run-later files (a hook,
//                   a git config, the .git file, a commondir, a worktree's gitdir: gitRunLaterPath) — are watched BUILT IN, with no
//                   policy at all: a skill that persists itself into the agent's memory steers every later
//                   session. A write raises the signal "memory-file" (not "protected-surface"), and
//                   cli/hook-core.mjs decideOversight resolves it: with NOTHING configured for #84 and no
//                   memoryFiles, notify (an alert, no prompt), because an agent saves memory and edits CLAUDE.md
//                   on request routinely; with #84 configured (threatPolicy), the stricter of memoryFiles and
//                   #84's action, so the default never weakens an admin's policy. An invalid memoryFiles, or
//                   `protectMemoryFiles: true`, takes #84's action; `protectMemoryFiles: false` is "off". With both
//                   keys set the stricter wins: `protectMemoryFiles: false` never turns off a memoryFiles that is
//                   set, and `protectMemoryFiles: true` raises "off" or "notify" to #84's action. A policy that
//                   disables #84 still disables it.
//                   A path the policy ALSO declares in protectedPaths stays "protected-surface" (ask).
// Any Write / Edit / MultiEdit / NotebookEdit of a protected path, a write that changes a line naming a
// protected key, and a shell command that deletes, moves or writes a protected path or writes a protected key,
// is judged under #84 with the signal "protected-surface". An older agent ignores the key.
//
// A path is matched as written, as resolved against cwd (path.resolve: "ops/x/../alerting/a.yaml" and a
// relative path from a subdirectory), and, with { real: true }, through realpath: the target's real path, or
// for a file that does not exist yet the real path of its nearest existing ancestor plus the rest, so a
// symlinked file or directory cannot dodge a protected surface. Each form is matched relative to cwd and as an
// absolute path (a relative glob matches at any directory boundary of it, so cwd's own real path is not needed).
// Each form is also matched in its Win32 canonical form, on every platform (data/path-canon.js): trailing dots and
// spaces stripped from every segment ("CLAUDE.md.", ".git./config "), an alternate-data-stream suffix dropped
// ("CLAUDE.md::$DATA", "a.md:s:$DATA") with a drive letter kept, and an 8.3 short-name segment ("CLAUDE~1.MD",
// "VSCODE~1") read as each long name it can abbreviate — resolved through realpath.native on win32 when it exists,
// otherwise matched by its stem and extension, failing toward protection. Policy globs match case-insensitively.
//
// A malformed entry is dropped with a warning that names its position, never its value. Pure apart from the
// warning sink and the realpath lookups of protectedPathHit({ real: true }).
import { realpathSync } from "node:fs";
import { resolve, dirname, basename, join } from "node:path";
import { persistentInstructionKind, agentSettingsKind } from "../data/skill-surface.js";
import { winCanonical, hasShortName, expandShortNames } from "../data/path-canon.js";


const MAX_ENTRIES = 64, MAX_LEN = 256;
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_.\-]{0,127}$/;
const CONTROL_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const KNOWN = new Set(["v", "protectedPaths", "protectedKeys", "stopDisclosure", "memoryFiles", "protectMemoryFiles"]);
const MEMORY_ACTIONS = new Set(["notify", "ask", "block"]);
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
  const none = { paths: [], keys: [], stopDisclosure: "alert", memory: "default" };
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
  // memory: "default" (nothing set), "notify" | "ask" | "block" (set), "inherit" (#84's action), or false (off).
  let memory = "default";
  if (o.memoryFiles !== undefined) {
    if (MEMORY_ACTIONS.has(o.memoryFiles)) memory = o.memoryFiles;
    else if (o.memoryFiles === "off") memory = false;
    else { memory = "inherit"; warn("oversight.memoryFiles: not notify, ask, block or off; #84's action applies"); }
  }
  // With both keys set, the stricter wins: false turns the set off only when memoryFiles is not set; true
  // raises "off" and "notify" (and nothing set) to #84's action.
  if (o.protectMemoryFiles !== undefined) {
    if (o.protectMemoryFiles === false) { if (memory === "default") memory = false; }
    else if (o.protectMemoryFiles === true) { if (memory === "default" || memory === false || memory === "notify") memory = "inherit"; }
    else warn("oversight.protectMemoryFiles ignored: true or false");
  }
  return { paths, keys: [...new Set(keys)], stopDisclosure, memory };
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
// The names an 8.3 short-name segment of a built-in surface can stand for (data/path-canon.js
// shortNameCandidates): every literal segment of the persistent-instruction, agent-settings and git run-later
// paths. A segment whose name is not listed is still read as its alias's own stem ("FOO~1.MD" as "FOO.MD"), which
// covers the entries that match on an extension (.claude/rules/*.md, *.git).
export const BUILTIN_LONG_NAMES = Object.freeze([
  "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", "AGENTS.override.md", "GEMINI.md", "SOUL.md", "MEMORY.md",
  ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md", "global_rules.md",
  ".claude", ".cursor", ".windsurf", ".devin", "windsurf", "devin", ".cline", "Cline", ".github", ".copilot", ".kiro",
  ".openclaw", ".codeium", ".vscode", ".vs", ".codex", ".gemini", "gemini-cli", "GeminiCli", "antigravity-cli",
  ".agents", ".factory", ".amp", ".amazonq", "amazonq", ".zed", ".continue", ".opencode", "opencode", ".config",
  "rules", "projects", "memory", "memories", "instructions", "steering", "workspace", "hooks", "mcpServers",
  "settings", "Application Support", "Program Files", "ProgramData",
  "settings.json", "settings.local.json", "managed-settings.json", "managed-settings.d", "managed-mcp.json",
  ".mcp.json", ".claude.json", "claude_desktop_config.json", "mcp.json", "mcp_config.json", "cline_mcp_settings.json",
  "hooks.json", "system-defaults.json", "tasks.json", "config.toml", "opencode.json", "permissions.json", "cli.json",
  "cli-config.json", "settings.VisualStudio.json",
  ".git", ".gitconfig", "git", "config", "config.worktree", "commondir", "gitdir", "worktrees", "modules", "gitconfig"
]);
const WIN = process.platform === "win32";
const nativeReal = (p) => { try { return realpathSync.native(p); } catch { return null; } };
// → { forms, overflow }. Each path form (as written, resolved against cwd, and with { real: true } its real path) is
// added in its Win32 canonical form (data/path-canon.js: trailing dots and spaces stripped from every segment, the
// alternate-data-stream suffix dropped, separators as "/"), and a form with an 8.3 short-name segment is expanded to
// each long name the alias can stand for (names: the built-in ones plus each policy glob's segments). On win32 with
// { real: true } an alias that exists is resolved through realpath.native (GetFinalPathNameByHandle) instead.
// overflow: more expansions than the bound; the caller counts it as a hit (fail toward protection).
function formsOf(path, { cwd = "", real: useReal = false, globSegs = [], platform = WIN ? "win32" : "", realNative = nativeReal } = {}) {
  const base = typeof cwd === "string" && cwd ? cwd : process.cwd();
  const forms = new Set([path]);
  let resolved = null;
  try { resolved = resolve(base, path); forms.add(resolved); } catch { resolved = null; }
  if (useReal && resolved) { const r = realOf(resolved); if (r) forms.add(r); }
  let longOnWin = false;
  if (useReal && resolved && platform === "win32" && hasShortName(resolved)) {
    const n = realNative(resolved);
    if (n) { forms.add(n); longOnWin = !hasShortName(n); }
  }
  for (const f of [...forms]) forms.add(winCanonical(f));
  let overflow = false;
  if (!longOnWin) {
    for (const f of [...forms]) {
      if (!hasShortName(f)) continue;
      const e = expandShortNames(winCanonical(f), BUILTIN_LONG_NAMES, globSegs);
      if (e.overflow) overflow = true;
      for (const x of e.forms) forms.add(x);
    }
  }
  const out = new Set();
  for (const f of forms) { out.add(slashes(f)); out.add(norm(f, cwd)); }
  return { forms: [...out], overflow };
}
export function pathForms(path, opts = {}) { return formsOf(path, opts).forms; }
const okPath = (path) => typeof path === "string" && !!path && !/[\r\n\0]/.test(path);
// Policy globs match case-insensitively on every platform (Windows and macOS file systems are case-insensitive by
// default, and an extra match only fails closed).
const ciCache = new WeakMap();
const ci = (re) => { let r = ciCache.get(re); if (!r) { r = new RegExp(re.source, "i"); ciCache.set(re, r); } return r; };
const globSegsOf = (surfaces) => surfaces.paths.flatMap((p) => String(p.glob || "").replace(/\\/g, "/").split("/"));
export function protectedPathHit(path, surfaces, { cwd = "", real: useReal = false, platform, realNative } = {}) {
  if (!surfaces || !surfaces.paths || !surfaces.paths.length || !okPath(path)) return false;
  const { forms, overflow } = formsOf(path, { cwd, real: useReal, globSegs: globSegsOf(surfaces), ...(platform !== undefined ? { platform } : {}), ...(realNative ? { realNative } : {}) });
  return overflow || surfaces.paths.some((p) => forms.some((f) => ci(p.re).test(f)));
}
// git's own run-later surfaces: a hook (of a repository, a bare *.git, a worktree or a submodule gitdir), a config git
// reads (where core.hooksPath, core.fsmonitor, alias.* and filter.* live: the repository's, a worktree's, a
// submodule's, the user's global and the system one) and the .git file that names the gitdir (measured, git 2.39.5
// and 2.54.0: a .git file naming another gitdir makes git read its config, whose core.fsmonitor runs on status), and
// the files that send git to another directory: a gitdir's commondir (.git/commondir, .git/worktrees/<w>/commondir,
// .git/modules/<m>/commondir: git reads that directory's config, whose core.fsmonitor runs, and runs its hooks;
// measured, 2.39.5 and 2.54.0) and a worktree's gitdir (.git/worktrees/<w>/gitdir names the worktree, and `git worktree
// repair` writes a .git file there pointing back at the gitdir; measured, the same versions). objects/info/alternates,
// info/ files, .git/gitdir and .git/modules/<m>/gitdir run nothing (measured, the same versions) and are not watched.
const GIT_RUN_LATER = [
  /(?:^|\/)[^/]*\.git\/(?:(?:modules|worktrees)\/.+\/)?hooks\/[^/]/i,
  /(?:^|\/)[^/]*\.git\/(?:(?:modules|worktrees)\/.+\/)?config(?:\.worktree)?$/i,
  /(?:^|\/)[^/]*\.git\/(?:(?:modules|worktrees)\/.+\/)?commondir$/i,
  /(?:^|\/)[^/]*\.git\/(?:modules\/.+\/)?worktrees\/[^/]+\/gitdir$/i,
  /(?:^|\/)\.git$/i, /(?:^|\/)\.gitconfig$/i, /(?:^|\/)\.config\/git\/config$/i, /^\/etc\/gitconfig$/i
];
export const gitRunLaterPath = (f) => GIT_RUN_LATER.some((re) => re.test(f));
// One of the agent's persistent-instruction files (oversightPolicy's built-in set), one of the agent and editor
// settings files that grant approvals or run commands (data/skill-surface.js AGENT_SETTINGS_KINDS) or one of git's
// run-later surfaces, unless the policy turned the set off.
export function memoryPathHit(path, surfaces, { cwd = "", real: useReal = false, platform, realNative } = {}) {
  if (!surfaces || !surfaces.memory || !okPath(path)) return false;
  const { forms, overflow } = formsOf(path, { cwd, real: useReal, ...(platform !== undefined ? { platform } : {}), ...(realNative ? { realNative } : {}) });
  return overflow || forms.some((f) => persistentInstructionKind(f) !== null || agentSettingsKind(f) !== null || gitRunLaterPath(f));
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
