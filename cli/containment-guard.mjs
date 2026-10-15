// The hook-side write guard for MXC containment on Windows (v1.18.2). While containmentRequired or
// containmentClaudeCode is on, the hook denies an agent tool call that writes where a write would undo the
// containment from outside it:
//
//   moorai-host      %LOCALAPPDATA%\MoorAI Host: the desktop host's launch state and the Claude Code wrap's
//                    per-command configs. A config rewritten between the hook writing it and wxc-exec reading
//                    it (Claude Code's permission prompt sits in between) chooses the container's policy and
//                    command line. The same class mxc-policy.mjs PATH_CLASSES never grants a container.
//   shell-snapshots  Claude Code's shell snapshots (~/.claude/shell-snapshots, or under CLAUDE_CONFIG_DIR):
//                    Claude Code sources one before each Bash command, on the host, before the wrap's
//                    launch runs, so a function or trap planted there runs uncontained.
//   shell-rc         The bash startup files Git Bash reads (~/.bashrc, ~/.bash_profile, ~/.bash_login,
//                    ~/.profile, ~/.bash_logout; the first three are mxc-policy.mjs's shell-profile class,
//                    data/persistence.js names the same files for #46) and Git for Windows' own etc\profile,
//                    etc\bash.bashrc and etc\profile.d: what the next snapshot is built from.
//
// Write / Edit / MultiEdit / NotebookEdit: the target path, resolved. A shell call (Bash, PowerShell, Monitor):
// a command that writes anything (data/tool-tags.js shellWrites, or an interpreter that can write without a
// shell verb) and names one of these locations. A string test, like exceptions.mjs SELF_GRANT: a path built at
// run time walks past it, and a read that also writes elsewhere (`cat ~/.bashrc > x`) is denied with it. The
// real boundary for a wrapped Bash command is the container, which grants none of these.
//
// Paths are compared in Win32-canonical form (cli/win-canon.mjs, v1.18.3): case, / and \, device and namespace
// prefixes, trailing dots and spaces, NTFS streams, . and .., environment forms, and 8.3 short names (a ~digit
// segment matches any protected name at its position). Not mxc-policy.mjs winNorm: that one is pinned to the
// Rust launcher (src-tauri/src/mxc.rs) by shared golden cases.
//
// Content-free: what leaves the device is the class id, never the path.
import { winCanon, canonUnder, canonSegment } from "./win-canon.mjs";
import { findGitBash } from "./containment-enforce.mjs";
import { shellWrites } from "../data/tool-tags.js";

export const GUARD_CLASSES = Object.freeze(["moorai-host", "shell-snapshots", "shell-rc"]);
export const GIT_BASH_RC = Object.freeze([".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout"]);
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
const SHELLS = new Set(["Bash", "PowerShell", "Monitor"]);
const INTERPRETER = /(?:^|[\s;&|(`])(?:python[0-9.]*|py|node|deno|bun|perl|ruby|php|pwsh|powershell|cmd)(?:\.exe)?(?=\s|$)/i;
const DIR_CHANGE = /(?:^|[\s;&|(`])(?:cd|pushd|Set-Location|sl|chdir)(?=\s|$)/i;

function envGet(env, name) {
  const k = Object.keys(env || {}).find((x) => x.toLowerCase() === name.toLowerCase());
  return k ? String(env[k] ?? "") : "";
}
const abs = (v) => winCanon(v, { literal: true });

// The protected locations for this environment: [{ cls, path }].
export function guardTargets(env) {
  const home = abs(envGet(env, "USERPROFILE"));
  const local = abs(envGet(env, "LOCALAPPDATA")) || (home ? `${home}\\AppData\\Local` : "");
  const cfg = abs(envGet(env, "CLAUDE_CONFIG_DIR")) || (home ? `${home}\\.claude` : "");
  const out = [];
  if (local) out.push({ cls: "moorai-host", path: `${local}\\MoorAI Host` });
  if (cfg) out.push({ cls: "shell-snapshots", path: `${cfg}\\shell-snapshots` });
  if (home) for (const f of GIT_BASH_RC) out.push({ cls: "shell-rc", path: `${home}\\${f}` });
  const git = findGitBash(env, () => true);
  if (git) for (const f of ["etc\\profile", "etc\\bash.bashrc", "etc\\profile.d"]) out.push({ cls: "shell-rc", path: `${git.root}\\${f}` });
  return out;
}

// A path as the agent wrote it, made absolute and Win32-canonical (cli/win-canon.mjs winCanon): quotes dropped,
// variables and ~ expanded from env, an MSYS /c/... path mapped to C:\..., a relative path joined to cwd.
// "" when it cannot be made absolute. literal: no variable or ~ expansion.
export function resolveTarget(p, { env = {}, cwd = "", literal = false } = {}) {
  return winCanon(p, { env, cwd, literal });
}

const classOf = (path, targets) => (path ? (targets.find((t) => canonUnder(path, t.path)) || {}).cls || null : null);
// A string as the guard reads it: expanded, and literally (a file API takes %X%\..\ as text, and .. folds it away).
const classOfWord = (w, env, cwd, targets) =>
  classOf(resolveTarget(w, { env, cwd }), targets) || classOf(resolveTarget(w, { env, cwd, literal: true }), targets);

// The words of a command that could be paths (split on whitespace and shell punctuation, `=` included so
// `of=~/.bashrc` and `--file=x` give their value), each quoted string whole (a path with a space), and the value
// of a PowerShell `-Path:x`.
function words(command) {
  const quoted = [...command.matchAll(/"([^"]*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2]).filter(Boolean);
  const split = command.split(/[\s;&|()<>=,`]+/).filter(Boolean);
  const colon = split.map((w) => /^-[A-Za-z]+:(.+)$/.exec(w)?.[1]).filter(Boolean);
  return [...split, ...quoted, ...colon];
}

// File-writing forms data/tool-tags.js shellWrites misses, for this gate only: cp/mv/tee/install/rsync/dd
// path-qualified, .exe, quoted or \-escaped; the PowerShell aliases of the write cmdlets (sc, ac, ni, cpi, copy,
// mi, move) and Tee-Object; redirects after a digit or & (1>, 2>>, &>, &>>) and >|.
const GUARD_WRITE = /(?:^|[\s;&|(`{])["']?(?:[^\s;&|()'"]*[\\/])?(?:cp|mv|tee|install|rsync|dd|Tee-Object|sc|ac|ni|cpi|copy|mi|move)(?:\.exe)?["']?(?=\s|$)|[0-9&]>{1,2}(?!&)|>\|/i;

// → the guard class the call writes into, or null. tool: the Claude Code tool name. ti: its tool_input.
export function guardHit({ tool, ti, env = {}, cwd = "" } = {}) {
  const input = ti && typeof ti === "object" ? ti : {};
  const targets = guardTargets(env);
  if (!targets.length) return null;
  if (WRITE_TOOLS.has(tool)) {
    const p = input.file_path || input.notebook_path;
    return typeof p === "string" ? classOfWord(p, env, cwd, targets) : null;
  }
  if (!SHELLS.has(tool) || typeof input.command !== "string") return null;
  const cmd = input.command.slice(0, 65536);
  if (!shellWrites(cmd) && !GUARD_WRITE.test(cmd) && !INTERPRETER.test(cmd)) return null;
  // The two directory names no ordinary command needs to write: matched as text too, so a quoted path with a
  // space (…\MoorAI Host\…) that the word split breaks still counts.
  const flat = cmd.replace(/["'`\\]/g, "/").replace(/\/+/g, "/");
  if (/moorai[\s/]*host(?:$|\/)/i.test(flat)) return "moorai-host";
  if (/(?:^|[\s/])\.claude\/shell-snapshots(?:$|\/|\s)/i.test(flat) || (envGet(env, "CLAUDE_CONFIG_DIR") && /(?:^|[\s/])shell-snapshots(?:$|\/|\s)/i.test(flat))) return "shell-snapshots";
  const dirChange = DIR_CHANGE.test(cmd);
  for (const w of words(cmd)) {
    const c = classOfWord(w, env, cwd, targets);
    if (c) return c;
    // `cd ~ && echo x >> .bashrc`: a bare rc name after a directory change may be the profile's.
    const bare = /[\\/]/.test(w) ? "" : canonSegment(w);
    if (dirChange && GIT_BASH_RC.some((f) => f.toLowerCase() === bare.toLowerCase())) return "shell-rc";
  }
  return null;
}

export function guardAlert({ tool, cls }) {
  return {
    threatId: 0, category: "Containment: write to a protected location", riskLevel: "Blocked", stage: "policy",
    tool: `hook:${tool}`, decision: "deny", guardClass: cls, contentHash: `containment:guard:${cls}`
  };
}
export function guardReason(cls) {
  const what = cls === "moorai-host" ? "MoorAI's containment state (%LOCALAPPDATA%\\MoorAI Host)" : cls === "shell-snapshots" ? "Claude Code's shell snapshots" : "a bash startup file Git Bash reads";
  return `your organization runs agent commands inside a Microsoft Execution Container (MXC), and this call writes to ${what}, which runs or configures commands outside the container`;
}
