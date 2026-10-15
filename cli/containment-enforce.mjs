// MXC enforcement on Windows (v1.18.0). cli/mxc-detect.mjs only REPORTS whether an agent's commands run
// inside Microsoft Execution Containers; this module lets the administrator REQUIRE it:
//
//   containmentRequired   "off" (default) | "alert" | "block"   Codex CLI and Copilot CLI: a command tool
//                         call (Bash / PowerShell) from a host whose own config does not put its commands in
//                         MXC is alerted on, or denied.
//   containmentClaudeCode "off" (default) | "wrap"             Claude Code has no MXC setting, so MoorAI's
//                         PreToolUse hook rewrites each Bash call (hookSpecificOutput.updatedInput) to run
//                         the command through wxc-exec.exe in a per-command MXC config scoped to the workspace.
//
// WHO DECIDES. Only the root-owned admin binding and the verified signed policy, in that order, exactly as
// failMode (cli/fail-mode.mjs). A user-writable file never turns either field on or off. Exact lowercase
// values only; anything else is warned about by source and key (never the value) and the next source decides.
//
// WINDOWS ONLY. On macOS and Linux both fields are ignored and the effective modes are "off".
//
// Content-free: what leaves the device is a host id, a containment kind/source from mxc-detect's fixed
// lists, mxcCapable, a mode and a fixed reason token. Never a path, a command or a config value.
import { lstatSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { codexContainment, copilotContainment, mxcCapable, readUbrFromRegistry } from "./mxc-detect.mjs";
import { buildMxcPolicy, winNorm, isAbsoluteWin, isUnder, winDirname } from "./mxc-policy.mjs";
import { REASON } from "./provenance.mjs";

export const CONTAINMENT_REQUIRED_MODES = Object.freeze(["off", "alert", "block"]);
export const CLAUDE_CODE_WRAP_MODES = Object.freeze(["off", "wrap"]);
// The hosts containmentRequired governs: the two whose own config can put their commands in MXC.
export const ENFORCED_HOSTS = Object.freeze(["codex", "copilot"]);
// Tool names (Claude Code's, which the agent-hook shim translates to) that run a command.
export const COMMAND_TOOLS = Object.freeze(["Bash", "PowerShell"]);
// The env variable that carries the wrapped command into the container (see wrapScript).
export const WRAP_ENV = "MOORAI_WRAP_CMD";
// Windows caps one environment variable at 32,767 characters including "NAME=" and the terminator.
export const WRAP_MAX_CHARS = 32767 - WRAP_ENV.length - 2;
// The outer command (display prefix + wxc-exec launch) must fit in the command line Claude Code builds to run it
// under Git Bash. CreateProcess caps a command line at 32,767 characters. Claude Code adds its own wrapper (shell
// snapshot, eval, cwd tracking) and quotes our command again; neither length is documented. So the outer command
// is measured after one more round of single-quote escaping and must stay under 32,767 minus a 4,096-character
// reserve for that wrapper. The reserve is an assumption, not a measurement.
export const WRAP_OUTER_MAX = 32767 - 4096;
// Config files older than this are removed on the next wrap: wxc-exec reads its config at start.
export const WRAP_SWEEP_MS = 10 * 60 * 1000;

const own = (o, k) => o !== null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
function defaultWarn(m) { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* a warning, never a decision */ } }

function pickMode(key, allowed, admin, policy, warn) {
  for (const [src, label, source] of [[admin, "admin binding", "admin"], [policy, "signed policy", "policy"]]) {
    if (!own(src, key)) continue;
    if (allowed.includes(src[key])) return { mode: src[key], source };
    warn(`${key} in the ${label} is not one of ${allowed.join(", ")}; ignored`);
  }
  return { mode: "off", source: "default" };
}

// policy: the verified signed policy (or null). admin: the parsed admin binding (cli/server-mode.mjs
// systemConfig()). platform: anything but "win32" turns both off (source "platform"). Never throws.
export function resolveContainment(policy, { admin = null, platform = process.platform, warn = defaultWarn } = {}) {
  const w = typeof warn === "function" ? (m) => { try { warn(m); } catch { /* never throws */ } } : () => {};
  const off = (source) => ({ required: { mode: "off", source }, claudeCode: { mode: "off", source } });
  try {
    if (platform !== "win32") return off("platform");
    return {
      required: pickMode("containmentRequired", CONTAINMENT_REQUIRED_MODES, admin, policy, w),
      claudeCode: pickMode("containmentClaudeCode", CLAUDE_CODE_WRAP_MODES, admin, policy, w)
    };
  } catch { return off("default"); }
}

// THE DECISION (pure). mode: containmentRequired's effective mode. kind: mxc-detect's containment kind
// for the host. capable: mxcCapable (true | false | null).
//   mxc                         allow: the host's own config puts its commands in MXC.
//   device not capable (false)  alert CONTAINMENT_UNAVAILABLE in both modes: the build cannot run MXC, so
//                               denying would refuse every command for something the user cannot fix.
//   none / other                CONTAINMENT_MISSING: alert, or deny in block. Capability unknown (null) is
//                               not an excuse: the host is not even set to MXC, and setting it is the fix.
//   unknown                     (Codex features.prefer_mxc, Copilot sandbox.enabled unset or unreadable)
//                               CONTAINMENT_MISSING: deny in block only when the device is known capable
//                               (then MXC can run and the user can make it explicit); otherwise alert.
// → { action: "allow" | "alert" | "deny", reasonCode: string | null }
export function containmentDecision({ mode = "off", kind = "unknown", capable = null } = {}) {
  if (mode !== "alert" && mode !== "block") return { action: "allow", reasonCode: null };
  if (kind === "mxc") return { action: "allow", reasonCode: null };
  if (capable === false) return { action: "alert", reasonCode: REASON.CONTAINMENT_UNAVAILABLE };
  if (kind === "none" || kind === "other") return { action: mode === "block" ? "deny" : "alert", reasonCode: REASON.CONTAINMENT_MISSING };
  return { action: mode === "block" && capable === true ? "deny" : "alert", reasonCode: REASON.CONTAINMENT_MISSING };
}

// The Claude Code wrap could not be applied: containmentRequired's mode decides, with UNAVAILABLE.
// "alert" and "off" both allow; the hook posts their alert once per session.
export function wrapFallback(mode) {
  if (mode === "block") return { action: "deny", reasonCode: REASON.CONTAINMENT_UNAVAILABLE };
  return { action: "alert", reasonCode: REASON.CONTAINMENT_UNAVAILABLE };
}

// The host's containment kind as the hook sees it. Codex: the user layer alone, and the user layer with the
// project's .codex/config.toml on top. MXC only if BOTH say mxc: Codex loads a project config only when the
// user trusted the project, so a project file claiming mxc is not believed on its own, while a trusted one
// that weakens the user's choice is caught. Copilot has no project-level sandbox settings.
export function hostKind(host, { home, env = {}, cwd = null } = {}) {
  if (host === "copilot") return copilotContainment({ home, env });
  if (host !== "codex") return null;
  const user = codexContainment({ home, env, cwd: null });
  if (!cwd) return user;
  const merged = codexContainment({ home, env, cwd });
  if (user.kind === "mxc" && merged.kind === "mxc") return merged;
  return merged.kind !== "mxc" ? merged : user;
}

// mxcCapable for the hook path. ~/.moorai/mxc-capable.json is user-writable, so under block the cache is
// never read: the build comes from os.release() and the UBR straight from the registry (one reg.exe spawn,
// only for a build >= 26100 and only when the host is not already set to mxc). A cache edited to "incapable"
// therefore cannot turn a deny into an UNAVAILABLE alert. Under alert the cache can at most change which
// reason an alert carries, so it is used. Memoised per process.
let CAPABLE_MEMO;
export function capableForHook({ mode, release, stateDir, readUbr = readUbrFromRegistry } = {}) {
  if (mode === "block") {
    if (CAPABLE_MEMO !== undefined) return CAPABLE_MEMO;
    return (CAPABLE_MEMO = mxcCapable({ release, stateDir: null, readUbr }));
  }
  return mxcCapable({ release, stateDir, readUbr });
}
export function _resetCapableMemoForTests() { CAPABLE_MEMO = undefined; }

// The content-free alert for a containment verdict (without ts / identity, which the hook adds).
export function containmentAlert({ host, tool, decision, reasonCode, mode, kind = null, source = null, capable = null, why = null }) {
  const missing = reasonCode === REASON.CONTAINMENT_MISSING;
  return {
    threatId: 0,
    category: missing ? "Containment: agent commands not in MXC" : "Containment: MXC unavailable",
    riskLevel: decision === "deny" ? "Blocked" : "Medium",
    stage: "policy",
    tool: `hook:${tool}`,
    decision: decision === "deny" ? "deny" : "allow",
    reasonCode,
    host,
    containmentRequired: mode,
    ...(kind ? { containmentKind: kind } : {}),
    ...(source ? { containmentSource: source } : {}),
    mxcCapable: capable === true || capable === false ? capable : null,
    ...(why ? { wrapWhy: why } : {}),
    contentHash: `containment:${reasonCode}:${host}${why ? `:${why}` : ""}`
  };
}

export function denyReason(reasonCode, host) {
  if (reasonCode === REASON.CONTAINMENT_MISSING) return `your organization requires ${host === "codex" ? "Codex" : "Copilot CLI"} to run commands inside a Microsoft Execution Container (MXC), and its configuration does not (${host === "codex" ? "set windows.sandbox = \"mxc\" in ~/.codex/config.toml" : "set sandbox.enabled to true in ~/.copilot/settings.json"})`;
  return "your organization requires commands to run inside a Microsoft Execution Container (MXC), and MoorAI cannot put this command in one on this device";
}

// ---- The Claude Code Bash wrap ----

// Windows command-line quoting (MSVC argv rules), the same as src-tauri/src/mxc_launch.rs quote_arg.
export function quoteArgWin(a) {
  const s = String(a);
  if (s && !/[ \t\n\v"]/.test(s)) return s;
  let out = "\"", bs = 0;
  for (const c of s) {
    if (c === "\\") { bs++; continue; }
    if (c === "\"") { out += "\\".repeat(bs * 2 + 1) + "\""; bs = 0; continue; }
    out += "\\".repeat(bs) + c; bs = 0;
  }
  return out + "\\".repeat(bs * 2) + "\"";
}
// A POSIX single-quoted word: exact for every byte except NUL (rejected before this is called).
export function bashQuote(s) { return `'${String(s).replace(/'/g, "'\\''")}'`; }
function bashUnquote(word) {
  if (!/^(?:'[^']*'|\\')+$/.test(word)) return null;
  return word.replace(/'([^']*)'|\\'/g, (_, a) => (a === undefined ? "'" : a));
}

// What bash runs inside the container. The command never runs from a command line (the outer command shows it
// in a no-op for the permission prompt, nothing more): it rides in the config's
// process.env as WRAP_ENV (JSON-encoded, so every byte but NUL survives as written) and is eval'd, which is
// how Claude Code itself runs a Bash command string. This fixed script is the only text MSYS2's command-line
// parser sees. The variable is unset before the command runs, so the command's children never inherit it.
export const WRAP_SCRIPT = `__moorai_c=$${WRAP_ENV}; unset ${WRAP_ENV}; eval "$__moorai_c"`;

export function innerCommandLine(bash) { return `${quoteArgWin(bash)} --noprofile --norc -c ${quoteArgWin(WRAP_SCRIPT)}`; }

// What Claude Code's Git Bash runs in place of the command:
//   : '<original>' ; MSYS_NO_PATHCONV=1 '<wxc-exec>' --config '<config>'
// The first part is display only, so Claude Code's permission prompt shows what is being approved: `:` is the
// shell's no-op builtin and its single-quoted argument is never expanded or executed (bashQuote is exact for
// every byte but NUL, which is refused earlier). The command that runs is the one in the config's env, inside
// the container. The exit status is wxc-exec's, the last command of the list. The executable is written with
// forward slashes so bash treats it as a path (a name with no "/" is looked up on PATH); the config path is a
// Windows path for wxc-exec, and MSYS_NO_PATHCONV=1 keeps Git Bash from converting either argument.
export function outerCommand(wxc, configPath, original) {
  return `: ${bashQuote(original)} ; MSYS_NO_PATHCONV=1 ${bashQuote(winNorm(wxc).replace(/\\/g, "/"))} --config ${bashQuote(winNorm(configPath))}`;
}
// Whether an outer command fits WRAP_OUTER_MAX after Claude Code quotes it once more.
export function outerFits(outer) { return bashQuote(outer).length <= WRAP_OUTER_MAX; }

function envGet(env, name) {
  const k = Object.keys(env || {}).find((x) => x.toLowerCase() === name.toLowerCase());
  return k ? String(env[k] ?? "") : "";
}
export function wrapDirOf(env) {
  const la = envGet(env, "LOCALAPPDATA");
  const home = envGet(env, "USERPROFILE");
  const base = isAbsoluteWin(la) ? winNorm(la) : isAbsoluteWin(home) ? `${winNorm(home)}\\AppData\\Local` : "";
  return base ? `${base}\\MoorAI Host\\wrap` : "";
}
// wxc-exec runs with the user's full rights, outside the container, so only Program Files qualifies (the
// rule of src-tauri/src/mxc_launch.rs wxc_location_allowed, without the desktop host's install directory:
// the hook does not know it, and a per-user install sits under %LOCALAPPDATA%). Found on PATH.
export function findWxcExec(env, exists = existsSync) {
  const pf = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"].map((k) => envGet(env, k)).filter(isAbsoluteWin).map(winNorm);
  for (const dir of envGet(env, "PATH").split(";")) {
    if (!isAbsoluteWin(dir) || dir.includes("..")) continue;
    const p = `${winNorm(dir)}\\wxc-exec.exe`;
    if (pf.some((d) => isUnder(p, d)) && exists(p)) return p;
  }
  return "";
}
// The bash Claude Code's Bash tool uses: CLAUDE_CODE_GIT_BASH_PATH (code.claude.com/docs/en/setup), else
// Git for Windows' default install. Returns the exe and the Git root granted read-only (bin\bash.exe and
// usr\bin\bash.exe both live under it; the first launches the second).
export function findGitBash(env, exists = existsSync) {
  const cands = [envGet(env, "CLAUDE_CODE_GIT_BASH_PATH"), envGet(env, "ProgramFiles") && `${envGet(env, "ProgramFiles")}\\Git\\bin\\bash.exe`];
  for (const c of cands) {
    if (!isAbsoluteWin(c) || !/\\bash\.exe$/i.test(winNorm(c)) || c.includes("..")) continue;
    const exe = winNorm(c);
    if (!exists(exe)) continue;
    const m = /^(.*?)\\(?:usr\\)?bin\\bash\.exe$/i.exec(exe);
    return { exe, root: m ? m[1] : winDirname(exe) };
  }
  return null;
}

// Each component a plain directory: not a file, a symlink or a junction (Node reports a junction as a
// symbolic link). The checks of src-tauri/src/mxc_launch.rs ensure_dir (v1.6.1) / cli/mxc-policy.mjs main.
function plainDir(lstat, d) { try { const s = lstat(d); return s.isDirectory() && !s.isSymbolicLink(); } catch (e) { return e && e.code === "ENOENT" ? null : false; } }
export function ensureWrapDir(dir, { lstat = lstatSync, mkdir = mkdirSync } = {}) {
  const parent = winDirname(dir);
  for (const d of [parent, dir]) {
    const st = plainDir(lstat, d);
    if (st === false) return false;
    if (st === null) { try { mkdir(d); } catch (e) { if (!e || e.code !== "EEXIST") return false; } }
    if (plainDir(lstat, d) !== true) return false;
  }
  return true;
}

// Recover the original command from a command already in wrapped form, so it is scanned and re-wrapped
// (never wrapped twice). Only the exact shape outerCommand produces, with this device's wxc-exec and a
// config of ours (wrap-<32 hex>.json in the wrap dir, a regular file). The displayed `: '…'` text is never
// read as the command: the command comes from the config file. → string | null (not wrapped form) | false
// (wrapped form whose command cannot be recovered: the caller treats the wrap as impossible).
const WRAPPED = /^: (?:(?:'[^']*'|\\')+) ; MSYS_NO_PATHCONV=1 ((?:'[^']*'|\\')+) --config ((?:'[^']*'|\\')+)$/;
export function unwrapCommand(command, { wxc, wrapDir, read = (p) => readFileSync(p, "utf8"), lstat = lstatSync } = {}) {
  const m = WRAPPED.exec(String(command || ""));
  if (!m) return null;
  const exe = bashUnquote(m[1]), cfg = bashUnquote(m[2]);
  if (exe === null || cfg === null) return null;
  try {
    if (!wxc || winNorm(exe).toLowerCase() !== winNorm(wxc).toLowerCase()) return false;
    if (!wrapDir || winDirname(cfg).toLowerCase() !== winNorm(wrapDir).toLowerCase() || !/\\wrap-[0-9a-f]{32}\.json$/.test(winNorm(cfg))) return false;
    const st = lstat(winNorm(cfg));
    if (!st.isFile() || st.isSymbolicLink()) return false;
    const env = JSON.parse(read(winNorm(cfg)))?.process?.env;
    const e = Array.isArray(env) ? env.find((x) => typeof x === "string" && x.startsWith(`${WRAP_ENV}=`)) : null;
    return e ? e.slice(WRAP_ENV.length + 1) : false;
  } catch { return false; }
}

// Everything the wrap needs that does not depend on the final command, or why it cannot be done.
// → { ok: true, wxc, bash, wrapDir, workspace, cwd } | { ok: false, why }
// why is a fixed token: not-windows, powershell-tool, host-cannot-rewrite, no-wxc-exec, not-capable,
// no-git-bash, no-workspace, wrap-dir-unsafe.
export function planWrap({ platform = process.platform, tool, canRewrite, env = process.env, cwd = "", capable = null, exists = existsSync, lstat = lstatSync, mkdir = mkdirSync } = {}) {
  if (platform !== "win32") return { ok: false, why: "not-windows" };
  if (tool === "PowerShell") return { ok: false, why: "powershell-tool" };
  if (tool !== "Bash") return { ok: false, why: "not-a-command" };
  if (!canRewrite) return { ok: false, why: "host-cannot-rewrite" };
  if (capable === false) return { ok: false, why: "not-capable" };
  const wxc = findWxcExec(env, exists);
  if (!wxc) return { ok: false, why: "no-wxc-exec" };
  const bash = findGitBash(env, exists);
  if (!bash) return { ok: false, why: "no-git-bash" };
  const proj = envGet(env, "CLAUDE_PROJECT_DIR");
  const workspace = isAbsoluteWin(proj) ? winNorm(proj) : isAbsoluteWin(cwd) ? winNorm(cwd) : "";
  if (!workspace) return { ok: false, why: "no-workspace" };
  const wrapDir = wrapDirOf(env);
  if (!wrapDir || !ensureWrapDir(wrapDir, { lstat, mkdir })) return { ok: false, why: "wrap-dir-unsafe" };
  return { ok: true, wxc, bash, wrapDir, workspace, cwd: isAbsoluteWin(cwd) ? winNorm(cwd) : workspace };
}

// The MXC config for one command (pure). → { ok: true, config } | { ok: false, why }
export function wrapConfig(plan, command, { env = process.env, nodeDir = "", egressRules, egressDefault, exists = existsSync } = {}) {
  const cmd = String(command ?? "");
  if (!cmd.trim()) return { ok: false, why: "empty-command" };
  if (cmd.includes("\0")) return { ok: false, why: "command-nul" };
  if (cmd.length > WRAP_MAX_CHARS) return { ok: false, why: "command-too-long" };
  if (!outerFits(outerCommand(plan.wxc, `${plan.wrapDir}\\wrap-${"0".repeat(32)}.json`, cmd))) return { ok: false, why: "command-line-too-long" };
  const r = buildMxcPolicy({
    scope: "commands", workspace: plan.workspace, processCwd: plan.cwd, env, agentBin: plan.bash.exe,
    nodeDir, extraReadonly: [plan.bash.root], commandLine: innerCommandLine(plan.bash.exe),
    extraEnv: [`${WRAP_ENV}=${cmd}`], egressRules, egressDefault
  }, { exists });
  if (!r.ok) return { ok: false, why: `policy-${r.reasonCode}` };
  return { ok: true, config: r.policy };
}

// Write the config (exclusive create under a random name, so nothing pre-planted at the name is written
// through) and return the command that replaces the original (`original` is shown in its display prefix).
// Old configs are swept first.
export function writeWrap(plan, config, original, { write = writeFileSync, list = readdirSync, lstat = lstatSync, unlink = unlinkSync, now = Date.now(), rand = () => randomBytes(16).toString("hex") } = {}) {
  try {
    for (const f of list(plan.wrapDir).filter((x) => /^wrap-[0-9a-f]{32}\.json$/.test(x)).slice(0, 64)) {
      try { const p = `${plan.wrapDir}\\${f}`; if (now - lstat(p).mtimeMs > WRAP_SWEEP_MS) unlink(p); } catch { /* next sweep */ }
    }
  } catch { /* sweeping never blocks a wrap */ }
  const configPath = `${plan.wrapDir}\\wrap-${rand()}.json`;
  write(configPath, JSON.stringify(config), { flag: "wx", mode: 0o600 });
  return { configPath, command: outerCommand(plan.wxc, configPath, original) };
}

// The updatedInput for a wrapped Bash call: every field Claude Code sent (description, timeout,
// run_in_background), the command replaced. updatedInput "Replaces the entire input object".
export function wrappedInput(toolInput, command) { return { ...(toolInput && typeof toolInput === "object" ? toolInput : {}), command }; }
export const WRAP_NOTE = "MoorAI: this command runs inside a Microsoft Execution Container (MXC) limited to the project directory; files outside it, network hosts other than allowed numeric addresses, and directory changes do not carry over.";

// claudeCodeWrap for the posture heartbeat: "on" | "off" | "unavailable". Static prerequisites only (the
// per-call checks — the workspace, the wrap dir, the command — are reported by the hook when they fail).
export function claudeCodeWrapState({ platform = process.platform, mode = "off", env = process.env, capable = null, exists = existsSync } = {}) {
  if (platform !== "win32" || mode !== "wrap") return "off";
  if (capable === false || !findWxcExec(env, exists) || !findGitBash(env, exists)) return "unavailable";
  return "on";
}
