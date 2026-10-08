// Agent posture: per-host, content-free flags for the settings that weaken or switch off MoorAI's
// protection, plus whether MoorAI's hook is registered and current and when the host was last used.
// Read-only probes. The console stores the result per device, shows a fleet report, and raises a
// finding when a flag turns on (server/coverage.js in the console repo).
//
// What leaves the device: host ids, flag names, scope names from a fixed vocabulary ("user",
// "project", "local", "managed", "system", "profile", "session"), a hook state word, an
// hour-rounded last-used timestamp, the host's version (digits, dots and a short build suffix only,
// or null) and whether that version is the one data/host-versions.json says the adapter was tested
// against (cli/agent-hooks/host-version.mjs). Never a path, a file's contents, a setting's value beyond the
// enumerated weak values, a project name or a session id.
//
// Hook registration reuses cli/doctor-hosts.mjs (hostTable, checkHost, checkManaged), so "registered"
// and "current" mean exactly what `moorai doctor` means: the expected surface comes from running
// MoorAI's own installers into a throwaway HOME.
//
// SETTING NAMES, quoted from each host's documentation (fetched 2026-10-01):
//   Claude Code (code.claude.com/docs/en/settings-reference):
//     disableAllHooks — "Turn off hooks, a custom status line, and a custom `@` file suggestion
//       command at once"
//     permissions.defaultMode — "Set the permission mode new sessions start in"; permission-modes:
//       "`bypassPermissions` mode disables permission prompts and safety checks so tool calls execute
//       immediately". settings: "values `auto` and `bypassPermissions` don't take effect from project
//       or local settings" (v2.1.257+), so the scope is reported and the console can weigh it.
//     sandbox.enabled — "Turn on Bash sandboxing on macOS, Linux, and WSL2" (off unless set).
//     allowManagedHooksOnly — "Run only the hooks your organization deploys".
//     hooks reference, permission_mode: `"default"`, `"plan"`, `"acceptEdits"`, `"auto"`, `"dontAsk"`,
//       or `"bypassPermissions"` — passed in by the hook as `permissionMode`.
//   Codex (learn.chatgpt.com/docs/config-file/config-reference, ~/.codex/config.toml and project
//     .codex/config.toml): approval_policy "on-request | never | { granular = … }"; sandbox_mode
//     "read-only | workspace-write | danger-full-access"; features.hooks "Enable lifecycle hooks loaded
//     from hooks.json or inline [hooks] config." (hooks doc: "`codex_hooks` still works as a deprecated
//     alias").
//   Gemini CLI (geminicli.com/docs/reference/configuration): hooksConfig.enabled "Canonical toggle for
//     the hooks system. When disabled, no hooks will be executed."; hooksConfig.disabled "List of hook
//     names (commands) that should be disabled."; general.defaultApprovalMode "'auto_edit' auto-approves
//     edit tools … YOLO mode … can only be enabled via command line" (so YOLO is not a setting to read);
//     tools.sandbox "Set to a boolean to enable or disable the sandbox". Files: ~/.gemini/settings.json,
//     .gemini/settings.json, and the system file (macOS /Library/Application Support/GeminiCli/).
//   Cursor (cursor.com/docs/cli/reference/configuration, ~/.cursor/cli-config.json and
//     <project>/.cursor/cli.json): approvalMode — allowed values "allowlist", "auto-review",
//     "unrestricted"; sandbox.mode — documented key, values not documented ("disabled" is what the CLI
//     writes; observed on disk). Hooks: ~/.cursor/hooks.json, <project>/.cursor/hooks.json.
//   GitHub Copilot CLI: hook registration only; no weakening setting is read.
//
// CONTAINMENT (Windows only, cli/mxc-detect.mjs): on win32 each Claude Code, Codex and Copilot entry
// also carries `containment: { kind, scope, source }` (is the agent's command execution inside a
// Microsoft Execution Container), and the report carries the device's `mxcCapable`. Other platforms
// get neither field: there the sandbox story is the existing sandboxOff / sandboxFullAccess flags.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";
import { hostTable, readJson, checkHost, checkManaged, readManagedSettings, diffSurface } from "./doctor-hosts.mjs";
import { hostVersion } from "./agent-hooks/host-version.mjs";
import { hostContainment, mxcCapable } from "./mxc-detect.mjs";

export const POSTURE_VERSION = 1;
// Every flag the module can emit. The console accepts only these names.
export const POSTURE_FLAGS = [
  "hooksDisabled",          // the host's hook system is switched off (all hooks, MoorAI's included)
  "mooraiHookDisabled",     // MoorAI's hook named in the host's per-hook disable list (Gemini)
  "managedHooksOnly",       // Claude Code allowManagedHooksOnly with MoorAI not among the managed hooks
  "bypassPermissionsDefault", // Claude Code permissions.defaultMode = bypassPermissions
  "sessionBypassPermissions", // this hook call's permission_mode = bypassPermissions
  "approvalNever",          // Codex approval_policy = "never"
  "approvalUnrestricted",   // Cursor CLI approvalMode = "unrestricted"
  "autoEditDefault",        // Gemini general.defaultApprovalMode = "auto_edit"
  "sandboxFullAccess",      // Codex sandbox_mode = "danger-full-access"
  "sandboxOff"              // the host's sandbox is not on (Claude Code, Gemini, Cursor CLI)
];
export const HOOK_STATES = ["ok", "missing", "stale", "broken", "untrusted", "unreadable", "absent"];

const add = (flags, name, scope) => { (flags[name] ||= []).includes(scope) || flags[name].push(scope); };
const get = (o, path) => path.split(".").reduce((v, k) => (v && typeof v === "object" ? v[k] : undefined), o);

// ---- hook registration (doctor-hosts) ----
export function hookState(result) {
  if (!result) return "absent";
  if (result.status === "skip" && result.installed === false) return "absent";
  if (result.installed === false) return "missing";
  if (!result.installed) return "unreadable"; // the host's config file is not valid JSON
  const d = result.details || {};
  if (d.expected && d.events && !diffSurface(d.expected, d.events).ok) return "stale";
  if (!Array.isArray(d.scripts) || !d.scripts.length) return "broken";
  if (/hook file missing|copy .* is gone|is missing|no hook script path/.test(result.summary || "")) return "broken";
  if (result.status === "warn" && /trust entry/.test(result.summary || "")) return "untrusted";
  return "ok";
}

// ---- last use, from the hosts' own session logs (mtimes only) ----
// Bounded walk: at each level only the K most recently modified entries are opened.
export const SESSION_DIRS = {
  "claude-code": (home) => [[join(home, ".claude", "projects"), 2]],
  codex: (home, env) => [[join(env.CODEX_HOME || join(home, ".codex"), "sessions"), 4]],
  gemini: (home) => [[join(home, ".gemini", "tmp"), 3]],
  cursor: (home) => [[join(home, ".cursor", "chats"), 3]],
  copilot: (home, env) => [[join(env.COPILOT_HOME || join(home, ".copilot"), "session-state"), 2]]
};
function newest(dir, depth, k = 8) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return 0; }
  const st = [];
  for (const e of entries.slice(0, 2000)) {
    try { st.push({ p: join(dir, e.name), dir: e.isDirectory(), m: statSync(join(dir, e.name)).mtimeMs }); } catch { /* raced */ }
  }
  st.sort((a, b) => b.m - a.m);
  let best = 0;
  for (const s of st.slice(0, k)) best = Math.max(best, s.dir && depth > 1 ? newest(s.p, depth - 1, k) || 0 : s.dir ? 0 : s.m);
  return best;
}
export function lastActive(hostId, { home = os.homedir(), env = process.env } = {}) {
  const dirs = (SESSION_DIRS[hostId] || (() => []))(home, env);
  const m = Math.max(0, ...dirs.map(([d, depth]) => newest(d, depth)));
  if (!m) return null;
  const h = new Date(m); h.setUTCMinutes(0, 0, 0);
  return h.toISOString();
}

// ---- weakened settings ----
// Minimal TOML reader for the three keys we need: `key = value` lines under their [section].
export function tomlKeys(src) {
  const out = [];
  let section = "";
  for (const raw of String(src || "").split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    const sec = line.match(/^\[\s*([^\]]+?)\s*\]$/);
    if (sec) { section = sec[1].replace(/\s+/g, ""); continue; }
    const kv = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    let v = kv[2].trim();
    if (/^".*"$|^'.*'$/.test(v)) v = v.slice(1, -1);
    else if (v === "true" || v === "false") v = v === "true";
    out.push({ section, key: kv[1], value: v });
  }
  return out;
}
const readText = (f) => { try { return readFileSync(f, "utf8"); } catch { return null; } };

function claudeFlags({ home, cwd, managedSources, managed }) {
  const flags = {};
  const scopes = [["user", readJson(join(home, ".claude", "settings.json")).data]];
  if (cwd) {
    scopes.push(["project", readJson(join(cwd, ".claude", "settings.json")).data]);
    scopes.push(["local", readJson(join(cwd, ".claude", "settings.local.json")).data]);
  }
  for (const s of managedSources) if (s.data) scopes.push(["managed", s.data]);
  let sandboxOn = false;
  for (const [scope, d] of scopes) {
    if (!d || typeof d !== "object") continue;
    if (d.disableAllHooks === true) add(flags, "hooksDisabled", scope);
    if (get(d, "permissions.defaultMode") === "bypassPermissions") add(flags, "bypassPermissionsDefault", scope);
    // Only the device-wide scopes decide the sandbox: a project file that turns it on would make this
    // flag flap with the directory the hook happens to run in.
    if ((scope === "user" || scope === "managed") && get(d, "sandbox.enabled") === true) sandboxOn = true;
  }
  if (!sandboxOn) add(flags, "sandboxOff", "user");
  const only = managedSources.some((s) => s.data && s.data.allowManagedHooksOnly === true);
  if (only && !(managed && (managed.managedHooks || (managed.managedPlugins || []).length))) add(flags, "managedHooksOnly", "managed");
  return flags;
}

function codexFlags({ home, env, cwd }) {
  const flags = {};
  const files = [["user", join(env.CODEX_HOME || join(home, ".codex"), "config.toml")]];
  if (cwd) files.push(["project", join(cwd, ".codex", "config.toml")]);
  for (const [scope, f] of files) {
    for (const { section, key, value } of tomlKeys(readText(f))) {
      const sc = section.startsWith("profiles.") ? "profile" : section === "" ? scope : null;
      if (sc && key === "approval_policy" && value === "never") add(flags, "approvalNever", sc === "profile" ? "profile" : scope);
      if (sc && key === "sandbox_mode" && value === "danger-full-access") add(flags, "sandboxFullAccess", sc === "profile" ? "profile" : scope);
      if (section === "features" && (key === "hooks" || key === "codex_hooks") && value === false) add(flags, "hooksDisabled", scope);
      if (section === "" && (key === "features.hooks" || key === "features.codex_hooks") && value === false) add(flags, "hooksDisabled", scope);
    }
  }
  return flags;
}

export function geminiSystemFile(platform = process.platform) {
  if (platform === "darwin") return "/Library/Application Support/GeminiCli/settings.json";
  if (platform === "win32") return "C:\\ProgramData\\gemini-cli\\settings.json";
  return "/etc/gemini-cli/settings.json";
}
function geminiFlags({ home, cwd, systemFiles }) {
  const flags = {};
  const files = [["user", join(home, ".gemini", "settings.json")]];
  if (cwd) files.push(["project", join(cwd, ".gemini", "settings.json")]);
  files.push(["system", systemFiles.gemini ?? geminiSystemFile()]);
  for (const [scope, f] of files) {
    const d = readJson(f, { comments: true }).data;
    if (!d || typeof d !== "object") continue;
    if (get(d, "hooksConfig.enabled") === false) add(flags, "hooksDisabled", scope);
    const dis = get(d, "hooksConfig.disabled");
    if (Array.isArray(dis) && dis.some((n) => /moorai/i.test(String(n)))) add(flags, "mooraiHookDisabled", scope);
    if (get(d, "general.defaultApprovalMode") === "auto_edit") add(flags, "autoEditDefault", scope);
    if (get(d, "tools.sandbox") === false) add(flags, "sandboxOff", scope);
  }
  return flags;
}

function cursorFlags({ home, cwd }) {
  const flags = {};
  const files = [["user", join(home, ".cursor", "cli-config.json")]];
  if (cwd) files.push(["project", join(cwd, ".cursor", "cli.json")]);
  for (const [scope, f] of files) {
    const d = readJson(f).data;
    if (!d || typeof d !== "object") continue;
    if (d.approvalMode === "unrestricted") add(flags, "approvalUnrestricted", scope);
    if (get(d, "sandbox.mode") === "disabled") add(flags, "sandboxOff", scope);
  }
  return flags;
}

const SETTINGS = { "claude-code": claudeFlags, codex: codexFlags, gemini: geminiFlags, cursor: cursorFlags };

// The whole posture. `caller` is the host whose hook is asking (always reported: it is running), and
// `permissionMode` that hook's permission_mode (Claude Code only).
// `versions` turns on host-version detection (env for the caller, then a cached PATH probe that may run
// `<bin> --version` once); `stateDir` holds that cache.
// `containment` turns on MXC detection on win32 (`platform`, `release` and `readUbr` are injectable for
// tests); the registry read behind mxcCapable is cached in `stateDir`.
export function agentPosture({ home = os.homedir(), env = process.env, cwd = null, caller = "", permissionMode = "", managedSources, systemFiles = {}, hookCheck = true, versions = true, stateDir = join(home, ".moorai"),
  containment = true, platform = process.platform, release = os.release(), readUbr } = {}) {
  const win = containment && platform === "win32";
  const sources = managedSources ?? readManagedSettings();
  const managed = checkManaged(sources);
  const hosts = [];
  for (const h of hostTable(home, env)) {
    const flags = (SETTINGS[h.id] || (() => ({})))({ home, env, cwd, managedSources: sources, managed, systemFiles });
    const res = hookCheck ? checkHost(h, { managedHooks: managed.managedHooks, managedPlugins: managed.managedPlugins || [], env, home }) : null;
    const hook = hookState(res);
    const present = hook !== "absent" || h.id === caller;
    if (h.id === "claude-code" && permissionMode === "bypassPermissions") add(flags, "sessionBypassPermissions", "session");
    for (const k of Object.keys(flags)) flags[k].sort();
    const last = lastActive(h.id, { home, env });
    if (!present && !last) continue; // host not on this device
    let v = { version: null, tested: false };
    if (versions) { try { v = hostVersion(h.id, { caller, env, stateDir }); } catch { /* report-only: unknown */ } }
    const entry = { host: h.id, present, hook, lastActive: last, flags, version: v.version, tested: v.tested };
    if (win) { const c = hostContainment(h.id, { home, env, cwd }); if (c) entry.containment = c; }
    hosts.push(entry);
  }
  if (!win) return { v: POSTURE_VERSION, hosts };
  return { v: POSTURE_VERSION, hosts, mxcCapable: mxcCapable({ release, stateDir, ...(readUbr ? { readUbr } : {}) }) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(JSON.stringify(agentPosture({ cwd: process.cwd() }), null, 2) + "\n");
}
