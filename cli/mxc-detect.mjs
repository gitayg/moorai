// MXC detect and report: on a Windows device, for each agent host, whether the commands that agent
// runs are contained by Microsoft Execution Containers (MXC, github.com/microsoft/mxc), plus whether
// the device's Windows build meets MXC's documented minimum. Report-only and content-free: it changes
// no verdict, reads config files and one registry value, and fails open (any error = field left out or
// "unknown"). Called only from cli/agent-posture.mjs, which runs in the daily posture-beat worker
// (cli/moorai-hook.mjs runPostureBeatWorker), never on a hook's verdict path.
//
// What leaves the device, per host: { kind, scope, source } from the fixed lists below. Per device:
// mxcCapable true | false | null. Never a path, a config value outside those lists, or a build number.
//
// WHAT IS DETECTED vs ASSUMED
//   Detected: what the host's own config file says. There is no documented way for a process to tell
//   it is inside MXC (no API, no environment marker), so nothing here observes a running container.
//   Assumed: that the host honours its config. A command-line override (codex -c ..., copilot
//   --sandbox / --no-sandbox), a Codex profile, or enterprise-managed settings MoorAI cannot read can
//   change what actually runs.
//   Scope: Codex and Copilot CLI contain the commands (and, for Copilot, MCP/LSP servers) the agent
//   runs, not the agent process itself — hence scope "commands". No host contains the whole agent
//   today, so "agent" is reserved.
//
// SOURCES (fetched 2026-10-07)
//   Codex — learn.chatgpt.com/docs/config-file/config-reference: "windows.sandbox: unelevated | elevated
//     | mxc", "Windows-only native sandbox mode when running Codex natively on Windows"; files
//     ~/.codex/config.toml and project .codex/config.toml ("loaded only when trusted").
//     openai/codex@f73a478 codex-rs/mxc-sandbox/README.md: "`windows.sandbox = "mxc"` is strict. The
//     default-off `features.prefer_mxc` selects MXC for local execution when available"; core/src/
//     windows_sandbox.rs resolve_windows_sandbox_mode(): `windows.sandbox`, else the legacy features
//     `elevated_windows_sandbox` (elevated) / `experimental_windows_sandbox`,
//     `enable_experimental_windows_sandbox` (unelevated); config/src/types.rs WindowsToml.allow_mxc:
//     "False blocks both explicit MXC configuration and automatic selection."
//   Copilot CLI — github/docs@7b80792 content/copilot/how-tos/cloud-and-local-sandboxes/
//     using-local-sandboxing.md: "An ordinary enable or disable command saves your choice as
//     `sandbox.enabled` in your personal settings file (`~/.copilot/settings.json` by default)." and
//     "If enterprise managed settings require sandboxing, ordinary configuration and the `--no-sandbox`
//     command line option cannot disable it." configuring-local-sandbox-settings.md: "Sandbox settings
//     are not supported in repository-level settings files"; "Enable sandbox | Run shell commands
//     inside the sandbox"; "Sandbox MCP servers | Run MCP servers inside the sandbox. Turned on by
//     default." On Windows that sandbox is MXC's ProcessContainer/BaseContainer tier (GitHub docs,
//     same page; commandline.microsoft.com "local models and sandboxed tools", 2026-10). An unsupported
//     host fails the shell "and does not run unsandboxed".
//   Claude Code — code.claude.com/docs/en/sandboxing: "On native Windows, Claude Code runs commands
//     unsandboxed." No MXC setting exists (anthropics/sandbox-runtime PR #427 is an open draft).
//   Build minimum — microsoft/mxc@7cd00d1 docs/backends/process-container/os-version-support.md,
//     Process Isolation column: 24H2 26100.9278, 25H2 26200.9278, 26H2 26300.9550, 26H1 28000.2804
//     (KB5120998 / KB5124010 / KB5120996). A build that meets it is "capable", not "enabled": MXC ships
//     under gradual rollout, so the BaseContainer feature may still be off on that device.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { readJson } from "./doctor-hosts.mjs";
import { tomlKeys } from "./agent-posture.mjs";

export const CONTAINMENT_KINDS = ["mxc", "other", "none", "unknown"];
export const CONTAINMENT_SCOPES = ["commands", "agent"];
// Every source token the module can emit; the console accepts only these.
export const CONTAINMENT_SOURCES = [
  "codex:windows.sandbox",   // windows.sandbox set: "mxc" -> mxc; "elevated"/"unelevated" -> other
  "codex:legacy-feature",    // a legacy [features] Windows sandbox flag -> other
  "codex:prefer-mxc",        // features.prefer_mxc: MXC only if available at run time -> unknown
  "codex:allow-mxc-false",   // windows.allow_mxc = false and no other sandbox -> none
  "codex:full-access",       // sandbox_mode = "danger-full-access": no sandbox at all -> none
  "codex:unset",             // no Windows sandbox configured -> none
  "copilot:sandbox.enabled", // sandbox.enabled true -> mxc, false -> none
  "copilot:unset",           // not set: default undocumented for the CLI, managed settings unreadable -> unknown
  "copilot:unreadable",      // settings.json is not valid JSON -> unknown
  "claude-code:no-mxc"       // Claude Code has no MXC support on native Windows -> none
];

// Process Isolation minimum UBR per Windows 11 build (os-version-support.md, above).
export const MXC_MIN_UBR = { 26100: 9278, 26200: 9278, 26300: 9550, 28000: 2804 };
const FIRST_MXC_BUILD = 26100;
const UBR_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
const CACHE_FILE = "mxc-capable.json";
const CACHE_MS = 20 * 3600 * 1000;

const make = (kind, scope, source) => ({ kind, scope, source });

// os.release() on Windows is "10.0.<build>".
export function parseBuild(release) {
  const m = /^10\.0\.(\d{4,6})(?:$|\.)/.exec(String(release || ""));
  return m ? Number(m[1]) : null;
}

// true: the build meets MXC's documented minimum. false: older than any MXC build (Windows 10 and
// Windows 11 before 24H2). null: unknown — no UBR, or a build the table does not list (Insider).
export function mxcCapableFrom(build, ubr) {
  if (!Number.isInteger(build)) return null;
  if (build < FIRST_MXC_BUILD) return false;
  const min = MXC_MIN_UBR[build];
  if (min == null || !Number.isInteger(ubr)) return null;
  return ubr >= min;
}

// `reg query <key> /v UBR` prints "    UBR    REG_DWORD    0x2446"; a missing value exits 1 with an
// ERROR line on stderr.
export function parseRegUbr(stdout) {
  const m = /^\s*UBR\s+REG_DWORD\s+0x([0-9a-f]{1,8})\s*$/im.exec(String(stdout || ""));
  return m ? parseInt(m[1], 16) : null;
}
// `reg query` needs no elevation for this key. The absolute path avoids a reg.exe planted on PATH.
export function readUbrFromRegistry({ env = process.env, timeoutMs = 3000 } = {}) {
  const reg = join(env.SystemRoot || env.SYSTEMROOT || "C:\\Windows", "System32", "reg.exe");
  const r = spawnSync(reg, ["query", UBR_KEY, "/v", "UBR"], { encoding: "utf8", timeout: timeoutMs, windowsHide: true });
  return r.status === 0 ? parseRegUbr(r.stdout) : null;
}

// Cached in the state dir by os.release() so the registry is read at most once per ~day per release.
export function mxcCapable({ release, stateDir, readUbr = readUbrFromRegistry, now = Date.now() } = {}) {
  try {
    const build = parseBuild(release);
    if (build == null) return null;
    if (build < FIRST_MXC_BUILD) return false;
    const file = stateDir ? join(stateDir, CACHE_FILE) : null;
    let ubr;
    if (file) {
      try {
        const c = JSON.parse(readFileSync(file, "utf8"));
        if (c && c.release === release && now - c.at < CACHE_MS && (c.ubr === null || Number.isInteger(c.ubr))) ubr = c.ubr;
      } catch { /* no cache */ }
    }
    if (ubr === undefined) {
      try { ubr = readUbr(); } catch { ubr = null; }
      if (!Number.isInteger(ubr)) ubr = null;
      if (file) { try { mkdirSync(stateDir, { recursive: true }); writeFileSync(file, JSON.stringify({ release, ubr, at: now }), { mode: 0o600 }); } catch { /* re-read next beat */ } }
    }
    return mxcCapableFrom(build, ubr);
  } catch { return null; }
}

const readText = (f) => { try { return readFileSync(f, "utf8"); } catch { return null; } };

// The top-level keys Codex resolves, from one config file. A later (project) file overrides an earlier
// (user) one key by key, as Codex merges its layers.
function codexKeys(src, into) {
  for (const { section, key, value } of tomlKeys(src)) {
    const k = section ? `${section}.${key}` : key;
    if (["windows.sandbox", "windows.allow_mxc", "sandbox_mode", "features.prefer_mxc", "features.elevated_windows_sandbox",
      "features.experimental_windows_sandbox", "features.enable_experimental_windows_sandbox"].includes(k)) into[k] = value;
  }
  return into;
}
export function codexContainment({ home, env = {}, cwd = null } = {}) {
  const k = {};
  codexKeys(readText(join(env.CODEX_HOME || join(home, ".codex"), "config.toml")), k);
  if (cwd) codexKeys(readText(join(cwd, ".codex", "config.toml")), k);
  if (k.sandbox_mode === "danger-full-access") return make("none", null, "codex:full-access");
  const mode = k["windows.sandbox"];
  if (mode === "mxc") return k["windows.allow_mxc"] === false ? make("none", null, "codex:allow-mxc-false") : make("mxc", "commands", "codex:windows.sandbox");
  if (mode === "elevated" || mode === "unelevated") return make("other", "commands", "codex:windows.sandbox");
  if (k["features.elevated_windows_sandbox"] === true || k["features.experimental_windows_sandbox"] === true || k["features.enable_experimental_windows_sandbox"] === true)
    return make("other", "commands", "codex:legacy-feature");
  if (k["windows.allow_mxc"] === false) return make("none", null, "codex:allow-mxc-false");
  if (k["features.prefer_mxc"] === true) return make("unknown", null, "codex:prefer-mxc");
  return make("none", null, "codex:unset");
}

export function copilotContainment({ home, env = {} } = {}) {
  const r = readJson(join(env.COPILOT_HOME || join(home, ".copilot"), "settings.json"));
  if (r.exists && (!r.data || typeof r.data !== "object")) return make("unknown", null, "copilot:unreadable");
  const on = r.data && r.data.sandbox && typeof r.data.sandbox === "object" ? r.data.sandbox.enabled : undefined;
  if (on === true) return make("mxc", "commands", "copilot:sandbox.enabled");
  if (on === false) return make("none", null, "copilot:sandbox.enabled");
  return make("unknown", null, "copilot:unset");
}

const DETECT = {
  "claude-code": () => make("none", null, "claude-code:no-mxc"),
  codex: codexContainment,
  copilot: copilotContainment
};
// Windows only. Hosts with no documented MXC story (Gemini CLI, Cursor CLI) get no field at all.
export function hostContainment(hostId, opts = {}) {
  const fn = DETECT[hostId];
  if (!fn) return null;
  try { return fn(opts); } catch { return make("unknown", null, null); }
}
