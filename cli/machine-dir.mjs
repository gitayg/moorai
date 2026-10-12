// Where the machine-wide, administrator-written MoorAI files live: /etc/moorai on macOS and Linux,
// <ProgramData>\MoorAI on Windows. Every root/admin anchor the hook trusts (policy.pub, breakglass.pub,
// offline-posture, policy-hwm.json, policy-lkg.json, exceptions.json, config.json) is a path under it.
//
// WINDOWS: NEVER FROM THE ENVIRONMENT. %ProgramData% and %SystemRoot% are the user's to set, and a
// settings file's `env` block (or any parent the agent starts) sets them for the hook. A hook that built
// its anchor paths from process.env.ProgramData read them from a directory the agent chose, where the
// icacls check (hook-core readRootOwned) is the only thing standing between the agent and a forged
// anchor, and that check does not see the file's owner (the owner gap described at readRootOwned). So:
//   * SystemRoot is the fixed C:\Windows when it holds System32\reg.exe (every supported install that
//     put Windows on C:); only a machine without it falls back to %SystemRoot%, and says so in
//     windowsDirs().source.
//   * ProgramData is HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList "ProgramData"
//     (REG_EXPAND_SZ "%SystemDrive%\ProgramData"), read with <SystemRoot>\System32\reg.exe by absolute
//     path, %SystemDrive% expanded from SystemRoot, never from the environment. The same source
//     src-tauri/src/admin_config.rs windows_dirs() reads through the registry API.
//   * If reg.exe fails or prints something unusable, <SystemDrive>\ProgramData.
// One reg.exe spawn per process, on Windows only, the first time a machine path is asked for; nothing
// is cached on disk (a user-scope cache would be the agent's to rewrite).
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { win32 } from "node:path";

export const PROFILE_LIST_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
const DEFAULT_ROOT = "C:\\Windows";
const drivePath = (s) => typeof s === "string" && /^[A-Za-z]:\\/.test(s) && !s.includes("%");

// `reg query <key> /v <name>` prints "    <name>    REG_EXPAND_SZ    <value>".
export function parseRegValue(out, name) {
  for (const line of String(out || "").split(/\r?\n/)) {
    const m = /^\s+(\S+)\s+REG_(?:EXPAND_)?SZ\s+(.+?)\s*$/.exec(line);
    if (m && m[1].toLowerCase() === String(name).toLowerCase()) return m[2];
  }
  return "";
}

function runReg(exe, args) {
  return execFileSync(exe, args, { encoding: "utf8", timeout: 3000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
}

// Pure apart from the injected probes: `exists` (fs.existsSync) and `run(exe, args)` (reg.exe). `env` is
// consulted ONLY for SystemRoot, and only when the fixed C:\Windows has no reg.exe.
export function windowsDirs({ exists = existsSync, run = runReg, env = process.env } = {}) {
  let systemRoot = DEFAULT_ROOT, source = "fixed";
  if (!exists(`${DEFAULT_ROOT}\\System32\\reg.exe`)) {
    const e = env.SystemRoot || env.SYSTEMROOT || "";
    if (drivePath(e)) { systemRoot = e.replace(/\\+$/, ""); source = "env-fallback"; }
  }
  const drive = systemRoot.slice(0, 2);
  let programData = "";
  try {
    const raw = parseRegValue(run(`${systemRoot}\\System32\\reg.exe`, ["query", PROFILE_LIST_KEY, "/v", "ProgramData"]), "ProgramData");
    const v = raw.replace(/%SystemDrive%/gi, drive).replace(/\\+$/, "");
    if (drivePath(v)) programData = v;
  } catch { /* fall through to the default */ }
  return { systemRoot, programData: programData || `${drive}\\ProgramData`, source, programDataSource: programData ? "hklm" : "default" };
}

let WIN = null;
export function windowsDirsCached() { return WIN || (WIN = windowsDirs()); }
export function _resetMachineDirForTests() { WIN = null; }

// The machine directory for `platform` (default: this process's). On Windows the HKLM ProgramData.
export function machineDir(platform = process.platform, dirs = null) {
  if (platform !== "win32") return "/etc/moorai";
  return win32.join((dirs || windowsDirsCached()).programData, "MoorAI");
}
export function machinePath(name, platform = process.platform, dirs = null) {
  return platform === "win32" ? win32.join(machineDir(platform, dirs), name) : `/etc/moorai/${name}`;
}
// A Windows system tool by absolute path (icacls.exe, reg.exe), never resolved through PATH or the cwd.
export function systemTool(name) {
  return `${windowsDirsCached().systemRoot}\\System32\\${name}`;
}
