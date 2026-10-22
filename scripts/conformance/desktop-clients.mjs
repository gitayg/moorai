// Desktop MCP clients in the live host-conformance tier: Claude Desktop, VS Code and the Cursor desktop
// app. These are GUI apps with no headless mode, so the tier records whether each is installed and at
// which version, and never launches one: a GUI run would use the person's real profile and account.
// Detection is macOS-only (an .app bundle in /Applications, or MOORAI_CONFORMANCE_APPS_DIR); elsewhere
// every desktop client is recorded as not installed.
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { cleanVersion, parseVersion } from "../../cli/agent-hooks/host-version.mjs";

export const DESKTOP_CLIENTS = [
  { id: "claude-desktop", label: "Claude Desktop", app: "Claude.app" },
  { id: "vscode", label: "Visual Studio Code", app: "Visual Studio Code.app" },
  { id: "cursor-desktop", label: "Cursor desktop app", app: "Cursor.app" }
];

export function appsDir(env = process.env) {
  return env.MOORAI_CONFORMANCE_APPS_DIR || (process.platform === "darwin" ? "/Applications" : null);
}

export function appVersion(appPath) {
  const r = spawnSync("/usr/bin/plutil", ["-extract", "CFBundleShortVersionString", "raw", join(appPath, "Contents", "Info.plist")], { encoding: "utf8", timeout: 10000 });
  return r.status === 0 ? cleanVersion(parseVersion(r.stdout)) : null;
}

export function desktopTargets(env = process.env) {
  const dir = appsDir(env);
  return DESKTOP_CLIENTS.map((c) => {
    const p = dir ? join(dir, c.app) : null;
    const installed = !!(p && existsSync(p));
    return { kind: "desktop-client", id: c.id, label: c.label, version: installed ? appVersion(p) : null, ran: false, model: "none", reason: installed ? "no-headless-mode" : "not-installed", cases: [] };
  });
}
