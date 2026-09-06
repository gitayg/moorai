#!/usr/bin/env node
// Installer for the MoorAI MCP Guard. Rewrites each mcpServers[*] entry in claude_desktop_config.json so
// its command launches through the guard, preserving the original command/args as the wrapped target.
// Idempotent (a re-wrap is a no-op) and fully reversible (uninstall reconstructs the original from the
// wrapped args — no sidecar keys are added to the config). The config file is BACKED UP before any write.
//
//   node install.mjs [--config <path>] [--dry-run]        # wrap every stdio MCP server (default action)
//   node install.mjs [--config <path>] uninstall          # restore the originals
//   node install.mjs [--config <path>] print              # show what the wrapped config would look like
//
// The transform functions (wrapConfig / unwrapConfig / isWrapped) are exported and pure so they can be
// tested against a fixture without touching a real Claude install.

import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join, basename } from "node:path";
import os from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
export const GUARD_PATH = join(HERE, "moorai-mcp-guard.mjs");
const GUARD_BASENAME = basename(GUARD_PATH); // "moorai-mcp-guard.mjs" — used to detect already-wrapped entries

// ---- MCP HOSTS ----
//
// The guard itself is host-agnostic and always was: moorai-mcp-guard.mjs speaks nothing but
// newline-delimited JSON-RPC over stdio, and every MCP host launches a stdio server the same way
// (argv + pipes). Nothing in it knows which host spawned it.
//
// This table is the ONLY thing that was Claude-Desktop-specific. Until it existed, defaultConfigPath()
// hardcoded claude_desktop_config.json and wrapConfig() hardcoded the `mcpServers` key, so a
// `servers`-keyed config (the VS Code / Copilot shape) came back with every server UNGUARDED plus a
// spurious empty `mcpServers` map. Host-independent enforcement that only one host's installer can
// reach is not multi-host enforcement.
//
// `key` is the config's server-map key. `path` is the conventional per-platform location; `--config`
// overrides it for any install that differs, which is the supported route for profile/workspace
// variants rather than growing this table into a guessing game.
function appData(home) { return process.env.APPDATA || join(home, "AppData", "Roaming"); }
function userDir(platform, home, app) {
  if (platform === "win32") return join(appData(home), app, "User");
  if (platform === "darwin") return join(home, "Library", "Application Support", app, "User");
  return join(home, ".config", app, "User");
}

export const HOSTS = [
  {
    id: "claude-desktop", label: "Claude Desktop", key: "mcpServers",
    path: (platform = process.platform, home = os.homedir()) => {
      if (platform === "win32") return join(appData(home), "Claude", "claude_desktop_config.json");
      if (platform === "darwin") return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
      return join(home, ".config", "Claude", "claude_desktop_config.json");
    }
  },
  {
    // Project-scoped MCP servers, read by Claude Code and by several other `.mcp.json` consumers.
    // Relative to the CWD by design — it is a per-repo file, not a per-user one.
    id: "mcp-json", label: "Project .mcp.json", key: "mcpServers",
    path: () => join(process.cwd(), ".mcp.json")
  },
  {
    id: "cursor", label: "Cursor", key: "mcpServers",
    path: (platform = process.platform, home = os.homedir()) => join(home, ".cursor", "mcp.json")
  },
  {
    // VS Code / GitHub Copilot. This is the shape that motivated the `key` field: its server map is
    // under `servers`, not `mcpServers`.
    id: "vscode", label: "VS Code / Copilot", key: "servers",
    path: (platform = process.platform, home = os.homedir()) => join(userDir(platform, home, "Code"), "mcp.json")
  }
];

export function hostById(id) { return HOSTS.find((h) => h.id === id) || null; }

// Which key holds this config's server map. Detected from the config itself so a file found via
// --config is handled correctly regardless of which host wrote it; falls back to the host's declared
// key, then to `mcpServers` (the historical behaviour, so an empty/new file is unchanged).
export function serversKeyOf(config, fallback = "mcpServers") {
  if (config && typeof config === "object") {
    if (config.mcpServers && typeof config.mcpServers === "object") return "mcpServers";
    if (config.servers && typeof config.servers === "object") return "servers";
  }
  return fallback;
}

// Default config path — Claude Desktop, unchanged, so every existing caller and test behaves as before.
export function defaultConfigPath(platform = process.platform, home = os.homedir()) {
  return hostById("claude-desktop").path(platform, home);
}

// Is this entry already routed through our guard?
export function isWrapped(entry, guardPath = GUARD_PATH) {
  if (!entry || !Array.isArray(entry.args)) return false;
  const a0 = entry.args[0];
  return a0 === guardPath || basename(String(a0 || "")) === GUARD_BASENAME;
}

// Wrap a single entry. stdio servers (those with a `command`) are wrapped; url/transport-only entries are
// returned unchanged. Already-wrapped entries are returned unchanged (idempotent).
export function wrapEntry(name, entry, guardPath = GUARD_PATH, nodeBin = "node") {
  if (!entry || typeof entry !== "object") return entry;
  if (!entry.command) return entry;          // not a stdio server (e.g. { url } SSE/HTTP) — leave alone
  if (isWrapped(entry, guardPath)) return entry;
  const wrapped = {
    ...entry,
    command: nodeBin,
    args: [guardPath, "--server", name, "--", entry.command, ...(Array.isArray(entry.args) ? entry.args : [])]
  };
  return wrapped;
}

// Restore a single entry to its original command/args (inverse of wrapEntry). Non-wrapped → unchanged.
export function unwrapEntry(entry, guardPath = GUARD_PATH) {
  if (!isWrapped(entry, guardPath)) return entry;
  const sep = entry.args.indexOf("--");
  if (sep < 0 || sep === entry.args.length - 1) return entry; // malformed — leave as-is rather than corrupt
  const origCmd = entry.args[sep + 1];
  const origArgs = entry.args.slice(sep + 2);
  const restored = { ...entry, command: origCmd, args: origArgs };
  if (!origArgs.length) delete restored.args; // omit an empty args array to match a typical original shape
  return restored;
}

// Both transforms operate on whichever key actually holds the server map, and NEVER create the other
// one: writing an empty `mcpServers` into a VS Code config is a silent corruption of a file the host
// re-reads, and it is exactly what the pre-multi-host version did.
function mapConfig(config, guardPath, key, fn) {
  const k = key || serversKeyOf(config);
  const servers = (config && config[k]) || {};
  const out = { ...config, [k]: {} };
  for (const [name, entry] of Object.entries(servers)) out[k][name] = fn(name, entry, guardPath);
  return out;
}

export function wrapConfig(config, guardPath = GUARD_PATH, key = null) {
  return mapConfig(config, guardPath, key, (name, entry, gp) => wrapEntry(name, entry, gp));
}

export function unwrapConfig(config, guardPath = GUARD_PATH, key = null) {
  return mapConfig(config, guardPath, key, (name, entry, gp) => unwrapEntry(entry, gp));
}

// ---- CLI ----
export function parseCli(argv) {
  let configPath = "", action = "wrap", dryRun = false, host = "", all = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config" || a === "-c") { configPath = argv[++i] || ""; }
    else if (a === "--host" || a === "-H") { host = argv[++i] || ""; }
    else if (a === "--all") { all = true; }
    else if (a === "--dry-run" || a === "--print") { dryRun = true; }
    else if (["wrap", "install", "uninstall", "print", "status"].includes(a)) { action = a; }
  }
  if (action === "print") dryRun = true;

  // Targets: --all = every known host that actually has a config on this machine; --host = one;
  // --config = that exact file (host inferred only for its declared key, which serversKeyOf overrides
  // anyway); default = Claude Desktop, so an existing invocation is byte-for-byte unchanged.
  let targets;
  if (all) targets = HOSTS.map((h) => ({ host: h, path: h.path() })).filter((t) => existsSync(t.path));
  else if (host) {
    const h = hostById(host);
    if (!h) { process.stderr.write(`moorai-mcp-guard install: unknown --host '${host}'. Known: ${HOSTS.map((x) => x.id).join(", ")}\n`); process.exit(2); }
    targets = [{ host: h, path: configPath || h.path() }];
  } else if (configPath) targets = [{ host: null, path: configPath }];
  else targets = [{ host: hostById("claude-desktop"), path: defaultConfigPath() }];

  return { targets, action, dryRun, all };
}

// Returns null instead of exiting when a config is simply absent, so `--all` can skip a host that
// isn't installed rather than aborting the whole run. A config that EXISTS but won't parse is still
// fatal for that target — silently skipping a corrupt file would leave the user believing it is
// guarded.
function readConfig(path, { soft = false } = {}) {
  if (!existsSync(path)) {
    if (soft) return null;
    process.stderr.write(`moorai-mcp-guard install: no config at ${path}\n`); process.exit(1);
  }
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (e) {
    process.stderr.write(`moorai-mcp-guard install: could not parse ${path}: ${e.message}\n`);
    if (soft) return null;
    process.exit(1);
  }
}

function backup(path) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dest = `${path}.moorai-backup-${stamp}`;
  copyFileSync(path, dest);
  return dest;
}

function summarize(before, after, key) {
  const names = new Set([...Object.keys(before[key] || {}), ...Object.keys(after[key] || {})]);
  const rows = [];
  for (const n of names) {
    const b = JSON.stringify((before[key] || {})[n]);
    const a = JSON.stringify((after[key] || {})[n]);
    const remote = !(before[key] || {})[n]?.command;
    rows.push(`  ${b === a ? (remote ? "· remote   " : "· unchanged") : "✎ changed  "}  ${n}`);
  }
  return rows.join("\n");
}

function runTarget({ host, path }, action, dryRun, soft) {
  const config = readConfig(path, { soft });
  if (!config) { process.stdout.write(`\n${host ? host.label : path}: no config at ${path} — skipped\n`); return; }
  const key = serversKeyOf(config, host?.key);
  const entries = Object.entries(config[key] || {});
  const label = host ? `${host.label} (${host.id})` : path;

  if (action === "status") {
    const wrapped = entries.filter(([, e]) => isWrapped(e)).map(([n]) => n);
    process.stdout.write(`\n${label}\n  config: ${path}\n  ${entries.length} MCP server(s) under '${key}'; ${wrapped.length} guarded${wrapped.length ? ": " + wrapped.join(", ") : ""}\n`);
    return;
  }

  const next = (action === "uninstall") ? unwrapConfig(config, GUARD_PATH, key) : wrapConfig(config, GUARD_PATH, key);
  const verb = action === "uninstall" ? "uninstall (restore originals)" : "wrap through MoorAI guard";
  process.stdout.write(`\n${label}\n  config: ${path}\n  action: ${verb}\n  key:    ${key}\n${summarize(config, next, key) || "  (no MCP servers)"}\n`);

  if (dryRun) { process.stdout.write("  [dry-run] no files written.\n"); return; }
  if (JSON.stringify(config) === JSON.stringify(next)) { process.stdout.write("  Already up to date — nothing to write.\n"); return; }

  mkdirSync(dirname(path), { recursive: true });
  const bak = backup(path);
  writeFileSync(path, JSON.stringify(next, null, 2) + "\n");
  process.stdout.write(`  Backup: ${bak}\n  Wrote:  ${path}\n  Restart ${host ? host.label : "the host"} for changes to take effect.\n`);
}

function main() {
  const { targets, action, dryRun, all } = parseCli(process.argv.slice(2));
  process.stdout.write(`guard: ${GUARD_PATH}\n`);
  if (!targets.length) { process.stdout.write("\nNo MCP host config found on this machine.\n"); return; }
  for (const t of targets) runTarget(t, action, dryRun, all);
  process.stdout.write("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) main();
