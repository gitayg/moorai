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

// Default claude_desktop_config.json location per platform.
export function defaultConfigPath(platform = process.platform, home = os.homedir()) {
  if (platform === "win32") {
    const appdata = process.env.APPDATA || join(home, "AppData", "Roaming");
    return join(appdata, "Claude", "claude_desktop_config.json");
  }
  if (platform === "darwin") return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  // Linux / other — Claude Desktop is macOS/Windows only, but keep a sane default for tooling/tests.
  return join(home, ".config", "Claude", "claude_desktop_config.json");
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

export function wrapConfig(config, guardPath = GUARD_PATH) {
  const servers = (config && config.mcpServers) || {};
  const out = { ...config, mcpServers: {} };
  for (const [name, entry] of Object.entries(servers)) out.mcpServers[name] = wrapEntry(name, entry, guardPath);
  return out;
}

export function unwrapConfig(config, guardPath = GUARD_PATH) {
  const servers = (config && config.mcpServers) || {};
  const out = { ...config, mcpServers: {} };
  for (const [name, entry] of Object.entries(servers)) out.mcpServers[name] = unwrapEntry(entry, guardPath);
  return out;
}

// ---- CLI ----
function parseCli(argv) {
  let configPath = "", action = "wrap", dryRun = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config" || a === "-c") { configPath = argv[++i] || ""; }
    else if (a === "--dry-run" || a === "--print") { dryRun = true; }
    else if (["wrap", "install", "uninstall", "print", "status"].includes(a)) { action = a; }
  }
  if (action === "print") dryRun = true;
  return { configPath: configPath || defaultConfigPath(), action, dryRun };
}

function readConfig(path) {
  if (!existsSync(path)) { process.stderr.write(`moorai-mcp-guard install: no config at ${path}\n`); process.exit(1); }
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (e) { process.stderr.write(`moorai-mcp-guard install: could not parse ${path}: ${e.message}\n`); process.exit(1); }
}

function backup(path) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dest = `${path}.moorai-backup-${stamp}`;
  copyFileSync(path, dest);
  return dest;
}

function summarize(before, after) {
  const names = new Set([...Object.keys(before.mcpServers || {}), ...Object.keys(after.mcpServers || {})]);
  const rows = [];
  for (const n of names) {
    const b = JSON.stringify((before.mcpServers || {})[n]);
    const a = JSON.stringify((after.mcpServers || {})[n]);
    rows.push(`  ${b === a ? "· unchanged" : "✎ changed  "}  ${n}`);
  }
  return rows.join("\n");
}

function main() {
  const { configPath, action, dryRun } = parseCli(process.argv.slice(2));
  const config = readConfig(configPath);
  const nServers = Object.keys(config.mcpServers || {}).length;

  if (action === "status") {
    const wrapped = Object.entries(config.mcpServers || {}).filter(([, e]) => isWrapped(e)).map(([n]) => n);
    process.stdout.write(`config: ${configPath}\n${nServers} MCP server(s); ${wrapped.length} guarded${wrapped.length ? ": " + wrapped.join(", ") : ""}\n`);
    return;
  }

  const next = (action === "uninstall") ? unwrapConfig(config) : wrapConfig(config);
  const verb = action === "uninstall" ? "uninstall (restore originals)" : "wrap through MoorAI guard";
  process.stdout.write(`config: ${configPath}\naction: ${verb}\nguard:  ${GUARD_PATH}\n\n${summarize(config, next) || "  (no MCP servers)"}\n`);

  if (dryRun) { process.stdout.write("\n[dry-run] no files written.\n"); return; }
  if (JSON.stringify(config) === JSON.stringify(next)) { process.stdout.write("\nAlready up to date — nothing to write.\n"); return; }

  mkdirSync(dirname(configPath), { recursive: true });
  const bak = backup(configPath);
  writeFileSync(configPath, JSON.stringify(next, null, 2) + "\n");
  process.stdout.write(`\nBackup: ${bak}\nWrote:  ${configPath}\nRestart Claude Desktop for changes to take effect.\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) main();
