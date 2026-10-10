// Check 10 of `moorai-mcp-check`: does this machine route MCP traffic through MoorAI at all? Local reads
// only (the agent hosts' settings and the MCP client configs); nothing is fetched or written.
//
//   hook     a MoorAI hook entry in an agent host's settings (the same recognisers moorai-doctor uses,
//            cli/doctor-hosts.mjs), or the Claude Code plugin enabled. Claude Code's PreToolUse matcher
//            set includes `mcp__.*`, so its hook sees every MCP tool call.
//   proxy    an MCP server entry wrapped by mcp-proxy/install.mjs (`… moorai-mcp-guard.mjs … -- real…`).
//   gateway  an HTTP server entry on loopback that carries the gateway token header or the gateway's
//            default port (mcp-gateway/config.mjs: TOKEN_HEADER, DEFAULT_PORT).

import { homedir } from "node:os";
import { join } from "node:path";
import { hostTable, readJson, ourSurface } from "../doctor-hosts.mjs";

export const GATEWAY_TOKEN_HEADER = "x-moorai-gateway-token";
export const GATEWAY_DEFAULT_PORT = 8848;
const GUARD = /moorai-mcp-guard\.mjs$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function clientConfigs(home, cwd, platform) {
  const desktop = platform === "darwin" ? join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    : platform === "win32" ? join(process.env.APPDATA || join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json")
      : join(home, ".config", "Claude", "claude_desktop_config.json");
  const vscode = platform === "darwin" ? join(home, "Library", "Application Support", "Code", "User", "mcp.json")
    : platform === "win32" ? join(process.env.APPDATA || join(home, "AppData", "Roaming"), "Code", "User", "mcp.json")
      : join(home, ".config", "Code", "User", "mcp.json");
  return [join(home, ".claude.json"), join(cwd, ".mcp.json"), join(home, ".cursor", "mcp.json"), desktop, vscode];
}

function serverMaps(doc) {
  const out = [];
  if (!doc || typeof doc !== "object") return out;
  for (const k of ["mcpServers", "servers"]) if (doc[k] && typeof doc[k] === "object") out.push(doc[k]);
  if (doc.projects && typeof doc.projects === "object") for (const p of Object.values(doc.projects)) if (p && p.mcpServers && typeof p.mcpServers === "object") out.push(p.mcpServers);
  return out;
}

function viaGateway(entry) {
  let u;
  try { u = new URL(entry.url); } catch { return false; }
  if (!LOOPBACK.has(u.hostname)) return false;
  const headers = entry.headers && typeof entry.headers === "object" ? Object.keys(entry.headers).map((h) => h.toLowerCase()) : [];
  return headers.includes(GATEWAY_TOKEN_HEADER) || Number(u.port) === GATEWAY_DEFAULT_PORT;
}

// → {hooks: [hostId], plugin, servers, proxied, gateway}
export function detectCheckpoint({ home = homedir(), cwd = process.cwd(), platform = process.platform, env = process.env } = {}) {
  const hooks = [];
  let plugin = false;
  for (const h of hostTable(home, env)) {
    const { data } = readJson(h.file, { comments: h.comments });
    if (!data) continue;
    if (Object.keys(ourSurface(data, h.ours)).length) hooks.push(h.id);
    if (h.id === "claude-code" && data.enabledPlugins && Object.entries(data.enabledPlugins).some(([id, on]) => on === true && id.startsWith("moorai@"))) plugin = true;
  }
  let servers = 0, proxied = 0, gateway = 0;
  const seen = new Set();
  for (const file of clientConfigs(home, cwd, platform)) {
    if (seen.has(file)) continue;
    seen.add(file);
    const { data } = readJson(file, { comments: true });
    for (const map of serverMaps(data)) {
      for (const entry of Object.values(map)) {
        if (!entry || typeof entry !== "object") continue;
        servers++;
        const argv = [entry.command, ...(Array.isArray(entry.args) ? entry.args : [])].filter((x) => typeof x === "string");
        if (argv.some((a) => GUARD.test(a))) proxied++;
        else if (typeof entry.url === "string" && viaGateway(entry)) gateway++;
      }
    }
  }
  return { hooks, plugin, servers, proxied, gateway };
}
