#!/usr/bin/env node
// moorai-mcp-gateway — the MoorAI MCP guard for REMOTE MCP servers (Streamable HTTP). An MCP client is
// pointed at http://127.0.0.1:<port>/<route> instead of the remote URL; every tools/call gets the stdio
// proxy's checks before it leaves, and every result gets the proxy's result scan before the client
// reads it. See mcp-gateway/README.md.
import { parseConfig, displayUrl, USAGE } from "./config.mjs";

let cfg;
try { cfg = parseConfig(process.argv.slice(2)); }
catch (e) { process.stderr.write(`moorai-mcp-gateway: ${e.message}\n${USAGE}\n`); process.exit(2); }
if (cfg.help) { process.stdout.write(USAGE + "\n"); process.exit(0); }

// Imported after the config is valid: these load the device config and policy state.
const { createGatewayServer } = await import("./server.mjs");
const { ensurePolicy } = await import("./policy.mjs");
const { startUsageFlush } = await import("./usage.mjs");

const server = createGatewayServer(cfg);
server.on("error", (e) => { process.stderr.write(`moorai-mcp-gateway: ${e.code || e.message}\n`); process.exit(1); });
server.listen(cfg.port, cfg.host, () => {
  const a = server.address();
  const host = a.family === "IPv6" || a.family === 6 ? `[${a.address}]` : a.address;
  const base = `http://${host}:${a.port}`;
  process.stderr.write(`moorai-mcp-gateway: listening on ${base}\n`);
  for (const r of cfg.routes) {
    process.stderr.write(`moorai-mcp-gateway:   ${base}${r.path} -> ${displayUrl(r.url)} (server "${r.server}"${r.localFiles ? ", local file arguments scanned" : ""})\n`);
  }
  // Placeholder names, routes and headers only: never a secret, its source or its length.
  if (cfg.credentials) {
    for (const b of cfg.credentials.bindings.values()) process.stderr.write(`moorai-mcp-gateway:   credential placeholder ${b.name} -> ${b.prefix} header ${b.header}\n`);
    if (cfg.requirePlaceholders) process.stderr.write("moorai-mcp-gateway:   raw credentials are refused (--require-placeholders)\n");
  }
});
// Warm the policy so the first call is not delayed by the fetch; each route's first-sight reputation
// (keyed on the remote URL, offline unless the policy opts in) rides on the same promise.
ensurePolicy().catch(() => {});
for (const g of server.guards) g.startReputation();
// C4: completed days of per-server / per-tool usage go to the console, once each, off the request path.
startUsageFlush();

const stop = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 2000).unref(); };
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
