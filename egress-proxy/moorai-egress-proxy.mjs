#!/usr/bin/env node
// moorai-egress-proxy — a forward proxy (HTTP_PROXY / HTTPS_PROXY) that enforces MoorAI's egressRules and
// egressDefault on the connections a workload actually opens. On its own it is a guard for clients that
// honour the proxy variables; with a network policy that makes it the workload's only way out (deploy/),
// it is the boundary. See server.mjs for the order of checks and README.md "Egress proxy".
import { parseConfig, USAGE } from "./config.mjs";

let cfg;
try { cfg = parseConfig(process.argv.slice(2)); }
catch (e) { process.stderr.write(`moorai-egress-proxy: ${e.message}\n${USAGE}\n`); process.exit(2); }
if (cfg.help) { process.stdout.write(USAGE + "\n"); process.exit(0); }

// Imported after the config is valid: these load the device config and policy state.
const { createEgressProxy } = await import("./server.mjs");
const { getState } = await import("./policy.mjs");
const { post } = await import("./report.mjs");

const server = createEgressProxy(cfg, { getState, report: post });
server.on("error", (e) => { process.stderr.write(`moorai-egress-proxy: ${e.code || e.message}\n`); process.exit(1); });
server.listen(cfg.port, cfg.host, () => {
  const a = server.address();
  const host = a.family === "IPv6" || a.family === 6 ? `[${a.address}]` : a.address;
  process.stderr.write(`moorai-egress-proxy: listening on http://${host}:${a.port}${cfg.token ? " (Proxy-Authorization required)" : ""}\n`);
});
getState().catch(() => {});

const stop = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 2000).unref(); };
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
