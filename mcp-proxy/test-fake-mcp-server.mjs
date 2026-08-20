#!/usr/bin/env node
// Tiny fake MCP server for tests. Speaks newline-delimited JSON-RPC 2.0 over stdio: answers `initialize`
// and `tools/list`, and ECHOES `tools/call` arguments back. Every tools/call it actually receives is
// appended to the log file given as argv[2] — the test asserts a BLOCKED call never appears there.
import { appendFileSync } from "node:fs";
const LOG = process.argv[2];
function send(o) { process.stdout.write(JSON.stringify(o) + "\n"); }
let buf = "";
process.stdin.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "fake-server", version: "0.0.1" } } });
    else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo", description: "echo", inputSchema: { type: "object" } }] } });
    else if (m.method === "tools/call") {
      if (LOG) { try { appendFileSync(LOG, JSON.stringify(m.params) + "\n"); } catch {} }
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ from: "fake-server", echoed: m.params.arguments }) }], isError: false } });
    } else if (m.id != null) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.stdin.on("end", () => process.exit(0));
