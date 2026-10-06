#!/usr/bin/env node
// The official MCP TypeScript SDK as a client, for the live-client matrix:
//   node sdk-client.mjs '<json spec>'
// spec: { "entry": { "command", "args", "env" } | { "type": "http", "url" },
//         "calls": [ { "name": "echo", "arguments": { ... } }, ... ] }
// Connects (initialize + notifications/initialized), lists tools, makes each call in order, and prints
// one JSON object: { ok, serverVersion, protocolVersion, tools, calls: [ { name, isError, text } ], error }.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { readFileSync } from "node:fs";

const spec = JSON.parse(process.argv[2]);
const sdkVersion = JSON.parse(readFileSync(new URL("../../../package.json", import.meta.resolve("@modelcontextprotocol/sdk/client/index.js")), "utf8")).version;
const out = { ok: false, sdkVersion, tools: null, calls: [] };
const e = spec.entry;
const transport = e.type === "http"
  ? new StreamableHTTPClientTransport(new URL(e.url))
  : new StdioClientTransport({ command: e.command, args: e.args || [], env: e.env, stderr: "ignore" });
const client = new Client({ name: "moorai-live-sdk-client", version: sdkVersion });
try {
  await client.connect(transport);
  out.serverVersion = client.getServerVersion();
  out.protocolVersion = transport.protocolVersion || null;
  out.tools = (await client.listTools()).tools.map((t) => t.name);
  for (const c of spec.calls || []) {
    const r = await client.callTool({ name: c.name, arguments: c.arguments || {} });
    out.calls.push({ name: c.name, isError: !!r.isError, text: (r.content || []).map((x) => x.text || "").join("") });
  }
  out.ok = true;
} catch (err) {
  out.error = String(err && err.message || err);
} finally {
  try { await client.close(); } catch { /* closing */ }
}
process.stdout.write(JSON.stringify(out) + "\n");
process.exit(0);
