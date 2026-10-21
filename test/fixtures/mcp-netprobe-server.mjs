#!/usr/bin/env node
// TEST-ONLY stdio MCP server for test/mcp-server-sandbox-guard.test.mjs. One tool, `probe`, opens a TCP
// connection to arguments.host:arguments.port (default 192.0.2.1:443, TEST-NET-1: documentation space,
// never routed on the internet) and answers with what happened: "connect:ok", "connect:timeout" (no
// answer within arguments.timeoutMs, default 1500) or "connect:<errno code>" (EPERM when the kernel
// sandbox refuses it). `lookup` resolves arguments.name with dns.lookup and answers "lookup:<family>" or
// "lookup:<errno code>". `exec` runs arguments.cmd with arguments.args and answers "exec:<exit status>" or
// "exec:<errno code>" (EPERM when the sandbox refuses the exec). It writes nothing anywhere.
import net from "node:net";
import dns from "node:dns";
import { spawnSync } from "node:child_process";

const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");
function probe({ host = "192.0.2.1", port = 443, timeoutMs = 1500 } = {}) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    const done = (r) => { clearTimeout(t); s.destroy(); resolve(r); };
    const t = setTimeout(() => done("connect:timeout"), timeoutMs);
    s.on("connect", () => done("connect:ok"));
    s.on("error", (e) => done(`connect:${e.code || "error"}`));
  });
}

function lookup({ name = "localhost" } = {}) {
  return new Promise((resolve) => dns.lookup(name, (e, _a, family) => resolve(e ? `lookup:${e.code || "error"}` : `lookup:${family}`)));
}
async function exec({ cmd, args = [] } = {}) {
  const r = spawnSync(cmd, args, { stdio: "ignore", timeout: 5000 });
  return r.error ? `exec:${r.error.code || "error"}` : `exec:${r.status}`;
}
const TOOLS = { probe, lookup, exec };

let buf = "";
process.stdin.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "netprobe", version: "0.0.1" } } });
    else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: Object.keys(TOOLS).map((name) => ({ name, description: `netprobe ${name}`, inputSchema: { type: "object" } })) } });
    else if (m.method === "tools/call") Promise.resolve((TOOLS[m.params && m.params.name] || probe)(m.params && m.params.arguments)).then((text) => send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text }], isError: false } }));
    else if (m.id != null) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.stdin.on("end", () => process.exit(0));
