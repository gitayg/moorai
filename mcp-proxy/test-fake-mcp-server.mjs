#!/usr/bin/env node
// Tiny fake MCP server for tests. Speaks newline-delimited JSON-RPC 2.0 over stdio: answers `initialize`
// and `tools/list`, and ECHOES `tools/call` arguments back. Every tools/call it actually receives is
// appended to the log file given as argv[2] — the test asserts a BLOCKED call never appears there.
//
// Two additive env hooks let a test drive the tool STAGE without changing any of the above:
//   FAKE_TOOLS_FILE   a JSON file holding either one tools[] array, or an array of tools[] arrays —
//                     successive tools/list calls get successive entries (the last one repeats). This
//                     is how a BEFORE/AFTER pair (capability expansion, rug-pull) is played.
//   FAKE_RAW_LIST     a file holding the EXACT bytes to emit for a tools/list response, newline
//                     appended by us. Used to assert the proxy forwards a response byte-identically,
//                     including whitespace and key order that JSON.stringify would normalise away.
import { appendFileSync, readFileSync } from "node:fs";
const LOG = process.argv[2];
function send(o) { process.stdout.write(JSON.stringify(o) + "\n"); }

const RAW_LIST = process.env.FAKE_RAW_LIST ? readFileSync(process.env.FAKE_RAW_LIST, "utf8").replace(/\n$/, "") : null;
let listBatches = null;
if (process.env.FAKE_TOOLS_FILE) {
  const j = JSON.parse(readFileSync(process.env.FAKE_TOOLS_FILE, "utf8"));
  listBatches = Array.isArray(j) && Array.isArray(j[0]) ? j : [j];
}
let listCall = 0;
function toolsForThisCall() {
  const batch = listBatches[Math.min(listCall, listBatches.length - 1)];
  listCall++;
  return batch;
}

let buf = "";
process.stdin.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "fake-server", version: "0.0.1" } } });
    else if (m.method === "tools/list") {
      if (RAW_LIST) process.stdout.write(RAW_LIST.replace("__ID__", String(m.id)) + "\n");
      else if (listBatches) send({ jsonrpc: "2.0", id: m.id, result: { tools: toolsForThisCall() } });
      else send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo", description: "echo", inputSchema: { type: "object" } }] } });
    }
    else if (m.method === "tools/call") {
      if (LOG) { try { appendFileSync(LOG, JSON.stringify(m.params) + "\n"); } catch {} }
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ from: "fake-server", echoed: m.params.arguments }) }], isError: false } });
    } else if (m.id != null) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.stdin.on("end", () => process.exit(0));
