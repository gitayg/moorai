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
//
// Two more for the RESULT stage — a tool result is content the agent ingests, and the echo behaviour
// above can only ever return what the caller already sent, so it could not model the class of attack
// where a server returns something the ARGUMENTS never mentioned (a credential file's contents, an
// injected directive). These are the "hostile / realistic child server" hooks:
//   FAKE_RESULT_FILE  a file whose contents are returned as the tools/call result text, VERBATIM and
//                     regardless of the arguments. This is what `read_file('/x/.env')` or
//                     `cat /x/.env` actually returns, and what the echo server structurally cannot.
//   FAKE_RAW_CALL     a file holding the EXACT bytes to emit for a tools/call response (`__ID__` is
//                     substituted). The tools/call analogue of FAKE_RAW_LIST, for byte-identity.
//
// And one for FRAMING specifically:
//   FAKE_SPLIT_BYTES  emit every tools/call response in slices of this many bytes, one per macrotask,
//                     so ONE JSON-RPC message provably arrives at the proxy across MANY stdout chunks
//                     — including a slice boundary that falls mid-key and mid-multi-byte-character.
//                     Relying on "a big payload will probably be chunked" tests the OS pipe, not the
//                     proxy's reassembly; this makes it deterministic.
import { appendFileSync, readFileSync } from "node:fs";
const LOG = process.argv[2];
const SPLIT = Number(process.env.FAKE_SPLIT_BYTES || 0);

// Slicing is done on BYTES, not characters, precisely so a multi-byte character can straddle a slice.
function emit(text) {
  const buf = Buffer.from(text, "utf8");
  if (!SPLIT || buf.length <= SPLIT) { process.stdout.write(buf); return; }
  let i = 0;
  const step = () => {
    if (i >= buf.length) return;
    process.stdout.write(buf.subarray(i, Math.min(i + SPLIT, buf.length)));
    i += SPLIT;
    setTimeout(step, 1);
  };
  step();
}
function send(o) { emit(JSON.stringify(o) + "\n"); }

const RAW_LIST = process.env.FAKE_RAW_LIST ? readFileSync(process.env.FAKE_RAW_LIST, "utf8").replace(/\n$/, "") : null;
const RAW_CALL = process.env.FAKE_RAW_CALL ? readFileSync(process.env.FAKE_RAW_CALL, "utf8").replace(/\n$/, "") : null;
const RESULT_TEXT = process.env.FAKE_RESULT_FILE ? readFileSync(process.env.FAKE_RESULT_FILE, "utf8") : null;
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
      if (RAW_CALL) emit(RAW_CALL.replace("__ID__", String(m.id)) + "\n");
      else if (RESULT_TEXT != null) send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: RESULT_TEXT }], isError: false } });
      else send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ from: "fake-server", echoed: m.params.arguments }) }], isError: false } });
    } else if (m.id != null) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.stdin.on("end", () => process.exit(0));
