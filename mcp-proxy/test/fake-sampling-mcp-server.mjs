#!/usr/bin/env node
// A fake stdio MCP server that asks the CLIENT for something, for test/mcp-sampling-scan.test.mjs.
// Newline-delimited JSON-RPC 2.0. Answers initialize; on tools/call it either
//   (default)       sends its own request first — { id: "srv-1", method: FAKE_SR_METHOD, params } — and
//                   then answers the tools/call with a plain text result (the 2025-11-25 shape), or
//   FAKE_SR_MRTR=1  answers the tools/call with an InputRequiredResult carrying that request in
//                   result.inputRequests (the 2026-07-28 shape).
// FAKE_SR_PARAMS is a file holding the request's params as JSON; FAKE_SR_METHOD defaults to
// sampling/createMessage. FAKE_SR_INPUTS is a file holding a whole result.inputRequests map (FAKE_SR_MRTR only),
// used in place of the one request. Every line it receives with an id that is not a request (the client's answer
// to "srv-1") is appended to the log file given as argv[2].
import { appendFileSync, readFileSync } from "node:fs";
const LOG = process.argv[2];
const METHOD = process.env.FAKE_SR_METHOD || "sampling/createMessage";
const PARAMS = process.env.FAKE_SR_PARAMS ? JSON.parse(readFileSync(process.env.FAKE_SR_PARAMS, "utf8")) : {};
const INPUTS = process.env.FAKE_SR_INPUTS ? JSON.parse(readFileSync(process.env.FAKE_SR_INPUTS, "utf8")) : null;
const send = (o) => process.stdout.write(JSON.stringify(o) + "\n");

let buf = "";
process.stdin.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.method == null && m.id != null) { if (LOG) appendFileSync(LOG, JSON.stringify(m) + "\n"); continue; }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "fake-sampling", version: "0.0.1" } } });
    else if (m.method === "tools/call") {
      if (process.env.FAKE_SR_MRTR) send({ jsonrpc: "2.0", id: m.id, result: { resultType: "input_required", inputRequests: INPUTS || { ask: { method: METHOD, params: PARAMS } }, requestState: "opaque-state" } });
      else {
        send({ jsonrpc: "2.0", id: "srv-1", method: METHOD, params: PARAMS });
        send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "done" }], isError: false } });
      }
    } else if (m.id != null) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.stdin.on("end", () => process.exit(0));
