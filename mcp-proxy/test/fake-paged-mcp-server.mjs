#!/usr/bin/env node
// A fake MCP server that PAGES its tool list, for the tool-drift tests (test/mcp-tool-drift-paged.test.mjs).
// Newline-delimited JSON-RPC 2.0 over stdio, like test-fake-mcp-server.mjs:
//
//   FAKE_PAGES_FILE  a JSON file holding an array of pages, each a tools[] array. It is RE-READ on every
//                    tools/list, so a test can change a description between two listings of one session.
//                    tools/list with no cursor → page 0; with cursor "p<N>" → page N. Every page but the
//                    last carries nextCursor "p<N+1>". An unknown cursor is a JSON-RPC error (-32602).
//   argv[2]          a log file: every tools/call received is appended (a refused call never appears).
//
//                    The file may instead hold { pages, escapeResultKey: true }: the tools/list response
//                    then spells its "result" key as "result" — the same JSON value to any parser,
//                    different bytes on the wire.
//
// tools/call echoes its arguments back.
//
// Two more for the block-mode re-list before a call (test/mcp-tool-drift-recheck.test.mjs):
//   FAKE_REQ_LOG      a log file: every request received is appended as { method, id, cursor }, so a test
//                     can count the tools/list requests the guard sent itself and see their ids.
//   FAKE_CONTROL_FILE a JSON file RE-READ on every request:
//                     { listDelayMs }        answer every tools/list after this many ms;
//                     { listError: true }    answer every tools/list with a JSON-RPC error;
//                     { notifyOnPing: true } answer a `ping` with notifications/tools/list_changed first.
import { appendFileSync, readFileSync } from "node:fs";

const LOG = process.argv[2];
const control = () => { try { return JSON.parse(readFileSync(process.env.FAKE_CONTROL_FILE, "utf8")) || {}; } catch { return {}; } };
let escapeResultKey = false;
const pages = () => {
  const j = JSON.parse(readFileSync(process.env.FAKE_PAGES_FILE, "utf8"));
  escapeResultKey = !Array.isArray(j) && j.escapeResultKey === true;
  return Array.isArray(j) ? j : j.pages;
};
const send = (o) => {
  let s = JSON.stringify(o);
  if (escapeResultKey && o.result && Array.isArray(o.result.tools)) s = s.replace('"result":', '"\\u0072esult":');
  process.stdout.write(s + "\n");
};

function answerList(all, id, cursor) {
  const n = cursor == null ? 0 : /^p(\d+)$/.test(String(cursor)) ? Number(String(cursor).slice(1)) : -1;
  if (n < 0 || n >= all.length) { escapeResultKey = false; send({ jsonrpc: "2.0", id, error: { code: -32602, message: "unknown cursor" } }); return; }
  send({ jsonrpc: "2.0", id, result: { tools: all[n], ...(n + 1 < all.length ? { nextCursor: `p${n + 1}` } : {}) } });
}

let buf = "";
process.stdin.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (process.env.FAKE_REQ_LOG && m.method) { try { appendFileSync(process.env.FAKE_REQ_LOG, JSON.stringify({ method: m.method, id: m.id, cursor: m.params && m.params.cursor }) + "\n"); } catch { /* log only */ } }
    const ctl = process.env.FAKE_CONTROL_FILE ? control() : {};
    if (m.method === "ping" && ctl.notifyOnPing) send({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
    if (m.method === "tools/list" && ctl.listError) { send({ jsonrpc: "2.0", id: m.id, error: { code: -32603, message: "listing failed" } }); continue; }
    if (m.method === "tools/list" && ctl.listDelayMs > 0) { const all = pages(), ids = m.id, cursor = m.params && m.params.cursor; setTimeout(() => answerList(all, ids, cursor), ctl.listDelayMs); continue; }
    if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "fake-paged-server", version: "0.0.1" } } });
    else if (m.method === "tools/list") answerList(pages(), m.id, m.params && m.params.cursor);
    else if (m.method === "tools/call") {
      escapeResultKey = false;
      if (LOG) { try { appendFileSync(LOG, JSON.stringify(m.params) + "\n"); } catch { /* log only */ } }
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ from: "fake-paged-server", echoed: m.params.arguments }) }], isError: false } });
    } else if (m.id != null) send({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});
process.stdin.on("end", () => process.exit(0));
