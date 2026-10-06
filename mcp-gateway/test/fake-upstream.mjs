// A fake REMOTE MCP server speaking Streamable HTTP, for test/mcp-gateway.test.mjs. In-process, so the
// test can read exactly what reached the "remote" side: every request's method, headers and body.
//
//   startUpstream({ mode: "json" | "sse", tools, rawList, resultText, sessionId, splitBytes })
//
// POST initialize      → JSON result, and an Mcp-Session-Id response header (2025-03-26..2025-11-25 era)
// POST <notification>  → 202, no body
// POST tools/list      → { tools } (or `rawList` verbatim, __ID__ substituted, for byte-identity)
// POST tools/call      → `resultText` if set, else an echo of the arguments; in "sse" mode a progress
//                        notification event first, then the response event, then the stream closes.
//                        `splitBytes` writes the SSE body in slices of that size, one per tick, so one
//                        event provably crosses many chunks.
// `callReply(msg)`      → the raw JSON text of the tools/call response (JSON mode) or of its SSE data line,
//                        for malformed / oversized / 2026-era results; `listReply(msg)` the same for
//                        tools/list. `chunked` writes a JSON body without a Content-Length.
// GET                  → a standalone SSE stream carrying one server notification, then closes
//                        (the legacy server-initiated stream); `noGet` → 405 as the 2026-07-28 spec says.
// DELETE               → 200 (session terminated)
import http from "node:http";

export async function startUpstream(opts = {}) {
  const received = [];
  const mode = opts.mode || "json";
  const sessionId = opts.sessionId || "sess-abc-123";
  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const rec = { method: req.method, url: req.url, headers: req.headers, body };
      received.push(rec);
      if (req.method === "DELETE") { res.writeHead(200); res.end(); return; }
      if (req.method === "GET") {
        if (opts.noGet) { res.writeHead(405); res.end(); return; }
        res.writeHead(200, { "Content-Type": "text/event-stream", "Mcp-Session-Id": sessionId });
        res.end(`id: g1\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/tools/list_changed" })}\n\n`);
        return;
      }
      let m;
      try { m = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      rec.json = m;
      if (m.id == null) { res.writeHead(202); res.end(); return; }
      let result;
      if (m.method === "initialize") {
        res.writeHead(200, { "Content-Type": "application/json", "Mcp-Session-Id": sessionId });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fake-remote", version: "0.0.1" } } }));
        return;
      }
      if (m.method === "tools/list") {
        if (opts.listReply) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(opts.listReply(m));
          return;
        }
        if (opts.rawList) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(opts.rawList.replace("__ID__", String(m.id)));
          return;
        }
        result = { tools: opts.tools || [{ name: "echo", description: "Echo the arguments back.", inputSchema: { type: "object" } }] };
      } else if (m.method === "tools/call") {
        const text = opts.resultText != null ? opts.resultText : JSON.stringify({ echoed: m.params && m.params.arguments });
        result = { content: [{ type: "text", text }], isError: false };
      } else result = {};
      const reply = m.method === "tools/call" && opts.callReply ? opts.callReply(m) : JSON.stringify({ jsonrpc: "2.0", id: m.id, result });
      if (mode === "sse" && m.method === "tools/call") {
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no" });
        const progress = JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: "p1", progress: 1, total: 2 } });
        const out = Buffer.from(`id: e1\nevent: message\ndata: ${progress}\n\nid: e2\nevent: message\ndata: ${reply}\n\n`, "utf8");
        const n = Number(opts.splitBytes || 0);
        if (!n) { res.end(out); return; }
        let i = 0;
        const step = () => {
          if (i >= out.length) { res.end(); return; }
          res.write(out.subarray(i, i + n));
          i += n;
          setTimeout(step, 1);
        };
        step();
        return;
      }
      if (opts.chunked) { res.writeHead(200, { "Content-Type": "application/json", "Transfer-Encoding": "chunked" }); res.write(reply.slice(0, 10)); res.end(reply.slice(10)); return; }
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(reply) });
      res.end(reply);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/mcp`;
  return {
    url, received,
    calls: () => received.filter((r) => r.json && r.json.method === "tools/call"),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); })
  };
}
