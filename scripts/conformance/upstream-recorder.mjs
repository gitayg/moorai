// A loopback relay between MoorAI's model proxy and the real model server, for the AI Servers live
// conformance tier. It forwards each request and response byte for byte (method, path, headers less
// hop-by-hop ones, body) and records per request only three facts: whether a marker string was in the
// request body (did a refused request reach the model?), whether the model server's answer carried a tool
// call (so a "withhold" case knows the model really produced one), and the upstream HTTP status.
// Bodies are inspected in memory and dropped; nothing of them is kept.
import http from "node:http";

const HOP = new Set(["host", "connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection", "content-length"]);
const MAX_INSPECT = 4 * 1024 * 1024;

// A tool call in any shape the tier exercises: OpenAI Chat / Ollama `tool_calls: [{…}]` (JSON, SSE delta or
// NDJSON line), Anthropic `"type": "tool_use"` blocks, Responses `"type": "function_call"` items.
export function toolCallIn(text) {
  const s = String(text || "");
  return /"tool_calls"\s*:\s*\[\s*\{/.test(s) || /"type"\s*:\s*"tool_use"/.test(s) || /"type"\s*:\s*"function_call"/.test(s);
}

export async function startUpstreamRecorder({ upstream, marker = null } = {}) {
  const base = new URL(upstream);
  const log = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const entry = { markerSeen: !!marker && body.includes(marker), toolCallSeen: false, status: null };
      log.push(entry);
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k.toLowerCase())) headers[k] = v;
      if (body.length) headers["content-length"] = body.length;
      const out = http.request({ host: base.hostname, port: base.port || 80, method: req.method, path: base.pathname.replace(/\/$/, "") + req.url, headers }, (up) => {
        entry.status = up.statusCode;
        const h = {};
        for (const [k, v] of Object.entries(up.headers)) if (!HOP.has(k.toLowerCase())) h[k] = v;
        res.writeHead(up.statusCode, h);
        let seen = 0, tail = "";
        up.on("data", (c) => {
          res.write(c);
          if (seen < MAX_INSPECT) { seen += c.length; tail += c.toString("utf8"); if (toolCallIn(tail)) entry.toolCallSeen = true; if (tail.length > 65536) tail = tail.slice(-1024); }
        });
        up.on("end", () => res.end());
        up.on("error", () => res.destroy());
      });
      out.on("error", () => { entry.status = 502; if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" }); res.end('{"error":"upstream unreachable"}'); });
      out.end(body);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`, log,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); })
  };
}
