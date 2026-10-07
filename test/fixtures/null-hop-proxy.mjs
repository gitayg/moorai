// A pass-through HTTP hop that does nothing else: the latency baseline for test/model-proxy.test.mjs.
//
//   node test/fixtures/null-hop-proxy.mjs <upstream-base-url>
//
// It does the same I/O shape as the real proxy on a report-mode, non-streaming call — its own process,
// buffer the whole request body, one keep-alive request upstream, pipe the response back — and none of the
// work (no parsing, no scan, no policy, no log). Its first stdout line is {"listening":"http://..."}.
import http from "node:http";

const upstream = new URL(process.argv[2]);
const agent = new http.Agent({ keepAlive: true });
const HOP = new Set(["connection", "keep-alive", "transfer-encoding", "host"]);

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    headers["content-length"] = body.length;
    const up = http.request({ host: upstream.hostname, port: upstream.port, path: req.url, method: req.method, headers, agent }, (ur) => {
      const h = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k)) h[k] = v;
      res.writeHead(ur.statusCode, h);
      ur.pipe(res);
    });
    up.on("error", () => { res.writeHead(502); res.end(); });
    up.end(body);
  });
});
server.listen(0, "127.0.0.1", () => process.stdout.write(JSON.stringify({ listening: `http://127.0.0.1:${server.address().port}` }) + "\n"));
process.on("SIGTERM", () => { agent.destroy(); server.close(() => process.exit(0)); server.closeAllConnections?.(); });
