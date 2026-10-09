// Shared harness for test/egress-proxy*.test.mjs: an in-process proxy with an injected policy, resolver and
// connector, a fake upstream HTTP server and a TCP echo server on loopback. The "public" addresses the
// resolver hands out are mapped by the fake connector to those loopback servers, so no test touches the
// real network, and every address the proxy asks to connect to is recorded.
import http from "node:http";
import net from "node:net";
import { createEgressProxy } from "../server.mjs";

export async function startUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const out = `ok ${req.method} ${req.url}`;
      res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": Buffer.byteLength(out), "X-Upstream": "1" });
      res.end(out);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { port: server.address().port, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

export async function startEcho() {
  const sockets = new Set();
  const server = net.createServer((s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); s.on("error", () => {}); s.pipe(s); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { port: server.address().port, close: () => new Promise((r) => { for (const s of sockets) s.destroy(); server.close(r); }) };
}

// A resolver from a table host → [addresses] (or a function per call), counting calls per host.
export function fakeResolver(table) {
  const calls = [];
  const fn = async (host) => {
    calls.push(host);
    const n = calls.filter((h) => h === host).length;
    const v = typeof table[host] === "function" ? table[host](n) : table[host];
    if (!v) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    return v.map((address) => ({ address, family: net.isIP(address) }));
  };
  fn.calls = calls;
  return fn;
}

// A connector that sends every address to the loopback server for its port (443 / 8443 → echo, anything
// else → the HTTP upstream) and records what it was asked for.
export function fakeConnect({ httpPort, echoPort }) {
  const calls = [];
  const fn = (opts) => {
    calls.push({ host: opts.host, port: opts.port });
    const port = opts.port === 443 || opts.port === 8443 ? echoPort : httpPort;
    return net.connect({ host: "127.0.0.1", port });
  };
  fn.calls = calls;
  return fn;
}

export async function startProxy(cfg, deps) {
  const reports = [];
  const server = createEgressProxy({ host: "127.0.0.1", port: 0, ...cfg }, { report: (a) => reports.push(a), ...deps });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { port: server.address().port, reports, server, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

export const stateOf = (policy, extra = {}) => async () => ({ policy, system: null, serviceId: "", coach: false, ...extra });

// One plain-HTTP request through the proxy in absolute form → { status, headers, body }.
export function viaProxy(proxyPort, url, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: proxyPort, method, path: url, headers, agent: false });
    req.on("response", (res) => { let b = ""; res.setEncoding("utf8"); res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: b })); });
    req.on("error", reject);
    req.end(body);
  });
}

// CONNECT through the proxy → { status, socket } (socket only on 200; the caller closes it).
export function connectVia(proxyPort, authority, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: proxyPort, method: "CONNECT", path: authority, headers, agent: false });
    // Node emits "connect" for every answer to a CONNECT; a refusal's body follows on the socket.
    req.on("connect", (res, socket, head) => {
      if (res.statusCode === 200) return resolve({ status: 200, socket });
      let b = head ? head.toString("utf8") : "";
      socket.setEncoding("utf8");
      socket.on("data", (c) => (b += c));
      socket.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
      socket.on("error", () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on("response", (res) => { let b = ""; res.setEncoding("utf8"); res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode, body: b })); });
    req.on("error", reject);
    req.end();
  });
}

export function echoOnce(socket, text) {
  return new Promise((resolve, reject) => {
    let got = "";
    socket.setEncoding("utf8");
    socket.on("data", (c) => { got += c; if (got.length >= text.length) resolve(got); });
    socket.on("error", reject);
    socket.write(text);
  });
}
