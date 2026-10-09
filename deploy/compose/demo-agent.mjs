// The agent side of deploy/compose: what a workload on the internal network can and cannot reach. Each line
// prints the outcome; the run exits non-zero if any expectation fails. With NODE_USE_ENV_PROXY=1 (set in the
// compose file) Node's http module and fetch both honour HTTP_PROXY / NO_PROXY, differently: http sends a
// plain-HTTP request to the proxy in absolute form (host, port, method and path judged), fetch opens a
// CONNECT tunnel even for http:// (host and port only; measured on Node 22.22).
import net from "node:net";
import http from "node:http";

const results = [];
const expect = (name, ok, detail) => { results.push(ok); console.log(`${ok ? "PASS" : "FAIL"}  ${name}: ${detail}`); };
const viaHttp = (url, method = "GET") => new Promise((resolve) => {
  const req = http.request(url, { method, timeout: 8000 }, (res) => { res.resume(); resolve(String(res.statusCode)); });
  req.on("timeout", () => req.destroy(new Error("timeout")));
  req.on("error", (e) => resolve(`error ${e.code || e.message}`));
  req.end(method === "POST" ? "x" : undefined);
});
const status = async (url, init) => { try { const r = await fetch(url, { ...init, signal: AbortSignal.timeout(8000) }); return String(r.status); } catch (e) { return `error ${(e.cause && (e.cause.code || e.cause.message)) || e.message}`; } };
const tcp = (host, port) => new Promise((resolve) => {
  const s = net.connect({ host, port, timeout: 4000 });
  s.on("connect", () => { s.destroy(); resolve("connected"); });
  s.on("timeout", () => { s.destroy(); resolve("timeout"); });
  s.on("error", (e) => resolve(`error ${e.code}`));
});

// Through the proxy (node:http reads HTTP_PROXY): judged by the egress rules in moorai-system.json.
const allowed = await viaHttp("http://internet:8080/public/readme");
expect("allowed by rule demo-site (GET /public/*)", allowed === "200", allowed);
const wrongPath = await viaHttp("http://internet:8080/private/keys");
expect("path outside the rule falls to egressDefault block", wrongPath === "403", wrongPath);
const wrongMethod = await viaHttp("http://internet:8080/public/upload", "POST");
expect("POST is not in the rule's methods", wrongMethod === "403", wrongMethod);
const literal = await viaHttp("http://1.1.1.1/");
expect("an IP literal needs a rule that names it", literal === "403", literal);
// fetch tunnels http:// through CONNECT: method and path are unknown there, so demo-site (which sets them)
// cannot match and egressDefault refuses the tunnel. Fail closed, not open.
const tunnelled = await status("http://internet:8080/public/readme");
expect("fetch's CONNECT tunnel cannot satisfy a method/path rule", tunnelled !== "200", tunnelled);

// Around the proxy: a raw socket ignores HTTP_PROXY. The internal network has no route out, so it fails.
const directInternet = await tcp("internet", 8080);
expect("raw TCP to the 'internet' service, bypassing the proxy", directInternet !== "connected", directInternet);
const directPublic = await tcp("1.1.1.1", 443);
expect("raw TCP to a public address, bypassing the proxy", directPublic !== "connected", directPublic);

// The proxy itself without its token.
const noToken = await new Promise((resolve) => {
  const s = net.connect({ host: "egress-proxy", port: 8850 }, () => s.write("GET http://internet:8080/public/readme HTTP/1.1\r\nHost: internet:8080\r\n\r\n"));
  let d = ""; s.on("data", (c) => (d += c)); s.on("end", () => resolve(d.split("\r\n")[0])); s.on("error", (e) => resolve(`error ${e.code}`));
});
expect("the proxy refuses a request without Proxy-Authorization", /^HTTP\/1\.1 407/.test(noToken), noToken);

process.exit(results.every(Boolean) ? 0 : 1);
