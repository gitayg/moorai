// The forward proxy itself: plain-HTTP requests in absolute form (`GET http://host/path`) and CONNECT
// tunnels (`CONNECT host:443`), each judged by judge.mjs before a byte goes upstream.
//
// One connection, in order:
//   1. Proxy-Authorization when a token is configured (Basic with the token as the password, or Bearer).
//   2. The destination is parsed and its host normalised (address.mjs). A host a rule could not name, a
//      URL the two parsers of cli/egress-rules.mjs read differently, or https:// in absolute form (that is
//      CONNECT's job) is refused 400. The path is canonicalised (path.mjs); an encoded separator, NUL or
//      percent sign, a malformed escape or a backslash is refused 400.
//   3. The egress rules decide (judge.mjs). A block is refused 403 with the deciding rule, before any DNS
//      lookup. With a cidr rule in force a name is judged per resolved address instead (step 4), unless no
//      cidr allow or alert rule could lift its block (judge.mjs blockHoldsForEveryAddress).
//   4. The address. An IP literal is used as written; a name is resolved ONCE (deps.resolve, a timeout).
//      The proxy's own port and the sibling ports (cfg.siblingPorts: moorai-serve, the model proxy, the
//      MCP gateway) on a loopback or local interface address are never connected to, whatever the rules
//      say. If any address is loopback / private / link-local, the connection needs an allow or alert rule
//      whose host is that exact name or IP literal (not a *.suffix rule, not egressDefault, not the
//      loopback exemption); a cloud metadata address needs a rule naming that IP literal itself. The
//      unspecified address, multicast and reserved space are never connected to. An IP literal needs an
//      exact rule too.
//   5. The upstream TCP connection goes to exactly the address checked in 4 (deps.connect gets the IP,
//      never the name), so a second DNS answer cannot redirect it (DNS rebinding). A plain-HTTP request
//      is sent with Host set to the judged host and the judged, canonical path.
//
// The address checks of step 4 are enforced on an unenrolled device too: they keep the proxy from being a
// way into its own pod's loopback (the other sidecars) or the cloud metadata service. Rule blocks coach
// there, as everywhere else in MoorAI. An error while judging refuses the connection (a network boundary
// fails closed; the hook, which judges command text, fails open).
//
// Content-free alerts (deps.report): the egressAlerts shape of cli/egress-rules.mjs (binary null, host,
// port, method; never a path, a query, a header or a body), at most once a minute per distinct alert.
//
// W3C trace context (cli/trace-context.mjs). A plain-HTTP request that carries a valid traceparent goes
// upstream with its traceparent and tracestate unchanged: the trace continues, and an alert about that request
// carries its traceId, a fresh spanId and parentSpanId = the incoming span. A request without a valid one goes
// upstream with a new random trace (sampled), any tracestate it carried removed, and its alerts carry that
// trace. The proxy adds no moorai tracestate entry: it does not know which agent opened the connection. A
// CONNECT tunnel is opaque TLS, so nothing is added inside it; its alerts carry the CONNECT request's trace
// context when it has one, else a new trace.
import http from "node:http";
import net from "node:net";
import dns from "node:dns";
import os from "node:os";
import { createHash, timingSafeEqual } from "node:crypto";
import { egressReason, egressAlerts, EGRESS_RULE, EGRESS_CATEGORY } from "../cli/egress-rules.mjs";
import { ipOf, addressClass, isMetadataAddress, isLocalAddress } from "./address.mjs";
import { judgeConnection, judgeAddresses, hasCidrRules, blockHoldsForEveryAddress, networkTarget, httpTarget, httpDestination, connectTarget, rejectedAlert } from "./judge.mjs";
import { createHelloSniffer } from "./sni.mjs";
import { DEFAULTS } from "./config.mjs";
import { parseTraceparent, formatTraceparent, newTraceId, newSpanId } from "../cli/trace-context.mjs";

const HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host"]);
const ALERT_EVERY_MS = 60000;
const ALERT_KEYS_MAX = 4096;
const STATUS_TEXT = { 400: "Bad Request", 403: "Forbidden", 407: "Proxy Authentication Required", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout" };

const digest = (s) => createHash("sha256").update(String(s)).digest();

// The trace context of one proxied request: { traceId, spanId, parentSpanId?, incoming? } (incoming: the valid
// traceparent it arrived with). A repeated traceparent header is not valid.
function requestTrace(headers = {}) {
  const raw = headers.traceparent;
  const inc = typeof raw === "string" ? parseTraceparent(raw) : null;
  return inc ? { traceId: inc.traceId, spanId: newSpanId(), parentSpanId: inc.parentSpanId, incoming: raw } : { traceId: newTraceId(), spanId: newSpanId() };
}
const traceOf = (tc) => (tc ? { traceId: tc.traceId, spanId: tc.spanId, ...(tc.parentSpanId ? { parentSpanId: tc.parentSpanId } : {}) } : {});

export function defaultResolve(host) {
  return dns.promises.lookup(host, { all: true, verbatim: true });
}

function interfaceAddresses() {
  return Object.values(os.networkInterfaces()).flat().filter(Boolean).map((i) => i.address);
}

function withTimeout(p, ms, what) {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(Object.assign(new Error(`${what} timed out`), { timeout: true })), ms); })]).finally(() => clearTimeout(t));
}

// cfg: parseConfig's object (limits default to config.mjs DEFAULTS). deps (all optional, for tests and the
// entrypoint): getState() → { policy, system, serviceId, coach }; resolve(host) → [{ address, family }];
// connect({ host, port }) → a net.Socket; report(alert); localAddresses() → this host's interface addresses.
export function createEgressProxy(cfg = {}, deps = {}) {
  const o = { ...DEFAULTS, ...cfg };
  const getState = deps.getState || (async () => ({ policy: null, system: null, serviceId: "", coach: false }));
  const resolve = deps.resolve || defaultResolve;
  const connect = deps.connect || ((opts) => net.connect(opts));
  const report = deps.report || (() => {});
  const localAddresses = deps.localAddresses || interfaceAddresses;
  const siblingPorts = new Set(o.siblingPorts);
  const posted = new Map();
  const rejectedSeen = new WeakSet();

  function alert(a, tc) {
    const now = Date.now();
    const prev = posted.get(a.contentHash);
    if (prev !== undefined && now - prev < ALERT_EVERY_MS) return;
    if (posted.size >= ALERT_KEYS_MAX) posted.clear();
    posted.set(a.contentHash, now);
    try { report({ ...a, tool: "egress-proxy", egressLayer: "network", ...traceOf(tc) }); } catch { /* reporting never touches the connection */ }
  }
  function alertRefusal(kind, t, tc) {
    alert({
      threatId: 0, category: EGRESS_CATEGORY, riskLevel: "Blocked", stage: "egress", decision: "deny", reasonCode: EGRESS_RULE,
      egressRefusal: kind, egressBinary: null, egressHost: t ? t.host.slice(0, 253) : null, egressPort: t ? t.port : null, egressMethod: t ? t.method : null,
      contentHash: `egress-net:${kind}:${t ? `${t.host.slice(0, 253)}:${t.port}` : "-"}`
    }, tc);
  }

  function authOk(req) {
    if (!o.token) return true;
    const h = String(req.headers["proxy-authorization"] || "");
    let given = null;
    const bearer = /^Bearer\s+(\S+)\s*$/i.exec(h);
    const basic = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(h);
    if (bearer) given = bearer[1];
    else if (basic) { const d = Buffer.from(basic[1], "base64").toString("utf8"); const c = d.indexOf(":"); given = c >= 0 ? d.slice(c + 1) : d; }
    return given !== null && timingSafeEqual(digest(given), digest(o.token));
  }

  // → { ok: true, address } | { ok: false, status, message }
  async function admit(t, tc) {
    let st;
    try { st = await getState(); } catch { return { ok: false, status: 503, message: "the egress policy could not be loaded" }; }
    let v = judgeConnection(t, st);
    if (v.rejected && v.rejected.length && st.policy && typeof st.policy === "object" && !rejectedSeen.has(st.policy)) {
      rejectedSeen.add(st.policy);
      const ra = rejectedAlert(v.rejected);
      if (ra) alert(ra, tc);
    }
    if (v.error) { alertRefusal("judge-error", t, tc); return { ok: false, status: 403, message: "the egress rules could not be evaluated" }; }
    const literal = ipOf(t.host);
    // With a cidr rule in force a name's verdict depends on its addresses (F23): it is resolved first and
    // judged per resolved address (judgeAddresses). A blocked name is refused before any DNS when there is
    // no cidr rule, or when no cidr allow or alert rule could lift the block for any address.
    const byAddress = !literal && hasCidrRules(st);
    let verdict = { target: t, action: v.action, ref: v.ref, ...(v.ruleId ? { ruleId: v.ruleId } : {}) };
    const ruleAlerts = () => { for (const a of egressAlerts([verdict], { coach: !!st.coach, profileId: v.profileId })) alert(a, tc); };
    if ((!byAddress || blockHoldsForEveryAddress(v, st)) && v.action === "block" && !st.coach) { ruleAlerts(); return { ok: false, status: 403, message: egressReason(verdict) }; }

    let addrs;
    if (literal) addrs = [{ address: literal, family: net.isIP(literal) }];
    else {
      try { addrs = await withTimeout(Promise.resolve(resolve(t.host)), o.dnsTimeoutMs, "DNS"); }
      catch (e) { return { ok: false, status: e && e.timeout ? 504 : 502, message: `${t.host} could not be resolved` }; }
      if (!Array.isArray(addrs) || !addrs.length || addrs.some((a) => !a || !net.isIP(String(a.address)))) return { ok: false, status: 502, message: `${t.host} could not be resolved` };
    }
    if (byAddress) {
      v = judgeAddresses(t, addrs.map((a) => String(a.address)), st);
      if (v.error) { alertRefusal("judge-error", t, tc); return { ok: false, status: 403, message: "the egress rules could not be evaluated" }; }
      verdict = { target: t, action: v.action, ref: v.ref, ...(v.ruleId ? { ruleId: v.ruleId } : {}) };
      if (v.action === "block" && !st.coach) { ruleAlerts(); return { ok: false, status: 403, message: egressReason(verdict) }; }
    }

    // A block never vouches for an address, also when coaching lets the block itself through. A *.suffix
    // rule never vouches for one either: only a rule naming the exact host or IP literal, or a cidr rule
    // whose range holds the address, does. A cloud metadata address needs a host rule naming the IP literal.
    const named = v.explicit && v.action !== "block";
    const exact = named && v.exactHost;
    const hostExact = named && v.hostExact;
    if (literal && !exact) { alertRefusal("ip-literal", t, tc); return { ok: false, status: 403, message: `egress to an IP literal (${t.host}:${t.port}) needs an egress rule that names it` }; }
    const own = server.address();
    const guarded = siblingPorts.has(t.port) || (own && typeof own === "object" && own.port === t.port);
    const local = guarded ? [...(own && typeof own === "object" ? [own.address] : []), ...localAddresses()] : null;
    for (const a of addrs) {
      const ip = String(a.address);
      const c = addressClass(ip);
      if (c === "never") { alertRefusal("unroutable-address", t, tc); return { ok: false, status: 403, message: `${t.host} resolves to an address the proxy never connects to` }; }
      if (guarded && isLocalAddress(ip, local)) { alertRefusal("proxy-port", t, tc); return { ok: false, status: 403, message: `${t.host}:${t.port} is the egress proxy or a MoorAI service beside it; the proxy never connects there` }; }
      if (c !== "special") continue;
      if (!named) { alertRefusal("private-address", t, tc); return { ok: false, status: 403, message: `${t.host} resolves to a loopback, private or link-local address; egress there needs an egress rule that names it` }; }
      if (isMetadataAddress(ip)) {
        if (!(literal && hostExact)) { alertRefusal("metadata-address", t, tc); return { ok: false, status: 403, message: `${t.host} resolves to a cloud metadata address; egress there needs an egress rule that names that IP literal` }; }
      } else if (!exact) { alertRefusal("wildcard-private-address", t, tc); return { ok: false, status: 403, message: `${t.host} resolves to a loopback, private or link-local address; a *.suffix rule never unlocks one, egress there needs a rule that names the exact host` }; }
    }
    if (v.action !== "allow") ruleAlerts();
    return { ok: true, address: String(addrs[0].address), st };
  }

  // The first client bytes of a CONNECT tunnel (sni.mjs): a TLS ClientHello's server name must be the
  // CONNECT host; on a CONNECT to an IP literal the server name is judged by the egress rules beside that
  // address. A ClientHello with no server name, or a first byte that is not TLS, is judged on the CONNECT
  // line alone. A malformed handshake is refused. → null (forward) | { kind, host } (refuse).
  function judgeHello(hello, t, st, tc) {
    if (hello.error) return { kind: "tls-unparsed", host: t.host };
    if (!hello.tls || hello.sni === null) return null;
    const literal = ipOf(t.host);
    if (!literal) return hello.sni === t.host ? null : { kind: "sni-mismatch", host: hello.sni };
    if (net.isIP(hello.sni)) return hello.sni === literal ? null : { kind: "sni-mismatch", host: hello.sni };

    const target = { ...networkTarget({ scheme: "connect", host: hello.sni, port: t.port }), addr: literal };
    const v = judgeConnection(target, st);
    if (v.error) return { kind: "judge-error", host: hello.sni };
    const verdict = { target, action: v.action, ref: v.ref, ...(v.ruleId ? { ruleId: v.ruleId } : {}) };
    if (v.action !== "allow") for (const a of egressAlerts([verdict], { coach: !!st.coach, profileId: v.profileId })) alert(a, tc);
    return v.action === "block" && !st.coach ? { kind: "rule", host: hello.sni } : null;
  }

  function open(address, port) {
    return new Promise((resolveSock, reject) => {
      let s;
      try { s = connect({ host: address, port }); } catch (e) { return reject(e); }
      const timer = setTimeout(() => { s.destroy(); reject(Object.assign(new Error("connect timed out"), { timeout: true })); }, o.connectTimeoutMs);
      s.once("connect", () => { clearTimeout(timer); s.removeListener("error", reject); resolveSock(s); });
      s.once("error", (e) => { clearTimeout(timer); reject(e); });
    });
  }

  function sendText(res, status, message, extra = {}) {
    const body = `MoorAI egress proxy: ${message}\n`;
    res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": Buffer.byteLength(body), Connection: "close", ...extra });
    res.end(body);
  }
  function rawReply(sock, status, message, extra = "") {
    const body = `MoorAI egress proxy: ${message}\n`;
    try { sock.end(`HTTP/1.1 ${status} ${STATUS_TEXT[status] || "Error"}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n${extra}\r\n${body}`); } catch { sock.destroy(); }
  }
  const AUTH_HEADER = { "Proxy-Authenticate": 'Basic realm="MoorAI egress proxy"' };

  async function onRequest(req, res) {
    if (req.url === "/healthz" && req.method === "GET") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end('{"status":"ok"}'); }
    if (!authOk(req)) return sendText(res, 407, "missing or wrong Proxy-Authorization", AUTH_HEADER);
    if (!/^http:\/\//i.test(req.url)) return sendText(res, 400, "only absolute http:// URLs are proxied here; https goes through CONNECT");
    const method = String(req.method).toUpperCase();
    const tc = requestTrace(req.headers);
    const t = httpTarget(req.url, method);
    if (!t) {
      const d = httpDestination(req.url, method);
      if (d) { alertRefusal("path-form", d, tc); return sendText(res, 400, "the request path has an encoded separator, NUL or percent sign, a malformed escape, a backslash or a dot segment with a parameter"); }
      alertRefusal("host-form", null, tc);
      return sendText(res, 400, "the destination host is not a form an egress rule can name");
    }
    const u = new URL(req.url);
    const a = await admit(t, tc);
    if (!a.ok) return sendText(res, a.status, a.message);
    let sock;
    try { sock = await open(a.address, t.port); }
    catch (e) { return sendText(res, e && e.timeout ? 504 : 502, `${t.host}:${t.port} is unreachable`); }
    sock.setTimeout(o.idleTimeoutMs, () => sock.destroy());
    const named = new Set(String(req.headers.connection || "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean));
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && !named.has(k)) headers[k] = v;
    headers.host = u.host;
    if (tc.incoming) headers.traceparent = tc.incoming;
    else { headers.traceparent = formatTraceparent({ traceId: tc.traceId, spanId: tc.spanId, sampled: true }); delete headers.tracestate; }
    const up = http.request({ method, path: `${t.path}${u.search}`, headers, createConnection: () => sock });
    res.on("close", () => { if (!res.writableFinished) up.destroy(); });
    up.on("error", () => {
      if (res.writableEnded) return;
      if (!res.headersSent) sendText(res, 502, `${t.host}:${t.port} closed the connection`);
      else res.destroy();
    });
    up.on("response", (ur) => {
      const rnamed = new Set(String(ur.headers.connection || "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean));
      const h = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k) && !rnamed.has(k)) h[k] = v;
      res.writeHead(ur.statusCode, ur.statusMessage, h);
      ur.pipe(res);
      ur.on("error", () => res.destroy());
    });
    req.pipe(up);
  }

  async function onConnect(req, csock, head) {
    csock.on("error", () => {});
    csock.setTimeout(o.idleTimeoutMs, () => csock.destroy());
    if (!authOk(req)) return rawReply(csock, 407, "missing or wrong Proxy-Authorization", `Proxy-Authenticate: Basic realm="MoorAI egress proxy"\r\n`);
    const tc = requestTrace(req.headers);
    const t = connectTarget(req.url);
    if (!t) { alertRefusal("host-form", null, tc); return rawReply(csock, 400, "CONNECT needs host:port with a host an egress rule can name"); }
    const { host, port } = t;
    const a = await admit(t, tc);
    if (!a.ok) return rawReply(csock, a.status, a.message);
    if (csock.destroyed) return;
    let up;
    try { up = await open(a.address, port); }
    catch (e) { return rawReply(csock, e && e.timeout ? 504 : 502, `${host}:${port} is unreachable`); }
    if (csock.destroyed) return up.destroy();
    up.setTimeout(o.idleTimeoutMs, () => { up.destroy(); csock.destroy(); });
    up.on("error", () => csock.destroy());
    up.on("close", () => csock.destroy());
    csock.on("close", () => up.destroy());
    csock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    up.pipe(csock);
    // Nothing the client sends goes upstream until its first bytes are judged (judgeHello). The server's
    // bytes flow at once, so a protocol where the server speaks first still works. The ClientHello is read
    // incrementally (sni.mjs createHelloSniffer) and the held chunks are forwarded as they came, never joined.
    // From the client's first byte, a ClientHello still incomplete after helloTimeoutMs closes the tunnel.
    const sniffer = createHelloSniffer();
    const held = [];
    let timer = null;
    const drop = () => { up.destroy(); csock.destroy(); };
    const onData = (c) => {
      held.push(c);
      const hello = sniffer.push(c);
      if (hello.need) {
        if (!timer) timer = setTimeout(() => { csock.removeListener("data", onData); alertRefusal("tls-timeout", { host: t.host, port, method: null }, tc); drop(); }, o.helloTimeoutMs);
        return;
      }
      clearTimeout(timer);
      csock.removeListener("data", onData);
      const refused = judgeHello(hello, t, a.st, tc);
      if (refused) {
        if (refused.kind !== "rule") alertRefusal(refused.kind, { host: refused.host, port, method: null }, tc);
        return drop();
      }
      for (const b of held) up.write(b);
      held.length = 0;
      csock.pipe(up);
    };
    csock.on("close", () => clearTimeout(timer));
    csock.on("data", onData);
    if (head && head.length) onData(Buffer.from(head));
  }

  const server = http.createServer({ maxHeaderSize: o.maxHeaderBytes, connectionsCheckingInterval: Math.min(1000, o.headersTimeoutMs) }, (req, res) => {
    onRequest(req, res).catch(() => { if (!res.headersSent) sendText(res, 502, "proxy error"); else res.destroy(); });
  });
  server.on("connect", (req, sock, head) => { onConnect(req, sock, head).catch(() => sock.destroy()); });
  server.headersTimeout = o.headersTimeoutMs;
  server.requestTimeout = Math.max(o.requestTimeoutMs, o.headersTimeoutMs);
  server.keepAliveTimeout = 5000;
  server.timeout = o.idleTimeoutMs;
  server.maxConnections = o.maxConnections;
  return server;
}
