// F23 at the network layer (egress-proxy/): cidr rules judged on the resolved connect address, and the TLS
// server name (SNI) of a CONNECT tunnel judged before a byte of it goes upstream. In process, with an
// injected policy, resolver and connector (egress-proxy/test/harness.mjs): no test reaches the network.
// The ClientHello bytes come from Node's own TLS client, captured on a loopback socket.
//
//   node --test --import ./test/hermetic-env.mjs test/egress-proxy-cidr-sni.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";
import { startUpstream, startEcho, fakeResolver, fakeConnect, startProxy, stateOf, viaProxy, connectVia } from "../egress-proxy/test/harness.mjs";
import * as SNI from "../egress-proxy/sni.mjs";
const { sniffClientHello } = SNI;

const PUBLIC = "93.184.216.34";
let up, echo;
before(async () => { up = await startUpstream(); echo = await startEcho(); });
after(async () => { await up.close(); await echo.close(); });

const TABLE = { "api.example.com": [PUBLIC], "plc.corp": ["10.20.1.5"], "intranet.corp": ["10.9.9.9"], "mixed.example": [PUBLIC, "10.1.1.1"], "evil.example": [PUBLIC], "two.example": [PUBLIC, "198.51.100.7"], "owt.example": ["198.51.100.7", PUBLIC] };
async function proxyWith(policy, extra = {}) {
  const resolve = fakeResolver(TABLE);
  const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
  const p = await startProxy({}, { getState: stateOf(policy, extra), resolve, connect });
  return { ...p, resolve, connect };
}

// A real ClientHello: Node's TLS client writing to a loopback socket that never answers.
async function realHello(servername) {
  const srv = net.createServer();
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const got = new Promise((resolve) => srv.once("connection", (s) => { const chunks = []; s.on("data", (c) => { chunks.push(c); const b = Buffer.concat(chunks); const v = sniffClientHello(b); if (!v.need) { resolve(b); s.destroy(); } }); }));
  const c = tls.connect({ host: "127.0.0.1", port: srv.address().port, ...(servername ? { servername } : {}), rejectUnauthorized: false });
  c.on("error", () => {});
  const b = await got;
  c.destroy();
  srv.close();
  return b;
}

// Write bytes into a tunnel → "echoed" when the echo upstream sent them back, "closed" when the proxy closed it.
function tunnelOutcome(socket, chunks) {
  return new Promise((resolve) => {
    const want = chunks.reduce((n, c) => n + c.length, 0);
    let got = 0;
    socket.on("data", (c) => { got += c.length; if (got >= want) { resolve("echoed"); socket.destroy(); } });
    socket.on("close", () => resolve(got >= want ? "echoed" : "closed"));
    socket.on("error", () => {});
    (async () => { for (const c of chunks) { socket.write(c); await new Promise((r) => setTimeout(r, 15)); } })();
  });
}
const lastRefusal = (p) => p.reports.filter((r) => r.egressRefusal).at(-1);

test("sniffClientHello: Node's real ClientHello yields its server name; no SNI is null; not-TLS and need-more are told apart", async () => {
  const h = await realHello("API.Example.com");
  assert.deepEqual(sniffClientHello(h), { tls: true, sni: "api.example.com" });
  assert.deepEqual(sniffClientHello(h.subarray(0, 40)), { need: true });
  assert.deepEqual(sniffClientHello(Buffer.from("SSH-2.0-OpenSSH_9.6\r\n")), { tls: false });
  const none = await realHello(null);
  assert.deepEqual(sniffClientHello(none), { tls: true, sni: null });
  assert.ok(sniffClientHello(Buffer.from([0x16, 3, 1, 0, 4, 1, 0, 0, 0])).error, "an empty ClientHello body is malformed");
  assert.ok(sniffClientHello(Buffer.from([0x16, 3, 1, 0, 4, 2, 0, 0, 0])).error, "a ServerHello first is refused");
});

test("sniffClientHello: a ClientHello fragmented across two TLS records is reassembled", async () => {
  const h = await realHello("api.example.com");
  const body = h.subarray(5);
  const cut = 60;
  const rec = (frag) => Buffer.concat([Buffer.from([0x16, 3, 1, frag.length >> 8, frag.length & 255]), frag]);
  const two = Buffer.concat([rec(body.subarray(0, cut)), rec(body.subarray(cut))]);
  assert.deepEqual(sniffClientHello(two), { tls: true, sni: "api.example.com" });
  assert.deepEqual(sniffClientHello(two.subarray(0, 5 + cut + 3)), { need: true });
});

test("CONNECT: a ClientHello naming the CONNECT host goes upstream byte for byte", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", port: 443, action: "allow" }], egressDefault: "block" });
  try {
    const c = await connectVia(p.port, "api.example.com:443");
    assert.equal(c.status, 200);
    const h = await realHello("api.example.com");
    assert.equal(await tunnelOutcome(c.socket, [h.subarray(0, 30), h.subarray(30)]), "echoed");
  } finally { await p.close(); }
});

test("CONNECT: a ClientHello naming another host than the CONNECT line is refused (the tunnel closes, nothing goes upstream), also when coaching", async () => {
  for (const coach of [false, true]) {
    const p = await proxyWith({ egressRules: [{ host: "api.example.com", port: 443, action: "allow" }], egressDefault: "block" }, { coach });
    try {
      const c = await connectVia(p.port, "api.example.com:443");
      assert.equal(c.status, 200);
      const h = await realHello("evil.example");
      assert.equal(await tunnelOutcome(c.socket, [h]), "closed", `coach=${coach}`);
      const r = lastRefusal(p);
      assert.equal(r.egressRefusal, "sni-mismatch");
      assert.equal(r.egressHost, "evil.example");
      assert.equal(r.egressPort, 443);
      assert.equal(r.decision, "deny");
    } finally { await p.close(); }
  }
});

test("CONNECT to an IP literal: the server name is judged by the egress rules", async () => {
  const policy = { egressRules: [{ host: PUBLIC, port: 443, action: "allow" }, { host: "api.example.com", action: "allow" }, { host: "evil.example", action: "block" }], egressDefault: "block" };
  const p = await proxyWith(policy);
  try {
    let c = await connectVia(p.port, `${PUBLIC}:443`);
    assert.equal(c.status, 200);
    assert.equal(await tunnelOutcome(c.socket, [await realHello("api.example.com")]), "echoed");
    c = await connectVia(p.port, `${PUBLIC}:443`);
    assert.equal(await tunnelOutcome(c.socket, [await realHello("evil.example")]), "closed");
    assert.equal(p.reports.at(-1).egressHost, "evil.example");
    assert.equal(p.reports.at(-1).egressAction, "block");
    c = await connectVia(p.port, `${PUBLIC}:443`);
    assert.equal(await tunnelOutcome(c.socket, [await realHello("unlisted.example")]), "closed", "egressDefault block applies to the server name");
  } finally { await p.close(); }
});

test("CONNECT: no SNI, or a first byte that is not TLS, is judged on the CONNECT host alone; a malformed handshake is refused", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", port: 443, action: "allow" }], egressDefault: "block" });
  try {
    let c = await connectVia(p.port, "api.example.com:443");
    assert.equal(await tunnelOutcome(c.socket, [await realHello(null)]), "echoed");
    c = await connectVia(p.port, "api.example.com:443");
    assert.equal(await tunnelOutcome(c.socket, [Buffer.from("SSH-2.0-x\r\n")]), "echoed");
    c = await connectVia(p.port, "api.example.com:443");
    assert.equal(await tunnelOutcome(c.socket, [Buffer.from([0x16, 3, 1, 0, 6, 1, 0, 0, 2, 3, 3])]), "closed");
    assert.equal(lastRefusal(p).egressRefusal, "tls-unparsed");
  } finally { await p.close(); }
});

test("cidr: a name whose resolved address is inside a cidr block rule is refused before any connection", async () => {
  const p = await proxyWith({ egressRules: [{ id: "rfc1918", cidr: ["10.0.0.0/8"], action: "block" }, { host: "intranet.corp", action: "allow" }], egressDefault: "allow" });
  try {
    const r = await viaProxy(p.port, "http://intranet.corp/x");
    assert.equal(r.status, 403);
    assert.match(r.body, /egress rule "rfc1918"/);
    assert.equal(p.connect.calls.length, 0);
    const a = p.reports.find((x) => x.egressRuleId === "rfc1918");
    assert.equal(a.egressHost, "intranet.corp");
    assert.equal(a.egressRule, "policy#0");
    const c = await connectVia(p.port, "mixed.example:443");
    assert.equal(c.status, 403, "one resolved address inside the range is enough");
  } finally { await p.close(); }
});

test("cidr: a public address range is judged too, and a name outside it still goes", async () => {
  const p = await proxyWith({ egressRules: [{ id: "bad-net", cidr: "93.184.0.0/16", action: "block" }], egressDefault: "allow" });
  try {
    assert.equal((await viaProxy(p.port, "http://api.example.com/")).status, 403);
    assert.equal((await connectVia(p.port, `${PUBLIC}:443`)).status, 403, "an IP literal inside the range");
  } finally { await p.close(); }
});

test("cidr: an allow range opens a private address under a block default, connecting to exactly the judged address", async () => {
  const p = await proxyWith({ egressRules: [{ id: "ot", cidr: "10.20.0.0/16", port: [80, 502], action: "allow" }], egressDefault: "block" });
  try {
    const r = await viaProxy(p.port, "http://plc.corp/status");
    assert.equal(r.status, 200);
    assert.deepEqual(p.connect.calls, [{ host: "10.20.1.5", port: 80 }]);
    assert.equal((await viaProxy(p.port, "http://intranet.corp/")).status, 403, "outside the range: the block default");
    assert.equal((await viaProxy(p.port, "http://plc.corp:8080/")).status, 403, "the port key still applies");
  } finally { await p.close(); }
});

// A minimal ClientHello built by hand: TLS 1.2 version, empty session id, one cipher suite, null
// compression, and a server_name extension carrying the given names (RFC 6066 3).
function handHello(names, { repeatExt = false, repeatOther = false } = {}) {
  const entry = (n) => Buffer.concat([Buffer.from([0, n.length >> 8, n.length & 255]), Buffer.from(n, "latin1")]);
  const list = Buffer.concat(names.map(entry));
  const sniData = Buffer.concat([Buffer.from([list.length >> 8, list.length & 255]), list]);
  const ext = Buffer.concat([Buffer.from([0, 0, sniData.length >> 8, sniData.length & 255]), sniData]);
  const groups = Buffer.from([0, 10, 0, 4, 0, 2, 0, 29]); // supported_groups(10): x25519
  const exts = repeatExt ? Buffer.concat([ext, ext]) : repeatOther ? Buffer.concat([groups, ext, groups]) : ext;
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32), Buffer.from([0, 0, 2, 0x13, 0x01, 1, 0]), Buffer.from([exts.length >> 8, exts.length & 255]), exts]);
  const hs = Buffer.concat([Buffer.from([1, body.length >> 16, (body.length >> 8) & 255, body.length & 255]), body]);
  return Buffer.concat([Buffer.from([0x16, 3, 1, hs.length >> 8, hs.length & 255]), hs]);
}

test("sniffClientHello: two host_name entries, a repeated server_name extension, or a name that is not a host name is malformed (refused)", () => {
  assert.deepEqual(sniffClientHello(handHello(["api.example.com"])), { tls: true, sni: "api.example.com" });
  assert.ok(sniffClientHello(handHello(["api.example.com", "evil.example"])).error, "two host_name entries");
  assert.ok(sniffClientHello(handHello(["api.example.com"], { repeatExt: true })).error, "a repeated server_name extension");
  assert.ok(sniffClientHello(handHello(["api.example.com"], { repeatOther: true })).error, "a repeated extension of another type (RFC 8446 4.2)");
  assert.ok(sniffClientHello(handHello(["bad name"])).error, "not a host name");
});

test("cidr: a range never vouches for a cloud metadata address", async () => {
  const p = await proxyWith({ egressRules: [{ cidr: "169.254.0.0/16", action: "allow" }], egressDefault: "block" });
  try {
    const r = await connectVia(p.port, "169.254.169.254:80");
    assert.equal(r.status, 403);
    assert.match(r.body, /cloud metadata/);
  } finally { await p.close(); }
});

test("cidr in force: a name a host rule blocks, or the block default with no cidr allow or alert rule, is refused before any DNS lookup", async () => {
  const p = await proxyWith({ egressRules: [{ id: "rfc1918", cidr: "10.0.0.0/8", action: "block" }, { id: "no-evil", host: "evil.example", action: "block" }], egressDefault: "allow" });
  try {
    const r = await viaProxy(p.port, "http://evil.example/x");
    assert.equal(r.status, 403);
    assert.match(r.body, /egress rule "no-evil"/);
    assert.equal((await connectVia(p.port, "evil.example:443")).status, 403);
    assert.deepEqual(p.resolve.calls, [], "the blocked name was looked up in DNS (a DNS query is itself egress)");
    assert.equal((await viaProxy(p.port, "http://api.example.com/")).status, 200, "a name no rule blocks is still resolved and judged per address");
    assert.deepEqual(p.resolve.calls, ["api.example.com"]);
  } finally { await p.close(); }
  const d = await proxyWith({ egressRules: [{ cidr: "10.0.0.0/8", action: "block" }, { host: "api.example.com", action: "allow" }], egressDefault: "block" });
  try {
    assert.equal((await connectVia(d.port, "unlisted.example:443")).status, 403);
    assert.deepEqual(d.resolve.calls, [], "under a block default only a cidr allow or alert rule could open a name");
  } finally { await d.close(); }
});

test("cidr in force: a cidr allow rule ahead of the blocking host rule can still open the name, so that name is resolved and judged per address", async () => {
  const p = await proxyWith({ egressRules: [{ id: "cdn", cidr: "93.184.0.0/16", action: "allow" }, { id: "no-evil", host: "evil.example", action: "block" }], egressDefault: "block" });
  try {
    assert.equal((await viaProxy(p.port, "http://evil.example/")).status, 200, "the earlier cidr allow decides for the resolved address");
    assert.deepEqual(p.resolve.calls, ["evil.example"]);
    assert.equal((await connectVia(p.port, "unlisted.example:443")).status, 502, "under the block default a cidr allow could open any name, so it is looked up (and does not resolve here)");
  } finally { await p.close(); }
});

test("cidr: EVERY resolved address is judged as an IP literal, so a blocked public range on any one of them refuses the name (no private-address check involved)", async () => {
  const p = await proxyWith({ egressRules: [{ id: "bad-net", cidr: "198.51.100.0/24", action: "block" }], egressDefault: "allow" });
  try {
    for (const name of ["two.example", "owt.example"]) {
      const r = await viaProxy(p.port, `http://${name}/`);
      assert.equal(r.status, 403, name);
      assert.match(r.body, /egress rule "bad-net"/, name);
      assert.equal((await connectVia(p.port, `${name}:443`)).status, 403, name);
    }
    assert.equal(p.connect.calls.length, 0);
    assert.equal((await viaProxy(p.port, "http://api.example.com/")).status, 200, "a name with no address in the range goes");
  } finally { await p.close(); }
});

// A ClientHello carrying a padding extension (21) of padLen bytes, its handshake message cut into TLS records
// of at most recLen bytes.
function paddedHello(name, padLen, recLen = 16384) {
  const nm = Buffer.from(name, "latin1");
  const entry = Buffer.concat([Buffer.from([0, nm.length >> 8, nm.length & 255]), nm]);
  const sniData = Buffer.concat([Buffer.from([entry.length >> 8, entry.length & 255]), entry]);
  const sni = Buffer.concat([Buffer.from([0, 0, sniData.length >> 8, sniData.length & 255]), sniData]);
  const pad = Buffer.concat([Buffer.from([0, 21, padLen >> 8, padLen & 255]), Buffer.alloc(padLen)]);
  const exts = Buffer.concat([sni, pad]);
  const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32), Buffer.from([0, 0, 2, 0x13, 0x01, 1, 0]), Buffer.from([exts.length >> 8, exts.length & 255]), exts]);
  const hs = Buffer.concat([Buffer.from([1, body.length >> 16, (body.length >> 8) & 255, body.length & 255]), body]);
  const recs = [];
  for (let o = 0; o < hs.length; o += recLen) { const f = hs.subarray(o, o + recLen); recs.push(Buffer.from([0x16, 3, 1, f.length >> 8, f.length & 255]), f); }
  return Buffer.concat(recs);
}

test("createHelloSniffer: a ClientHello pushed one byte at a time is read incrementally, each byte copied a bounded number of times (no reparse per chunk)", () => {
  const h = paddedHello("api.example.com", 60000);
  assert.ok(h.length > 60000 && h.length < 65536);
  const concat = Buffer.concat;
  let copied = 0;
  Buffer.concat = function (list, n) { const b = concat.call(Buffer, list, n); copied += b.length; return b; };
  let v;
  try {
    const s = SNI.createHelloSniffer();
    for (let i = 0; i < h.length; i++) { v = s.push(h.subarray(i, i + 1)); if (i < h.length - 1) assert.deepEqual(v, { need: true }, `byte ${i}`); }
  } finally { Buffer.concat = concat; }
  assert.deepEqual(v, { tls: true, sni: "api.example.com" });
  assert.ok(copied <= 3 * h.length, `${copied} bytes copied for a ${h.length}-byte ClientHello`);
  assert.deepEqual(sniffClientHello(h), { tls: true, sni: "api.example.com" }, "the one-buffer form agrees");
});

test("sniffClientHello: at most MAX_HELLO_RECORDS (16) TLS records before the ClientHello completes; one more is refused", async () => {
  assert.equal(SNI.MAX_HELLO_RECORDS, 16);
  const h = await realHello("api.example.com");
  const body = h.subarray(5);
  const cut = (n) => { const step = Math.ceil(body.length / n); const out = []; for (let o = 0; o < body.length; o += step) { const f = body.subarray(o, o + step); out.push(Buffer.from([0x16, 3, 1, f.length >> 8, f.length & 255]), f); } assert.equal(out.length / 2, n); return Buffer.concat(out); };
  assert.deepEqual(sniffClientHello(cut(16)), { tls: true, sni: "api.example.com" });
  assert.match(String(sniffClientHello(cut(17)).error), /records/);
  const s = SNI.createHelloSniffer();
  const r17 = cut(17);
  let v;
  for (let i = 0; i < r17.length; i += 7) { v = s.push(r17.subarray(i, i + 7)); if (!v.need) break; }
  assert.match(String(v.error), /records/, "pushed in pieces too");
});

test("CONNECT: a TLS first flight that does not complete its ClientHello within the deadline closes the tunnel; a client that has sent nothing yet is not cut", async () => {
  const resolve = fakeResolver(TABLE);
  const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
  const p = await startProxy({ helloTimeoutMs: 200 }, { getState: stateOf({ egressRules: [{ host: "api.example.com", port: 443, action: "allow" }], egressDefault: "block" }), resolve, connect });
  try {
    let c = await connectVia(p.port, "api.example.com:443");
    assert.equal(c.status, 200);
    const outcome = await new Promise((done) => {
      const t = setTimeout(() => done("open"), 1500);
      c.socket.on("close", () => { clearTimeout(t); done("closed"); });
      c.socket.on("error", () => {});
      c.socket.write(Buffer.from([0x16, 3, 1]));
    });
    c.socket.destroy();
    assert.equal(outcome, "closed", "a stalled ClientHello held the tunnel open past the deadline");
    assert.equal(p.reports.filter((r) => r.egressRefusal).at(-1).egressRefusal, "tls-timeout");
    c = await connectVia(p.port, "api.example.com:443");
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(await tunnelOutcome(c.socket, [Buffer.from("SSH-2.0-x\r\n")]), "echoed", "the deadline starts with the client's first byte");
  } finally { await p.close(); }
});
