// moorai-egress-proxy: the address side. Private, loopback and link-local destinations need a rule that
// names them; IP literals need one too; odd host forms are refused; DNS is resolved once and the checked
// address is the one connected to. Injected resolver and connector (egress-proxy/test/harness.mjs).
//
//   node --test --import ./test/hermetic-env.mjs test/egress-proxy-address.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { startUpstream, startEcho, fakeResolver, fakeConnect, startProxy, stateOf, viaProxy, connectVia } from "../egress-proxy/test/harness.mjs";
import { addressClass, normalizeHost, isMetadataAddress } from "../egress-proxy/address.mjs";
import { httpTarget, connectTarget, judgeConnection, networkTarget } from "../egress-proxy/judge.mjs";

const PUBLIC = "93.184.216.34";
let up, echo;
before(async () => { up = await startUpstream(); echo = await startEcho(); });
after(async () => { await up.close(); await echo.close(); });

async function proxyWith(policy, table) {
  const resolve = fakeResolver(table);
  const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
  const p = await startProxy({}, { getState: stateOf(policy), resolve, connect });
  return { ...p, resolve, connect };
}

test("private: a name that resolves to a private address is refused under an allow default, and allowed by a rule that names it", async () => {
  const table = { "internal.example": ["10.0.0.5"], "meta.example": ["169.254.169.254"], "mixed.example": [PUBLIC, "127.0.0.1"], "v6.example": ["fd00::1"] };
  const p = await proxyWith({ egressDefault: "allow" }, table);
  try {
    for (const host of ["internal.example", "meta.example", "mixed.example", "v6.example"]) {
      const r = await viaProxy(p.port, `http://${host}/`);
      assert.equal(r.status, 403, host);
      assert.match(r.body, /loopback, private or link-local/);
    }
    assert.equal((await connectVia(p.port, "internal.example:443")).status, 403);
    assert.equal(p.connect.calls.length, 0, "never connected");
    assert.ok(p.reports.some((a) => a.egressRefusal === "private-address" && a.egressHost === "internal.example"));
  } finally { await p.close(); }
  const q = await proxyWith({ egressRules: [{ host: "internal.example", action: "allow" }], egressDefault: "block" }, table);
  try {
    assert.equal((await viaProxy(q.port, "http://internal.example/")).status, 200);
    assert.deepEqual(q.connect.calls, [{ host: "10.0.0.5", port: 80 }]);
  } finally { await q.close(); }
});

test("loopback: localhost is not exempt at the network layer; it needs a rule", async () => {
  const table = { localhost: ["127.0.0.1"] };
  const p = await proxyWith({ egressDefault: "allow" }, table);
  try {
    assert.equal((await viaProxy(p.port, `http://localhost:${up.port}/`)).status, 403);
    assert.equal((await viaProxy(p.port, `http://127.0.0.1:${up.port}/`)).status, 403);
    assert.equal((await viaProxy(p.port, `http://[::1]:${up.port}/`)).status, 403);
  } finally { await p.close(); }
  const q = await proxyWith({ egressRules: [{ host: "localhost", port: up.port, action: "allow" }] }, table);
  try { assert.equal((await viaProxy(q.port, `http://localhost:${up.port}/`)).status, 200); } finally { await q.close(); }
});

test("IP literals: refused unless a rule names the address, in every spelling the URL parser accepts", async () => {
  const p = await proxyWith({ egressDefault: "allow" }, {});
  try {
    for (const url of [`http://${PUBLIC}/`, "http://10.0.0.5/", "http://2130706433/", "http://0x7f.1/", "http://[::ffff:7f00:1]/", "http://169.254.169.254/latest/meta-data/"]) {
      const r = await viaProxy(p.port, url);
      assert.equal(r.status, 403, url);
      assert.match(r.body, /IP literal/, url);
    }
    assert.equal((await connectVia(p.port, `${PUBLIC}:443`)).status, 403);
    assert.equal((await connectVia(p.port, "[::1]:443")).status, 403);
    assert.equal(p.resolve.calls.length, 0, "an IP literal is never resolved");
    assert.equal(p.connect.calls.length, 0);
    assert.ok(p.reports.some((a) => a.egressRefusal === "ip-literal"));
  } finally { await p.close(); }
  const q = await proxyWith({ egressRules: [{ host: PUBLIC, action: "allow" }], egressDefault: "block" }, {});
  try {
    assert.equal((await viaProxy(q.port, `http://${PUBLIC}/`)).status, 200);
    const c = await connectVia(q.port, `${PUBLIC}:443`);
    assert.equal(c.status, 200);
    c.socket.destroy();
    assert.deepEqual(q.connect.calls, [{ host: PUBLIC, port: 80 }, { host: PUBLIC, port: 443 }]);
  } finally { await q.close(); }
});

test("never: the unspecified address, multicast and reserved space are refused even when a rule names the host", async () => {
  const p = await proxyWith({ egressRules: [{ host: "zero.example", action: "allow" }, { host: "mc.example", action: "allow" }] }, { "zero.example": ["0.0.0.0"], "mc.example": ["224.0.0.1"] });
  try {
    assert.equal((await viaProxy(p.port, "http://zero.example/")).status, 403);
    assert.equal((await viaProxy(p.port, "http://mc.example/")).status, 403);
    assert.equal(p.connect.calls.length, 0);
  } finally { await p.close(); }
});

test("host forms: a host no rule could name, parser disagreement, https in absolute form and origin form are refused 400", async () => {
  const p = await proxyWith({ egressDefault: "allow" }, { "api.example.com": [PUBLIC], "evil.example": [PUBLIC] });
  try {
    // (Node 22's HTTP parser passes a backslash in the request target through; the proxy refuses it.)
    for (const url of ["http://a_b.example/", "http://api.example.com\\@evil.example/", "http://exa%20mple.example/", "/healthz/x", "/"]) {
      assert.equal((await viaProxy(p.port, url)).status, 400, url);
    }
    const https = await viaProxy(p.port, "https://api.example.com/");
    assert.equal(https.status, 400);
    assert.match(https.body, /only absolute http:\/\/ URLs are proxied here; https goes through CONNECT/);
    for (const auth of ["a_b.example:443", "user@api.example.com:443", "api.example.com", "api.example.com:0", "api.example.com:99999", "api.example.com:443/x"]) {
      assert.equal((await connectVia(p.port, auth)).status, 400, auth);
    }
    assert.equal(p.connect.calls.length, 0);
  } finally { await p.close(); }
});

test("DNS: resolved once per connection, and the connection goes to exactly the address that was checked", async () => {
  // A rebinding name: the first answer is public, every later one is the metadata service.
  const table = { "rebind.example": (n) => (n === 1 ? [PUBLIC] : ["169.254.169.254"]) };
  const p = await proxyWith({ egressDefault: "allow" }, table);
  try {
    assert.equal((await viaProxy(p.port, "http://rebind.example/a")).status, 200);
    assert.deepEqual(p.resolve.calls, ["rebind.example"], "one lookup for the request");
    assert.deepEqual(p.connect.calls, [{ host: PUBLIC, port: 80 }], "connected to the checked address, not the name");
    // The second connection gets the second answer, and it is checked, not trusted from the first.
    const second = await connectVia(p.port, "rebind.example:443");
    assert.equal(second.status, 403);
    assert.deepEqual(p.resolve.calls, ["rebind.example", "rebind.example"]);
    assert.equal(p.connect.calls.length, 1);
  } finally { await p.close(); }
});

test("DNS: a name that does not resolve is a 502 and nothing is connected", async () => {
  const p = await proxyWith({ egressDefault: "allow" }, {});
  try {
    assert.equal((await viaProxy(p.port, "http://nowhere.example/")).status, 502);
    assert.equal(p.connect.calls.length, 0);
  } finally { await p.close(); }
});

test("address classes and host normalisation", () => {
  for (const ip of ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::"]) assert.equal(addressClass(ip), "special", ip);
  for (const ip of ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"]) assert.equal(addressClass(ip), "never", ip);
  for (const ip of [PUBLIC, "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8"]) assert.equal(addressClass(ip), "public", ip);
  assert.equal(addressClass("not-an-ip"), "never");
  assert.equal(normalizeHost("API.Example.COM."), "api.example.com");
  assert.equal(normalizeHost("2130706433"), "127.0.0.1");
  assert.equal(normalizeHost("[::FFFF:127.0.0.1]"), "[::ffff:7f00:1]");
  for (const bad of ["a_b.example", "", "x y", "user@h", "h/x", "%31.example", "foo.123"]) assert.equal(normalizeHost(bad), null, bad);
  assert.equal(net.isIP("93.184.216.34"), 4);
});

test("targets: the two parsers of cli/egress-rules.mjs must agree on the host; ports and forms are checked", () => {
  const t = httpTarget("http://API.example.com./repos/a/../b?q=1", "GET");
  assert.deepEqual({ host: t.host, port: t.port, method: t.method, path: t.path, binary: t.binary }, { host: "api.example.com", port: 80, method: "GET", path: "/repos/b", binary: null });
  assert.equal(httpTarget("http://api.example.com\\@evil.example/", "GET"), null, "WHATWG reads api.example.com, curl's reading evil.example");
  for (const bad of ["https://api.example.com/", "http://exa%20mple.example/", "http://a_b.example/", "http://api.example.com:0/", "ftp://api.example.com/"]) assert.equal(httpTarget(bad, "GET"), null, bad);
  const c = connectTarget("API.example.com:443");
  assert.deepEqual({ host: c.host, port: c.port, method: c.method, path: c.path }, { host: "api.example.com", port: 443, method: null, path: null });
  assert.equal(connectTarget("[::1]:443").host, "[::1]");
  for (const bad of ["api.example.com", "api.example.com:0", "user@api.example.com:443", "a_b.example:443", "api.example.com:443/x", ":443"]) assert.equal(connectTarget(bad), null, bad);
});

test("a policy the rules cannot be evaluated against refuses the connection (fail closed)", async () => {
  const hostile = { get egressRules() { throw new Error("unreadable"); } };
  const p = await startProxy({}, { getState: stateOf(hostile), resolve: fakeResolver({ "ok.example": [PUBLIC] }), connect: fakeConnect({ httpPort: up.port, echoPort: echo.port }) });
  try {
    assert.equal((await viaProxy(p.port, "http://ok.example/")).status, 403);
    assert.equal((await connectVia(p.port, "ok.example:443")).status, 403);
    assert.ok(p.reports.some((a) => a.egressRefusal === "judge-error"));
  } finally { await p.close(); }
});

test("a block rule that names a private address or an IP literal never lifts the address refusal, enforcing or coaching", async () => {
  const policy = { egressRules: [{ host: "10.0.0.5", action: "block" }, { host: "internal.example", action: "block" }, { host: "127.0.0.1", action: "block" }], egressDefault: "allow" };
  for (const coach of [false, true]) {
    const resolve = fakeResolver({ "internal.example": ["10.0.0.5"] });
    const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
    const p = await startProxy({}, { getState: stateOf(policy, { coach }), resolve, connect });
    try {
      for (const url of ["http://10.0.0.5/", "http://internal.example/", `http://127.0.0.1:${up.port}/`]) assert.equal((await viaProxy(p.port, url)).status, 403, `${url} coach=${coach}`);
      for (const auth of ["10.0.0.5:443", "internal.example:443"]) assert.equal((await connectVia(p.port, auth)).status, 403, `${auth} coach=${coach}`);
      assert.equal(connect.calls.length, 0, `nothing connected, coach=${coach}`);
    } finally { await p.close(); }
  }
});

test("judge: only an allow or alert rule is an explicit grant; a block rule, the default and the loopback exemption are not", () => {
  const t = (host) => networkTarget({ scheme: "connect", host, port: 443 });
  const policy = { egressRules: [{ host: "10.0.0.5", action: "block" }, { host: "10.0.0.6", action: "allow" }, { host: "10.0.0.7", action: "alert" }], egressDefault: "allow" };
  assert.equal(judgeConnection(t("10.0.0.5"), { policy }).explicit, false, "block");
  assert.equal(judgeConnection(t("10.0.0.6"), { policy }).explicit, true, "allow");
  assert.equal(judgeConnection(t("10.0.0.7"), { policy }).explicit, true, "alert");
  assert.equal(judgeConnection(t("10.0.0.8"), { policy }).explicit, false, "default");
  assert.equal(judgeConnection(t("localhost"), { policy }).explicit, false, "loopback exemption");
});

// The Azure WireServer (168.63.129.16) is a metadata address; NAT64 64:ff9b::/96 and 64:ff9b:1::/48 are read
// from their last 32 bits, and the rest of 64:ff9b::/32 is special.
test("address classes: the Azure WireServer and NAT64 (64:ff9b::/96, 64:ff9b:1::/48, the rest of 64:ff9b::/32)", () => {
  for (const ip of ["168.63.129.16", "::ffff:168.63.129.16", "64:ff9b::a83f:8110", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "64:ff9b:1:abcd::a83f:8110"]) {
    assert.equal(addressClass(ip), "special", ip);
    assert.equal(isMetadataAddress(ip), true, ip);
  }
  for (const ip of ["64:ff9b:1::a00:5", "64:ff9b:1::7f00:1", "64:ff9b:2::1", "64:ff9b::1:0:0:808:808", "64:ff9b:ffff::808:808"]) {
    assert.equal(addressClass(ip), "special", ip);
    assert.equal(isMetadataAddress(ip), false, ip);
  }
  assert.equal(addressClass("64:ff9b:1::"), "never", "embedded 0.0.0.0");
  assert.equal(addressClass("64:ff9b:1::e000:1"), "never", "embedded multicast");
  for (const ip of ["64:ff9b::808:808", "64:ff9b:1::808:808", "168.63.129.15", "168.63.130.16"]) assert.equal(addressClass(ip), "public", ip);
});

test("WireServer and NAT64: refused by name even under a rule naming the host, and by literal unless a rule names the IP", async () => {
  const table = { "wire.example": ["168.63.129.16"], "n64meta.example": ["64:ff9b::a9fe:a9fe"], "n64local.example": ["64:ff9b:1::a00:5"], "n64pub.example": ["64:ff9b:1::5db8:d822"] };
  const named = ["wire.example", "n64meta.example", "n64local.example", "n64pub.example"].map((host) => ({ host, action: "allow" }));
  const p = await proxyWith({ egressRules: named, egressDefault: "allow" }, table);
  try {
    for (const host of ["wire.example", "n64meta.example"]) {
      const r = await viaProxy(p.port, `http://${host}/machine?comp=goalstate`);
      assert.equal(r.status, 403, host);
      assert.match(r.body, /cloud metadata address/, host);
      assert.equal((await connectVia(p.port, `${host}:443`)).status, 403, `CONNECT ${host}`);
    }
    assert.equal((await viaProxy(p.port, "http://n64local.example/")).status, 200, "a rule naming the host unlocks a private NAT64 address");
    assert.equal((await viaProxy(p.port, "http://n64pub.example/")).status, 200);
    for (const lit of ["168.63.129.16", "[64:ff9b::a9fe:a9fe]", "[64:ff9b:1::a00:5]"]) assert.equal((await viaProxy(p.port, `http://${lit}/`)).status, 403, lit);
    assert.deepEqual(p.connect.calls.map((c) => c.host), ["64:ff9b:1::a00:5", "64:ff9b:1::5db8:d822"]);
    assert.ok(p.reports.some((a) => a.egressRefusal === "metadata-address" && a.egressHost === "wire.example"));
  } finally { await p.close(); }
  const q = await proxyWith({ egressRules: [{ host: "*.example", action: "allow" }], egressDefault: "block" }, table);
  try {
    assert.equal((await viaProxy(q.port, "http://n64local.example/")).status, 403, "a *.suffix rule never unlocks a NAT64-embedded private address");
    assert.equal((await viaProxy(q.port, "http://n64pub.example/")).status, 200, "DNS64 to a public address still works");
  } finally { await q.close(); }
  const r = await proxyWith({ egressRules: [{ host: "168.63.129.16", action: "allow" }], egressDefault: "block" }, table);
  try {
    assert.equal((await viaProxy(r.port, "http://168.63.129.16/?comp=versions")).status, 200, "a rule naming the WireServer IP literal reaches it");
  } finally { await r.close(); }
});
