// moorai-egress-proxy (egress-proxy/): the v1.7.0 egressRules enforced on real connections. Plain HTTP by
// host, port, method and path; CONNECT by host and port; the binary unknown at the network layer. In
// process, with an injected policy, resolver and connector (egress-proxy/test/harness.mjs): no test
// reaches the real network.
//
//   node --test --import ./test/hermetic-env.mjs test/egress-proxy.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startUpstream, startEcho, fakeResolver, fakeConnect, startProxy, stateOf, viaProxy, connectVia, echoOnce } from "../egress-proxy/test/harness.mjs";
import { createPolicySource } from "../egress-proxy/policy.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";

const PUBLIC = "93.184.216.34";
let up, echo;
before(async () => { up = await startUpstream(); echo = await startEcho(); });
after(async () => { await up.close(); await echo.close(); });

const resolverAll = () => fakeResolver({ "api.example.com": [PUBLIC], "x.paste.example": [PUBLIC], "ok.example": [PUBLIC], "evil.example": [PUBLIC] });
async function proxyWith(policy, extra = {}) {
  const resolve = resolverAll();
  const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
  const p = await startProxy({}, { getState: stateOf(policy, extra), resolve, connect });
  return { ...p, resolve, connect };
}

const GH = { id: "gh-read", host: "api.example.com", port: 80, method: ["GET", "HEAD"], path: "/repos/acme/*", action: "allow" };

test("HTTP: an allow rule on host, port, method and path lets the request through to the checked address", async () => {
  const p = await proxyWith({ egressRules: [GH], egressDefault: "block" });
  try {
    const before = up.seen.length;
    const r = await viaProxy(p.port, "http://api.example.com/repos/acme/app?x=1");
    assert.equal(r.status, 200);
    assert.equal(r.body, "ok GET /repos/acme/app?x=1");
    const got = up.seen[before];
    assert.equal(got.headers.host, "api.example.com");
    assert.deepEqual(p.connect.calls, [{ host: PUBLIC, port: 80 }]);
    assert.equal(p.reports.length, 0, "an allow raises no alert");
  } finally { await p.close(); }
});

test("HTTP: the method and the path of a request are judged (POST and another path fall to the block default)", async () => {
  const p = await proxyWith({ egressRules: [GH], egressDefault: "block" });
  try {
    const before = up.seen.length;
    const post = await viaProxy(p.port, "http://api.example.com/repos/acme/app", { method: "POST", body: "{}" });
    assert.equal(post.status, 403);
    assert.match(post.body, /egress to api\.example\.com:80 is blocked by egressDefault/);
    const other = await viaProxy(p.port, "http://api.example.com/orgs/acme");
    assert.equal(other.status, 403);
    // dot segments are resolved before the path is judged, and the resolved path is what goes upstream
    const dots = await viaProxy(p.port, "http://api.example.com/repos/acme/../../orgs/acme");
    assert.equal(dots.status, 403);
    const inside = await viaProxy(p.port, "http://api.example.com/repos/x/../acme/app");
    assert.equal(inside.status, 200);
    assert.equal(up.seen.at(-1).url, "/repos/acme/app");
    assert.equal(up.seen.length, before + 1, "only the allowed request reached the upstream");
    assert.equal(p.connect.calls.length, 1, "no upstream connection for a blocked request");
  } finally { await p.close(); }
});

test("HTTP: a block rule refuses; the default allows the rest; the alert is content-free", async () => {
  const p = await proxyWith({ egressRules: [{ id: "no-paste", host: "*.paste.example", action: "block" }], egressDefault: "allow" });
  try {
    const r = await viaProxy(p.port, "http://x.paste.example/secret-path/doc?token=hunter2");
    assert.equal(r.status, 403);
    assert.match(r.body, /egress rule "no-paste"/);
    const ok = await viaProxy(p.port, "http://ok.example/");
    assert.equal(ok.status, 200);
    assert.equal((await viaProxy(p.port, "http://x.paste.example/other")).status, 403);
    assert.equal(p.reports.length, 1, "a repeat of the same alert within a minute is not posted again");
    const a = p.reports[0];
    assert.equal(a.reasonCode, "EGRESS_RULE");
    assert.equal(a.decision, "deny");
    assert.equal(a.egressHost, "x.paste.example");
    assert.equal(a.egressPort, 80);
    assert.equal(a.egressMethod, "GET");
    assert.equal(a.egressBinary, null);
    assert.equal(a.egressRuleId, "no-paste");
    assert.equal(a.tool, "egress-proxy");
    const wire = JSON.stringify(a);
    assert.ok(!wire.includes("secret-path") && !wire.includes("hunter2") && !wire.includes("token"), wire);
  } finally { await p.close(); }
});

test("HTTP: Host is the judged host, and Proxy-Authorization and hop-by-hop headers never go upstream", async () => {
  const p = await proxyWith({ egressRules: [GH], egressDefault: "block" });
  try {
    const before = up.seen.length;
    const r = await viaProxy(p.port, "http://api.example.com/repos/acme/app", { headers: { host: "evil.example", "proxy-authorization": "Bearer nope-nope-nope-nope", connection: "x-drop-me", "x-drop-me": "1", "x-keep": "1" } });
    assert.equal(r.status, 200);
    const h = up.seen[before].headers;
    assert.equal(h.host, "api.example.com");
    assert.equal(h["proxy-authorization"], undefined);
    assert.equal(h["x-drop-me"], undefined);
    assert.equal(h["x-keep"], "1");
  } finally { await p.close(); }
});

test("CONNECT: allowed by host and port, the tunnel carries bytes both ways to the checked address", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", port: 443, action: "allow" }], egressDefault: "block" });
  try {
    const c = await connectVia(p.port, "api.example.com:443");
    assert.equal(c.status, 200);
    assert.equal(await echoOnce(c.socket, "ping-through-tunnel"), "ping-through-tunnel");
    c.socket.destroy();
    assert.deepEqual(p.connect.calls, [{ host: PUBLIC, port: 443 }]);
  } finally { await p.close(); }
});

test("CONNECT: blocked by port, by host, and by a block rule on the destination", async () => {
  const p = await proxyWith({ egressRules: [{ host: "evil.example", action: "block" }, { host: "api.example.com", port: 443, action: "allow" }], egressDefault: "block" });
  try {
    assert.equal((await connectVia(p.port, "api.example.com:8443")).status, 403, "port not in the rule");
    assert.equal((await connectVia(p.port, "ok.example:443")).status, 403, "host not in any rule");
    const evil = await connectVia(p.port, "evil.example:443");
    assert.equal(evil.status, 403);
    assert.match(evil.body, /egress rule \(policy#0\)/);
    assert.equal(p.connect.calls.length, 0);
    assert.ok(p.reports.every((a) => a.egressMethod === null), "CONNECT has no method");
  } finally { await p.close(); }
});

test("CONNECT: method and path are unknown, so an allow rule that sets them does not match (and a block rule that sets them does)", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", method: "GET", action: "allow" }, { host: "ok.example", path: "/upload*", action: "block" }], egressDefault: "allow" });
  try {
    const p2 = await proxyWith({ egressRules: [{ host: "api.example.com", method: "GET", action: "allow" }], egressDefault: "block" });
    try { assert.equal((await connectVia(p2.port, "api.example.com:443")).status, 403); } finally { await p2.close(); }
    assert.equal((await connectVia(p.port, "ok.example:443")).status, 403, "a block rule with a path matches a tunnel");
    const c = await connectVia(p.port, "api.example.com:443");
    assert.equal(c.status, 200);
    c.socket.destroy();
  } finally { await p.close(); }
});

test("binary: a binary-scoped allow rule does not allow at the network layer, over HTTP or CONNECT", async () => {
  const p = await proxyWith({ egressRules: [{ binary: "curl", host: "api.example.com", action: "allow" }], egressDefault: "block" });
  try {
    assert.equal((await viaProxy(p.port, "http://api.example.com/repos/acme/app")).status, 403);
    assert.equal((await connectVia(p.port, "api.example.com:443")).status, 403);
    assert.equal(p.connect.calls.length, 0);
  } finally { await p.close(); }
});

test("binary: a binary-scoped block rule still blocks on the destination alone", async () => {
  const p = await proxyWith({ egressRules: [{ binary: "curl", host: "api.example.com", action: "block" }], egressDefault: "allow" });
  try {
    assert.equal((await viaProxy(p.port, "http://api.example.com/")).status, 403);
    assert.equal((await connectVia(p.port, "api.example.com:443")).status, 403);
  } finally { await p.close(); }
});

test("binary: a binary-scoped alert rule reports but cannot open a host the block default closes", async () => {
  const rules = [{ id: "curl-watch", binary: "curl", host: "api.example.com", action: "alert" }];
  const shut = await proxyWith({ egressRules: rules, egressDefault: "block" });
  try {
    const r = await viaProxy(shut.port, "http://api.example.com/");
    assert.equal(r.status, 403);
    assert.equal((await connectVia(shut.port, "api.example.com:443")).status, 403);
  } finally { await shut.close(); }
  const open = await proxyWith({ egressRules: rules, egressDefault: "allow" });
  try {
    assert.equal((await viaProxy(open.port, "http://api.example.com/")).status, 200);
    assert.equal(open.reports.length, 1);
    assert.equal(open.reports[0].egressAction, "alert");
    assert.equal(open.reports[0].decision, "allow");
  } finally { await open.close(); }
});

test("sources: the machine-wide config's rules apply, and a profile's rules apply only to the workload it names", async () => {
  const sys = await proxyWith(null, { system: { egressRules: [{ host: "evil.example", action: "block" }] } });
  try {
    assert.equal((await viaProxy(sys.port, "http://evil.example/")).status, 403);
    assert.equal((await viaProxy(sys.port, "http://ok.example/")).status, 200);
  } finally { await sys.close(); }
  const policy = { workloadProfiles: [{ id: "agent", match: { serviceId: "agent-1" }, egressRules: [{ host: "api.example.com", action: "allow" }], egressDefault: "block" }] };
  const named = await proxyWith(policy, { serviceId: "agent-1" });
  try {
    assert.equal((await viaProxy(named.port, "http://api.example.com/")).status, 200);
    assert.equal((await viaProxy(named.port, "http://ok.example/")).status, 403);
  } finally { await named.close(); }
  const other = await proxyWith(policy, { serviceId: "someone-else" });
  try { assert.equal((await viaProxy(other.port, "http://ok.example/")).status, 200); } finally { await other.close(); }
});

test("coach: on an unenrolled device a rule block is reported as coach and forwarded", async () => {
  const p = await proxyWith({ egressRules: [{ host: "evil.example", action: "block" }] }, { coach: true });
  try {
    assert.equal((await viaProxy(p.port, "http://evil.example/")).status, 200);
    assert.equal(p.reports[0].decision, "coach");
    assert.equal(p.reports[0].enforcement, "LIMITED");
  } finally { await p.close(); }
});

test("a policy that cannot be loaded refuses the connection", async () => {
  const p = await startProxy({}, { getState: async () => { throw new Error("no"); }, resolve: resolverAll(), connect: fakeConnect({ httpPort: up.port, echoPort: echo.port }) });
  try {
    assert.equal((await viaProxy(p.port, "http://ok.example/")).status, 503);
    assert.equal((await connectVia(p.port, "ok.example:443")).status, 503);
  } finally { await p.close(); }
});

// egress-proxy/policy.mjs with an injected loader, posture, clock and reporter: what the proxy holds when
// loadVerifiedPolicy throws.
function policySource({ load, posture }) {
  const clock = { t: 1000 }, reports = [];
  const src = createPolicySource({ load: () => load(), posture: () => ({ posture: posture() }), system: () => null, report: (...a) => reports.push(a), now: () => clock.t });
  return { ...src, clock, reports };
}
const THROWS = async () => { throw new Error("loader failed"); };
const settle = () => new Promise((r) => setImmediate(r));

for (const posture of ["fail-closed", "fail-open"]) {
  test(`policy: a FIRST load that throws is not a loaded state; the proxy answers 503 until a load succeeds (${posture})`, async () => {
    let load = THROWS;
    const src = policySource({ load: () => load(), posture: () => posture });
    await assert.rejects(src.getState(), /could not be loaded/);
    const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
    const p = await startProxy({}, { getState: src.getState, resolve: resolverAll(), connect });
    try {
      assert.equal((await viaProxy(p.port, "http://ok.example/")).status, 503);
      assert.equal((await connectVia(p.port, "ok.example:443")).status, 503);
      assert.equal(connect.calls.length, 0, "never connected");
      load = async () => ({ policy: { egressDefault: "allow" }, rejected: [] });
      assert.equal((await viaProxy(p.port, "http://ok.example/")).status, 200, "the next connection retries the load");
    } finally { await p.close(); }
  });
}

test("policy: the posture ratchet runs when a refresh throws: a fail-closed device holding no policy gets OFFLINE_DEFAULT_POLICY and enforces", async () => {
  let load = async () => ({ policy: null, rejected: [] }), posture = "fail-open";
  const src = policySource({ load: () => load(), posture: () => posture });
  const first = await src.getState();
  assert.equal(first.policy, null);
  assert.equal(first.coach, true, "an unenrolled fail-open device coaches");
  load = THROWS; posture = "fail-closed"; src.clock.t += 60000;
  await src.getState(); await settle();
  const after = await src.getState();
  assert.equal(after.policy, OFFLINE_DEFAULT_POLICY);
  assert.equal(after.coach, false, "a fail-closed device enforces");
  assert.ok(src.reports.some((r) => r[1] === "offline:fail-closed"));
});

test("policy: a refresh that throws keeps a verified policy it already holds", async () => {
  const held = { egressDefault: "block" };
  let load = async () => ({ policy: held, rejected: [] });
  const src = policySource({ load: () => load(), posture: () => "fail-closed" });
  assert.equal((await src.getState()).policy, held);
  load = THROWS; src.clock.t += 60000;
  await src.getState(); await settle();
  assert.equal((await src.getState()).policy, held);
});
