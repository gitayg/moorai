// moorai-egress-proxy: two hardenings.
//   1. A special address (loopback, private, link-local, ULA, metadata) is unlocked only by a rule whose host
//      is an exact name or an IP literal, never by a `*.suffix` rule. Cloud metadata needs a rule naming that
//      exact IP. The proxy's own port and the MoorAI sibling ports on a local address are always refused.
//   2. The request path is canonicalised before it is judged, and the canonical string is what goes
//      upstream: unreserved escapes decoded, other escapes upper-case, %2F %5C %00 %25 and a raw backslash
//      refused, dot segments resolved after decoding.
// Injected resolver and connector (egress-proxy/test/harness.mjs): no test reaches the real network.
//
//   node --test --import ./test/hermetic-env.mjs test/egress-proxy-harden.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startUpstream, startEcho, fakeResolver, fakeConnect, startProxy, stateOf, viaProxy, connectVia } from "../egress-proxy/test/harness.mjs";
import { judgeConnection, networkTarget } from "../egress-proxy/judge.mjs";
import { parseConfig } from "../egress-proxy/config.mjs";

const PUBLIC = "93.184.216.34";
let up, echo;
before(async () => { up = await startUpstream(); echo = await startEcho(); });
after(async () => { await up.close(); await echo.close(); });

const TABLE = {
  "pub.example.com": [PUBLIC],
  "ten.example.com": ["10.0.0.5"],
  "lo.example.com": ["127.0.0.1"],
  "meta.example.com": ["169.254.169.254"],
  "ula.example.com": ["fd00::1"],
  "ec2v6.example.com": ["fd00:ec2::254"],
  "mapped.example.com": ["::ffff:169.254.169.254"],
  "api.example.com": [PUBLIC],
  localhost: ["127.0.0.1"],
  "pod.example": ["10.1.2.3"],
  "mapped-lo.example": ["::ffff:127.0.0.1"]
};
async function proxyWith(policy, { cfg = {}, extra = {}, deps = {} } = {}) {
  const resolve = fakeResolver(TABLE);
  const connect = fakeConnect({ httpPort: up.port, echoPort: echo.port });
  const p = await startProxy(cfg, { getState: stateOf(policy, extra), resolve, connect, localAddresses: () => [], ...deps });
  return { ...p, resolve, connect };
}
const PRIVATE_NAMES = ["ten.example.com", "lo.example.com", "meta.example.com", "ula.example.com", "ec2v6.example.com", "mapped.example.com"];

// ------------------------------------------------------------------------------------------------------
// 1. Special addresses
// ------------------------------------------------------------------------------------------------------

test("wildcard: a *.suffix allow or alert rule never unlocks a name that resolves to a private, loopback or metadata address", async () => {
  for (const action of ["allow", "alert"]) {
    for (const coach of [false, true]) {
      const p = await proxyWith({ egressRules: [{ host: "*.example.com", action }], egressDefault: "block" }, { extra: { coach } });
      try {
        assert.equal((await viaProxy(p.port, "http://pub.example.com/")).status, 200, "a wildcard still allows a public address");
        for (const host of PRIVATE_NAMES) {
          const r = await viaProxy(p.port, `http://${host}/`);
          assert.equal(r.status, 403, `${host} ${action} coach=${coach}`);
          assert.match(r.body, /exact|metadata/, host);
          assert.equal((await connectVia(p.port, `${host}:443`)).status, 403, `CONNECT ${host} ${action} coach=${coach}`);
        }
        assert.deepEqual(p.connect.calls, [{ host: PUBLIC, port: 80 }], `only the public address was connected (${action}, coach=${coach})`);
        assert.ok(p.reports.some((a) => a.egressRefusal === "wildcard-private-address" && a.egressHost === "ten.example.com"));
      } finally { await p.close(); }
    }
  }
});

test("exact: a rule naming the exact host unlocks its private, loopback and ULA address; metadata needs a rule naming the IP", async () => {
  const names = PRIVATE_NAMES.map((host) => ({ host, action: "allow" }));
  const p = await proxyWith({ egressRules: [...names, { host: "169.254.169.254", action: "allow" }, { host: "[fd00:ec2::254]", action: "allow" }], egressDefault: "block" });
  try {
    for (const host of ["ten.example.com", "lo.example.com", "ula.example.com"]) assert.equal((await viaProxy(p.port, `http://${host}/`)).status, 200, host);
    for (const host of ["meta.example.com", "ec2v6.example.com", "mapped.example.com"]) {
      const r = await viaProxy(p.port, `http://${host}/latest/meta-data/`);
      assert.equal(r.status, 403, host);
      assert.match(r.body, /metadata/, host);
    }
    assert.equal((await viaProxy(p.port, "http://169.254.169.254/latest/meta-data/")).status, 200, "a rule naming the metadata IP unlocks it");
    assert.equal((await viaProxy(p.port, "http://[fd00:ec2::254]/latest/meta-data/")).status, 200, "a rule naming the IPv6 metadata IP unlocks it");
    assert.deepEqual(p.connect.calls.map((c) => c.host), ["10.0.0.5", "127.0.0.1", "fd00::1", "169.254.169.254", "fd00:ec2::254"]);
    assert.ok(p.reports.some((a) => a.egressRefusal === "metadata-address" && a.egressHost === "meta.example.com"));
  } finally { await p.close(); }
});

test("exact: a wildcard rule before an exact rule does not hide it; a block rule after a wildcard is not skipped", async () => {
  const p = await proxyWith({ egressRules: [{ host: "*.example.com", action: "allow" }, { host: "ten.example.com", action: "allow" }, { host: "lo.example.com", action: "block" }], egressDefault: "block" });
  try {
    assert.equal((await viaProxy(p.port, "http://ten.example.com/")).status, 200, "the later exact rule names it");
    assert.equal((await viaProxy(p.port, "http://lo.example.com/")).status, 403, "only a block rule names it");
    assert.equal((await viaProxy(p.port, "http://ula.example.com/")).status, 403, "only the wildcard matches");
  } finally { await p.close(); }
});

test("judge: exactHost is true only when an exact-host allow or alert rule grants the connection", () => {
  const t = (host) => networkTarget({ scheme: "connect", host, port: 443 });
  const wild = { egressRules: [{ host: "*.example.com", action: "allow" }], egressDefault: "block" };
  const v = judgeConnection(t("ten.example.com"), { policy: wild });
  assert.equal(v.explicit, true);
  assert.equal(v.exactHost, false);
  const exact = { egressRules: [{ host: "ten.example.com", action: "alert" }, { host: "10.0.0.9", action: "allow" }] };
  assert.equal(judgeConnection(t("ten.example.com"), { policy: exact }).exactHost, true);
  assert.equal(judgeConnection(t("10.0.0.9"), { policy: exact }).exactHost, true);
  assert.equal(judgeConnection(t("other.example.com"), { policy: exact }).exactHost, false, "the default is not a grant");
});

test("self and siblings: the proxy's own port and the MoorAI service ports on a local address are refused even with an exact rule", async () => {
  const rules = [{ host: "localhost", action: "allow" }, { host: "127.0.0.1", action: "allow" }, { host: "pod.example", action: "allow" }, { host: "mapped-lo.example", action: "allow" }];
  const p = await proxyWith({ egressRules: rules, egressDefault: "block" }, { deps: { localAddresses: () => ["10.1.2.3"] } });
  try {
    for (const url of [`http://localhost:${p.port}/`, `http://127.0.0.1:${p.port}/`]) {
      const r = await viaProxy(p.port, url);
      assert.equal(r.status, 403, url);
      assert.match(r.body, /egress proxy or a MoorAI service/, url);
    }
    assert.equal((await connectVia(p.port, `localhost:${p.port}`)).status, 403);
    for (const port of [8790, 8791, 8848, 8850]) {
      assert.equal((await viaProxy(p.port, `http://localhost:${port}/`)).status, 403, `sibling ${port}`);
      assert.equal((await connectVia(p.port, `127.0.0.1:${port}`)).status, 403, `CONNECT sibling ${port}`);
    }
    assert.equal((await viaProxy(p.port, "http://pod.example:8848/")).status, 403, "the pod's own interface address");
    assert.equal((await viaProxy(p.port, "http://mapped-lo.example:8791/")).status, 403, "IPv4-mapped loopback");
    assert.equal((await viaProxy(p.port, "http://pod.example/")).status, 200, "another port on the interface address");
    assert.equal((await viaProxy(p.port, `http://localhost:${up.port}/`)).status, 200, "another loopback port with an exact rule");
    const guarded = new Set([p.port, 8790, 8791, 8848, 8850]);
    assert.ok(p.connect.calls.every((c) => !guarded.has(c.port)), JSON.stringify(p.connect.calls));
    assert.ok(p.reports.some((a) => a.egressRefusal === "proxy-port"));
  } finally { await p.close(); }
});

test("self and siblings: the sibling list is configurable; the proxy's own port stays refused", async () => {
  const p = await proxyWith({ egressRules: [{ host: "localhost", action: "allow" }], egressDefault: "block" }, { cfg: { siblingPorts: [up.port] } });
  try {
    assert.equal((await viaProxy(p.port, `http://localhost:${up.port}/`)).status, 403, "a configured sibling port");
    assert.equal((await viaProxy(p.port, "http://localhost:8848/")).status, 200, "a default port the list no longer names");
    assert.equal((await viaProxy(p.port, `http://localhost:${p.port}/`)).status, 403, "the proxy's own port");
  } finally { await p.close(); }
  assert.deepEqual(parseConfig([], {}).siblingPorts, [8790, 8791, 8848, 8850]);
  assert.deepEqual(parseConfig(["--sibling-ports", "9000,9001"], {}).siblingPorts, [9000, 9001]);
  assert.deepEqual(parseConfig(["--sibling-ports", ""], {}).siblingPorts, []);
  for (const bad of ["0", "abc", "70000", "9000,,9001", "1.5"]) assert.throws(() => parseConfig(["--sibling-ports", bad], {}), /sibling-ports/, bad);
});

// ------------------------------------------------------------------------------------------------------
// 2. Path canonicalisation
// ------------------------------------------------------------------------------------------------------

test("path: encoding tricks against a /admin* block rule are refused 400 or judged on the decoded path", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", path: "/admin*", action: "block" }], egressDefault: "allow" });
  try {
    const seen = up.seen.length;
    for (const path of ["/%61dmin", "/%61%64%6D%69%6E/x", "/x/%2e%2e/admin", "/x/%2E%2E/admin", "/x/.%2E/admin", "/x/%2e./admin", "/x/./../admin", "//admin", "/x//..//admin"]) {
      const r = await viaProxy(p.port, `http://api.example.com${path}`);
      assert.equal(r.status, 403, path);
      assert.match(r.body, /egress rule \(policy#0\)/, path);
    }
    for (const path of ["/allowed%2F..%2Fadmin", "/x%2f..%2fadmin", "/x%5C..%5Cadmin", "/x%5c..%5cadmin", "/%2561dmin", "/x/%252e%252e/admin", "/x%00/admin", "/x/%zz", "/x/%4", "/x/..;/admin", "/x/.;/admin"]) {
      const r = await viaProxy(p.port, `http://api.example.com${path}`);
      assert.equal(r.status, 400, path);
      assert.match(r.body, /request path/, path);
    }
    // Node 22's HTTP parser passes a raw backslash through to the handler (measured), so the proxy refuses it.
    for (const url of ["http://api.example.com/x\\..\\admin", "http://api.example.com/x?q=a\\b"]) {
      const r = await viaProxy(p.port, url);
      assert.equal(r.status, 400, url);
      assert.match(r.body, /request path/, url);
    }
    assert.equal(up.seen.length, seen, "nothing reached the upstream");
    assert.ok(p.reports.some((a) => a.egressRefusal === "path-form" && a.egressHost === "api.example.com"));
    assert.ok(p.reports.every((a) => !JSON.stringify(a).includes("admin")), "alerts stay content-free");
  } finally { await p.close(); }
});

test("path: an allow rule does not widen through encoding, and the path that goes upstream is the judged one", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", path: "/allowed/*", action: "allow" }], egressDefault: "block" });
  try {
    for (const path of ["/allowed/%2e%2e/admin", "/allowed/%2E%2E/admin", "/allowed/.%2e/admin", "/allowed/./../admin", "/%61llowed/../admin"]) {
      assert.equal((await viaProxy(p.port, `http://api.example.com${path}`)).status, 403, path);
    }
    for (const path of ["/allowed%2F..%2Fadmin", "/allowed/..%2Fadmin", "/allowed/%2E%2E%2Fadmin", "/allowed/..%5Cadmin", "/allowed/%252e%252e/admin", "/allowed/..;/admin"]) {
      assert.equal((await viaProxy(p.port, `http://api.example.com${path}`)).status, 400, path);
    }
    // judged and forwarded: the same canonical string
    const cases = [
      ["/%61llowed/x", "/allowed/x"],
      ["/allowed/%7e%2D%5f%2E", "/allowed/~-_."],
      ["/allowed/a%3bb", "/allowed/a%3Bb"],
      ["/allowed/%c3%bc", "/allowed/%C3%BC"],
      ["/allowed//x/./y/../z", "/allowed/x/z"],
      ["/allowed/x/", "/allowed/x/"],
      ["/allowed/q?a=%2F&b=%61", "/allowed/q?a=%2F&b=%61"]
    ];
    for (const [sent, canonical] of cases) {
      const r = await viaProxy(p.port, `http://api.example.com${sent}`);
      assert.equal(r.status, 200, sent);
      assert.equal(up.seen.at(-1).url, canonical, `upstream saw the judged path for ${sent}`);
      assert.equal(r.body, `ok GET ${canonical}`);
    }
  } finally { await p.close(); }
});

test("path: rules are case-sensitive, and the case the client sent is the case that goes upstream", async () => {
  const p = await proxyWith({ egressRules: [{ host: "api.example.com", path: "/admin*", action: "block" }], egressDefault: "allow" });
  try {
    assert.equal((await viaProxy(p.port, "http://api.example.com/%41dmin")).status, 200);
    assert.equal(up.seen.at(-1).url, "/Admin", "%41 decodes to A; the rule does not match /Admin, and /Admin is what was forwarded");
  } finally { await p.close(); }
});

test("path: canonicalPath, directly", async () => {
  const { canonicalPath } = await import("../egress-proxy/path.mjs");
  const ok = {
    "/": "/", "/a/b": "/a/b", "/%61": "/a", "/a/%2e%2e/b": "/b", "/a/%2E/b": "/a/b", "/../..": "/", "/a/..": "/", "/a/.": "/a/",
    "//a///b//": "/a/b/", "/a%3a": "/a%3A", "/%7E%7e": "/~~", "/a b": "/a%20b", "/ü": "/%C3%BC", "/a|b": "/a|b", "/a;b=1/c": "/a;b=1/c"
  };
  for (const [raw, want] of Object.entries(ok)) assert.equal(canonicalPath(raw), want, raw);
  for (const bad of ["", "a", "/a\\b", "/a%2fb", "/a%2Fb", "/a%5cb", "/%00", "/%25", "/%2541", "/%", "/%g0", "/a/..;x/b", "/.;/b", "/a/%2e%2e;/b"]) assert.equal(canonicalPath(bad), null, bad);
});
