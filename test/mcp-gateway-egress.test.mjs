// F23 proxy-side egress at the HTTP MCP gateway: (1) the egress rules judge every destination a tools/call's
// arguments name, the same function and the same verdict as the hook for mcp__<route>__<tool>; (2) the
// gateway's own upstream connection is judged by host, port, method and path, and a cidr rule by the
// address the gateway actually connects to (checked in the socket's DNS lookup, so no second answer can
// redirect it). A real gateway process, the fake remote server and a fake console serving a SIGNED policy.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-egress.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { scenario, startConsole, makeHome, sign, startGateway, stopGateway, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";
import { startUpstream } from "../mcp-gateway/test/fake-upstream.mjs";
import { evaluateProfile } from "../cli/workload-profile.mjs";

const RFC1918 = { id: "rfc1918", cidr: ["10.0.0.0/8"], action: "block" };
const policy = (rules, extra = {}) => ({ captureTier: "content-free", egressRules: rules, ...extra });
const egressAlerts = (con) => con.alerts.filter((a) => a.reasonCode === "EGRESS_RULE");

test("tools/call arguments: a destination inside a cidr block rule is refused at the gateway, as the hook refuses the same call", async () => {
  const pol = policy([RFC1918]);
  await scenario({ policy: pol }, async ({ con, up, base }) => {
    const ok = await rpc(base, call(1, "fetch", { url: "https://example.com/a" }));
    assert.equal(ok.json.result.isError, false);
    const r = await rpc(base, call(2, "fetch", { url: "http://10.1.2.3/admin?token=SECRET-ARG" }));
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /egress to 10\.1\.2\.3:80 by mcp__remote__fetch is blocked by egress rule "rfc1918"/);
    assert.deepEqual(up.calls().map((c) => c.json.id), [1], "the refused call never reached the upstream");
    // The hook's verdict for the same call, by the same function.
    const hook = evaluateProfile({ policy: pol, tool: "mcp__remote__fetch", toolInput: { url: "http://10.1.2.3/admin?token=SECRET-ARG" } });
    assert.equal(hook.decision, "deny");
    assert.equal(hook.reasonCode, "EGRESS_RULE");
    await settle();
    const a = egressAlerts(con);
    assert.equal(a.length, 1);
    assert.deepEqual([a[0].egressHost, a[0].egressRuleId, a[0].decision, a[0].egressBinary], ["10.1.2.3", "rfc1918", "deny", "mcp__remote__fetch"]);
    assert.ok(!JSON.stringify(con.alerts).includes("SECRET-ARG"), "argument text reached an alert");
  });
});

test("upstream connection: an IP-literal route inside a cidr block rule is refused before any byte goes upstream", async () => {
  await scenario({ policy: policy([{ id: "no-loopback", cidr: "127.0.0.0/8", action: "block" }]) }, async ({ con, up, base }) => {
    const r = await rpc(base, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    assert.equal(r.status, 403);
    assert.match(r.json.error.message, /egress to 127\.0\.0\.1:\d+ is blocked by egress rule "no-loopback"/);
    assert.equal(up.received.length, 0);
    await settle();
    assert.ok(egressAlerts(con).some((a) => a.egressRuleId === "no-loopback" && a.egressLayer === "network"));
  });
});

test("upstream connection: a route by name is judged on the address its DNS lookup returns (cidr), and a host rule on the name", async () => {
  const up = await startUpstream();
  const port = new URL(up.url).port;
  try {
  for (const [rules, want] of [
    [[{ id: "no-loopback", cidr: ["127.0.0.0/8", "::1/128"], action: "block" }], 403],
    [[{ id: "by-name", host: "localhost", method: "POST", path: "/mcp", action: "block" }], 403],
    [[{ id: "other-path", host: "localhost", path: "/other", action: "block" }], 200]
  ]) {
    const con = await startConsole(sign(policy(rules)));
    const home = makeHome(con.url, true);
    const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/byname=http://localhost:${port}/mcp`] });
    try {
      assert.ok(gw.url, gw.stderr);
      const before = up.received.length;
      const r = await rpc(`${gw.url}/byname`, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
      assert.equal(r.status, want, `${JSON.stringify(rules)} -> ${r.text}`);
      if (want === 403) {
        assert.match(r.json.error.message, new RegExp(`egress rule "${rules[0].id}"`));
        assert.equal(up.received.length, before, "nothing reached the upstream");
      }
    } finally { await stopGateway(gw); await con.close(); rmSync(home, { recursive: true, force: true }); }
  }
  } finally { await up.close(); }
});
