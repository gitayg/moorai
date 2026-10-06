// MCP usage from the HTTP gateway end to end (CONTRACT C4): a real gateway process in server mode, a fake
// remote MCP server and a fake console. Calls through the gateway are counted per server and per tool
// name in the gateway's tally; when the day is over (simulated by moving the tally's day back one, as a
// real midnight would leave it) the next gateway start posts exactly the C4 body, once.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-usage.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { scenario, startConsole, makeHome, sign, serverModeEnv, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";

const SECRET_ARG = "ARG-VALUE-must-not-leave-7f3a";
const POLICY = { captureTier: "content-free", threatPolicy: { 39: "block" } };
const AWS = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\n";
const today = () => new Date().toISOString().slice(0, 10);
const yesterday = () => new Date(Date.now() - 86400000).toISOString().slice(0, 10);
const tallyPath = (home) => join(home, ".moorai", "mcp-usage.json");

// Rewrites the tally as if the day had ended: today's entries become yesterday's.
function endTheDay(home) {
  const t = JSON.parse(readFileSync(tallyPath(home), "utf8"));
  for (const k of ["days", "tools"]) if (t[k] && t[k][today()]) { t[k][yesterday()] = t[k][today()]; delete t[k][today()]; }
  writeFileSync(tallyPath(home), JSON.stringify(t));
}

test("GATEWAY USAGE: per-server + per-tool counts, posted once after the day ends, exact C4 body, server-mode identity, no arguments", async () => {
  const con = await startConsole(sign(POLICY));
  const home = makeHome(con.url);
  const env = serverModeEnv(con.url, "gw-usage-svc");
  try {
    await scenario({ con, home, env }, async ({ base }) => {
      for (let i = 0; i < 3; i++) assert.equal((await rpc(base, call(i + 1, "create_issue", { body: SECRET_ARG }))).json.result.isError, false);
      await rpc(base, call(10, "search_code", { q: SECRET_ARG }));
      // A refused call is counted too (the proxy and the hook count blocked or not).
      const refused = await rpc(base, call(11, "send_note", { body: AWS }));
      assert.equal(refused.json.result.isError, true);
      // Not a tools/call: not counted.
      await rpc(base, { jsonrpc: "2.0", id: 12, method: "tools/list", params: {} });
      await settle(300);
      const t = JSON.parse(readFileSync(tallyPath(home), "utf8"));
      assert.deepEqual(t.days[today()], { "gateway|gateway": { remote: 5 } });
      assert.deepEqual(t.tools[today()]["gateway|gateway"].remote.c, { create_issue: 3, search_code: 1, send_note: 1 });
      assert.equal(con.usage.length, 0, "today's partial day was posted");
    });
    const tallyText = readFileSync(tallyPath(home), "utf8");
    assert.ok(!tallyText.includes(SECRET_ARG) && !tallyText.includes("AKIAIOSFODNN7EXAMPLE"), "argument text reached the tally");

    endTheDay(home);
    await scenario({ con, home, env }, async () => {
      for (let i = 0; i < 50 && !con.usage.length; i++) await settle(100);
    });
    assert.equal(con.usage.length, 1, "the completed day was not posted on the next start");
    const { token, raw, body } = con.usage[0];
    assert.equal(token, "tok");
    assert.match(body.actor, /^h2:/);
    assert.deepEqual({ ...body, actor: "h2" }, {
      user: "service", device: "svc:gw-usage-svc", platform: process.platform, actor: "h2",
      day: yesterday(), path: "gateway", host: "gateway",
      servers: [{ label: "remote", calls: 5, tools: [{ name: "create_issue", calls: 3 }, { name: "search_code", calls: 1 }, { name: "send_note", calls: 1 }] }]
    });
    assert.ok(!raw.includes(SECRET_ARG) && !raw.includes("AKIA"), "argument text reached the console");
    assert.ok(existsSync(join(home, ".moorai", "mcp-usage-gateway-gateway.sent.json")));

    // A third start the same day posts nothing more.
    await scenario({ con, home, env }, async () => { await settle(800); });
    assert.equal(con.usage.length, 1, "a completed day was posted twice");
  } finally {
    await con.close();
    rmSync(home, { recursive: true, force: true });
  }
});

test("GATEWAY USAGE: more than 64 tools on one server post the 64 busiest with toolsTruncated", async () => {
  const con = await startConsole(sign(POLICY));
  const home = makeHome(con.url);
  const env = serverModeEnv(con.url, "gw-trunc");
  try {
    await scenario({ con, home, env }, async ({ base }) => {
      const reqs = [];
      for (let i = 0; i < 66; i++) reqs.push(rpc(base, call(i + 1, `tool_${String(i).padStart(2, "0")}`, {})));
      await Promise.all(reqs);
      for (let i = 0; i < 2; i++) await rpc(base, call(100 + i, "tool_65", {}));
      await settle(400);
    });
    endTheDay(home);
    await scenario({ con, home, env }, async () => { for (let i = 0; i < 50 && !con.usage.length; i++) await settle(100); });
    const s = con.usage[0].body.servers[0];
    assert.equal(s.calls, 68);
    assert.equal(s.tools.length, 64);
    assert.deepEqual(s.tools[0], { name: "tool_65", calls: 3 });
    assert.equal(s.toolsTruncated, true);
  } finally {
    await con.close();
    rmSync(home, { recursive: true, force: true });
  }
});

test("GATEWAY USAGE: unenrolled, nothing is posted (the tally still counts locally)", async () => {
  await scenario({ enrolled: false }, async ({ base, con, home }) => {
    await rpc(base, call(1, "echo", {}));
    await settle(300);
    assert.ok(existsSync(tallyPath(home)));
    assert.equal(con.usage.length, 0);
  });
});
