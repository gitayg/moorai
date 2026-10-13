// The HTTP MCP gateway's admin-chosen fail mode (cli/fail-mode.mjs surface "mcpGateway", via
// mcp-gateway/fail.mjs), driven through a real gateway process, the fake remote server and a fake console
// serving a SIGNED policy. The faults come from test hooks: MOORAI_TEST_GATECALL_THROW (the call gate
// throws), MOORAI_TEST_RESULTSCAN_THROW and MOORAI_TEST_RESULT_STALL_MS (the stdio guard's names: the
// result scan throws / stalls past CAPS.resultDeadlineMs).
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-fail-mode.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { scenario, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";

const V = "ARG-VALUE-not-for-alerts-77";
const CLOSED = { captureTier: "content-free", failMode: { mcpGateway: "closed" } };
const CLOSED_DEFAULT = { captureTier: "content-free", failMode: { default: "closed" } };
const OPEN_EXPLICIT = { captureTier: "content-free", failMode: { mcpGateway: "open", default: "closed" } };
const ABSENT = { captureTier: "content-free" };
const isFailBlock = (m, kind = "call") => Boolean(m && m.result && m.result.isError === true && new RegExp(`^MoorAI blocked this MCP tool ${kind}: not evaluated \\(`).test(String(m.result.content?.[0]?.text)));
const failAlerts = (con, stage) => con.alerts.filter((a) => a.reasonCode === "FAIL_CLOSED" && a.stage === stage);
async function until(fn, ms = 5000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await settle(100); } return false; }

test("CALL, closed: a tools/call the gate failed on is refused and never reaches the upstream; one content-free alert", async () => {
  for (const policy of [CLOSED, CLOSED_DEFAULT]) {
    await scenario({ policy, env: { MOORAI_TEST_GATECALL_THROW: "1" } }, async ({ con, up, base }) => {
      const r = await rpc(base, call(7, "echo", { a: V }));
      assert.equal(r.status, 200);
      assert.equal(r.json.id, 7);
      assert.ok(isFailBlock(r.json), `refused with a fail-closed tool error: ${r.text.slice(0, 200)}`);
      assert.match(r.json.result.content[0].text, /your organization blocks what MoorAI cannot evaluate/);
      assert.deepEqual(up.calls(), [], "the unevaluated call reached the upstream");
      assert.ok(await until(() => failAlerts(con, "mcp").length), `alerts: ${JSON.stringify(con.alerts.map((a) => a.category))}`);
      const a = failAlerts(con, "mcp")[0];
      assert.deepEqual([a.category, a.riskLevel, a.decision, a.tool, a.mcpServer, a.failMode, a.failModeSource, a.failWhy, a.enforcement, a.basisCode],
        ["Fail-closed: MCP call not evaluated", "Blocked", "deny", "gateway:echo", "remote", "closed", "policy", "error", "STRENGTHENED", "UNEVALUATED_HOOK_ERROR"]);
      assert.ok(!JSON.stringify(con.alerts).includes(V), "an argument value left in an alert");
    });
  }
});

test("CALL, open (explicit, and no failMode at all): the same faulted call is forwarded as before", async () => {
  for (const policy of [OPEN_EXPLICIT, ABSENT]) {
    await scenario({ policy, env: { MOORAI_TEST_GATECALL_THROW: "1" } }, async ({ con, up, base }) => {
      const r = await rpc(base, call(8, "echo", { a: V }));
      assert.equal(r.json.result.isError, false, `forwarded under ${JSON.stringify(policy)}: ${r.text.slice(0, 200)}`);
      assert.equal(up.calls().length, 1, "the upstream did not receive the call");
      await settle();
      assert.equal(failAlerts(con, "mcp").length, 0);
    });
  }
});

test("CALL, closed but unenrolled (coach): forwarded, as every other gateway block is when unenrolled", async () => {
  await scenario({ policy: CLOSED, enrolled: false, env: { MOORAI_TEST_GATECALL_THROW: "1" } }, async ({ up, base }) => {
    const r = await rpc(base, call(9, "echo", { a: V }));
    assert.equal(r.json.result.isError, false, r.text.slice(0, 200));
    assert.equal(up.calls().length, 1);
  });
});

test("CALL, closed: a fail-closed refusal does not count toward the client's cool-down", async () => {
  await scenario({ policy: CLOSED, env: { MOORAI_TEST_GATECALL_THROW: "1" }, gatewayArgs: ["--cooldown-refusals", "2", "--cooldown-seconds", "60"] }, async ({ base }) => {
    for (let i = 1; i <= 4; i++) {
      const r = await rpc(base, call(i, "echo", { a: V }));
      assert.ok(isFailBlock(r.json), `call ${i}: ${r.text.slice(0, 200)}`);
      assert.doesNotMatch(r.text, /cool-down/, `call ${i} was refused by a cool-down`);
    }
  });
});

test("RESULT, closed: a result the scan threw on or did not finish in time is replaced (JSON and SSE); open forwards it", async () => {
  for (const mode of ["json", "sse"]) {
    for (const env of [{ MOORAI_TEST_RESULTSCAN_THROW: "1" }, { MOORAI_TEST_RESULT_STALL_MS: "1500" }]) {
      await scenario({ policy: CLOSED, env, upstream: { mode } }, async ({ con, up, base }) => {
        const r = await rpc(base, call(3, "echo", { a: V }));
        const m = mode === "sse" ? sseMessages(r.text).find((x) => x.id === 3) : r.json;
        assert.ok(isFailBlock(m, "result"), `closed ${mode} ${JSON.stringify(env)}: ${r.text.slice(0, 300)}`);
        assert.equal(up.calls().length, 1, "the call itself was gated normally and forwarded");
        assert.ok(await until(() => failAlerts(con, "result").length), `alerts: ${JSON.stringify(con.alerts.map((a) => a.category))}`);
        const a = failAlerts(con, "result")[0];
        assert.deepEqual([a.category, a.tool, a.mcpServer, a.failWhy], ["Fail-closed: MCP result not evaluated", "gateway:echo", "remote", env.MOORAI_TEST_RESULTSCAN_THROW ? "error" : "timeout"]);
      });
      await scenario({ policy: ABSENT, env, upstream: { mode } }, async ({ con, base }) => {
        const r = await rpc(base, call(3, "echo", { a: V }));
        const m = mode === "sse" ? sseMessages(r.text).find((x) => x.id === 3) : r.json;
        assert.equal(m?.result?.isError, false, `open ${mode} ${JSON.stringify(env)}: ${r.text.slice(0, 300)}`);
        assert.ok(String(m.result.content[0].text).includes(V), "the upstream's own result was not forwarded");
        await settle();
        assert.equal(failAlerts(con, "result").length, 0);
      });
    }
  }
});

function sseMessages(text) {
  const out = [];
  for (const block of String(text).split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/).filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
    if (!data) continue;
    try { out.push(JSON.parse(data)); } catch { /* not a message */ }
  }
  return out;
}
