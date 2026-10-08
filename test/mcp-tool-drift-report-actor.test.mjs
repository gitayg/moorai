// The block-mode fingerprint report (POST /api/mcp/tools) names its reporting device. The install token
// is per tenant, so without a device id the console could only keep the LAST report and an approval
// pinned whatever the last device said (console: server/mcp-tool-baseline.js, test/mcp-tool-drift-
// reporters.test.js). The id is the same content-free actor hash every alert already carries
// (cli/content-hash.mjs actorHash: a hash of user@host, never the names). Through the stdio guard and
// the HTTP gateway.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-drift-report-actor.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { rmTree } from "./fs-cleanup.mjs";
import { startConsole, makeHome, startGuard, ADD, ECHO, BLOCK, settle, unchecked } from "./tool-drift-helpers.mjs";
import { writeFileSync } from "node:fs";
import { scenario, rpc, call } from "../mcp-gateway/test/harness.mjs";

// The actor hash is keyed per device, so the expected value is the one this process's own alerts carry.
const alertActor = (con) => { const a = con.alerts.find((x) => typeof x.actor === "string"); return a && a.actor; };
const fpOnly = (r) => r.tools.every((t) => Object.keys(t).sort().join(",") === "desc,key,schema,srv");

test("PROXY: the fingerprint report carries the device's actor hash and nothing else identifying", async () => {
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  try {
    const tools = join(home, "tools.json");
    writeFileSync(tools, JSON.stringify([ADD, ECHO]));
    const g = startGuard({ home, url: con.url, serverEnv: { FAKE_TOOLS_FILE: tools }, recvLog: join(home, "recv.log") });
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await g.list();
      await settle();
    } finally { await g.close(); }
    const rep = con.toolReports.find((r) => r.server === "testsrv");
    assert.ok(rep, "no fingerprint report");
    assert.match(String(rep.actor), /^h2:[0-9a-f]{16}$/, `the report does not name its device: ${JSON.stringify(Object.keys(rep))}`);
    assert.equal(rep.actor, alertActor(con), "the report's device id is not the one the same process's alerts carry");
    assert.deepEqual(Object.keys(rep).sort(), ["actor", "server", "tools"]);
    assert.ok(fpOnly(rep));
  } finally { await con.close(); rmTree(home); }
});

test("GATEWAY: the fingerprint report carries the device's actor hash", async () => {
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  try {
    await scenario({ con, home, upstream: { tools: [ADD, ECHO] }, env: { MOORAI_TEST_POLICY_REFRESH_MS: "0" } }, async ({ base }) => {
      await rpc(base, call(1, "__prime__"));
      await rpc(base, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
      await settle();
    });
    const rep = con.toolReports.find((r) => r.server === "remote");
    assert.ok(rep, "no fingerprint report");
    assert.match(String(rep.actor), /^h2:[0-9a-f]{16}$/, `the report does not name its device: ${JSON.stringify(Object.keys(rep))}`);
    assert.equal(rep.actor, alertActor(con), "the report's device id is not the one the same process's alerts carry");
    assert.deepEqual(Object.keys(rep).sort(), ["actor", "server", "tools"]);
  } finally { await con.close(); rmTree(home); }
});
