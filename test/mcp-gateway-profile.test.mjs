// Declared workload profiles enforced at the HTTP MCP gateway (cli/workload-profile.mjs via
// mcp-gateway/profile.mjs, CONTRACT C5 PROFILE_DRIFT). A real gateway process in server mode, the fake
// remote server (route label "remote") and a fake console serving a SIGNED policy. The tool is evaluated
// as mcp__<route>__<params.name>, exactly as the hook names the same call.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-gateway-profile.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scenario, startConsole, makeHome, sign, serverModeEnv, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";

const V = "ARG-VALUE-not-for-alerts-55";
const drift = (con) => con.alerts.filter((a) => a.reasonCode === "PROFILE_DRIFT");
const policyWith = (profiles) => ({ captureTier: "content-free", ...(profiles ? { workloadProfiles: profiles } : {}) });

async function run({ profiles, serviceId = "gw-bot", enrolled = true, extraEnv = {}, home: mkHome }, fn) {
  const con = await startConsole(sign(policyWith(profiles)));
  const home = makeHome(con.url, enrolled);
  if (mkHome) mkHome(home);
  try {
    await scenario({ con, home, env: serviceId ? { ...serverModeEnv(con.url, serviceId), ...extraEnv } : extraEnv }, (ctx) => fn({ ...ctx, con }));
  } finally { await con.close(); }
}

test("PROFILE block: a tool outside the profile is refused (tool error, never upstream); driftKind tool, content-free", async () => {
  const profiles = [{ id: "gw-block", match: { serviceId: "gw-bot" }, tools: ["mcp__remote__echo", "mcp__remote__search_*"], action: "block" }];
  await run({ profiles }, async ({ con, up, base }) => {
    assert.equal((await rpc(base, call(1, "echo", { a: V }))).json.result.isError, false, "an in-profile tool was refused");
    assert.equal((await rpc(base, call(2, "search_code", { q: V }))).json.result.isError, false, "a glob-matched tool was refused");
    const r = await rpc(base, call(3, "delete_repo", { repo: V }));
    assert.equal(r.json.id, 3);
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /outside the declared workload profile "gw-block" \(tool not in the profile\)/);
    assert.deepEqual(up.calls().map((c) => c.json.params.name), ["echo", "search_code"], "an out-of-profile call reached the upstream");
    await settle();
    const a = drift(con);
    assert.equal(a.length, 1, JSON.stringify(con.alerts.map((x) => x.category)));
    assert.deepEqual([a[0].driftKind, a[0].driftItem, a[0].profileId, a[0].decision, a[0].riskLevel, a[0].tool, a[0].mcpServer, a[0].device],
      ["tool", "mcp__remote__delete_repo", "gw-block", "deny", "Blocked", "gateway:delete_repo", "remote", "svc:gw-bot"]);
    assert.ok(!JSON.stringify(con.alerts).includes(V), "argument text reached an alert");
  });
});

test("PROFILE report: an MCP server outside the profile is forwarded and reported (driftKind mcpServer)", async () => {
  const profiles = [{ id: "gw-report", match: { serviceId: "gw-bot" }, mcpServers: ["github"], action: "report" }];
  await run({ profiles }, async ({ con, up, base }) => {
    const r = await rpc(base, call(1, "echo", { a: 1 }));
    assert.equal(r.json.result.isError, false);
    assert.equal(up.calls().length, 1);
    await settle();
    const a = drift(con);
    assert.equal(a.length, 1);
    assert.deepEqual([a[0].driftKind, a[0].driftItem, a[0].profileId, a[0].decision, a[0].riskLevel], ["mcpServer", "remote", "gw-report", "allow", "Medium"]);
  });
});

test("PROFILE block on mcpServer: a profile that lists other servers only refuses every call on this route", async () => {
  const profiles = [{ id: "gw-srv", match: { serviceId: "gw-bot" }, mcpServers: ["github"], action: "block" }];
  await run({ profiles }, async ({ con, up, base }) => {
    const r = await rpc(base, call(1, "echo", {}));
    assert.equal(r.json.result.isError, true);
    assert.match(r.json.result.content[0].text, /\(mcpServer not in the profile\)/);
    assert.equal(up.calls().length, 0);
    await settle();
    assert.equal(drift(con)[0].driftKind, "mcpServer");
  });
});

test("PROFILE none: no profiles in the policy, or none matching this workload — no effect", async () => {
  await run({ profiles: null }, async ({ con, up, base }) => {
    assert.equal((await rpc(base, call(1, "anything", {}))).json.result.isError, false);
    assert.equal(up.calls().length, 1);
    await settle();
    assert.equal(drift(con).length, 0);
  });
  await run({ profiles: [{ id: "other", match: { serviceId: "someone-else" }, tools: [], action: "block" }] }, async ({ con, up, base }) => {
    assert.equal((await rpc(base, call(1, "anything", {}))).json.result.isError, false);
    assert.equal(up.calls().length, 1);
    await settle();
    assert.equal(drift(con).length, 0);
  });
});

test("PROFILE trust: a profile in ~/.moorai/config.json or the environment is ignored", async () => {
  const planted = [{ id: "planted", match: { serviceId: "gw-bot" }, tools: [], action: "block" }];
  await run({
    profiles: null,
    extraEnv: { MOORAI_WORKLOAD_PROFILES: JSON.stringify(planted), workloadProfiles: JSON.stringify(planted) },
    home: (h) => writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ workloadProfiles: planted }))
  }, async ({ con, up, base }) => {
    assert.equal((await rpc(base, call(1, "echo", {}))).json.result.isError, false, "an untrusted profile was enforced");
    assert.equal(up.calls().length, 1);
    await settle();
    assert.equal(drift(con).length, 0);
  });
});

test("PROFILE unenrolled: a block profile coaches — forwarded, note on stderr naming the profile, nothing posted", async () => {
  const profiles = [{ id: "repo-block", match: { repo: "github:acme/app" }, tools: ["mcp__remote__echo"], action: "block" }];
  await run({
    profiles, serviceId: "", enrolled: false,
    home: (h) => { mkdirSync(join(h, ".git"), { recursive: true }); writeFileSync(join(h, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:Acme/App.git\n'); }
  }, async ({ con, up, gw, base }) => {
    const r = await rpc(base, call(1, "delete_repo", { repo: V }));
    assert.equal(r.json.result.isError, false, `an unenrolled device must not block: ${r.text}`);
    assert.equal(up.calls().length, 1);
    await settle(300);
    assert.match(gw.stderr, /outside the declared workload profile "repo-block"/, "no coach note");
    assert.ok(!gw.stderr.includes(V));
    assert.equal(con.alerts.length, 0, "an unenrolled device posts nothing");
  });
});
