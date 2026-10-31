// Agent session identity at the HTTP MCP gateway, end to end: a real gateway process, a fake remote MCP server and a
// fake console whose signed policy the test changes. A verified X-MoorAI-Agent-Identity rides on the request's
// alerts as agentSession and never reaches the upstream; the console revoking the session reaches the gateway on its
// next policy fetch and every later call from that session is refused 403, before the upstream is contacted; under
// agentIdentity.mode "require" a call with no identity, an expired one or one from another device's key is refused 401.
//
//   node --test --import ./test/hermetic-env.mjs test/agent-identity-gateway.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { makeHome, sign, startConsole, startGateway, stopGateway, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";
import { startUpstream } from "../mcp-gateway/test/fake-upstream.mjs";
import { mintToken, newSessionId } from "../cli/agent-session-identity.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const keyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { pem: privateKey.export({ type: "pkcs8", format: "pem" }), signer: { sign: (b) => edSign(null, b, privateKey), publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64") } };
};
const DEVICE = keyPair(), OTHER = keyPair();
const AWS = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\n";
const HDR = "X-MoorAI-Agent-Identity";
const now = () => Math.floor(Date.now() / 1000);

// The harness's signing key and pubkey body, with a policy the test can replace between calls.
async function mutableConsole(policy) {
  const alerts = [];
  let body = sign(policy);
  const pk = await startConsole(null);
  const pubkeyRes = await fetch(`${pk.url}/api/policy/pubkey`).then((x) => x.text());
  await pk.close();
  const srv = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(pubkeyRes); }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(body); }
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(201); res.end("{}"); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${srv.address().port}`, setPolicy: (p) => { body = sign(p); }, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}

async function withGateway(policy, fn) {
  const con = await mutableConsole(policy);
  const home = makeHome(con.url);
  writeFileSync(join(home, ".moorai", "agency-ed25519.key"), DEVICE.pem, { mode: 0o600 });
  const up = await startUpstream({});
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`], env: { MOORAI_TEST_POLICY_REFRESH_MS: "0" } });
  try {
    assert.ok(gw.url, `gateway did not start: ${gw.stderr}`);
    await fn({ con, up, base: `${gw.url}/remote` });
  } finally { await stopGateway(gw); await up.close(); await con.close(); rmTree(home); }
}
const waitFor = async (pred, ms = 4000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (pred()) return true; await settle(25); } return pred(); };

test("GATEWAY IDENTITY: a verified identity rides on the request's alerts, is never forwarded, and a revocation served in the next policy refuses the session 403", async () => {
  await withGateway({ captureTier: "content-free", threatPolicy: { 39: "block" } }, async ({ con, up, base }) => {
    const sid = newSessionId();
    const tok = mintToken({ sid, agentName: "claude-code", sat: now(), signer: DEVICE.signer });
    const ok = await rpc(base, call(1, "create_issue", { title: "x" }), { [HDR]: tok });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.result.isError, false);
    const seen = up.received.filter((r) => r.method === "POST");
    assert.ok(seen.length >= 1);
    for (const r of seen) assert.equal(r.headers["x-moorai-agent-identity"], undefined, "the identity header reached the upstream MCP server");
    // A call the gateway blocks raises an alert; it carries the session.
    await rpc(base, call(2, "send_note", { body: AWS }), { [HDR]: tok });
    assert.ok(await waitFor(() => con.alerts.some((a) => a.threatId === 39 || /secret|credential/i.test(a.category || ""))), "no detector alert");
    const det = con.alerts.find((a) => a.agentSession);
    assert.deepEqual(det.agentSession, { status: "verified", id: sid, agentName: "claude-code" });
    assert.ok(!JSON.stringify(con.alerts).includes(tok), "the token itself reached the console");

    // The console revokes the session; the gateway's next refresh picks it up.
    con.setPolicy({ captureTier: "content-free", threatPolicy: { 39: "block" }, revokedAgentSessions: [sid] });
    const before = up.received.length;
    const t0 = Date.now();
    let refused = null;
    while (Date.now() - t0 < 5000) { const r = await rpc(base, call(3, "create_issue", { title: "y" }), { [HDR]: tok }); if (r.status === 403) { refused = r; break; } await settle(50); }
    assert.ok(refused, "the revoked session was never refused");
    assert.match(refused.json.error.message, /revoked/);
    const lastAllowed = up.received.length;
    const again = await rpc(base, call(4, "create_issue", { title: "z" }), { [HDR]: mintToken({ sid, agentName: "claude-code", sat: now(), signer: DEVICE.signer }) });
    assert.equal(again.status, 403, "a fresh token for the revoked session was accepted");
    assert.equal(up.received.length, lastAllowed, "a refused call reached the upstream");
    assert.ok(lastAllowed >= before);
    assert.ok(await waitFor(() => con.alerts.some((a) => a.category === "Agent identity: revoked")));
    const rv = con.alerts.find((a) => a.category === "Agent identity: revoked");
    assert.deepEqual([rv.riskLevel, rv.decision, rv.reasonCode, rv.agentSession.id, rv.mcpServer], ["Blocked", "deny", "AGENT_IDENTITY", sid, "remote"]);
    // Another session on the device is unaffected, and so is a call with no identity in report mode.
    const other = await rpc(base, call(5, "create_issue", { title: "w" }), { [HDR]: mintToken({ sid: newSessionId(), sat: now(), signer: DEVICE.signer }) });
    assert.equal(other.status, 200);
    assert.equal((await rpc(base, call(6, "create_issue", { title: "v" }))).status, 200);
  });
});

test("GATEWAY IDENTITY: require mode refuses no identity, an expired one and another device's 401; a verified one passes", async () => {
  await withGateway({ captureTier: "content-free", agentIdentity: { mode: "require" } }, async ({ con, up, base }) => {
    const sid = newSessionId();
    const none = await rpc(base, call(1, "create_issue", { title: "x" }));
    assert.equal(none.status, 401);
    assert.match(none.json.error.message, /requires an agent identity/);
    const expired = mintToken({ sid, sat: now() - 1000, ttlSec: 60, now: Date.now() - 900_000, signer: DEVICE.signer });
    assert.equal((await rpc(base, call(2, "create_issue", {}), { [HDR]: expired })).status, 401);
    assert.equal((await rpc(base, call(3, "create_issue", {}), { [HDR]: mintToken({ sid, sat: now(), signer: OTHER.signer }) })).status, 401);
    assert.equal(up.received.length, 0, "a refused call reached the upstream");
    const ok = await rpc(base, call(4, "create_issue", { title: "x" }), { [HDR]: mintToken({ sid, sat: now(), signer: DEVICE.signer }) });
    assert.equal(ok.status, 200);
    assert.ok(await waitFor(() => ["absent", "expired", "foreign"].every((s) => con.alerts.some((a) => a.category === `Agent identity: ${s}` && a.decision === "deny"))));
  });
});

test("GATEWAY IDENTITY: report mode (no agentIdentity key) forwards an invalid identity and reports it", async () => {
  await withGateway({ captureTier: "content-free" }, async ({ con, base }) => {
    const r = await rpc(base, call(1, "create_issue", { title: "x" }), { [HDR]: mintToken({ sid: newSessionId(), sat: now(), signer: OTHER.signer }) });
    assert.equal(r.status, 200);
    assert.ok(await waitFor(() => con.alerts.some((a) => a.category === "Agent identity: foreign")));
    const a = con.alerts.find((x) => x.category === "Agent identity: foreign");
    assert.deepEqual([a.riskLevel, a.decision, a.agentSession], ["Medium", "allow", { status: "foreign" }]);
  });
});
