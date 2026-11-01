// Agent session identity at the model proxy, in the real proxy process with a signing fake console: a verified
// X-MoorAI-Agent-Identity rides on the request's alerts and never reaches the provider; a session the signed policy
// revokes is refused 403 in --mode enforce, before the provider is contacted, and only reported (enforcement
// LIMITED) in --mode report; agentIdentity.mode "require" refuses a request with no identity 401 in enforce mode.
//
//   node --test --import ./test/hermetic-env.mjs test/agent-identity-model-proxy.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { sandbox, startProxy, request, waitFor } from "../model-proxy/test/harness.mjs";
import { mintToken, newSessionId } from "../cli/agent-session-identity.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const TENANT = "t-mp-identity";
const consoleKey = generateKeyPairSync("ed25519");
const device = generateKeyPairSync("ed25519");
const DEVICE_PEM = device.privateKey.export({ type: "pkcs8", format: "pem" });
const SIGNER = { sign: (b) => edSign(null, b, device.privateKey), publicKey: device.publicKey.export({ type: "spki", format: "der" }).toString("base64") };
const HDR = "x-moorai-agent-identity";
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), consoleKey.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
async function signingConsole(policy) {
  const alerts = [];
  const srv = http.createServer((q, r) => {
    let b = ""; q.on("data", (d) => (b += d));
    q.on("end", () => {
      if (q.url === "/api/alerts") { alerts.push(JSON.parse(b)); r.writeHead(201); return r.end("{}"); }
      if (q.url.startsWith("/api/policy/pubkey")) { r.writeHead(200, { "Content-Type": "application/json" }); return r.end(JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(consoleKey.publicKey) })); }
      if (q.url.startsWith("/api/policy")) { r.writeHead(200, { "Content-Type": "application/json" }); return r.end(signed(policy)); }
      r.writeHead(404); r.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}

let fp; const homes = [];
before(async () => { fp = await startFakeProvider(); fp.on((req, res) => sendJson(res, anthropicMessage({ text: "ok" }))); });
after(async () => { await fp?.close(); for (const h of homes) rmTree(h); });
async function proxyWith(con, mode) {
  const h = sandbox(); homes.push(h);
  mkdirSync(join(h, ".moorai"), { recursive: true });
  writeFileSync(join(h, ".moorai", "agency-ed25519.key"), DEVICE_PEM, { mode: 0o600 });
  return startProxy(h, ["--mode", mode, "--route", `/anthropic=${fp.url}`], { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok-identity", MOORAI_TENANT: TENANT });
}
const ANT = "/anthropic/v1/messages";
const BODY = { model: "claude-fake", max_tokens: 16, messages: [{ role: "user", content: "hello" }] };
const SECRET_BODY = { ...BODY, messages: [{ role: "user", content: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1 AKIAIOSFODNN7EXAMPLE" }] };
const tokenFor = (sid) => mintToken({ sid, agentName: "claude-code", sat: Math.floor(Date.now() / 1000), signer: SIGNER });

test("MODEL PROXY IDENTITY: verified identity on the request's alerts, header not forwarded; a revoked session is refused 403 in enforce mode", async () => {
  const sid = newSessionId(), revoked = newSessionId();
  const con = await signingConsole({ revokedAgentSessions: [revoked] });
  const px = await proxyWith(con, "enforce");
  try {
    const n0 = fp.requests.length;
    const ok = await request(px.listening, ANT, { body: SECRET_BODY, headers: { [HDR]: tokenFor(sid) } });
    assert.ok(ok.status === 200 || ok.status === 400, `status ${ok.status}`);
    for (const r of fp.requests.slice(n0)) assert.equal(r.headers[HDR], undefined, "the identity header reached the provider");
    assert.ok(await waitFor(() => con.alerts.some((a) => a.agentSession && a.agentSession.id === sid)), "no alert carried the session");
    const a = con.alerts.find((x) => x.agentSession && x.agentSession.id === sid);
    assert.deepEqual(a.agentSession, { status: "verified", id: sid, agentName: "claude-code" });
    const n1 = fp.requests.length;
    const no = await request(px.listening, ANT, { body: BODY, headers: { [HDR]: tokenFor(revoked) } });
    assert.equal(no.status, 403);
    assert.match(no.raw.toString(), /revoked/);
    assert.equal(fp.requests.length, n1, "a refused request reached the provider");
    assert.ok(await waitFor(() => con.alerts.some((x) => x.category === "Agent identity: revoked")));
    const rv = con.alerts.find((x) => x.category === "Agent identity: revoked");
    assert.deepEqual([rv.riskLevel, rv.decision, rv.reasonCode, rv.agentSession.id, rv.tool], ["Blocked", "deny", "AGENT_IDENTITY", revoked, "model-proxy:identity"]);
  } finally { await px.stop(); await con.close(); }
});

test("MODEL PROXY IDENTITY: --mode report forwards a revoked session and reports it LIMITED", async () => {
  const revoked = newSessionId();
  const con = await signingConsole({ revokedAgentSessions: [revoked] });
  const px = await proxyWith(con, "report");
  try {
    const n0 = fp.requests.length;
    const r = await request(px.listening, ANT, { body: BODY, headers: { [HDR]: tokenFor(revoked) } });
    assert.equal(r.status, 200);
    assert.equal(fp.requests.length, n0 + 1);
    assert.ok(await waitFor(() => con.alerts.some((x) => x.category === "Agent identity: revoked")));
    const rv = con.alerts.find((x) => x.category === "Agent identity: revoked");
    assert.deepEqual([rv.riskLevel, rv.decision, rv.enforcement], ["Medium", "allow", "LIMITED"]);
  } finally { await px.stop(); await con.close(); }
});

test("MODEL PROXY IDENTITY: require mode refuses a request with no identity 401 and passes a verified one", async () => {
  const con = await signingConsole({ agentIdentity: { mode: "require" } });
  const px = await proxyWith(con, "enforce");
  try {
    const n0 = fp.requests.length;
    const none = await request(px.listening, ANT, { body: BODY });
    assert.equal(none.status, 401);
    assert.equal(fp.requests.length, n0);
    const ok = await request(px.listening, ANT, { body: BODY, headers: { [HDR]: tokenFor(newSessionId()) } });
    assert.equal(ok.status, 200);
  } finally { await px.stop(); await con.close(); }
});
