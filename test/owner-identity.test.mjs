// Device owner sign-in, agent side (cli/owner-assertion.mjs, cli/owner-login.mjs, cli/owner-verify.mjs, the `own` claim in
// cli/agent-session-identity.mjs, moorai-identity login / whoami / logout). The console-signed owner assertion verifies
// only under the policy key, for this tenant and this device key, until it expires; a session token's `own` claim is
// judged against it at the real MCP gateway and the real model proxy and recorded on alerts as agentSession.owner
// { id, status }; an assertion the signed policy lists in revokedOwnerAssertions is "revoked"; under agentIdentity
// { mode: "require", requireOwner: true } a request whose owner is not verified is refused 401. The real CLI signs in
// through a fake console (device code and browser + PKCE), keeps the assertion, mints tokens carrying the owner and
// signs out. No token or code is printed or stored by the CLI.
//
//   node --test --import ./test/hermetic-env.mjs test/owner-identity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey, createHash, randomBytes } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { makeHome, startGateway, stopGateway, rpc, call, settle, TENANT } from "../mcp-gateway/test/harness.mjs";
import { startUpstream } from "../mcp-gateway/test/fake-upstream.mjs";
import { startFakeProvider, sendJson, anthropicMessage } from "../model-proxy/test/fake-provider.mjs";
import { sandbox, startProxy, request, waitFor as proxyWaitFor } from "../model-proxy/test/harness.mjs";
import { mintToken, newSessionId, verifyToken, judgeIdentity, keyIdOf, identityAlert } from "../cli/agent-session-identity.mjs";
import { verifyAssertion, parseAssertion, ownerStatus, assertionCanonical } from "../cli/owner-assertion.mjs";
import { requestCanonical, codeRef } from "../cli/owner-login.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-identity.mjs");
const edPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey, pem: privateKey.export({ type: "pkcs8", format: "pem" }), signer: { sign: (b) => edSign(null, b, privateKey), publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64") } };
};
const CONSOLE = edPair(), DEVICE = edPair(), OTHER = edPair();
const KID = keyIdOf(DEVICE.signer.publicKey);
const OID = "own-0123456789abcdef", AID = "a1a2a3a4a5a6a7a8";
const nowSec = () => Math.floor(Date.now() / 1000);
const HDR = "X-MoorAI-Agent-Identity";

function assertion({ tenant = TENANT, oid = OID, aid = AID, kid = KID, iat = nowSec() - 10, exp = nowSec() + 86400, key = CONSOLE.privateKey } = {}) {
  const body = `moo1.${Buffer.from(JSON.stringify({ v: 1, oid, aid, kid, iat, exp })).toString("base64url")}`;
  return `${body}.${edSign(null, Buffer.from(assertionCanonical(tenant, body)), key).toString("base64url")}`;
}
// A fixed, old iat (as mcp-gateway/test/harness.mjs signs): a policy issued "now" is fresh for 60 s and not re-fetched.
function signedPolicy(policy, tenant = TENANT) {
  const iat = "2026-09-01T00:00:00.000Z";
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest: policyDigest(policy) })), CONSOLE.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } });
}
const PUBKEY = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(CONSOLE.publicKey) });

test("assertion: verifies only under the policy key, for this tenant and device key, until it expires", () => {
  const keys = [CONSOLE.publicKey];
  const a = assertion();
  assert.deepEqual(parseAssertion(a), { v: 1, oid: OID, aid: AID, kid: KID, iat: parseAssertion(a).iat, exp: parseAssertion(a).exp });
  assert.equal(verifyAssertion(a, { keys, tenant: TENANT, kid: KID }).status, "ok");
  assert.equal(verifyAssertion(a, { keys: [], tenant: TENANT, kid: KID }).status, "untrusted", "an unpinned device verifies nothing");
  assert.equal(verifyAssertion(a, { keys: [OTHER.publicKey], tenant: TENANT, kid: KID }).status, "untrusted");
  assert.equal(verifyAssertion(a, { keys, tenant: "beta", kid: KID }).status, "untrusted", "replayed onto another tenant");
  assert.equal(verifyAssertion(a, { keys, tenant: TENANT, kid: keyIdOf(OTHER.signer.publicKey) }).status, "foreign");
  assert.equal(verifyAssertion(assertion({ iat: nowSec() - 100, exp: nowSec() - 1 }), { keys, tenant: TENANT, kid: KID }).status, "expired");
  const [h, b, s] = a.split(".");
  const forged = `${h}.${Buffer.from(JSON.stringify({ ...parseAssertion(a), oid: "own-ffffffffffffffff" })).toString("base64url")}.${s}`;
  assert.equal(verifyAssertion(forged, { keys, tenant: TENANT, kid: KID }).status, "untrusted", "an edited owner id verified");
  assert.equal(verifyAssertion(`${h}.${b}`, { keys, tenant: TENANT, kid: KID }).status, "invalid");
  assert.equal(ownerStatus(OID, { status: "ok", oid: OID, aid: AID }, {}), "verified");
  assert.equal(ownerStatus(OID, { status: "ok", oid: "own-ffffffffffffffff", aid: AID }, {}), "mismatch");
  assert.equal(ownerStatus(OID, { status: "ok", oid: OID, aid: AID }, { revokedOwnerAssertions: [AID] }), "revoked");
  assert.equal(ownerStatus(OID, { status: "untrusted" }, {}), "unverified");
});

test("token: the own claim is signed with the session, malformed owner ids are refused, and requireOwner refuses an unverified owner under require", () => {
  const sid = newSessionId();
  const t = mintToken({ sid, agentName: "claude-code", sat: nowSec(), signer: DEVICE.signer, ownerId: OID });
  assert.equal(verifyToken(t, { publicKey: DEVICE.signer.publicKey }).own, OID);
  const odd = mintToken({ sid, sat: nowSec(), signer: DEVICE.signer, ownerId: "alice@acme.test" });
  assert.equal(JSON.parse(Buffer.from(odd.split(".")[1], "base64url")).own, undefined, "a non-id owner was put in a token");
  assert.equal(verifyToken(odd, { publicKey: DEVICE.signer.publicKey }).status, "verified");
  const signedOdd = (() => { const body = `mai1.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(odd.split(".")[1], "base64url")), own: "alice@acme.test" })).toString("base64url")}`; return `${body}.${DEVICE.signer.sign(Buffer.from(body)).toString("base64url")}`; })();
  assert.equal(verifyToken(signedOdd, { publicKey: DEVICE.signer.publicKey }).status, "invalid", "a signed token with a non-id owner verified");
  const [p, c, s] = t.split(".");
  const swapped = `${p}.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(c, "base64url")), own: "own-ffffffffffffffff" })).toString("base64url")}.${s}`;
  assert.equal(verifyToken(swapped, { publicKey: DEVICE.signer.publicKey }).status, "invalid", "an edited own claim verified");
  const ok = { status: "ok", oid: OID, aid: AID };
  assert.deepEqual(judgeIdentity(t, { policy: {}, publicKey: DEVICE.signer.publicKey, owner: ok }), { record: { status: "verified", id: sid, agentName: "claude-code", owner: { id: OID, status: "verified" } }, refuse: null, alert: false });
  const mm = judgeIdentity(t, { policy: {}, publicKey: DEVICE.signer.publicKey, owner: { ...ok, oid: "own-ffffffffffffffff" } });
  assert.deepEqual([mm.record.owner, mm.refuse, mm.alert], [{ id: OID, status: "mismatch" }, null, true]);
  assert.deepEqual([identityAlert(mm.record, { refused: false, surfacePrefix: "gateway" }).category, identityAlert(mm.record, { refused: false, surfacePrefix: "gateway" }).contentHash], ["Agent owner: mismatch", "agent-owner:mismatch"]);
  const req = { agentIdentity: { mode: "require", requireOwner: true } };
  assert.equal(judgeIdentity(t, { policy: req, publicKey: DEVICE.signer.publicKey, owner: ok }).refuse, null);
  assert.equal(judgeIdentity(t, { policy: { ...req, revokedOwnerAssertions: [AID] }, publicKey: DEVICE.signer.publicKey, owner: ok }).refuse.status, 401);
  const noOwn = judgeIdentity(mintToken({ sid, sat: nowSec(), signer: DEVICE.signer }), { policy: req, publicKey: DEVICE.signer.publicKey, owner: ok });
  assert.deepEqual([noOwn.refuse.status, noOwn.record.owner], [401, { status: "absent" }]);
  assert.equal(judgeIdentity(mintToken({ sid, sat: nowSec(), signer: DEVICE.signer }), { policy: { agentIdentity: { mode: "report", requireOwner: true } }, publicKey: DEVICE.signer.publicKey, owner: ok }).refuse, null, "requireOwner applies under require only");
});

async function mutableConsole(policy) {
  const alerts = [];
  let body = signedPolicy(policy);
  const srv = http.createServer((req, res) => {
    if (req.url === "/api/policy/pubkey") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(body); }
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(201); res.end("{}"); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${srv.address().port}`, setPolicy: (p) => { body = signedPolicy(p); }, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
const AWS = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\n";
const waitFor = async (pred, ms = 4000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (pred()) return true; await settle(25); } return pred(); };

async function withGateway(policy, ownerFile, fn) {
  const con = await mutableConsole(policy);
  const home = makeHome(con.url);
  writeFileSync(join(home, ".moorai", "agency-ed25519.key"), DEVICE.pem, { mode: 0o600 });
  if (ownerFile) writeFileSync(join(home, ".moorai", "agent-owner.json"), JSON.stringify({ v: 1, assertion: ownerFile }), { mode: 0o600 });
  const up = await startUpstream({});
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`], env: { MOORAI_TEST_POLICY_REFRESH_MS: "0" } });
  try {
    assert.ok(gw.url, `gateway did not start: ${gw.stderr}`);
    await fn({ con, up, base: `${gw.url}/remote` });
  } finally { await stopGateway(gw); await up.close(); await con.close(); rmTree(home); }
}

test("GATEWAY OWNER: a verified owner rides on the request's alerts; another owner id is a mismatch; a revoked assertion is reported", async () => {
  await withGateway({ captureTier: "content-free", threatPolicy: { 39: "block" } }, assertion(), async ({ con, base }) => {
    const sid = newSessionId();
    const tok = mintToken({ sid, agentName: "claude-code", sat: nowSec(), signer: DEVICE.signer, ownerId: OID });
    assert.equal((await rpc(base, call(1, "send_note", { body: AWS }), { [HDR]: tok })).status, 200);
    assert.ok(await waitFor(() => con.alerts.some((a) => a.agentSession && a.threatId !== 0)), "no detector alert");
    assert.deepEqual(con.alerts.find((a) => a.agentSession && a.threatId !== 0).agentSession, { status: "verified", id: sid, agentName: "claude-code", owner: { id: OID, status: "verified" } });
    const other = mintToken({ sid: newSessionId(), sat: nowSec(), signer: DEVICE.signer, ownerId: "own-ffffffffffffffff" });
    assert.equal((await rpc(base, call(2, "create_issue", { title: "x" }), { [HDR]: other })).status, 200, "report mode refused a mismatch");
    assert.ok(await waitFor(() => con.alerts.some((a) => a.category === "Agent owner: mismatch")));
    const mm = con.alerts.find((a) => a.category === "Agent owner: mismatch");
    assert.deepEqual([mm.riskLevel, mm.decision, mm.reasonCode, mm.agentSession.owner], ["Medium", "allow", "AGENT_IDENTITY", { id: "own-ffffffffffffffff", status: "mismatch" }]);
    con.setPolicy({ captureTier: "content-free", threatPolicy: { 39: "block" }, revokedOwnerAssertions: [AID] });
    let seen = false;
    for (let i = 0; i < 40 && !seen; i++) { await rpc(base, call(10 + i, "create_issue", { title: "y" }), { [HDR]: tok }); seen = con.alerts.some((a) => a.category === "Agent owner: revoked"); if (!seen) await settle(50); }
    assert.ok(seen, "a revoked owner assertion was never reported");
    assert.ok(!JSON.stringify(con.alerts).includes(tok), "a token reached the console");
  });
});

test("GATEWAY OWNER: require + requireOwner refuses no owner, an owner the device cannot verify and a revoked one 401; a verified owner passes", async () => {
  const policy = { captureTier: "content-free", agentIdentity: { mode: "require", requireOwner: true } };
  await withGateway(policy, assertion(), async ({ con, up, base }) => {
    const sid = newSessionId();
    const none = await rpc(base, call(1, "create_issue", { title: "x" }), { [HDR]: mintToken({ sid, sat: nowSec(), signer: DEVICE.signer }) });
    assert.equal(none.status, 401);
    assert.match(none.json.error.message, /signed-in owner/);
    assert.equal((await rpc(base, call(2, "create_issue", {}), { [HDR]: mintToken({ sid, sat: nowSec(), signer: DEVICE.signer, ownerId: "own-ffffffffffffffff" }) })).status, 401);
    assert.equal(up.received.length, 0, "a refused call reached the upstream");
    const own = mintToken({ sid, sat: nowSec(), signer: DEVICE.signer, ownerId: OID });
    assert.equal((await rpc(base, call(3, "create_issue", { title: "x" }), { [HDR]: own })).status, 200);
    con.setPolicy({ ...policy, revokedOwnerAssertions: [AID] });
    let r = null;
    for (let i = 0; i < 40; i++) { r = await rpc(base, call(10 + i, "create_issue", {}), { [HDR]: own }); if (r.status === 401) break; await settle(50); }
    assert.equal(r.status, 401, "a revoked owner assertion was accepted");
  });
  // The same token on a device whose assertion was signed by another key: the owner is unverified, so refused.
  await withGateway(policy, assertion({ key: OTHER.privateKey }), async ({ base }) => {
    assert.equal((await rpc(base, call(1, "create_issue", {}), { [HDR]: mintToken({ sid: newSessionId(), sat: nowSec(), signer: DEVICE.signer, ownerId: OID }) })).status, 401);
  });
});

test("MODEL PROXY OWNER: a verified owner rides on the request's alerts; require + requireOwner refuses a token without one in enforce mode", async () => {
  const fp = await startFakeProvider();
  fp.on((req, res) => sendJson(res, anthropicMessage({ text: "ok" })));
  const homes = [];
  const run = async (policy, fn) => {
    const con = await mutableConsole(policy);
    const h = sandbox(); homes.push(h);
    mkdirSync(join(h, ".moorai"), { recursive: true });
    writeFileSync(join(h, ".moorai", "agency-ed25519.key"), DEVICE.pem, { mode: 0o600 });
    writeFileSync(join(h, ".moorai", "agent-owner.json"), JSON.stringify({ v: 1, assertion: assertion() }), { mode: 0o600 });
    const px = await startProxy(h, ["--mode", "enforce", "--route", `/anthropic=${fp.url}`], { MOORAI_SERVER_URL: con.url, MOORAI_INSTALL_TOKEN: "tok", MOORAI_TENANT: TENANT });
    try { await fn({ con, px }); } finally { await px.stop(); await con.close(); }
  };
  const BODY = { model: "claude-fake", max_tokens: 16, messages: [{ role: "user", content: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1 AKIAIOSFODNN7EXAMPLE" }] };
  const HI = { ...BODY, messages: [{ role: "user", content: "hi" }] };
  try {
    await run({ captureTier: "content-free" }, async ({ con, px }) => {
      const sid = newSessionId();
      await request(px.listening, "/anthropic/v1/messages", { body: BODY, headers: { "x-moorai-agent-identity": mintToken({ sid, agentName: "claude-code", sat: nowSec(), signer: DEVICE.signer, ownerId: OID }) } });
      assert.ok(await proxyWaitFor(() => con.alerts.some((a) => a.agentSession)), "no alert carried the session");
      assert.deepEqual(con.alerts.find((a) => a.agentSession).agentSession, { status: "verified", id: sid, agentName: "claude-code", owner: { id: OID, status: "verified" } });
    });
    await run({ captureTier: "content-free", agentIdentity: { mode: "require", requireOwner: true } }, async ({ px }) => {
      const before = fp.requests.length;
      const r = await request(px.listening, "/anthropic/v1/messages", { body: HI, headers: { "x-moorai-agent-identity": mintToken({ sid: newSessionId(), sat: nowSec(), signer: DEVICE.signer }) } });
      assert.equal(r.status, 401);
      assert.equal(fp.requests.length, before, "a refused request reached the provider");
      const ok = await request(px.listening, "/anthropic/v1/messages", { body: HI, headers: { "x-moorai-agent-identity": mintToken({ sid: newSessionId(), sat: nowSec(), signer: DEVICE.signer, ownerId: OID }) } });
      assert.equal(ok.status, 200);
    });
  } finally { await fp.close(); for (const h of homes) rmTree(h); }
});

// A stand-in console for the CLI: it checks each request's device signature over the pinned canonical bytes, runs a
// device flow (pending once, then bound) and a browser flow (it also plays the provider's authorization endpoint and
// checks PKCE S256 and the nonce), signs assertions with the console key and records unbinds.
async function fakeOwnerConsole() {
  const seen = { bad: [], unbound: [], authorize: [] };
  const codes = new Map();
  let polls = 0;
  const bind = (b) => ({ status: "bound", owner: { id: OID, email: "alice@acme.test", name: "Alice" }, keyId: b.kid, keyVerified: true, assertion: assertion({ kid: b.kid }), expiresAt: new Date(Date.now() + 86400000).toISOString() });
  const ok = (op, b, ref = "") => keyIdOf(b.pub) === b.kid && edVerify(null, Buffer.from(requestCanonical(op, TENANT, { kid: b.kid, ref, ts: b.ts })), createPublicKey({ key: Buffer.from(b.pub, "base64"), format: "der", type: "spki" }), Buffer.from(b.sig, "base64"));
  const srv = http.createServer((req, res) => {
    let raw = ""; req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const u = new URL(req.url, "http://x");
      const send = (code, j) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(j)); };
      if (u.pathname === "/api/policy/pubkey") return send(200, JSON.parse(PUBKEY));
      if (u.pathname === "/api/policy") { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(signedPolicy({ captureTier: "content-free" })); }
      // The provider's authorization endpoint: a browser calls it, with no install token.
      if (u.pathname === "/authorize") {
        const code = randomBytes(8).toString("hex");
        seen.authorize.push(Object.fromEntries(u.searchParams));
        codes.set(code, { challenge: u.searchParams.get("code_challenge"), nonce: u.searchParams.get("nonce"), redirect: u.searchParams.get("redirect_uri") });
        const to = new URL(u.searchParams.get("redirect_uri")); to.searchParams.set("code", code); to.searchParams.set("state", u.searchParams.get("state"));
        res.writeHead(302, { Location: to.href }); return res.end();
      }
      if (req.headers["x-install-token"] !== "tok") return send(401, { error: "enrollment required" });
      const b = raw ? JSON.parse(raw) : {};
      if (u.pathname === "/api/owner-identity/device/start") { if (!ok("start", b)) { seen.bad.push("start"); return send(401, { error: "signature does not verify" }); } return send(200, { flow: "flw-" + "1".repeat(32), userCode: "WDJB-MJHT", verificationUri: "https://idp.example/activate", interval: 1, expiresIn: 60 }); }
      if (u.pathname === "/api/owner-identity/device/poll") { if (!ok("poll", b, b.flow)) { seen.bad.push("poll"); return send(401, { error: "signature does not verify" }); } return send(200, ++polls < 2 ? { status: "pending", interval: 1 } : bind(b)); }
      if (u.pathname === "/api/owner-identity/config") return send(200, { issuer: "https://idp.example", clientId: "moorai", scopes: "openid email", authorizationEndpoint: `http://127.0.0.1:${srv.address().port}/authorize`, deviceGrant: true, pkceS256: true });
      if (u.pathname === "/api/owner-identity/code") {
        const c = codes.get(b.code);
        if (!ok("code", b, codeRef(b.code))) { seen.bad.push("code"); return send(401, { error: "signature does not verify" }); }
        if (!c || createHash("sha256").update(b.codeVerifier).digest("base64url") !== c.challenge || c.nonce !== b.nonce || c.redirect !== b.redirectUri) return send(200, { status: "refused", reason: "invalid-grant" });
        return send(200, bind(b));
      }
      if (u.pathname === "/api/owner-identity/unbind") { if (!ok("unbind", b)) return send(401, {}); seen.unbound.push(b.kid); return send(200, { ok: true }); }
      send(404, {});
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, seen, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function runCli(home, args, { onStderr, env = {} } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_POLICY_PUBKEY: publicKeyId(CONSOLE.publicKey), ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => { err += d; if (onStderr) onStderr(err); });
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

test("CLI: login (device code, then browser + PKCE) keeps the console-signed assertion, new tokens carry the owner, whoami verifies it, logout unbinds and removes it", async () => {
  const con = await fakeOwnerConsole();
  const home = makeHome(con.url);
  writeFileSync(join(home, ".moorai", "agency-ed25519.key"), DEVICE.pem, { mode: 0o600 });
  const file = join(home, ".moorai", "agent-owner.json");
  try {
    const dev = await runCli(home, ["login", "--json"]);
    assert.equal(dev.code, 0, `${dev.err}\n${dev.out}`);
    assert.match(dev.err, /open https:\/\/idp\.example\/activate and enter the code WDJB-MJHT/);
    assert.deepEqual(JSON.parse(dev.out), { status: "bound", ownerId: OID, email: "alice@acme.test", keyId: KID, expiresAt: JSON.parse(dev.out).expiresAt, local: "ok" });
    assert.deepEqual(con.seen.bad, [], "the console could not verify a device signature");
    const kept = JSON.parse(readFileSync(file, "utf8"));
    assert.equal(parseAssertion(kept.assertion).kid, KID);
    assert.equal((readFileSync(file).length && (await import("node:fs")).statSync(file).mode & 0o777), 0o600);
    const who = await runCli(home, ["whoami", "--json"]);
    assert.deepEqual([who.code, JSON.parse(who.out).status, JSON.parse(who.out).ownerId], [0, "ok", OID]);
    const unpinned = await runCli(home, ["whoami", "--json"], { env: { MOORAI_POLICY_PUBKEY: "" } });
    assert.equal(JSON.parse(unpinned.out).status, "untrusted", "an assertion verified with no trusted key");
    const mint = await runCli(home, ["mint", "--new", "--json"]);
    const tok = JSON.parse(mint.out).token;
    assert.equal(verifyToken(tok, { publicKey: DEVICE.signer.publicKey }).own, OID, "a new token does not carry the owner");
    const ver = await runCli(home, ["verify", tok]);
    assert.deepEqual(JSON.parse(ver.out).owner, { id: OID, status: "verified" });

    const br = await runCli(home, ["login", "--browser", "--no-open", "--json"], { onStderr: (e) => {
      const m = /visit:\n(\S+)/.exec(e);
      if (m && !con.seen.authorize.length) fetch(m[1], { redirect: "follow" }).catch(() => {});
    } });
    assert.equal(br.code, 0, br.err);
    assert.equal(JSON.parse(br.out).status, "bound");
    const a = con.seen.authorize[0];
    assert.deepEqual([a.response_type, a.code_challenge_method, a.client_id], ["code", "S256", "moorai"]);
    assert.match(a.redirect_uri, /^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    assert.ok(a.nonce && a.state && a.code_challenge.length === 43);
    assert.deepEqual(con.seen.bad, []);
    for (const r of [dev, br, who, mint]) assert.ok(!/moo1\.|eyJ/.test(r.err), "a token or assertion was printed to stderr");

    const out = await runCli(home, ["logout"]);
    assert.equal(out.code, 0);
    assert.deepEqual(con.seen.unbound, [KID]);
    assert.equal(existsSync(file), false);
    const tok2 = JSON.parse((await runCli(home, ["mint", "--new", "--json"])).out).token;
    assert.equal(verifyToken(tok2, { publicKey: DEVICE.signer.publicKey }).own, undefined, "a token after logout carries the owner");
  } finally { await con.close(); rmTree(home); }
});
