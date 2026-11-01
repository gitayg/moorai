// Agent session identity tokens (cli/agent-session-identity.mjs) and the moorai-identity CLI: a token minted with
// the device key verifies against that key only, a changed byte, another device's key, an expired token or a session
// past its maximum does not, the signed policy's revokedAgentSessions turns a verified token into "revoked" and its
// agentIdentity.mode decides what is refused; the CLI's headers / run / mint register and carry the token as stated.
//
//   node --test --import ./test/hermetic-env.mjs test/agent-session-identity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey } from "node:crypto";
import { mintToken, verifyToken, judgeIdentity, identityConfig, identityAlert, keyIdOf, newSessionId, registrationRecord, registrationCanonical, devicePublicKey, SESSION_ID_RE } from "../cli/agent-session-identity.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-identity.mjs");
const keyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, pem: privateKey.export({ type: "pkcs8", format: "pem" }), signer: { sign: (b) => edSign(null, b, privateKey), publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64") } };
};
const K = keyPair(), OTHER = keyPair();
const T0 = Date.parse("2026-10-31T12:00:00.000Z");
const sec = (ms) => Math.floor(ms / 1000);

test("mint -> verify: the claims, the device key id, and the session id survive; nothing but ids and times is in the token", () => {
  const sid = newSessionId();
  assert.match(sid, SESSION_ID_RE);
  const tok = mintToken({ sid, agentName: "claude-code", sat: sec(T0), ttlSec: 900, now: T0, signer: K.signer });
  const v = verifyToken(tok, { publicKey: K.signer.publicKey, now: T0 + 1000 });
  assert.deepEqual(v, { status: "verified", sid, agentName: "claude-code", exp: sec(T0) + 900 });
  const claims = JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString("utf8"));
  assert.deepEqual(Object.keys(claims).sort(), ["agent", "exp", "iat", "jti", "kid", "sat", "sid", "v"]);
  assert.equal(claims.kid, keyIdOf(K.signer.publicKey));
  assert.equal(verifyToken(tok, { publicKey: K.signer.publicKey, now: T0 + 1000 }).status, "verified");
});

test("a token does not verify under another device key, with a changed claim, past exp, or past the session maximum", () => {
  const sid = newSessionId();
  const tok = mintToken({ sid, agentName: "codex", sat: sec(T0), ttlSec: 900, now: T0, signer: K.signer });
  assert.equal(verifyToken(tok, { publicKey: OTHER.signer.publicKey, now: T0 }).status, "foreign");
  const [p, c, s] = tok.split(".");
  const claims = JSON.parse(Buffer.from(c, "base64url").toString("utf8"));
  // Changed claims that stay inside every other check (exp within maxTokenSeconds, a well-formed session id).
  const forge = (c2) => `${p}.${Buffer.from(JSON.stringify({ ...claims, ...c2 })).toString("base64url")}.${s}`;
  assert.equal(verifyToken(forge({ exp: claims.exp + 3600 }), { publicKey: K.signer.publicKey, now: T0 }).status, "invalid", "a changed exp kept the old signature");
  assert.equal(verifyToken(forge({ sid: newSessionId() }), { publicKey: K.signer.publicKey, now: T0 }).status, "invalid", "a changed session id kept the old signature");
  assert.equal(verifyToken(tok, { publicKey: K.signer.publicKey, now: T0 + 900_000 }).status, "expired");
  // A long token for a session that started long ago: the policy's maxSessionSeconds ends it.
  const old = mintToken({ sid, agentName: "codex", sat: sec(T0) - 7200, ttlSec: 86400, sessionMaxSec: 86400, now: T0, signer: K.signer });
  assert.equal(verifyToken(old, { publicKey: K.signer.publicKey, now: T0, maxSessionSec: 3600 }).status, "expired");
  assert.equal(verifyToken(old, { publicKey: K.signer.publicKey, now: T0, maxTokenSec: 3600 }).status, "invalid", "a token longer than maxTokenSeconds");
  assert.equal(verifyToken("mai1.x.y", { publicKey: K.signer.publicKey }).status, "invalid");
  assert.equal(verifyToken(tok, { publicKey: null, now: T0 }).status, "invalid", "no device key: nothing verifies");
  assert.equal(verifyToken(mintToken({ sid, sat: sec(T0) + 600, ttlSec: 900, now: T0 + 600_000, signer: K.signer }), { publicKey: K.signer.publicKey, now: T0 }).status, "invalid", "issued in the future");
});

test("judgeIdentity: report mode records, refuses only a revoked session; require refuses anything unverified; off ignores", () => {
  const sid = newSessionId(), other = newSessionId();
  const tok = mintToken({ sid, agentName: "claude-code", sat: sec(T0), now: T0, signer: K.signer });
  const pub = K.signer.publicKey;
  assert.deepEqual(judgeIdentity(undefined, { policy: null, publicKey: pub, now: T0 }), { record: null, refuse: null, alert: false });
  assert.deepEqual(judgeIdentity(tok, { policy: null, publicKey: pub, now: T0 }), { record: { status: "verified", id: sid, agentName: "claude-code" }, refuse: null, alert: false });
  const rev = { revokedAgentSessions: [other, sid] };
  const r = judgeIdentity(tok, { policy: rev, publicKey: pub, now: T0 });
  assert.equal(r.record.status, "revoked");
  assert.equal(r.refuse.status, 403);
  assert.equal(judgeIdentity(tok, { policy: { revokedAgentSessions: [other] }, publicKey: pub, now: T0 }).refuse, null);
  const bad = judgeIdentity("mai1.garbage.x", { policy: null, publicKey: pub, now: T0 });
  assert.deepEqual([bad.record, bad.refuse, bad.alert], [{ status: "invalid" }, null, true]);
  const req = { agentIdentity: { mode: "require" } };
  assert.equal(judgeIdentity(undefined, { policy: req, publicKey: pub, now: T0 }).refuse.status, 401);
  assert.equal(judgeIdentity(tok, { policy: req, publicKey: pub, now: T0 + 900_000 }).refuse.status, 401, "expired under require");
  assert.equal(judgeIdentity(tok, { policy: req, publicKey: OTHER.signer.publicKey, now: T0 }).refuse.status, 401, "foreign under require");
  assert.equal(judgeIdentity([tok, tok], { policy: req, publicKey: pub, now: T0 }).record.status, "invalid", "a repeated header");
  assert.equal(judgeIdentity(tok, { policy: req, publicKey: pub, now: T0 }).refuse, null);
  assert.deepEqual(judgeIdentity(tok, { policy: { agentIdentity: { mode: "off" }, revokedAgentSessions: [sid] }, publicKey: pub, now: T0 }), { record: null, refuse: null, alert: false });
  // Malformed policy values fall back; a malformed revocation entry is ignored.
  const cfg = identityConfig({ agentIdentity: { mode: "bogus", maxTokenSeconds: 5, maxSessionSeconds: "x" }, revokedAgentSessions: ["asi-short", 7, sid] });
  assert.deepEqual({ ...cfg, revoked: [...cfg.revoked] }, { mode: "report", maxTokenSec: 86400, maxSessionSec: 86400, revoked: [sid] });
});

test("identityAlert is content-free: ids, a status enum and a fixed hash", () => {
  const a = identityAlert({ status: "revoked", id: "asi-0123456789abcdef", agentName: "claude-code" }, { refused: true, surfacePrefix: "gateway" });
  assert.deepEqual(a, { threatId: 0, category: "Agent identity: revoked", riskLevel: "Blocked", stage: "identity", tool: "gateway:identity", decision: "deny", reasonCode: "AGENT_IDENTITY", contentHash: "agent-identity:revoked", agentSession: { status: "revoked", id: "asi-0123456789abcdef", agentName: "claude-code" } });
  assert.equal(identityAlert({ status: "<script>" }, { refused: false, surfacePrefix: "model-proxy" }).category, "Agent identity: invalid");
});

test("registrationRecord: signed over the canonical string with the device key", () => {
  const r = registrationRecord({ sid: "asi-00112233445566ff", agentName: "claude-code", satSec: sec(T0), sessionExpSec: sec(T0) + 3600, signer: K.signer });
  assert.equal(r.kid, keyIdOf(K.signer.publicKey));
  assert.equal(registrationCanonical(r), `moorai-agent-session-v1|asi-00112233445566ff|claude-code|2026-10-31T12:00:00.000Z|2026-10-31T13:00:00.000Z|${r.kid}`);
  const pub = createPublicKey({ key: Buffer.from(r.pub, "base64"), format: "der", type: "spki" });
  assert.ok(edVerify(null, Buffer.from(registrationCanonical(r)), pub, Buffer.from(r.sig, "base64")));
});

test("devicePublicKey reads the device key and never creates one", () => {
  assert.equal(devicePublicKey({ read: () => "", now: 1 }), null);
  assert.equal(devicePublicKey({ read: () => K.pem, now: 2 }), null, "a miss is retried after 30 s, not at once");
  assert.equal(devicePublicKey({ read: () => K.pem, now: 40000 }), K.signer.publicKey);
});

// ---- the CLI ------------------------------------------------------------------------------------------
function sandbox(consoleUrl) {
  const home = mkdtempSync(join(tmpdir(), "moorai-identity-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "agency-ed25519.key"), K.pem, { mode: 0o600 });
  if (consoleUrl) writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: consoleUrl, tenant: "acme", installToken: "tok-id" }));
  return home;
}
function cli(home, args, env = {}, input) {
  return new Promise((resolve) => {
    const base = { PATH: process.env.PATH, HOME: home, USERPROFILE: home };
    const c = spawn(process.execPath, [CLI, ...args], { env: { ...base, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (code) => resolve({ code, out, err }));
    c.stdin.end(input || "");
  });
}
async function fakeConsole() {
  const posts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/agent-sessions/register") posts.push({ token: q.headers["x-install-token"], body: JSON.parse(b) }); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, posts, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}

test("CLI headers: {} without a session or for a non-loopback MCP server; otherwise a short token for the session", async () => {
  const home = sandbox();
  try {
    const none = await cli(home, ["headers"]);
    assert.deepEqual([none.code, JSON.parse(none.out)], [0, {}]);
    const now = sec(Date.now());
    const sess = { MOORAI_AGENT_SESSION: "asi-aaaaaaaaaaaaaaaa", MOORAI_AGENT_SESSION_START: String(now - 10), MOORAI_AGENT_SESSION_EXP: String(now + 3600), MOORAI_AGENT_NAME: "claude-code" };
    const remote = await cli(home, ["headers"], { ...sess, CLAUDE_CODE_MCP_SERVER_URL: "https://mcp.example.com/mcp" });
    assert.deepEqual(JSON.parse(remote.out), {}, "a token was handed to a non-loopback MCP server");
    const ok = await cli(home, ["headers", "--ttl", "120"], { ...sess, CLAUDE_CODE_MCP_SERVER_URL: "http://127.0.0.1:8848/github" });
    const tok = JSON.parse(ok.out)["X-MoorAI-Agent-Identity"];
    const v = verifyToken(tok, { publicKey: K.signer.publicKey });
    assert.equal(v.status, "verified");
    assert.equal(v.sid, "asi-aaaaaaaaaaaaaaaa");
    assert.ok(v.exp - sec(Date.now()) <= 121, "the --ttl was not applied");
    const ended = await cli(home, ["headers"], { ...sess, MOORAI_AGENT_SESSION_EXP: String(now - 1), MOORAI_AGENT_SESSION_START: String(now - 100) });
    assert.deepEqual(JSON.parse(ended.out), {}, "a token for an ended session");
  } finally { rmTree(home); }
});

test("CLI run: registers the session (signature verifies), passes it to the command, and adds the model header only for a loopback base URL", async () => {
  const con = await fakeConsole();
  const home = sandbox(con.url);
  try {
    const show = ["-e", "process.stdout.write(JSON.stringify({s:process.env.MOORAI_AGENT_SESSION,t:process.env.MOORAI_AGENT_IDENTITY,h:process.env.ANTHROPIC_CUSTOM_HEADERS||null,a:process.env.MOORAI_AGENT_NAME}))"];
    const r = await cli(home, ["run", "--agent", "claude-code", "--", process.execPath, ...show], { ANTHROPIC_BASE_URL: "http://127.0.0.1:8791/anthropic", ANTHROPIC_CUSTOM_HEADERS: "X-Team: blue" });
    assert.equal(r.code, 0, r.err);
    const got = JSON.parse(r.out);
    assert.match(got.s, SESSION_ID_RE);
    assert.equal(got.a, "claude-code");
    assert.equal(verifyToken(got.t, { publicKey: K.signer.publicKey }).sid, got.s);
    assert.equal(got.h, `X-Team: blue\nX-MoorAI-Agent-Identity: ${got.t}`);
    assert.equal(con.posts.length, 1);
    const reg = con.posts[0].body;
    assert.equal(con.posts[0].token, "tok-id");
    assert.equal(reg.sid, got.s);
    assert.ok(edVerify(null, Buffer.from(registrationCanonical(reg)), createPublicKey({ key: Buffer.from(reg.pub, "base64"), format: "der", type: "spki" }), Buffer.from(reg.sig, "base64")));
    assert.deepEqual(Object.keys(reg).sort(), ["actor", "agentName", "alg", "device", "kid", "platform", "pub", "sat", "sessionExp", "sid", "sig", "tenant", "user", "v"]);
    const direct = await cli(home, ["run", "--", process.execPath, ...show], { ANTHROPIC_BASE_URL: "https://api.anthropic.com" });
    assert.equal(JSON.parse(direct.out).h, null, "the identity header was set for a non-loopback model endpoint");
    const exit = await cli(home, ["run", "--", process.execPath, "-e", "process.exit(7)"]);
    assert.equal(exit.code, 7, "the command's exit code is passed on");
  } finally { await con.close(); rmTree(home); }
});

test("CLI verify: prints the status against this device's key", async () => {
  const home = sandbox();
  try {
    const tok = mintToken({ sid: "asi-bbbbbbbbbbbbbbbb", agentName: "codex", sat: sec(Date.now()), signer: K.signer });
    const ok = await cli(home, ["verify", tok]);
    assert.deepEqual([ok.code, JSON.parse(ok.out).status, JSON.parse(ok.out).id], [0, "verified", "asi-bbbbbbbbbbbbbbbb"]);
    const foreign = await cli(home, ["verify"], {}, mintToken({ sid: "asi-bbbbbbbbbbbbbbbb", sat: sec(Date.now()), signer: OTHER.signer }));
    assert.deepEqual([foreign.code, JSON.parse(foreign.out).status], [1, "foreign"]);
  } finally { rmTree(home); }
});
