#!/usr/bin/env node
// moorai-identity: start an agent under a MoorAI agent session identity, and mint its short-lived tokens
// (cli/agent-session-identity.mjs; docs/proposals/agent-identity.md §12).
//
//   moorai-identity run [--agent claude-code] [--session-max 43200] -- claude …
//       New session id, registered with the console (content-free, signed with the device key), then runs the
//       command with MOORAI_AGENT_SESSION, MOORAI_AGENT_SESSION_START / _EXP, MOORAI_AGENT_NAME and
//       MOORAI_AGENT_IDENTITY set. When ANTHROPIC_BASE_URL names a loopback address (the model proxy),
//       ANTHROPIC_CUSTOM_HEADERS gains "X-MoorAI-Agent-Identity: <token>". Claude Code reads that header once
//       and cannot refresh it, so that token lives as long as the session (--session-max, at most 86400 s).
//   moorai-identity headers [--ttl 900] [--allow-remote]
//       For an MCP server's headersHelper: prints {"X-MoorAI-Agent-Identity": "<token>"} for the session in the
//       environment, valid --ttl seconds (default 900). Prints {} when there is no session, the session has ended,
//       or CLAUDE_CODE_MCP_SERVER_URL is not a loopback address (unless --allow-remote, for a remote gateway).
//   moorai-identity mint [--new] [--agent …] [--ttl 900] [--json]
//       Prints one token for the session in the environment, or for a new registered session with --new.
//   moorai-identity verify [<token>]    (else stdin)
//       Checks a token against this device's key and the device's verified policy (read offline): prints
//       { status, id?, agentName?, exp?, mode, owner? }.
//   moorai-identity login [--browser] [--no-open] [--timeout <s>] [--json]
//       Signs the person in at the tenant's identity provider, through the console (cli/owner-login.mjs): a device
//       code by default (RFC 8628), or the browser with PKCE and a loopback redirect. The console binds the person to
//       this device key and returns a signed owner assertion, kept in ~/.moorai/agent-owner.json; sessions started
//       afterwards carry the owner id (token claim `own`). Prints who was bound; --json prints
//       { status, ownerId, email, keyId, expiresAt }.
//   moorai-identity whoami [--json]     The owner bound to this device key, checked against the policy's keys.
//   moorai-identity logout              Unbinds this device key on the console and removes the local assertion.
//
// Nothing here prints or sends a prompt, a path or a command line; the console gets the session id, the agent
// name, its start and end, the device key id and the signature. login prints the provider's verification URI and
// user code (or authorization URL) for the person to use; no token is printed or written.
import { spawn } from "node:child_process";
import os from "node:os";
import { readFileSync } from "node:fs";
import { deviceReceiptSigner } from "../data/agency-sign.mjs";
import { loadConfig } from "./config.mjs";
import { actorHash } from "./content-hash.mjs";
import { serverMode, serviceWho } from "./server-mode.mjs";
import { isEnrolled } from "../data/enforcement.js";
import { newSessionId, mintToken, verifyToken, identityConfig, devicePublicKey, registrationRecord, SESSION_ID_RE, TOKEN_TTL_SEC, SESSION_MAX_SEC, POLICY_SESSION_MAX, agentLabel, keyIdOf } from "./agent-session-identity.mjs";
import { ownerClaimFor, readOwnerFile, writeOwnerFile, removeOwnerFile, verifyAssertion, ownerStatus, parseAssertion } from "./owner-assertion.mjs";

const HEADER_NAME = "X-MoorAI-Agent-Identity";
const ENV = { sid: "MOORAI_AGENT_SESSION", start: "MOORAI_AGENT_SESSION_START", exp: "MOORAI_AGENT_SESSION_EXP", agent: "MOORAI_AGENT_NAME", token: "MOORAI_AGENT_IDENTITY" };
const BIN_AGENT = { claude: "claude-code", codex: "codex", gemini: "gemini", "cursor-agent": "cursor", copilot: "copilot" };

function isLoopbackUrl(v) {
  try {
    const h = new URL(String(v)).hostname.toLowerCase().replace(/^\[|\]$/g, "");
    return h === "localhost" || h === "::1" || /^127(?:\.\d{1,3}){3}$/.test(h);
  } catch { return false; }
}

function parse(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { o.rest = argv.slice(i + 1); break; }
    if (a === "--agent" || a === "--ttl" || a === "--session-max" || a === "--timeout") { o[a.slice(2)] = argv[++i]; continue; }
    if (a === "--new" || a === "--json" || a === "--allow-remote" || a === "--browser" || a === "--no-open") { o[a.slice(2)] = true; continue; }
    o._.push(a);
  }
  return o;
}

const secs = (v, dflt, max) => { const n = Number(v); return Number.isSafeInteger(n) && n > 0 ? Math.min(n, max) : dflt; };

function sessionFromEnv(env = process.env) {
  const sid = String(env[ENV.sid] || "");
  const start = Number(env[ENV.start]), exp = Number(env[ENV.exp]);
  if (!SESSION_ID_RE.test(sid) || !Number.isSafeInteger(start) || !Number.isSafeInteger(exp) || exp <= start) return null;
  return { sid, start, exp, agentName: agentLabel(env[ENV.agent]) };
}

function signerOrDie() {
  const s = deviceReceiptSigner();
  if (!s) { process.stderr.write("moorai-identity: no device key could be read or created in ~/.moorai\n"); process.exit(2); }
  return s;
}

function whoAmI() {
  const sm = serverMode();
  const who = sm.active ? serviceWho(sm) : { user: os.userInfo().username, device: os.hostname() };
  return { user: who.user, device: who.device, actor: actorHash(who.user, who.device) };
}

// Best effort, 1.5 s: the console learns the session also from the first alert that carries it.
async function register(session, signer) {
  const config = loadConfig();
  if (!isEnrolled(config)) return "not-enrolled";
  const who = whoAmI();
  const body = { ...registrationRecord({ sid: session.sid, agentName: session.agentName, satSec: session.start, sessionExpSec: session.exp, signer }),
    tenant: config.tenant, user: who.user, device: who.device, platform: os.platform(), actor: who.actor };
  try {
    const r = await fetch(`${config.serverUrl}/api/agent-sessions/register`, { method: "POST", headers: { "Content-Type": "application/json", "X-Install-Token": config.installToken }, body: JSON.stringify(body), signal: AbortSignal.timeout(1500) });
    return r.ok ? "registered" : `refused (HTTP ${r.status})`;
  } catch { return "console unreachable"; }
}

function newSession(o, now = Date.now()) {
  const start = Math.floor(now / 1000);
  const max = secs(o["session-max"], SESSION_MAX_SEC, POLICY_SESSION_MAX.dflt);
  const bin = o.rest && o.rest[0] ? String(o.rest[0]).split(/[\\/]/).pop().replace(/\.(exe|cmd)$/i, "") : "";
  return { sid: newSessionId(), start, exp: start + max, agentName: agentLabel(o.agent || BIN_AGENT[bin]) };
}

async function run(o) {
  if (!o.rest || !o.rest.length) { process.stderr.write("usage: moorai-identity run [--agent <name>] [--session-max <s>] -- <command> [args…]\n"); return 2; }
  const signer = signerOrDie();
  const s = newSession(o);
  const ownerId = ownerClaimFor(keyIdOf(signer.publicKey));
  const token = mintToken({ sid: s.sid, agentName: s.agentName, sat: s.start, ttlSec: s.exp - s.start, sessionMaxSec: s.exp - s.start, signer, ownerId });
  const reg = await register(s, signer);
  process.stderr.write(`moorai-identity: session ${s.sid} (${s.agentName}), until ${new Date(s.exp * 1000).toISOString()}; owner: ${ownerId || "none (moorai-identity login)"}; console: ${reg}\n`);
  const env = { ...process.env, [ENV.sid]: s.sid, [ENV.start]: String(s.start), [ENV.exp]: String(s.exp), [ENV.agent]: s.agentName, [ENV.token]: token };
  if (isLoopbackUrl(process.env.ANTHROPIC_BASE_URL)) {
    const prev = String(process.env.ANTHROPIC_CUSTOM_HEADERS || "").split("\n").filter((l) => l.trim() && !/^\s*x-moorai-agent-identity\s*:/i.test(l));
    env.ANTHROPIC_CUSTOM_HEADERS = [...prev, `${HEADER_NAME}: ${token}`].join("\n");
  }
  const child = spawn(o.rest[0], o.rest.slice(1), { stdio: "inherit", env });
  // The terminal sends SIGINT / SIGHUP to the whole process group, so the agent already gets them: forwarding would
  // deliver a second interrupt. A SIGTERM sent to this process alone is passed on.
  process.on("SIGINT", () => {});
  process.on("SIGHUP", () => {});
  process.on("SIGTERM", () => { try { child.kill("SIGTERM"); } catch { /* gone */ } });
  return await new Promise((resolve) => {
    child.on("error", () => { process.stderr.write(`moorai-identity: could not start the command\n`); resolve(127); });
    child.on("exit", (code, signal) => resolve(code ?? (signal ? 128 + (os.constants.signals[signal] || 1) : 1)));
  });
}

function headers(o) {
  const s = sessionFromEnv();
  const url = process.env.CLAUDE_CODE_MCP_SERVER_URL;
  const out = (h) => { process.stdout.write(`${JSON.stringify(h)}\n`); return 0; };
  if (!s) { process.stderr.write("moorai-identity: no agent session in the environment (start the agent with moorai-identity run)\n"); return out({}); }
  if (url && !isLoopbackUrl(url) && !o["allow-remote"]) { process.stderr.write("moorai-identity: the MCP server is not a loopback address; no identity sent (--allow-remote for a remote MoorAI gateway)\n"); return out({}); }
  const now = Date.now();
  if (Math.floor(now / 1000) >= s.exp) { process.stderr.write("moorai-identity: the agent session has ended\n"); return out({}); }
  const signer = signerOrDie();
  const token = mintToken({ sid: s.sid, agentName: s.agentName, sat: s.start, ttlSec: secs(o.ttl, TOKEN_TTL_SEC, s.exp - s.start), sessionMaxSec: s.exp - s.start, now, signer, ownerId: ownerClaimFor(keyIdOf(signer.publicKey), { now }) });
  return out({ [HEADER_NAME]: token });
}

async function mint(o) {
  const signer = signerOrDie();
  let s = o.new ? null : sessionFromEnv();
  let reg = null;
  if (!s) {
    if (!o.new) { process.stderr.write("moorai-identity: no agent session in the environment; pass --new to start one\n"); return 2; }
    s = newSession(o);
    reg = await register(s, signer);
  }
  const token = mintToken({ sid: s.sid, agentName: s.agentName, sat: s.start, ttlSec: secs(o.ttl, TOKEN_TTL_SEC, s.exp - s.start), sessionMaxSec: s.exp - s.start, signer, ownerId: ownerClaimFor(keyIdOf(signer.publicKey)) });
  if (o.json) process.stdout.write(`${JSON.stringify({ token, id: s.sid, agentName: s.agentName, sessionExp: new Date(s.exp * 1000).toISOString(), ...(reg ? { console: reg } : {}) })}\n`);
  else process.stdout.write(`${token}\n`);
  return 0;
}

// The device's own view of its owner: the local assertion checked with the policy's keys (anchor or pin), offline.
async function localOwnerView() {
  const config = loadConfig();
  const pub = devicePublicKey();
  const f = readOwnerFile();
  if (!f) return { config, f: null, v: { status: "none" } };
  const { policyTrustKeys } = await import("./hook-core.mjs");
  return { config, f, v: verifyAssertion(f.assertion, { keys: policyTrustKeys(config), tenant: config.tenant, kid: pub ? keyIdOf(pub) : "" }) };
}

async function verify(o) {
  const token = (o._[1] || readFileSync(0, "utf8")).trim();
  let policy = null;
  try { const { loadVerifiedPolicy } = await import("./hook-core.mjs"); policy = (await loadVerifiedPolicy(loadConfig(), { network: false })).policy || null; } catch { policy = null; }
  const cfg = identityConfig(policy);
  const v = verifyToken(token, { publicKey: devicePublicKey(), maxTokenSec: cfg.maxTokenSec, maxSessionSec: cfg.maxSessionSec });
  const status = v.sid && cfg.revoked.has(v.sid) ? "revoked" : v.status;
  let owner = null;
  if (v.own) { const lo = await localOwnerView(); owner = { id: v.own, status: ownerStatus(v.own, lo.v.claims ? { status: lo.v.status, oid: lo.v.claims.oid, aid: lo.v.claims.aid } : lo.v, policy) }; }
  process.stdout.write(`${JSON.stringify({ status, ...(v.sid ? { id: v.sid, agentName: v.agentName, exp: new Date(v.exp * 1000).toISOString() } : {}), mode: cfg.mode, ...(owner ? { owner } : {}) })}\n`);
  return status === "verified" ? 0 : 1;
}

async function login(o) {
  const config = loadConfig();
  if (!isEnrolled(config)) { process.stderr.write("moorai-identity: this device is not enrolled with a MoorAI console\n"); return 2; }
  const signer = signerOrDie();
  const { deviceLogin, browserLogin } = await import("./owner-login.mjs");
  const say = (t) => process.stderr.write(`${t}\n`);
  const timeoutSec = secs(o.timeout, o.browser ? 300 : 900, 900);
  const r = o.browser ? await browserLogin({ config, signer, who: whoAmI(), say, open: !o["no-open"], timeoutSec }) : await deviceLogin({ config, signer, who: whoAmI(), say, timeoutSec });
  if (r.status !== "bound") {
    process.stderr.write(`moorai-identity: sign-in ${r.status}${r.reason ? ` (${r.reason})` : ""}${r.error ? `: ${r.error}` : ""}\n`);
    if (o.json) process.stdout.write(`${JSON.stringify({ status: r.status, ...(r.reason ? { reason: r.reason } : {}) })}\n`);
    return 1;
  }
  const c = parseAssertion(r.assertion);
  if (!c || c.kid !== keyIdOf(signer.publicKey)) { process.stderr.write("moorai-identity: the console's owner assertion does not name this device key\n"); return 1; }
  writeOwnerFile({ assertion: r.assertion, ...(r.owner.email ? { email: r.owner.email } : {}), ...(r.owner.name ? { name: r.owner.name } : {}), boundAt: new Date(c.iat * 1000).toISOString(), expiresAt: r.expiresAt });
  const { v } = await localOwnerView();
  process.stderr.write(`moorai-identity: signed in as ${r.owner.email || r.owner.name || r.owner.id} (${r.owner.id}) on device key ${c.kid} until ${r.expiresAt}${v.status === "ok" ? "" : `; the assertion is ${v.status} here until the device has a verified policy`}. New agent sessions carry this owner.\n`);
  if (o.json) process.stdout.write(`${JSON.stringify({ status: "bound", ownerId: r.owner.id, email: r.owner.email || null, keyId: c.kid, expiresAt: r.expiresAt, local: v.status })}\n`);
  return 0;
}

async function whoami(o) {
  const { f, v } = await localOwnerView();
  const c = f && parseAssertion(f.assertion);
  const out = { status: v.status, ...(c ? { ownerId: c.oid, keyId: c.kid, expiresAt: new Date(c.exp * 1000).toISOString() } : {}), ...(f && f.email ? { email: f.email } : {}) };
  if (o.json) process.stdout.write(`${JSON.stringify(out)}\n`);
  else process.stdout.write(v.status === "none" ? "no owner signed in on this device key (moorai-identity login)\n" : `${out.email || out.ownerId} (${out.ownerId}), key ${out.keyId}, until ${out.expiresAt}: ${v.status}\n`);
  return v.status === "ok" ? 0 : 1;
}

async function logout() {
  const config = loadConfig();
  const signer = signerOrDie();
  let remote = "not enrolled";
  if (isEnrolled(config)) { const { deviceLogout } = await import("./owner-login.mjs"); remote = await deviceLogout({ config, signer, who: whoAmI() }); }
  const removed = removeOwnerFile();
  process.stderr.write(`moorai-identity: ${removed ? "removed the local owner assertion" : "no local owner assertion"}; ${remote}\n`);
  return 0;
}

const o = parse(process.argv.slice(2));
const cmd = o._[0];
const code = cmd === "run" ? await run(o) : cmd === "headers" ? headers(o) : cmd === "mint" ? await mint(o) : cmd === "verify" ? await verify(o)
  : cmd === "login" ? await login(o) : cmd === "whoami" ? await whoami(o) : cmd === "logout" ? await logout()
  : (process.stderr.write("usage: moorai-identity run|headers|mint|verify|login|whoami|logout (see the comment at the top of cli/moorai-identity.mjs)\n"), 2);
process.exit(code);
