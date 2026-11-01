// Operator stop (cli/session-stop.mjs), device side, end to end against a fake console: the signed policy's
// agentStops denies every PreToolUse and blocks every UserPromptSubmit of the stopped session (or, for a device
// stop, of every session), posts one content-free SESSION_KILL acknowledgement per session, SIGTERMs the agent
// process that ran the hook and, for a device stop, drops the desktop host's kill-session sentinel. A stop the
// console no longer serves no longer applies; an unsigned or wrongly signed stop is never applied.
// The hook always runs under a fake agent (a node process that catches SIGTERM and reports it), never as a direct
// child of the test runner, so a SIGTERM never reaches the runner.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { hashWithKey, deriveKey } from "../cli/content-hash.mjs";
import { stopFor, agentStops, agentProcess, findAgentPid, stopReason, stopAlert } from "../cli/session-stop.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";
const TOKEN = "tok-session-stop";
const key = generateKeyPairSync("ed25519");
const otherKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function signedWith(k, policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), k.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const SESSION = "sess-stop-a";
const OTHER_SESSION = "sess-stop-b";
const sessionHash = (s) => hashWithKey(deriveKey(TOKEN), s);
const STOP_ID = "st-" + "a1".repeat(16);
const DEV_ID = "st-" + "b2".repeat(16);
const CANARY = "zz-stop-canary-5521";

async function consoleServer() {
  const alerts = [];
  const state = { stops: [], signer: key, unsignedStops: null };
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST") {
        try {
          if (req.url === "/api/alerts") alerts.push(JSON.parse(body));
          if (req.url === "/api/alerts/batch") { const b = JSON.parse(body); for (const a of b.alerts || []) alerts.push(a); }
        } catch { /* ignore */ }
        res.writeHead(201); return res.end("{}");
      }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(pubkeyBody); }
      if (req.url.startsWith("/api/policy")) {
        let out = signedWith(state.signer, { captureTier: "content-free", ...(state.stops.length ? { agentStops: state.stops } : {}) });
        if (state.unsignedStops) out = JSON.stringify({ ...JSON.parse(out), agentStops: state.unsignedStops });
        res.writeHead(200, { "content-type": "application/json" }); return res.end(out);
      }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, state, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function sandbox(c) {
  const home = mkdtempSync(join(tmpdir(), "moorai-stop-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: TOKEN }));
  return home;
}
const CACHE = (home) => join(home, ".moorai", "hook-policy.json");
const dropCache = (home) => rmSync(CACHE(home), { force: true });
// The fake agent: runs the hook as its child, catches SIGTERM (counting it) and reports the hook's result.
const AGENT = `const { spawn } = require("node:child_process");
let term = 0; process.on("SIGTERM", () => { term++; });
const c = spawn(process.execPath, [process.argv[1]], { stdio: ["pipe", "pipe", "pipe"], env: process.env, cwd: process.cwd() });
let out = "", err = ""; c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
c.on("close", (status) => setTimeout(() => { process.stdout.write(JSON.stringify({ status, out, err, term })); process.exit(0); }, 150));
process.stdin.pipe(c.stdin);`;
function runHook(home, payload, { session = SESSION } = {}) {
  const proj = join(home, "proj");
  return new Promise((res) => {
    const c = spawn(process.execPath, ["-e", AGENT, HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", () => { try { res(JSON.parse(out)); } catch { res({ status: -1, out: "", err: out + err, term: 0 }); } });
    c.stdin.end(JSON.stringify({ session_id: session, cwd: proj, ...payload }));
  });
}
const bash = (command) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const prompt = (p) => ({ hook_event_name: "UserPromptSubmit", prompt: p });
const decision = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecision || "allow"; } catch { return r.out.trim() ? "?" : "allow"; } };
const reasonOf = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecisionReason || ""; } catch { return ""; } };
const acks = (c) => c.alerts.filter((a) => a.reasonCode === "SESSION_KILL" && a.stopId);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return fn(); }
async function pin(home) { const r = await runHook(home, bash("echo pin")); assert.equal(r.status, 0, r.err); assert.equal(decision(r), "allow"); dropCache(home); }

test("unit: only well-formed stops count, a session stop matches only its session, a device stop matches every session", () => {
  const s = sessionHash(SESSION);
  const pol = { agentStops: [{ id: STOP_ID, scope: "session", session: s, at: "2026-10-31T00:00:00.000Z" }, { id: "bad", scope: "device" }, { id: DEV_ID, scope: "session", session: "nope" }, null, "x"] };
  assert.deepEqual(agentStops(pol).map((x) => x.id), [STOP_ID]);
  assert.equal(stopFor(pol, s).id, STOP_ID);
  assert.equal(stopFor(pol, sessionHash(OTHER_SESSION)), null);
  assert.equal(stopFor(pol, ""), null, "no session id: a session stop cannot match");
  assert.equal(stopFor({ agentStops: [{ id: DEV_ID, scope: "device" }] }, "").id, DEV_ID);
  assert.equal(stopFor({}, s), null);
  assert.equal(stopFor({ agentStops: "x" }, s), null);
  assert.match(stopReason({ id: STOP_ID, scope: "session", reason: "incident\n42" }), /^an administrator stopped this agent session \(stop st-[0-9a-f]{32}\): incident 42\. No further tool calls run in it/);
  assert.deepEqual(Object.keys(stopAlert({ id: STOP_ID, scope: "session", reason: CANARY }, { tool: "hook:Bash", signalled: true })).sort(),
    ["category", "contentHash", "decision", "reasonCode", "riskLevel", "signalled", "stage", "stopId", "stopScope", "threatId", "tool"], "the reason text never rides on the alert");
});

test("unit: the agent process is the first non-shell ancestor, and only an AI CLI or node is ever signalled", () => {
  const ch = (...imgs) => imgs.map((image, i) => ({ pid: 100 + i, ppid: 101 + i, image }));
  assert.equal(agentProcess(ch("sh", "claude", "zsh")), 101);
  assert.equal(agentProcess(ch("bash", "zsh", "node", "Terminal")), 102);
  assert.equal(agentProcess(ch("codex")), 100);
  assert.equal(agentProcess(ch("zsh", "Terminal")), 0, "a terminal is never signalled");
  assert.equal(agentProcess(ch("zsh", "Code Helper")), 0, "an IDE is never signalled");
  assert.equal(agentProcess(ch("sh", "launchd")), 0);
  assert.equal(agentProcess(ch("sh", "sh", "sh", "sh", "claude")), 104, "four hook shells are walked past");
  assert.equal(agentProcess(ch("sh", "sh", "sh", "sh", "sh", "claude")), 0, "a fifth is not");
  assert.equal(agentProcess(ch("node", "sh", "codex"), { shim: true }), 102, "a shim's adapter node is walked past");
  assert.equal(agentProcess([{ pid: 1, ppid: 0, image: "node" }]), 0);
  assert.equal(findAgentPid({ startPid: 5, platform: "win32", readChain: () => ch("claude") }), 0, "Windows: never signalled");
  assert.equal(findAgentPid({ startPid: 5, platform: "darwin", readChain: () => ch("sh", "claude") }), 101);
});

test("session stop: every later call of that session is denied, one content-free ack, the agent is SIGTERMed; another session runs", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    await pin(home);
    c.state.stops = [{ id: STOP_ID, scope: "session", session: sessionHash(SESSION), at: new Date().toISOString(), reason: "incident 42" }];
    dropCache(home);
    const r = await runHook(home, bash(`echo ${CANARY}`));
    assert.equal(r.status, 0, r.err);
    assert.equal(decision(r), "deny", r.out);
    assert.match(reasonOf(r), /an administrator stopped this agent session \(stop st-a1a1/);
    assert.match(reasonOf(r), /: incident 42\./);
    assert.equal(r.term, 1, "the agent process that ran the hook got one SIGTERM");
    assert.ok(await until(() => acks(c).length === 1), `one ack: ${JSON.stringify(c.alerts.map((a) => a.category))}`);
    const a = acks(c)[0];
    assert.equal(a.category, "Session stopped by an administrator");
    assert.equal(a.stopId, STOP_ID);
    assert.equal(a.stopScope, "session");
    assert.equal(a.signalled, true);
    assert.equal(a.session, sessionHash(SESSION), "the ack carries the session it stopped");
    assert.equal(a.riskLevel, "Blocked");
    assert.equal(existsSync(join(home, ".moorai", "kill-session")), false, "a session stop does not end the desktop host's agent");
    // Second call of the same session (fresh fetch): denied again, no second ack and no second SIGTERM.
    dropCache(home);
    const r2 = await runHook(home, bash("echo again"));
    assert.equal(decision(r2), "deny");
    assert.equal(r2.term, 0);
    const p = await runHook(home, prompt(`do ${CANARY}`));
    assert.match(p.out, /"decision":"block"/);
    assert.match(p.out, /an administrator stopped this agent session/);
    await sleep(400);
    assert.equal(acks(c).length, 1, "one ack per stop and session");
    // Another session on the same device is not stopped.
    const o = await runHook(home, bash("echo other"), { session: OTHER_SESSION });
    assert.equal(decision(o), "allow", o.out);
    assert.equal(o.term, 0);
    for (const x of c.alerts) { const s = JSON.stringify(x); assert.ok(!s.includes(CANARY) && !s.includes("incident 42"), `content-free: ${s}`); }
  } finally { await c.close(); rmTree(home); }
});

test("device stop: every session is denied and the desktop host's kill-session sentinel is dropped", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    await pin(home);
    c.state.stops = [{ id: DEV_ID, scope: "device", at: new Date().toISOString() }];
    dropCache(home);
    const r = await runHook(home, bash("echo a"));
    assert.equal(decision(r), "deny");
    assert.match(reasonOf(r), /an administrator stopped every agent on this device/);
    assert.equal(r.term, 1);
    const k = JSON.parse(readFileSync(join(home, ".moorai", "kill-session"), "utf8"));
    assert.equal(k.stopId, DEV_ID);
    assert.ok(Date.now() - k.ts < 60000, "fresh, so the desktop host acts on it");
    const o = await runHook(home, bash("echo b"), { session: OTHER_SESSION });
    assert.equal(decision(o), "deny");
    assert.equal(o.term, 1, "each session's agent is signalled once");
    assert.ok(await until(() => acks(c).length === 2));
    assert.deepEqual(acks(c).map((x) => x.stopScope), ["device", "device"]);
  } finally { await c.close(); rmTree(home); }
});

test("lift: once the console no longer serves the stop the session runs again", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    await pin(home);
    c.state.stops = [{ id: STOP_ID, scope: "session", session: sessionHash(SESSION), at: new Date().toISOString() }];
    dropCache(home);
    assert.equal(decision(await runHook(home, bash("echo a"))), "deny");
    c.state.stops = [];
    dropCache(home);
    assert.equal(decision(await runHook(home, bash("echo a"))), "allow");
  } finally { await c.close(); rmTree(home); }
});

test("signature: a stop added outside the signature, or signed by another key, is never applied", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    await pin(home);
    c.state.unsignedStops = [{ id: STOP_ID, scope: "device" }];
    dropCache(home);
    const r = await runHook(home, bash("echo a"));
    assert.equal(decision(r), "allow", r.out);
    assert.equal(r.term, 0);
    c.state.unsignedStops = null;
    c.state.signer = otherKey;
    c.state.stops = [{ id: STOP_ID, scope: "device" }];
    dropCache(home);
    const r2 = await runHook(home, bash("echo a"));
    assert.equal(decision(r2), "allow", r2.out);
    assert.equal(r2.term, 0);
    assert.equal(acks(c).length, 0);
    // A planted cache file with a stop and no valid signature: ignored too.
    writeFileSync(CACHE(home), JSON.stringify({ captureTier: "content-free", agentStops: [{ id: STOP_ID, scope: "device" }] }));
    c.state.signer = key; c.state.stops = [];
    assert.equal(decision(await runHook(home, bash("echo a"))), "allow");
  } finally { await c.close(); rmTree(home); }
});

test("latency: a cached policy younger than 60 s is used without a fetch, so the stop applies on the first call after that", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    await pin(home);
    assert.equal(decision(await runHook(home, bash("echo warm"))), "allow"); // fetch + cache, no stop yet
    c.state.stops = [{ id: STOP_ID, scope: "session", session: sessionHash(SESSION), at: new Date().toISOString() }];
    const inWindow = await runHook(home, bash("echo b"));
    assert.equal(decision(inWindow), "allow", "inside the cache window the stop is not seen yet");
    const past = (Date.now() - 61000) / 1000;
    utimesSync(CACHE(home), past, past);
    const t0 = Date.now();
    const r = await runHook(home, bash("echo c"));
    const ms = Date.now() - t0;
    assert.equal(decision(r), "deny", "the first call after the window fetches and is denied");
    console.log(`# stop applied on the first call after the 60 s cache window; that call took ${ms} ms including the fetch`);
  } finally { await c.close(); rmTree(home); }
});
