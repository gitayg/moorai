// Operator stop, fast path (cli/stop-channel.mjs, cli/stop-watch.mjs). Units: the stop document's signed form is the
// console's and never a policy's; a document only adds stops, only when it verifies, names this tenant and actor and is
// newer than the policy; the watcher is started only while the verified policy names the channel; a session's agent
// process is recorded once; the watcher signals only a signed stop's live, still-identical processes, once each.
// End to end (real hook, real watcher, a fake console that holds the long-poll): an idle agent is SIGTERMed within a
// second of the stop and its next call is denied with no policy fetch; deleting the file falls back to the policy;
// a lift is followed; a console without the channel starts nothing.
// Every agent is a node process that catches SIGTERM, never the test runner.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, utimesSync, rmSync } from "node:fs";
import { tmpdir, userInfo, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId, canonicalJson } from "../cli/hook-core.mjs";
import { hashWithKey, deriveKey } from "../cli/content-hash.mjs";
import { stopDocCanonical, stopDocDigest, verifyStopDoc, fastStops, withFastStops, ensureWatcher, registerSession, sessionFile, processIdentity, STOP_FILE, WATCH_LOCK, STOP_CHANNEL_PATH, STALE_MS } from "../cli/stop-channel.mjs";
import { act, takeLock, readSessions } from "../cli/stop-watch.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";
const TOKEN = "tok-stop-channel";
const key = generateKeyPairSync("ed25519");
const otherKey = generateKeyPairSync("ed25519");
const h = (s) => hashWithKey(deriveKey(TOKEN), s);
const ACTOR = h(`${userInfo().username}@${hostname()}`);
const SESSION = "sess-fast-a";
const OTHER_SESSION = "sess-fast-b";
const STOP_ID = "st-" + "c3".repeat(16);
const DEV_ID = "st-" + "d4".repeat(16);
const DEV2_ID = "st-" + "e5".repeat(16);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return true; await sleep(25); } return fn(); }

function signDoc(k, body) {
  const doc = { v: 1, tenant: TENANT, actor: ACTOR, iat: new Date().toISOString(), ...body };
  const sig = edSign(null, Buffer.from(stopDocCanonical({ v: 1, tenant: doc.tenant, iat: doc.iat, digest: stopDocDigest(doc) })), k.privateKey).toString("base64");
  return { ...doc, sig };
}
function signPolicy(k, policy, iat = new Date().toISOString()) {
  return { ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig: edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), k.privateKey).toString("base64") } };
}
const sess = (s = SESSION) => ({ id: STOP_ID, scope: "session", session: h(s), at: "2026-10-31T00:00:00.000Z" });

// ---------------- units ----------------

test("unit: the signed form is the console's, pinned literally, and a signed policy never verifies as a stop document", () => {
  assert.equal(stopDocCanonical({ v: 1, tenant: "acme", iat: "2026-10-31T00:00:00.000Z", digest: "d0" }), "moorai-stops|v1|acme|2026-10-31T00:00:00.000Z|d0");
  const doc = signDoc(key, { agentStops: [sess()] });
  const keys = [key.publicKey];
  assert.deepEqual(verifyStopDoc(doc, { keys, tenant: TENANT, actor: ACTOR }), { ok: true, stops: [sess()], signed: true });
  assert.equal(verifyStopDoc(doc, { keys: [otherKey.publicKey], tenant: TENANT, actor: ACTOR }).status, "untrusted");
  assert.equal(verifyStopDoc(doc, { keys, tenant: "globex", actor: ACTOR }).status, "mismatch");
  assert.equal(verifyStopDoc(doc, { keys, tenant: TENANT, actor: "h2:" + "0".repeat(16) }).status, "actor");
  assert.equal(verifyStopDoc({ ...doc, agentStops: [sess(), { id: DEV_ID, scope: "device" }] }, { keys, tenant: TENANT, actor: ACTOR }).status, "untrusted", "a stop added outside the signature");
  assert.equal(verifyStopDoc({ ...doc, v: 2 }, { keys, tenant: TENANT, actor: ACTOR }).status, "malformed");
  assert.equal(verifyStopDoc(null, { keys }).status, "malformed");
  // A policy-shaped body signed as a policy, carrying the same fields, is not a stop document.
  const pol = signPolicy(key, { v: 1, tenant: TENANT, actor: ACTOR, iat: doc.iat, agentStops: [sess()] });
  assert.equal(verifyStopDoc({ ...pol, sig: pol.policySig.sig, policySig: undefined }, { keys, tenant: TENANT, actor: ACTOR }).status, "untrusted");
  assert.deepEqual(verifyStopDoc(doc, { keys: [], tenant: TENANT, actor: ACTOR }), { ok: true, stops: [sess()], signed: false }, "no key yet: taken unsigned (it can only add a stop)");
});

test("unit: the file only adds stops, and only when it is newer than the policy being enforced", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-fast-u-"));
  try {
    const keys = [key.publicKey];
    const older = signPolicy(key, { captureTier: "content-free" }, new Date(Date.now() - 5000).toISOString());
    const args = { policy: older, keys, tenant: TENANT, actor: ACTOR, stateDir: dir };
    assert.deepEqual(fastStops(args), [], "no file: nothing");
    writeFileSync(join(dir, STOP_FILE), JSON.stringify(signDoc(key, { agentStops: [sess()] })));
    assert.deepEqual(fastStops(args), [sess()]);
    const newer = signPolicy(key, { captureTier: "content-free" }, new Date(Date.now() + 5000).toISOString());
    assert.deepEqual(fastStops({ ...args, policy: newer }), [], "a policy issued after the document decides (a lift)");
    writeFileSync(join(dir, STOP_FILE), JSON.stringify(signDoc(otherKey, { agentStops: [sess()] })));
    assert.deepEqual(fastStops(args), [], "another key");
    writeFileSync(join(dir, STOP_FILE), "{not json");
    assert.deepEqual(fastStops(args), []);
    const withOwn = { agentStops: [{ id: DEV_ID, scope: "device" }] };
    assert.deepEqual(withFastStops(withOwn, []).agentStops, withOwn.agentStops, "an empty document removes nothing");
    assert.deepEqual(withFastStops(withOwn, [sess(), { id: DEV_ID, scope: "device" }]).agentStops.map((s) => s.id), [STOP_ID, DEV_ID]);
  } finally { rmTree(dir); }
});

test("unit: the watcher starts only for an enrolled device whose verified policy names the channel, and not while one is alive", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-fast-w-"));
  try {
    let n = 0;
    const start = () => { n++; };
    assert.equal(ensureWatcher({ policy: { captureTier: "x" }, enrolled: true, stateDir: dir, start }), false);
    assert.equal(ensureWatcher({ policy: { stopChannel: { v: 1 } }, enrolled: false, stateDir: dir, start }), false);
    assert.equal(ensureWatcher({ policy: { stopChannel: { v: 1 } }, enrolled: true, stateDir: dir, start }), true);
    writeFileSync(join(dir, WATCH_LOCK), "123\n");
    assert.equal(ensureWatcher({ policy: { stopChannel: { v: 1 } }, enrolled: true, stateDir: dir, start }), false, "a fresh lock");
    const old = (Date.now() - STALE_MS - 1000) / 1000;
    utimesSync(join(dir, WATCH_LOCK), old, old);
    assert.equal(ensureWatcher({ policy: { stopChannel: { v: 1 } }, enrolled: true, stateDir: dir, start }), true, "a stale lock");
    assert.equal(n, 2);
  } finally { rmTree(dir); }
});

test("unit: a session's agent process is recorded once; the lock is held by one watcher", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-fast-r-"));
  try {
    let walks = 0;
    const find = () => { walks++; return 4242; };
    const tag = h(SESSION);
    assert.equal(registerSession({ sessionTag: "", stateDir: dir, find }), false);
    assert.equal(registerSession({ sessionTag: tag, stateDir: dir, find, identity: () => "id-4242" }), true);
    assert.equal(registerSession({ sessionTag: tag, stateDir: dir, find, identity: () => "id-4242" }), false);
    assert.equal(walks, 1, "walked once per session");
    assert.deepEqual(JSON.parse(readFileSync(sessionFile(tag, dir), "utf8")).pid, 4242);
    assert.equal(readSessions(dir, { isAlive: () => true }).length, 1);
    assert.equal(readSessions(dir, { isAlive: () => false }).length, 0, "a dead process's record is removed");
    assert.equal(existsSync(sessionFile(tag, dir)), false);
    assert.equal(takeLock(dir, process.pid), true);
    assert.equal(takeLock(dir, 999999999), false, "held by a live, fresh watcher");
    const old = (Date.now() - STALE_MS - 1000) / 1000;
    utimesSync(join(dir, WATCH_LOCK), old, old);
    assert.equal(takeLock(dir, 999999999), true, "a stale lock is taken over");
    assert.equal(processIdentity(process.pid) !== "" || !["darwin", "linux"].includes(process.platform), true);
    assert.equal(processIdentity(process.pid), processIdentity(process.pid), "stable");
  } finally { rmTree(dir); }
});

test("unit: the watcher signals only a signed stop's live, unchanged processes, each once, and a device stop drops the sentinel once", () => {
  const killed = [], sent = [];
  const sessions = [{ session: h(SESSION), pid: 101, id: "A" }, { session: h(OTHER_SESSION), pid: 102, id: "B" }, { session: h("c"), pid: 0, id: "" }];
  const identity = (pid) => ({ 101: "A", 102: "B-reused" })[pid] || "";
  const base = { sessions, identity, kill: (pid) => killed.push(pid), sentinel: (r) => sent.push(r.stopId) };
  assert.deepEqual(act([sess()], { ...base, signed: false, done: new Set() }), [], "unsigned: nothing is signalled");
  assert.deepEqual(killed, []);
  const done = new Set();
  const acks = act([sess()], { ...base, signed: true, done });
  assert.deepEqual(killed, [101]);
  assert.deepEqual(acks.map((a) => a.session), [h(SESSION)]);
  assert.deepEqual(act([sess()], { ...base, signed: true, done }), [], "once per stop and session");
  const d = act([{ id: DEV_ID, scope: "device" }], { ...base, signed: true, done });
  assert.deepEqual(killed, [101, 101], "a device stop: every session, but pid 102 is no longer the recorded process");
  assert.deepEqual(d.length, 1);
  act([{ id: DEV_ID, scope: "device" }], { ...base, signed: true, done });
  assert.deepEqual(sent, [DEV_ID]);
});

// ---------------- end to end ----------------

// A fake console: a signed policy (with or without stopChannel) and the stop channel's long-poll.
async function consoleServer({ channel = true } = {}) {
  const alerts = [], polls = [];
  const state = { stops: [], policyFetches: 0, held: new Set() };
  const stateOf = () => createHash("sha256").update(canonicalJson({ actor: ACTOR, agentStops: state.stops })).digest("hex").slice(0, 32);
  const doc = () => signDoc(key, { state: stateOf(), agentStops: state.stops });
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const u = new URL(req.url, "http://x");
      if (req.method === "POST") {
        try { if (u.pathname === "/api/alerts") alerts.push(JSON.parse(body)); if (u.pathname === "/api/alerts/batch") for (const a of JSON.parse(body).alerts || []) alerts.push(a); } catch { /* ignore */ }
        res.writeHead(201); return res.end("{}");
      }
      if (u.pathname === "/api/policy/pubkey") { res.writeHead(200); return res.end(JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) })); }
      if (u.pathname === "/api/policy") {
        state.policyFetches++;
        res.writeHead(200); return res.end(JSON.stringify(signPolicy(key, { captureTier: "content-free", ...(channel ? { stopChannel: { v: 1, path: STOP_CHANNEL_PATH, waitSec: 25 } } : {}), ...(state.stops.length ? { agentStops: state.stops } : {}) })));
      }
      if (channel && u.pathname === STOP_CHANNEL_PATH) {
        polls.push({ actor: u.searchParams.get("actor"), token: req.headers["x-install-token"] });
        if (u.searchParams.get("actor") !== ACTOR) { res.writeHead(400); return res.end("{}"); }
        if (u.searchParams.get("known") !== stateOf()) { res.writeHead(200); return res.end(JSON.stringify(doc())); }
        const w = { known: u.searchParams.get("known"), answer: () => { state.held.delete(w); clearTimeout(w.t); res.writeHead(200); res.end(JSON.stringify(doc())); } };
        w.t = setTimeout(() => { state.held.delete(w); res.writeHead(204); res.end(); }, 25000);
        state.held.add(w);
        res.on("close", () => { state.held.delete(w); clearTimeout(w.t); });
        return;
      }
      res.writeHead(404); res.end();
    });
  });
  const setStops = (stops) => { state.stops = stops; for (const w of [...state.held]) if (w.known !== stateOf()) w.answer(); };
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, polls, state, setStops, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function sandbox(c) {
  const home = mkdtempSync(join(tmpdir(), "moorai-fast-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: TOKEN }));
  return home;
}
const env = (home) => ({ PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: join(home, "proj") });
// A busy agent: runs one hook call as its child, catches SIGTERM, reports.
const BUSY = `const { spawn } = require("node:child_process");
let term = 0; process.on("SIGTERM", () => { term++; });
const c = spawn(process.execPath, [process.argv[1]], { stdio: ["pipe", "pipe", "pipe"], env: process.env, cwd: process.cwd() });
let out = "", err = ""; c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
c.on("close", (status) => setTimeout(() => { process.stdout.write(JSON.stringify({ status, out, err, term })); process.exit(0); }, 150));
process.stdin.pipe(c.stdin);`;
// An idle agent: runs one hook call (which records it as the session's agent), prints "ready", then idles until SIGTERM,
// which it answers by writing the time to its file and exiting.
const IDLE = `const { spawn } = require("node:child_process"); const fs = require("node:fs");
process.on("SIGTERM", () => { fs.writeFileSync(process.argv[2], String(Date.now())); process.exit(0); });
const c = spawn(process.execPath, [process.argv[1]], { stdio: ["pipe", "pipe", "ignore"], env: process.env, cwd: process.cwd() });
c.stdin.end(process.argv[3]);
c.on("close", () => { process.stdout.write("ready\\n"); setInterval(() => {}, 1000); });`;
const call = (home, payload, { session = SESSION } = {}) => new Promise((res) => {
  const c = spawn(process.execPath, ["-e", BUSY, HOOK], { cwd: join(home, "proj"), env: env(home) });
  let out = "";
  c.stdout.on("data", (d) => (out += d));
  c.on("close", () => { try { res(JSON.parse(out)); } catch { res({ status: -1, out: "", err: out, term: 0 }); } });
  c.stdin.end(JSON.stringify({ session_id: session, cwd: join(home, "proj"), ...payload }));
});
function idleAgent(home, session) {
  const termFile = join(home, `term-${session}`);
  const c = spawn(process.execPath, ["-e", IDLE, HOOK, termFile, JSON.stringify({ session_id: session, cwd: join(home, "proj"), ...bash("echo idle") })], { cwd: join(home, "proj"), env: env(home), stdio: ["ignore", "pipe", "ignore"] });
  const ready = new Promise((r) => c.stdout.on("data", (d) => { if (String(d).includes("ready")) r(); }));
  return { proc: c, ready, termAt: () => { try { return Number(readFileSync(termFile, "utf8")); } catch { return 0; } } };
}
const bash = (command) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const decision = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecision || "allow"; } catch { return r.out.trim() ? "?" : "allow"; } };
const watcherPid = (home) => { try { return Number(readFileSync(join(home, ".moorai", WATCH_LOCK), "utf8").trim()); } catch { return 0; } };
function stopWatcher(home) { const p = watcherPid(home); if (p > 1) try { process.kill(p, "SIGTERM"); } catch { /* gone */ } }
const acks = (c) => c.alerts.filter((a) => a.reasonCode === "SESSION_KILL" && a.stopId);

test("e2e: a held channel ends an idle agent within a second of the stop, and its next call is denied with no policy fetch", { skip: !["darwin", "linux"].includes(process.platform) && "SIGTERM is macOS and Linux" }, async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  const idle = idleAgent(home, SESSION);
  try {
    await idle.ready;
    assert.ok(await until(() => watcherPid(home) > 1), "the hook started the watcher");
    assert.ok(await until(() => c.state.held.size === 1), `the watcher holds the channel open: ${JSON.stringify(c.polls)} ${readdirSync(join(home, ".moorai")).join(",")}`);
    assert.ok(c.polls.every((p) => p.actor === ACTOR && p.token === TOKEN), "polled as this device's actor, with its install token");
    assert.ok(existsSync(sessionFile(h(SESSION), join(home, ".moorai"))), "the session's agent process is recorded");
    const fetches = c.state.policyFetches;
    const t0 = Date.now();
    c.setStops([{ ...sess(), at: new Date().toISOString(), reason: "incident 77" }]);
    assert.ok(await until(() => idle.termAt() > 0, 5000), "the idle agent got SIGTERM");
    const ms = idle.termAt() - t0;
    console.log(`# stop -> SIGTERM of the idle agent: ${ms} ms`);
    assert.ok(ms < 1000, `SIGTERM ${ms} ms after the stop`);
    assert.ok(existsSync(join(home, ".moorai", STOP_FILE)), "the signed document is on disk");
    const r = await call(home, bash("echo after"));
    assert.equal(decision(r), "deny", r.out);
    assert.match(JSON.parse(r.out).hookSpecificOutput.permissionDecisionReason, /an administrator stopped this agent session \(stop st-c3c3/);
    assert.equal(c.state.policyFetches, fetches, "denied from the stop document: the 60 s policy cache was not refetched");
    assert.equal(decision(await call(home, bash("echo other"), { session: OTHER_SESSION })), "allow", "another session runs");
    assert.ok(await until(() => acks(c).some((a) => a.tool === "stop-watch")), "the watcher acknowledged the stop");
    const a = acks(c).find((x) => x.tool === "stop-watch");
    assert.deepEqual([a.stopId, a.stopScope, a.session, a.signalled, a.actor], [STOP_ID, "session", h(SESSION), true, ACTOR]);
    for (const x of c.alerts) assert.ok(!JSON.stringify(x).includes("incident 77"), "content-free");
  } finally { idle.proc.kill("SIGKILL"); stopWatcher(home); await c.close(); rmTree(home); }
});

test("e2e: the file can only add a stop: deleted, the policy still decides; a lift is followed; an older document never applies", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    assert.equal(decision(await call(home, bash("echo warm"))), "allow");
    assert.ok(await until(() => c.state.held.size === 1), "the watcher holds the channel open");
    c.setStops([{ id: DEV_ID, scope: "device", at: new Date().toISOString() }]);
    assert.ok(await until(() => existsSync(join(home, ".moorai", STOP_FILE))), "the watcher wrote the document");
    assert.equal(decision(await call(home, bash("echo a"))), "deny", "within the policy cache window, from the document");
    assert.ok(await until(() => existsSync(join(home, ".moorai", "kill-session"))), "a device stop drops the desktop host's sentinel");
    // A lift: the watcher removes the document, and the next policy decides.
    c.setStops([]);
    assert.ok(await until(() => !existsSync(join(home, ".moorai", STOP_FILE))), "the watcher removed the document");
    rmSync(join(home, ".moorai", "hook-policy.json"));
    assert.equal(decision(await call(home, bash("echo b"))), "allow", "lifted");
    // The agent deletes the document of a new stop: the stop still reaches it from the signed policy at its next fetch.
    c.setStops([{ id: DEV2_ID, scope: "device", at: new Date().toISOString() }]);
    assert.ok(await until(() => existsSync(join(home, ".moorai", STOP_FILE))), "the watcher wrote the second document");
    rmSync(join(home, ".moorai", STOP_FILE));
    rmSync(join(home, ".moorai", "hook-policy.json"));
    assert.equal(decision(await call(home, bash("echo c"))), "deny", "the policy carries the stop");
    c.setStops([]);
    assert.ok(await until(() => c.state.held.size === 1));
    // A stop document issued before the policy being enforced (a stale file, or a replay) never applies.
    const stale = signDoc(key, { agentStops: [{ id: DEV_ID, scope: "device" }] });
    await sleep(20);
    rmSync(join(home, ".moorai", "hook-policy.json"));
    assert.equal(decision(await call(home, bash("echo d"))), "allow");
    writeFileSync(join(home, ".moorai", STOP_FILE), JSON.stringify(stale));
    assert.equal(decision(await call(home, bash("echo e"))), "allow", "older than the policy");
    // Signed by another key: never applies.
    writeFileSync(join(home, ".moorai", STOP_FILE), JSON.stringify(signDoc(otherKey, { agentStops: [{ id: DEV_ID, scope: "device" }] })));
    assert.equal(decision(await call(home, bash("echo f"))), "allow", "another key");
  } finally { stopWatcher(home); await c.close(); rmTree(home); }
});

test("e2e: a console that does not name the stop channel starts no watcher and records nothing", async () => {
  const c = await consoleServer({ channel: false });
  const home = sandbox(c);
  try {
    assert.equal(decision(await call(home, bash("echo a"))), "allow");
    await sleep(500);
    assert.equal(existsSync(join(home, ".moorai", WATCH_LOCK)), false);
    assert.equal(existsSync(join(home, ".moorai", "stop-sessions")), false);
    assert.equal(c.polls.length, 0);
  } finally { stopWatcher(home); await c.close(); rmTree(home); }
});
