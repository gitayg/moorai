// Trace context on the hook's records (cli/moorai-hook.mjs, cli/trace-spawns.mjs): the real hook in a
// throwaway HOME, enrolled against a stand-in console. Every alert and allow-trail record carries the
// session's traceId (traceIdFor of session_id under the install token), a fresh spanId, and, on a
// sub-agent's records, parentSpanId = the span of the Task / Agent call that spawned it.
//
// The payload shapes are the ones Claude Code 2.1.295 sent in a live run against a local fake Messages API
// (PreToolUse(Agent) → [SubagentStart] → the child's PreToolUse with agent_id + agent_type → PostToolUse(Agent)
// with tool_response.agentId; a background spawn reports PostToolUse(Agent) before the child's first call).
//
//   node --test --import ./test/hermetic-env.mjs test/trace-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { traceIdFor } from "../cli/trace-context.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "trace-hook";
const TOKEN = "tok-trace-hook";
const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const HEX32 = /^[0-9a-f]{32}$/, HEX16 = /^[0-9a-f]{16}$/;
const key = generateKeyPairSync("ed25519");
const PUBKEY = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}

async function consoleStub(t, policy = () => JSON.stringify({ captureTier: "content-free" })) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (req.method === "POST") { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(policy()); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts };
}
function box(t, url, token = TOKEN) {
  const home = mkdtempSync(join(tmpdir(), "moorai-trace-hook-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: TENANT, ...(token ? { installToken: token } : {}) }));
  return home;
}
function hook(home, payload, extraEnv = {}) {
  const proj = join(home, "proj");
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, ...extraEnv } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, out, err }));
    c.stdin.end(JSON.stringify({ cwd: proj, ...payload }));
  });
}
const leak = (session, extra = {}) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name: "Bash", tool_input: { command: `echo ${AWS}` }, tool_use_id: `toolu_${Math.random().toString(36).slice(2)}`, ...extra });
const spawnCall = (session, toolUseId, type = "general-purpose", extra = {}) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name: "Agent", tool_input: { description: "child", prompt: "run the tests", subagent_type: type }, tool_use_id: toolUseId, ...extra });
const spawned = (session, toolUseId, agentId, status = "async_launched") => ({ hook_event_name: "PostToolUse", session_id: session, tool_name: "Agent", tool_input: { description: "child", prompt: "run the tests", subagent_type: "general-purpose" }, tool_use_id: toolUseId, tool_response: { isAsync: status === "async_launched", status, agentId, ...(status === "completed" ? { content: [{ type: "text", text: "done" }] } : {}) } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function newAlerts(c, n, fn) {
  const before = c.alerts.length;
  await fn();
  for (let i = 0; i < 40 && c.alerts.length - before < n; i++) await sleep(50);
  return c.alerts.slice(before);
}
const delegation = (alerts) => alerts.find((a) => a.threatId === 66);

test("every alert of a call carries the session's traceId, its own spanId, and no parent at the top level", async (t) => {
  const c = await consoleStub(t);
  const home = box(t, c.url);
  const sid = "4c1a2b3c-0000-4000-8000-000000000001";
  const a = await newAlerts(c, 1, () => hook(home, leak(sid)));
  assert.ok(a.length > 0, "the leak alerted");
  const want = traceIdFor({ tenantKey: TOKEN, sessionKey: sid });
  assert.match(want, HEX32);
  for (const x of a) {
    assert.equal(x.traceId, want, x.category);
    assert.match(x.spanId, HEX16);
    assert.equal(x.parentSpanId, undefined);
    assert.ok(!JSON.stringify(x).includes(sid), "the raw session id never leaves");
  }
  assert.equal(new Set(a.map((x) => x.spanId)).size, a.length, "a fresh span per record");
  // A second process in the same session joins the same trace; another session gets another.
  const b = await newAlerts(c, 1, () => hook(home, leak(sid)));
  assert.equal(b[0].traceId, want);
  const o = await newAlerts(c, 1, () => hook(home, leak("4c1a2b3c-0000-4000-8000-000000000002")));
  assert.notEqual(o[0].traceId, want);
});

test("a sub-agent's records join the parent session's trace under the Task call's span (inferred: one pending spawn of its type)", async (t) => {
  const c = await consoleStub(t);
  const home = box(t, c.url);
  const sid = "4c1a2b3c-0000-4000-8000-000000000003";
  const trace = traceIdFor({ tenantKey: TOKEN, sessionKey: sid });
  const d = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_parent1"))));
  assert.ok(d, "the delegation record");
  assert.equal(d.traceId, trace);
  assert.match(d.spanId, HEX16);
  // The child's own call (sync spawn: PostToolUse(Agent) comes only after the child has finished).
  const kid = await newAlerts(c, 1, () => hook(home, leak(sid, { agent_id: "a81befcc10c568217", agent_type: "general-purpose" })));
  assert.ok(kid.length > 0);
  for (const x of kid) { assert.equal(x.traceId, trace); assert.equal(x.parentSpanId, d.spanId, x.category); assert.notEqual(x.spanId, d.spanId); }
  // A grandchild spawned by that child hangs under the child's own Task span.
  const d2 = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_child1", "Explore", { agent_id: "a81befcc10c568217", agent_type: "general-purpose" }))));
  assert.equal(d2.parentSpanId, d.spanId, "the child's Task call is itself under the parent's Task span");
  const g = await newAlerts(c, 1, () => hook(home, leak(sid, { agent_id: "a0000000000000002", agent_type: "Explore" })));
  assert.equal(g[0].parentSpanId, d2.spanId);
  assert.equal(g[0].traceId, trace);
});

test("parallel spawns of one type: no parent is guessed until PostToolUse(Agent) names the child, then it is exact", async (t) => {
  const c = await consoleStub(t);
  const home = box(t, c.url);
  const sid = "4c1a2b3c-0000-4000-8000-000000000004";
  const d1 = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_p1"))));
  const d2 = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_p2"))));
  assert.notEqual(d1.spanId, d2.spanId);
  const child = { agent_id: "a2222222222222222", agent_type: "general-purpose" };
  const amb = await newAlerts(c, 1, () => hook(home, leak(sid, child)));
  assert.equal(amb[0].traceId, d1.traceId, "still the session's trace");
  assert.equal(amb[0].parentSpanId, undefined, "two candidates: no guess");
  await hook(home, spawned(sid, "toolu_p2", child.agent_id));
  const exact = await newAlerts(c, 1, () => hook(home, leak(sid, child)));
  assert.equal(exact[0].parentSpanId, d2.spanId);
  // The other child now has exactly one candidate left.
  const other = await newAlerts(c, 1, () => hook(home, leak(sid, { agent_id: "a1111111111111111", agent_type: "general-purpose" })));
  assert.equal(other[0].parentSpanId, d1.spanId);
});

test("an exact PostToolUse(Agent) binding corrects a wrong inference", async (t) => {
  const c = await consoleStub(t);
  const home = box(t, c.url);
  const sid = "4c1a2b3c-0000-4000-8000-000000000005";
  const d1 = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_q1"))));
  // Child B infers d1 (the only pending spawn) although it was spawned by q2, whose record went missing.
  const childB = { agent_id: "abbbbbbbbbbbbbbbb", agent_type: "general-purpose" };
  const wrong = await newAlerts(c, 1, () => hook(home, leak(sid, childB)));
  assert.equal(wrong[0].parentSpanId, d1.spanId);
  // q1 really spawned child A: its PostToolUse rebinds, and B goes back to unbound.
  await hook(home, spawned(sid, "toolu_q1", "aaaaaaaaaaaaaaaaa", "completed"));
  const a = await newAlerts(c, 1, () => hook(home, leak(sid, { agent_id: "aaaaaaaaaaaaaaaaa", agent_type: "general-purpose" })));
  assert.equal(a[0].parentSpanId, d1.spanId);
  const b = await newAlerts(c, 1, () => hook(home, leak(sid, childB)));
  assert.equal(b[0].parentSpanId, undefined, "B's wrong binding is gone");
});

test("a denied Task call records no spawn: its would-be child is not parented to it", async (t) => {
  const c = await consoleStub(t, () => JSON.stringify({ captureTier: "content-free", threatPolicy: { 66: "block" } }));
  const home = box(t, c.url);
  const sid = "4c1a2b3c-0000-4000-8000-000000000006";
  const r = await hook(home, spawnCall(sid, "toolu_denied"));
  assert.match(r.out, /"permissionDecision":"deny"/, r.out + r.err);
  const kid = await newAlerts(c, 1, () => hook(home, leak(sid, { agent_id: "a6666666666666666", agent_type: "general-purpose" })));
  assert.equal(kid[0].parentSpanId, undefined);
});

test("no install token: each invocation starts its own random trace (no keyed session trace)", async (t) => {
  const c = await consoleStub(t);
  const home = box(t, c.url, null);
  const sid = "4c1a2b3c-0000-4000-8000-000000000007";
  // Unenrolled: nothing is posted to the console; the OTLP mirror is the only export. Read it there.
  const spans = [];
  const otlp = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { try { spans.push(JSON.parse(b).resourceSpans[0].scopeSpans[0].spans[0]); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); }); });
  await new Promise((r) => otlp.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => otlp.close(r)));
  const OT = { MOORAI_OTLP_ENDPOINT: `http://127.0.0.1:${otlp.address().port}` };
  await hook(home, leak(sid), OT);
  await hook(home, leak(sid), OT);
  for (let i = 0; i < 40 && spans.length < 2; i++) await sleep(50);
  assert.ok(spans.length >= 2, `OTLP spans: ${spans.length}`);
  for (const s of spans) { assert.match(s.traceId, HEX32); assert.match(s.spanId, HEX16); }
  assert.notEqual(spans[0].traceId, spans[spans.length - 1].traceId);
});

test("OTLP export: the hook's spans carry the alert's trace ids, so a sub-agent's span is a child of the Task span", async (t) => {
  const c = await consoleStub(t);
  const home = box(t, c.url);
  const spans = [];
  const otlp = http.createServer((req, res) => { let b = ""; req.on("data", (d) => (b += d)); req.on("end", () => { try { spans.push(JSON.parse(b).resourceSpans[0].scopeSpans[0].spans[0]); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); }); });
  await new Promise((r) => otlp.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => otlp.close(r)));
  const OT = { MOORAI_OTLP_ENDPOINT: `http://127.0.0.1:${otlp.address().port}` };
  const sid = "4c1a2b3c-0000-4000-8000-000000000008";
  const d = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_o1"), OT)));
  const kid = await newAlerts(c, 1, () => hook(home, leak(sid, { agent_id: "a8888888888888888", agent_type: "general-purpose" }), OT));
  for (let i = 0; i < 40 && spans.length < 2; i++) await sleep(50);
  const ds = spans.find((s) => s.spanId === d.spanId);
  assert.ok(ds, "the delegation's span was exported with its own spanId");
  assert.equal(ds.traceId, d.traceId);
  const ks = spans.find((s) => s.spanId === kid[0].spanId);
  assert.ok(ks, "the child's span was exported");
  assert.equal(ks.traceId, d.traceId);
  assert.equal(ks.parentSpanId, d.spanId);
});

test("allow trail: the queued record of an allowed call carries the session's traceId and its own spanId", async (t) => {
  const c = await consoleStub(t, () => signed({ captureTier: "content-free", actionTrail: "allowed" }));
  const home = box(t, c.url);
  const sid = "4c1a2b3c-0000-4000-8000-000000000009";
  const d = delegation(await newAlerts(c, 1, () => hook(home, spawnCall(sid, "toolu_t1"))));
  const r = await hook(home, { hook_event_name: "PreToolUse", session_id: sid, tool_name: "Bash", tool_input: { command: "ls" }, agent_id: "a9999999999999999", agent_type: "general-purpose" });
  assert.equal(r.status, 0, r.err);
  const recs = readFileSync(join(home, ".moorai", "action-trail.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const task = recs.find((x) => x.tool === "Agent");
  const ls = recs.find((x) => x.tool === "Bash");
  assert.ok(task && ls, JSON.stringify(recs));
  const trace = traceIdFor({ tenantKey: TOKEN, sessionKey: sid });
  assert.equal(task.traceId, trace);
  assert.equal(ls.traceId, trace);
  assert.match(ls.spanId, HEX16);
  assert.notEqual(task.spanId, d.spanId, "a fresh span per record");
  assert.equal(ls.parentSpanId, d.spanId);
});

// Device-level inventory alerts belong to no session. The real posture-beat worker posts LOCAL_MODEL_EXPOSED
// with a stand-in TCP table (the test/posture-inventory-beat.test.mjs loader hook); it must carry no trace.
test("inventory: the posture beat's LOCAL_MODEL_EXPOSED alert carries no traceId, spanId or parentSpanId", async (t) => {
  const { pathToFileURL } = await import("node:url");
  const net = await import("node:net");
  const REAL = pathToFileURL(join(ROOT, "cli", "local-ai-inventory.mjs")).href;
  const dataUrl = (src) => `data:text/javascript,${encodeURIComponent(src)}`;
  const FAKE = dataUrl(`export * from ${JSON.stringify(REAL)};
export function tcpTable() { return { sockets: JSON.parse(process.env.TEST_SOCKETS || "[]"), source: "test" }; }`);
  const HOOKS = dataUrl(`export async function resolve(s, c, next) { if (s === "./local-ai-inventory.mjs" && c.parentURL && c.parentURL.endsWith("/cli/agent-posture.mjs")) return { url: ${JSON.stringify(FAKE)}, shortCircuit: true }; return next(s, c); }`);
  const IMPORT = dataUrl(`import { register } from "node:module"; register(${JSON.stringify(HOOKS)});`);
  const c = await consoleStub(t, () => signed({ captureTier: "content-free" }));
  // A loopback listener the worker's connect probe reaches: the "model server".
  const srv = net.createServer((s) => s.destroy());
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  const home = box(t, c.url);
  const sockets = [{ pid: "1", proc: "ollama", state: "listen", lhost: "127.0.0.1", lport: srv.address().port, rhost: null, rport: null }];
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, TEST_SOCKETS: JSON.stringify(sockets) };
  await new Promise((res) => { const p = spawn(process.execPath, ["--import", IMPORT, HOOK], { cwd: home, env, stdio: ["pipe", "ignore", "ignore"] }); p.on("close", res); p.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s-inv-trace", cwd: home })); });
  for (let i = 0; i < 200 && !c.alerts.some((a) => a.reasonCode === "LOCAL_MODEL_EXPOSED"); i++) await sleep(50);
  const ex = c.alerts.filter((a) => a.reasonCode === "LOCAL_MODEL_EXPOSED");
  assert.equal(ex.length, 1, `alerts: ${c.alerts.map((a) => a.reasonCode || a.category).join(", ")}`);
  for (const k of ["traceId", "spanId", "parentSpanId"]) assert.equal(ex[0][k], undefined, k);
});
