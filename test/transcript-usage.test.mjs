// F15 endpoint source (cli/transcript-usage.mjs): the usage Claude Code records on each assistant message in its
// local transcripts (~/.claude/projects/**/*.jsonl, message.usage), read incrementally, deduplicated by message
// id (Claude Code writes one line per content block, each repeating the message's usage), bucketed by hour,
// model and keyed project hash, and posted as source "transcript". Never content, never a path.
//
//   node --test test/transcript-usage.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, utimesSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runTranscriptUsage, TRANSCRIPT_INSTANCE, TRANSCRIPT_STATE, TRANSCRIPT_STAMP } from "../cli/transcript-usage.mjs";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const NOW = Date.parse("2026-10-21T12:00:00Z");
const CWD = "/Users/someone/secret-project";
const hash = (s) => `h2:${Buffer.from(s).toString("hex").slice(0, 16)}`;
const asst = (id, model, ts, usage, text = "PRIVATE-ANSWER") => JSON.stringify({ parentUuid: "p", isSidechain: false, type: "assistant", uuid: "u", timestamp: ts, cwd: CWD, sessionId: "s", message: { model, id, type: "message", role: "assistant", content: [{ type: "text", text }], ...(usage ? { usage } : {}) }, requestId: "req" }) + "\n";
const U1 = { input_tokens: 10, cache_creation_input_tokens: 100, cache_read_input_tokens: 1000, output_tokens: 5, service_tier: "standard" };
const U2 = { input_tokens: 3, cache_creation_input_tokens: 0, cache_read_input_tokens: 0, output_tokens: 7 };

function fixture(t) {
  const home = mkdtempSync(join(tmpdir(), "moorai-trusage-"));
  t.after(() => rmTree(home));
  const proj = join(home, ".claude", "projects", "-Users-someone-secret-project");
  mkdirSync(join(proj, "s1", "subagents"), { recursive: true });
  const main = join(proj, "s1.jsonl");
  writeFileSync(main,
    JSON.stringify({ type: "user", message: { role: "user", content: "PRIVATE-PROMPT" }, cwd: CWD, timestamp: "2026-10-21T10:01:00Z" }) + "\n" +
    asst("msg_1", "claude-opus-5-5", "2026-10-21T10:02:00Z", U1, "block one") +
    asst("msg_1", "claude-opus-5-5", "2026-10-21T10:02:01Z", U1, "block two") +
    asst("msg_1", "claude-opus-5-5", "2026-10-21T10:02:02Z", U1, "block three") +
    asst("msg_2", "claude-haiku-4-5", "2026-10-21T11:30:00Z", U2) +
    asst("msg_s", "<synthetic>", "2026-10-21T11:31:00Z", { input_tokens: 0, output_tokens: 0 }) +
    asst("msg_3", "claude-opus-5-5", "2026-10-21T11:40:00Z", null) +
    asst("msg_p", "claude-opus-5-5", "2026-10-21T11:50:00Z", U2).slice(0, 40));
  writeFileSync(join(proj, "s1", "subagents", "agent-a1.jsonl"), asst("msg_sub", "claude-opus-5-5", "2026-10-21T10:30:00Z", U2));
  const old = join(proj, "old.jsonl");
  writeFileSync(old, asst("msg_old", "claude-opus-5-5", "2026-08-01T10:00:00Z", U1));
  const t60 = (NOW - 60 * 86400_000) / 1000;
  utimesSync(old, t60, t60);
  for (const f of [main, join(proj, "s1", "subagents", "agent-a1.jsonl")]) utimesSync(f, NOW / 1000, NOW / 1000);
  return { home, proj, main, stateDir: join(home, ".moorai") };
}
function fakeFetch(status = 200) {
  const calls = [];
  const f = async (url, init) => { calls.push({ url, headers: init.headers, body: JSON.parse(init.body), raw: init.body }); return { ok: status >= 200 && status < 300, status }; };
  f.calls = calls;
  return f;
}
const CFG = { serverUrl: "http://console.test", installToken: "tok-1" };
const ID = { user: "alice", device: "mac-1", platform: "darwin" };
const run = (f, fetchImpl, extra = {}) => runTranscriptUsage({ home: f.home, stateDir: f.stateDir, config: CFG, identity: ID, fetchImpl, hash, now: NOW, ...extra });

test("TRANSCRIPT: per-message usage, deduplicated by message id, bucketed by hour, model and project hash", async (t) => {
  const f = fixture(t);
  const fetch = fakeFetch();
  await run(f, fetch);
  assert.equal(fetch.calls.length, 1);
  const { url, headers, body, raw } = fetch.calls[0];
  assert.equal(url, "http://console.test/api/token-usage");
  assert.equal(headers["X-Install-Token"], "tok-1");
  assert.equal(body.source, "transcript");
  assert.equal(body.instance, TRANSCRIPT_INSTANCE);
  assert.match(body.instance, /^tr-[0-9a-f]{8}$/);
  const by = (hour, model) => body.buckets.find((b) => b.hour === hour && b.model === model);
  assert.deepEqual(by("2026-10-21T10:00:00Z", "claude-opus-5-5"), { hour: "2026-10-21T10:00:00Z", agentName: "claude-code", provider: "anthropic", model: "claude-opus-5-5", projectKey: hash(CWD), requests: 2, requestsNoUsage: 0, in: 13, out: 12, cacheRead: 1000, cacheWrite: 100 }, "msg_1 once (three lines), plus the sub-agent's msg_sub");
  assert.deepEqual([by("2026-10-21T11:00:00Z", "claude-haiku-4-5").in, by("2026-10-21T11:00:00Z", "claude-haiku-4-5").out], [3, 7]);
  const nu = by("2026-10-21T11:00:00Z", "claude-opus-5-5");
  assert.deepEqual([nu.requests, nu.requestsNoUsage], [1, 1], "a message without usage; the unfinished last line is not read yet");
  assert.ok(!body.buckets.some((b) => b.model === "<synthetic>" || b.model === "other"), "synthetic messages are not requests");
  assert.ok(!body.buckets.some((b) => b.hour.startsWith("2026-08")), "a file untouched for 60 days is not read");
  for (const leak of ["PRIVATE", "block one", CWD, "secret-project", f.home]) assert.ok(!raw.includes(leak), leak);
  const state = readFileSync(join(f.stateDir, TRANSCRIPT_STATE), "utf8");
  for (const leak of [CWD, "secret-project", "PRIVATE"]) assert.ok(!state.includes(leak), `state holds ${leak}`);
});

test("TRANSCRIPT: incremental; the finished line and new lines add to running totals; nothing new, nothing sent", async (t) => {
  const f = fixture(t);
  const fetch = fakeFetch();
  await run(f, fetch);
  const line = asst("msg_p", "claude-opus-5-5", "2026-10-21T11:50:00Z", U2);
  appendFileSync(f.main, line.slice(40) + asst("msg_4", "claude-opus-5-5", "2026-10-21T11:55:00Z", U2));
  await run(f, fetch);
  assert.equal(fetch.calls.length, 2);
  const b = fetch.calls[1].body.buckets;
  assert.equal(b.length, 1, "only the bucket that changed");
  assert.deepEqual([b[0].hour, b[0].requests, b[0].requestsNoUsage, b[0].in, b[0].out], ["2026-10-21T11:00:00Z", 3, 1, 6, 14]);
  await run(f, fetch);
  assert.equal(fetch.calls.length, 2);
});

test("TRANSCRIPT: a byte budget per run; later runs continue to the same totals", async (t) => {
  const f = fixture(t);
  const full = fakeFetch();
  await runTranscriptUsage({ home: f.home, stateDir: join(f.home, ".moorai-full"), config: CFG, identity: ID, fetchImpl: full, hash, now: NOW });
  const step = fakeFetch();
  for (let i = 0; i < 12; i++) await run(f, step, { maxBytes: 300 });
  const last = new Map();
  for (const c of step.calls) for (const b of c.body.buckets) last.set(`${b.hour}|${b.model}`, b);
  for (const b of full.calls[0].body.buckets) assert.deepEqual(last.get(`${b.hour}|${b.model}`), b);
});

test("TRANSCRIPT: a 404 (a console without the route) pauses posting for a day; unsent buckets stay", async (t) => {
  const f = fixture(t);
  const f404 = fakeFetch(404);
  await run(f, f404);
  await run(f, f404, { now: NOW + 3600_000 });
  assert.equal(f404.calls.length, 1);
  const ok = fakeFetch();
  await run(f, ok, { now: NOW + 25 * 3600_000 });
  assert.equal(ok.calls.length, 1);
  assert.ok(ok.calls[0].body.buckets.length >= 3);
});

async function consoleStub(t) {
  const usage = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url === "/api/token-usage") usage.push(JSON.parse(b)); res.writeHead(req.url === "/api/token-usage" || req.url === "/api/agent-posture" ? 200 : 404); res.end("{}"); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, usage };
}
function hookBox(t, url, enrolled) {
  const empty = mkdtempSync(join(tmpdir(), "moorai-trusage-hook-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: url, tenant: "acme", ...(enrolled ? { installToken: "tok-test" } : {}) } });
  t.after(() => { sb.cleanup(); rmTree(empty); });
  const proj = join(sb.home, ".claude", "projects", "-p");
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, "s.jsonl"), asst("msg_1", "claude-opus-5-5", new Date().toISOString(), U1));
  const run = () => spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s-1", cwd: sb.proj }), env: sb.env(), encoding: "utf8", timeout: 20000 });
  return { ...sb, run };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("HOOK: an enrolled Claude Code hook call starts the transcript usage worker, at most once an hour", async (t) => {
  const c = await consoleStub(t);
  const b = hookBox(t, c.url, true);
  b.run();
  const end = Date.now() + 10000;
  while (!c.usage.length && Date.now() < end) await sleep(100);
  assert.equal(c.usage.length, 1, "usage posted");
  assert.equal(c.usage[0].source, "transcript");
  assert.equal(c.usage[0].buckets[0].in, 10);
  appendFileSync(join(b.home, ".claude", "projects", "-p", "s.jsonl"), asst("msg_2", "claude-opus-5-5", new Date().toISOString(), U1));
  b.run();
  await sleep(2500);
  assert.equal(c.usage.length, 1, "no second run inside the hour, though there is new usage to send");
});

test("HOOK: an unenrolled device never reads transcripts", async (t) => {
  const c = await consoleStub(t);
  const b = hookBox(t, c.url, false);
  b.run();
  await sleep(1500);
  assert.equal(c.usage.length, 0);
  assert.equal(existsSync(join(b.home, ".moorai", TRANSCRIPT_STATE)), false);
  assert.equal(existsSync(join(b.home, ".moorai", TRANSCRIPT_STAMP)), false, "the worker is not even started");
});
