// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/task-bound-recovery.test.mjs
//
// Task-bound recovery and key-tree shape (cli/task-bound-hook.mjs, data/task-bound.js):
//   1. after the hook's state is tampered with, a session that existed before cannot get back out of the
//      fail-closed path by capturing a new prompt into the fresh state: the sessions the tampered state held are
//      carried over (keyed, HMAC-protected), and within 24 h any session not proven new — its transcript created
//      after the tamper — has every allowlist entry applied as if selected;
//   2. listed argument keys form a tree in which a dotted key below a listed leaf is cut off, never attached
//      to a higher node.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import * as tb from "../data/task-bound.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---- 2. key tree ----

const outcome = (args, input, extra = {}) => {
  const [e] = tb.resolveTaskBound({ taskAllowlists: [{ task: "t", match: { keywords: ["t"] }, tools: { arm: { args } }, default: "deny", ...extra }] }).lists;
  return tb.entryOutcome(e, "arm", input);
};

test("key tree: a dotted key below a listed leaf is cut off, never attached higher up", () => {
  for (const args of [{ a: ["x"], "a.b.c": ["y"] }, { "a.b.c": ["y"], a: ["x"] }]) {
    const order = Object.keys(args).join(",");
    assert.equal(outcome(args, { a: "x", b: { c: "y" } }).reason, "argument-not-listed", `${order}: b is not a listed top-level key`);
    assert.equal(outcome(args, { b: { c: "y" } }).reason, "argument-not-listed", `${order}`);
    assert.equal(outcome(args, { a: "x", "a.c": "y" }).reason, "argument-not-listed", `${order}: a.c is not listed`);
    assert.notEqual(outcome(args, { a: { c: "y" } }).outcome, "allow", `${order}: a is a leaf, its value an object`);
    assert.equal(outcome(args, { a: "x" }).outcome, "allow", `${order}`);
  }
  assert.equal(outcome({ "a.b": ["x"], "a.b.c": ["y"] }, { a: { b: "x" } }).outcome, "allow", "a listed a.b stays a leaf whatever the order");
  assert.equal(outcome({ "a.b.c": ["y"], "a.b": ["x"] }, { a: { b: "x" } }).outcome, "allow");
});

// ---- 1. tamper recovery ----

const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const POLICY = { captureTier: "content-free", taskAllowlists: [{ task: "harvest", match: { keywords: ["harvest"] }, tools: { "mcp__robot__cut": { args: { target: ["apple"] } } }, default: "deny" }] };
async function withHook(fn) {
  const alerts = [];
  const srv = http.createServer((q, r) => {
    let b = ""; q.on("data", (d) => (b += d));
    q.on("end", () => {
      if (q.url.startsWith("/api/policy")) { r.writeHead(200, { "Content-Type": "application/json" }); r.end(JSON.stringify(POLICY)); return; }
      if (q.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } }
      r.writeHead(201); r.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "moorai-tb-rec-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "transcripts"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "acme", installToken: "tok-tb-rec" }));
  const run = async (payload) => {
    const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "", MOORAI_LOCAL_HOST: "http://127.0.0.1:9" } });
    let out = "";
    child.stdout.on("data", (c) => { out += c; });
    child.stderr.on("data", () => {});
    child.stdin.end(JSON.stringify(payload));
    await new Promise((r) => child.on("exit", r));
    const t = out.trim();
    return t ? JSON.parse(t).hookSpecificOutput?.permissionDecision || "allow" : "allow";
  };
  // A transcript file per session, created when the session starts (as the host creates one).
  const transcript = (session) => { const p = join(home, "transcripts", `${session}.jsonl`); rmSync(p, { force: true }); writeFileSync(p, "{}\n"); return p; };
  const prompt = (session, text, tp) => run({ hook_event_name: "UserPromptSubmit", session_id: session, prompt: text, source: "user", ...(tp ? { transcript_path: tp } : {}) });
  const mcp = (session, tool, input) => run({ hook_event_name: "PreToolUse", session_id: session, tool_name: tool, tool_input: input });
  try { await fn({ prompt, mcp, transcript, alerts, state: join(home, ".moorai", "task-terms.json") }); } finally { srv.close(); rmTree(home); }
}
const later = () => new Promise((r) => setTimeout(r, 20));
const birthtimes = (() => { try { const d = mkdtempSync(join(tmpdir(), "bt-")); const p = join(d, "f"); writeFileSync(p, ""); const ok = statSync(p).birthtimeMs > 0; rmTree(d); return ok; } catch { return false; } })();

test("recovery: tamper, then a new prompt in the same session — allowlisted tools stay held", async () => {
  await withHook(async ({ prompt, mcp, transcript, state }) => {
    const t1 = transcript("s1");
    await prompt("s1", "harvest the orchard", t1);
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny");
    rmSync(state);
    await prompt("s1", "write a poem", t1);
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "the old session is not proven new: held");
    assert.equal(await mcp("s1", "mcp__robot__cut", { target: "apple" }), "allow", "what every entry allows is not held");
    await prompt("s1", "and another prompt", t1);
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "nor after a second prompt");
  });
});

test("recovery: a session the tampered state held is carried over even if its transcript looks new", async () => {
  await withHook(async ({ prompt, mcp, transcript, state }) => {
    await prompt("s1", "harvest the orchard", transcript("s1"));
    const o = JSON.parse(readFileSync(state, "utf8"));
    if (o.m) o.m = {};
    writeFileSync(state, JSON.stringify(o)); // edited: fails the HMAC, its session keys still readable
    await prompt("s2", "write a poem", null); // this capture records the tamper and carries s1 over
    await later();
    const t1 = transcript("s1"); // s1's transcript recreated after the tamper: it looks new
    if (birthtimes) assert.ok(statSync(t1).birthtimeMs > statSync(state).mtimeMs - 1);
    await prompt("s1", "write a poem", t1);
    assert.equal(await mcp("s1", "mcp__robot__open_gate", {}), "deny", "carried over: held despite a new-looking transcript");
  });
});

test("recovery: within the window only a session proven new (transcript created after the tamper) is judged normally", async () => {
  await withHook(async ({ prompt, mcp, transcript, state }) => {
    await prompt("s1", "harvest the orchard", transcript("s1"));
    rmSync(state);
    await prompt("s1", "write a poem", null); // this capture records the tamper
    await later();
    if (birthtimes) {
      await prompt("s3", "write a poem", transcript("s3"));
      assert.equal(await mcp("s3", "mcp__robot__open_gate", {}), "allow", "a new session");
    }
    await prompt("s4", "write a poem", null);
    assert.equal(await mcp("s4", "mcp__robot__open_gate", {}), "deny", "no proof of newness: held");
    assert.equal(await mcp("s5", "mcp__robot__open_gate", {}), "deny", "never captured since the tamper: held");
  });
});
