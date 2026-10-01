// The coverage heartbeat (cli/moorai-hook.mjs maybePostureBeat / posturebeat worker): the real hook,
// run in a throwaway HOME against a local stand-in console, posts at most one content-free heartbeat
// per host per UTC day — one more on the day's first bypassPermissions session — and nothing at all
// when the device is not enrolled. A failed post is retried after a pause, not on every tool call.
//
//   node --test test/agent-posture-beat.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const AGENT_HOOK = join(ROOT, "cli", "moorai-agent-hook.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function consoleStub(t, status = 201) {
  const posts = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/agent-posture") { posts.push({ token: req.headers["x-install-token"], body: JSON.parse(b) }); res.writeHead(status); return res.end("{}"); }
      res.writeHead(404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, posts };
}
function box(t, url, token = "tok-test") {
  const empty = mkdtempSync(join(tmpdir(), "moorai-beat-real-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: url, tenant: "acme", ...(token ? { installToken: token } : {}) } });
  t.after(() => { sb.cleanup(); rmSync(empty, { recursive: true, force: true }); });
  const run = (extra = {}, file = HOOK, args = []) => spawnSync(process.execPath, [file, ...args], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la" }, session_id: "s-1", cwd: sb.proj, ...extra }),
    env: sb.env(), encoding: "utf8", timeout: 20000
  });
  return { ...sb, run };
}
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

test("ONE A DAY: the first hook call posts one heartbeat with the posture; the next calls that day post nothing", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  assert.equal(b.run().status, 0);
  assert.ok(await until(() => c.posts.length === 1), "heartbeat posted");
  for (let i = 0; i < 3; i++) b.run();
  await sleep(1500);
  assert.equal(c.posts.length, 1, "no second heartbeat the same day");
  const { token, body } = c.posts[0];
  assert.equal(token, "tok-test");
  assert.deepEqual(body.heartbeat, { host: "claude-code", permissionMode: "" });
  assert.equal(body.device, hostname());
  assert.equal(body.serverMode, false);
  assert.equal(body.posture.v, 1);
  assert.ok(Array.isArray(body.posture.hosts));
  const raw = JSON.stringify(body);
  assert.ok(!raw.includes(b.proj) && !raw.includes(b.home) && !raw.includes("ls -la"), raw);
  const stamp = JSON.parse(readFileSync(join(b.home, ".moorai", "posture-beat-claude-code.json"), "utf8"));
  assert.equal(stamp.day, new Date().toISOString().slice(0, 10));
});

test("BYPASS SESSION: the day's first bypassPermissions call posts once more, flagged; later ones do not", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  b.run();
  assert.ok(await until(() => c.posts.length === 1));
  b.run({ permission_mode: "bypassPermissions" });
  assert.ok(await until(() => c.posts.length === 2), "bypass heartbeat posted");
  b.run({ permission_mode: "bypassPermissions" });
  await sleep(1500);
  assert.equal(c.posts.length, 2);
  assert.equal(c.posts[1].body.heartbeat.permissionMode, "bypassPermissions");
  const cc = c.posts[1].body.posture.hosts.find((h) => h.host === "claude-code");
  assert.deepEqual(cc && cc.flags.sessionBypassPermissions, ["session"]);
});

test("OTHER HOSTS: a Codex call through the agent hook beats as codex, separately from Claude Code", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  b.run({}, AGENT_HOOK, ["codex"]);
  assert.ok(await until(() => c.posts.length === 1));
  assert.equal(c.posts[0].body.heartbeat.host, "codex");
  b.run();
  assert.ok(await until(() => c.posts.length === 2));
  assert.equal(c.posts[1].body.heartbeat.host, "claude-code");
});

test("NOT ENROLLED: no token, no console, no heartbeat", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url, null);
  b.run();
  await sleep(2000);
  assert.equal(c.posts.length, 0);
});

test("CONSOLE DOWN: a refused post is retried after a pause, not on every tool call", async (t) => {
  const c = await consoleStub(t, 503);
  const b = box(t, c.url);
  b.run();
  assert.ok(await until(() => c.posts.length === 1));
  for (let i = 0; i < 3; i++) b.run();
  await sleep(1500);
  assert.equal(c.posts.length, 1, "one attempt inside the retry pause");
  const stamp = JSON.parse(readFileSync(join(b.home, ".moorai", "posture-beat-claude-code.json"), "utf8"));
  assert.equal(stamp.day, undefined, "the day is not marked done");
  assert.ok(stamp.pending > 0);
});
