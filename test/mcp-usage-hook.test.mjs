// The hook half of the MCP usage cross-check: cli/moorai-hook.mjs counts every mcp__ PreToolUse call
// under path "hook", the agent it is running for ("claude-code", or MOORAI_HOOK_AGENT behind the
// agent-hook shim) and the server label its alerts carry as mcpServer, and hands completed days to a
// detached worker (cli/mcp-usage-beat.mjs) that posts them to /api/mcp-usage. The real hook, a
// throwaway HOME, a local stand-in console.
//
//   node --test test/mcp-usage-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";
import { TALLY_FILE } from "../cli/mcp-usage-beat.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const AGENT_HOOK = join(ROOT, "cli", "moorai-agent-hook.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const today = () => new Date().toISOString().slice(0, 10);
const yesterday = () => new Date(Date.now() - 86400000).toISOString().slice(0, 10);

async function consoleStub(t) {
  const usage = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/mcp-usage" && req.method === "POST") { usage.push({ token: req.headers["x-install-token"], body: JSON.parse(b) }); res.writeHead(201); return res.end("{}"); }
      res.writeHead(req.url === "/api/agent-posture" || req.url === "/api/alerts" ? 201 : 404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, usage };
}
function box(t, url, token = "tok-hook") {
  const empty = mkdtempSync(join(tmpdir(), "moorai-usage-real-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: url, tenant: "acme", ...(token ? { installToken: token } : {}) } });
  t.after(() => { sb.cleanup(); rmTree(empty); });
  const run = (tool = "mcp__github__create_issue", file = HOOK, args = []) => spawnSync(process.execPath, [file, ...args], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, tool_input: { title: "ARG-SECRET-TITLE" }, session_id: "s-1", cwd: sb.proj }),
    env: sb.env(), encoding: "utf8", timeout: 20000
  });
  const tally = () => { try { return JSON.parse(readFileSync(join(sb.home, ".moorai", TALLY_FILE), "utf8")); } catch { return null; } };
  return { ...sb, run, tally };
}
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

test("HOOK: every mcp__ call is counted under hook / claude-code / its server label; other tools are not", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  assert.equal(b.run().status, 0);
  b.run("mcp__github__list_issues");
  b.run("mcp__filesystem__read_file");
  b.run("Bash");
  assert.deepEqual(b.tally().days[today()], { "hook|claude-code": { github: 2, filesystem: 1 } });
  const raw = readFileSync(join(b.home, ".moorai", TALLY_FILE), "utf8");
  assert.ok(!raw.includes("create_issue") && !raw.includes("ARG-SECRET"), raw);
});

test("HOOK: an adapter's calls count under its agent id (codex)", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  b.run("mcp__github__create_issue", AGENT_HOOK, ["codex"]);
  assert.deepEqual(b.tally().days[today()], { "hook|codex": { github: 1 } });
});

test("HOOK FLUSH: a completed day is posted once by the detached worker, in the frozen shape", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  writeFileSync(join(b.home, ".moorai", TALLY_FILE), JSON.stringify({ v: 1, days: { [yesterday()]: { "hook|claude-code": { github: 7 }, "proxy|claude-desktop": { github: 9 } } } }));
  b.run();
  assert.ok(await until(() => c.usage.length === 1), "usage posted");
  for (let i = 0; i < 3; i++) b.run();
  await sleep(1500);
  assert.equal(c.usage.length, 1, "once — and the proxy's key is not the hook's to post");
  const { token, body } = c.usage[0];
  assert.equal(token, "tok-hook");
  assert.deepEqual(Object.keys(body).sort(), ["actor", "day", "device", "host", "path", "platform", "servers", "user"]);
  assert.equal(body.path, "hook");
  assert.equal(body.host, "claude-code");
  assert.equal(body.day, yesterday());
  assert.equal(body.device, hostname());
  assert.deepEqual(body.servers, [{ label: "github", calls: 7 }]);
});

test("HOOK FLUSH: not enrolled, nothing is posted", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url, null);
  writeFileSync(join(b.home, ".moorai", TALLY_FILE), JSON.stringify({ v: 1, days: { [yesterday()]: { "hook|claude-code": { github: 7 } } } }));
  b.run();
  await sleep(1500);
  assert.equal(c.usage.length, 0);
});
