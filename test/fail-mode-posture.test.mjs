// The effective fail mode per surface on the coverage heartbeat (cli/moorai-hook.mjs posturebeat worker →
// POST /api/agent-posture, body.failMode), so the console can show what each surface does when it cannot
// decide. Content-free: four {mode, source} pairs. The real hook, a throwaway HOME, a stand-in console.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-posture.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function consoleStub(t) {
  const posts = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/agent-posture") { posts.push(JSON.parse(b)); res.writeHead(201); return res.end("{}"); }
      res.writeHead(404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, posts };
}
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

for (const [label, policy, expect] of [
  ["a policy that sets the gateway and a default", { captureTier: "content-free", failMode: { default: "closed", mcpGateway: "open" } }, {
    hook: { mode: "closed", source: "policy" }, modelProxy: { mode: "closed", source: "policy" }, mcpGateway: { mode: "open", source: "policy" }, inferenceHook: { mode: "closed", source: "policy" }
  }],
  ["no failMode at all", { captureTier: "content-free" }, {
    hook: { mode: "open", source: "default" }, modelProxy: { mode: "open", source: "default" }, mcpGateway: { mode: "open", source: "default" }, inferenceHook: { mode: "open", source: "default" }
  }]
]) {
  test(`heartbeat carries failMode per surface: ${label}`, async (t) => {
    const c = await consoleStub(t);
    const empty = mkdtempSync(join(tmpdir(), "moorai-fm-beat-"));
    const sb = makeSandbox({ realHome: empty, config: { serverUrl: c.url, tenant: "acme", installToken: "tok-fm" } });
    t.after(() => { sb.cleanup(); rmTree(empty); });
    writeFileSync(join(sb.home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la" }, session_id: "s-1", cwd: sb.proj }),
      env: sb.env(), encoding: "utf8", timeout: 20000
    });
    assert.equal(r.status, 0);
    assert.ok(await until(() => c.posts.length === 1), "heartbeat posted");
    assert.deepEqual(c.posts[0].failMode, expect);
  });
}
