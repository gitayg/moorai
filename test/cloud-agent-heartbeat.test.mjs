// The coverage heartbeat (cli/moorai-hook.mjs posturebeat worker -> POST /api/agent-posture) carries the
// top-level cloudAgent field (CONTRACT-F28 §5.2) for a cloud agent in server mode, and no such key on a laptop.
// The real hook, a throwaway HOME, a stand-in console.
//
//   node --test --import ./test/hermetic-env.mjs test/cloud-agent-heartbeat.test.mjs
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
async function until(fn, ms = 15000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

async function beat(t, extraEnv) {
  const c = await consoleStub(t);
  const empty = mkdtempSync(join(tmpdir(), "moorai-cloud-beat-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: c.url, tenant: "acme", installToken: "tok-cloud" } });
  t.after(() => { sb.cleanup(); rmTree(empty); });
  writeFileSync(join(sb.home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free" }));
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls -la" }, session_id: "s-1", cwd: sb.proj }),
    env: sb.env(extraEnv(c.url)), encoding: "utf8", timeout: 20000
  });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(await until(() => c.posts.length >= 1), "heartbeat posted");
  return c.posts[0];
}

test("a cloud agent in server mode: the heartbeat carries cloudAgent { host, attestation }", async (t) => {
  const body = await beat(t, (url) => ({ MOORAI_MODE: "server", MOORAI_SERVER_URL: url, MOORAI_TENANT: "acme", MOORAI_INSTALL_TOKEN: "tok-cloud", MOORAI_SERVICE_ID: "cloud-bot", MOORAI_CLOUD_HOST: "claude-code-web" }));
  assert.equal(body.serverMode, true);
  assert.deepEqual(body.cloudAgent, { host: "claude-code-web", attestation: "static-token" });
});

test("a laptop (not server mode): the heartbeat has no cloudAgent key", async (t) => {
  const body = await beat(t, () => ({}));
  assert.equal(body.serverMode, false);
  assert.equal(Object.prototype.hasOwnProperty.call(body, "cloudAgent"), false);
});
