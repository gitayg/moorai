// A policy cache whose modification time is in the future must not count as fresh: before the fix,
// `Date.now() - mtime < 60000` accepted a negative age, so a cache stamped 2099 suppressed every policy
// fetch forever. The hook runs for real against a local console that counts /api/policy requests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

test("a policy cache dated in the future is refetched, not trusted forever", async () => {
  let fetches = 0;
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy") && !req.url.startsWith("/api/policy/pubkey")) fetches++;
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const home = mkdtempSync(join(tmpdir(), "moorai-future-mtime-"));
  try {
    mkdirSync(join(home, ".curaiq"), { recursive: true }); mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-future-mtime" }));
    const cache = join(home, ".moorai", "hook-policy.json");
    writeFileSync(cache, JSON.stringify({ captureTier: "content-free" }));
    const future = new Date("2099-01-01T00:00:00Z").getTime() / 1000;
    utimesSync(cache, future, future);
    const child = spawn(process.execPath, [HOOK], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home } });
    child.stdout.on("data", () => {}); child.stderr.on("data", () => {});
    child.stdin.end(JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" }, hook_event_name: "PreToolUse" }));
    await new Promise((r) => child.on("exit", r));
    assert.ok(fetches >= 1, `expected a policy fetch, got ${fetches}`);
  } finally { srv.close(); rmTree(home); }
});
