// Integration proof that cli/moorai-hook.mjs derives content-free SUBAGENT LINEAGE from Claude Code's
// PreToolUse stdin. Claude Code stamps a subagent's OWN tool-call payloads with `agent_id`/`agent_type`
// (common input fields present only inside a subagent). The hook must attribute those events to the
// subagent as a DISTINCT actor with the spawning session as its parent, so the per-agent baseline
// profiles each subagent separately instead of merging it into its spawner.
//
// The hook is spawned as a real subprocess with an isolated, ENROLLED HOME (so contentHash is a keyed
// HMAC and the ids are distinct rather than the NO_KEY sentinel an unenrolled device emits), then the
// on-device ~/.moorai/agent-events.jsonl it writes is read back and checked.
//
//   node --test test/hook-subagent-lineage.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { deriveKey, hashWithKey } from "../cli/content-hash.mjs";
import { buildBaseline } from "../data/agent-baseline.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TOKEN = "test-enroll-token";
const KEY = deriveKey(TOKEN);
const h = (s) => hashWithKey(KEY, s);

// One http server stands in for the console: serves an (unsigned, TOFU-accepted) policy so the hook
// proceeds past policy load into the Read branch, and swallows alert POSTs.
async function withServer(fn) {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free" })); return; }
    if (req.url === "/api/alerts" && req.method === "POST") { req.on("data", () => {}); req.on("end", () => { res.writeHead(200); res.end("{}"); }); return; }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(server.address().port); } finally { server.close(); }
}

function makeHome(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-lineage-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: TOKEN }));
  writeFileSync(join(home, "target.txt"), "nothing sensitive here\n"); // the file the Read branch scans
  return home;
}

async function runHook(home, input) {
  const child = spawn(process.execPath, [HOOK], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  child.stdout.on("data", () => {});
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify(input));
  await new Promise((r) => child.on("exit", r));
}

function events(home) {
  const p = join(home, ".moorai", "agent-events.jsonl");
  return existsSync(p) ? readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
}

test("a top-level Read is attributed to the session; a subagent's Read is a distinct actor with the session as parent", async () => {
  await withServer(async (port) => {
    const home = makeHome(port);
    const sessionId = "sess-abc-123";
    const file = join(home, "target.txt");

    // 1) Top-level agent call — no agent_id/agent_type on the payload.
    await runHook(home, { tool_name: "Read", session_id: sessionId, tool_input: { file_path: file } });
    // 2) A subagent's OWN call in the SAME session — carries agent_id + agent_type (Claude Code fields).
    await runHook(home, { tool_name: "Read", session_id: sessionId, agent_id: "agent-xyz", agent_type: "Explore", tool_input: { file_path: file } });

    const rows = events(home);
    assert.equal(rows.length, 2, `expected two recorded agent events, got ${rows.length}`);

    const SESSION = h(sessionId);
    const CHILD = h("Explore"); // actor keyed on agent_type so it joins the Task handoff edge

    const [top, sub] = rows;
    // Top-level: actor and session are the session; no child lineage.
    assert.equal(top.agent, SESSION, "top-level event must be attributed to the session");
    assert.equal(top.session, SESSION);
    assert.equal(top.parent, undefined, "a top-level event has no parent edge");
    assert.equal(top.role, undefined, "a top-level event is not a subagent");

    // Subagent: distinct actor, spawning session as parent, same session/trace, role marked.
    assert.equal(sub.agent, CHILD, "a subagent's event must be attributed to the subagent (by agent_type)");
    assert.equal(sub.parent, SESSION, "the subagent's parent must be the spawning session");
    assert.equal(sub.session, SESSION, "the subagent shares its parent's session/trace");
    assert.equal(sub.role, "subagent");
    assert.notEqual(sub.agent, top.agent, "the subagent must NOT collapse into the spawning session");

    // End-to-end: the baseline now profiles the two as separate actors.
    const base = buildBaseline(rows);
    assert.equal(base.actorCount, 2, "the session and the subagent must be distinct baseline actors");
    assert.ok(base.actors[SESSION] && base.actors[CHILD]);

    rmSync(home, { recursive: true, force: true });
  });
});
