// F19 hook wiring: the Claude Code hook hands the policy's top-level mcpCatalogue to MCP reputation, so a
// cached catalogue signed by a key the policy anchors (and no other key) adds its verdict on an
// mcp__<label>__<tool> call. The hook never fetches the catalogue; it reads the cached copy only.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-catalogue-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { REPUTATION_CATEGORY } from "../data/mcp-reputation.js";
import { CATALOGUE_FORMAT } from "../data/mcp-catalogue.js";
import { signCatalogue, CATALOGUE_FILE } from "../cli/mcp-catalogue.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

const pub = generateKeyPairSync("ed25519");
const PUB_B64 = pub.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const CATALOGUE = signCatalogue({
  catalogue: CATALOGUE_FORMAT, v: 1, seq: 1, issuedAt: "2026-10-21T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", publisher: "test",
  entries: [{ kind: "mcp-server", ecosystem: "npm", name: "evil-mcp-thing", status: "do-not-install", source: "advisory", versions: [] }]
}, pub.privateKey);

async function withServer(policy, fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(policy)); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => { b += c; }); req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(server.address().port, alerts); } finally { server.closeAllConnections?.(); server.close(); }
}

function makeHome(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-cathook-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-cathook" }));
  writeFileSync(join(home, ".moorai", CATALOGUE_FILE), JSON.stringify({ url: "https://catalogue.example/cat.json", fetchedAt: Date.now() - 60000, catalogue: CATALOGUE }));
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { evil: { command: "npx", args: ["-y", "evil-mcp-thing@1.0.0"] } } }));
  return home;
}

async function runHook(home, tool) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" };
  for (const k of Object.keys(env)) if (/CATALOGUE/i.test(k)) delete env[k];
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env });
  child.stdout.on("data", () => {});
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, session_id: "cathook", cwd: home, tool_input: { path: "README.md" } }));
  await new Promise((r) => child.on("exit", r));
}
const settle = () => new Promise((r) => setTimeout(r, 300));

test("hook e2e: a cached catalogue anchored only by the policy's mcpCatalogue key adds catalogue-do-not-install to the reputation alert", async () => {
  await withServer({ captureTier: "content-free", mcpCatalogue: { publicKeys: [PUB_B64] } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, "mcp__evil__read_file");
      await settle();
      const reps = alerts.filter((a) => a.category === REPUTATION_CATEGORY);
      assert.equal(reps.length, 1, JSON.stringify(alerts.map((x) => x.category)));
      assert.ok(reps[0].reputation.reasons.includes("catalogue-do-not-install"), JSON.stringify(reps[0].reputation));
    } finally { rmTree(home); }
  });
});

test("hook e2e: without the policy's anchor the same cached catalogue does not verify and adds no verdict", async () => {
  await withServer({ captureTier: "content-free" }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, "mcp__evil__read_file");
      await settle();
      const reps = alerts.filter((a) => a.category === REPUTATION_CATEGORY);
      for (const a of reps) assert.equal(a.reputation.reasons.includes("catalogue-do-not-install"), false, JSON.stringify(a.reputation));
    } finally { rmTree(home); }
  });
});
