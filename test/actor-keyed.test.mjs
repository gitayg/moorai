// The `actor` every sender stamps on an outgoing event is KEYED — `h2:` + HMAC-SHA-256 of user@host
// under the tenant's enrollment token (cli/content-hash.mjs) — and never the bare 32-bit djb2 it used
// to be. djb2(user@host) is an encoding, not a hash: a login name and a hostname are a small space,
// so the console (or anyone holding its DB or SIEM feed) could read the pair back by enumeration.
//
// Every sender is exercised for real, against a listener that records what reaches the wire:
// the Claude Code hook, the `moorai-guard` CLI, the Claude Desktop MCP proxy, and the desktop app's
// renderer bridge (src/api.js). Unenrolled, the actor is the self-describing NO_KEY sentinel — the
// same fail-safe contentHash() already has — never a reversible fallback, and the hook still posts.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import os, { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { hashWithKey, deriveKey, NO_KEY, actorHash } from "../cli/content-hash.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOKEN = "it_test_actor_keyed_token";
const USER = os.userInfo().username, HOST = os.hostname();
const djb2 = (s) => { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; return "h" + h.toString(16); };
const LEGACY = djb2(`${USER}@${HOST}`);
const KEYED = hashWithKey(deriveKey(TOKEN), `${USER}@${HOST}`);
const AWS = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

async function listener() {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); res.end(); return; }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ captureTier: "content-free" })); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(201); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

function home(url, { enrolled }) {
  const h = mkdtempSync(join(tmpdir(), "moorai-actor-"));
  mkdirSync(join(h, ".moorai"), { recursive: true });
  writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", ...(enrolled ? { installToken: TOKEN } : {}) }));
  return h;
}
const envFor = (h) => { const e = { ...process.env, HOME: h, USERPROFILE: h, MOORAI_OFFLINE_MODE: "" }; delete e.MoorAI_SERVER; delete e.MoorAI_TENANT; return e; };

async function run(args, h, stdin) {
  const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: envFor(h) });
  child.stdout.on("data", () => {}); child.stderr.on("data", () => {});
  if (stdin != null) child.stdin.end(stdin); else child.stdin.end();
  const code = await new Promise((r) => child.on("exit", r));
  await new Promise((r) => setTimeout(r, 1200)); // an orphaned in-flight post would land here
  return code;
}

const assertKeyed = (alerts, expected, who) => {
  assert.ok(alerts.length > 0, `${who}: nothing reached the server`);
  for (const a of alerts) {
    assert.equal(a.actor, expected, `${who}: ${a.category} carried actor ${a.actor}`);
    assert.notEqual(a.actor, LEGACY, `${who}: djb2(user@host) on the wire`);
    assert.doesNotMatch(String(a.actor), /^h[0-9a-f]{1,8}$/, `${who}: a bare djb2 actor on the wire`);
  }
};

test("actorHash is the tenant-keyed content hash of user@host, and NO_KEY when unenrolled", () => {
  assert.match(KEYED, /^h2:[0-9a-f]{16}$/);
  assert.notEqual(KEYED, LEGACY);
  assert.equal(hashWithKey(deriveKey("another-tenant-token"), `${USER}@${HOST}`) === KEYED, false, "a different tenant's token gives a different actor");
  // actorHash() resolves the key from this process's own config; with the hermetic HOME in the unit
  // runner there is none, so it must take the fail-safe path rather than fall back to djb2.
  assert.ok(actorHash(USER, HOST) === NO_KEY || actorHash(USER, HOST).startsWith("h2:"));
});

test("HOOK (enrolled): every posted alert carries the keyed actor, never djb2", async () => {
  const L = await listener(); const h = home(L.url, { enrolled: true });
  try {
    await run([join(ROOT, "cli", "moorai-hook.mjs")], h, JSON.stringify({ tool_name: "Bash", tool_input: { command: `echo ${AWS}` } }));
    assertKeyed(L.alerts, KEYED, "hook");
  } finally { L.close(); rmSync(h, { recursive: true, force: true }); }
});

test("HOOK (unenrolled): still posts as today, with the NO_KEY actor — no reversible fallback", async () => {
  const L = await listener(); const h = home(L.url, { enrolled: false });
  try {
    const code = await run([join(ROOT, "cli", "moorai-hook.mjs")], h, JSON.stringify({ tool_name: "Bash", tool_input: { command: `echo ${AWS}` } }));
    assert.equal(code, 0);
    assert.ok(L.alerts.some((a) => a.category === "Information & Privacy"), "the finding still reaches the server");
    assertKeyed(L.alerts, NO_KEY, "hook/unenrolled");
  } finally { L.close(); rmSync(h, { recursive: true, force: true }); }
});

test("GUARD (enrolled): the moorai-guard CLI posts the keyed actor", async () => {
  const L = await listener(); const h = home(L.url, { enrolled: true });
  try {
    await run([join(ROOT, "cli", "moorai-guard.mjs"), "--decide", "abort", `deploy with ${AWS}`], h);
    assertKeyed(L.alerts, KEYED, "guard");
  } finally { L.close(); rmSync(h, { recursive: true, force: true }); }
});

test("MCP PROXY (enrolled): Claude Desktop's guard posts the keyed actor", async () => {
  const L = await listener(); const h = home(L.url, { enrolled: true });
  const recv = join(h, "recv.log");
  try {
    const child = spawn(process.execPath, [join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs"), "--server", "testsrv", "--", process.execPath, join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs"), recv],
      { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: envFor(h) });
    child.stderr.on("data", () => {});
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { msg: AWS } } }) + "\n");
    const deadline = Date.now() + 8000;
    while (!out.includes('"id":1') && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 1500));
    child.stdin.end(); child.kill();
    assertKeyed(L.alerts, KEYED, "mcp-proxy");
  } finally { L.close(); rmSync(h, { recursive: true, force: true }); }
});

test("DESKTOP (src/api.js): alerts, prompt events and the identity beacon carry the keyed actor", async () => {
  // The renderer bridge reads browser globals at module scope; give it the smallest honest set.
  const store = new Map([["raiseme.installToken", TOKEN], ["raiseme.tenant", "acme"], ["raiseme.server", "https://console.test"]]);
  const sent = [];
  const saved = {};
  const shim = (k, v) => { saved[k] = Object.getOwnPropertyDescriptor(globalThis, k); Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true }); };
  shim("localStorage", { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) });
  shim("navigator", { platform: "MacIntel", userAgent: "test" });
  shim("screen", { width: 1 });
  shim("window", { __TAURI__: { core: { invoke: async (cmd) => (cmd === "identity" ? { user: USER, device: HOST, platform: "darwin", tenant: "acme", installToken: TOKEN } : null) } } });
  shim("fetch", async (url, opts) => { sent.push({ url: String(url), body: opts && opts.body ? JSON.parse(opts.body) : null }); return { ok: true, json: async () => ({}) }; });
  try {
  const api = await import("../src/api.js");
  await api.loadIdentity();
  api.postAlert({ threatId: 39, category: "Information & Privacy", riskLevel: "High", stage: "prompt" });
  api.reportPrompt("sent", 1);
  api.reportIdentity();
  const bodies = sent.filter((s) => /\/api\/(alerts|prompt-event|device-report)$/.test(s.url)).map((s) => s.body);
  assert.equal(bodies.length, 3, JSON.stringify(sent.map((s) => s.url)));
  // Same user@host, same token → byte-identical to the CLI senders, so one machine is one actor.
  for (const b of bodies) assert.equal(b.actor, KEYED, `desktop sent actor ${b.actor}`);
  } finally {
    for (const [k, d] of Object.entries(saved)) { if (d) Object.defineProperty(globalThis, k, d); else delete globalThis[k]; }
  }
});

test("SOURCE: no sender builds its actor from djb2 any more", () => {
  for (const f of ["cli/moorai-hook.mjs", "cli/moorai-guard.mjs", "mcp-proxy/moorai-mcp-guard.mjs"]) {
    const src = readFileSync(join(ROOT, f), "utf8");
    assert.doesNotMatch(src, /actor:\s*djb2\(/, `${f} still stamps actor = djb2(...)`);
    assert.match(src, /actor:\s*actorHash\(/, `${f} stamps the keyed actor`);
  }
});
