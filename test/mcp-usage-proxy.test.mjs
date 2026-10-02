// The proxy half of the MCP usage cross-check: mcp-proxy/install.mjs stamps which host a wrapped
// server belongs to into the guard's launch args (`--host <id>`), and the guard counts every
// tools/call under path "proxy", that host and its server label (cli/mcp-usage-beat.mjs), then posts
// completed days to POST /api/mcp-usage off its stdio path. Driven end to end: the real installer
// output is what launches the real guard over a fake MCP server, against a local stand-in console.
//
//   node --test test/mcp-usage-proxy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir, hostname, userInfo } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { HOSTS, wrapConfig, unwrapConfig, wrapEntry, isWrapped, GUARD_PATH } from "../mcp-proxy/install.mjs";
import { TALLY_FILE } from "../cli/mcp-usage-beat.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const today = () => new Date().toISOString().slice(0, 10);
const yesterday = () => new Date(Date.now() - 86400000).toISOString().slice(0, 10);

test("INSTALL: each host stamps its usage host id; uninstall restores the original byte for byte", () => {
  const want = { "claude-desktop": "claude-desktop", "mcp-json": "claude-code", cursor: "cursor", vscode: "vscode" };
  for (const h of HOSTS) {
    assert.equal(h.usageHost, want[h.id], h.id);
    const cfg = { [h.key]: { gh: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { A: "1" } } } };
    const w = wrapConfig(cfg, GUARD_PATH, h.key, h.usageHost);
    assert.deepEqual(w[h.key].gh.args, [GUARD_PATH, "--server", "gh", "--host", h.usageHost, "--", "npx", "-y", "@modelcontextprotocol/server-github"]);
    assert.deepEqual(wrapConfig(w, GUARD_PATH, h.key, h.usageHost), w, "re-wrap is a no-op");
    assert.deepEqual(unwrapConfig(w, GUARD_PATH, h.key), cfg);
  }
  // No host (a bare --config) → no stamp, exactly the historical shape.
  assert.deepEqual(wrapEntry("gh", { command: "npx" }).args, [GUARD_PATH, "--server", "gh", "--", "npx"]);
});

test("INSTALL: a server wrapped before the stamp existed gains it on re-install, and still unwraps cleanly", () => {
  const original = { command: "uvx", args: ["mcp-server-git", "--", "x"] };
  const old = wrapEntry("git", original); // pre-stamp shape
  const upgraded = wrapEntry("git", old, GUARD_PATH, "node", "cursor");
  assert.ok(isWrapped(upgraded));
  assert.deepEqual(upgraded.args, [GUARD_PATH, "--server", "git", "--host", "cursor", "--", "uvx", "mcp-server-git", "--", "x"]);
  assert.deepEqual(wrapEntry("git", upgraded, GUARD_PATH, "node", "cursor"), upgraded);
  const back = wrapConfig({ mcpServers: { git: upgraded } }, GUARD_PATH, "mcpServers");
  assert.deepEqual(unwrapConfig(back, GUARD_PATH, "mcpServers").mcpServers.git, original);
});

async function consoleStub(t) {
  const usage = [];
  const alerts = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/mcp-usage" && req.method === "POST") { usage.push({ token: req.headers["x-install-token"], body: JSON.parse(b) }); res.writeHead(201); return res.end("{}"); }
      if (req.url === "/api/alerts" && req.method === "POST") { alerts.push(b); res.writeHead(200); return res.end("{}"); }
      res.writeHead(404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, usage, alerts };
}

// Launch the guard exactly as an installed host config would (the installer's own args), send N
// tools/calls, wait for the N replies.
async function drive(t, { url, entry, home, calls = 2 }) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: "acme" };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME; delete env.MOORAI_MODE;
  const child = spawn(entry.command === "node" ? process.execPath : entry.command, entry.args, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  t.after(() => { try { child.kill(); } catch { /* gone */ } });
  child.stderr.on("data", () => {});
  const got = new Set();
  let buf = "";
  const done = new Promise((resolve) => {
    child.stdout.on("data", (c) => {
      buf += c.toString();
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        try { const m = JSON.parse(line); if (m.id != null) got.add(m.id); } catch { /* ignore */ }
      }
      if (got.size >= calls) resolve();
    });
    setTimeout(resolve, 15000);
  });
  for (let i = 1; i <= calls; i++) child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: i, method: "tools/call", params: { name: "echo", arguments: { msg: `ARG-SECRET-${i}` } } }) + "\n");
  await done;
  return { child, replies: got.size };
}

function home(t, url) {
  const h = mkdtempSync(join(tmpdir(), "moorai-usage-proxy-"));
  t.after(() => rmSync(h, { recursive: true, force: true }));
  mkdirSync(join(h, ".moorai"), { recursive: true });
  writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", installToken: "tok-proxy" }));
  return h;
}

test("PROXY END TO END: the installer's host stamp reaches the tally and the console post; nothing of the call leaves", async (t) => {
  const c = await consoleStub(t);
  const h = home(t, c.url);
  // A completed day already on disk for this path/host — the guard's start-up flush posts it.
  writeFileSync(join(h, ".moorai", TALLY_FILE), JSON.stringify({ v: 1, days: { [yesterday()]: { "proxy|claude-desktop": { testsrv: 4, other: 1 } } } }));
  const host = HOSTS.find((x) => x.id === "claude-desktop");
  const cfg = wrapConfig({ mcpServers: { testsrv: { command: process.execPath, args: [FAKE, join(h, "recv.log")] } } }, GUARD_PATH, "mcpServers", host.usageHost);
  const { replies } = await drive(t, { url: c.url, entry: cfg.mcpServers.testsrv, home: h, calls: 3 });
  assert.equal(replies, 3, "every call answered — the tally never blocks the transport");
  const tally = JSON.parse(readFileSync(join(h, ".moorai", TALLY_FILE), "utf8"));
  assert.deepEqual(tally.days[today()], { "proxy|claude-desktop": { testsrv: 3 } });
  for (let i = 0; i < 50 && !c.usage.length; i++) await sleep(100);
  assert.equal(c.usage.length, 1);
  const { token, body } = c.usage[0];
  assert.equal(token, "tok-proxy");
  assert.deepEqual(Object.keys(body).sort(), ["actor", "day", "device", "host", "path", "platform", "servers", "user"]);
  assert.equal(body.path, "proxy");
  assert.equal(body.host, "claude-desktop");
  assert.equal(body.day, yesterday());
  assert.equal(body.device, hostname());
  assert.equal(body.user, userInfo().username);
  assert.deepEqual(body.servers, [{ label: "testsrv", calls: 4 }, { label: "other", calls: 1 }]);
  const raw = JSON.stringify(body) + readFileSync(join(h, ".moorai", TALLY_FILE), "utf8");
  assert.ok(!raw.includes("echo") && !raw.includes("ARG-SECRET"), raw);
});

test("PROXY: a wrapped install without the stamp counts under host 'unknown'", async (t) => {
  const c = await consoleStub(t);
  const h = home(t, c.url);
  const entry = wrapEntry("legacy", { command: process.execPath, args: [FAKE, join(h, "recv.log")] });
  assert.ok(!entry.args.includes("--host"));
  await drive(t, { url: c.url, entry, home: h, calls: 2 });
  const tally = JSON.parse(readFileSync(join(h, ".moorai", TALLY_FILE), "utf8"));
  assert.deepEqual(tally.days[today()], { "proxy|unknown": { legacy: 2 } });
  await sleep(500);
  assert.equal(c.usage.length, 0, "today's tally is not posted");
  assert.ok(!existsSync(join(h, ".moorai", "mcp-usage-proxy-unknown.sent.json")));
});
