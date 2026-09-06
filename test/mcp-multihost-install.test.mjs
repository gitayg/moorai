// MULTI-HOST MCP ENFORCEMENT — is it real, and is it REACHABLE?
//
// The published posture (README.md line 240) is:
//
//     Claude Code (full hook enforcement) · Codex / Copilot CLI (detection-only — no equivalent deny hook)
//
// That is true of the *hook*. It is not automatically true of the *MCP proxy*, which is host-agnostic
// by construction: mcp-proxy/moorai-mcp-guard.mjs speaks nothing but newline-delimited JSON-RPC over
// stdio, and every MCP host — Claude Desktop, Cursor, VS Code/Copilot, any `.mcp.json` consumer —
// launches stdio servers the same way. Nothing in the guard knows or cares which host spawned it.
//
// So the guard could enforce on those hosts. It DOESN'T, and the reason is one file: mcp-proxy/
// install.mjs hardcodes `claude_desktop_config.json` in defaultConfigPath() and hardcodes the
// `mcpServers` key in wrapConfig()/unwrapConfig(). Host-independent enforcement that only one host's
// installer can reach is not multi-host enforcement.
//
// Two groups of assertions:
//
//   REACH   the installer enumerates more than one host, resolves each host's real config path, and
//           wraps configs whose server map is under `servers` (the VS Code / Copilot shape) as well
//           as `mcpServers`. Round-trips exactly.
//   PROOF   end-to-end over real stdio: a guard launched EXACTLY as a non-Claude host would launch it
//           refuses a malicious tools/call, the caller gets a well-formed JSON-RPC reply with the
//           right id, the real server never sees the call, benign calls still pass, and framing
//           survives a scanner that throws.
//
//   node --test test/mcp-multihost-install.test.mjs
//   (bare `node --test` walks src-tauri/target/ and hangs — always name the file.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { HOSTS, hostById, serversKeyOf, wrapConfig, unwrapConfig, isWrapped, GUARD_PATH } from "../mcp-proxy/install.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");

// ============================ REACH ============================

test("INSTALL: more than one MCP host is wirable, and each resolves a real per-platform config path", () => {
  assert.ok(Array.isArray(HOSTS) && HOSTS.length >= 3,
    `the installer must know several MCP hosts, not just Claude Desktop (got ${HOSTS?.length})`);
  const ids = HOSTS.map((h) => h.id);
  for (const want of ["claude-desktop", "cursor", "vscode"]) {
    assert.ok(ids.includes(want), `host '${want}' is not wirable: ${ids.join(", ")}`);
  }
  for (const h of HOSTS) {
    for (const platform of ["darwin", "win32", "linux"]) {
      const p = h.path(platform, platform === "win32" ? "C:\\Users\\dev" : "/home/dev");
      assert.equal(typeof p, "string");
      assert.ok(p.length > 0, `${h.id} has no config path on ${platform}`);
    }
    assert.ok(["mcpServers", "servers"].includes(h.key), `${h.id} has an unknown server-map key: ${h.key}`);
  }
});

test("INSTALL: a `servers`-keyed config (VS Code / Copilot shape) is wrapped, not silently ignored", () => {
  const cfg = { servers: { gh: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] } } };
  assert.equal(serversKeyOf(cfg), "servers");

  const wrapped = wrapConfig(cfg);
  assert.ok(!("mcpServers" in wrapped), "wrapping a `servers` config must not invent an empty `mcpServers` map");
  assert.ok(isWrapped(wrapped.servers.gh), "the `servers` entry was left unguarded — the host is unprotected");
  assert.equal(wrapped.servers.gh.args[0], GUARD_PATH);
  assert.deepEqual(wrapped.servers.gh.args.slice(1, 4), ["--server", "gh", "--"]);
  assert.deepEqual(wrapped.servers.gh.args.slice(4), ["npx", "-y", "@modelcontextprotocol/server-github"]);

  // Reversible, byte-for-byte.
  assert.deepEqual(unwrapConfig(wrapped), cfg);
  // Idempotent.
  assert.deepEqual(wrapConfig(wrapped), wrapped);
});

test("INSTALL: the Claude Desktop path is unchanged — this is additive, not a migration", () => {
  const cfg = { mcpServers: { fs: { command: "npx", args: ["-y", "server-filesystem", "/tmp"] } } };
  assert.equal(serversKeyOf(cfg), "mcpServers");
  const wrapped = wrapConfig(cfg);
  assert.ok(isWrapped(wrapped.mcpServers.fs));
  assert.deepEqual(unwrapConfig(wrapped), cfg);
  assert.equal(hostById("claude-desktop").key, "mcpServers");
  assert.match(hostById("claude-desktop").path("darwin", "/home/dev"), /claude_desktop_config\.json$/);
});

test("INSTALL: remote (url/SSE) servers are left alone on every host — a stdio proxy cannot wrap them", () => {
  // Stated as a test rather than a comment because it is a real coverage hole, not an oversight: an
  // HTTP/SSE MCP server never spawns a local process, so there is no command for the guard to sit in
  // front of. Any claim of host coverage has to exclude these.
  const cfg = { servers: { remote: { url: "https://mcp.example.com/sse" }, local: { command: "node", args: ["s.js"] } } };
  const wrapped = wrapConfig(cfg);
  assert.deepEqual(wrapped.servers.remote, cfg.servers.remote, "a url-only server must be returned untouched");
  assert.ok(isWrapped(wrapped.servers.local));
});

// ============================ PROOF ============================

// Launch the guard the way ANY MCP host launches a stdio server: argv + stdio, nothing Claude-specific.
// `policy` is planted in the cache of a throwaway HOME; the device is unanchored + unpinned, so the
// planted body is admitted (the documented no-brick path).
function driveHost({ server, tool, args, policy, env = {}, extraSends = [] }, timeoutMs = 20000) {
  return new Promise((resolve) => {
    const home = mkdtempSync(join(tmpdir(), "moorai-multihost-"));
    const recv = join(home, "recv.log");
    mkdirSync(join(home, ".curaiq"), { recursive: true });
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".curaiq", "config.json"),
      JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "multihost-test", installToken: "tok" }));
    if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));

    const childEnv = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "multihost-test", ...env };
    delete childEnv.XDG_CONFIG_HOME; delete childEnv.XDG_STATE_HOME;

    const child = spawn(process.execPath, [GUARD, "--server", server, "--", process.execPath, FAKE, recv],
      { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env: childEnv });
    child.stderr.on("data", () => {});

    const byId = new Map();
    const lines = [];
    let buf = "";
    child.stdout.on("data", (c) => {
      buf += c.toString();
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        lines.push(line);
        try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* framing violation — caught by the assertion below */ }
      }
      if (byId.size >= 2 + extraSends.length) finish();
    });

    let done = false;
    const timer = setTimeout(finish, timeoutMs);
    function finish() {
      if (done) return; done = true;
      clearTimeout(timer);
      const received = existsSync(recv) ? readFileSync(recv, "utf8") : "";
      try { child.stdin.end(); } catch { /* ignore */ }
      try { child.kill(); } catch { /* ignore */ }
      rmSync(home, { recursive: true, force: true });
      resolve({ byId, lines, received });
    }

    const send = (o) => { try { child.stdin.write(JSON.stringify(o) + "\n"); } catch { /* ignore */ } };
    send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "warmup", arguments: { msg: "hello world" } } });
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: tool, arguments: args } });
    for (const s of extraSends) send(s);
  });
}

const AWS_ARG = "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
// Exactly the shape scripts/moorai-validate-blocking.mjs plants for its enforcing "policy" mode.
const BLOCK_SECRETS = { captureTier: "content-free", mcpAllow: ["github"], threatPolicy: { 39: "block", 43: "block", 65: "block" } };

test("PROXY: a malicious MCP tool call is refused for a NON-Claude host, and the caller gets a clean JSON-RPC reply", async () => {
  const r = await driveHost({ server: "github", tool: "create_issue", args: { body: AWS_ARG }, policy: BLOCK_SECRETS });

  const reply = r.byId.get(2);
  assert.ok(reply, "the agent got NO reply for the blocked call — a hang is worse than no enforcement");
  // Well-formed enough for any MCP client to handle: correct envelope, correct id, tool-result error
  // shape (NOT a protocol-level error, which some clients treat as a transport fault).
  assert.equal(reply.jsonrpc, "2.0");
  assert.equal(reply.id, 2, "the reply id must match the request id or the client cannot correlate it");
  assert.equal(reply.result.isError, true);
  assert.equal(reply.result.content[0].type, "text");
  assert.match(String(reply.result.content[0].text), /MoorAI blocked/i);
  assert.ok(!("error" in reply), "must be a tool-result error, not a JSON-RPC protocol error");

  // "Blocked" means the call never executed, not merely that the model saw a message.
  assert.ok(!/AKIAIOSFODNN7EXAMPLE/.test(r.received), "the real MCP server RECEIVED the secret-bearing call");
  // ...and normal work is untouched.
  const benign = r.byId.get(1);
  assert.ok(benign && benign.result.isError === false, "the benign warm-up call must succeed");
  assert.ok(/hello world/.test(r.received), "the benign call never reached the real server — this is a brick, not a guard");

  // Every line the host received parses as JSON: the refusal did not corrupt the stream framing.
  for (const l of r.lines) JSON.parse(l);
});

test("PROXY: nothing is refused without an explicit org block — report-first survives on other hosts", async () => {
  // The same secret-bearing argument, under a policy with NO threatPolicy at all. #39 resolves to
  // "notify" through threatActionFor, so the call must be FORWARDED. If this ever goes red, the MCP
  // layer has grown a blocking default the hook does not have.
  const r = await driveHost({ server: "github", tool: "create_issue", args: { body: AWS_ARG }, policy: { captureTier: "content-free" } });
  const reply = r.byId.get(2);
  assert.ok(reply, "no reply at all");
  assert.notEqual(reply.result?.isError, true, "a default policy must not block — report-first is the posture");
  assert.ok(/AKIAIOSFODNN7EXAMPLE/.test(r.received), "the call should have been forwarded to the real server");
});

test("PROXY: FAIL-OPEN — a SYNCHRONOUS observer fault on every chunk still delivers every response intact", async () => {
  // The ordering rule the whole tool stage rests on: the child's bytes go to the agent FIRST, and the
  // observer runs on a copy behind a try/catch. MOORAI_TEST_TOOLSCAN_THROW cannot test that (it throws
  // inside observeTools, already behind observeLine's own try) — so this uses the synchronous hook,
  // which fires on EVERY stdout chunk from the child. If the write were moved after the observation,
  // or the try/catch dropped, the agent would get nothing at all.
  const r = await driveHost({
    server: "github", tool: "create_issue", args: { body: AWS_ARG }, policy: BLOCK_SECRETS,
    env: { MOORAI_TEST_OBSERVE_THROW: "1" },
    extraSends: [{ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }]
  });
  assert.equal(r.byId.get(1)?.result?.isError, false, "the benign call's response was lost to an observer fault");
  assert.equal(r.byId.get(2)?.result?.isError, true, "enforcement stopped when the observer threw");
  const list = r.byId.get(3);
  assert.ok(list && Array.isArray(list.result.tools) && list.result.tools.length > 0,
    "tools/list was dropped while the observer threw on every chunk — the proxy became the outage");
  for (const l of r.lines) JSON.parse(l); // framing intact
});

test("PROXY: FAIL-OPEN — a scanner that throws never costs the host a tool call or a byte of framing", async () => {
  const r = await driveHost({
    server: "github", tool: "create_issue", args: { body: AWS_ARG }, policy: BLOCK_SECRETS,
    env: { MOORAI_TEST_TOOLSCAN_THROW: "1" },
    extraSends: [{ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }]
  });
  // The injected fault lives in the tools/list observer. The list must still come back complete...
  const list = r.byId.get(3);
  assert.ok(list, "tools/list got no reply while the observer was throwing — the proxy became the outage");
  assert.ok(Array.isArray(list.result.tools) && list.result.tools.length > 0, "the tool list was dropped or emptied by a scanner fault");
  // ...and the tools/call gate is unaffected by it.
  assert.equal(r.byId.get(2)?.result?.isError, true, "the call gate stopped enforcing because the list observer threw");
  assert.equal(r.byId.get(1)?.result?.isError, false, "the benign call broke");
  for (const l of r.lines) JSON.parse(l);
});
