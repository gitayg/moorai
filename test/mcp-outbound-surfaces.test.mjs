// What an agent sends to an MCP tool (cli/mcp-outbound.mjs) on the three surfaces that gate an MCP call:
// the Claude Code hook (a real hook process, the policy cached on an unanchored device), the stdio MCP guard
// (real stdio, the fake MCP server, which logs every call it receives) and the HTTP MCP gateway (a real
// gateway process, the fake upstream, a signed policy). Plus #65 at the stdio guard
// (cli/mcp-secret-egress.mjs), which the hook and the gateway already ran. Made-up values only.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-outbound-surfaces.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { scenario, rpc, call as gwCall } from "../mcp-gateway/test/harness.mjs";
import { docx, LABEL_ID } from "./fixtures/label-files.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 6000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

const HEADING = "Release notes\n\n## API keys\n- primary: 9fK2mQ7xLp3Vz8Rt\n- backup: 4hT6nW1yBq9Cs2Dk\n";
const MARK = "zebra-lantern-quartz";
const BIG = `${MARK} plain words in a row\n`.repeat(200);
const SECRET = "Rk7vQ2xM9pL4wZ8tY1nB3cD6";
const LEARNED = "ghp_" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa";
const OVERSHARE = { mcpOversharing: { action: "block", maxArgBytes: 2000 } };
const LABELS = { labelPolicy: { rules: [{ match: { id: LABEL_ID }, onSend: "block" }] } };
const DOC64 = () => docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] }).toString("base64");
const overshareAlert = (alerts) => alerts.find((a) => a.oversharing);
const contentFree = (alerts) => { const s = JSON.stringify(alerts); return !s.includes(MARK) && !s.includes("9fK2mQ7xLp3Vz8Rt") && !s.includes(SECRET) && !s.includes(LEARNED); };

async function sink() {
  const alerts = [];
  const server = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      if (req.method === "POST" && req.url === "/api/alerts/batch") { try { alerts.push(...(JSON.parse(b).alerts || [])); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      res.writeHead(503); res.end("");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
function sandbox(url, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-outbound-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "outb", installToken: "tok-outb" }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", ...policy }));
  const proj = join(home, "proj");
  mkdirSync(proj);
  return { home, proj };
}

// ---- the Claude Code hook ----
function hook(home, proj, tool_name, tool_input) {
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [HOOK], { env, cwd: proj, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.on("close", (code) => {
      let d = {};
      try { d = JSON.parse(stdout.trim()).hookSpecificOutput || {}; } catch { /* allow prints nothing */ }
      resolve({ code, stderr, decision: d.permissionDecision || "allow", reason: d.permissionDecisionReason || "" });
    });
    child.stdin.end(JSON.stringify({ session_id: "s-outb", hook_event_name: "PreToolUse", cwd: proj, tool_name, tool_input }));
  });
}
async function hookRun(policy, fn, { setup } = {}) {
  const s = await sink();
  const { home, proj } = sandbox(s.url, policy);
  if (setup) setup({ home, proj });
  try { await fn({ alerts: s.alerts, run: (tool, input) => hook(home, proj, tool, input) }); } finally { await s.close(); rmTree(home); }
}

// The launch declarations the hook reads for a label (cli/mcp-reputation.mjs findServerDecl: the project's .mcp.json).
const FS_PKG = "@modelcontextprotocol/server-filesystem";
const mcpServers = ({ proj }) => writeFileSync(join(proj, ".mcp.json"), JSON.stringify({ mcpServers: {
  filesystem: { command: "npx", args: ["-y", FS_PKG, proj] },
  remote: { type: "http", url: "https://mcp.example.com/mcp" },
  lookalike: { command: "npx", args: ["-y", "fs-helper-tools", FS_PKG, proj] }
} }));

test("HOOK: a key list in a multi-line value is #39; with #39 block it is refused", async () => {
  await hookRun({ threatPolicy: { 39: "block" } }, async ({ alerts, run }) => {
    const r = await run("mcp__slack__post_message", { channel: "eng", text: HEADING });
    assert.equal(r.decision, "deny", r.stderr);
    assert.match(r.reason, /#39/);
    assert.ok(await until(() => alerts.some((a) => a.threatId === 39)), JSON.stringify(alerts.map((a) => a.category)));
    assert.ok(contentFree(alerts));
  });
});

test("HOOK: over-sharing with mcpOversharing block is refused; the alert carries the signal and sizes, no value", async () => {
  await hookRun(OVERSHARE, async ({ alerts, run }) => {
    const r = await run("mcp__notion__create_page", { title: "dump", body: BIG });
    assert.equal(r.decision, "deny", r.stderr);
    assert.match(r.reason, /MCP over-sharing: size/);
    assert.ok(await until(() => overshareAlert(alerts)), JSON.stringify(alerts.map((a) => a.category)));
    const a = overshareAlert(alerts);
    assert.deepEqual([a.category, a.oversharing.signals, a.oversharing.bytes > 2000, /^h2:|^[0-9a-f]/.test(a.oversharing.argsHash)], ["MCP: over-sharing", ["size"], true, true]);
    assert.ok(contentFree(alerts));
    const w = await run("mcp__filesystem__write_file", { path: "notes/dump.md", content: BIG });
    assert.notEqual(w.decision, "deny", "a local filesystem write is exempt from the signal");
  }, { setup: mcpServers });
});

test("HOOK: the over-sharing exemption needs a local filesystem server by launch or by signed policy, never the tool name", async () => {
  await hookRun(OVERSHARE, async ({ alerts, run }) => {
    for (const label of ["remote", "lookalike", "undeclared"]) {
      const r = await run(`mcp__${label}__write_file`, { path: "notes/dump.md", content: BIG });
      assert.equal(r.decision, "deny", `${label}: ${r.reason} ${r.stderr}`);
      assert.match(r.reason, /MCP over-sharing: size/);
    }
    assert.notEqual((await run("mcp__filesystem__write_file", { path: "notes/dump.md", content: BIG })).decision, "deny");
    assert.ok(await until(() => overshareAlert(alerts)), JSON.stringify(alerts.map((a) => a.category)));
    assert.ok(contentFree(alerts));
  }, { setup: mcpServers });
  await hookRun({ mcpOversharing: { action: "block", maxArgBytes: 2000, localWriteServers: ["notes"] } }, async ({ run }) => {
    assert.notEqual((await run("mcp__notes__write_file", { path: "notes/dump.md", content: BIG })).decision, "deny", "a server the policy lists");
    assert.equal((await run("mcp__notes__create_page", { body: BIG })).decision, "deny", "only its write-shaped calls");
  });
});

test("HOOK: the data-loss detectors still judge a write to a local filesystem server", async () => {
  await hookRun({ threatPolicy: { 39: "block" } }, async ({ run }) => {
    const r = await run("mcp__filesystem__write_file", { path: "notes/keys.md", content: HEADING });
    assert.equal(r.decision, "deny", r.stderr);
    assert.match(r.reason, /#39/);
  }, { setup: mcpServers });
});

test("HOOK: a labelled .docx sent base64-encoded is refused by labelPolicy onSend block", async () => {
  await hookRun(LABELS, async ({ alerts, run }) => {
    const r = await run("mcp__drive__upload_file", { name: "board.docx", content: DOC64() });
    assert.equal(r.decision, "deny", r.stderr);
    assert.ok(await until(() => alerts.some((a) => a.sensitivityLabel)));
    assert.deepEqual(alerts.find((a) => a.sensitivityLabel).sensitivityLabel.verdict, "block");
  });
});

// ---- the stdio guard ----
function guard(home, cwd, url, env = {}, server = FAKE) {
  const recv = join(home, "recv.log");
  const child = spawn(process.execPath, [GUARD, "--server", "share", "--", process.execPath, server, recv], { cwd, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: "outb", ...env } });
  const byId = new Map();
  let buf = "", stderr = "", next = 1;
  child.stderr.on("data", (c) => { stderr += c; });
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* not a response */ } }
  });
  return {
    async call(name, args) {
      const id = next++;
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }) + "\n");
      assert.ok(await until(() => byId.has(id), 15000), `no response to ${name}; stderr=${stderr}`);
      return byId.get(id).result;
    },
    received: () => (existsSync(recv) ? readFileSync(recv, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l).name) : []),
    close: () => new Promise((r) => { child.once("exit", () => r()); try { child.stdin.end(); child.kill(); } catch { r(); } })
  };
}
const blocked = (r) => Boolean(r && r.isError === true && /MoorAI blocked/i.test(String(r.content?.[0]?.text)));
async function guardRun(policy, fn, { env = {}, setup, server } = {}) {
  const s = await sink();
  const { home, proj } = sandbox(s.url, policy);
  if (setup) setup({ home, proj });
  const g = guard(home, proj, s.url, typeof env === "function" ? env({ home, proj }) : env, typeof server === "function" ? server({ home, proj }) : server);
  try { await fn({ alerts: s.alerts, g }); } finally { await g.close(); await s.close(); rmTree(home); }
}

test("GUARD: a key list in a multi-line value with #39 block, and over-sharing with mcpOversharing block, never reach the server", async () => {
  await guardRun({ threatPolicy: { 39: "block" }, ...OVERSHARE }, async ({ alerts, g }) => {
    assert.ok(blocked(await g.call("post_message", { text: HEADING })));
    assert.ok(blocked(await g.call("create_page", { body: BIG })));
    assert.ok(!blocked(await g.call("post_message", { text: "hello" })));
    assert.deepEqual(g.received(), ["post_message"]);
    assert.ok(await until(() => overshareAlert(alerts) && alerts.some((a) => a.threatId === 39)), JSON.stringify(alerts.map((a) => a.category)));
    assert.deepEqual(overshareAlert(alerts).oversharing.signals, ["size"]);
    assert.ok(contentFree(alerts));
  });
});

test("GUARD: a write-shaped tool name does not exempt over-sharing; the reference filesystem server or a server the policy lists does", async () => {
  await guardRun(OVERSHARE, async ({ alerts, g }) => {
    assert.ok(blocked(await g.call("write_file", { path: "notes/dump.md", content: BIG })), "a write_file on a server that is not a filesystem server");
    assert.deepEqual(g.received(), []);
    assert.ok(await until(() => overshareAlert(alerts)));
    assert.ok(contentFree(alerts));
  });
  await guardRun({ mcpOversharing: { action: "block", maxArgBytes: 2000, localWriteServers: ["share"] } }, async ({ g }) => {
    assert.ok(!blocked(await g.call("write_file", { path: "notes/dump.md", content: BIG })));
    assert.ok(blocked(await g.call("create_page", { body: BIG })));
    assert.deepEqual(g.received(), ["write_file"]);
  });
  // The same fake server, installed where the reference filesystem server's entry point lives.
  const fsEntry = ({ home }) => {
    const dir = join(home, "node_modules", "@modelcontextprotocol", "server-filesystem", "dist");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "index.js"), readFileSync(FAKE));
    writeFileSync(join(dir, "..", "package.json"), JSON.stringify({ name: FS_PKG, version: "1.0.0", type: "module" }));
    return join(dir, "index.js");
  };
  await guardRun({ ...OVERSHARE, threatPolicy: { 39: "block" } }, async ({ g }) => {
    assert.ok(!blocked(await g.call("write_file", { path: "notes/dump.md", content: BIG })));
    assert.ok(blocked(await g.call("create_page", { body: BIG })));
    assert.ok(blocked(await g.call("write_file", { path: "notes/keys.md", content: HEADING })), "#39 still judges a local write");
    assert.deepEqual(g.received(), ["write_file"]);
  }, { server: fsEntry });
});

test("GUARD: a labelled .docx sent base64-encoded is refused by labelPolicy onSend block", async () => {
  await guardRun(LABELS, async ({ alerts, g }) => {
    assert.ok(blocked(await g.call("upload_file", { name: "board.docx", content: DOC64() })));
    assert.deepEqual(g.received(), []);
    assert.ok(await until(() => alerts.some((a) => a.sensitivityLabel)));
  });
});

test("GUARD: #65 — a value from the project's .env in an argument is refused by default; only hash prefixes leave", async () => {
  await guardRun({}, async ({ alerts, g }) => {
    assert.ok(blocked(await g.call("post_message", { text: `the deploy token is ${SECRET}` })));
    assert.ok(!blocked(await g.call("post_message", { text: "no secret here" })));
    assert.deepEqual(g.received(), ["post_message"]);
    assert.ok(await until(() => alerts.some((a) => a.threatId === 65)), JSON.stringify(alerts.map((a) => a.category)));
    const a = alerts.find((x) => x.threatId === 65);
    assert.deepEqual([a.riskLevel, a.tool, a.mcpServer, a.secretEgress[0].source], ["Blocked", "desktop:post_message", "share", "store"]);
    assert.ok(alerts.some((x) => x.category === "MCP: local secret egress"));
    assert.ok(contentFree(alerts));
  }, { setup: ({ proj }) => writeFileSync(join(proj, ".env"), `DEPLOY_TOKEN=${SECRET}\n`) });
});

test("GUARD: #65 — a secret a tool result carried is refused when a later call sends it", async () => {
  await guardRun({}, async ({ alerts, g }) => {
    assert.ok(!blocked(await g.call("read_config", { name: "ci" })), "the read itself is forwarded");
    assert.ok(blocked(await g.call("post_message", { text: `token ${LEARNED}` })));
    assert.deepEqual(g.received(), ["read_config"]);
    assert.ok(await until(() => alerts.some((a) => a.threatId === 65)));
    assert.equal(alerts.find((x) => x.threatId === 65).secretEgress[0].source !== "store", true);
    assert.ok(contentFree(alerts.filter((x) => x.threatId === 65)));
  }, { env: ({ home }) => { const f = join(home, "result.txt"); writeFileSync(f, `GITHUB_TOKEN=${LEARNED}\n`); return { FAKE_RESULT_FILE: f }; } });
});

// ---- the HTTP gateway ----
const refused = (r) => r.json && r.json.result && r.json.result.isError === true && /MoorAI blocked/.test(r.json.result.content[0].text);
const upNames = (up) => up.calls().filter((c) => c.json && c.json.method === "tools/call").map((c) => c.json.params.name);

test("GATEWAY: #39 in a multi-line value, over-sharing and a base64 labelled .docx are refused before the upstream", async () => {
  await scenario({ policy: { captureTier: "content-free", threatPolicy: { 39: "block" }, ...OVERSHARE, ...LABELS } }, async ({ con, up, base }) => {
    assert.ok(refused(await rpc(base, gwCall(1, "post_message", { text: HEADING }))));
    assert.ok(refused(await rpc(base, gwCall(2, "create_page", { body: BIG }))));
    assert.ok(refused(await rpc(base, gwCall(3, "upload_file", { name: "board.docx", content: DOC64() }))));
    assert.ok(!refused(await rpc(base, gwCall(4, "post_message", { text: "hello" }))));
    assert.deepEqual(upNames(up), ["post_message"]);
    assert.ok(await until(() => overshareAlert(con.alerts) && con.alerts.some((a) => a.sensitivityLabel) && con.alerts.some((a) => a.threatId === 39)), JSON.stringify(con.alerts.map((a) => a.category)));
    assert.deepEqual([overshareAlert(con.alerts).tool, overshareAlert(con.alerts).oversharing.signals], ["gateway:create_page", ["size"]]);
    assert.ok(contentFree(con.alerts));
  });
});

test("GATEWAY: a write-shaped tool name never exempts over-sharing, a route the policy lists included; every upstream is remote", async () => {
  await scenario({ policy: { captureTier: "content-free", mcpOversharing: { action: "block", maxArgBytes: 2000, localWriteServers: ["remote"] } } }, async ({ con, up, base }) => {
    assert.ok(refused(await rpc(base, gwCall(1, "write_file", { path: "notes/dump.md", content: BIG }))));
    assert.ok(refused(await rpc(base, gwCall(2, "edit_file", { path: "notes/dump.md", edits: [{ oldText: "a", newText: BIG }] }))));
    assert.deepEqual(upNames(up), []);
    assert.ok(await until(() => overshareAlert(con.alerts)));
    assert.equal(overshareAlert(con.alerts).tool, "gateway:write_file");
  });
});
