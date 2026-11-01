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
import { docx, pdf, LABEL_ID } from "./fixtures/label-files.mjs";

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
// Encoded values not decoded whole (cli/mcp-outbound.mjs OUTBOUND_CAPS, cli/mcp-outbound-fail.mjs): text over
// 1 MiB (decodedBytes), a labelled .docx over 1 MiB, a .docx cut short.
const NOTES = () => Array.from({ length: 12 }, (_, i) => Buffer.from(`note ${i} ${"x".repeat(80)}`).toString("base64"));
const PAST_CAP = () => ({ content: Buffer.from(`${MARK} words past the decode cap\n`.repeat(40_000)).toString("base64") });
const filler = (n) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = (i * 2654435761) >>> 24; return b; };
const BIG_DOC64 = () => docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }], extra: [{ name: "word/media/image1.bin", data: filler(1_200_000), store: true }] }).toString("base64");
const BROKEN64 = () => docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] }).subarray(0, 150).toString("base64");
// Review: an image over 1 MiB is unevaluated like any other value not decoded whole; a value with characters a
// lenient decoder skips is decoded the way that decoder reads it, and a labelled file in it is a label unevaluated.
const PNG_MAGIC = Buffer.from("89504e470d0a1a0a", "hex"), IEND = Buffer.from("0000000049454e44ae426082", "hex");
const FAKE_PNG = () => Buffer.concat([PNG_MAGIC, Buffer.from(`${MARK} pasted after an image header\n`.repeat(40_000))]).toString("base64");
const REAL_PNG = () => Buffer.concat([PNG_MAGIC, filler(1_500_000), IEND]).toString("base64");
const HC = [{ id: LABEL_ID, name: "Highly Confidential" }];
const JUNK_PDF = () => { const b = pdf({ info: HC, padding: 1_200_000 }).toString("base64"); const at = Math.floor(b.length / 8) * 4 + 1; return `data:application/pdf;base64,${b.slice(0, at)}.${b.slice(at)}`; };
const junk = (s, n, ch) => s.replace(new RegExp(`(.{${n}})`, "g"), `$1${ch}`);
const JUNK_SMALL = () => [junk(pdf({ info: HC }).toString("base64"), 40, "!"), junk(docx({ custom: HC }).toString("base64"), 40, "!")];
const JUNK_CARD = () => junk(Buffer.from(`id,name,card\n1,Test Person,4111 1111 1111 1111\n${MARK}\n`).toString("base64"), 30, ".");
const CARD_BLOCK = { threatPolicy: { 90: "block" } };
const PAD_CARD = () => `QQ==${Buffer.from(`id,name,card\n1,Test Person,4111 1111 1111 1111\n${MARK}\n`).toString("base64")}`;
const PAD_PDF = () => `QUI=${pdf({ info: HC }).toString("base64")}`;
const RUNS_CARD = () => "card 4111 1111 1111 1111 exp 12/29\n".match(/.{1,2}/gs).map((p) => Buffer.from(p).toString("base64")).join("");
const unevalFor = (alerts, tool) => alerts.filter((a) => a.category === UNEVAL && a.tool === tool);
// The server answers briefly, so no 2 MB echo holds the event loop while an alert is in flight.
const SHORT_RESULT = ({ home }) => { const f = join(home, "result.txt"); writeFileSync(f, "stored"); return { FAKE_RESULT_FILE: f }; };
const UNEVAL = "MCP: outbound arguments not fully evaluated";
const unevalAlert = (alerts) => alerts.find((a) => a.category === UNEVAL);
const failAlert = (alerts) => alerts.find((a) => a.reasonCode === "FAIL_CLOSED");
const cats = (alerts) => JSON.stringify(alerts.map((a) => a.category));

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

test("HOOK: encoded text past the decode caps follows failMode.hook: closed denies (FAIL_CLOSED), open allows and reports it", async () => {
  await hookRun({ failMode: { hook: "closed" } }, async ({ alerts, run }) => {
    const r = await run("mcp__drive__upload_file", PAST_CAP());
    assert.equal(r.decision, "deny", r.stderr);
    assert.match(r.reason, /not evaluated/);
    assert.ok(await until(() => failAlert(alerts)), cats(alerts));
    assert.equal(failAlert(alerts).failWhy, "size-cap");
    assert.equal((await run("mcp__drive__upload_file", { parts: NOTES() })).decision, "allow", "within the caps");
    assert.ok(contentFree(alerts));
  });
  await hookRun({}, async ({ alerts, run }) => {
    assert.equal((await run("mcp__drive__upload_file", PAST_CAP())).decision, "allow");
    assert.ok(await until(() => unevalAlert(alerts)), cats(alerts));
    const a = unevalAlert(alerts);
    assert.deepEqual([a.threatId, a.riskLevel, a.decision, a.failMode, a.failWhy, a.unevaluatedValues, a.tool], [0, "Medium", "notify", "open", "size", 1, "hook:mcp__drive__upload_file"]);
    assert.ok(contentFree(alerts));
  });
});

test("HOOK: under labelPolicy onSend block, a labelled .docx over 1 MiB is refused (label read in place), and so is one whose label cannot be read", async () => {
  await hookRun(LABELS, async ({ alerts, run }) => {
    const r = await run("mcp__drive__upload_file", { name: "board.docx", content: BIG_DOC64() });
    assert.equal(r.decision, "deny", r.stderr);
    assert.ok(await until(() => alerts.some((a) => a.sensitivityLabel && a.sensitivityLabel.verdict === "block")), cats(alerts));
    const b = await run("mcp__drive__upload_file", { name: "board.docx", content: BROKEN64() });
    assert.equal(b.decision, "deny", b.stderr);
    assert.match(b.reason, /could not be label-checked/);
  });
});

test("HOOK: an image over 1 MiB is unevaluated: failMode.hook closed denies it, open allows it with one alert per tool in the session", async () => {
  await hookRun({ failMode: { hook: "closed" } }, async ({ alerts, run }) => {
    for (const content of [REAL_PNG(), FAKE_PNG()]) {
      const r = await run("mcp__drive__upload_file", { name: "photo.png", content });
      assert.equal(r.decision, "deny", r.stderr);
      assert.match(r.reason, /not evaluated/);
    }
    assert.ok(await until(() => failAlert(alerts)), cats(alerts));
    assert.ok(contentFree(alerts));
  });
  await hookRun({}, async ({ alerts, run }) => {
    assert.equal((await run("mcp__drive__upload_file", { content: REAL_PNG() })).decision, "allow");
    assert.ok(await until(() => unevalFor(alerts, "hook:mcp__drive__upload_file").length === 1), cats(alerts));
    for (let i = 0; i < 2; i++) assert.equal((await run("mcp__drive__upload_file", { content: REAL_PNG() })).decision, "allow");
    await sleep(2000);
    assert.equal((await run("mcp__photos__add", { content: REAL_PNG() })).decision, "allow");
    assert.ok(await until(() => unevalFor(alerts, "hook:mcp__photos__add").length === 1), cats(alerts));
    assert.equal(unevalFor(alerts, "hook:mcp__drive__upload_file").length, 1, cats(alerts));
    const a = unevalFor(alerts, "hook:mcp__drive__upload_file")[0];
    assert.deepEqual([a.threatId, a.riskLevel, a.decision, a.failMode, a.failWhy, a.unevaluatedValues], [0, "Medium", "notify", "open", "size", 1]);
  });
});

test("HOOK: characters a lenient decoder skips: a card number is found; a labelled PDF or .docx is refused under onSend block", async () => {
  await hookRun({ ...LABELS, ...CARD_BLOCK }, async ({ alerts, run }) => {
    const c = await run("mcp__drive__upload_file", { name: "export.csv", content: JUNK_CARD() });
    assert.equal(c.decision, "deny", c.stderr);
    assert.match(c.reason, /#90/);
    for (const content of [JUNK_PDF(), ...JUNK_SMALL()]) {
      const r = await run("mcp__drive__upload_file", { content });
      assert.equal(r.decision, "deny", r.stderr);
      assert.match(r.reason, /could not be label-checked/);
    }
    assert.ok(contentFree(alerts));
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

test("GUARD: encoded text or an image past the decode caps follows failMode.mcpGateway: closed never reaches the server, open forwards and reports it once per tool", async () => {
  await guardRun({ failMode: { mcpGateway: "closed" } }, async ({ alerts, g }) => {
    assert.ok(blocked(await g.call("upload_file", PAST_CAP())));
    assert.ok(blocked(await g.call("upload_file", { content: REAL_PNG() })));
    assert.ok(!blocked(await g.call("upload_file", { parts: NOTES() })), "within the caps");
    assert.deepEqual(g.received(), ["upload_file"]);
    assert.ok(await until(() => failAlert(alerts)), cats(alerts));
    assert.deepEqual([failAlert(alerts).failWhy, failAlert(alerts).tool], ["size", "desktop:upload_file"]);
    assert.ok(contentFree(alerts));
  });
  await guardRun({}, async ({ alerts, g }) => {
    assert.ok(!blocked(await g.call("upload_file", PAST_CAP())));
    assert.ok(await until(() => unevalFor(alerts, "desktop:upload_file").length === 1), cats(alerts));
    for (let i = 0; i < 2; i++) assert.ok(!blocked(await g.call("upload_file", { content: REAL_PNG() })));
    await sleep(2000);
    assert.ok(!blocked(await g.call("add_photo", { content: REAL_PNG() })));
    assert.deepEqual(g.received(), ["upload_file", "upload_file", "upload_file", "add_photo"]);
    assert.ok(await until(() => unevalFor(alerts, "desktop:add_photo").length === 1), cats(alerts));
    assert.equal(unevalFor(alerts, "desktop:upload_file").length, 1, cats(alerts));
    const a = unevalAlert(alerts);
    assert.deepEqual([a.riskLevel, a.decision, a.failMode, a.failWhy, a.tool, a.mcpServer], ["Medium", "notify", "open", "size", "desktop:upload_file", "share"]);
    assert.ok(contentFree(alerts));
  }, { env: SHORT_RESULT });
});

test("GUARD: under labelPolicy onSend block, a labelled .docx over 1 MiB and one whose label cannot be read never reach the server", async () => {
  await guardRun(LABELS, async ({ alerts, g }) => {
    assert.ok(blocked(await g.call("upload_file", { name: "board.docx", content: BIG_DOC64() })));
    assert.ok(blocked(await g.call("upload_file", { name: "board.docx", content: BROKEN64() })));
    assert.deepEqual(g.received(), []);
    assert.ok(await until(() => alerts.some((a) => a.sensitivityLabel && a.sensitivityLabel.verdict === "block")), cats(alerts));
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

test("GATEWAY: encoded text past the decode caps follows failMode.mcpGateway; a labelled .docx over 1 MiB and an unreadable one are refused under onSend block", async () => {
  await scenario({ policy: { captureTier: "content-free", failMode: { mcpGateway: "closed" } } }, async ({ con, up, base }) => {
    assert.ok(refused(await rpc(base, gwCall(1, "upload_file", PAST_CAP()))));
    assert.ok(!refused(await rpc(base, gwCall(2, "upload_file", { parts: NOTES() }))));
    assert.deepEqual(upNames(up), ["upload_file"]);
    assert.ok(await until(() => failAlert(con.alerts)), cats(con.alerts));
    assert.deepEqual([failAlert(con.alerts).failWhy, failAlert(con.alerts).tool], ["size", "gateway:upload_file"]);
    assert.ok(contentFree(con.alerts));
  });
  await scenario({ policy: { captureTier: "content-free", ...LABELS } }, async ({ con, up, base }) => {
    assert.ok(!refused(await rpc(base, gwCall(1, "upload_file", PAST_CAP()))), "open: forwarded");
    assert.ok(refused(await rpc(base, gwCall(2, "upload_file", { name: "board.docx", content: BIG_DOC64() }))));
    assert.ok(refused(await rpc(base, gwCall(3, "upload_file", { name: "board.docx", content: BROKEN64() }))));
    assert.deepEqual(upNames(up), ["upload_file"]);
    assert.ok(await until(() => unevalAlert(con.alerts) && con.alerts.some((a) => a.sensitivityLabel)), cats(con.alerts));
    assert.deepEqual([unevalAlert(con.alerts).riskLevel, unevalAlert(con.alerts).failMode, unevalAlert(con.alerts).tool], ["Medium", "open", "gateway:upload_file"]);
    assert.ok(contentFree(con.alerts));
  });
});

test("GATEWAY: an image over 1 MiB is unevaluated: failMode.mcpGateway closed refuses it, open forwards it with one alert per tool", async () => {
  await scenario({ policy: { captureTier: "content-free", failMode: { mcpGateway: "closed" } }, upstream: { resultText: "stored" } }, async ({ con, up, base }) => {
    assert.ok(refused(await rpc(base, gwCall(1, "upload_file", { content: FAKE_PNG() }))));
    assert.ok(refused(await rpc(base, gwCall(2, "upload_file", { content: REAL_PNG() }))));
    assert.ok(!refused(await rpc(base, gwCall(3, "upload_file", { parts: NOTES() }))));
    assert.deepEqual(upNames(up), ["upload_file"]);
    assert.ok(await until(() => failAlert(con.alerts)), cats(con.alerts));
    assert.ok(contentFree(con.alerts));
  });
  await scenario({ policy: { captureTier: "content-free" }, upstream: { resultText: "stored" } }, async ({ con, up, base }) => {
    assert.ok(!refused(await rpc(base, gwCall(1, "upload_file", { content: REAL_PNG() }))));
    assert.ok(await until(() => unevalFor(con.alerts, "gateway:upload_file").length === 1), cats(con.alerts));
    for (const id of [2, 3]) assert.ok(!refused(await rpc(base, gwCall(id, "upload_file", { content: REAL_PNG() }))));
    await sleep(2000);
    assert.ok(!refused(await rpc(base, gwCall(4, "add_photo", { content: REAL_PNG() }))));
    assert.deepEqual(upNames(up), ["upload_file", "upload_file", "upload_file", "add_photo"]);
    assert.ok(await until(() => unevalFor(con.alerts, "gateway:add_photo").length === 1), cats(con.alerts));
    assert.equal(unevalFor(con.alerts, "gateway:upload_file").length, 1, cats(con.alerts));
    const a = unevalFor(con.alerts, "gateway:upload_file")[0];
    assert.deepEqual([a.riskLevel, a.decision, a.failMode, a.failWhy, a.unevaluatedValues], ["Medium", "notify", "open", "size", 1]);
  });
});

test("GATEWAY: characters a lenient decoder skips: a card number is found; a labelled PDF or .docx is refused under onSend block", async () => {
  await scenario({ policy: { captureTier: "content-free", ...LABELS, ...CARD_BLOCK } }, async ({ con, up, base }) => {
    assert.ok(refused(await rpc(base, gwCall(1, "upload_file", { name: "export.csv", content: JUNK_CARD() }))));
    let id = 2;
    for (const content of [JUNK_PDF(), ...JUNK_SMALL()]) assert.ok(refused(await rpc(base, gwCall(id++, "upload_file", { content }))));
    assert.ok(!refused(await rpc(base, gwCall(id++, "upload_file", { content: Buffer.from("plain words in a row ".repeat(10)).toString("base64") }))));
    assert.deepEqual(upNames(up), ["upload_file"]);
    assert.ok(await until(() => con.alerts.some((a) => a.threatId === 90)), cats(con.alerts));
    assert.ok(contentFree(con.alerts));
  });
});

test("GATEWAY: an \"=\" before the end of a value: a card number after it, or split two bytes to a run, is found; a labelled PDF after it is refused under onSend block", async () => {
  await scenario({ policy: { captureTier: "content-free", ...LABELS, ...CARD_BLOCK } }, async ({ con, up, base }) => {
    assert.ok(refused(await rpc(base, gwCall(1, "upload_file", { name: "export.csv", content: PAD_CARD() }))));
    assert.ok(refused(await rpc(base, gwCall(2, "upload_file", { content: PAD_PDF() }))));
    assert.ok(refused(await rpc(base, gwCall(3, "upload_file", { content: RUNS_CARD() }))));
    assert.ok(!refused(await rpc(base, gwCall(4, "upload_file", { content: Buffer.from("plain words in a row!".repeat(10)).toString("base64") }))));
    assert.deepEqual(upNames(up), ["upload_file"]);
    assert.ok(await until(() => con.alerts.some((a) => a.threatId === 90)), cats(con.alerts));
    assert.ok(contentFree(con.alerts));
  });
});
