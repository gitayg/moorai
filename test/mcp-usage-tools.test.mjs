// Per-tool MCP usage counts (CONTRACT C4) in cli/mcp-usage-beat.mjs: the gateway path counts the MCP tool
// NAME of each tools/call next to its server; a completed day posts servers[].tools (top 64, busiest first)
// and toolsTruncated when more were seen. Names only — never arguments. The hook and proxy paths keep
// ignoring a tool name, as test/mcp-usage-beat.test.mjs's CONTRACT test pins.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-usage-tools.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordMcpCall, flushMcpUsage, dueDays, readTally, TALLY_FILE, MAX_TOOLS, MAX_TOOLS_STORED, GATEWAY_HOST } from "../cli/mcp-usage-beat.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const DAY = 24 * 3600 * 1000;
const T0 = Date.parse("2026-10-01T12:00:00Z");
const ID = { user: "service", device: "svc:gw-1", platform: "linux", actor: "h2:actor" };
const CFG = (url) => ({ serverUrl: url, tenant: "acme", installToken: "tok-usage" });
const G = (label, tool, extra = {}) => ({ path: "gateway", host: "gateway", label, tool, ...extra });

function dir(t) { const d = mkdtempSync(join(tmpdir(), "moorai-usage-tools-")); t.after(() => rmTree(d)); return d; }
async function consoleStub(t) {
  const posts = [];
  const srv = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url === "/api/mcp-usage") posts.push({ raw: b, body: JSON.parse(b) }); res.writeHead(201); res.end("{}"); });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, posts };
}

test("C4 BODY: a completed gateway day posts servers with per-tool counts — exact shape, no arguments", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  for (let i = 0; i < 3; i++) recordMcpCall(G("github", "create_issue", { arguments: { body: "ARG-SECRET-1" } }), { dir: d, now: T0 });
  recordMcpCall(G("github", "search_code"), { dir: d, now: T0 });
  recordMcpCall(G("files", "read_file"), { dir: d, now: T0 });
  const r = await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "gateway", host: "anything", dir: d, now: T0 + DAY });
  assert.deepEqual(r.posted, ["2026-10-01"]);
  assert.equal(c.posts.length, 1);
  assert.deepEqual(c.posts[0].body, {
    user: "service", device: "svc:gw-1", platform: "linux", actor: "h2:actor",
    day: "2026-10-01", path: "gateway", host: "gateway",
    servers: [
      { label: "github", calls: 4, tools: [{ name: "create_issue", calls: 3 }, { name: "search_code", calls: 1 }] },
      { label: "files", calls: 1, tools: [{ name: "read_file", calls: 1 }] }
    ]
  });
  assert.ok(!c.posts[0].raw.includes("ARG-SECRET-1"), "an argument reached the post");
  assert.ok(!readFileSync(join(d, TALLY_FILE), "utf8").includes("ARG-SECRET-1"), "an argument reached the tally");
});

test("C4 HOST: the gateway path always reports host 'gateway', whatever the caller passes", (t) => {
  const d = dir(t);
  recordMcpCall({ path: "gateway", host: "claude-code", label: "github", tool: "x" }, { dir: d, now: T0 });
  assert.deepEqual(Object.keys(readTally(d).days["2026-10-01"]), [`gateway|${GATEWAY_HOST}`]);
});

test("C4 ROLLOVER + ONCE A DAY: today never posts; each completed day posts once, oldest first, with its own tools", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  recordMcpCall(G("github", "a"), { dir: d, now: T0 });
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "gateway", dir: d, now: T0 });
  assert.equal(c.posts.length, 0, "today's partial day was posted");
  recordMcpCall(G("github", "b"), { dir: d, now: T0 + DAY });
  recordMcpCall(G("github", "b"), { dir: d, now: T0 + DAY });
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "gateway", dir: d, now: T0 + 2 * DAY });
  assert.deepEqual(c.posts.map((p) => [p.body.day, p.body.servers[0].tools]), [
    ["2026-10-01", [{ name: "a", calls: 1 }]],
    ["2026-10-02", [{ name: "b", calls: 2 }]]
  ]);
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "gateway", dir: d, now: T0 + 2 * DAY + 1000 });
  assert.equal(c.posts.length, 2, "a day was posted twice");
});

test("C4 TRUNCATION: more than 64 tools on a server post the 64 busiest and toolsTruncated: true", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  for (let i = 0; i < MAX_TOOLS + 6; i++) recordMcpCall(G("big", `tool_${String(i).padStart(3, "0")}`), { dir: d, now: T0 });
  for (let i = 0; i < 4; i++) recordMcpCall(G("big", "tool_069"), { dir: d, now: T0 });
  recordMcpCall(G("small", "only"), { dir: d, now: T0 });
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "gateway", dir: d, now: T0 + DAY });
  const [big, small] = c.posts[0].body.servers;
  assert.equal(big.label, "big");
  assert.equal(big.tools.length, MAX_TOOLS);
  assert.deepEqual(big.tools[0], { name: "tool_069", calls: 5 });
  assert.deepEqual(big.tools[1], { name: "tool_000", calls: 1 }, "ties break by name");
  assert.equal(big.toolsTruncated, true);
  assert.equal(small.toolsTruncated, undefined, "an untruncated server must not carry the flag");
});

test("C4 STORAGE BOUND: past MAX_TOOLS_STORED names a server keeps counting calls and marks the day truncated", (t) => {
  const d = dir(t);
  for (let i = 0; i < MAX_TOOLS_STORED + 3; i++) recordMcpCall(G("huge", `t${i}`), { dir: d, now: T0 });
  const tally = readTally(d);
  assert.equal(tally.days["2026-10-01"]["gateway|gateway"].huge, MAX_TOOLS_STORED + 3);
  assert.equal(Object.keys(tally.tools["2026-10-01"]["gateway|gateway"].huge.c).length, MAX_TOOLS_STORED);
  assert.equal(tally.tools["2026-10-01"]["gateway|gateway"].huge.x, 1);
  assert.equal(dueDays({ path: "gateway", host: "gateway" }, { dir: d, now: T0 + DAY })[0].servers[0].toolsTruncated, true);
});

test("C4 NAMES: a name outside [A-Za-z0-9_.:/-]{1,128} is not stored; the server call still counts", (t) => {
  const d = dir(t);
  for (const bad of ["", "has space", "x".repeat(129), "semi;colon", { n: 1 }, 7, "new\nline"]) recordMcpCall(G("srv", bad), { dir: d, now: T0 });
  recordMcpCall(G("srv", "ns:tool/v1.2_x-y"), { dir: d, now: T0 });
  const tally = readTally(d);
  assert.equal(tally.days["2026-10-01"]["gateway|gateway"].srv, 8);
  assert.deepEqual(Object.keys(tally.tools["2026-10-01"]["gateway|gateway"].srv.c), ["ns:tool/v1.2_x-y"]);
});

test("C4 HOOK/PROXY UNCHANGED: a tool name passed on the proxy or hook path is ignored", (t) => {
  const d = dir(t);
  recordMcpCall({ path: "proxy", host: "vscode", label: "github", tool: "create_issue" }, { dir: d, now: T0 });
  recordMcpCall({ path: "hook", host: "claude-code", label: "github", tool: "create_issue" }, { dir: d, now: T0 });
  assert.ok(!readFileSync(join(d, TALLY_FILE), "utf8").includes("create_issue"));
  assert.ok(dueDays({ path: "proxy", host: "vscode" }, { dir: d, now: T0 + DAY })[0].servers.every((s) => Object.keys(s).join() === "label,calls"));
});

test("C4 CORRUPT FILE: hand-edited tool entries shrink to valid ones; a tools key for a non-tool path is dropped", (t) => {
  const d = dir(t);
  writeFileSync(join(d, TALLY_FILE), JSON.stringify({
    v: 1,
    days: { "2026-10-01": { "gateway|gateway": { s: 3 }, "proxy|vscode": { s: 1 } } },
    tools: { "2026-10-01": { "gateway|gateway": { s: { c: { ok: 2, "bad name": 1, neg: -1, f: 1.5 } }, ghost: { c: { a: 1 } } }, "proxy|vscode": { s: { c: { leaked: 1 } } } } }
  }));
  const tally = readTally(d);
  assert.deepEqual(JSON.parse(JSON.stringify(tally.tools)), { "2026-10-01": { "gateway|gateway": { s: { c: { ok: 2 } } } } });
});
