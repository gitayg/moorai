// Unit tests for the MCP harvest budgets (cli/mcp-harvest.mjs) and the MCP path scope (cli/mcp-scope.mjs).
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-harvest-scope.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mcpHarvestConfig, isMcpRead, dumpShaped, assessHarvest, MCP_HARVEST_DEFAULTS } from "../cli/mcp-harvest.mjs";
import { launchRoots, declaredScope, judgeScope, decideScope, mcpScopeConfig, pathArgs } from "../cli/mcp-scope.mjs";

test("harvest config: defaults, malformed fields fall back, off is honoured", () => {
  assert.deepEqual(mcpHarvestConfig(null), { ...MCP_HARVEST_DEFAULTS });
  assert.deepEqual(mcpHarvestConfig({ mcpHarvest: { mode: "loud", reads: -1, bytes: "9", windowMin: 0 } }), { ...MCP_HARVEST_DEFAULTS });
  assert.equal(mcpHarvestConfig({ mcpHarvest: { mode: "off" } }).mode, "off");
  assert.equal(mcpHarvestConfig({ mcpHarvest: { reads: 7.9 } }).reads, 7);
});

test("isMcpRead: resources/read, read and detokenize classes, query-named unknown tools; not writes or destructive", () => {
  const r = (tool, extra = {}) => isMcpRead(null, { server: "s", tool, ...extra });
  assert.equal(isMcpRead(null, { method: "resources/read" }), true);
  for (const t of ["get_customer", "list_rows", "mcp__crm__search_contacts", "run_query", "execute_sql", "export_table", "decrypt_record"]) assert.equal(r(t), true, t);
  for (const t of ["update_customer", "delete_rows", "send_email", "frobnicate", "insert_query_log"]) assert.equal(r(t), false, t);
  assert.equal(isMcpRead({ mcpToolClasses: { s: { frobnicate: "read" } } }, { server: "s", tool: "frobnicate" }), true, "an admin override names a read");
  assert.equal(r("get_report", { annotation: "destructive" }), false, "an annotation that tightens to destructive is not a read");
});

test("dumpShaped: bulk export forms only", () => {
  for (const s of ["COPY customers TO '/tmp/c.csv' CSV", "copy (select * from t) to stdout", "SELECT * INTO OUTFILE '/tmp/x' FROM t", "BACKUP DATABASE crm TO DISK='x'", "pg_dump -t users crm", "mongoexport --collection users", "sqlite3 app.db .dump"]) assert.equal(dumpShaped({ sql: s }), true, s);
  for (const s of ["select * from users where id = 1", "COPY users FROM '/tmp/in.csv'", "copy the file to the folder", "how do I use pg_dumpall_helper"]) assert.equal(dumpShaped({ sql: s }), false, s);
  assert.equal(dumpShaped({ a: [{ b: "x" }, { q: "mysqldump crm" }] }), true, "nested");
});

test("assessHarvest: distinct reads, bytes, one alert per kind per window, levels only for read calls under ask/block", () => {
  const cfg = { mode: "block", reads: 3, bytes: 100, windowMin: 1 };
  let st = null, r;
  const step = (ev, t) => { r = assessHarvest(st, "k", ev, t, cfg); st = r.state; return r; };
  step({ pre: true, readKey: "a" }, 0);
  step({ pre: true, readKey: "a" }, 1);
  assert.equal(r.reads, 1);
  step({ pre: true, readKey: "b" }, 2);
  assert.equal(r.level, "allow");
  step({ pre: true, readKey: "c" }, 3);
  assert.deepEqual([r.over, r.fresh, r.level], [["reads"], ["reads"], "block"]);
  step({ pre: true, readKey: "d" }, 4);
  assert.deepEqual([r.fresh, r.level], [[], "block"]);
  step({ pre: true }, 5);
  assert.equal(r.level, "allow", "a call that is not a read is never held");
  step({ bytes: 150 }, 6);
  assert.deepEqual([r.fresh, r.level], [["bytes"], "allow"], "a result is past holding");
  step({ pre: true, readKey: "e" }, 61000);
  assert.deepEqual([r.reads, r.bytes, r.level], [1, 0, "allow"], "the window slid");
  st = null;
  step({ pre: true, readKey: "a" }, 0);
  step({ pre: true, readKey: "b" }, 50000);
  step({ pre: true, readKey: "c" }, 70000);
  assert.deepEqual([r.reads, r.level], [2, "allow"], "a read older than the window drops out while the key stays active");
  assert.equal(assessHarvest(null, "k", { pre: true, readKey: "a" }, 0, { ...cfg, mode: "report", reads: 1 }).level, "allow", "report never holds");
  assert.deepEqual(assessHarvest(null, "k", { pre: true, readKey: "a" }, 0, { ...cfg, mode: "off", reads: 1 }).fresh, []);
  assert.deepEqual(JSON.parse(JSON.stringify(assessHarvest(null, "k", { pre: true, readKey: "a", dump: true }, 0, cfg))).fresh, ["dump"]);
});

test("launchRoots: the filesystem server's positional arguments, through npx, its bin, node dist/index.js and the guard", () => {
  assert.deepEqual(launchRoots({ command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2026.1.0", "/a", "--flag", "~/b"] }), ["/a", "~/b"]);
  assert.deepEqual(launchRoots({ command: "/usr/local/bin/mcp-server-filesystem", args: ["/a"] }), ["/a"]);
  assert.deepEqual(launchRoots({ command: "node", args: ["/x/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/a"] }), ["/a"]);
  assert.deepEqual(launchRoots({ command: "node", args: ["/opt/moorai/mcp-proxy/moorai-mcp-guard.mjs", "--server", "fs", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/a"] }), ["/a"]);
  assert.equal(launchRoots({ command: "docker", args: ["run", "-i", "mcp/filesystem", "/projects"] }), null, "a docker launch's paths are the container's");
  assert.equal(launchRoots({ command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] }), null);
  assert.equal(launchRoots({ command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] }), null, "no directories: the client's roots decide");
});

test("declaredScope: policy roots win, then the client's roots for a filesystem server, then its launch arguments", () => {
  const decl = { command: "npx", args: ["@modelcontextprotocol/server-filesystem", "/a"] };
  assert.deepEqual(declaredScope({ policy: { mcpScope: { servers: { fs: { roots: ["/p"] } } } }, label: "fs", decl, clientRoots: ["/r"] }), { roots: ["/p"], source: "policy" });
  assert.deepEqual(declaredScope({ policy: {}, label: "fs", decl, clientRoots: ["/r"] }), { roots: ["/r"], source: "roots" });
  assert.deepEqual(declaredScope({ policy: {}, label: "fs", decl }), { roots: ["/a"], source: "args" });
  assert.equal(declaredScope({ policy: {}, label: "gh", decl: { command: "gh-mcp" }, clientRoots: ["/r"] }), null, "client roots do not scope a server that is not a filesystem server");
  assert.equal(mcpScopeConfig({ mcpScope: { mode: "block", servers: { fs: { mode: "off" } } } }, "fs").mode, "off");
  assert.equal(mcpScopeConfig({ mcpScope: { mode: "nonsense" } }, "fs").mode, "report");
});

test("judgeScope: path-named keys only, relative against the roots, ~ expanded, Windows rules on win32", () => {
  assert.deepEqual(pathArgs({ path: "/a", content: "/etc/passwd", edits: [{ oldText: "/x" }], paths: ["/b", "/c"], source: { nested: "/d" } }).sort(), ["/a", "/b", "/c", "/d"]);
  const missing = () => { throw new Error("ENOENT"); };
  const sc = { roots: ["/srv/a", "~/b"], source: "args" };
  const j = (args, tool = "read_text_file") => judgeScope(sc, tool, args, { home: "/home/u", platform: "linux", realpath: missing });
  assert.deepEqual(j({ path: "/srv/a/x" }).kinds, []);
  assert.deepEqual(j({ path: "x/y" }).kinds, []);
  assert.deepEqual(j({ path: "~/b/notes" }).kinds, []);
  assert.deepEqual(j({ path: "/srv/a" }).kinds, [], "a root itself is inside");
  assert.deepEqual(j({ path: "/srv/ab/x" }).kinds, ["outside"], "a sibling with a common prefix is outside");
  assert.deepEqual(j({ path: "../a2/x" }).kinds, ["traversal"]);
  assert.deepEqual(j({ path: "/srv/a/../../etc/shadow" }).kinds, ["traversal"]);
  assert.deepEqual(j({ path: "file:///etc/hosts" }).kinds, ["outside"]);
  assert.deepEqual(j({ path: "https://example.com/x" }).checked, 0, "a URL is not a path");
  assert.deepEqual(j({ path: "C:\\Windows\\x" }).checked, 0, "a Windows path on a POSIX host is the server's to refuse");
  assert.equal(j({ path: "/" }, "directory_tree").listing, true);
  const w = judgeScope({ roots: ["C:\\Users\\u\\proj"], source: "policy" }, "read_file", { path: "c:/users/U/PROJ/a.txt", other: { path: "C:\\Users\\u\\proj\\..\\secret.txt" } }, { home: "C:\\Users\\u", platform: "win32", realpath: missing });
  assert.deepEqual([w.checked, w.kinds], [2, ["traversal"]]);
  // symlink: lexically inside, really outside
  const real = (p) => (p === "/srv/a/link" ? "/etc" : p === "/srv/a" ? "/srv/a" : missing());
  assert.deepEqual(judgeScope(sc, "read_text_file", { path: "/srv/a/link/passwd" }, { home: "/home/u", platform: "linux", realpath: real }).kinds, ["symlink"]);
});

test("decideScope: report allows, ask asks, block denies, off is silent; listing and traversal reasons", () => {
  const judged = { checked: 1, kinds: ["traversal"], findings: 1, listing: false };
  assert.equal(decideScope({}, "fs", "read_text_file", judged).decision, "allow");
  assert.equal(decideScope({ mcpScope: { mode: "ask" } }, "fs", "read_text_file", judged).decision, "ask");
  const b = decideScope({ mcpScope: { mode: "block" } }, "fs", "mcp__fs__read_text_file", judged);
  assert.equal(b.decision, "deny");
  assert.match(b.reason, /^read_text_file — path traversal outside/);
  assert.equal(decideScope({ mcpScope: { mode: "off" } }, "fs", "read_text_file", judged), null);
  assert.equal(decideScope({}, "fs", "read_text_file", { ...judged, findings: 0, kinds: [] }), null);
  assert.match(decideScope({}, "fs", "list_directory", { ...judged, kinds: ["outside"], listing: true }).reason, /directory listing outside/);
});
