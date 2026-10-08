// Block-mode tool drift against servers that PAGE their tool list (MCP `nextCursor` / `cursor`), through
// the real stdio guard (over mcp-proxy/test/fake-paged-mcp-server.mjs) and the real HTTP gateway (over the
// fake upstream with a paging listReply). What must hold:
//   * a server new to the device is a first sighting on EVERY page of its first listing, not just page 1:
//     page 2's tools are not "added after approval" just because page 1 was recorded a moment earlier;
//   * a tool that drifts on a later page is quarantined there (left out of that page, its call refused),
//     and the tools on the other pages keep working;
//   * a page is not a complete listing: its fingerprints are never reported to the console, and a tool
//     missing from one page (or from pages the client never fetched) raises no removal alert — while the
//     same change on a single-page server does (the control that shows those assertions can fail);
//   * the documented over-1 MB path: a page over CAPS.maxLineBytes is forwarded unfiltered and calls are
//     refused as "not in a checked listing" — for its own tools and for those an earlier page passed.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-drift-paged.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { rmTree } from "./fs-cleanup.mjs";
import {
  startConsole, makeHome, startGuard, PAGED_FAKE, ADD, ADD_DESC, ECHO, MUL, MUL_DESC, PAD, BLOCK,
  settle, called, blocked, quarantined, unchecked
} from "./tool-drift-helpers.mjs";
import { scenario, rpc, call } from "../mcp-gateway/test/harness.mjs";

const REMOVED = "MCP: tool removed after approval";
const ADDED = "MCP: tool added after approval";
const names = (r) => r.tools.map((t) => t.name);

async function proxyScenario(fn) {
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  const pages = join(home, "pages.json");
  const log = join(home, "recv.log");
  const setPages = (p) => writeFileSync(pages, JSON.stringify(p));
  const start = (label = "pagedsrv") => startGuard({ home, url: con.url, label, server: PAGED_FAKE, serverEnv: { FAKE_PAGES_FILE: pages }, recvLog: log });
  try { await fn({ con, home, log, setPages, start }); }
  finally { await con.close(); rmTree(home); }
}

// Walk every page the way a client does. → [{ tools, nextCursor }]
async function walk(g) {
  const out = [];
  let r = await g.list();
  out.push(r);
  while (r.nextCursor != null) { r = await g.list({ cursor: r.nextCursor }); out.push(r); }
  return out;
}

test("PROXY PAGED: the first listing of a new server is a first sighting on every page", async () => {
  await proxyScenario(async ({ con, log, setPages, start }) => {
    setPages([[ADD, ECHO], [MUL]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      const pages = await walk(g);
      assert.deepEqual(pages.map(names), [["add", "echo"], ["mul"]], "page 2's tool was quarantined on the server's first sighting");
      assert.ok(!blocked(await g.call("mul", { a: 2, b: 3 })), "a page-2 tool of a first sighting must be callable");
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["mul"]);
    assert.ok(!con.alerts.some((a) => a.category === ADDED), JSON.stringify(con.alerts.map((a) => a.category)));
  });
});

test("PROXY PAGED: drift on page 2 is quarantined there; page-1 tools keep working; nothing is reported or alerted as removed", async () => {
  await proxyScenario(async ({ con, log, setPages, start }) => {
    setPages([[ADD, ECHO], [MUL]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await walk(g);
      setPages([[ADD, ECHO], [MUL_DESC]]);
      const pages = await walk(g);
      assert.deepEqual(pages.map(names), [["add", "echo"], []], "the drifted page-2 tool must be left out of page 2");
      assert.equal(pages[0].nextCursor, "p1", "the cursor is forwarded untouched");
      const r = await g.call("mul", { a: 2, b: 3 });
      assert.ok(quarantined(r), JSON.stringify(r));
      assert.ok(!blocked(await g.call("add", { a: 1, b: 2 })), "an unchanged page-1 tool still works");
      // Drift on page 1 is caught on page 1.
      setPages([[ADD_DESC, ECHO], [MUL]]);
      assert.deepEqual(names(await g.list()), ["echo"]);
      assert.ok(quarantined(await g.call("add", { a: 1, b: 2 })));
      // ECHO removed from page 1 and the client stops after page 1: no removal alert from a partial list.
      setPages([[ADD], [MUL]]);
      assert.deepEqual(names(await g.list()), ["add"]);
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["add"]);
    const q = con.alerts.filter((a) => a.decision === "quarantine");
    assert.ok(q.some((a) => a.tool === "desktop:mul" && /description changed/.test(a.category)), JSON.stringify(q.map((a) => [a.tool, a.category])));
    assert.ok(!con.alerts.some((a) => a.category === REMOVED), "a removal alert was raised on a partial (paged) list");
    assert.equal(con.toolReports.length, 0, "an incomplete (paged) listing must never be reported to the console");
  });
});

test("PROXY CONTROL: the same removal on a single-page server alerts and its complete listing is reported", async () => {
  await proxyScenario(async ({ con, setPages, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await g.list();
      setPages([[ADD]]);
      await g.list();
      await settle();
    } finally { await g.close(); }
    assert.equal(con.alerts.filter((a) => a.category === REMOVED).length, 1, JSON.stringify(con.alerts.map((a) => a.category)));
    assert.ok(con.toolReports.length >= 1 && con.toolReports.every((r) => r.server === "pagedsrv"));
  });
});

test("PROXY PAGED: a page over 1 MB is forwarded unfiltered and calls are refused as not in a checked listing", async () => {
  await proxyScenario(async ({ con, log, setPages, start }) => {
    setPages([[ADD, ECHO], [MUL]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await walk(g);
      assert.ok(!blocked(await g.call("add", { a: 1, b: 2 })));
      setPages([[ADD, ECHO], [MUL_DESC, PAD]]);
      const pages = await walk(g);
      assert.deepEqual(pages.map(names), [["add", "echo"], ["mul", "pad"]], "documented: the over-cap page goes unfiltered");
      assert.ok(unchecked(await g.call("mul", { a: 2, b: 3 })), "a tool from the over-cap page must be refused as unchecked");
      assert.ok(unchecked(await g.call("pad", {})));
      assert.ok(unchecked(await g.call("add", { a: 1, b: 2 })), "after an unjudged page no earlier verdict vouches for any tool");
      // The next judged walk restores the checked tools.
      setPages([[ADD, ECHO], [MUL_DESC]]);
      await walk(g);
      assert.ok(!blocked(await g.call("add", { a: 1, b: 2 })));
      assert.ok(quarantined(await g.call("mul", { a: 2, b: 3 })));
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["add", "add"]);
    assert.equal(con.toolReports.length, 0);
  });
});

// ---- the HTTP gateway ----
const env = { MOORAI_TEST_POLICY_REFRESH_MS: "0" };
function pagedReply(state) {
  return (m) => {
    const cursor = m.params && m.params.cursor;
    const n = cursor == null ? 0 : Number(String(cursor).slice(1));
    const pages = state.pages;
    return JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: pages[n], ...(n + 1 < pages.length ? { nextCursor: `p${n + 1}` } : {}) } });
  };
}
let rid = 100;
const glist = async (base, cursor) => (await rpc(base, { jsonrpc: "2.0", id: rid++, method: "tools/list", params: cursor ? { cursor } : {} })).json.result;
async function gwalk(base) {
  const out = [];
  let r = await glist(base);
  out.push(r);
  while (r.nextCursor != null) { r = await glist(base, r.nextCursor); out.push(r); }
  return out;
}
const gcall = async (base, name, args = {}) => (await rpc(base, call(rid++, name, args))).json.result;

async function gwScenario(fn) {
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  const state = { pages: [[ADD, ECHO], [MUL]] };
  try { await scenario({ con, home, upstream: { listReply: pagedReply(state) }, env }, (ctx) => fn({ ...ctx, con, state })); }
  finally { await con.close(); rmTree(home); }
}

test("GATEWAY PAGED: first sighting on every page; page-2 drift quarantined there; no report, no removal alert", async () => {
  await gwScenario(async ({ base, up, con, state }) => {
    assert.ok(unchecked(await gcall(base, "__prime__")));
    assert.deepEqual((await gwalk(base)).map(names), [["add", "echo"], ["mul"]], "page 2's tool was quarantined on the server's first sighting");
    assert.ok(!blocked(await gcall(base, "mul", { a: 2, b: 3 })));
    state.pages = [[ADD, ECHO], [MUL_DESC]];
    assert.deepEqual((await gwalk(base)).map(names), [["add", "echo"], []]);
    assert.ok(quarantined(await gcall(base, "mul", { a: 2, b: 3 })));
    assert.ok(!blocked(await gcall(base, "add", { a: 1, b: 2 })));
    state.pages = [[ADD], [MUL]];
    assert.deepEqual(names(await glist(base)), ["add"]);
    await settle();
    assert.deepEqual(up.calls().map((c) => c.json.params.name), ["mul", "add"]);
    assert.ok(!con.alerts.some((a) => a.category === REMOVED || a.category === ADDED), JSON.stringify(con.alerts.map((a) => a.category)));
    assert.equal(con.toolReports.length, 0, "an incomplete (paged) listing must never be reported to the console");
  });
});

test("GATEWAY PAGED: a page over 1 MB is forwarded unfiltered and calls are refused as not in a checked listing", async () => {
  await gwScenario(async ({ base, up, state }) => {
    assert.ok(unchecked(await gcall(base, "__prime__")));
    await gwalk(base);
    state.pages = [[ADD, ECHO], [MUL_DESC, PAD]];
    assert.deepEqual((await gwalk(base)).map(names), [["add", "echo"], ["mul", "pad"]]);
    assert.ok(unchecked(await gcall(base, "mul", { a: 2, b: 3 })));
    assert.ok(unchecked(await gcall(base, "add", { a: 1, b: 2 })));
    assert.deepEqual(up.calls().map((c) => c.json.params.name), []);
  });
});
