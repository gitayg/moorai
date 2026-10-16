// Block-mode tool drift against a STALE CLIENT: the server changes a tool after the client listed, and the
// client calls it without listing again. In block mode the stdio guard (mcp-proxy/moorai-mcp-guard.mjs)
// and the HTTP gateway (mcp-gateway/) decide such a call against a fresh enough listing: past the signed
// policy's `mcpToolRecheckSeconds` window (default 300, 0 = every call), or after the server's
// notifications/tools/list_changed, they send their OWN tools/list upstream (every page), judge it, and
// only then forward or refuse (mcp-proxy/tool-recheck.mjs). Over real stdio (the paged fake server) and
// real HTTP (the fake upstream), with a fake console serving a signed policy.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-drift-recheck.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { rmTree } from "./fs-cleanup.mjs";
import {
  startConsole, makeHome, startGuard, PAGED_FAKE, ADD, ADD_DESC, ECHO, MUL, MUL_DESC, BLOCK,
  settle, called, blocked, quarantined, unchecked, fp
} from "./tool-drift-helpers.mjs";
import { scenario, rpc, call } from "../mcp-gateway/test/harness.mjs";
import { recheckSeconds, relistAll, createRecheck, RECHECK_DEFAULT_SECONDS, RECHECK_MAX_SECONDS } from "../mcp-proxy/tool-recheck.mjs";

const ADD_SCHEMA = { ...ADD, inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" }, cmd: { type: "string" } } } };
const EVERY_CALL = { ...BLOCK, mcpToolRecheckSeconds: 0 };
const CLOSED = { failMode: { mcpGateway: "closed" } };
const FAILED = "MCP: tool list re-check failed";
const failClosedRecheck = (r) => blocked(r) && /could not re-check the MCP server's current tool list/.test(r.content[0].text);
const echoed = (r) => r && !r.isError && /echoed/.test(r.content[0].text);
const elapsed = async (fn) => { const t0 = Date.now(); const v = await fn(); return [v, Date.now() - t0]; };

// ---------------------------------------------------------------------------------------------
// The shared loop and the policy field, without a transport.
// ---------------------------------------------------------------------------------------------
test("mcpToolRecheckSeconds: an integer of at least 0 is taken (0 = every call), capped at a day; anything else is the default", () => {
  assert.equal(recheckSeconds(null), RECHECK_DEFAULT_SECONDS);
  assert.equal(recheckSeconds({}), 300);
  assert.equal(recheckSeconds({ mcpToolRecheckSeconds: 0 }), 0);
  assert.equal(recheckSeconds({ mcpToolRecheckSeconds: 45 }), 45);
  for (const bad of [-1, 1.5, "30", null, true, NaN, Infinity]) assert.equal(recheckSeconds({ mcpToolRecheckSeconds: bad }), 300, String(bad));
  assert.equal(recheckSeconds({ mcpToolRecheckSeconds: 10 ** 9 }), RECHECK_MAX_SECONDS);
});

test("relistAll walks every page, refuses a looping cursor, and stops at the budget", async () => {
  const pages = { undefined: { tools: [ADD], nextCursor: "c1" }, c1: { tools: [ECHO], nextCursor: "c2" }, c2: { tools: [MUL] } };
  const seen = [];
  const r = await relistAll(async (cursor) => { seen.push(cursor); return pages[String(cursor)]; });
  assert.deepEqual(r.tools.map((t) => t.name), ["add", "echo", "mul"]);
  assert.deepEqual(seen, [undefined, "c1", "c2"]);
  assert.deepEqual(await relistAll(async () => ({ tools: [ADD], nextCursor: "same" })), { error: "error" }, "a cursor that repeats never ends");
  assert.deepEqual(await relistAll(async () => { throw new Error("error response"); }), { error: "error" });
  const [t, ms] = await elapsed(() => relistAll(() => new Promise(() => {}), { budgetMs: 150 }));
  assert.deepEqual(t, { error: "timeout" });
  assert.ok(ms < 1000, `the budget did not bound the re-list: ${ms} ms`);
});

test("createRecheck: one re-list in flight is shared; a fresh tracker sends none", async () => {
  let fresh = false;
  const tracker = { freshWithin: () => fresh, awaitingClientListing: () => false };
  const rc = createRecheck({ tracker });
  let sent = 0, release;
  const fetchPage = () => { sent++; return new Promise((r) => { release = () => r({ tools: [ADD] }); }); };
  const judge = () => { fresh = true; return true; };
  const a = rc.ensureFresh({ policy: BLOCK, fetchPage, judge });
  const b = rc.ensureFresh({ policy: BLOCK, fetchPage, judge });
  await new Promise((r) => setImmediate(r));
  release();
  assert.deepEqual(await Promise.all([a, b]), [{ ok: true, rechecked: true }, { ok: true, rechecked: true }]);
  assert.equal(sent, 1, "two concurrent calls sent two re-lists");
  assert.deepEqual(await rc.ensureFresh({ policy: BLOCK, fetchPage, judge }), { ok: true, rechecked: false });
  assert.equal(sent, 1);
});

// ---------------------------------------------------------------------------------------------
// The stdio guard, over the paged fake server (its tool list is re-read on every tools/list).
// ---------------------------------------------------------------------------------------------
async function proxyScenario(policy, fn) {
  const con = await startConsole(policy);
  const home = makeHome(con.url);
  const pages = join(home, "pages.json");
  const control = join(home, "control.json");
  const reqLog = join(home, "requests.log");
  const log = join(home, "recv.log");
  const setPages = (p) => writeFileSync(pages, JSON.stringify(p));
  const setControl = (c) => writeFileSync(control, JSON.stringify(c));
  setControl({});
  const requests = () => (existsSync(reqLog) ? readFileSync(reqLog, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  const ownLists = () => requests().filter((r) => r.method === "tools/list" && typeof r.id === "string" && r.id.startsWith("moorai-recheck-"));
  const start = () => startGuard({ home, url: con.url, label: "recheck", server: PAGED_FAKE, serverEnv: { FAKE_PAGES_FILE: pages, FAKE_CONTROL_FILE: control, FAKE_REQ_LOG: reqLog }, recvLog: log });
  try { await fn({ con, log, setPages, setControl, requests, ownLists, start }); }
  finally { await con.close(); rmTree(home); }
}
// Ids the client sent vs. ids it was answered with: the guard's own re-list answers must never appear.
const strayAnswers = (g, sent) => g.received().filter((m) => m.id != null && !sent.has(m.id));

test("PROXY STALE CLIENT: the server changes a tool's description after the client listed; the call without a re-list is refused and never reaches the server", async () => {
  await proxyScenario(EVERY_CALL, async ({ con, log, setPages, ownLists, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")), "block mode loads its policy on the first call");
      assert.deepEqual((await g.list()).tools.map((t) => t.name), ["add", "echo"]);
      assert.ok(echoed(await g.call("add", { a: 1, b: 2 })), "unchanged: forwarded");
      setPages([[ADD_DESC, ECHO]]); // the server changes the tool; the client does not list again
      const before = ownLists().length;
      const r = await g.call("add", { a: 1, b: 2 });
      assert.ok(quarantined(r), `the changed tool was called on the strength of the client's stale listing: ${JSON.stringify(r)}`);
      assert.equal(ownLists().length, before + 1, "the guard did not list the server itself before deciding");
      assert.ok(echoed(await g.call("echo", { x: 1 })), "the unchanged tool still works");
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["add", "echo"], "the refused call reached the server");
    const q = con.alerts.find((a) => a.decision === "quarantine" && a.tool === "desktop:add");
    assert.ok(q && q.reasonCode === "MCP_TOOL_DRIFT" && q.driftCheck === "recheck" && /description changed/.test(q.category), JSON.stringify(con.alerts.map((a) => [a.category, a.decision, a.driftCheck])));
    assert.ok(con.alerts.some((a) => a.decision === "deny" && a.tool === "desktop:add" && a.driftCheck === "recheck" && a.reasonCode === "MCP_TOOL_DRIFT"));
    assert.ok(!JSON.stringify(con.alerts).includes("credentials"), "alerts are content-free");
    // Only the client's own (complete) listing is reported; what only the re-list saw is not.
    assert.ok(con.toolReports.length >= 1);
    assert.ok(!con.toolReports.some((r) => r.tools.some((t) => t.desc === fp(ADD_DESC, "recheck").desc)), "a re-list's fingerprints were reported to the console");
  });
});

test("PROXY WINDOW: inside mcpToolRecheckSeconds no extra request; past it one extra tools/list, then an unchanged tool is forwarded", async () => {
  await proxyScenario({ ...BLOCK, mcpToolRecheckSeconds: 1 }, async ({ log, setPages, ownLists, requests, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await g.list();
      const n0 = ownLists().length, lists0 = requests().filter((r) => r.method === "tools/list").length;
      assert.ok(echoed(await g.call("add", { a: 1, b: 2 })));
      assert.equal(ownLists().length, n0, "inside the window the guard listed the server again");
      assert.equal(requests().filter((r) => r.method === "tools/list").length, lists0);
      await settle(1100);
      assert.ok(echoed(await g.call("add", { a: 3, b: 4 })), "an unchanged tool past the window must be forwarded");
      assert.equal(ownLists().length, n0 + 1, "past the window exactly one extra tools/list");
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["add", "add"]);
  });
});

test("PROXY list_changed: the server's notifications/tools/list_changed makes the next call re-list (default window), and reaches the client", async () => {
  await proxyScenario(BLOCK, async ({ log, setPages, setControl, ownLists, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await g.list();
      assert.ok(echoed(await g.call("add", { a: 1, b: 2 })));
      const n0 = ownLists().length;
      setControl({ notifyOnPing: true });
      setPages([[ADD_SCHEMA, ECHO]]);
      await g.send("ping");
      assert.ok(g.received().some((m) => m.method === "notifications/tools/list_changed"), "the notification must still reach the client");
      assert.ok(quarantined(await g.call("add", { a: 1, b: 2, cmd: "id" })), "after list_changed the call was decided on the stale listing");
      assert.equal(ownLists().length, n0 + 1);
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["add"]);
  });
});

test("PROXY CONCURRENCY: calls sent together while the listing is stale share one re-list", async () => {
  await proxyScenario(BLOCK, async ({ log, setPages, setControl, ownLists, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await g.list();
      setControl({ notifyOnPing: true });
      await g.send("ping"); // stale now
      setControl({ listDelayMs: 300 });
      const n0 = ownLists().length;
      const rs = await Promise.all([g.call("add", { a: 1, b: 2 }), g.call("echo", { x: 1 }), g.call("add", { a: 5, b: 6 })]);
      assert.ok(rs.every(echoed), JSON.stringify(rs));
      assert.equal(ownLists().length, n0 + 1, "concurrent calls must share one re-list");
    } finally { await g.close(); }
    assert.deepEqual(called(log).sort(), ["add", "add", "echo"]);
  });
});

for (const closed of [true, false]) {
  test(`PROXY TIMEOUT, fail ${closed ? "closed" : "open"}: a re-list past its budget ${closed ? "refuses the call" : "forwards the call with an alert"}, never hangs it, and its late answer never reaches the client`, async () => {
    await proxyScenario({ ...EVERY_CALL, ...(closed ? CLOSED : {}) }, async ({ con, log, setPages, setControl, requests, start }) => {
      setPages([[ADD, ECHO]]);
      const g = start();
      const sent = new Set();
      try {
        assert.ok(unchecked(await g.call("__prime__")));
        await g.list();
        for (let i = 1; i <= 2; i++) sent.add(i);
        setControl({ listDelayMs: 3000 });
        const [r, ms] = await elapsed(() => g.call("add", { a: 1, b: 2 }));
        sent.add(3);
        assert.ok(ms >= 1800 && ms < 3000, `the call waited ${ms} ms (budget 2 s)`);
        if (closed) assert.ok(failClosedRecheck(r), JSON.stringify(r));
        else assert.ok(echoed(r), `fail-open must forward: ${JSON.stringify(r)}`);
        await settle(1800); // the stalled answer arrives (3 s) and must be swallowed
        setControl({});
        assert.ok(requests().some((q) => q.method === "tools/list" && String(q.id).startsWith("moorai-recheck-")));
        assert.deepEqual(strayAnswers(g, sent), [], "the guard's own re-list answer reached the client");
        assert.ok(echoed(await g.call("echo", { after: 1 })), "the session still works after a timed-out re-list");
      } finally { await g.close(); }
      await settle(300);
      assert.deepEqual(called(log), closed ? ["echo"] : ["add", "echo"]);
      if (closed) assert.ok(con.alerts.some((a) => a.category === "Fail-closed: MCP call not evaluated" && a.failWhy === "recheck" && a.tool === "desktop:add"), JSON.stringify(con.alerts.map((a) => [a.category, a.failWhy])));
      else assert.ok(con.alerts.some((a) => a.category === FAILED && a.failMode === "open" && a.failWhy === "timeout" && a.driftCheck === "recheck" && a.decision === "allow"), JSON.stringify(con.alerts.map((a) => [a.category, a.failWhy])));
    });
  });
}

test("PROXY ERROR, fail closed: a re-list answered with a JSON-RPC error refuses the call at once", async () => {
  await proxyScenario({ ...EVERY_CALL, ...CLOSED }, async ({ log, setPages, setControl, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      await g.list();
      setControl({ listError: true });
      const [r, ms] = await elapsed(() => g.call("add", { a: 1, b: 2 }));
      assert.ok(failClosedRecheck(r), JSON.stringify(r));
      assert.ok(ms < 1500, `an error answer should not wait for the budget: ${ms} ms`);
      assert.ok(!g.received().some((m) => m.error), "the re-list's error answer reached the client");
    } finally { await g.close(); }
    assert.deepEqual(called(log), []);
  });
});

test("PROXY IDS: the guard's re-list answers never reach the client, and client ids that look like the guard's still work", async () => {
  await proxyScenario(EVERY_CALL, async ({ log, setPages, requests, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    const look = ["moorai-recheck-000000000000000000000000-1", "moorai-recheck-", "moorai-recheck-ffffffffffffffffffffffff-2"];
    const sent = new Set([1, ...look]);
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      const listed = await g.send("tools/list", {}, { id: look[0] });
      assert.deepEqual(listed.msg.result.tools.map((t) => t.name), ["add", "echo"], "a client tools/list with a look-alike id was not answered");
      const c1 = await g.send("tools/call", { name: "echo", arguments: { n: 1 } }, { id: look[1] });
      const c2 = await g.send("tools/call", { name: "add", arguments: { a: 1, b: 2 } }, { id: look[2] });
      assert.ok(echoed(c1.msg.result) && echoed(c2.msg.result), JSON.stringify([c1.msg, c2.msg]));
      const own = requests().filter((q) => q.method === "tools/list" && !sent.has(q.id));
      assert.ok(own.length >= 3, "each call re-listed (window 0)");
      assert.ok(own.every((o) => /^moorai-recheck-[0-9a-f]{24}-\d+$/.test(o.id)), JSON.stringify(own));
      assert.deepEqual(strayAnswers(g, sent), [], "a re-list answer reached the client");
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["echo", "add"]);
  });
});

test("PROXY PAGINATION: the re-list walks every page; drift on page 2 is refused, a tool that vanished is refused, page-1 tools work", async () => {
  await proxyScenario(EVERY_CALL, async ({ log, setPages, ownLists, start }) => {
    setPages([[ADD, ECHO], [MUL]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      let r = await g.list();
      while (r.nextCursor != null) r = await g.list({ cursor: r.nextCursor });
      assert.ok(echoed(await g.call("mul", { a: 2, b: 3 })));
      setPages([[ADD, ECHO], [MUL_DESC]]);
      const n0 = ownLists().length;
      assert.ok(quarantined(await g.call("mul", { a: 2, b: 3 })), "drift on page 2 was not caught by the re-list");
      const own = ownLists().slice(n0);
      assert.deepEqual(own.map((o) => o.cursor ?? null), [null, "p1"], "the re-list did not walk both pages");
      assert.ok(echoed(await g.call("add", { a: 1, b: 2 })));
      setPages([[ADD, ECHO]]);
      assert.ok(unchecked(await g.call("mul", { a: 2, b: 3 })), "a tool the server no longer lists must be refused");
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["mul", "add"]);
  });
});

test("PROXY ALERT mode: no re-list, ever — the policy's window does not apply outside block mode", async () => {
  await proxyScenario({ mcpToolRecheckSeconds: 0 }, async ({ log, setPages, requests, start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      await g.list();
      assert.ok(echoed(await g.call("add", { a: 1, b: 2 })));
      setPages([[ADD_DESC, ECHO]]);
      assert.ok(echoed(await g.call("add", { a: 1, b: 2 })), "alert mode never refuses for drift");
      await settle();
    } finally { await g.close(); }
    assert.deepEqual(requests().filter((r) => r.method === "tools/list").map((r) => r.id), [1], "alert mode sent a tools/list of its own");
    assert.deepEqual(called(log), ["add", "add"]);
  });
});

// ---------------------------------------------------------------------------------------------
// The HTTP gateway, over the fake Streamable HTTP upstream.
// ---------------------------------------------------------------------------------------------
const OWN = (r) => r.json && r.json.method === "tools/list" && String(r.json.id).startsWith("moorai-gw-recheck-");
const env = { MOORAI_TEST_POLICY_REFRESH_MS: "0" };
const res = (r) => r.json && r.json.result;
const gwBlocked = (r) => blocked(res(r));
const gwEchoed = (r) => { const x = res(r); return !!(x && !x.isError && /echoed/.test(x.content[0].text)); };

async function gwScenario(policy, fn) {
  const con = await startConsole(policy);
  const home = makeHome(con.url);
  const state = { pages: [[ADD, ECHO]], delayOwn: 0 };
  const listReply = (m) => {
    const cursor = m.params && m.params.cursor;
    const n = cursor == null ? 0 : Number(String(cursor).slice(1));
    return JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: state.pages[n], ...(n + 1 < state.pages.length ? { nextCursor: `p${n + 1}` } : {}) } });
  };
  const upstream = { listReply, listDelayMs: (m) => (String(m.id).startsWith("moorai-gw-recheck-") ? state.delayOwn : 0) };
  try {
    await scenario({ con, home, upstream, env }, async ({ base, up, gw }) => {
      const own = () => up.received.filter(OWN);
      await fn({ base, up, gw, con, state, own, calledNames: () => up.calls().map((c) => c.json.params.name) });
    });
  } finally { await con.close(); rmTree(home); }
}
const glist = (base, id, headers, cursor) => rpc(base, { jsonrpc: "2.0", id, method: "tools/list", params: cursor ? { cursor } : {} }, headers);

test("GATEWAY STALE CLIENT: a schema changed after the client listed is refused without a re-list by the client; the gateway's own tools/list carries the client's session headers (2025 era)", async () => {
  await gwScenario(EVERY_CALL, async ({ base, con, state, own, calledNames }) => {
    const H = { "Mcp-Session-Id": "sess-recheck-1", "MCP-Protocol-Version": "2025-06-18", Authorization: "Bearer client-token" };
    assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"), H)));
    assert.deepEqual(res(await glist(base, 2, H)).tools.map((t) => t.name), ["add", "echo"]);
    assert.ok(gwEchoed(await rpc(base, call(3, "add", { a: 1, b: 2 }), H)));
    state.pages = [[ADD_SCHEMA, ECHO]];
    const n0 = own().length;
    const r = await rpc(base, call(4, "add", { a: 1, b: 2, cmd: "id" }), H);
    assert.ok(quarantined(res(r)), `the changed tool was called on the client's stale listing: ${r.text}`);
    assert.equal(r.json.id, 4);
    assert.equal(own().length, n0 + 1);
    const o = own().at(-1);
    assert.equal(o.headers["mcp-session-id"], "sess-recheck-1");
    assert.equal(o.headers["mcp-protocol-version"], "2025-06-18");
    assert.equal(o.headers.authorization, "Bearer client-token");
    assert.match(o.headers.accept, /application\/json/);
    assert.match(o.headers.accept, /text\/event-stream/);
    assert.ok(gwEchoed(await rpc(base, call(5, "echo", {}), H)));
    assert.deepEqual(calledNames(), ["add", "echo"]);
    await settle();
    assert.ok(con.alerts.some((a) => a.decision === "quarantine" && a.tool === "gateway:add" && a.driftCheck === "recheck" && /schema changed/.test(a.category)), JSON.stringify(con.alerts.map((a) => [a.category, a.decision, a.driftCheck])));
    assert.ok(con.alerts.some((a) => a.decision === "deny" && a.tool === "gateway:add" && a.driftCheck === "recheck"));
  });
});

test("GATEWAY STALE CLIENT (2026-07-28 metadata headers): the own tools/list says Mcp-Method tools/list, drops Mcp-Name, and carries the protocol _meta", async () => {
  await gwScenario(EVERY_CALL, async ({ base, state, own, calledNames }) => {
    const PV = "2026-07-28";
    const meta = { "io.modelcontextprotocol/protocolVersion": PV };
    const c = (id, name, args) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args, _meta: meta } });
    const H = (name) => ({ "MCP-Protocol-Version": PV, "Mcp-Method": "tools/call", "Mcp-Name": name });
    assert.ok(gwBlocked(await rpc(base, c(1, "__prime__", {}), H("__prime__"))));
    await rpc(base, { jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: meta } }, { "MCP-Protocol-Version": PV, "Mcp-Method": "tools/list" });
    state.pages = [[ADD_DESC, ECHO]];
    const r = await rpc(base, c(3, "add", { a: 1, b: 2 }), H("add"));
    assert.ok(quarantined(res(r)), r.text);
    const o = own().at(-1);
    assert.equal(o.headers["mcp-method"], "tools/list");
    assert.equal(o.headers["mcp-name"], undefined);
    assert.equal(o.headers["mcp-protocol-version"], PV);
    assert.deepEqual(o.json.params._meta, meta);
    assert.deepEqual(calledNames(), []);
  });
});

test("GATEWAY WINDOW: inside mcpToolRecheckSeconds no extra request; past it one extra tools/list, then an unchanged tool is forwarded", async () => {
  await gwScenario({ ...BLOCK, mcpToolRecheckSeconds: 1 }, async ({ base, own, calledNames }) => {
    assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"))));
    await glist(base, 2);
    const n0 = own().length;
    assert.ok(gwEchoed(await rpc(base, call(3, "add", { a: 1, b: 2 }))));
    assert.equal(own().length, n0, "inside the window the gateway listed the upstream again");
    await settle(1100);
    assert.ok(gwEchoed(await rpc(base, call(4, "add", { a: 1, b: 2 }))));
    assert.equal(own().length, n0 + 1, "past the window exactly one extra tools/list");
    assert.deepEqual(calledNames(), ["add", "add"]);
  });
});

test("GATEWAY list_changed: the upstream's notifications/tools/list_changed (GET stream) makes the next call re-list (default window)", async () => {
  await gwScenario(BLOCK, async ({ base, state, own, calledNames }) => {
    assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"))));
    await glist(base, 2);
    assert.ok(gwEchoed(await rpc(base, call(3, "add", { a: 1, b: 2 }))));
    const n0 = own().length;
    state.pages = [[ADD_DESC, ECHO]];
    const g = await fetch(base, { method: "GET", headers: { Accept: "text/event-stream" } });
    assert.match(await g.text(), /notifications\/tools\/list_changed/, "the notification must still reach the client");
    assert.ok(quarantined(res(await rpc(base, call(4, "add", { a: 1, b: 2 })))), "after list_changed the call was decided on the stale listing");
    assert.equal(own().length, n0 + 1);
    assert.deepEqual(calledNames(), ["add"]);
  });
});

test("GATEWAY CONCURRENCY: concurrent calls on one route share one re-list", async () => {
  await gwScenario(EVERY_CALL, async ({ base, state, own, calledNames }) => {
    assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"))));
    await glist(base, 2);
    state.delayOwn = 400;
    const n0 = own().length;
    const rs = await Promise.all([rpc(base, call(10, "add", { a: 1, b: 2 })), rpc(base, call(11, "echo", {})), rpc(base, call(12, "add", { a: 3, b: 4 }))]);
    assert.ok(rs.every(gwEchoed), rs.map((r) => r.text).join("\n"));
    assert.equal(own().length, n0 + 1, "concurrent calls must share one re-list");
    assert.deepEqual(calledNames().sort(), ["add", "add", "echo"]);
  });
});

for (const closed of [true, false]) {
  test(`GATEWAY TIMEOUT, fail ${closed ? "closed" : "open"}: a re-list past its budget ${closed ? "refuses the call" : "forwards the call with an alert"} and never hangs it`, async () => {
    await gwScenario({ ...EVERY_CALL, ...(closed ? CLOSED : {}) }, async ({ base, con, state, calledNames }) => {
      assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"))));
      await glist(base, 2);
      state.delayOwn = 3000;
      const [r, ms] = await elapsed(() => rpc(base, call(3, "add", { a: 1, b: 2 })));
      assert.ok(ms >= 1800 && ms < 3000, `the call waited ${ms} ms (budget 2 s)`);
      assert.equal(r.json.id, 3);
      if (closed) assert.ok(failClosedRecheck(res(r)), r.text);
      else assert.ok(gwEchoed(r), `fail-open must forward: ${r.text}`);
      assert.deepEqual(calledNames(), closed ? [] : ["add"]);
      await settle();
      if (closed) assert.ok(con.alerts.some((a) => a.category === "Fail-closed: MCP call not evaluated" && a.failWhy === "recheck" && a.tool === "gateway:add"), JSON.stringify(con.alerts.map((a) => [a.category, a.failWhy])));
      else assert.ok(con.alerts.some((a) => a.category === FAILED && a.failMode === "open" && a.failWhy === "timeout" && a.driftCheck === "recheck"), JSON.stringify(con.alerts.map((a) => [a.category, a.failWhy])));
    });
  });
}

test("GATEWAY IDS: the own tools/list uses an id no client sends; a client id that looks like it still works", async () => {
  await gwScenario(EVERY_CALL, async ({ base, own, calledNames }) => {
    assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"))));
    await glist(base, 2);
    const look = "moorai-gw-recheck-000000000000000000000000-1";
    const r = await rpc(base, call(look, "echo", { n: 1 }));
    assert.equal(r.json.id, look);
    assert.ok(gwEchoed(r), r.text);
    assert.ok(own().length >= 2 && own().every((o) => o.json.id !== look));
    assert.deepEqual(calledNames(), ["echo"]);
  });
});

test("GATEWAY PAGINATION: the re-list walks every page; drift on page 2 is refused, page-1 tools work", async () => {
  await gwScenario(EVERY_CALL, async ({ base, state, own, calledNames }) => {
    state.pages = [[ADD, ECHO], [MUL]];
    assert.ok(gwBlocked(await rpc(base, call(1, "__prime__"))));
    let r = res(await glist(base, 2));
    let id = 3;
    while (r.nextCursor != null) r = res(await glist(base, id++, {}, r.nextCursor));
    assert.ok(gwEchoed(await rpc(base, call(10, "mul", { a: 2, b: 3 }))));
    state.pages = [[ADD, ECHO], [MUL_DESC]];
    const n0 = own().length;
    assert.ok(quarantined(res(await rpc(base, call(11, "mul", { a: 2, b: 3 })))));
    assert.deepEqual(own().slice(n0).map((o) => (o.json.params && o.json.params.cursor) ?? null), [null, "p1"]);
    assert.ok(gwEchoed(await rpc(base, call(12, "add", { a: 1, b: 2 }))));
    assert.deepEqual(calledNames(), ["mul", "add"]);
  });
});

test("GATEWAY ALERT mode: no re-list, ever", async () => {
  await gwScenario({ mcpToolRecheckSeconds: 0 }, async ({ base, up, state, own, calledNames }) => {
    await glist(base, 1);
    assert.ok(gwEchoed(await rpc(base, call(2, "add", { a: 1, b: 2 }))));
    state.pages = [[ADD_DESC, ECHO]];
    assert.ok(gwEchoed(await rpc(base, call(3, "add", { a: 1, b: 2 }))));
    await settle();
    assert.equal(own().length, 0, "alert mode sent a tools/list of its own");
    assert.equal(up.received.filter((q) => q.json && q.json.method === "tools/list").length, 1);
    assert.deepEqual(calledNames(), ["add", "add"]);
  });
});
