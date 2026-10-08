// Block-mode tool drift when a tools/list goes UNJUDGED. The documented contract (mcp-proxy/README.md,
// "Which way each failure goes"): a listing MoorAI could not check is forwarded unfiltered, and every call
// to a tool from it is refused as "MCP: tool not in a checked listing" (closed). Before this file that
// held only for a tool MoorAI had never seen: a tool that passed an EARLIER listing kept its clean verdict,
// so a server could serve a clean list, then rug-pull the description inside a listing MoorAI does not
// judge, and the drifted tool stayed callable. The unjudged listings exercised here:
//   * a tools/list line over CAPS.maxLineBytes (1 MB) through the stdio guard;
//   * a tools/list whose "result" key is spelled "result" (same JSON to every parser) — the guard's
//     cheap `"result"` substring pre-filter skipped parsing it;
//   * a JSON tools/list body over 1 MB (and under the 4 MiB response cap) through the HTTP gateway;
//   * an SSE-framed tools/list event over 1 MB through the HTTP gateway.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-tool-drift-unjudged.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import {
  startConsole, makeHome, startGuard, PAGED_FAKE, ADD, ADD_DESC, ECHO, PAD, BLOCK,
  called, blocked, quarantined, unchecked
} from "./tool-drift-helpers.mjs";
import { scenario, rpc, call } from "../mcp-gateway/test/harness.mjs";

async function proxyScenario(fn) {
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  const pages = join(home, "pages.json");
  const log = join(home, "recv.log");
  const setPages = (p) => writeFileSync(pages, JSON.stringify(p));
  try { await fn({ con, home, log, setPages, g: () => startGuard({ home, url: con.url, server: PAGED_FAKE, serverEnv: { FAKE_PAGES_FILE: pages }, recvLog: log }) }); }
  finally { await con.close(); rmTree(home); }
}

test("PROXY: a tool that passed a clean listing is refused after the server re-lists it in a listing over 1 MB", async () => {
  await proxyScenario(async ({ log, setPages, g: start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")), "block mode loads its policy on the first call");
      assert.deepEqual((await g.list()).tools.map((t) => t.name), ["add", "echo"]);
      assert.ok(!blocked(await g.call("add", { a: 1, b: 2 })), "clean listing: add works");
      setPages([[ADD_DESC, ECHO, PAD]]);
      const big = await g.list();
      assert.deepEqual(big.tools.map((t) => t.name), ["add", "echo", "pad"], "documented: an over-cap listing is forwarded unfiltered");
      const r = await g.call("add", { a: 1, b: 2 });
      assert.ok(blocked(r), `the drifted tool from an unjudged listing was forwarded: ${JSON.stringify(r)}`);
      assert.ok(unchecked(r), "refused as not in a checked listing");
      assert.ok(unchecked(await g.call("echo", {})), "documented: every call to a tool from the unjudged listing is refused");
      // A judged listing restores normal service: the drifted tool stays quarantined, the clean one works.
      setPages([[ADD_DESC, ECHO]]);
      assert.deepEqual((await g.list()).tools.map((t) => t.name), ["echo"]);
      assert.ok(quarantined(await g.call("add", { a: 1, b: 2 })));
      assert.ok(!blocked(await g.call("echo", {})));
    } finally { await g.close(); }
    assert.deepEqual(called(log), ["add", "echo"], "only the calls made after judged listings reached the server");
  });
});

test("PROXY: a listing whose result key is spelled \\u0072esult is judged like any other", async () => {
  await proxyScenario(async ({ log, setPages, g: start }) => {
    setPages([[ADD, ECHO]]);
    const g = start();
    try {
      assert.ok(unchecked(await g.call("__prime__")));
      assert.deepEqual((await g.list()).tools.map((t) => t.name), ["add", "echo"]);
      setPages({ escapeResultKey: true, pages: [[ADD_DESC, ECHO]] });
      const r = await g.send("tools/list");
      assert.deepEqual(r.msg.result.tools.map((t) => t.name), ["echo"], "the drifted tool must be left out");
      const c = await g.call("add", { a: 1, b: 2 });
      assert.ok(quarantined(c), `drifted tool callable after an escaped-key listing: ${JSON.stringify(c)}`);
    } finally { await g.close(); }
    assert.deepEqual(called(log), []);
  });
});

// ---- the HTTP gateway ----
const env = { MOORAI_TEST_POLICY_REFRESH_MS: "0" };
const list = (base, id) => rpc(base, { jsonrpc: "2.0", id, method: "tools/list", params: {} });
const names = (r) => r.json.result.tools.map((t) => t.name);
const refused = (r) => !!(r.json && r.json.result && r.json.result.isError === true && /MoorAI blocked this MCP tool call/.test(r.json.result.content[0].text));
const notChecked = (r) => refused(r) && /not in a tool listing MoorAI could check/.test(r.json.result.content[0].text);

test("GATEWAY: a tool that passed a clean listing is refused after a JSON listing over 1 MB re-lists it", async () => {
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  let i = 0;
  const batches = [[ADD, ECHO], [ADD_DESC, ECHO, PAD]];
  const listReply = (m) => JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: batches[Math.min(i++, batches.length - 1)] } });
  try {
    await scenario({ con, home, upstream: { listReply }, env }, async ({ base, up }) => {
      assert.ok(notChecked(await rpc(base, call(1, "__prime__"))));
      assert.deepEqual(names(await list(base, 2)), ["add", "echo"]);
      assert.ok(!refused(await rpc(base, call(3, "add", { a: 1, b: 2 }))));
      const big = await list(base, 4);
      assert.deepEqual(names(big), ["add", "echo", "pad"], "documented: forwarded unfiltered");
      const r = await rpc(base, call(5, "add", { a: 1, b: 2 }));
      assert.ok(notChecked(r), `the drifted tool from an unjudged listing was forwarded: ${r.text.slice(0, 300)}`);
      assert.ok(notChecked(await rpc(base, call(6, "echo", {}))));
      assert.deepEqual(up.calls().map((c) => c.json.params.name), ["add"]);
    });
  } finally { await con.close(); rmTree(home); }
});

// An upstream that answers tools/list as an SSE stream (one event), for the SSE leg of the gateway.
async function sseListUpstream(batches) {
  let i = 0;
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = ""; req.setEncoding("utf8");
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      let m; try { m = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      if (m.id == null) { res.writeHead(202); res.end(); return; }
      if (m.method === "tools/list") {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.end(`id: e1\nevent: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { tools: batches[Math.min(i++, batches.length - 1)] } })}\n\n`);
        return;
      }
      if (m.method === "tools/call") calls.push(m.params.name);
      const result = m.method === "tools/call" ? { content: [{ type: "text", text: "ok" }], isError: false } : {};
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}/mcp`, calls, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

const sseNames = (r) => {
  const data = r.text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => JSON.parse(l.slice(6)));
  return data.find((d) => d.result && d.result.tools).result.tools.map((t) => t.name);
};

test("GATEWAY: a tool that passed a clean listing is refused after an SSE listing event over 1 MB re-lists it", async () => {
  const { startGateway, stopGateway } = await import("../mcp-gateway/test/harness.mjs");
  const con = await startConsole(BLOCK);
  const home = makeHome(con.url);
  const up = await sseListUpstream([[ADD, ECHO], [ADD_DESC, ECHO, PAD]]);
  const gw = await startGateway({ home, consoleUrl: con.url, args: ["--port", "0", "--route", `/remote=${up.url}`], env });
  try {
    assert.ok(gw.url, gw.stderr);
    const base = `${gw.url}/remote`;
    assert.ok(notChecked(await rpc(base, call(1, "__prime__"))));
    assert.deepEqual(sseNames(await list(base, 2)), ["add", "echo"]);
    assert.ok(!refused(await rpc(base, call(3, "add", { a: 1, b: 2 }))));
    assert.deepEqual(sseNames(await list(base, 4)), ["add", "echo", "pad"], "documented: forwarded unfiltered");
    const r = await rpc(base, call(5, "add", { a: 1, b: 2 }));
    assert.ok(notChecked(r), `the drifted tool from an unjudged SSE listing was forwarded: ${r.text.slice(0, 300)}`);
    assert.deepEqual(up.calls, ["add"]);
  } finally { await stopGateway(gw); await up.close(); await con.close(); rmTree(home); }
});
