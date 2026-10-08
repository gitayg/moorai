// Opt-in: block-mode MCP tool drift (`mcpToolDrift: "block"`) seen by REAL MCP client applications, with
// NO model call — the official TypeScript SDK client, the MCP Inspector CLI, `cursor-agent mcp list-tools`
// and `claude mcp list` — through both MoorAI pieces: the stdio guard and the HTTP gateway.
//
//   MOORAI_LIVE_MCP=1 node --test --import ./test/hermetic-env.mjs test/mcp-tool-drift-live.test.mjs
//
// Per transport: a baseline run (SDK) lists the fake server's tools and calls both, so MoorAI records them;
// then the fake server's `add` description changes (a rug-pull) and every installed client runs again:
//   (a) `add` is missing from the tool list the client received (cursor-agent / SDK / Inspector print the
//       names; `claude mcp list` does not, so a client-side wire tap records the tools/list it was sent);
//   (b) the SDK's tools/call to `add` comes back as MoorAI's quarantine refusal (MCP_TOOL_DRIFT) and
//       never reaches the server. The Inspector CLI refuses to call a tool missing from its own list, so
//       its call is proven on the documented "list open, call closed" path: a listing that went out
//       before the policy loaded still has `add`, and the Inspector's call to it is refused at the gate;
//   (c) the unchanged `echo` is still listed and still works.
// The clients run with the same isolation as test/mcp-live-client.test.mjs (mcp-gateway/test/live/
// live-clients.mjs): throwaway HOME / project, credentials scrubbed, sandbox-exec on macOS denying writes
// to ~/.claude.json, ~/.claude and ~/.cursor and all non-localhost network. The last test diffs the keys
// of the real ~/.claude.json and the ~/.cursor files before and after.
//
// Falsification: MOORAI_LIVE_BREAK=bypass (clients pointed straight at the fake server) must turn the
// drift assertions red.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import {
  detectClients, stdioTarget, httpTarget, CLIENTS, newCell, entryFor, baselineFor, waitFor, cleanup, readJsonl,
  REAL_HOME, NODE, REPO
} from "../mcp-gateway/test/live/live-clients.mjs";
import { startConsole, approved, ADD, ADD_DESC, ECHO } from "./tool-drift-helpers.mjs";

const OPT_IN = process.env.MOORAI_LIVE_MCP === "1";
const CLIENT_TAP = join(REPO, "mcp-proxy", "test", "live", "client-tap.mjs");
const POLICY = { captureTier: "content-free", mcpToolDrift: "block" };
const QUARANTINE_TEXT = /^MoorAI blocked this MCP tool call: this tool changed since your organization approved this MCP server \(MCP_TOOL_DRIFT: description-drift\)/;
const WATCH = [join(REAL_HOME, ".claude.json"), join(REAL_HOME, ".cursor", "mcp.json"), join(REAL_HOME, ".cursor", "cli-config.json")];
const readJson = (p) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } };
const sha = (p) => { try { return createHash("sha256").update(readFileSync(p)).digest("hex"); } catch { return "(absent)"; } };

// The tools/list result names inside whatever a client received (JSON lines, a JSON body, or SSE data).
function listedNames(texts) {
  const msgs = [];
  for (const t of texts) {
    for (const part of String(t).split("\n")) {
      const s = part.startsWith("data: ") ? part.slice(6) : part;
      if (!s.trim().startsWith("{") && !s.trim().startsWith("[")) continue;
      try { const j = JSON.parse(s); for (const m of Array.isArray(j) ? j : [j]) msgs.push(m); } catch { /* not a message */ }
    }
  }
  const lists = msgs.filter((m) => m && m.result && Array.isArray(m.result.tools));
  return lists.length ? lists[lists.length - 1].result.tools.map((t) => t.name) : null;
}

// An HTTP tap in front of the gateway for `claude mcp list`: forwards every request, records each body sent back.
async function httpTap(targetUrl) {
  const bodies = [];
  const u = new URL(targetUrl);
  const server = http.createServer((req, res) => {
    const up = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: req.method, headers: { ...req.headers, host: u.host } }, (ur) => {
      let body = "";
      ur.setEncoding("utf8");
      res.writeHead(ur.statusCode, ur.headers);
      ur.on("data", (c) => { body += c; res.write(c); });
      ur.on("end", () => { bodies.push(body); res.end(); });
    });
    up.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(up);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}${u.pathname}`, bodies, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

if (!OPT_IN) {
  test("live MCP tool-drift tests", { skip: "opt-in: set MOORAI_LIVE_MCP=1" }, () => {});
} else {
  const scratch = mkdtempSync(join(tmpdir(), "moorai-drift-live-"));
  const clients = await detectClients(scratch);
  const has = (id) => clients.find((c) => c.id === id && c.bin);
  let world, shaBefore, claudeBefore;
  before(async () => {
    shaBefore = WATCH.map(sha);
    claudeBefore = readJson(WATCH[0]);
    world = { scratch, con: await startConsole(POLICY) };
  });
  after(async () => { if (world) await world.con.close(); cleanup(scratch); });

  // One transport, end to end. `setTools(list)` changes what the fake server advertises from the next run.
  async function driftRun(t, setTools, report) {
    const sdk = has("mcp-sdk");
    assert.ok(sdk, "the MCP TypeScript SDK client is required for the baseline run");
    const calls = (n) => t.toolCalls().filter((p) => p && p.name === n).length;

    // Baseline: list + call both tools; MoorAI records them (the call waits for the off-path observation).
    const base = await CLIENTS["mcp-sdk"].run(sdk.bin, newCell(world, "mcp-sdk", t.transport + "-base"), entryFor("mcp-sdk", t), [{ name: "add", arguments: { a: 1, b: 2 } }, { name: "echo", arguments: { m: "before" } }]);
    assert.ok(base.j && base.j.ok, `baseline run failed: ${base.r.stdout}${base.r.stderr}`);
    report.baseline = { tools: base.j.tools, calls: base.j.calls.map((c) => ({ name: c.name, isError: c.isError })) };
    assert.deepEqual(base.j.tools, ["add", "echo"]);
    assert.ok(base.j.calls.every((c) => !c.isError), JSON.stringify(base.j.calls));
    assert.ok(await waitFor(() => baselineFor(t, "add").present && baselineFor(t, "echo").present, 4000), "MoorAI recorded no baseline for add/echo");
    const addCallsBefore = calls("add");

    setTools([ADD_DESC, ECHO]);

    // (a) every installed client: add missing, echo present.
    for (const id of ["mcp-sdk", "mcp-inspector", "cursor-agent", "claude-code"]) {
      const c = has(id);
      if (!c) { report[id] = "not installed"; continue; }
      const cell = newCell(world, id, t.transport);
      let tools, status;
      if (id === "claude-code") {
        if (t.transport === "stdio") {
          const tapLog = join(cell.dir, "client-tap.jsonl");
          const e = t.entry;
          const hs = await CLIENTS[id].handshake(c.bin, cell, "moorai-drift", { command: NODE, args: [CLIENT_TAP, tapLog, "--", e.command, ...e.args], env: e.env });
          status = hs.status;
          tools = listedNames(readJsonl(tapLog).map((m) => JSON.stringify(m)));
          assert.ok(hs.connected && hs.toolsFetched, `claude mcp list: ${hs.status}\n${hs.raw.stdout}\n${hs.raw.stderr}`);
        } else {
          const tap = await httpTap(t.url);
          try {
            const hs = await CLIENTS[id].handshake(c.bin, cell, "moorai-drift", { type: "http", url: tap.url });
            status = hs.status;
            tools = listedNames(tap.bodies);
            assert.ok(hs.connected && hs.toolsFetched, `claude mcp list: ${hs.status}\n${hs.raw.stdout}\n${hs.raw.stderr}`);
          } finally { await tap.close(); }
        }
      } else {
        const hs = await CLIENTS[id].handshake(c.bin, cell, "moorai-drift", entryFor(id, t));
        status = hs.status;
        tools = hs.tools;
        assert.ok(hs.connected, `${id}: ${hs.status}\n${hs.raw && hs.raw.stdout}\n${hs.raw && hs.raw.stderr}`);
      }
      report[id] = { version: c.version, status, tools };
      assert.ok(Array.isArray(tools), `${id}: no tool list captured (${status})`);
      assert.ok(!tools.includes("add"), `(a) ${id} still lists the drifted tool: ${JSON.stringify(tools)}`);
      assert.ok(tools.includes("echo"), `(c) ${id} lost the unchanged tool: ${JSON.stringify(tools)}`);
    }

    // (b) + (c) tools/call. The SDK client sends a call to any name, so its call to `add` reaches MoorAI.
    const sdkCalls = await CLIENTS["mcp-sdk"].toolCalls(sdk.bin, newCell(world, "mcp-sdk", t.transport + "-call"), "moorai-drift", entryFor("mcp-sdk", t), [{ name: "add", arguments: { a: 1, b: 2 } }, { name: "echo", arguments: { m: "after-drift" } }]);
    report["mcp-sdk:calls"] = sdkCalls.results || sdkCalls.error;
    assert.ok(sdkCalls.results, `mcp-sdk could not call tools: ${sdkCalls.error}`);
    const [add, echo] = sdkCalls.results;
    assert.ok(add.isError && QUARANTINE_TEXT.test(add.text), `(b) mcp-sdk: the drifted tool's call was not refused with the quarantine message: ${JSON.stringify(add)}`);
    assert.ok(!echo.isError && echo.text.includes("after-drift"), `(c) mcp-sdk: the unchanged tool no longer works: ${JSON.stringify(echo)}`);
    // The Inspector CLI (2.9.0) looks a tool up in its own tools/list before calling it, so with `add`
    // filtered out it refuses the call itself ("Tool 'add' not found on server.") and sends nothing; its
    // tools/call reaching MoorAI's gate is proven by the "list open, call closed" tests below.
    const insp = has("mcp-inspector");
    if (insp) {
      const ia = await CLIENTS["mcp-inspector"].run(insp.bin, newCell(world, "mcp-inspector", t.transport + "-call"), "moorai-drift", entryFor("mcp-inspector", t), ["--method", "tools/call", "--tool-name", "add", "--tool-arg", "a=1", "b=2"]);
      const ie = await CLIENTS["mcp-inspector"].toolCalls(insp.bin, newCell(world, "mcp-inspector", t.transport + "-call2"), "moorai-drift", entryFor("mcp-inspector", t), [{ name: "echo", arguments: { m: "after-drift" } }]);
      report["mcp-inspector:calls"] = { add: (ia.r.stdout + ia.r.stderr).trim(), echo: ie.results || ie.error };
      assert.match(ia.r.stdout + ia.r.stderr, /Tool 'add' not found on server/, "(b) the Inspector was offered the drifted tool");
      assert.ok(ie.results && !ie.results[0].isError && ie.results[0].text.includes("after-drift"), `(c) mcp-inspector: echo failed: ${JSON.stringify(ie)}`);
    }
    assert.equal(calls("add"), addCallsBefore, "a refused call to the drifted tool reached the server");
    report.serverCalls = t.toolCalls().map((p) => p && p.name);
  }

  test("stdio guard: a drifted tool disappears from real clients' tool lists and its calls are refused; the unchanged tool works", async (tt) => {
    const toolsFile = join(scratch, "stdio-tools.json");
    writeFileSync(toolsFile, JSON.stringify([ADD, ECHO]));
    const t = stdioTarget(world, { host: "unknown", label: "drift-stdio", fakeEnv: { FAKE_TOOLS_FILE: toolsFile } });
    const report = {};
    try { await driftRun(t, (tools) => writeFileSync(toolsFile, JSON.stringify(tools)), report); }
    finally { tt.diagnostic(JSON.stringify(report)); }
    assert.ok(await waitFor(() => world.con.alerts.some((a) => a.mcpServer === "drift-stdio" && a.decision === "quarantine" && a.reasonCode === "MCP_TOOL_DRIFT" && a.tool === "desktop:add"), 3000), "the console got no quarantine alert");
  });

  test("HTTP gateway: a drifted tool disappears from real clients' tool lists and its calls are refused; the unchanged tool works", async (tt) => {
    const upstream = { tools: [ADD, ECHO] };
    const t = await httpTarget(world, { label: "drift-http", route: "/drift", upstream, gatewayArgs: [] });
    const report = {};
    try { await driftRun(t, (tools) => { upstream.tools = tools; }, report); }
    finally { tt.diagnostic(JSON.stringify(report)); await t.stop(); }
    assert.ok(world.con.alerts.some((a) => a.mcpServer === "drift-http" && a.decision === "quarantine" && a.reasonCode === "MCP_TOOL_DRIFT"), "the console got no quarantine alert");
  });

  // "List open, call closed" with the Inspector: the device's policy is held back until the Inspector has
  // received its tools/list, so that listing goes out unjudged and `add` (drifted from the APPROVED
  // baseline in the policy) is in it. The Inspector then calls `add`, and the call — which waits for the
  // policy — is refused with the quarantine message. Later Inspector runs (policy now loaded) list only
  // `echo` and call it.
  async function listOpenCallClosed(transport, tt) {
    const insp = has("mcp-inspector");
    if (!insp) return tt.skip("mcp-inspector is not installed");
    const label = `drift-insp-${transport}`;
    const con = await startConsole({ ...POLICY, mcpToolBaselines: approved(label, 1, [ADD, ECHO]) }, { hold: true });
    const w = { scratch, con };
    const report = {};
    let t, tap, poll;
    try {
      let entry, listed;
      const cell = newCell(w, "mcp-inspector", transport + "-loc");
      if (transport === "stdio") {
        const toolsFile = join(cell.dir, "tools.json");
        writeFileSync(toolsFile, JSON.stringify([ADD_DESC, ECHO]));
        t = stdioTarget(w, { host: "unknown", label, fakeEnv: { FAKE_TOOLS_FILE: toolsFile } });
        const tapLog = join(cell.dir, "client-tap.jsonl");
        entry = { command: NODE, args: [CLIENT_TAP, tapLog, "--", t.entry.command, ...t.entry.args], env: t.entry.env };
        listed = () => listedNames(readJsonl(tapLog).map((m) => JSON.stringify(m)));
      } else {
        t = await httpTarget(w, { label, route: "/insp", upstream: { tools: [ADD_DESC, ECHO] } });
        tap = await httpTap(t.url);
        entry = { type: "http", url: tap.url };
        listed = () => listedNames(tap.bodies);
      }
      poll = setInterval(() => { const n = listed(); if (n) { report.listedBeforePolicy = n; con.release(); clearInterval(poll); } }, 5);
      const first = await CLIENTS["mcp-inspector"].run(insp.bin, cell, "moorai-drift", entry, ["--method", "tools/call", "--tool-name", "add", "--tool-arg", "a=1", "b=2"]);
      report.add = first.j || (first.r.stdout + first.r.stderr);
      const second = await CLIENTS["mcp-inspector"].toolCalls(insp.bin, newCell(w, "mcp-inspector", transport + "-loc2"), "moorai-drift", t.entry, [{ name: "echo", arguments: { m: "after-policy" } }]);
      const third = await CLIENTS["mcp-inspector"].handshake(insp.bin, newCell(w, "mcp-inspector", transport + "-loc3"), "moorai-drift", t.entry);
      report.echo = second.results || second.error;
      report.listAfterPolicy = third.tools;
      assert.ok(report.listedBeforePolicy && report.listedBeforePolicy.includes("add"), `the Inspector's first listing was already filtered: ${JSON.stringify(report.listedBeforePolicy)}`);
      const text = first.j && Array.isArray(first.j.content) ? first.j.content.map((x) => x.text || "").join("") : "";
      assert.ok(first.j && first.j.isError === true && QUARANTINE_TEXT.test(text), `(b) the Inspector's call to the drifted tool was not refused with the quarantine message: ${JSON.stringify(report.add)}`);
      assert.ok(second.results && !second.results[0].isError && second.results[0].text.includes("after-policy"), `(c) echo: ${JSON.stringify(second)}`);
      assert.deepEqual(third.tools, ["echo"], "(a) once the policy is loaded the drifted tool is filtered");
      assert.deepEqual(t.toolCalls().map((p) => p && p.name), ["echo"], "the refused call reached the server");
    } finally {
      clearInterval(poll);
      tt.diagnostic(JSON.stringify(report));
      if (tap) await tap.close();
      if (t) await t.stop();
      con.release();
      await con.close();
    }
  }
  test("stdio guard + Inspector: a tool listed before the policy arrived is refused at tools/call with the quarantine message", (tt) => listOpenCallClosed("stdio", tt));
  test("HTTP gateway + Inspector: a tool listed before the policy arrived is refused at tools/call with the quarantine message", (tt) => listOpenCallClosed("http", tt));

  // Same check as test/mcp-live-client.test.mjs, plus a top-level key diff of ~/.claude.json.
  test("the developer's own client config is untouched by the run", (tt) => {
    const shaAfter = WATCH.map(sha);
    assert.deepEqual(shaAfter.slice(1), shaBefore.slice(1), WATCH.slice(1).join(", "));
    const cj = readJson(WATCH[0]);
    const kb = Object.keys(claudeBefore || {}), ka = Object.keys(cj || {});
    const diff = { added: ka.filter((k) => !kb.includes(k)), removed: kb.filter((k) => !ka.includes(k)) };
    tt.diagnostic(`~/.claude.json top-level key diff: ${JSON.stringify(diff)}`);
    assert.deepEqual(diff, { added: [], removed: [] }, "top-level keys of ~/.claude.json changed during the run");
    if (cj) {
      assert.deepEqual(cj.mcpServers || {}, (claudeBefore && claudeBefore.mcpServers) || {}, "user-scope mcpServers in ~/.claude.json changed");
      const had = new Set(Object.keys((claudeBefore && claudeBefore.projects) || {}));
      const leaked = Object.keys(cj.projects || {}).filter((k) => !had.has(k) && (k.includes("moorai-drift-live-") || k.startsWith(tmpdir()) || k.startsWith("/private" + tmpdir())));
      assert.deepEqual(leaked, [], "a scratch project was recorded in ~/.claude.json");
    }
  });
}
