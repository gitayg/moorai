// Opt-in: real MCP client applications (Claude Code, cursor-agent, the official MCP TypeScript SDK client,
// the MCP Inspector CLI) complete the MCP handshake THROUGH MoorAI's stdio guard and HTTP gateway; the
// SDK and Inspector also make a benign and a policy-denied tools/call. No model call, no network beyond
// localhost.
//
//   MOORAI_LIVE_MCP=1 node --test --import ./test/hermetic-env.mjs test/mcp-live-client.test.mjs
//
// Without MOORAI_LIVE_MCP=1 every test here is skipped (the default unit run must not spawn installed
// client apps); with it, a client whose binary is not on PATH is skipped. The clients run in a
// throwaway HOME / project with their credentials scrubbed, sandboxed on macOS so they cannot write the
// real ~/.claude.json, ~/.claude or ~/.cursor — see mcp-gateway/test/live/live-clients.mjs.
//
// Falsification: MOORAI_LIVE_BREAK=bypass | dead | toolscan | no-refusal | no-policy | list-error must each
// turn this file red.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectClients, startWorld, stdioTarget, httpTarget, runCell, runToolCallCell, judgeToolCall, cleanup, waitFor,
  REAL_HOME, REFUSED_LABEL, BREAK, CLIENTS
} from "../mcp-gateway/test/live/live-clients.mjs";
import { judgeOk, judgeRefused, HOST_STAMP } from "../scripts/mcp-client-matrix.mjs";

const OPT_IN = process.env.MOORAI_LIVE_MCP === "1";
const EXPECT_CLIENT_NAME = { "claude-code": "claude-code", "cursor-agent": "Cursor", "mcp-sdk": "moorai-live-sdk-client", "mcp-inspector": "inspector-cli" };
const WATCH = [join(REAL_HOME, ".claude.json"), join(REAL_HOME, ".cursor", "mcp.json"), join(REAL_HOME, ".cursor", "cli-config.json")];
const readJson = (p) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } };
const sha = (p) => { try { return createHash("sha256").update(readFileSync(p)).digest("hex"); } catch { return "(absent)"; } };

if (!OPT_IN) {
  test("live MCP client tests", { skip: "opt-in: set MOORAI_LIVE_MCP=1" }, () => {});
} else {
  const scratch = mkdtempSync(join(tmpdir(), "moorai-mcp-live-"));
  const clients = await detectClients(scratch);
  let world;
  let shaBefore, claudeJsonBefore;
  before(async () => { shaBefore = WATCH.map(sha); claudeJsonBefore = readJson(WATCH[0]); world = await startWorld(scratch); });
  after(async () => { if (world) await world.close(); cleanup(scratch); });

  for (const c of clients) {
    const skip = c.bin ? false : `${c.id} is not installed`;
    const show = (r) => `client said: ${r.status}\nstdout: ${r.raw && r.raw.stdout}\nstderr: ${r.raw && r.raw.stderr}`;

    test(`${c.id}: handshake + tools/list through the MoorAI stdio guard`, { skip }, async () => {
      const t = stdioTarget(world, { host: HOST_STAMP[c.id] });
      const r = await runCell(world, c, t, "moorai-stdio");
      assert.deepEqual(judgeOk(r), [], show(r));
      assert.equal(r.clientInfo.name, EXPECT_CLIENT_NAME[c.id], "the initialize behind the guard came from this client");
    });

    test(`${c.id}: handshake + tools/list through the MoorAI HTTP gateway`, { skip }, async () => {
      const t = await httpTarget(world);
      try {
        const r = await runCell(world, c, t, "moorai-http");
        assert.deepEqual(judgeOk(r), [], show(r));
        assert.equal(r.clientInfo.name, EXPECT_CLIENT_NAME[c.id], "the initialize behind the gateway came from this client");
      } finally { await t.stop(); }
    });

    test(`${c.id}: a gateway method allow-list refusal reaches the client and the console`, { skip }, async () => {
      const n0 = world.con.alerts.length;
      const t = await httpTarget(world, { label: REFUSED_LABEL, route: "/refused", gatewayArgs: BREAK === "no-refusal" ? [] : ["--allow-method", "initialize"] });
      try {
        const r = await runCell(world, c, t, "moorai-refused");
        const mine = () => world.con.alerts.slice(n0);
        await waitFor(() => mine().some((a) => a.mcpServer === REFUSED_LABEL), 3000);
        assert.deepEqual(judgeRefused(r, mine()), [], show(r));
      } finally { await t.stop(); }
    });

    if (CLIENTS[c.id].toolCalls) {
      const showCall = (r) => `results: ${JSON.stringify(r.results)}\nerror: ${r.error}`;
      test(`${c.id}: tools/call through the stdio guard — benign forwarded, policy-denied refused, both recorded`, { skip }, async () => {
        const r = await runToolCallCell(world, c, stdioTarget(world, { host: HOST_STAMP[c.id] }), "moorai-stdio");
        assert.deepEqual(judgeToolCall(r), [], showCall(r));
      });
      test(`${c.id}: tools/call through the HTTP gateway — benign forwarded, policy-denied refused, both recorded`, { skip }, async () => {
        const t = await httpTarget(world);
        try {
          const r = await runToolCallCell(world, c, t, "moorai-http");
          assert.deepEqual(judgeToolCall(r), [], showCall(r));
        } finally { await t.stop(); }
      });
    }
  }

  // ~/.claude.json is rewritten all the time by whatever Claude Code session is running on this machine,
  // so a raw checksum would flake on writes that are not ours. What a leak from this run would look like
  // is asserted instead: a change to its user-scope mcpServers, or a projects[] entry for a scratch path.
  // The ~/.cursor files have no such concurrent writer and are compared byte for byte.
  test("the developer's own client config is untouched by the run", async () => {
    const shaAfter = WATCH.map(sha);
    assert.deepEqual(shaAfter.slice(1), shaBefore.slice(1), WATCH.slice(1).join(", "));
    const cj = readJson(WATCH[0]);
    if (cj) {
      assert.deepEqual(cj.mcpServers || {}, (claudeJsonBefore && claudeJsonBefore.mcpServers) || {}, "user-scope mcpServers in ~/.claude.json changed");
      const had = new Set(Object.keys((claudeJsonBefore && claudeJsonBefore.projects) || {}));
      const leaked = Object.keys(cj.projects || {}).filter((k) => !had.has(k) && (k.includes("moorai-mcp-live-") || k.startsWith(tmpdir()) || k.startsWith("/private" + tmpdir())));
      assert.deepEqual(leaked, [], "a scratch project was recorded in ~/.claude.json");
    }
  });
}
