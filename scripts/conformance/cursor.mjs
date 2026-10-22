// Cursor (cursor-agent CLI) driver for the live host-conformance tier.
//
// What can run without an account, measured on cursor-agent 2026.05.27-fe9a6e2:
//   * an agent turn cannot: `cursor-agent -p` in an empty HOME exits 1 with "Authentication required"
//     (login or CURSOR_API_KEY). The `--base-url` local-model flag exists in the bundle but this build
//     refuses it ("can only be used with agent-cli-local", a separate build). Both probes are recorded as
//     booleans and the agent-turn case is a skip with reason auth-required. No login is attempted.
//   * the MCP client side can: `cursor-agent mcp enable` + `mcp list-tools` run the full MCP handshake
//     with no account. The server is MoorAI's stdio guard wrapping the fake MCP server, so the case passes
//     when Cursor listed the tool THROUGH MoorAI and MoorAI recorded the tools/list it relayed.
//   * the hook events and version fields the adapter relies on are still in the installed bundle (static).
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startStandInConsole } from "./stand-in-console.mjs";
import { CLAUDE_POLICY } from "./claude-code.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE_MCP = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
export const CURSOR_MCP_LABEL = "moorai-stdio";

export const AUTH_REQUIRED_RE = /Authentication required/i;
export const LOCAL_BUILD_ONLY_RE = /can only be used with agent-cli-local/i;

export function judgeAgentTurnProbe({ authOut = "", baseUrlOut = "" }) {
  const authRequired = AUTH_REQUIRED_RE.test(authOut);
  const localModeRefused = LOCAL_BUILD_ONLY_RE.test(baseUrlOut);
  return {
    case: { id: "agent-turn", surface: "agent-turn", expect: "deny", observed: "none", status: "skip", checks: { authRequired, localModeRefused }, alert: null },
    reason: authRequired ? "auth-required" : localModeRefused ? "separate-build-required" : "unspecified"
  };
}

export function judgeMcpHandshake(hs, { baselinePresent, serverSawToolsList }) {
  const listed = !!(hs.tools && hs.tools.includes("echo"));
  const pass = !!hs.connected && !!hs.toolsFetched && listed && baselinePresent && serverSawToolsList;
  return { id: "mcp-handshake-stdio", surface: "mcp-handshake", expect: "handshake", observed: hs.connected ? "handshake" : "none", status: pass ? "pass" : "fail", checks: { connected: !!hs.connected, toolsFetched: !!hs.toolsFetched, toolListed: listed, moorAIRecordedList: !!baselinePresent, serverSawToolsList: !!serverSawToolsList }, alert: null };
}

export function readBundle(bin) {
  let dir;
  try { dir = dirname(realpathSync(bin)); } catch { return ""; }
  let text = "";
  try { for (const f of readdirSync(dir)) if (f.endsWith(".js")) { try { text += readFileSync(join(dir, f), "utf8"); } catch { /* skip */ } } } catch { /* none */ }
  return text;
}

// ctx: { bin, scratch, live (mcp-gateway/test/live/live-clients.mjs module), checkCursorBundle }
export async function runCursor(ctx) {
  const { runClient, clientEnv, CLIENTS, baselineFor } = ctx.live;
  const cases = [];
  const probeHome = mkdtempSync(join(ctx.scratch, "cursor-probe-"));
  const env = clientEnv(probeHome);
  const auth = await runClient(ctx.bin, ["-p", "MoorAI conformance probe"], { cwd: probeHome, env, timeoutMs: 60000 });
  const local = await runClient(ctx.bin, ["-p", "MoorAI conformance probe", "--base-url", "http://127.0.0.1:9/v1"], { cwd: probeHome, env, timeoutMs: 60000 });
  const turn = judgeAgentTurnProbe({ authOut: auth.stdout + auth.stderr, baseUrlOut: local.stdout + local.stderr });
  cases.push(turn.case);

  const con = await startStandInConsole({ policy: CLAUDE_POLICY });
  try {
    const gHome = mkdtempSync(join(ctx.scratch, "cursor-guard-"));
    mkdirSync(join(gHome, ".moorai"), { recursive: true });
    writeFileSync(join(gHome, ".moorai", "config.json"), JSON.stringify({ serverUrl: con.url, tenant: con.tenant, installToken: "conformance" }), { mode: 0o600 });
    const wireDir = mkdtempSync(join(ctx.scratch, "cursor-wire-"));
    const calls = join(wireDir, "calls.jsonl");
    const entry = { command: process.execPath, args: [GUARD, "--server", CURSOR_MCP_LABEL, "--host", "cursor", "--", process.execPath, FAKE_MCP, calls], env: { HOME: gHome, USERPROFILE: gHome, XDG_CONFIG_HOME: join(gHome, ".config"), XDG_STATE_HOME: join(gHome, ".local", "state") } };
    const cellDir = mkdtempSync(join(ctx.scratch, "cursor-cell-"));
    const cell = { dir: cellDir, home: join(cellDir, "home"), proj: join(cellDir, "proj") };
    mkdirSync(cell.home, { recursive: true });
    mkdirSync(cell.proj, { recursive: true });
    const started = Date.now();
    const hs = await CLIENTS["cursor-agent"].handshake(ctx.bin, cell, CURSOR_MCP_LABEL, entry);
    const b = baselineFor({ home: gHome, label: CURSOR_MCP_LABEL });
    // The guard records the tools/list it relayed in its tool-stage baseline; the fake server itself
    // logs only tools/call, so "the server saw tools/list" is read from MoorAI's relay record.
    cases.push({ ...judgeMcpHandshake(hs, { baselinePresent: b.present && b.labelMatches, serverSawToolsList: b.present }), latencyMs: Date.now() - started });
  } finally { await con.close(); }

  const markers = ctx.checkCursorBundle(readBundle(ctx.bin));
  cases.push({ id: "bundle-markers", surface: "static", expect: "none", observed: "none", status: markers.length ? "fail" : "pass", checks: { hookEventsPresent: markers.length === 0 }, alert: null });
  return { cases, reason: turn.reason };
}
