#!/usr/bin/env node
// Real MCP client × MoorAI transport matrix — NO model call, NO network beyond localhost.
//
//   node scripts/mcp-client-matrix.mjs [--json]
//
// For every installed client (Claude Code `claude`, `cursor-agent`; narrow with MOORAI_LIVE_CLIENTS)
// and every MoorAI MCP piece (the stdio guard, the HTTP gateway), the client is configured — in a
// throwaway HOME / project, sandboxed on macOS — to reach the fake MCP server THROUGH MoorAI, and its
// own MCP health-check / tool-listing subcommand is run. A third column points the client at a gateway
// whose method allow-list refuses tools/list, the one handshake-time refusal a client can observe.
// See mcp-gateway/test/live/live-clients.mjs for what each client subcommand was measured to do.
//
// A cell passes when: the client reports a connection with tools fetched; the server behind MoorAI
// received the client's own initialize (clientInfo) and tools/list; and MoorAI recorded the tools/list
// it relayed (its tool-stage baseline entry for `echo` under that route's label). The refused cell
// passes when the client reports the tools fetch failed with MoorAI's refusal, the upstream never saw a
// tools/list, and the stand-in console received MoorAI's deny alert. Exit 1 if any cell fails.
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  detectClients, startWorld, stdioTarget, httpTarget, runCell, runToolCallCell, judgeToolCall, cleanup, waitFor,
  REAL_HOME, SANDBOX, BREAK, REFUSED_LABEL, CLIENTS
} from "../mcp-gateway/test/live/live-clients.mjs";

const JSON_OUT = process.argv.includes("--json");
const sha = (p) => { try { return createHash("sha256").update(readFileSync(p)).digest("hex"); } catch { return "(absent)"; } };
const WATCH = [join(REAL_HOME, ".claude.json"), join(REAL_HOME, ".cursor", "mcp.json"), join(REAL_HOME, ".cursor", "cli-config.json")];

export const HOST_STAMP = { "claude-code": "claude-code", "cursor-agent": "cursor" };

export function judgeOk(r) {
  const why = [];
  if (!r.connected) why.push("client did not connect");
  if (!r.toolsFetched) why.push("client did not fetch tools");
  if (!r.serverSawInitialize) why.push("server never saw initialize");
  if (!r.clientInfo) why.push("no clientInfo reached the server");
  if (!r.serverSawToolsList) why.push("server never saw tools/list");
  if (!r.baseline.present) why.push("MoorAI recorded no tool-stage baseline for echo");
  else if (!r.baseline.labelMatches) why.push("baseline entry is under another server label");
  if (r.tools && !r.tools.includes("echo")) why.push("client's tool list lacks echo");
  return why;
}

export const REFUSAL_TEXT = /MoorAI (?:refused|\[redacted\]) this MCP message: this MCP message failed validation \(method at \$\.method\)/;

export function judgeRefused(r, alerts) {
  const why = [];
  if (r.toolsFetched) why.push("client fetched tools — nothing was refused");
  // Claude Code 2.1.284 prints this as "MoorAI [redacted] this MCP message: …" — it masks the word
  // "refused" in a server's tools/list error — so the stable part is matched, not that word.
  if (!REFUSAL_TEXT.test([r.status, r.raw && r.raw.stdout, r.raw && r.raw.stderr].join("\n"))) why.push("client output does not carry MoorAI's refusal");
  if (r.serverSawToolsList) why.push("upstream received tools/list");
  if (!r.serverSawInitialize) why.push("upstream never saw initialize (handshake did not get that far)");
  const a = alerts.find((x) => x.category === "MCP gateway: invalid message" && x.decision === "deny" && x.schemaStage === "method" && x.mcpServer === REFUSED_LABEL);
  if (!a) why.push("console received no MoorAI deny alert for the refused method");
  return why;
}

export async function runMatrix({ log = () => {} } = {}) {
  const scratch = mkdtempSync(join(tmpdir(), "moorai-mcp-matrix-"));
  const before = WATCH.map(sha);
  const world = await startWorld(scratch);
  const rows = [];
  let clients = [];
  try {
    clients = await detectClients(scratch);
    for (const c of clients) {
      if (!c.bin) { rows.push({ client: c.id, version: null, transport: "-", skipped: "not installed" }); continue; }
      const s = stdioTarget(world, { host: HOST_STAMP[c.id] });
      const rs = await runCell(world, c, s, "moorai-stdio");
      rows.push({ ...rs, kind: "ok", fail: judgeOk(rs) });
      log(`${c.id} stdio: ${rs.status}`);

      const h = await httpTarget(world);
      try {
        const rh = await runCell(world, c, h, "moorai-http");
        rows.push({ ...rh, kind: "ok", fail: judgeOk(rh) });
        log(`${c.id} http: ${rh.status}`);
      } finally { await h.stop(); }

      const n0 = world.con.alerts.length;
      const x = await httpTarget(world, { label: REFUSED_LABEL, route: "/refused", gatewayArgs: BREAK === "no-refusal" ? [] : ["--allow-method", "initialize"] });
      try {
        const rx = await runCell(world, c, x, "moorai-refused");
        const mine = () => world.con.alerts.slice(n0);
        await waitFor(() => mine().some((a) => a.mcpServer === REFUSED_LABEL), 3000);
        rows.push({ ...rx, transport: "http (refused)", kind: "refused", alerts: mine(), fail: judgeRefused(rx, mine()) });
        log(`${c.id} http-refused: ${rx.status}`);
      } finally { await x.stop(); }

      // No-model tool calls, for clients that can make one themselves.
      if (CLIENTS[c.id].toolCalls) {
        const ts = stdioTarget(world, { host: HOST_STAMP[c.id] });
        const cs = await runToolCallCell(world, c, ts, "moorai-stdio");
        rows.push({ ...cs, transport: "stdio tools/call", kind: "call", fail: judgeToolCall(cs) });
        const th = await httpTarget(world);
        try {
          const ch = await runToolCallCell(world, c, th, "moorai-http");
          rows.push({ ...ch, transport: "http tools/call", kind: "call", fail: judgeToolCall(ch) });
        } finally { await th.stop(); }
      }
    }
  } finally {
    await world.close();
  }
  const after = WATCH.map(sha);
  const userConfig = WATCH.map((p, i) => ({ path: p, before: before[i], after: after[i], unchanged: before[i] === after[i] }));
  if (!process.env.MOORAI_LIVE_KEEP) cleanup(scratch);
  return { rows, clients, userConfig, sandbox: SANDBOX, break: BREAK || null, scratch };
}

function cellText(r) {
  if (r.skipped) return { hs: "skip", tools: "-", moor: "-", res: r.skipped };
  if (r.kind === "call") {
    const [b, d] = r.results || [];
    return {
      hs: r.results ? "ok" : "FAILED",
      tools: `echo:${b && !b.isError ? "ok" : "bad"} BLOCKME:${d && d.isError ? "refused" : "NOT refused"}`,
      moor: `usage=${r.usage} ledger=${r.ledger.join("/")} alerts=${r.alerts.filter((a) => a.riskLevel === "Blocked").length} server-got-BLOCKME=${r.serverGotDenied}`,
      res: r.fail.length ? "FAIL: " + r.fail.join("; ") : "PASS"
    };
  }
  if (r.kind === "refused") {
    const a = (r.alerts || []).find((x) => x.mcpServer === REFUSED_LABEL);
    return {
      hs: r.serverSawInitialize ? "init ok" : "no init",
      tools: r.toolsFetched ? "FETCHED" : "refused",
      moor: a ? `alert ${a.reasonCode || a.category}/${a.schemaStage}/${a.decision}` : "no alert",
      res: r.fail.length ? "FAIL: " + r.fail.join("; ") : "PASS"
    };
  }
  return {
    hs: r.connected ? "ok" : "FAILED",
    tools: r.tools ? r.tools.join(",") || "(none)" : r.toolsFetched ? "fetched (names not printed)" : "not fetched",
    moor: [r.serverSawToolsList ? "server saw tools/list" : "no tools/list", r.baseline.present && r.baseline.labelMatches ? `baseline[echo@${r.label}]` : "no baseline"].join(", "),
    res: r.fail.length ? "FAIL: " + r.fail.join("; ") : "PASS"
  };
}

export function formatMatrix(out) {
  const head = ["client", "version", "transport", "handshake", "tools via MoorAI", "MoorAI side-effects", "client said", "result"];
  const body = out.rows.map((r) => {
    const t = cellText(r);
    const said = r.kind === "call" ? (r.results ? (r.results[1] || {}).text || "-" : r.error || "-") : r.status || "-";
    return [r.client, r.version || "-", r.transport, t.hs, t.tools, t.moor, said.replace(/\s+/g, " ").slice(0, 70), t.res];
  });
  const w = head.map((h, i) => Math.max(h.length, ...body.map((b) => String(b[i]).length)));
  const fmt = (cols) => cols.map((c, i) => String(c).padEnd(w[i])).join(" | ");
  const lines = [fmt(head), w.map((n) => "-".repeat(n)).join("-+-"), ...body.map(fmt)];
  lines.push("");
  for (const r of out.rows) if (r.clientInfo) lines.push(`clientInfo seen behind MoorAI (${r.client}, ${r.transport}): ${JSON.stringify({ name: r.clientInfo.name, version: r.clientInfo.version })}`);
  lines.push(`sandbox-exec: ${out.sandbox ? "on (writes to ~/.claude.json, ~/.claude, ~/.cursor and non-localhost egress denied)" : "off"}${out.break ? `   MOORAI_LIVE_BREAK=${out.break}` : ""}`);
  for (const u of out.userConfig) lines.push(`user config ${u.path}: ${u.unchanged ? "unchanged" : "CHANGED"} sha256 ${u.before.slice(0, 16)}… → ${u.after.slice(0, 16)}…`);
  return lines.join("\n");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const out = await runMatrix({ log: (s) => process.stderr.write(`  ${s}\n`) });
  if (JSON_OUT) process.stdout.write(JSON.stringify(out.rows.map(({ raw, cell, ...r }) => r), null, 2) + "\n");
  else process.stdout.write(formatMatrix(out) + "\n");
  const ran = out.rows.filter((r) => !r.skipped);
  const failed = ran.filter((r) => r.fail.length);
  if (!ran.length) { process.stderr.write("no MCP client installed — nothing ran\n"); process.exit(0); }
  process.exit(failed.length ? 1 : 0);
}
