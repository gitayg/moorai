#!/usr/bin/env node
// The LIVE tool-call tier: a real model, through Claude Code, calls a tool on the fake MCP server THROUGH
// MoorAI. This spends model usage, so it does nothing unless asked:
//
//   node scripts/mcp-live-toolcall.mjs                 print the plan (exact commands, cost drivers), run nothing
//   node scripts/mcp-live-toolcall.mjs --run           run all three cases (3 `claude -p` turns)
//   node scripts/mcp-live-toolcall.mjs --run --only stdio-denied     run a subset
//
// Cases (one `claude -p` each):
//   stdio-benign   echo {"m":"hello-moorai"} via the stdio guard     → forwarded, echoed, recorded (allow)
//   http-benign    echo {"m":"hello-moorai"} via the HTTP gateway    → forwarded, echoed, recorded (allow)
//   stdio-denied   echo {"m":"BLOCKME"} via the stdio guard          → MoorAI refuses (policy deny rule)
//
// Claude Code runs with the user's NORMAL auth and config dir (that is the point: the real client, as
// installed). MCP servers are passed ONLY with --mcp-config <tempfile> --strict-mcp-config; nothing is
// added to ~/.claude.json or ~/.claude. The one tool is allowed with --allowedTools (no bypass mode).
// Claude Code's own state writes to ~/.claude.json are expected; the script prints the before/after
// key diff so an mcpServers / settings change would be visible. Any MoorAI hook installed on the machine
// will also fire on the tool use — that is the machine's own config, reported, not controlled here.
//
// The MoorAI side (guard / gateway processes, their policy console, their state) is all throwaway and
// local, exactly as in scripts/mcp-client-matrix.mjs.
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  startWorld, stdioTarget, httpTarget, usageCount, ledgerCalls, waitFor, which, REAL_HOME, POLICY
} from "../mcp-gateway/test/live/live-clients.mjs";

export const MODEL = process.env.MOORAI_LIVE_MODEL || "haiku";
export const MAX_BUDGET_USD = process.env.MOORAI_LIVE_MAX_BUDGET_USD || "0.50";
export const CASES = {
  "stdio-benign": { transport: "stdio", server: "moorai-stdio", args: { m: "hello-moorai" }, expect: "allow" },
  "http-benign": { transport: "http", server: "moorai-http", args: { m: "hello-moorai" }, expect: "allow" },
  "stdio-denied": { transport: "stdio", server: "moorai-stdio", args: { m: "BLOCKME" }, expect: "deny" }
};
export const promptFor = (c) =>
  `Call the tool mcp__${c.server}__echo exactly once with the arguments ${JSON.stringify(c.args)}. ` +
  "Do not call any other tool and do not retry. Then reply with the single word DONE.";

export function claudeArgs(c, mcpConfigPath) {
  return [
    "-p", promptFor(c),
    "--mcp-config", mcpConfigPath, "--strict-mcp-config",
    "--allowedTools", `mcp__${c.server}__echo`,
    "--output-format", "stream-json", "--verbose",
    "--model", MODEL, "--max-turns", "3", "--max-budget-usd", MAX_BUDGET_USD,
    "--no-session-persistence"
  ];
}

// The parent session's own coupling (when this is launched from inside Claude Code / the desktop app):
// removed so the child is a plain standalone `claude` using the user's normal stored login.
const SESSION_VARS = ["CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_HOST_SESSION_ID", "CLAUDE_CODE_MESSAGING_SOCKET",
  "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_CHILD_SESSION", "CLAUDE_CODE_SESSION_ATTENDED", "CLAUDE_PID", "CLAUDE_CODE_ENTRYPOINT",
  "CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH", "CLAUDE_AGENT_SDK_VERSION", "CLAUDE_CODE_DESKTOP_APP_VERSION", "CLAUDE_CODE_EXECPATH"];
function childEnv() {
  const env = { ...process.env };
  for (const k of SESSION_VARS) delete env[k];
  return env;
}

function readClaudeJson() { try { return JSON.parse(readFileSync(join(REAL_HOME, ".claude.json"), "utf8")); } catch { return null; } }
export function keyDiff(a, b) {
  const out = { added: [], removed: [], changed: [] };
  const ka = Object.keys(a || {}), kb = Object.keys(b || {});
  for (const k of kb) if (!ka.includes(k)) out.added.push(k);
  for (const k of ka) if (!kb.includes(k)) out.removed.push(k);
  for (const k of ka) if (kb.includes(k) && JSON.stringify(a[k]) !== JSON.stringify(b[k])) out.changed.push(k);
  return out;
}

function runClaude(bin, args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { cwd, env: childEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (c) => { stdout += c; });
    child.stderr.on("data", (c) => { stderr += c; });
    const t = setTimeout(() => child.kill("SIGKILL"), 180000);
    child.on("close", (code) => { clearTimeout(t); resolve({ code, stdout, stderr }); });
  });
}

// stream-json → the mcp tool_use / tool_result blocks and the final result event.
export function parseStream(stdout) {
  const ev = stdout.split("\n").filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const uses = [], results = [];
  for (const e of ev) {
    const content = e.message && Array.isArray(e.message.content) ? e.message.content : [];
    for (const b of content) {
      if (b.type === "tool_use") uses.push({ id: b.id, name: b.name, input: b.input });
      if (b.type === "tool_result") results.push({ tool_use_id: b.tool_use_id, is_error: !!b.is_error, content: b.content });
    }
  }
  const init = ev.find((e) => e.type === "system" && e.subtype === "init");
  const result = ev.find((e) => e.type === "result");
  return { uses, results, init, result };
}
const textOf = (c) => (typeof c === "string" ? c : Array.isArray(c) ? c.map((x) => x.text || "").join("") : JSON.stringify(c));

export function judge(c, p, moor) {
  const why = [];
  const use = p.uses.find((u) => u.name === `mcp__${c.server}__echo`);
  if (!use) why.push("model made no mcp echo tool_use");
  const res = use && p.results.find((r) => r.tool_use_id === use.id);
  if (use && !res) why.push("no tool_result for the echo call");
  // ToolSearch is Claude Code loading the deferred MCP tool's schema before the call (measured on 2.1.284:
  // every run did select:mcp__<server>__echo first). It has no side effect and is not a tool on the server.
  const others = p.uses.filter((u) => u !== use && u.name !== "ToolSearch");
  if (others.length) why.push(`other tool uses: ${others.map((u) => u.name).join(",")}`);
  if (c.expect === "allow") {
    if (res && (res.is_error || !textOf(res.content).includes("hello-moorai"))) why.push("tool_result is not the echo");
    if (!moor.serverGot) why.push("server never received the call");
    if (moor.usage < 1) why.push("MoorAI usage tally did not count the call");
    if (!moor.ledger.includes("allow")) why.push("MoorAI ledger has no allow for the call");
  } else {
    if (res && !(res.is_error && /MoorAI blocked this MCP tool call/.test(textOf(res.content)))) why.push("tool_result is not MoorAI's refusal");
    if (moor.serverGot) why.push("DENIED CALL REACHED THE SERVER");
    if (!moor.ledger.includes("deny")) why.push("MoorAI ledger has no deny for the call");
    if (!moor.blockedAlert) why.push("console got no Blocked alert");
  }
  return why;
}

export function plan(bin) {
  const lines = [
    "Live tool-call tier — NOT run without --run.",
    `client: ${bin || "claude (not on PATH)"}   model: ${MODEL}   per-run budget cap: --max-budget-usd ${MAX_BUDGET_USD}   --max-turns 3`,
    `MoorAI policy served to the guard/gateway: ${JSON.stringify(POLICY)}`,
    ""
  ];
  for (const [id, c] of Object.entries(CASES)) {
    lines.push(`[${id}] (${c.transport}) expect ${c.expect}`);
    lines.push(`  claude ${claudeArgs(c, "<tmp>/mcp-config.json").map((a) => (/[\s{}"]/.test(a) ? `'${a.replace(/'/g, "'\\''")}'` : a)).join(" ")}`);
  }
  lines.push(
    "",
    "Cost drivers per run: Claude Code's system prompt + tool definitions as input tokens (the bulk; prompt",
    "caching applies across the runs), 2 model turns (tool_use, then DONE), a few dozen output tokens. The",
    "budget cap and --max-turns bound a misbehaving run. With a claude.ai subscription login this draws on",
    "the plan's usage rather than per-token billing; with an API key it is billed per token.",
    "3 runs total; no retry loop."
  );
  return lines.join("\n");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  // --rejudge <scratch>: re-apply judge() to the stream.jsonl + case.json a previous --run saved (no model
  // call). MOORAI_LIVE_REJUDGE_MUTATE=<field>=<json> overrides one MoorAI observation, for falsification.
  const rj = process.argv.indexOf("--rejudge");
  if (rj > 0) {
    const { readdirSync } = await import("node:fs");
    const root = process.argv[rj + 1];
    let bad = 0;
    for (const d of readdirSync(root).filter((x) => x.startsWith("proj-")).sort()) {
      let cs;
      try { cs = JSON.parse(readFileSync(join(root, d, "case.json"), "utf8")); } catch { continue; }
      const m = process.env.MOORAI_LIVE_REJUDGE_MUTATE;
      if (m) { const i = m.indexOf("="); cs.moor[m.slice(0, i)] = JSON.parse(m.slice(i + 1)); }
      const why = judge(CASES[cs.id], parseStream(readFileSync(join(root, d, "stream.jsonl"), "utf8")), cs.moor);
      if (why.length) bad++;
      process.stdout.write(`[${cs.id}] ${why.length ? "FAIL: " + why.join("; ") : "PASS"}\n`);
    }
    process.exit(bad ? 1 : 0);
  }
  const bin = which("claude");
  const run = process.argv.includes("--run");
  const oi = process.argv.indexOf("--only");
  const only = oi > 0 ? process.argv[oi + 1].split(",") : Object.keys(CASES);
  process.stdout.write(plan(bin) + "\n\n");
  if (!run) process.exit(0);
  if (!bin) { process.stderr.write("claude is not on PATH\n"); process.exit(2); }

  const scratch = mkdtempSync(join(tmpdir(), "moorai-mcp-livecall-"));
  const world = await startWorld(scratch);
  const before = readClaudeJson();
  let failed = 0;
  try {
    for (const id of only) {
      const c = CASES[id];
      if (!c) { process.stderr.write(`unknown case ${id}\n`); continue; }
      const target = c.transport === "stdio" ? stdioTarget(world, { host: "claude-code" }) : await httpTarget(world);
      const proj = mkdtempSync(join(scratch, `proj-${id}-`));
      const cfg = join(proj, "mcp-config.json");
      writeFileSync(cfg, JSON.stringify({ mcpServers: { [c.server]: target.entry } }, null, 2));
      const n0 = world.con.alerts.length;
      const args = claudeArgs(c, cfg);
      process.stdout.write(`===== [${id}] $ claude ${args.map((a) => JSON.stringify(a)).join(" ")}\n`);
      const r = await runClaude(bin, args, proj);
      await waitFor(() => usageCount(target) >= 1, 3000);
      const p = parseStream(r.stdout);
      const serverArgs = target.toolCalls().map((x) => JSON.stringify(x && x.arguments));
      const moor = {
        serverGot: serverArgs.some((a) => a.includes(c.args.m)),
        usage: usageCount(target),
        ledger: ledgerCalls(target).map((e) => e.decision),
        blockedAlert: world.con.alerts.slice(n0).some((a) => a.mcpServer === target.label && a.riskLevel === "Blocked"),
        serverReceived: target.toolCalls(),
        ledgerRows: ledgerCalls(target),
        alerts: world.con.alerts.slice(n0).filter((a) => a.mcpServer === target.label)
      };
      const why = judge(c, p, moor);
      if (why.length) failed++;
      process.stdout.write(`exit code: ${r.code}\n`);
      process.stdout.write(`mcp servers at init: ${JSON.stringify(p.init && p.init.mcp_servers)}\n`);
      process.stdout.write(`tool_use: ${JSON.stringify(p.uses)}\n`);
      process.stdout.write(`tool_result: ${JSON.stringify(p.results)}\n`);
      process.stdout.write(`result: ${JSON.stringify(p.result && { subtype: p.result.subtype, is_error: p.result.is_error, num_turns: p.result.num_turns, total_cost_usd: p.result.total_cost_usd, result: p.result.result, permission_denials: p.result.permission_denials })}\n`);
      process.stdout.write(`MoorAI: server received ${JSON.stringify(moor.serverReceived)}; usage tally ${moor.usage}; ledger ${JSON.stringify(moor.ledgerRows.map(({ ts, decision, tool, mcpServer, riskLevel, contentHash }) => ({ ts, decision, tool, mcpServer, riskLevel, contentHash })))}; console alerts ${JSON.stringify(moor.alerts.map(({ category, riskLevel, decision, tool, mcpServer }) => ({ category, riskLevel, decision, tool, mcpServer })))}\n`);
      process.stdout.write(`verdict: ${why.length ? "FAIL: " + why.join("; ") : "PASS"}\n`);
      if (r.stderr.trim()) process.stdout.write(`stderr: ${r.stderr.trim().slice(0, 2000)}\n`);
      writeFileSync(join(proj, "stream.jsonl"), r.stdout);
      writeFileSync(join(proj, "case.json"), JSON.stringify({ id, moor: { serverGot: moor.serverGot, usage: moor.usage, ledger: moor.ledger, blockedAlert: moor.blockedAlert } }));
      await target.stop();
    }
  } finally {
    await world.close();
  }
  const after = readClaudeJson();
  const d = keyDiff(before, after);
  process.stdout.write(`\n~/.claude.json top-level keys: added ${JSON.stringify(d.added)} removed ${JSON.stringify(d.removed)} changed ${JSON.stringify(d.changed)}\n`);
  process.stdout.write(`~/.claude.json mcpServers unchanged: ${JSON.stringify((before || {}).mcpServers) === JSON.stringify((after || {}).mcpServers)}\n`);
  const pd = keyDiff((before || {}).projects, (after || {}).projects);
  process.stdout.write(`~/.claude.json projects: added ${JSON.stringify(pd.added)} changed ${JSON.stringify(pd.changed)}\n`);
  for (const k of pd.added.concat(pd.changed)) {
    const pa = ((after || {}).projects || {})[k] || {};
    process.stdout.write(`  ${k}: mcpServers=${JSON.stringify(pa.mcpServers)} enabledMcpjsonServers=${JSON.stringify(pa.enabledMcpjsonServers)} allowedTools=${JSON.stringify(pa.allowedTools)}\n`);
  }
  process.stdout.write(`scratch (stream-json per run): ${scratch}\n`);
  process.exit(failed ? 1 : 0);
}
