// Live check of the HTTP hook transport against a real Claude Code (`claude -p`), with no paid model call:
// the model is the scripted Anthropic endpoint (scripts/conformance/scripted-anthropic.mjs), the console the
// stand-in console with a signed policy (scripts/conformance/stand-in-console.mjs), each case in a throwaway
// HOME and CLAUDE_CONFIG_DIR, Claude Code under sandbox-exec on macOS (no outbound connection but localhost, no
// write to the real ~/.claude). The hook is installed by its own installer with --hook-transport http.
//
//   node scripts/hookd-live.mjs [--claude <path to claude>] [--json]
//
// Cases:
//   headers   the http entries point at a recorder instead of moorai-hookd: which forwarded values Claude Code
//             interpolates into the headers (booleans, and whether CLAUDE_PROJECT_DIR is the project)
//   read-env  Read of a fake .env with moorai-hookd running: PreToolUse reaches moorai-hookd, the Read is denied
//             with MoorAI's reason, a Blocked alert reaches the console
//   shell-ok  Bash echo with moorai-hookd running: allowed, the output reaches the model
//   down      Bash echo with moorai-hookd NOT running and failMode.hook closed (onFailure "block"): refused
//   allowlist read-env again, with a project .claude/settings.json holding "allowedHttpHookUrls": []
//   allowlist-open  the same under a policy with no fail mode (open: onFailure "continue")
//   down-open       moorai-hookd NOT running, fail mode open
//   disable-all-command  for comparison, the COMMAND transport with a project .claude/settings.json holding
//                   "disableAllHooks": true
// Prints one JSON line per case; nothing from a prompt, file or command is printed.
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import net from "node:net";
import { startScriptedAnthropic } from "./conformance/scripted-anthropic.mjs";
import { startStandInConsole } from "./conformance/stand-in-console.mjs";
import { sandboxProfile, clientEnv } from "../mcp-gateway/test/live/live-clients.mjs";
import { FORWARDED_ENV, envHeader } from "../cli/hook-http.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const HOOKD = join(ROOT, "cli", "moorai-hookd.mjs");
const POLICY = { captureTier: "content-free", threatPolicy: { 39: "block", 54: "block" }, failMode: { hook: "closed" } };
const SECRET = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
const argv = process.argv.slice(2);
const CLAUDE = argv.includes("--claude") ? argv[argv.indexOf("--claude") + 1] : "claude";
const SANDBOX = process.platform === "darwin";

const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function run(bin, args, { cwd, env, sandbox = false, timeoutMs = 120000 }) {
  const a = sandbox && SANDBOX ? ["/usr/bin/sandbox-exec", "-p", sandboxProfile(), bin, ...args] : [bin, ...args];
  return new Promise((res) => {
    const c = spawn(a[0], a.slice(1), { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (d) => { out += d; });
    c.stderr.on("data", (d) => { if (err.length < 8000) err += d; });
    const t = setTimeout(() => { try { c.kill("SIGKILL"); } catch { /* gone */ } }, timeoutMs);
    c.on("close", (code) => { clearTimeout(t); res({ code, out, err }); });
  });
}

async function setup(con, port, { project = null, transport = "http" } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-hookd-live-"));
  const cfg = join(home, ".claude"), proj = join(home, "proj");
  for (const d of [cfg, proj, join(home, ".moorai")]) mkdirSync(d, { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: con.url, tenant: con.tenant, installToken: "conformance" }), { mode: 0o600 });
  writeFileSync(join(proj, ".env"), SECRET);
  if (project) { mkdirSync(join(proj, ".claude"), { recursive: true }); writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify(project)); }
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: cfg, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
  const ins = await run(process.execPath, [HOOK, "install", "--hook-transport", transport, "--hookd-port", String(port)], { cwd: proj, env });
  if (ins.code !== 0) throw new Error(`install exited ${ins.code}: ${ins.err}`);
  const settings = JSON.parse(readFileSync(join(cfg, "settings.json"), "utf8"));
  return { home, cfg, proj, env, settings };
}

async function claudeTurn(sb, { tool, input, okMarker = null }) {
  const model = await startScriptedAnthropic({ toolName: tool, toolInput: input, okMarker });
  try {
    const r = await run(CLAUDE, ["-p", "Run the MoorAI probe.", "--permission-mode", "dontAsk", "--allowedTools", tool, "--max-turns", "3", "--output-format", "json", "--no-session-persistence"], {
      cwd: sb.proj, sandbox: true, timeoutMs: 180000,
      env: clientEnv(sb.home, { CLAUDE_CONFIG_DIR: sb.cfg, ANTHROPIC_API_KEY: "sk-moorai-conformance-not-a-key", ANTHROPIC_BASE_URL: model.url, DISABLE_AUTOUPDATER: "1", XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state") })
    });
    return { exit: r.code, ...model.stats(), stderrTail: r.code === 0 ? "" : r.err.slice(-400) };
  } finally { await model.close(); }
}

async function startHookd(sb, port) {
  const d = spawn(process.execPath, [HOOKD, "--port", String(port), "--log"], { cwd: sb.home, env: sb.env, stdio: ["ignore", "pipe", "pipe"] });
  const log = [];
  d.stderr.on("data", (c) => log.push(...String(c).split("\n").filter(Boolean)));
  await new Promise((res, rej) => { let b = ""; d.stdout.on("data", (x) => { b += x; if (b.includes("listening")) res(); }); d.on("exit", (c) => rej(new Error(`moorai-hookd exited ${c}`))); });
  return { log, stop: () => new Promise((r) => { d.once("exit", r); d.kill(); }) };
}

const blocked = (alerts) => alerts.filter((a) => a.riskLevel === "Blocked" || a.decision === "deny");
const pick = (a) => ({ category: a.category, reasonCode: a.reasonCode, agentVersion: a.agentVersion ?? null });

async function caseHeaders(con) {
  const seen = [];
  const port = await freePort();
  const rec = http.createServer((q, s) => { q.resume(); q.on("end", () => { seen.push({ event: "", headers: q.headers }); s.writeHead(200); s.end(); }); });
  await new Promise((r) => rec.listen(port, "127.0.0.1", r));
  const sb = await setup(con, port);
  try {
    const t = await claudeTurn(sb, { tool: "Bash", input: { command: "echo moorai-live-ok", description: "probe" }, okMarker: "moorai-live-ok" });
    const h = seen[0] ? seen[0].headers : {};
    const vals = Object.fromEntries(FORWARDED_ENV.map((n) => [n, typeof h[envHeader(n)] === "string" && h[envHeader(n)] !== ""]));
    return { case: "headers", requests: seen.length, forwardedNonEmpty: vals, projectDirIsProject: h[envHeader("CLAUDE_PROJECT_DIR")] === sb.proj, aiAgentForm: /^claude-code_[0-9-]+_harness$/.test(h[envHeader("AI_AGENT")] || ""), bearer: /^Bearer [0-9a-f]{64}$/.test(h.authorization || ""), toolRan: !!(t.toolResult && !t.toolResult.isError) };
  } finally { rec.close(); }
}

async function caseRun(con, id, { tool, input, okMarker, hookdUp = true, project = null, transport = "http" }) {
  const port = await freePort();
  const sb = await setup(con, port, { project, transport });
  const n0 = con.alerts.length;
  const d = hookdUp ? await startHookd(sb, port) : null;
  try {
    const t = await claudeTurn(sb, { tool, input: typeof input === "function" ? input(sb) : input, okMarker });
    for (let i = 0; i < 40 && !blocked(con.alerts.slice(n0)).length && hookdUp; i++) await sleep(250);
    const hookd = d ? d.log.filter((l) => / POST \/v1\/hook\/claude-code /.test(l)).map((l) => l.split(" ").slice(3, 5).join(" ")) : [];
    return { case: id, hookdUp, transport, onFailurePreToolUse: sb.settings.hooks.PreToolUse[0].hooks[0].onFailure ?? null, toolUseSent: t.toolUseSent, toolRan: !!(t.toolResult && !t.toolResult.isError), refusedByMoorAI: !!(t.toolResult && t.toolResult.isError && t.toolResult.mentionsMoorAI), toolResultError: !!(t.toolResult && t.toolResult.isError), hookdRequests: hookd, blockedAlerts: blocked(con.alerts.slice(n0)).map(pick), exit: t.exit, ...(t.stderrTail ? { stderrTail: t.stderrTail } : {}) };
  } finally { if (d) await d.stop(); }
}

async function main() {
  const con = await startStandInConsole({ policy: POLICY });
  const out = [];
  try {
    const v = await run(CLAUDE, ["--version"], { cwd: tmpdir(), env: process.env });
    out.push({ claude: v.out.trim() });
    out.push(await caseHeaders(con));
    out.push(await caseRun(con, "read-env", { tool: "Read", input: (sb) => ({ file_path: join(sb.proj, ".env") }) }));
    out.push(await caseRun(con, "shell-ok", { tool: "Bash", input: { command: "echo moorai-live-ok", description: "probe" }, okMarker: "moorai-live-ok" }));
    out.push(await caseRun(con, "down", { tool: "Bash", input: { command: "echo moorai-live-ok", description: "probe" }, okMarker: "moorai-live-ok", hookdUp: false }));
    out.push(await caseRun(con, "allowlist", { tool: "Read", input: (sb) => ({ file_path: join(sb.proj, ".env") }), project: { allowedHttpHookUrls: [] } }));
    const open = await startStandInConsole({ policy: { ...POLICY, failMode: undefined } });
    try {
      out.push(await caseRun(open, "allowlist-open", { tool: "Read", input: (sb) => ({ file_path: join(sb.proj, ".env") }), project: { allowedHttpHookUrls: [] } }));
      out.push(await caseRun(open, "disable-all-command", { tool: "Read", input: (sb) => ({ file_path: join(sb.proj, ".env") }), project: { disableAllHooks: true }, transport: "command", hookdUp: false }));
      out.push(await caseRun(open, "down-open", { tool: "Bash", input: { command: "echo moorai-live-ok", description: "probe" }, okMarker: "moorai-live-ok", hookdUp: false }));
    } finally { await open.close(); }
  } finally { await con.close(); }
  for (const o of out) process.stdout.write(`${JSON.stringify(o)}\n`);
}
main().catch((e) => { process.stderr.write(`hookd-live: ${e.message}\n`); process.exit(1); });
