// Claude Code driver for the live host-conformance tier.
//
// Each case is one headless `claude -p` turn in a throwaway HOME and CLAUDE_CONFIG_DIR, with MoorAI's hook
// installed there by its own installer (cli/moorai-hook.mjs install) and the device enrolled against the
// stand-in console. The model is the scripted Anthropic endpoint (scripted-anthropic.mjs): Claude Code
// runs its real hook pipeline, permission layer and tools; only the model's turns are scripted, so no
// paid model call is made and no API key is read (ANTHROPIC_API_KEY is a fixed non-key string).
//
// On macOS the host runs under sandbox-exec with the profile from mcp-gateway/test/live/live-clients.mjs:
// outbound connections other than localhost are denied, and so are writes to the real ~/.claude.json,
// ~/.claude and ~/.cursor. Permission mode is dontAsk with only the case's tool allowed, so Claude Code's
// own auto-mode classifier never runs and nothing waits for a prompt.
//
// Cases (fixed MoorAI probes; none of their text reaches the report):
//   shell-allow   Bash `echo` → MoorAI allows, the command runs, its output reaches the model
//   shell-deny    Bash reverse shell to 127.0.0.1:9 (a closed local port) → MoorAI's PreToolUse deny; the
//                 command never runs; a Blocked alert reaches the console
//   prompt-block  a prompt carrying a fake AWS key under a policy that scans every prompt and blocks #39
//                 (promptScan all, promptScanAction block) → MoorAI's UserPromptSubmit block; the prompt never reaches the model; a Blocked alert
//   mcp-allow     Claude Code as an MCP client: echo through MoorAI's stdio guard → forwarded and echoed
//   mcp-deny      the same with BLOCKME (the policy's mcpToolRules deny) → refused; the server never
//                 receives the call
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startScriptedAnthropic } from "./scripted-anthropic.mjs";
import { startStandInConsole } from "./stand-in-console.mjs";
import { sandboxProfile, clientEnv } from "../../mcp-gateway/test/live/live-clients.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE_MCP = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
export const MCP_LABEL = "moorai-stdio";
export const FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// promptScan "all" + promptScanAction "block": by default a person's own prompt is not scanned
// (cli/prompt-scan.mjs), so the prompt case opts in, the way a server-mode or pipeline policy would.
export const CLAUDE_POLICY = { captureTier: "content-free", threatPolicy: { 39: "block" }, promptScan: "all", promptScanAction: "block", mcpToolRules: { echo: { deny: ["BLOCKME"] } } };

export const CLAUDE_CASES = [
  { id: "shell-allow", surface: "agent-turn", expect: "allow", tool: "Bash", input: { command: "echo moorai-conformance-ok", description: "MoorAI conformance probe" }, okMarker: "moorai-conformance-ok" },
  { id: "shell-deny", surface: "agent-turn", expect: "deny", tool: "Bash", input: { command: "bash -i >& /dev/tcp/127.0.0.1/9 0>&1", description: "MoorAI conformance probe" } },
  { id: "prompt-block", surface: "prompt", expect: "deny", tool: null, marker: FAKE_AWS_KEY, prompt: `Store these for later: AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY}\naws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1"` },
  { id: "mcp-allow", surface: "mcp-client", expect: "allow", tool: `mcp__${MCP_LABEL}__echo`, input: { m: "hello-moorai" }, okMarker: "hello-moorai", mcp: true },
  { id: "mcp-deny", surface: "mcp-client", expect: "deny", tool: `mcp__${MCP_LABEL}__echo`, input: { m: "BLOCKME" }, mcp: true }
];

const pickAlert = (a) => ({ category: a.category ?? null, riskLevel: a.riskLevel ?? null, decision: a.decision ?? null, reasonCode: a.reasonCode ?? null });
const isBlocked = (a) => a && (a.riskLevel === "Blocked" || a.decision === "deny");

export function judgeClaudeCase(def, o) {
  const tr = o.toolResult;
  const toolRan = !!(tr && !tr.isError);
  const refusedByMoorAI = !!(tr && tr.isError && tr.mentionsMoorAI);
  const blocked = (o.alerts || []).find(isBlocked) || null;
  const checks = { toolUseSent: !!o.toolUseSent, toolRan, refusedByMoorAI, alertSeen: !!blocked, promptReachedModel: !!o.markerSeen, hostExitZero: o.exitCode === 0 };
  if (o.serverGotCall !== null && o.serverGotCall !== undefined) checks.serverGotCall = !!o.serverGotCall;
  let pass, observed;
  if (def.id === "prompt-block") {
    observed = o.markerSeen ? "allow" : "deny";
    pass = !o.markerSeen && !!blocked;
  } else if (def.expect === "allow") {
    observed = toolRan ? "allow" : refusedByMoorAI ? "deny" : "none";
    pass = !!o.toolUseSent && toolRan && !!(tr && tr.okMarker) && (!def.mcp || o.serverGotCall === true);
  } else {
    observed = toolRan ? "allow" : refusedByMoorAI ? "deny" : "none";
    pass = !!o.toolUseSent && refusedByMoorAI && !!blocked && (!def.mcp || o.serverGotCall === false);
  }
  return { id: def.id, surface: def.surface, expect: def.expect, observed, status: pass ? "pass" : "fail", checks, alert: blocked ? pickAlert(blocked) : null };
}

function enrol(home, con) {
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: con.url, tenant: con.tenant, installToken: "conformance" }), { mode: 0o600 });
}
const xdg = (home) => ({ XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") });

function runHost(bin, args, { cwd, env, sandbox, timeoutMs }) {
  const argv = sandbox ? ["/usr/bin/sandbox-exec", "-p", sandboxProfile(), bin, ...args] : [bin, ...args];
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stdout.on("data", () => {});
    child.stderr.on("data", (c) => { if (stderr.length < 4000) stderr += c; });
    const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } }, timeoutMs);
    child.on("close", (code) => { clearTimeout(t); resolve({ code, stderr }); });
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function readCalls(p) { try { return readFileSync(p, "utf8").split("\n").filter((l) => l.trim()).length; } catch { return 0; } }

// One case, with its own stand-in console so a late alert from one case cannot land in another's window.
// ctx: { bin, scratch, sandbox, timeoutMs }
export async function runClaudeCase(def, ctx) {
  const con = await startStandInConsole({ policy: CLAUDE_POLICY });
  try { return await runCase(def, { ...ctx, con }); } finally { await con.close(); }
}

async function runCase(def, ctx) {
  const home = mkdtempSync(join(ctx.scratch, `claude-${def.id}-`));
  const cfg = join(home, ".claude");
  const proj = join(home, "proj");
  mkdirSync(cfg, { recursive: true });
  mkdirSync(proj, { recursive: true });
  enrol(home, ctx.con);
  const env0 = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, CLAUDE_CONFIG_DIR: cfg, ...xdg(home) };
  const ins = await runHost(process.execPath, [HOOK, "install"], { cwd: proj, env: env0, sandbox: false, timeoutMs: 30000 });
  if (ins.code !== 0) throw new Error(`moorai-hook install exited ${ins.code}`);

  const model = await startScriptedAnthropic({ toolName: def.tool, toolInput: def.input || {}, okMarker: def.okMarker || null, marker: def.marker || null });
  const args = ["-p", def.prompt || "Run the MoorAI conformance probe.", "--permission-mode", "dontAsk", "--max-turns", "3", "--output-format", "json", "--no-session-persistence"];
  if (def.tool) args.push("--allowedTools", def.tool);
  let calls = null;
  if (def.mcp) {
    const gHome = mkdtempSync(join(ctx.scratch, `guard-${def.id}-`));
    enrol(gHome, ctx.con);
    calls = join(gHome, "calls.jsonl");
    const entry = { command: process.execPath, args: [GUARD, "--server", MCP_LABEL, "--host", "claude-code", "--", process.execPath, FAKE_MCP, calls], env: { HOME: gHome, USERPROFILE: gHome, ...xdg(gHome) } };
    const mcpCfg = join(home, "mcp.json");
    writeFileSync(mcpCfg, JSON.stringify({ mcpServers: { [MCP_LABEL]: entry } }));
    args.push("--mcp-config", mcpCfg, "--strict-mcp-config");
  }
  const n0 = ctx.con.alerts.length;
  const started = Date.now();
  let r;
  try {
    r = await runHost(ctx.bin, args, {
      cwd: proj, sandbox: ctx.sandbox, timeoutMs: ctx.timeoutMs || 180000,
      env: clientEnv(home, { CLAUDE_CONFIG_DIR: cfg, ANTHROPIC_API_KEY: "sk-moorai-conformance-not-a-key", ANTHROPIC_BASE_URL: model.url, DISABLE_AUTOUPDATER: "1", ...xdg(home) })
    });
  } finally { await model.close(); }
  const latencyMs = Date.now() - started;
  // Alerts are posted by the hook's detached worker; give it time to land.
  const wantAlert = def.expect === "deny";
  const end = Date.now() + (wantAlert ? 10000 : 1500);
  while (Date.now() < end && !(wantAlert && ctx.con.alerts.slice(n0).some(isBlocked))) await sleep(200);
  const o = { exitCode: r.code, ...model.stats(), alerts: ctx.con.alerts.slice(n0), serverGotCall: calls ? readCalls(calls) > 0 : null };
  return { ...judgeClaudeCase(def, o), latencyMs };
}

