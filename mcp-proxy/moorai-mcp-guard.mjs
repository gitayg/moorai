#!/usr/bin/env node
// MoorAI MCP Guard for Claude Desktop — a stdio JSON-RPC proxy that inserts the SAME on-device AI Agent
// Gateway (mcpGateway) the Claude Code PreToolUse hook uses, between Claude Desktop and each MCP server.
//
// Claude Desktop has NO PreToolUse hooks (that is a Claude Code CLI feature), but it launches MCP servers
// from claude_desktop_config.json. So we guard it by spawning THIS proxy in place of the real server; the
// proxy spawns the real server as a child and pumps stdio both ways, gating every `tools/call` through
// mcpGateway (server allow-list #3 → per-tool arg rules #18 → argument content scan #2). All other
// JSON-RPC traffic (initialize, tools/list, notifications, responses) passes through verbatim.
//
// Content-free by construction: only category / risk / one-way hash / server / tool / decision may leave
// the device. Tool-call CONTENT is NEVER emitted. Governance, not a sandbox: on ANY error (bad policy,
// engine failure, unparseable line) we FAIL OPEN — the message is forwarded unchanged.
//
//   node moorai-mcp-guard.mjs [--server <label>] -- <real-server-cmd> [args...]
//
//   --server <label>   the MCP server name used for the gateway (allow-list / audit). Defaults to the
//                      basename of the real command. install.mjs passes the configured server key here.

import { spawn } from "node:child_process";
import { basename } from "node:path";
import os from "node:os";
import { loadConfig } from "../cli/config.mjs";
import { buildEngine, mcpGateway, literacyTouchpoint, loadVerifiedPolicy, ratchetPosture, readRootOwned, readText, POSTURE_STATE, POSTURE_LATCH, POSTURE_LEGACY, SYSTEM_POSTURE } from "../cli/hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { applyCaptureTier } from "../data/capture-tiers.js";
import { recordAction } from "../cli/signals.mjs";
import { contentHash } from "../cli/content-hash.mjs";
import { emitOtel } from "../cli/otel.mjs";

// ---- argv parsing: [--server label] -- realcmd args... ----
function parseArgv(argv) {
  const sep = argv.indexOf("--");
  if (sep < 0 || sep === argv.length - 1) {
    process.stderr.write("moorai-mcp-guard: usage: node moorai-mcp-guard.mjs [--server <label>] -- <cmd> [args...]\n");
    process.exit(2);
  }
  const pre = argv.slice(0, sep);
  const rest = argv.slice(sep + 1);
  let label = "";
  for (let i = 0; i < pre.length; i++) {
    if (pre[i] === "--server" || pre[i] === "-s") { label = pre[i + 1] || ""; i++; }
  }
  const cmd = rest[0];
  const args = rest.slice(1);
  if (!label) label = basename(cmd || "mcp").replace(/\.(mjs|js|cjs|exe|sh|py)$/i, "") || "mcp";
  return { label, cmd, args };
}

const { label: SERVER, cmd: REAL_CMD, args: REAL_ARGS } = parseArgv(process.argv.slice(2));

// ---- config / identity / content-free reporting (same shape as the Claude Code hook) ----
const CONFIG = loadConfig();
function djb2(s) { let h = 5381; for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0; return "h" + h.toString(16); }
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant, actor: djb2(`${os.userInfo().username}@${os.hostname()}`) };
function post(alert) {
  // Content-free OTLP mirror — no-op unless an OTLP endpoint is configured; bounded + swallows errors,
  // so it can never touch the proxy path (same contract as the alert post below).
  try { emitOtel(alert, { config: CONFIG, identity: IDENTITY }); } catch { /* telemetry is never enforcement */ }
  try {
    return fetch(`${CONFIG.serverUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) },
      body: JSON.stringify(alert),
      signal: AbortSignal.timeout(1500)
    }).catch(() => {});
  } catch { /* never let a network/timeout error touch the proxy path */ }
}

// ---- policy load ----
//
// THE FIFTH BYPASS DOOR, and it was this file. loadPolicy() here used to be a verbatim copy of the
// hook's PRE-v0.51 logic — `JSON.parse(readFileSync(~/.curaiq/hook-policy.json))`, no signature check,
// no anchor, no pin. v0.51-v0.53 closed `echo '{}' > ~/.curaiq/hook-policy.json` in cli/moorai-hook.mjs,
// but Claude Desktop kept reading the SAME attacker-writable file with none of that verification, so
// the one-liner still collapsed enforcement here.
//
// There is now no copy at all: loadVerifiedPolicy() lives in cli/hook-core.mjs and BOTH entrypoints
// call it, so the anchor precedence (/etc/moorai/policy.pub → TOFU pin → nothing), the TOFU arming,
// the last-known-good fallback and the "unverifiable policy is NO policy" rule are the same code, not
// the same intent. Re-verification happens on EVERY refresh, not once at startup: this process is
// long-lived, so a cache poisoned an hour after Claude Desktop launched has to be caught too.
//
// DIVERGENCE FROM THE HOOK, stated rather than hidden: break-glass (#33) is not honoured here. An
// operator-signed marker forces the hook fail-OPEN; this proxy has no such override, so a fail-closed
// device stays enforced in Claude Desktop until the marker lets the policy load again. That is the
// safe direction (more enforcement, not less), and Claude Desktop has no interactive justify banner
// for the operator to answer anyway.

// mutable — refreshed lazily so a long-lived Claude Desktop session picks up policy changes.
let POLICY = null;
let ENGINE = null;
let LAST_POLICY_LOAD = 0;
// Tamper alerts are deduped by their content-free token: this process re-verifies every 60s, and a
// poisoned cache that is left in place would otherwise page the SOC once a minute forever.
const REPORTED = new Set();
function reportOnce(category, hash, riskLevel) {
  if (REPORTED.has(hash)) return;
  REPORTED.add(hash);
  post({ threatId: 0, category, riskLevel, stage: "policy", tool: "desktop:policy", ts: new Date().toISOString(), contentHash: hash, ...IDENTITY });
}

// Same content-free signals the hook emits, under the same tokens, so one console rule covers both
// surfaces. Only source names and failure statuses leave — never a byte of the policy.
function reportPolicyTrust({ rejected, pin, trust, absence }) {
  for (const r of rejected || []) reportOnce(`Policy signature rejected (${r.status})`, `policy:${r.source}:${r.status}`, "Critical");
  if (trust && trust.mode === "rebind") reportOnce("Policy key pin tenant rebind refused", "policy:pin:tenant-rebind", "Critical");
  if (pin && pin.corrupt) reportOnce("Policy key pin unreadable", "policy:pin:corrupt", "Critical");
  else if (pin && pin.evidenceMissing) reportOnce("Policy key pin evidence missing", "policy:pin:evidence-missing", "High");
  if (absence && absence.suspicious) reportOnce("Policy key pin absent on a device with prior operation", "policy:pin:absent-operational", "Critical");
}

// The hook's durable posture ratchet, read through the same shared helpers. "Unverifiable policy = no
// policy" only bites if "no policy" is not simply "forward everything": a fail-closed org gets the
// reviewable built-in default (OFFLINE_DEFAULT_POLICY) here exactly as it does in the hook. A
// fail-open org keeps today's behaviour — no engine, forward — which is the documented default.
function durablePosture() {
  return ratchetPosture({
    system: readRootOwned(SYSTEM_POSTURE),
    state: readText(POSTURE_STATE),
    latch: readText(POSTURE_LATCH),
    legacy: readText(POSTURE_LEGACY),
    env: process.env.MOORAI_OFFLINE_MODE
  });
}

async function ensurePolicy() {
  if (Date.now() - LAST_POLICY_LOAD < 60000 && ENGINE) return;
  try {
    const v = await loadVerifiedPolicy(CONFIG);
    reportPolicyTrust(v);
    let policy = v.policy;
    if (!policy) {
      const posture = durablePosture();
      if (posture.posture === "fail-closed") {
        reportOnce("Offline: fail-closed default applied", "offline:fail-closed", "High");
        policy = OFFLINE_DEFAULT_POLICY;
      }
    } else if (v.source === "last-known-good") {
      reportOnce("Enforcing last-known-good verified policy", "policy:lkg:applied", "High");
    }
    POLICY = policy;
    // buildEngine(null) is deliberate and UNCHANGED from before this fix: with no policy at all the
    // gateway still scans arguments and reports findings under threatActionFor's defaults. Refusing a
    // poisoned cache must not be allowed to REDUCE what the proxy sees — that would hand the attacker
    // a quieter bypass than the one just closed.
    ENGINE = buildEngine(policy);
    LAST_POLICY_LOAD = Date.now();
  } catch { /* keep whatever we had; fail open below if still null */ }
}

// ---- content-free per-call audit ledger + alert ----
function auditCall(tool, decision, argsHash) {
  try {
    recordAction(applyCaptureTier({
      threatId: 0, category: "MCP tool call", riskLevel: decision === "deny" ? "Blocked" : "Info",
      stage: "mcp", tool: `desktop:${tool}`, decision, mcpServer: SERVER,
      ts: new Date().toISOString(), contentHash: argsHash, ...IDENTITY
    }, {}, (POLICY && POLICY.captureTier) || "content-free"));
  } catch { /* ledger is best-effort; never affects the decision */ }
}
function alertBlock(tool, gate, reason, argsHash) {
  const category = gate === "server" ? "MCP: unapproved server" : gate === "args" ? "MCP: denied tool argument" : "MCP: blocked tool argument";
  post({ threatId: 0, category, riskLevel: "Blocked", stage: "mcp", tool: `desktop:${tool}`, decision: "deny", mcpServer: SERVER, ts: new Date().toISOString(), contentHash: argsHash, ...IDENTITY });
  // Coach-as-literacy: the blocked-call message Claude Desktop shows the user is a literacy touchpoint.
  try { post({ ...literacyTouchpoint({ threatId: 0, category, tool: `desktop:${tool}` }), ...IDENTITY }); } catch { /* evidence, not enforcement */ }
}
function alertFindings(tool, findings, blocked, argsHash) {
  for (const f of findings || []) {
    post({ threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage: "mcp", tool: `desktop:${tool}`, mcpServer: SERVER, ts: new Date().toISOString(), contentHash: contentHash(f.match || ""), ...IDENTITY });
    if (blocked || f.riskLevel === "High" || f.riskLevel === "Critical") {
      try { post({ ...literacyTouchpoint({ threatId: f.threatId, category: f.category, tool: `desktop:${tool}` }), ...IDENTITY }); } catch { /* evidence, not enforcement */ }
    }
  }
}

// ---- spawn the real MCP server ----
const child = spawn(REAL_CMD, REAL_ARGS, { stdio: ["pipe", "pipe", "pipe"], env: process.env });

child.on("error", (e) => {
  // The real server could not be spawned. Fail loudly to Claude Desktop's stderr (visible in its logs)
  // and exit — there is nothing to proxy. This is a startup/config error, not a gated tool-call.
  process.stderr.write(`moorai-mcp-guard: failed to spawn '${REAL_CMD}': ${e && e.message}\n`);
  process.exit(1);
});
child.on("exit", (code, signal) => { process.exit(code == null ? (signal ? 1 : 0) : code); });

// Responses from the real server → Claude Desktop, verbatim (transparent pass-through).
child.stdout.pipe(process.stdout);
// The real server's diagnostics → our stderr (Claude Desktop surfaces these in its MCP logs).
child.stderr.pipe(process.stderr);

// ---- write a JSON-RPC MCP tool-error RESULT back to Claude Desktop (so the model sees a clean refusal,
// not a hang). We use the tool-result `isError` shape, NOT a protocol-level JSON-RPC error object. ----
function writeBlock(id, reason) {
  const msg = { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool call: ${reason}` }], isError: true } };
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function forward(rawLine) { child.stdin.write(rawLine + "\n"); }

// ---- gate one JSON-RPC message. tools/call is inspected; everything else is forwarded verbatim. ----
async function handleLine(rawLine) {
  const trimmed = rawLine.replace(/\r$/, "");
  if (!trimmed.trim()) { forward(rawLine); return; }
  let msg;
  try { msg = JSON.parse(trimmed); } catch { forward(rawLine); return; } // not JSON we understand → pass through

  if (!msg || msg.method !== "tools/call" || !msg.params || typeof msg.params !== "object") { forward(rawLine); return; }

  // This is a tool-call — the surface we gate.
  try {
    await ensurePolicy();
    const tool = msg.params.name || "";
    const args = JSON.stringify(msg.params.arguments == null ? {} : msg.params.arguments);
    const argsHash = contentHash(args);

    if (!ENGINE) { auditCall(tool, "allow", argsHash); forward(rawLine); return; } // fail open: no engine

    const g = mcpGateway(ENGINE, POLICY, { tool, server: SERVER, args });

    if (g.decision === "deny") {
      // Blocked: do NOT forward. The real server never receives the call. Return a clean tool error.
      alertBlock(tool, g.gate, g.reason, argsHash);
      alertFindings(tool, g.findings, true, argsHash);
      auditCall(tool, "deny", argsHash);
      writeBlock(msg.id, g.reason || "policy");
      return;
    }
    // allow OR coach ("ask"): Claude Desktop has no interactive banner, so coach = allow + record.
    alertFindings(tool, g.findings, false, argsHash);
    auditCall(tool, g.decision, argsHash);
    forward(rawLine);
  } catch {
    // Governance, not a sandbox: any gate error must not drop the call — forward it unchanged.
    forward(rawLine);
  }
}

// ---- newline-delimited framing of Claude Desktop → proxy stdin. Buffer partial lines; a tool-call must
// be fully awaited before the next line is processed so ordering to the child is preserved. ----
let buf = "";
let queue = Promise.resolve();
function enqueue(line) { queue = queue.then(() => handleLine(line)); }

process.stdin.on("data", (chunk) => {
  buf += chunk.toString("utf8");
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    enqueue(line);
  }
});
process.stdin.on("end", () => {
  queue = queue.then(() => { if (buf.length) return handleLine(buf); }).then(() => { try { child.stdin.end(); } catch {} });
});

// Best-effort warm-up so the first tool-call is not delayed by the initial policy fetch.
ensurePolicy();
