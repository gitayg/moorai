#!/usr/bin/env node
// MoorAI MCP Guard for Claude Desktop — a stdio JSON-RPC proxy that inserts the SAME on-device AI Agent
// Gateway (mcpGateway) the Claude Code PreToolUse hook uses, between Claude Desktop and each MCP server.
//
// Claude Desktop has NO PreToolUse hooks (that is a Claude Code CLI feature), but it launches MCP servers
// from claude_desktop_config.json. So we guard it by spawning THIS proxy in place of the real server; the
// proxy spawns the real server as a child and pumps stdio both ways, gating every `tools/call` through
// mcpGateway (server allow-list #3 → per-tool arg rules #18 → argument content scan #2).
//
// AND — new — OBSERVING every `tools/list` response at the "tool" stage. The header used to say
// "tools/list passes through verbatim", and it still does byte-for-byte; what changed is that the
// bytes are now also COPIED to a bounded, fail-open scanner. Until this existed, `grep -rn
// 'decideText([^)]*"tool"' cli/` returned zero: data/detectors.js shipped mcp-tool-poisoning (#60)
// and mcp-hidden-canary (#50) scoped to ["tool","file","index"] and no shipped caller ever handed
// them a tool description or an input schema. See mcp-proxy/tool-scan.mjs for the composition and
// the caps, mcp-proxy/tool-baseline.mjs for the cross-call (shadowing / capability-expansion) half.
//
// ENFORCEMENT POSTURE AT THE tools/list STAGE — REPORT-FIRST, and never a mutation:
//   * A tools/list response is NEVER altered, delayed, reordered, or dropped. Byte-identity is a
//     hard contract (test/mcp-tool-stage.test.mjs asserts it on the wire), because "block" here
//     could only mean deleting a tool from the agent's list, which is a lie about what the server
//     offers and breaks clients that cache the list.
//   * A finding therefore ALERTS. Every vector-3 threat resolves through threatActionFor, whose
//     default for #60/#50 is "notify" — the house default; nothing here invents a new blocking one.
//   * Only when an org policy explicitly resolves a finding to block/kill does anything stronger
//     happen, and it happens at the NEXT surface rather than this one: the tool is QUARANTINED, and
//     the already-existing, already-tested tools/call gate refuses calls to it. Observation at list
//     time, enforcement at call time.
//
// AND — new again — SCANNING AND, WHERE POLICY SAYS SO, BLOCKING every tool RESULT (server → agent).
// A tools/list is metadata; a tool RESULT is the content the agent actually ingests, and it was the
// one direction this proxy had no eyes on at all. See "THE RESULT STAGE" below for the defect as it
// was measured, why the stage is "file", what "block" can and cannot prevent once a tool has already
// run, and — the crux — how the fail-open guarantee survives inverting write-first into
// parse-then-forward. Report-first here too: the default policy resolves #39 to "notify" and forwards.
//
// All other JSON-RPC traffic (initialize, notifications, server→client requests) passes through
// verbatim.
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
import { buildEngine, mcpGateway, decideText, literacyTouchpoint, loadVerifiedPolicy, ratchetPosture, readRootOwned, readText, POSTURE_STATE, POSTURE_LATCH, POSTURE_LEGACY, SYSTEM_POSTURE } from "../cli/hook-core.mjs";
import { CAPS, toolsOfResponse, toolScanText, toolIdentity, resultOfResponse, resultScanText } from "./tool-scan.mjs";
import { loadBaseline, saveBaseline, driftSignals, recordTool } from "./tool-baseline.mjs";
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

// Responses from the real server → Claude Desktop. See "THE RESULT STAGE" below for why this is now a
// parse-THEN-forward framer rather than the write-first copy it used to be, and for the deadline that
// keeps fail-open true across that inversion. A throw escaping the framer forwards the raw chunk.
child.stdout.on("data", (chunk) => { onServerChunk(chunk); });
child.stdout.on("end", () => { flushPending(); });
// The real server's diagnostics → our stderr (Claude Desktop surfaces these in its MCP logs).
child.stderr.pipe(process.stderr);

// ---- write a JSON-RPC MCP tool-error RESULT back to Claude Desktop (so the model sees a clean refusal,
// not a hang). We use the tool-result `isError` shape, NOT a protocol-level JSON-RPC error object. ----
function writeBlock(id, reason) {
  const msg = { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool call: ${reason}` }], isError: true } };
  process.stdout.write(JSON.stringify(msg) + "\n");
}

// The RESULT-side twin of writeBlock, and deliberately the SAME shape: a tool-result carrying
// `isError: true`, NOT a protocol-level JSON-RPC `error` object. A protocol error is a transport
// failure to a client — it can surface as a broken session or a retry loop — whereas an isError
// result is the documented way a tool says "this went wrong", which every MCP client already renders
// to the model as text. `reason` is a list of threat ids and category NAMES produced by decideText;
// no byte of the result it replaces appears in it, which is the whole point of replacing it.
function blockedResultLine(id, reason) {
  return JSON.stringify({
    jsonrpc: "2.0", id,
    result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool result: ${reason}` }], isError: true }
  }) + "\n";
}

function forward(rawLine) { child.stdin.write(rawLine + "\n"); }

// ---- id → tool name, so a RESULT can be attributed to the call that produced it. ----
// The result stage matches structurally and never REQUIRES this map (a result whose call we never saw
// is still scanned, just attributed to "mcp"), so the map is a label, not a correctness dependency —
// which is what lets it be bounded by simple FIFO eviction instead of by a timeout. Entries are
// deleted on use, so a well-behaved session keeps at most the in-flight calls.
const CALL_TOOL = new Map();
const MAX_CALL_TOOL = 512;
function rememberCall(id, tool) {
  if (id == null) return;
  if (CALL_TOOL.size >= MAX_CALL_TOOL) CALL_TOOL.delete(CALL_TOOL.keys().next().value);
  CALL_TOOL.set(String(id), String(tool || "mcp"));
}
function toolForId(id) {
  if (id == null) return "mcp";
  const k = String(id);
  const v = CALL_TOOL.get(k);
  if (v == null) return "mcp";
  CALL_TOOL.delete(k);
  return v;
}

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

    // Deferred enforcement from the tool stage. A tools/list finding NEVER edits the list; if — and
    // only if — org policy resolved that finding to block/kill, the tool lands here and the call is
    // refused through the same path an argument-level block already takes.
    if (QUARANTINE.has(tool)) {
      alertBlock(tool, "content", "tool metadata quarantined", argsHash);
      auditCall(tool, "deny", argsHash);
      writeBlock(msg.id, "this tool's advertised metadata was blocked by policy (MCP tool poisoning)");
      return;
    }

    if (!ENGINE) { auditCall(tool, "allow", argsHash); rememberCall(msg.id, tool); forward(rawLine); return; } // fail open: no engine

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
    rememberCall(msg.id, tool);
    forward(rawLine);
  } catch {
    // Governance, not a sandbox: any gate error must not drop the call — forward it unchanged.
    forward(rawLine);
  }
}

// ============================================================================================
// THE TOOL STAGE — observation of tools/list RESPONSES (server → agent).
// ============================================================================================
//
// Everything below runs on a COPY, after the bytes have already been forwarded. It is structurally
// incapable of blocking, delaying, dropping or rewriting a message; the worst a bug here can do is
// produce no alert. That is the fail-open contract, expressed as control flow rather than as a
// promise: there is no path from this section back to process.stdout or to child.stdin.

// Tools whose metadata resolved to a BLOCK under org policy. Empty under the default policy (#60/#50
// resolve to "notify" via threatActionFor), so this is inert unless an admin armed it. Enforcement
// lands on the next tools/call, never on the list itself.
const QUARANTINE = new Set();

const SEEN_ALERTS = new Set(); // dedup content-free tokens; a long-lived session re-lists often
const MAX_SEEN = 2048;
function seenOnce(token) {
  if (SEEN_ALERTS.has(token)) return false;
  if (SEEN_ALERTS.size >= MAX_SEEN) SEEN_ALERTS.clear();
  SEEN_ALERTS.add(token);
  return true;
}

function alertTool(toolName, { category, riskLevel, threatId = 0, hash, decision = "notify" }) {
  post({ threatId, category, riskLevel, stage: "tool", tool: `desktop:${toolName}`, decision, mcpServer: SERVER, ts: new Date().toISOString(), contentHash: hash, ...IDENTITY });
  if (riskLevel === "High" || riskLevel === "Critical" || riskLevel === "Blocked") {
    try { post({ ...literacyTouchpoint({ threatId, category, tool: `desktop:${toolName}` }), ...IDENTITY }); } catch { /* evidence, not enforcement */ }
  }
  try {
    recordAction(applyCaptureTier({
      threatId, category, riskLevel, stage: "tool", tool: `desktop:${toolName}`, decision,
      mcpServer: SERVER, ts: new Date().toISOString(), contentHash: hash, ...IDENTITY
    }, {}, (POLICY && POLICY.captureTier) || "content-free"));
  } catch { /* ledger is best-effort */ }
}

// One tools/list response. Bounded by CAPS.maxTools and by a wall-clock budget checked BETWEEN tools
// — regex execution in V8 is synchronous and cannot be interrupted mid-match, so the honest bound is
// "stop starting new work", plus the per-tool byte cap that keeps any single match small.
async function observeTools(tools) {
  if (process.env.MOORAI_TEST_TOOLSCAN_THROW) throw new Error("injected tool-scan fault (test hook)");
  await ensurePolicy();
  const deadline = Date.now() + CAPS.scanBudgetMs;
  const baseline = loadBaseline();
  let counter = 0;
  for (const t of Object.values(baseline)) if ((t.n || 0) > counter) counter = t.n || 0;
  let dirty = false;

  const limit = Math.min(tools.length, CAPS.maxTools);
  for (let i = 0; i < limit; i++) {
    if (Date.now() > deadline) break;
    const tool = tools[i];
    const name = String(tool.name);

    // (a) content scan of the metadata at the "tool" stage — the detectors that had no caller.
    if (ENGINE) {
      const d = decideText(ENGINE, POLICY, toolScanText(tool), "tool");
      for (const f of d.findings) {
        if (!seenOnce(`${name}|${f.threatId}|${f.category}`)) continue;
        alertTool(name, {
          threatId: f.threatId, category: f.category,
          riskLevel: d.decision === "deny" ? "Blocked" : f.riskLevel,
          hash: contentHash(f.match || ""),
          decision: d.decision === "deny" ? "quarantine" : "notify"
        });
      }
      // Report-first: only an explicit org block/kill escalates, and it escalates to the tools/call
      // gate rather than to touching this response.
      if (d.decision === "deny") QUARANTINE.add(name);
    }

    // (b) cross-call drift — shadowing across servers, capability expansion / rug-pull on one server.
    const cur = toolIdentity(tool, SERVER);
    for (const sig of driftSignals(baseline[cur.key], cur)) {
      if (!seenOnce(sig.token)) continue;
      alertTool(name, { category: sig.category, riskLevel: sig.riskLevel, hash: sig.token });
    }
    recordTool(baseline, cur, ++counter);
    dirty = true;
  }
  if (dirty) saveBaseline(baseline);
}

// ============================================================================================
// THE RESULT STAGE — the content a tool RETURNS, which the agent INGESTS, and which this proxy
// could not see at all until now.
// ============================================================================================
//
// THE DEFECT, measured before a line was written. The old observer skipped every line that did not
// contain the substring `"tools"`, and toolsOfResponse required `result.tools` — so the ONLY thing
// ever inspected on the server→agent direction was a tool LISTING. Reproduced against a child server
// that returns a secret regardless of its arguments:
//
//     ARGS sent (benign path only):       {path:'/home/u/creds/.env'}
//     agent received the secret verbatim: true
//     alerts raised by the proxy:         []
//
// That is exactly the two misses in mcp-proxy/measure-mcp-coverage.mjs condition B (read-dotenv,
// bash-cat-creds): a credential READ carries only a path in its arguments, so nothing incriminating
// exists until the RESULT comes back.
//
// WHAT "BLOCK" MEANS HERE, stated precisely so it is not oversold. By the time a result exists the
// tool has already run — the file has already been read, and no proxy can un-read it. Blocking the
// result prevents the secret from entering the AGENT'S CONTEXT, and therefore from being summarised,
// quoted, or shipped onward to the next tool call. That is the harm this stage exists to stop; it is
// not, and is not claimed to be, prevention of the read itself. The CALL-side gate above is the one
// that prevents execution.
//
// STAGE: "file". Measured on this repo's own engine, not assumed:
//     stage    DOTENV fixture        an injected directive in a result
//     file     #39 Critical          #3 Critical, #40, #55, #60
//     output   #39 Critical          #17 High, #55, #40      (no Critical #3)
// Both catch the secret; only "file" catches result-borne injection as Critical, and "file" is the
// SAME stage cli/moorai-hook.mjs uses when Claude Code reads a file — so one org policy resolves
// identically on both surfaces instead of needing a second, parallel rule set.
//
// ---- HOW FAIL-OPEN SURVIVES PARSE-THEN-FORWARD ----
//
// The old ordering (`process.stdout.write(chunk)` first, observe a copy second) WAS the fail-open
// guarantee: a bug downstream could not touch the transport because the bytes had already left. That
// ordering also makes blocking impossible, so it is gone. Fail-open is now four explicit properties
// instead of one accident of ordering:
//
//   1. EXACTLY-ONCE WRITE. gateResult() holds a `done` latch and a `pass()` that forwards the
//      ORIGINAL bytes. Every early return, every catch, and the deadline all funnel through it, so a
//      line is written once and only once, and the fallback is always the untouched original.
//   2. A HARD PER-MESSAGE DEADLINE (CAPS.resultDeadlineMs). The decision races an unref'd timer;
//      losing the race forwards the original. This is what bounds the ASYNC hazards — a policy
//      refresh, a starved microtask queue, any await a later change introduces.
//   3. A SIZE CAP INSTEAD OF A TIMER FOR SYNCHRONOUS WORK. V8 cannot interrupt a running regex, so a
//      timer is not a bound on the scan itself. CAPS.maxResultBytes is: at 64 KB of composed text,
//      decideText at stage "file" measured 3.8-4.2 ms warm on this repo. Over CAPS.maxLineBytes a
//      line is never parsed at all — it is streamed straight through. LESS scanning, never a delayed
//      or dropped message.
//   4. NOTHING ELSE MAY BLOCK. Only a result whose findings resolve to `deny` through the existing
//      threatActionFor is replaced. "ask" (justify) and "notify" forward, because Claude Desktop has
//      no interactive banner — the same rule the call-side gate already follows. Under the default
//      policy #39 resolves to "notify", so the default does NOT start blocking results.
//
// FRAMING is now done on BYTES, not on a decoded string. The old path needed a StringDecoder because
// it decoded arbitrary chunks; splitting on the 0x0a byte cannot split a multi-byte character (no
// UTF-8 continuation byte is 0x0a), so a line is decoded only once it is whole. Every write goes
// through one ordered queue, so lines cannot be reordered, merged, or split.

const EMPTY = Buffer.alloc(0);
let obsQueue = Promise.resolve(); // the OFF-path tools/list observation chain (see the bottom of this file)
let outPending = EMPTY;   // bytes of the current, incomplete line
let outRaw = false;       // this line blew past maxLineBytes: stream it through raw until its newline
let outQueue = Promise.resolve(); // ONE ordered write queue; nothing writes to stdout outside it

function emitRaw(buf) { outQueue = outQueue.then(() => { process.stdout.write(buf); }, () => {}); }
function emitLine(buf) { outQueue = outQueue.then(() => gateResult(buf), () => gateResult(buf)); }

// Newline framing of the child's stdout. `emitted` exists so the outer catch cannot double-write: if
// nothing has gone out yet the whole chunk is forwarded raw, and if something has, the framer state is
// reset rather than the already-sent bytes repeated.
function onServerChunk(chunk) {
  let emitted = false;
  try {
    // Test hook for a SYNCHRONOUS framer fault — the fault class that the old write-first ordering
    // made unreachable, and that a parse-then-forward design has to answer for explicitly. Placed
    // before any emit so the fallback below is exactly-once. Inert unless the env var is set.
    if (process.env.MOORAI_TEST_OBSERVE_THROW) throw new Error("injected synchronous observer fault (test hook)");
    let buf = chunk;
    if (outRaw) {
      const nl = buf.indexOf(0x0a);
      if (nl < 0) { emitted = true; emitRaw(buf); return; }
      emitted = true; emitRaw(buf.subarray(0, nl + 1));
      outRaw = false;
      buf = buf.subarray(nl + 1);
      if (!buf.length) return;
    }
    if (outPending.length) buf = Buffer.concat([outPending, buf]);
    let start = 0, nl;
    while ((nl = buf.indexOf(0x0a, start)) >= 0) {
      emitted = true;
      emitLine(buf.subarray(start, nl + 1)); // the newline travels WITH the line: framing is preserved by construction
      start = nl + 1;
    }
    const rest = buf.subarray(start);
    if (rest.length > CAPS.maxLineBytes) {
      // A line with no newline in sight, past the cap. Buffering further is exactly what a hostile
      // server wants; forward what we have and pass the remainder through raw. Unscanned, never stuck.
      outRaw = true; outPending = EMPTY; emitted = true; emitRaw(Buffer.from(rest));
    } else outPending = rest.length ? Buffer.from(rest) : EMPTY;
  } catch {
    if (!emitted) emitRaw(chunk);
    outPending = EMPTY; outRaw = false;
  }
}

// The child died mid-line. A partial line is not a message, but withholding bytes is not this file's
// job — forward whatever is buffered.
function flushPending() {
  if (outPending.length) { const p = outPending; outPending = EMPTY; emitRaw(p); }
}

// Race any decision against an unref'd timer. Resolves to `null` on timeout OR on rejection, and the
// single caller treats null as "forward the original". unref() so a pending timer can never be the
// reason this process outlives its stdio.
function withDeadline(promise, ms) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } };
    const timer = setTimeout(() => { if (!settled) { settled = true; resolve(null); } }, ms);
    if (timer.unref) timer.unref();
    promise.then(finish, () => finish(null));
  });
}

// The sliding overload window described at CAPS.resultBudgetMs. Not a kill switch: it goes quiet only
// while the window is hot, and says so once, content-free.
let winStart = 0, winSpent = 0, winSaid = false;
function budgetOk() {
  const now = Date.now();
  if (now - winStart > CAPS.resultWindowMs) { winStart = now; winSpent = 0; }
  return winSpent < CAPS.resultBudgetMs;
}

async function scanResult(result) {
  if (process.env.MOORAI_TEST_RESULTSCAN_THROW) throw new Error("injected result-scan fault (test hook)");
  // Test hook for an ASYNC stall — the fault class CAPS.resultDeadlineMs exists for, and the only way
  // to exercise it deterministically. A synchronous hang cannot be simulated OR survived; that is what
  // CAPS.maxResultBytes bounds instead, and it is stated as such. Inert unless the env var is set.
  const stallMs = Number(process.env.MOORAI_TEST_RESULT_STALL_MS || 0);
  if (stallMs > 0) await new Promise((r) => setTimeout(r, stallMs));
  // No engine → forward. A refresh is KICKED OFF but never awaited: loadVerifiedPolicy does network
  // I/O, and awaiting it here would put a remote server's latency on the agent's transport. By the
  // time any tools/call result exists, handleLine has already awaited ensurePolicy for that call.
  if (!ENGINE) { ensurePolicy(); return null; }
  if (!budgetOk()) {
    if (!winSaid) { winSaid = true; reportOnce("Result scanning throttled (overload window)", "result:budget:throttled", "Info"); }
    return null;
  }
  const text = resultScanText(result);
  if (!text) return null;
  const t0 = Date.now();
  const d = decideText(ENGINE, POLICY, text, "file");
  winSpent += Date.now() - t0;
  return d;
}

// NOT deduped through seenOnce, unlike the tool stage, and the difference is deliberate: a tool's
// advertised metadata is a standing PROPERTY (re-listed constantly, worth reporting once), whereas a
// result is an EVENT — the second time a credential file crosses this boundary is a second exfiltration
// opportunity, not a repeat of the first.
function alertResult(toolName, findings, blocked) {
  for (const f of findings || []) {
    const hash = contentHash(f.match || "");
    const riskLevel = blocked ? "Blocked" : f.riskLevel;
    const decision = blocked ? "deny" : "notify";
    post({ threatId: f.threatId, category: f.category, riskLevel, stage: "result", tool: `desktop:${toolName}`, decision, mcpServer: SERVER, ts: new Date().toISOString(), contentHash: hash, ...IDENTITY });
    if (blocked || f.riskLevel === "High" || f.riskLevel === "Critical") {
      try { post({ ...literacyTouchpoint({ threatId: f.threatId, category: f.category, tool: `desktop:${toolName}` }), ...IDENTITY }); } catch { /* evidence, not enforcement */ }
    }
    try {
      recordAction(applyCaptureTier({
        threatId: f.threatId, category: f.category, riskLevel, stage: "result", tool: `desktop:${toolName}`,
        decision, mcpServer: SERVER, ts: new Date().toISOString(), contentHash: hash, ...IDENTITY
      }, {}, (POLICY && POLICY.captureTier) || "content-free"));
    } catch { /* ledger is best-effort */ }
  }
}

// ONE message from the child. Exactly one write happens, and the default is always the original bytes.
async function gateResult(lineBuf) {
  let done = false;
  const pass = () => { if (!done) { done = true; process.stdout.write(lineBuf); } };
  try {
    // Over the line cap: never parsed, never buffered further — forwarded and declared unscanned.
    if (lineBuf.length > CAPS.maxLineBytes) return pass();
    const s = lineBuf.toString("utf8");
    if (!s.trim() || s.indexOf("\"result\"") < 0) return pass(); // only a RESPONSE can carry either stage's payload
    let msg;
    try { msg = JSON.parse(s); } catch { return pass(); }

    // The tool stage is unchanged and stays FORWARD-FIRST: a tools/list response is never altered,
    // delayed or reordered (test/mcp-tool-stage.test.mjs asserts byte-identity on the wire), so it is
    // written before the observation is queued and the observation is structurally unable to block.
    const tools = toolsOfResponse(msg);
    if (tools) { pass(); queueToolObservation(tools); return; }

    const result = resultOfResponse(msg);
    if (!result) return pass();

    const verdict = await withDeadline(scanResult(result), CAPS.resultDeadlineMs);
    if (!verdict || !verdict.findings.length) return pass();

    // Report-first. Only an explicit block/kill resolution refuses; the house default for #39 is
    // "notify", so an unconfigured device reports and forwards.
    const blocked = verdict.decision === "deny" && msg.id != null;
    const toolName = toolForId(msg.id);
    if (blocked) {
      done = true;
      process.stdout.write(blockedResultLine(msg.id, verdict.reasons.join(", ") || "policy"));
    } else pass();
    alertResult(toolName, verdict.findings, blocked);
  } catch {
    pass(); // governance, not a sandbox
  } finally {
    pass(); // belt-and-braces: no path may leave a message unwritten
  }
}

// ---- tools/list observation backlog. This one is OFF the transport (the bytes are already gone), so
// it is the one queue where a backlog may be DROPPED rather than allowed to grow without bound. ----
let obsInFlight = 0;
function queueToolObservation(tools) {
  if (obsInFlight >= CAPS.maxQueuedObs) return; // skip a LISTING, never a result
  obsInFlight++;
  obsQueue = obsQueue.then(() => observeTools(tools)).catch(() => {}).finally(() => { obsInFlight--; });
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
