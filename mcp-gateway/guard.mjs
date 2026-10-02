// The per-route gate: what the stdio proxy (mcp-proxy/moorai-mcp-guard.mjs) does to each JSON-RPC
// message, minus the stdio transport. One guard per route (= one remote MCP server label).
//
//   gateCall(msg)        a tools/call REQUEST → { block: null } (forward) or { block: "<reason>" }
//   observeTools(tools)  a tools/list RESULT  → never alters it; alerts, baseline drift, quarantine
//   gateResult(msg,tool) any other RESULT     → null (forward the original) or a replacement message
//
// Order for a call, same as the proxy and the hook's mcp__* branch: quarantine (a tool whose metadata
// policy blocked) → reputation threshold → mcpGateway (server allow-list → per-tool argument rules →
// argument content scan) → local secret egress (#65, the hook's check; the stdio proxy has none) →
// files the arguments name (opt-in per route: only meaningful when the gateway shares a disk with them).
//
// Fail-open, like the proxy: no engine, a thrown check, or a result scan past its deadline forwards the
// original. Only an explicit deny under an enforcing device refuses; "ask" forwards (no banner exists)
// except in server mode, where the hook's headless rule settles it (deny unless policy says
// allow-with-report).
import { fileURLToPath } from "node:url";
import { mcpGateway, decideText, threatActionFor } from "../cli/hook-core.mjs";
import { CAPS, toolScanText, toolIdentity, resultOfResponse, resultScanText } from "../mcp-proxy/tool-scan.mjs";
import { loadBaseline, saveBaseline, driftSignals, recordTool } from "../mcp-proxy/tool-baseline.mjs";
import { scanMcpFileArgs } from "../cli/mcp-file-args.mjs";
import { egressHits } from "../cli/secret-egress.mjs";
import { assessServer, addToolSignals } from "../cli/mcp-reputation.mjs";
import { reputationAction, reputationAlert, reputationSummary } from "../data/mcp-reputation.js";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { contentHash } from "../cli/content-hash.mjs";
import { state, ensurePolicy } from "./policy.mjs";
import { IDENTITY, SERVER_MODE, post, reportOnce, seenOnce, coachNote, auditCall, alertBlock, alertFindings, alertEgress, alertTool, alertResult, alertHeadless, recordLedger } from "./report.mjs";

const RANK = { allow: 1, ask: 2, deny: 3 };

export function withDeadline(promise, ms) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => { if (!settled) { settled = true; resolve(null); } }, ms);
    if (timer.unref) timer.unref();
    promise.then((v) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } }, () => { if (!settled) { settled = true; clearTimeout(timer); resolve(null); } });
  });
}

// The proxy's overload window for result scanning, shared by every route of this process.
let winStart = 0, winSpent = 0, winSaid = false;
function budgetOk() {
  const now = Date.now();
  if (now - winStart > CAPS.resultWindowMs) { winStart = now; winSpent = 0; }
  return winSpent < CAPS.resultBudgetMs;
}

// tools/list observations run off the request path, serialized (the baseline file is shared).
let obsQueue = Promise.resolve();
let obsInFlight = 0;

function toPath(r) {
  try { return /^file:/i.test(r) ? fileURLToPath(r) : r; } catch { return null; }
}

export function createGuard(route) {
  const SERVER = route.server;
  const QUARANTINE = new Set();
  const cfgRoots = route.roots.map(toPath).filter(Boolean);
  let clientRoots = [];
  const REP_DECL = { url: route.url };
  let REP = null;
  let REP_READY = null;

  const repPolicy = () => { const p = state.POLICY && state.POLICY.mcpReputation; return p && typeof p === "object" ? p : {}; };
  function reportReputation(rep) {
    const action = reputationAction(rep, repPolicy(), { enforce: !state.COACH });
    if (action === "allow") return;
    if (state.COACH) coachNote(`MCP server ${SERVER}`, `reputation ${reputationSummary(rep)}`);
    const alert = { ...reputationAlert(rep, { server: SERVER, decision: action, identityHash: contentHash(`mcp-reputation:${rep.key}`), tool: "gateway:mcp" }), ...IDENTITY };
    post(alert);
    recordLedger(alert);
  }
  function startReputation() {
    REP_READY = ensurePolicy()
      .then(() => assessServer(REP_DECL, { policy: repPolicy(), engine: state.ENGINE || undefined }))
      .then((rep) => { REP = rep; if (rep.firstSeen || rep.versionChanged) reportReputation(rep); return rep; })
      .catch(() => null);
    return REP_READY;
  }
  async function reputationBlocks() {
    const rp = repPolicy();
    if (rp.enabled === false || !(Number(rp.blockBelow) > 0)) return null;
    if (!REP && REP_READY) await withDeadline(REP_READY, 3000);
    if (!REP) return null;
    const action = reputationAction(REP, rp, { enforce: !state.COACH });
    if (action === "coach") { if (seenOnce(`rep-coach:${SERVER}:${REP.score}`)) coachNote(`calls to MCP server ${SERVER}`, `reputation ${reputationSummary(REP)} is below the org threshold`); return null; }
    if (action !== "block") return null;
    if (seenOnce(`rep-block:${SERVER}:${REP.score}`)) reportReputation(REP);
    return `this MCP server's reputation (${REP.score}/100, ${REP.band}) is below your organization's threshold`;
  }

  // The client's own roots, from its answer to a legacy roots/list request (a JSON-RPC response it
  // POSTs). Only file:// roots, at most 16; used as bases for relative file arguments.
  function rememberRoots(roots) {
    const out = [];
    for (const r of roots.slice(0, 16)) { if (r && typeof r.uri === "string" && /^file:/i.test(r.uri)) { const p = toPath(r.uri); if (p) out.push(p); } }
    clientRoots = out;
  }

  async function gateCall(msg) {
    await ensurePolicy();
    const tool = String(msg.params.name || "");
    const rawArgs = msg.params.arguments == null ? {} : msg.params.arguments;
    const args = JSON.stringify(rawArgs);
    const argsHash = contentHash(args);

    if (QUARANTINE.has(tool)) {
      alertBlock(SERVER, tool, "content", argsHash);
      auditCall(SERVER, tool, "deny", argsHash);
      return { block: "this tool's advertised metadata was blocked by policy (MCP tool poisoning)" };
    }
    const rep = await reputationBlocks();
    if (rep) { auditCall(SERVER, tool, "deny", argsHash); return { block: rep }; }
    if (!state.ENGINE) { auditCall(SERVER, tool, "allow", argsHash); return { block: null }; }

    const { POLICY, ENGINE } = state;
    const g = mcpGateway(ENGINE, POLICY, { tool, server: SERVER, args });
    const early = g.gate === "server" || g.gate === "args";

    // #65 — a local secret VALUE shipped as an argument. The hook's check, against the secrets on THIS
    // machine (cwd dotenv files, ~/.aws/credentials, ~/.npmrc, ~/.netrc, .git-credentials).
    let egress = null;
    if (!early) {
      const hits = egressHits(args);
      if (hits.length) {
        const act = threatActionFor(POLICY, 65);
        egress = { hits, block: act === "block" || act === "kill" };
        if (egress.block && g.decision !== "deny") { g.decision = "deny"; g.gate = "egress"; g.reason = `${tool} — local secret egress`; }
      }
    }

    const fsr = !early && route.localFiles
      ? scanMcpFileArgs(ENGINE, POLICY, { tool, args: rawArgs, bases: [process.cwd(), ...cfgRoots, ...clientRoots], argIds: (g.findings || []).map((f) => f.threatId) })
      : null;
    if (fsr && RANK[fsr.decision] > RANK[g.decision]) { g.decision = fsr.decision; g.gate = "file"; g.reason = fsr.reasons.join(", "); g.alternatives = fsr.alternatives; }
    else if (fsr && fsr.decision !== "allow" && fsr.decision === g.decision) g.reason = [g.reason, ...fsr.reasons].filter(Boolean).join(", ");
    const fileFindings = fsr ? fsr.findings : [];

    // Server mode: no human will answer an "ask". The hook's rule decides it (deny by default).
    if (g.decision === "ask" && SERVER_MODE.active) {
      const s = settleHeadlessAsk(SERVER_MODE, POLICY, { decision: "ask", reason: g.reason, tool });
      if (s.alert) alertHeadless(SERVER, tool, s.alert);
      g.decision = s.decision;
      if (s.decision === "deny") g.reason = s.reason;
    }

    if (state.COACH && g.decision === "deny") {
      coachNote(`MCP tool call ${tool} (server ${SERVER})`, g.reason, g.alternatives);
      if (egress) alertEgress(SERVER, tool, egress.hits, false);
      alertFindings(SERVER, tool, g.findings, false);
      alertFindings(SERVER, tool, fileFindings, false, "file");
      auditCall(SERVER, tool, "coach", argsHash);
      return { block: null };
    }
    if (g.decision === "deny") {
      alertBlock(SERVER, tool, g.gate, argsHash);
      if (egress) alertEgress(SERVER, tool, egress.hits, egress.block);
      alertFindings(SERVER, tool, g.findings, true);
      alertFindings(SERVER, tool, fileFindings, true, "file");
      auditCall(SERVER, tool, "deny", argsHash);
      return { block: g.reason || "policy" };
    }
    if (egress) alertEgress(SERVER, tool, egress.hits, false);
    alertFindings(SERVER, tool, g.findings, false);
    alertFindings(SERVER, tool, fileFindings, false, "file");
    auditCall(SERVER, tool, g.decision, argsHash);
    return { block: null };
  }

  async function observeTools(tools) {
    await ensurePolicy();
    const { POLICY, ENGINE } = state;
    const deadline = Date.now() + CAPS.scanBudgetMs;
    const baseline = loadBaseline();
    let counter = 0;
    for (const t of Object.values(baseline)) if ((t.n || 0) > counter) counter = t.n || 0;
    let dirty = false;
    const repFindings = [];
    const limit = Math.min(tools.length, CAPS.maxTools);
    for (let i = 0; i < limit; i++) {
      if (Date.now() > deadline) break;
      const tool = tools[i];
      const name = String(tool.name);
      if (ENGINE) {
        const d = decideText(ENGINE, POLICY, toolScanText(tool), "tool");
        repFindings.push(...d.findings);
        for (const f of d.findings) {
          if (!seenOnce(`${SERVER}|${name}|${f.threatId}|${f.category}`)) continue;
          alertTool(SERVER, name, {
            threatId: f.threatId, category: f.category,
            riskLevel: d.decision === "deny" && !state.COACH ? "Blocked" : f.riskLevel,
            hash: contentHash(f.match || ""),
            decision: d.decision === "deny" ? (state.COACH ? "coach" : "quarantine") : "notify"
          });
        }
        if (d.decision === "deny") { if (state.COACH) coachNote(`advertised metadata of MCP tool ${name} (server ${SERVER})`, d.reasons.join(", "), d.alternatives); else QUARANTINE.add(name); }
      }
      // Rug-pull / capability expansion / shadowing against the shared tool baseline, as the proxy does.
      const cur = toolIdentity(tool, SERVER);
      for (const sig of driftSignals(baseline[cur.key], cur)) {
        if (!seenOnce(`${SERVER}|${sig.token}`)) continue;
        alertTool(SERVER, name, { category: sig.category, riskLevel: sig.riskLevel, hash: sig.token });
      }
      recordTool(baseline, cur, ++counter);
      dirty = true;
    }
    if (dirty) saveBaseline(baseline);
    if (repFindings.length) {
      try {
        const rep = addToolSignals(REP_DECL, repFindings.map((f) => ({ threatId: f.threatId, riskLevel: f.riskLevel })));
        REP = rep;
        if (rep.changed) reportReputation(rep);
      } catch { /* reputation is evidence */ }
    }
  }

  function queueToolObservation(tools) {
    if (obsInFlight >= CAPS.maxQueuedObs) return;
    obsInFlight++;
    obsQueue = obsQueue.then(() => observeTools(tools)).catch(() => {}).finally(() => { obsInFlight--; });
  }

  async function scanResult(result) {
    if (!state.ENGINE) { ensurePolicy(); return null; }
    if (!budgetOk()) {
      if (!winSaid) { winSaid = true; reportOnce("Result scanning throttled (overload window)", "result:budget:throttled", "Info"); }
      return null;
    }
    const text = resultScanText(result);
    if (!text) return null;
    const t0 = Date.now();
    const d = decideText(state.ENGINE, state.POLICY, text, "file");
    winSpent += Date.now() - t0;
    return d;
  }

  // One server→client message. Returns a replacement message object, or null to forward the original.
  async function gateResult(msg, toolName) {
    try {
      const r = msg && msg.result;
      if (r && typeof r === "object" && Array.isArray(r.tools)) {
        const tools = r.tools.filter((x) => x && typeof x === "object" && !Array.isArray(x) && typeof x.name === "string");
        if (tools.length) queueToolObservation(tools);
        return null; // a listing is never altered
      }
      const result = resultOfResponse(msg);
      if (!result) return null;
      const verdict = await withDeadline(scanResult(result), CAPS.resultDeadlineMs);
      if (!verdict || !verdict.findings.length) return null;
      const label = toolName || "mcp";
      const blocked = !state.COACH && verdict.decision === "deny" && msg.id != null;
      if (state.COACH && verdict.decision === "deny") coachNote(`MCP tool result from ${label} (server ${SERVER})`, verdict.reasons.join(", "), verdict.alternatives);
      alertResult(SERVER, label, verdict.findings, blocked);
      if (!blocked) return null;
      return { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool result: ${verdict.reasons.join(", ") || "policy"}` }], isError: true } };
    } catch { return null; }
  }

  return { server: SERVER, gateCall, gateResult, rememberRoots, startReputation };
}

// The refusal for a CALL: the proxy's shape, an MCP tool result with isError and the request's id —
// not a JSON-RPC protocol error, which clients treat as a transport failure (retry / broken session).
export function blockedCall(id, reason) {
  return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool call: ${reason}` }], isError: true } };
}
