// The per-route gate: what the stdio proxy (mcp-proxy/moorai-mcp-guard.mjs) does to each JSON-RPC
// message, minus the stdio transport. One guard per route (= one remote MCP server label).
//
//   gateCall(msg)        a tools/call REQUEST → { block: null } (forward) or { block: "<reason>" }
//   observeTools(tools)  a tools/list RESULT  → alerts, baseline drift, quarantine; alters the list only
//                        under policy mcpToolDrift "block" (../mcp-proxy/tool-drift.mjs), and then only
//                        to leave out a quarantined tool
//   gateResult(msg,tool) any other RESULT     → null (forward the original) or a replacement message
//
// Order for a call, same as the proxy and the hook's mcp__* branch: quarantine (a tool whose metadata
// policy blocked) → reputation threshold → declared workload profile (./profile.mjs; the hook runs it
// before its tool branches) → mcpGateway (server allow-list → per-tool argument rules →
// argument content scan) → local secret egress (#65, the hook's check; the stdio proxy has none) →
// files the arguments name (opt-in per route: only meaningful when the gateway shares a disk with them) →
// a vector-store write's documents at the "index" stage (../cli/index-tools.mjs; report-first).
//
// Fail-open, like the proxy: no engine, a thrown check, or a result scan past its deadline forwards the
// original. Only an explicit deny under an enforcing device refuses; "ask" forwards (no banner exists)
// except in server mode, where the hook's headless rule settles it (deny unless policy says
// allow-with-report).
import { fileURLToPath } from "node:url";
import { mcpGateway, decideText, threatActionFor } from "../cli/hook-core.mjs";
import { CAPS, toolScanText, toolIdentity, resultOfResponse } from "../mcp-proxy/tool-scan.mjs";
import { decideInbound, inboundText } from "../cli/inbound.mjs";
import { loadBaseline, saveBaseline, driftSignals, recordTool } from "../mcp-proxy/tool-baseline.mjs";
import { createDriftTracker, toolDriftMode, reportFingerprints, policyMayBlock, TOOL_DRIFT_REASON } from "../mcp-proxy/tool-drift.mjs";
import { isEnrolled } from "../data/enforcement.js";
import { scanMcpFileArgs } from "../cli/mcp-file-args.mjs";
import { indexWriteScan } from "../cli/index-tools.mjs";
import { egressHits } from "../cli/secret-egress.mjs";
import { assessServer, addToolSignals } from "../cli/mcp-reputation.mjs";
import { reputationAction, reputationAlert, reputationSummary } from "../data/mcp-reputation.js";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { contentHash } from "../cli/content-hash.mjs";
import { state, ensurePolicy } from "./policy.mjs";
import { profileCheck } from "./profile.mjs";
import { CONFIG, IDENTITY, SERVER_MODE, post, reportOnce, seenOnce, coachNote, auditCall, alertBlock, alertFindings, alertEgress, alertTool, alertResult, alertHeadless, alertProfile, alertDriftCall, recordLedger } from "./report.mjs";

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
const DRIFT_POLICY_WAIT_MS = 2000;

function toPath(r) {
  try { return /^file:/i.test(r) ? fileURLToPath(r) : r; } catch { return null; }
}

export function createGuard(route) {
  const SERVER = route.server;
  const QUARANTINE = new Set();
  const cfgRoots = route.roots.map(toPath).filter(Boolean);
  let clientRoots = [];
  const REP_DECL = { url: route.url };
  const DRIFT = createDriftTracker({ server: SERVER });
  // Coach (unenrolled, unmanaged) never blocks, so block mode degrades to today's alert path there.
  const driftBlocking = () => !state.COACH && toolDriftMode(state.POLICY) === "block";
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
    // Block-mode tool drift: re-judged against the policy in force now, so a console re-approval
    // releases the tool without the client listing again.
    if (driftBlocking()) {
      if (!DRIFT.has(tool) && obsInFlight) await withDeadline(obsQueue, CAPS.resultDeadlineMs);
      const q = DRIFT.checkCall(tool, { policy: state.POLICY });
      if (q) {
        alertDriftCall(SERVER, tool, q.category, argsHash);
        auditCall(SERVER, tool, "deny", argsHash);
        return { block: q.reason };
      }
    }
    const rep = await reputationBlocks();
    if (rep) { auditCall(SERVER, tool, "deny", argsHash); return { block: rep }; }

    // Declared workload profile: report or block per the profile's action; coached when unenrolled.
    const wp = profileCheck({ policy: state.POLICY, server: SERVER, tool, serviceId: SERVER_MODE.active ? SERVER_MODE.serviceId : "", coach: state.COACH });
    for (const a of wp.alerts) alertProfile(SERVER, tool, a);
    if (wp.rejectedAlert && seenOnce(`profile-rejected:${wp.rejectedAlert.contentHash}`)) alertProfile(SERVER, tool, wp.rejectedAlert);
    if (wp.coach) coachNote(`MCP tool call ${tool} (server ${SERVER})`, wp.coach);
    if (wp.decision === "deny") { auditCall(SERVER, tool, "deny", argsHash); return { block: wp.reason }; }
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

    // A vector-store write (cli/index-tools.mjs: policy.indexTools or the name / argument heuristic):
    // its document arguments are content headed for an index, scanned at the "index" stage. Report-first;
    // only policy.indexScanAction "block" refuses the call. Findings the argument scan already reported
    // are not reported twice.
    const ix = !early && g.decision !== "deny" ? indexWriteScan(ENGINE, POLICY, { tool, server: SERVER, args: rawArgs }) : null;
    if (ix && ix.verdict === "deny") { g.decision = "deny"; g.gate = "index"; g.reason = `${tool} — vector-store write: ${ix.reasons.join(", ")}`; g.alternatives = []; }
    const seenIds = new Set((g.findings || []).map((f) => f.threatId));
    const indexFindings = ix ? ix.findings.filter((f) => !seenIds.has(f.threatId)) : [];

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
      alertFindings(SERVER, tool, indexFindings, false, "index");
      auditCall(SERVER, tool, "coach", argsHash);
      return { block: null };
    }
    if (g.decision === "deny") {
      alertBlock(SERVER, tool, g.gate, argsHash);
      if (egress) alertEgress(SERVER, tool, egress.hits, egress.block);
      alertFindings(SERVER, tool, g.findings, true);
      alertFindings(SERVER, tool, fileFindings, true, "file");
      alertFindings(SERVER, tool, indexFindings, g.gate === "index", "index");
      auditCall(SERVER, tool, "deny", argsHash);
      return { block: g.reason || "policy" };
    }
    if (egress) alertEgress(SERVER, tool, egress.hits, false);
    alertFindings(SERVER, tool, g.findings, false);
    alertFindings(SERVER, tool, fileFindings, false, "file");
    alertFindings(SERVER, tool, indexFindings, false, "index");
    auditCall(SERVER, tool, g.decision, argsHash);
    return { block: null };
  }

  // Judge one listing in block mode → { changed, names } or null when it could not run.
  function judgeListing(tools, shape) {
    try {
      const ev = DRIFT.evaluateListing(tools, { policy: state.POLICY, ...shape });
      for (const q of ev.quarantined) {
        for (const sig of q.signals) {
          if (!seenOnce(`${SERVER}|quarantine|${sig.token}`)) continue;
          alertTool(SERVER, q.name, { category: sig.category, riskLevel: sig.riskLevel, hash: sig.token, decision: "quarantine", reasonCode: TOOL_DRIFT_REASON });
        }
      }
      for (const sig of ev.removed) {
        if (seenOnce(`${SERVER}|${sig.token}`)) alertTool(SERVER, "mcp", { category: sig.category, riskLevel: sig.riskLevel, hash: sig.token, decision: "notify", reasonCode: TOOL_DRIFT_REASON });
      }
      reportFingerprints({ config: CONFIG, server: SERVER, fingerprints: ev.fingerprints, enrolled: isEnrolled(CONFIG), actor: IDENTITY.actor });
      return { changed: ev.changed, names: new Set(ev.quarantined.map((q) => q.name)) };
    } catch { try { DRIFT.invalidate(); } catch { /* nothing to clear */ } return null; }
  }

  // Block mode for a listing about to be forwarded. A gateway that has not loaded a policy yet waits
  // for one up to DRIFT_POLICY_WAIT_MS when its last policy said "block" (tool-drift.mjs
  // policyMayBlock); otherwise, or past the wait, the listing goes unjudged and the off-path
  // observation judges it when the policy arrives (the call gate enforces; the list is not filtered).
  async function listBlocking() {
    if (!state.loadedAt) { if (!policyMayBlock()) return false; await withDeadline(ensurePolicy(), DRIFT_POLICY_WAIT_MS); }
    else ensurePolicy();
    return Boolean(state.loadedAt) && driftBlocking();
  }

  async function observeTools(tools, { driftDone = false, shape = { complete: false } } = {}) {
    await ensurePolicy();
    if (!driftDone && driftBlocking()) { judgeListing(tools, shape); driftDone = true; }
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
      // Alert mode only: block mode judged it above and never re-baselines a drifted tool.
      if (driftDone) continue;
      const cur = toolIdentity(tool, SERVER);
      DRIFT.observe(name, cur);
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

  function queueToolObservation(tools, opts) {
    if (obsInFlight >= CAPS.maxQueuedObs) return;
    obsInFlight++;
    obsQueue = obsQueue.then(() => observeTools(tools, opts)).catch(() => {}).finally(() => { obsInFlight--; });
  }

  async function scanResult(result) {
    if (!state.ENGINE) { ensurePolicy(); return null; }
    if (!budgetOk()) {
      if (!winSaid) { winSaid = true; reportOnce("Result scanning throttled (overload window)", "result:budget:throttled", "Info"); }
      return null;
    }
    const text = inboundText(result);
    if (!text) return null;
    const t0 = Date.now();
    const d = decideInbound(state.ENGINE, state.POLICY, text, { surface: "door", stage: "file" });
    winSpent += Date.now() - t0;
    return d;
  }

  // One server→client message. Returns a replacement message object, or null to forward the original.
  // `paged`: the request asked for a later page, so an absent tool is not a removed one.
  async function gateResult(msg, toolName, { paged = false } = {}) {
    try {
      const r = msg && msg.result;
      if (r && typeof r === "object" && Array.isArray(r.tools)) {
        const tools = r.tools.filter((x) => x && typeof x === "object" && !Array.isArray(x) && typeof x.name === "string");
        if (!tools.length) return null;
        const last = r.nextCursor == null;
        const shape = { complete: !paged && last, continued: paged, last };
        // Alert mode (the default): a listing is never altered. Block mode: a quarantined tool is left
        // out of it; with nothing quarantined the original still goes.
        if (await listBlocking()) {
          const ev = judgeListing(tools, shape);
          queueToolObservation(tools, { driftDone: true, shape });
          if (!ev || !ev.changed) return null;
          return { ...msg, result: { ...r, tools: r.tools.filter((x) => !(x && typeof x === "object" && typeof x.name === "string" && ev.names.has(x.name))) } };
        }
        queueToolObservation(tools, { shape });
        return null;
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

  // A tools/list response this route forwarded without judging it (over CAPS.maxLineBytes, JSON or SSE):
  // no earlier verdict may vouch for a tool it advertised, so calls are refused as not in a checked
  // listing until a listing is judged again (../mcp-proxy/tool-drift.mjs invalidate).
  function listingUnjudged() { try { DRIFT.invalidate(); } catch { /* governance, not a sandbox */ } }

  return { server: SERVER, gateCall, gateResult, rememberRoots, startReputation, listingUnjudged };
}

// The refusal for a CALL: the proxy's shape, an MCP tool result with isError and the request's id —
// not a JSON-RPC protocol error, which clients treat as a transport failure (retry / broken session).
export function blockedCall(id, reason) {
  return { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `MoorAI blocked this MCP tool call: ${reason}` }], isError: true } };
}
