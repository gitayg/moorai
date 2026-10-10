// The PreToolUse decision for one tool call, in-process, composed ONLY from the decision functions the
// shell hook (cli/moorai-hook.mjs main()) composes — decideText, decideCredFileRead, decideFileMetadata,
// decideAgentStateWrite, extractReadPaths, decideEndpoints, mcpGateway, mcpFloor, decideEnvelope,
// threatActionFor, saferAlternativesFor from cli/hook-core.mjs; scanMcpFileArgs; egressHits — in the
// same order, with the same merge rule (deny > ask > allow, never downgrading) and the same reason text.
//
// WHY A COMPOSITION AND NOT A CALL. The hook's branch logic lives in main(), which runs at module scope
// and awaits stdin, so it cannot be imported (test/hook-tool-coverage.test.mjs reads that file as text for
// the same reason). Every detector, every policy resolution and every gate below is the hook's own
// function; what is restated here is the ORDER they are called in. test/agent-sdk-parity.test.mjs holds
// that order to the real hook process over red-team and benign payloads.
//
// WHAT IS NOT HERE — the hook steps that need per-session state on disk or a network lookup, listed in
// NOT_EVALUATED and returned on every result so a caller can see them: the runaway circuit breaker,
// session-risk escalation, cumulative deletion volume, intent alignment, learned drift, MCP server
// reputation, model escalation, honeytokens and the mask rewrite (a "mask" policy resolves to its
// fallback here, as threatActionFor does for every caller that cannot rewrite). With no policy, all of
// these are report-only in the hook too, so the verdict matches; with a policy that arms one of them,
// the hook can be stricter than this function.
import { readFileSync } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";
import { hookCore, mcpFileArgs, secretEgress, modelEndpoints, outboundUpload, serverModeLib, toolTagsLib, exceptionsLib } from "./core.mjs";

const {
  decideText, decideCredFileRead, decideFileMetadata, decideAgentStateWrite, isEnvTemplate, fileScanText,
  decideEndpoints, decideEnvelope, threatActionFor, extractReadPaths, mcpGateway, mcpFloor,
  saferAlternativesFor, PS_OUTBOUND_UPLOAD, evaluateProfile, rejectedAlert, readRootOwned
} = hookCore;
const { systemConfigPath } = serverModeLib;
const { scanMcpFileArgs } = mcpFileArgs;
const { egressHits } = secretEgress;
const { extractHosts } = modelEndpoints;
const { OUTBOUND_UPLOAD } = outboundUpload;
const { callTags, tagGate, applyTagGate, tagHitAlert } = toolTagsLib;
const { readExceptionStore, liveExceptions, matchExceptions, applyExceptions, subjectOf } = exceptionsLib;

const RANK = { allow: 1, ask: 2, deny: 3 };
export const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
export const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
// Cursor's alias, as the hook maps it (TOOL_ALIASES).
const TOOL_ALIASES = { Shell: "Bash" };
export const NOT_EVALUATED = Object.freeze(["circuit-breaker", "session-risk", "deletion-volume", "intent-alignment", "learned-drift", "mcp-reputation", "model-escalation", "honeytokens", "mask-rewrite", "tag-rules"]);
const FILE_CAP = 262144;

function readFileCapped(fp) {
  try { if (!fp) return ""; return fileScanText(readFileSync(fp).subarray(0, FILE_CAP)); } catch { return ""; }
}
function agentPath(p, cwd) {
  if (typeof p !== "string" || !p || isAbsolute(p) || p.startsWith("~") || typeof cwd !== "string" || !cwd) return p;
  return resolve(cwd, p);
}
function writeText(tool, ti) {
  if (tool === "Write") return typeof ti.content === "string" ? ti.content : "";
  if (tool === "Edit") return typeof ti.new_string === "string" ? ti.new_string : "";
  if (tool === "NotebookEdit") return typeof ti.new_source === "string" ? ti.new_source : "";
  if (tool === "MultiEdit") return (Array.isArray(ti.edits) ? ti.edits : []).map((e) => (e && typeof e.new_string === "string" ? e.new_string : "")).join("\n");
  return "";
}
const tagged = (findings, stage) => findings.map((f) => ({ ...f, stage }));

// Side gates the hook reports as their own alerts. Each returns the hook's verdict and pushes a
// content-free signal (names and hashes only) for the caller to report.
function envelopeBlocks(policy, ctx, actor, stage, signals) {
  const mode = policy?.entitlementMode || "off";
  if (mode === "off") return false;
  const d = decideEnvelope(policy, { ...ctx, actor });
  if (d.elevated) signals.push({ threatId: 0, category: "JIT elevation used", riskLevel: "Info", stage, key: `elev:${d.usedGrants}` });
  if (d.inScope) return false;
  signals.push({ threatId: 64, category: "Agent entitlement drift", riskLevel: mode === "block" ? "Blocked" : "High", stage, key: `drift:${d.reasons.join("|")}`, driftReasons: d.reasons });
  return mode === "block";
}
function secretEgressBlocks(policy, text, cwd, stage, signals) {
  try {
    const hits = egressHits(text, cwd);
    if (!hits.length) return false;
    const act = threatActionFor(policy, 65);
    const block = act === "block" || act === "kill";
    signals.push({ threatId: 65, category: "Local secret value egress", riskLevel: block ? "Blocked" : "Critical", stage, key: `egress:${hits.join(".")}` });
    return block;
  } catch { return false; }
}
function endpointSignal(epD, signals) {
  signals.push({ threatId: 63, category: "Unapproved model endpoint", riskLevel: "Blocked", stage: "egress", key: `endpoint:${epD.hosts.join(",")}` });
}

// The declared workload profile step (cli/workload-profile.mjs), as the hook's profileStep runs it right
// after the circuit breaker: profiles from the verified policy and the root-owned machine-wide config only.
// Malformed profiles are signalled once per policy object for the life of the process.
const REJECT_SIGNALLED = new WeakSet();
// Re-read at most once a minute: a long-lived service keeps one parsed object, so the profile cache
// (keyed on the object) compiles its globs once per read rather than once per call.
const SYSTEM_TTL_MS = 60000;
let SYSTEM = { at: -Infinity, value: null };
function readSystemConfig() {
  if (Date.now() - SYSTEM.at < SYSTEM_TTL_MS) return SYSTEM.value;
  let value = null;
  try { const v = JSON.parse(readRootOwned(systemConfigPath()) || "null"); value = v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { value = null; }
  SYSTEM = { at: Date.now(), value };
  return value;
}
function profileGate(policy, { tool, ti, cwd, serviceId, systemConfig }, signals) {
  const r = evaluateProfile({ policy, system: systemConfig !== undefined ? systemConfig : readSystemConfig(), serviceId, cwd, tool, toolInput: ti });
  for (const a of r.alerts) { const { contentHash: key, ...rest } = a; signals.push({ ...rest, key }); }
  const ra = rejectedAlert(r.rejected);
  if (ra && policy && typeof policy === "object" && !REJECT_SIGNALLED.has(policy)) { REJECT_SIGNALLED.add(policy); const { contentHash: key, ...rest } = ra; signals.push({ ...rest, key }); }
  return r;
}

// tool: the host's tool name. toolInput: its arguments. cwd: the agent's working directory (relative
// paths resolve against it, as in the hook). actor: the workload's actor hash (entitlement JIT grants).
// serviceId: the workload name a profile's match.serviceId is compared with. systemConfig: the parsed
// machine-wide config (tests); omitted, the root-owned /etc/moorai/config.json is read.
// The hook's two per-call policy layers around the branch verdict, as its main() and emit() apply them:
// the exceptions that cover this call (cli/exceptions.mjs — console policy, and the root-owned local store
// when the policy switches local exceptions on) decide the policy the branches run under, and the static
// tag actions (cli/tool-tags.mjs) apply to the verdict, the stricter winning. Tag RULES need the session's
// earlier calls and are not evaluated here (NOT_EVALUATED "tag-rules").
export function decideToolCall(engine, policy, opts = {}) {
  const tool = TOOL_ALIASES[opts.tool] || String(opts.tool || "");
  const ti = opts.toolInput && typeof opts.toolInput === "object" ? opts.toolInput : {};
  const sys = opts.systemConfig !== undefined ? opts.systemConfig : readSystemConfig();
  let exc = { threats: new Set(), rules: new Set() };
  try { exc = matchExceptions(liveExceptions({ policy, system: sys, store: readExceptionStore(), enrolled: true }).live, subjectOf({ tool, toolInput: ti, cwd: opts.cwd })); } catch { /* no exception applies */ }
  const v = decideBranch(engine, applyExceptions(policy, exc.threats), { ...opts, systemConfig: sys });
  try {
    const tags = callTags({ tool: v.tool, toolInput: ti, cwd: opts.cwd || "", findingIds: v.findings.filter((f) => f.stage === "file").map((f) => f.threatId) });
    const gate = tagGate({ policy, system: sys, tags: tags.tags, inferred: tags.inferred, exceptedRules: [...exc.rules], rules: false });
    for (const h of gate.hits) { const { contentHash: key, ...rest } = tagHitAlert(h); v.signals.push({ ...rest, key }); }
    const m = applyTagGate({ decision: v.decision, reason: v.reason, alternatives: v.alternatives }, gate);
    if (m.changed) Object.assign(v, { decision: m.decision, reason: m.reason, alternatives: m.alternatives, evaluated: true, tags: tags.tags });
    else v.tags = tags.tags;
  } catch { /* tags are a policy layer; a failure leaves the branch verdict */ }
  return v;
}
function decideBranch(engine, policy, { tool: rawTool = "", toolInput, cwd, actor = "", serviceId = "", systemConfig } = {}) {
  const tool = TOOL_ALIASES[rawTool] || String(rawTool || "");
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  const base = cwd || process.cwd();
  const signals = [];
  const out = (decision, reason, alternatives, findings, extra = {}) => ({ tool, decision, reason, alternatives: alternatives || [], findings, signals, kill: false, killIds: [], evaluated: true, notEvaluated: NOT_EVALUATED, ...extra });
  const wp = profileGate(policy, { tool, ti, cwd, serviceId, systemConfig }, signals);
  if (wp.decision === "deny") return out("deny", wp.reason, [], [], { ...(wp.profile ? { profileId: wp.profile.id } : {}), driftKinds: wp.kinds, reasonCode: wp.reasonCode });

  if (tool === "Read") {
    const text = readFileCapped(agentPath(ti.file_path, cwd));
    const d = decideText(engine, policy, text, "file", { ctx: { template: isEnvTemplate(ti.file_path) } });
    const pd = decideCredFileRead(engine, policy, ti.file_path);
    d.findings.push(...pd.findings);
    if (pd.kill) { d.kill = true; d.killIds.push(...pd.killIds); }
    if (RANK[pd.decision] > RANK[d.decision]) { d.decision = pd.decision; d.reasons = pd.reasons; d.alternatives = pd.alternatives; }
    const md = decideFileMetadata(engine, policy, agentPath(ti.file_path, cwd));
    d.findings.push(...md.findings);
    if (md.kill) { d.kill = true; d.killIds.push(...md.killIds); }
    if (RANK[md.decision] > RANK[d.decision]) { d.decision = md.decision; d.reasons = md.reasons; d.alternatives = md.alternatives; }
    let rdec = d.decision, ralts = d.alternatives;
    if (envelopeBlocks(policy, { tool: "Read", paths: [ti.file_path] }, actor, "file", signals) && rdec !== "deny") { rdec = "deny"; ralts = saferAlternativesFor([64]); }
    return out(rdec, `${d.kill ? "killed session" : "blocked Read"} of ${basename(ti.file_path || "file")} — ${d.reasons.join(", ")}`, ralts, tagged(d.findings, "file"), { kill: d.kill, killIds: d.killIds });
  }

  if (SHELL_TOOLS.has(tool)) {
    let dec = "allow", reasons = [], alts = [];
    const finds = [], killIds = [];
    const ps = tool === "PowerShell";
    const command = typeof ti.command === "string" ? ti.command : "";
    const readPaths = extractReadPaths(ti.command, ps ? { shell: "powershell" } : undefined);
    const uploading = OUTBOUND_UPLOAD.some((r) => r.test(command)) || (ps && PS_OUTBOUND_UPLOAD.some((r) => r.test(command)));
    const cmdEgress = uploading || extractHosts(command).length > 0;
    const merge = (d) => {
      finds.push(...d.findings);
      if (d.kill) killIds.push(...d.killIds);
      if (RANK[d.decision] > RANK[dec]) { dec = d.decision; reasons = d.reasons; alts = d.alternatives; }
    };
    for (const p of readPaths) {
      merge(decideText(engine, policy, readFileCapped(agentPath(p, cwd)), "file", { ctx: { template: isEnvTemplate(p), egress: uploading } }));
      merge(decideFileMetadata(engine, policy, agentPath(p, cwd)));
      if (ps) merge(decideCredFileRead(engine, policy, p));
    }
    merge(decideText(engine, policy, ti.command, "prompt", { ctx: { egress: cmdEgress } }));
    const epD = decideEndpoints(policy, ti.command);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; alts = saferAlternativesFor([63]); endpointSignal(epD, signals); }
    if (secretEgressBlocks(policy, ti.command, cwd, "egress", signals) && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; alts = saferAlternativesFor([65]); }
    if (envelopeBlocks(policy, { tool: "Bash", paths: readPaths }, actor, "file", signals) && dec !== "deny") { dec = "deny"; reasons = ["out-of-envelope (entitlement drift)"]; alts = saferAlternativesFor([64]); }
    return out(dec, `${killIds.length ? "killed session" : "blocked"} via ${tool} — ${reasons.join(", ")}`, alts, tagged(finds, "file"), { kill: killIds.length > 0, killIds });
  }

  if (WRITE_TOOLS.has(tool)) {
    const path = ti.file_path || ti.notebook_path || "";
    const text = writeText(tool, ti);
    const d = decideText(engine, policy, text, "output", { ctx: { targetPath: path } });
    let dec = d.decision, reasons = d.reasons.slice(), alts = d.alternatives;
    const sd = decideAgentStateWrite(engine, policy, path);
    d.findings.push(...sd.findings);
    if (RANK[sd.decision] > RANK[dec]) { dec = sd.decision; reasons = sd.reasons; alts = sd.alternatives; }
    if (sd.kill) { d.kill = true; d.killIds.push(...sd.killIds); }
    const epD = decideEndpoints(policy, text);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; alts = saferAlternativesFor([63]); endpointSignal(epD, signals); }
    if (secretEgressBlocks(policy, text, cwd, "file", signals) && dec === "allow") { dec = "ask"; reasons = ["local secret written to a new file"]; alts = saferAlternativesFor([65]); }
    if (envelopeBlocks(policy, { tool, paths: [path] }, actor, "file", signals) && dec !== "deny") { dec = "deny"; reasons = ["out-of-envelope (entitlement drift)"]; alts = saferAlternativesFor([64]); }
    return out(dec, `${d.kill ? "killed session" : dec === "ask" ? "needs justification" : "blocked"} ${tool} of ${basename(path || "file")} — ${reasons.join(", ")}`, alts, tagged(d.findings, "output"), { kill: d.kill, killIds: d.killIds });
  }

  if (tool === "WebFetch") {
    const url = typeof ti.url === "string" ? ti.url : "";
    const prompt = typeof ti.prompt === "string" ? ti.prompt : "";
    const d = decideText(engine, policy, `${url}\n${prompt}`, "prompt", { ctx: { egress: true } });
    let dec = d.decision, reasons = d.reasons.slice(), alts = d.alternatives;
    const epD = decideEndpoints(policy, url);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; alts = saferAlternativesFor([63]); endpointSignal(epD, signals); }
    if (secretEgressBlocks(policy, `${url}\n${prompt}`, cwd, "egress", signals) && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; alts = saferAlternativesFor([65]); }
    if (envelopeBlocks(policy, { tool: "WebFetch" }, actor, "egress", signals) && dec !== "deny") { dec = "deny"; reasons = ["out-of-envelope (entitlement drift)"]; alts = saferAlternativesFor([64]); }
    return out(dec, `${d.kill ? "killed session" : dec === "ask" ? "needs justification" : "blocked"} WebFetch — ${reasons.join(", ")}`, alts, tagged(d.findings, "egress"), { kill: d.kill, killIds: d.killIds });
  }

  if (tool.startsWith("mcp__")) {
    const server = tool.split("__")[1] || "";
    const args = JSON.stringify(ti);
    const g = mcpGateway(engine, policy, { tool, server, args });
    if (g.gate === "server") { signals.push({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", key: `mcp-server:${server}` }); return out("deny", g.reason, saferAlternativesFor([25]), []); }
    if (g.gate === "args") { signals.push({ threatId: 0, category: "MCP: denied tool argument", riskLevel: "Blocked", stage: "mcp", key: `mcp-args:${tool}` }); return out("deny", g.reason, [], []); }
    if (envelopeBlocks(policy, { tool, mcpServer: server }, actor, "egress", signals)) return out("deny", `${tool} — out-of-envelope MCP server`, saferAlternativesFor([64]), []);
    const epD = decideEndpoints(policy, args);
    if (epD.decision === "deny") { endpointSignal(epD, signals); return out("deny", epD.reason, saferAlternativesFor([63]), []); }
    if (secretEgressBlocks(policy, args, cwd, "egress", signals)) return out("deny", `${tool} — local secret egress`, saferAlternativesFor([65]), []);
    const fsr = scanMcpFileArgs(engine, policy, { tool, args: ti, bases: [typeof cwd === "string" && cwd ? cwd : base], argIds: g.findings.map((f) => f.threatId) });
    if (RANK[fsr.decision] > RANK[g.decision]) { g.decision = fsr.decision; g.reason = fsr.reasons.join(", "); g.alternatives = fsr.alternatives; }
    else if (fsr.decision !== "allow" && fsr.decision === g.decision) g.reason = [g.reason, ...fsr.reasons].filter(Boolean).join(", ");
    if (fsr.kill) { g.kill = true; g.killIds = [...(g.killIds || []), ...fsr.killIds]; }
    const floored = mcpFloor(policy, g.decision);
    if (floored !== g.decision) { g.decision = floored; g.reason = g.reason || "fail-closed default: MCP requires justification"; }
    const reasons = g.reason ? [g.reason] : [];
    return out(g.decision, `${g.kill ? "killed session" : g.decision === "ask" ? "needs justification" : "blocked"} ${tool} — ${reasons.join(", ")}`, g.alternatives, [...tagged(g.findings, "egress"), ...tagged(fsr.findings, "file")], { kill: !!g.kill, killIds: g.killIds || [], mcpServer: server });
  }

  if (tool === "Task" || tool === "Agent") {
    const act = threatActionFor(policy, 66);
    const block = act === "block" || act === "kill";
    signals.push({ threatId: 66, category: "Sub-agent / A2A delegation", riskLevel: block ? "Blocked" : "Medium", stage: "behavior", key: `task:${ti.subagent_type || ""}` });
    const pd = decideText(engine, policy, ti.prompt || "", "prompt");
    const findings = tagged(pd.findings, "egress");
    if (block || pd.decision === "deny" || envelopeBlocks(policy, { tool: "Task" }, actor, "behavior", signals)) {
      return out("deny", `Task (sub-agent delegation) — ${block ? "blocked by policy" : pd.decision === "deny" ? pd.reasons.join(", ") : "out of envelope"}`, block ? saferAlternativesFor([66]) : pd.decision === "deny" ? pd.alternatives : saferAlternativesFor([64]), findings);
    }
    return out("allow", "sub-agent delegation logged", [], findings);
  }

  // Any other tool: the hook allows it unread, and says so in its ledger.
  return out("allow", "", [], [], { evaluated: false });
}
