// The PreToolUse decision for one tool call, in-process, composed ONLY from the decision functions the
// shell hook (cli/moorai-hook.mjs main()) composes — decideText, decideCredFileRead, decideFileMetadata,
// decideAgentStateWrite, decideAuthorizedKeysWrite, decodedCommandPayloads, decideTransit, decideThreat,
// extractReadPaths, decideEndpoints, mcpGateway, mcpFloor, decideEnvelope, threatActionFor,
// saferAlternativesFor from cli/hook-core.mjs; scanMcpFileArgs; egressHits — in the
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
// session-risk escalation, cumulative deletion volume, learned drift, MCP server
// reputation, model escalation, honeytokens and the mask rewrite (a "mask" policy resolves to its
// fallback here, as threatActionFor does for every caller that cannot rewrite). Also not here, by design:
// the hook's transit check on the AGENT'S OWN environment ("transit-env", #67 transitEnvStep). The hook
// process inherits the environment of the agent that launched it, so a proxy or CA override there is the
// agent's; this runtime also backs the moorai-serve sidecar, whose environment is not the agent's, so it
// has no reliable view of it (and the hook reports it once per session from state on disk). A proxy or CA
// override a shell COMMAND sets is a property of the call and is decided below, as in the hook. With no
// policy, all of these are report-only in the hook too, so the verdict matches; with a policy that arms
// one of them (transitAllow for "transit-env"), the hook can be stricter than this function.
// "mxc-containment" (v1.18.0, cli/containment-enforce.mjs) is hook-only too. containmentRequired judges the
// Codex / Copilot CLI host the shim names and that host's own config files on a Windows device;
// containmentClaudeCode "wrap" rewrites a Bash call through updatedInput, which this runtime cannot do
// ("mask-rewrite"). Neither is a function of the call, and an SDK host is neither of those CLIs. The pure
// decision (containmentDecision) is shared code the hook imports; off Windows both are inert in the hook too.
// Intent alignment is NOT in NOT_EVALUATED: it needs the session's task, so src/runtime.mjs judges it around
// this function (data/intent-server.mjs, in memory), as the hook's intentStep runs after its branch verdict.
import { readFileSync } from "node:fs";
import { basename, isAbsolute, resolve } from "node:path";
import { hookCore, mcpFileArgs, secretEgress, secretLearnLib, modelEndpoints, outboundUpload, serverModeLib, toolTagsLib, exceptionsLib } from "./core.mjs";

const {
  decideText, decideCredFileRead, decideFileMetadata, decideAgentStateWrite, decideAuthorizedKeysWrite, isEnvTemplate, fileScanText,
  decodedCommandPayloads, decideTransit, decideThreat,
  decideEndpoints, decideEnvelope, threatActionFor, extractReadPaths, mcpGateway, mcpFloor, decideMcpToolClass,
  saferAlternativesFor, PS_OUTBOUND_UPLOAD, evaluateProfile, rejectedAlert, readRootOwned
} = hookCore;
const { systemConfigPath } = serverModeLib;
const { scanMcpFileArgs } = mcpFileArgs;
const { egressMatches, secretEgressVerdict, unverifiedLevel } = secretEgress;
const UNVERIFIED_REASON = "outbound content MoorAI could not check for a tracked secret";
const { learnableSecrets, isCredentialPath, LEARN_TOTAL } = secretLearnLib;
const { extractHosts } = modelEndpoints;
const { OUTBOUND_UPLOAD } = outboundUpload;
const { callTags, tagGate, applyTagGate, tagHitAlert } = toolTagsLib;
const { readExceptionStore, liveExceptions, matchCallExceptions, applyExceptions } = exceptionsLib;

const RANK = { allow: 1, ask: 2, deny: 3 };
export const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
export const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
// Cursor's alias, as the hook maps it (TOOL_ALIASES).
const TOOL_ALIASES = { Shell: "Bash" };
export const NOT_EVALUATED = Object.freeze(["circuit-breaker", "session-risk", "deletion-volume", "learned-drift", "mcp-reputation", "model-escalation", "honeytokens", "mask-rewrite", "tag-rules", "transit-env", "mxc-containment"]);
const FILE_CAP = 262144;

function readFileCapped(fp) {
  try { if (!fp) return ""; return fileScanText(readFileSync(fp).subarray(0, FILE_CAP)); } catch { return ""; }
}
// The file's head for the scan, and what #65 learns from: the whole file up to LEARN_TOTAL (`truncated` past it).
function readFileForLearn(fp) {
  try {
    if (!fp) return { text: "", learn: { text: "", truncated: false } };
    const buf = readFileSync(fp);
    const text = fileScanText(buf.subarray(0, FILE_CAP));
    return { text, learn: buf.length > FILE_CAP ? { text: fileScanText(buf.subarray(0, LEARN_TOTAL)), truncated: buf.length > LEARN_TOTAL } : { text, truncated: false } };
  } catch { return { text: "", learn: { text: "", truncated: false } }; }
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
// #65 as the hook's checkSecretEgress: local secrets raw or encoded, plus — at an egress sink, when the
// caller passes one — the secrets its tracker learned from tool results (cli/secret-taint.mjs).
// Returns "deny" | "ask" | false, as the hook's checkSecretEgress; `admin` is the root-owned admin binding.
function secretEgressBlocks(policy, text, cwd, stage, signals, tracker = null, admin = null) {
  try {
    const r = egressMatches(text, cwd, { tracker });
    if (!r.matches.length) return false;
    const hits = [...new Set(r.matches.map((m) => m.hash))];
    const v = secretEgressVerdict(r.matches, { action: threatActionFor(policy, 65), level: unverifiedLevel(policy, admin) });
    const block = v === "deny";
    signals.push({ threatId: 65, category: "Local secret value egress", riskLevel: block ? "Blocked" : v === "ask" ? "High" : "Critical", stage, key: `egress:${hits.join(".")}`, secretEgress: r.matches.slice(0, 16).map((m) => ({ hashPrefix: m.hash.slice(0, 11), encoding: m.encoding, source: m.source })) });
    return v === "deny" || v === "ask" ? v : false;
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
  try { exc = matchCallExceptions(liveExceptions({ policy, system: sys, store: readExceptionStore(), enrolled: true }).live, { tool, toolInput: ti, cwd: opts.cwd }); } catch { /* no exception applies */ }
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
function decideBranch(engine, policy, { tool: rawTool = "", toolInput, cwd, actor = "", serviceId = "", systemConfig, secretTracker = null } = {}) {
  const tool = TOOL_ALIASES[rawTool] || String(rawTool || "");
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  const base = cwd || process.cwd();
  const signals = [];
  const out = (decision, reason, alternatives, findings, extra = {}) => ({ tool, decision, reason, alternatives: alternatives || [], findings, signals, kill: false, killIds: [], evaluated: true, notEvaluated: NOT_EVALUATED, ...extra });
  const wp = profileGate(policy, { tool, ti, cwd, serviceId, systemConfig }, signals);
  if (wp.decision === "deny") return out("deny", wp.reason, [], [], { ...(wp.profile ? { profileId: wp.profile.id } : {}), driftKinds: wp.kinds, reasonCode: wp.reasonCode });

  if (tool === "Read") {
    const rd = readFileForLearn(agentPath(ti.file_path, cwd));
    const text = rd.text;
    // #65, as the hook's Read branch: a secret in the file joins the caller's session-read set; a file whose
    // secrets could not all be learned holds the session as unverified.
    if (secretTracker && secretTracker.learn) { try { const cred = isCredentialPath(ti.file_path); const r = learnableSecrets(rd.learn.text, { kv: cred }); const cut = rd.learn.truncated || r.truncated; if (r.values.length || cut) secretTracker.learn(r.values, "Read", cred, cut); } catch { /* evidence only */ } }
    const d = decideText(engine, policy, text, "file", { ctx: { template: isEnvTemplate(ti.file_path), scope: "tool-result" } });
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
      merge(decideText(engine, policy, readFileCapped(agentPath(p, cwd)), "file", { ctx: { template: isEnvTemplate(p), egress: uploading, scope: "tool-result" } }));
      merge(decideFileMetadata(engine, policy, agentPath(p, cwd)));
      if (ps) merge(decideCredFileRead(engine, policy, p));
    }
    merge(decideText(engine, policy, ti.command, "prompt", { ctx: { egress: cmdEgress, shell: ps ? "ps" : "sh", scope: "command" } }));
    // Base64/hex payloads the command decodes straight into a shell (T1027.010), as the hook adds them to
    // the scripts it re-scans: a pure function of the command, so decided here exactly as there.
    const scripts = decodedCommandPayloads(command);
    // #67 — the command starts a program behind a proxy or a CA override; the hook's same step and merge.
    const trD = decideTransit(policy, [command, ...scripts].join("\n"));
    if (trD.proxies.length || trD.caVars.length) {
      const xd = decideThreat(policy, 67, "transit-override");
      finds.push(...xd.findings);
      if (trD.decision === "deny" && dec !== "deny") { dec = "deny"; reasons = [trD.reason]; alts = saferAlternativesFor([67]); }
      else if (RANK[xd.decision] > RANK[dec]) { dec = xd.decision; reasons = xd.reasons; alts = xd.alternatives; }
    }
    for (const script of scripts) merge(decideText(engine, policy, script, "prompt", { ctx: { egress: cmdEgress, shell: ps ? "ps" : "sh", scope: "command" } }));
    const epD = decideEndpoints(policy, ti.command);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; alts = saferAlternativesFor([63]); endpointSignal(epD, signals); }
    { const sv = secretEgressBlocks(policy, ti.command, cwd, "egress", signals, cmdEgress ? secretTracker : null, systemConfig); if (sv === "deny" && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; alts = saferAlternativesFor([65]); } else if (sv === "ask" && dec === "allow") { dec = "ask"; reasons = [UNVERIFIED_REASON]; alts = saferAlternativesFor([65]); } }
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
    // #48 — the target is an authorized_keys file (ATT&CK T1098.004): the hook's same step on the path.
    const kd = decideAuthorizedKeysWrite(engine, policy, path);
    d.findings.push(...kd.findings);
    if (RANK[kd.decision] > RANK[dec]) { dec = kd.decision; reasons = kd.reasons; alts = kd.alternatives; }
    if (kd.kill) { d.kill = true; d.killIds.push(...kd.killIds); }
    const epD = decideEndpoints(policy, text);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; alts = saferAlternativesFor([63]); endpointSignal(epD, signals); }
    if (secretEgressBlocks(policy, text, cwd, "file", signals, null, systemConfig) && dec === "allow") { dec = "ask"; reasons = ["local secret written to a new file"]; alts = saferAlternativesFor([65]); }
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
    { const sv = secretEgressBlocks(policy, `${url}\n${prompt}`, cwd, "egress", signals, secretTracker, systemConfig); if (sv === "deny" && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; alts = saferAlternativesFor([65]); } else if (sv === "ask" && dec === "allow") { dec = "ask"; reasons = [UNVERIFIED_REASON]; alts = saferAlternativesFor([65]); } }
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
    const secretV = secretEgressBlocks(policy, args, cwd, "egress", signals, secretTracker, systemConfig);
    if (secretV === "deny") return out("deny", `${tool} — local secret egress`, saferAlternativesFor([65]), []);
    const fsr = scanMcpFileArgs(engine, policy, { tool, args: ti, bases: [typeof cwd === "string" && cwd ? cwd : base], argIds: g.findings.map((f) => f.threatId) });
    if (RANK[fsr.decision] > RANK[g.decision]) { g.decision = fsr.decision; g.reason = fsr.reasons.join(", "); g.alternatives = fsr.alternatives; }
    else if (fsr.decision !== "allow" && fsr.decision === g.decision) g.reason = [g.reason, ...fsr.reasons].filter(Boolean).join(", ");
    if (fsr.kill) { g.kill = true; g.killIds = [...(g.killIds || []), ...fsr.killIds]; }
    if (secretV === "ask" && g.decision === "allow") { g.decision = "ask"; g.reason = `${tool} — ${UNVERIFIED_REASON}`; g.alternatives = saferAlternativesFor([65]); }
    // The hook's class default (policy.mcpToolClassDefaults): by override or name, merged by rank.
    const tc = decideMcpToolClass(policy, { tool, server });
    if (tc && RANK[tc.decision] > RANK[g.decision]) {
      g.decision = tc.decision; g.reason = tc.reason; g.alternatives = [];
      signals.push({ threatId: 0, category: tc.decision === "deny" ? "MCP: tool blocked by class default" : "MCP: tool held by class default", riskLevel: tc.decision === "deny" ? "Blocked" : "Medium", stage: "mcp", key: `mcp-class:${tc.toolClass}:${tool}` });
    }
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
