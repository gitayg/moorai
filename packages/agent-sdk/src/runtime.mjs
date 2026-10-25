// One long-lived MoorAI decision runtime: configuration, workload identity, policy, engine and the
// content-free reporter, resolved once and reused for every call. Shared by the Agent SDK hooks
// (src/index.mjs) and the localhost sidecar (cli/moorai-serve.mjs), so both answer exactly alike.
//
// SERVER-MODE SEMANTICS, from cli/server-mode.mjs rather than restated:
//   * binding and identity — resolveServerMode() with server mode forced on: the root-owned system file
//     (/etc/moorai/config.json), then MOORAI_SERVER_URL / MOORAI_TENANT / MOORAI_INSTALL_TOKEN /
//     MOORAI_SERVICE_ID, then GitHub Actions' workload name. Options passed in code win over both: in an
//     SDK service the operator's own code is the most trusted source there is. Settings-file `env`
//     injection is a hook-subprocess problem; this runs in the application's process, whose environment
//     no settings file sets.
//   * headless ask — settleHeadlessAsk(): an "ask" becomes a deny with the no-approver reason, unless a
//     trusted source (options, the system file, the org policy) says allow-with-report.
//     MOORAI_HEADLESS_ASK may only say "deny". One addition the hook does not have: `headlessAsk:
//     "pass-through"` returns the "ask" to the SDK, whose permission flow then hands it to the
//     application's own `canUseTool` — for a service that has a real approver. Never the default.
//   * enforcement without a token — server mode is management evidence; this surface never coaches.
//
// INTENT ALIGNMENT (data/intent-server.mjs). captureTask(session, prompt) records the user's task for a
// session as keyed hashes in memory (the SDK's UserPromptSubmit, moorai-serve's POST /v1/task); toolCall
// then judges an already-risky call with a `session` against it, after the branch verdict and before the
// headless rule, as the hook's intentStep does. policy.intentAlignment: "report" (default: one alert per
// session per target, verdict unchanged), "ask" (allow -> ask, which the headless rule then settles),
// "block" (allow or ask -> deny), "off". A branch deny is not re-judged. The alert is the hook's category,
// "Action outside the stated task" (#64, reason code INTENT_MISMATCH) with keyed hashes only; the verdict
// gains `intent: { class, mode }`. The store's HMAC key is random per runtime (options.intentStore.key to
// pin one) and never leaves the process. Lexical, with the hook's limits: it asks whether the user NAMED
// the destination, file or service, not whether the action serves the task, and a pasted untrusted
// request puts its hosts in scope. A risky call with no live task for its session (no session, never
// captured, evicted, expired) is judged as class "task-unknown": not aligned, so ask/block fail closed and
// report alerts. Unlike the hook, which skips a session with no task, so "block" needs the caller to
// supply the task. One exception: in "report" mode a call with no session id at all is not judged.
// options.intentStore false: this runtime does not judge intent at all (no store; captureTask records
// nothing). For a caller that judges intent itself with its own sessions — moorai-model-proxy
// (model-proxy/intent.mjs), whose toolCall carries no session and would otherwise be task-unknown.
//
// TASK-BOUND CALLS (data/task-bound.js, held by the same store). After intent alignment, toolCall judges the
// call by the name the caller sent: (1) the object check — a high-impact call whose object fields
// (policy.intentArgs, else the built-in recipient / account / path / URL / repository fields) name nothing
// in the task is class "object-not-in-task", decided by policy.intentAlignment exactly as the classes above
// (report alerts, ask asks, block denies; no live task is "task-unknown"); (2) task allowlists —
// policy.taskAllowlists: when the session's task matches an entry (its keywords, or the explicit task id
// set with setTaskId), a tool or argument value outside it is class "outside-task-allowlist", held at the
// entry's default ("deny" or "ask", whatever intentAlignment says). An unreadable allowlist entry denies
// what it would have covered and raises one "Task-bound policy invalid" alert per policy. Both read
// the policy this runtime loaded and the root-owned admin binding (which wins key by key); the task is
// captured whenever intentAlignment is not "off" or an allowlist is configured.
import { readFileSync } from "node:fs";
import os from "node:os";
import { hookCore, serverModeLib, contentHashLib, provenance, offlineDefault, inboundLib, indexScanLib, agentNamesLib, intentServerLib, secretTaintLib, secretLearnLib, sessionRiskLib } from "./core.mjs";
import { decideToolCall } from "./decide.mjs";
import { createReporter } from "./report.mjs";
import { taskBoundLib } from "./core.mjs";

const { buildEngine, decideText, loadVerifiedPolicy, readRootOwned, withSafer, saferAlternativesFor } = hookCore;
const { resolveServerMode, systemConfigPath, settleHeadlessAsk, serviceWho, normalizeServiceId, HEADLESS_MODES } = serverModeLib;
const { hashWithKey, deriveKey, NO_KEY } = contentHashLib;
const { policyIdOf, REASON } = provenance;
const { OFFLINE_DEFAULT_POLICY } = offlineDefault;
const { decideInbound, surfaceOf, inboundText } = inboundLib;
const { decideIndexChunk, indexScanAction, indexSource, INDEX_MAX_CHUNKS } = indexScanLib;
const { createIntentStore, intentModeFromPolicy, INTENT_CATEGORY, INTENT_CLASS_TEXT } = intentServerLib;
// The TTL of a session-read secret: the session-risk window, resolved as the hook resolves it.
const sessionRiskWindowMs = (policy) => { try { return sessionRiskLib.sessionRiskConfig(policy).windowMin * 60000; } catch { return 30 * 60000; } };

// The hook's NO_POLICY_BASELINE, byte for byte: no threat configuration, so threatActionFor falls through
// to BUILTIN_DEFAULT_ACTIONS (cli/moorai-hook.mjs explains why this differs from the offline default).
export const NO_POLICY_BASELINE = Object.freeze({ captureTier: "content-free", builtinDefault: true });
export const STAGES = ["prompt", "file", "output", "index", "tool"];
export const POLICY_REFRESH_MS = 60000;
const RANK = { allow: 1, ask: 2, deny: 3 };

function parseObj(text) {
  try { const v = JSON.parse(text); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
}

// Options (code) > system file > environment > defaults. Returns everything the runtime needs.
export function resolveSettings(options = {}, { env = process.env, system } = {}) {
  const sys = system !== undefined ? system : parseObj(readRootOwned(systemConfigPath()));
  const sm = resolveServerMode({ env: { ...env, MOORAI_MODE: "server" }, system: sys, user: null, hits: [], managed: [] });
  const c = options.console || {};
  const config = {
    serverUrl: typeof c.serverUrl === "string" && c.serverUrl ? c.serverUrl.replace(/\/+$/, "") : sm.config.serverUrl,
    tenant: typeof c.tenant === "string" && c.tenant ? c.tenant : sm.config.tenant,
    installToken: typeof c.installToken === "string" ? c.installToken : sm.config.installToken
  };
  const consoleConfigured = Boolean(c.serverUrl) || sm.sources.serverUrl !== "default";
  const serviceId = normalizeServiceId(options.serviceId || "") || sm.serviceId;
  const optAsk = options.headlessAsk;
  if (optAsk !== undefined && !HEADLESS_MODES.includes(optAsk) && optAsk !== "pass-through") throw new Error(`headlessAsk must be one of ${[...HEADLESS_MODES, "pass-through"].join(", ")}`);
  // A trusted source sits in `headless.system` (cli/server-mode.mjs headlessAskMode reads it after the
  // env-deny check), so an env "deny" still wins over every option, as it does on the hook.
  const headless = { ...sm.headless, system: HEADLESS_MODES.includes(optAsk) ? optAsk : sm.headless.system };
  return { sm: { ...sm, serviceId, headless }, config, consoleConfigured, passThrough: optAsk === "pass-through" && !sm.headless.envDeny, admin: sys };
}

export async function createMoorAI(options = {}) {
  const env = options.env || process.env;
  const settings = resolveSettings(options, { env, system: options.systemConfig });
  const { sm, config } = settings;
  const key = deriveKey(config.installToken);
  const hash = (s) => hashWithKey(key, s);
  // The `session` correlation key on a console alert: the keyed hash of a caller-provided session id (the
  // Agent SDK's hook input session_id, or moorai-serve's `session` field), the same value the shell hook
  // computes for the same id under the same install token. Omitted with no id, or no key to hash it with.
  const sessionOf = (raw) => { if (typeof raw !== "string" || !raw) return {}; const h = hash(raw); return h === NO_KEY ? {} : { session: h }; };
  const who = serviceWho(sm);
  // agentName: the surface in the console's agent_name vocabulary (cli/agent-names.mjs), next to `surface`,
  // which older consoles read. No agentVersion: the agent behind an SDK, serve, model-proxy or inference-hook
  // call does not state its version to this process.
  const surface = options.surface || "agent-sdk";
  const agentName = agentNamesLib.agentNameOf(surface);
  const identity = { user: who.user, device: who.device, platform: os.platform(), tenant: config.tenant, actor: hash(`${who.user}@${who.device}`), surface, ...(agentName ? { agentName } : {}) };
  const reporter = options.reporter || createReporter({ config, identity, fetchImpl: options.fetch });
  const intent = options.intentStore === false ? null : createIntentStore(options.intentStore || {});
  // #65 session-read secrets (cli/secret-taint.mjs): what inbound tool results carried, as keyed
  // fingerprints in memory under a random per-process key, one tracker per owner (moorai-serve's bearer
  // principal; "" otherwise) and session id. A call with a session id matches that session's tracker plus
  // its owner's unattributed one; a call with none matches the union of its owner's live trackers.
  let evictCtx = null;
  const ownerKey = (o) => (typeof o === "string" ? o : "");
  const sessKey = (x) => (typeof x === "string" ? x : "");
  const post65 = (s, tool, sess, category, contentHash, secretTaint) => reporter.post({ threatId: 65, category, riskLevel: "High", stage: "output", tool: `hook:${tool}`, contentHash, secretTaint, ...sess }, { prov: prov(s, "PostToolUse") });
  const secrets = options.secretTracker === false ? null : secretTaintLib.memorySessions({
    maxSessions: options.secretSessions || secretTaintLib.MAX_MEMORY_SESSIONS,
    ...(options.secretEvictedMax ? { evictedMax: options.secretEvictedMax } : {}),
    onEvict: ({ evictedLive, evictedMapTrimmed }) => {
      if (!evictCtx) return;
      if (evictedLive) post65(evictCtx.s, evictCtx.tool, evictCtx.sess, "Session secret tracking evicted a live session", "secret-evict", { evictedLive });
      if (evictedMapTrimmed) post65(evictCtx.s, evictCtx.tool, evictCtx.sess, "Session secret tracking evicted-session map full", "secret-evict-map", { evictedMapTrimmed });
    }
  });
  const trackerFor = (s, sess, session, owner) => (secrets ? { kr: secrets.kr, entries: () => secrets.entries(ownerKey(owner), sessKey(session), { ttl: sessionRiskWindowMs(s.policy) }), overflowed: () => secrets.overflowed(ownerKey(owner), sessKey(session)), learn: (values, tool, cred) => learnValues(s, values, tool, sess, cred, session, owner) } : null);
  function learnInbound(s, text, tool, sess, session, owner) {
    if (!secrets || tool === "WebFetch" || tool === "WebSearch") return;
    try { learnValues(s, secretLearnLib.learnableSecrets(text), tool, sess, false, session, owner); } catch { /* tracking is evidence; never the verdict */ }
  }
  function learnValues(s, values, tool, sess, cred = false, session = "", owner = "") {
    try {
      if (!values.length) return;
      evictCtx = { s, tool, sess };
      const r = secrets.learn(ownerKey(owner), sessKey(session), values, { ttl: sessionRiskWindowMs(s.policy), cred });
      evictCtx = null;
      if (r.report) post65(s, tool, sess, "Session secret tracking cap reached", `secret-cap:${r.cap}`, { pool: r.pool, cap: r.cap, dropped: r.dropped, overQuota: r.overQuota, kept: r.size, retained: r.retained });
      if (r.reportRetained) post65(s, tool, sess, "Session secret retained store full", `secret-retain:${r.retainCap}`, { retainCap: r.retainCap, retainedDropped: r.retainedDropped });
    } catch { evictCtx = null; /* tracking is evidence; never the verdict */ }
  }

  let state = null, loading = null, loadedAt = 0;
  async function loadPolicy() {
    if (options.policy && typeof options.policy === "object") return { policy: options.policy, source: "options" };
    if (typeof options.policyFile === "string") return { policy: JSON.parse(readFileSync(options.policyFile, "utf8")), source: "file" };
    if (settings.consoleConfigured && options.fetchPolicy !== false) {
      try {
        const r = await loadVerifiedPolicy(config);
        if (r.policy) return { policy: r.policy, source: r.source };
      } catch { /* offline: fall through */ }
    }
    if (options.offlineMode === "fail-closed") return { policy: OFFLINE_DEFAULT_POLICY, source: "offline-default" };
    return { policy: NO_POLICY_BASELINE, source: "builtin" };
  }
  function install(p) {
    state = { ...p, engine: buildEngine(p.policy), policyId: policyIdOf(p.policy, { builtin: NO_POLICY_BASELINE, offline: OFFLINE_DEFAULT_POLICY }) };
    loadedAt = Date.now();
    return state;
  }
  async function ready() {
    if (state && (options.policy || options.policyFile || Date.now() - loadedAt < POLICY_REFRESH_MS)) return state;
    if (!loading) loading = loadPolicy().then(install).finally(() => { loading = null; });
    // A refresh never blocks a call while a previous policy is in force.
    if (state) { loading.catch(() => {}); return state; }
    return loading;
  }
  const prov = (s, event) => ({ policyId: s.policyId, policySource: s.source, event });

  function report(s, findings, { tool, decision, event = "PreToolUse", sess = {} }) {
    for (const f of findings) {
      reporter.post({ threatId: f.threatId, category: f.category, riskLevel: decision === "deny" ? "Blocked" : f.riskLevel, stage: f.stage, tool: `hook:${tool}`, contentHash: hash(f.match || ""), ...sess }, { prov: prov(s, event) });
    }
  }
  function reportSignals(s, signals, tool, event = "PreToolUse", sess = {}) {
    for (const g of signals) {
      const { key: k, ...rest } = g;
      reporter.post({ ...rest, tool: `hook:${tool}`, contentHash: hash(k || ""), ...sess }, { prov: prov(s, event) });
    }
  }
  const contentFree = (findings) => findings.map((f) => ({ threatId: f.threatId, category: f.category, riskLevel: f.riskLevel, stage: f.stage, ...(f.detectorId ? { detectorId: f.detectorId } : {}) }));
  const summary = (findings) => ({ threatIds: [...new Set(findings.map((f) => f.threatId).filter((id) => id > 0))].sort((a, b) => a - b), categories: [...new Set(findings.map((f) => f.category))] });

  // Server mode's headless rule applied to a verdict, exactly as the hook's emit() applies it.
  function settle(s, v, { tool, permissionMode = "", sess = {} }) {
    if (v.decision !== "ask" || settings.passThrough) return { decision: v.decision, reason: v.reason, headlessAsk: null };
    const h = settleHeadlessAsk(sm, s.policy, { decision: v.decision, reason: v.reason, tool, permissionMode });
    if (h.alert) reporter.post({ ...h.alert, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED", ...sess }, { prov: prov(s, "PreToolUse") });
    return { decision: h.decision, reason: h.reason, headlessAsk: h.alert ? h.alert.headlessAsk : null };
  }

  // Content-free verdict on one string: decision, threat ids, categories, the hook's reasons ("#id
  // category"), safer alternatives (static hints from data/threats.json). The text is never returned.
  // meta (callers inside this package): { event, tool, settle, session } — the event the alert is filed
  // under, the tool label, whether the headless rule applies (false for a PostToolUse observation), and
  // the caller's raw session id (only its keyed hash leaves, as `session`).
  // ctx.inbound: the text arrived INTO the agent (a tool result, a fetched page), so it is resolved under
  // the inbound rules every inbound surface shares (cli/inbound.mjs) — the web rule set for WebFetch /
  // WebSearch (ctx.tool or meta.tool), the door rule set for anything else — and its JSON escapes are
  // decoded as every inbound surface decodes them, unless the caller already did (meta.decoded: the SDK's
  // PostToolUse and moorai-serve pass text from inboundText; the model proxy passes its blocks' text).
  async function scan(text, stage = "prompt", ctx = {}, meta = {}) {
    if (!STAGES.includes(stage)) throw new RangeError(`stage must be one of ${STAGES.join(", ")}`);
    const s = await ready();
    const c = ctx && typeof ctx === "object" ? ctx : {};
    const raw = typeof text === "string" ? text : "";
    const t = c.inbound === true && meta.decoded !== true ? inboundText(raw, Math.max(1, raw.length)) : raw;
    const tool = typeof meta.tool === "string" ? meta.tool.slice(0, 64) : "scan";
    const d = c.inbound === true
      ? decideInbound(s.engine, s.policy, t, { surface: surfaceOf(typeof c.tool === "string" ? c.tool : tool), stage })
      : decideText(s.engine, s.policy, t, stage, { ctx: c });
    const findings = d.findings.map((f) => ({ ...f, stage }));
    const sess = sessionOf(meta.session);
    if (c.inbound === true) learnInbound(s, t, typeof c.tool === "string" ? c.tool : tool, sess, meta.session, meta.owner);
    report(s, findings, { tool, decision: d.decision, event: meta.event || "Scan", sess });
    const st = meta.settle === false ? { decision: d.decision, headlessAsk: null } : settle(s, { decision: d.decision, reason: d.reasons.join(", ") }, { tool, sess });
    return { decision: st.decision, configuredDecision: d.decision, ...summary(findings), reasons: d.reasons, alternatives: d.alternatives, kill: d.kill, findings: contentFree(findings), ...(st.headlessAsk ? { headlessAsk: st.headlessAsk } : {}), policyId: s.policyId };
  }

  // The user's task for a session (intent alignment), held as keyed hashes only. Returns content-free
  // counts: { mode, captured, features }.
  // owner: the principal the session belongs to (moorai-serve: the bearer token presented); sessions are
  // namespaced by it, so one principal cannot set, replace or evict another's task.
  // authenticated (default true): whether an authenticated task writer sent it (moorai-serve passes false
  // when it has no token); "ask" and "block" judge only against authenticated captures.
  async function captureTask(session, prompt, owner, authenticated = true) {
    const s = await ready();
    const mode = intentModeFromPolicy(s.policy);
    const lists = taskBoundLib.hasAllowlists(taskBoundLib.resolveTaskBound(s.policy, settings.admin));
    if ((mode === "off" && !lists) || !intent) return { mode: intent ? mode : "off", captured: false, features: 0 };
    const r = intent.captureTask(session, prompt, owner, { authenticated, bound: { policy: s.policy, admin: settings.admin } });
    return { mode, captured: typeof session === "string" && session.length > 0 && typeof prompt === "string", features: r.features };
  }

  // Intent alignment on the branch verdict v (see the header). Returns v, or a copy with the adjusted
  // decision, reason and alternatives plus `intent`. Reasons are fixed text per class: no argument, no task.
  function intentStep(s, v, input, session, sess, owner) {
    if (v.decision === "deny" || !intent) return v;
    const mode = intentModeFromPolicy(s.policy);
    if (mode === "off") return v;
    // Report mode skips a call with NO session id at all, so callers that never send one see no new
    // alerts; ask and block still judge it (task-unknown), and a supplied id with no task alerts in every mode.
    if (mode === "report" && (typeof session !== "string" || !session)) return v;
    const j = intent.judge(session, v.tool, input, v.findings, owner, { authenticatedOnly: mode === "ask" || mode === "block" });
    if (!j || j.aligned) return v;
    if (j.firstForTarget) {
      reporter.post({ threatId: 64, category: INTENT_CATEGORY, riskLevel: mode === "block" ? "Blocked" : "Medium", stage: "behavior", tool: `hook:${v.tool}`, contentHash: hash(`intent:${j.class}`), intent: { class: j.class, mode, targetHash: j.targetHash }, ...sess }, { prov: prov(s, "PreToolUse") });
    }
    const why = `action outside the stated task — ${INTENT_CLASS_TEXT[j.class]}`;
    const w = { ...v, intent: { class: j.class, mode } };
    if (mode === "block") return { ...w, decision: "deny", reason: `blocked ${v.tool} — ${why}`, alternatives: saferAlternativesFor([64]) };
    if (mode === "ask") {
      if (v.decision === "allow") return { ...w, decision: "ask", reason: `needs justification ${v.tool} — ${why}`, alternatives: saferAlternativesFor([64]) };
      return { ...w, reason: `${v.reason}, ${why}` };
    }
    return w;
  }

  // The session's explicit task id, which selects the task allowlist entry naming it (data/task-bound.js).
  // owner / authenticated as captureTask; an id an unauthenticated writer set never selects an entry.
  async function setTaskId(session, taskId, owner, authenticated = true) {
    await ready();
    if (!intent || typeof intent.setTaskId !== "function") return { taskId: false };
    return intent.setTaskId(session, taskId, owner, { authenticated });
  }

  // Task-bound checks on v (see the header). Returns v, or a copy with the adjusted decision and reason plus
  // `intent`. Reasons are fixed text: the class, the entry's name and a reason token; never an argument.
  const problemsPosted = new Set();
  function boundStep(s, v, tool, input, session, sess, owner) {
    if (v.decision === "deny" || !intent || typeof intent.judgeBound !== "function") return v;
    const mode = intentModeFromPolicy(s.policy);
    const objects = mode !== "off" && !(mode === "report" && (typeof session !== "string" || !session)) && !(v.intent && v.intent.class === "task-unknown");
    const r = intent.judgeBound(session, typeof tool === "string" ? tool : v.tool, input, { policy: s.policy, admin: settings.admin }, owner, { authenticatedOnly: mode === "ask" || mode === "block", objects });
    if (r.problems.length && !problemsPosted.has(`${s.policyId}\0${r.problems.join(",")}`)) {
      problemsPosted.add(`${s.policyId}\0${r.problems.join(",")}`);
      reporter.post({ threatId: 0, category: "Task-bound policy invalid", riskLevel: "High", stage: "policy", tool: `hook:${v.tool}`, reasonCode: REASON.FAIL_CLOSED, contentHash: hash(`task-bound-policy:${r.problems.join(",")}`), taskBoundPolicy: { problems: r.problems }, ...sess }, { prov: prov(s, "PreToolUse") });
    }
    let w = v;
    const o = r.objects;
    if (o && !o.aligned) {
      if (o.firstForTarget) reporter.post({ threatId: 64, category: INTENT_CATEGORY, riskLevel: mode === "block" ? "Blocked" : "Medium", stage: "behavior", tool: `hook:${v.tool}`, reasonCode: REASON.INTENT_MISMATCH, contentHash: hash(`intent:${o.class}`), intent: { class: o.class, mode, targetHash: o.targetHash }, ...sess }, { prov: prov(s, "PreToolUse") });
      const why = `action outside the stated task — ${INTENT_CLASS_TEXT[o.class]}`;
      w = { ...w, intent: w.intent || { class: o.class, mode } };
      if (mode === "block") return { ...w, decision: "deny", reason: `blocked ${v.tool} — ${why}`, alternatives: saferAlternativesFor([64]), intent: { class: o.class, mode } };
      if (mode === "ask") w = w.decision === "allow" ? { ...w, decision: "ask", reason: `needs justification ${v.tool} — ${why}`, alternatives: saferAlternativesFor([64]), intent: { class: o.class, mode } } : { ...w, reason: `${w.reason}, ${why}` };
    }
    const a = r.allowlist;
    if (a) {
      if (a.firstForTarget) reporter.post({ threatId: 64, category: INTENT_CATEGORY, riskLevel: a.decision === "deny" ? "Blocked" : "High", stage: "behavior", tool: `hook:${v.tool}`, reasonCode: REASON.INTENT_MISMATCH, contentHash: hash(`intent:${a.class}`), intent: { class: a.class, mode: a.decision, task: a.task, reason: a.reason, targetHash: a.targetHash }, ...sess }, { prov: prov(s, "PreToolUse") });
      const why = `outside the task allowlist${a.task ? ` "${a.task}"` : ""} (${a.reason})`;
      const tag = { class: a.class, mode: a.decision, task: a.task };
      if (a.decision === "deny") return { ...w, decision: "deny", reason: `blocked ${v.tool} — ${why}`, alternatives: saferAlternativesFor([64]), intent: tag };
      w = w.decision === "allow" ? { ...w, decision: "ask", reason: `needs justification ${v.tool} — ${why}`, alternatives: saferAlternativesFor([64]), intent: tag } : { ...w, reason: `${w.reason}, ${why}` };
    }
    return w;
  }

  // The verdict the hook reaches for one tool call (src/decide.mjs), judged for intent alignment (a call
  // with no session has no task: a risky one is task-unknown) and the task-bound checks, then settled for a
  // headless run.
  async function toolCall({ tool, input, cwd, permissionMode = "", session, owner } = {}) {
    const s = await ready();
    const sess = sessionOf(session);
    const b = decideToolCall(s.engine, s.policy, { tool, toolInput: input, cwd, actor: identity.actor, serviceId: sm.serviceId, secretTracker: trackerFor(s, sess, session, owner) });
    report(s, b.findings, { tool: b.tool, decision: b.decision, sess });
    reportSignals(s, b.signals, b.tool, "PreToolUse", sess);
    const v = boundStep(s, intentStep(s, b, input, session, sess, owner), tool, input, session, sess, owner);
    const st = settle(s, v, { tool: v.tool, permissionMode, sess });
    const message = st.decision === "allow" ? "" : `MoorAI: ${withSafer(st.reason, v.alternatives)}`;
    return { decision: st.decision, configuredDecision: v.decision, ...summary(v.findings), reasons: v.decision === "allow" ? [] : [st.reason], alternatives: v.alternatives, kill: v.kill, message, findings: contentFree(v.findings), evaluated: v.evaluated, notEvaluated: v.notEvaluated, ...(v.intent ? { intent: v.intent } : {}), ...(st.headlessAsk ? { headlessAsk: st.headlessAsk } : {}), policyId: s.policyId };
  }

  // The index stage (cli/index-scan.mjs): chunks an application is about to embed, one verdict each —
  // "allow" (no finding), "flag" (reported, kept), "hold" (a business-value claim from an untrusted or
  // unknown author under policy.indexProvenance.untrustedClaims "ask": keep it out of the index until a
  // person reviews it) or "deny" (policy.indexScanAction "block" and an instruction-carrying or blocked
  // threat, or untrustedClaims "block"). Report-first: no policy, no deny. Never settled by the headless
  // rule — nothing here asks a person. Content-free: one alert per finding (threat, category, risk, stage
  // "index", a keyed hash of the matched span, and a keyed hash of the source name — never the name
  // itself, which is often a path or a URL). The verdicts never carry chunk text; a claim verdict carries
  // its claim kinds (price, policy, payment, authority).
  // source: a string label, or { name?, trust?: "trusted" | "untrusted" | "unknown", kind? } (indexSource).
  async function scanForIndex(chunks, { source, session } = {}) {
    if (!Array.isArray(chunks)) throw new TypeError("chunks must be an array");
    if (chunks.length > INDEX_MAX_CHUNKS) throw new RangeError(`at most ${INDEX_MAX_CHUNKS} chunks per call`);
    const s = await ready();
    const src = indexSource(source);
    const sourceHash = src.name ? hash(`index-source:${src.name}`) : undefined;
    const sess = sessionOf(session);
    const results = [], allowed = [], flagged = [], held = [], denied = [];
    const decisionOf = { deny: "deny", hold: "ask" };
    for (let i = 0; i < chunks.length; i++) {
      const r = decideIndexChunk(s.engine, s.policy, chunks[i], { source });
      for (const f of r.findings) {
        reporter.post({ threatId: f.threatId, category: f.category, riskLevel: r.verdict === "deny" ? "Blocked" : f.riskLevel, stage: "index", tool: "index:embed", decision: decisionOf[r.verdict] || "notify", contentHash: hash(f.match || ""), ...(sourceHash ? { indexSource: sourceHash } : {}), ...sess }, { prov: prov(s, "IndexScan") });
      }
      ({ deny: denied, hold: held, flag: flagged }[r.verdict] || allowed).push(i);
      results.push({ index: i, verdict: r.verdict, ...summary(r.findings), reasons: r.reasons, findings: contentFree(r.findings), ...(r.claims.length ? { claims: r.claims } : {}) });
    }
    return { action: indexScanAction(s.policy), policyId: s.policyId, results, allowed, flagged, held, denied };
  }

  return { identity, config: { serverUrl: config.serverUrl, tenant: config.tenant, enrolled: reporter.enrolled }, settings: { serviceId: sm.serviceId, serviceIdSource: options.serviceId ? "options" : sm.serviceIdSource, headless: sm.headless, passThrough: settings.passThrough, admin: settings.admin }, ready, scan, toolCall, captureTask, setTaskId, scanForIndex, flush: () => reporter.flush(), reporter, hash, RANK };
}
