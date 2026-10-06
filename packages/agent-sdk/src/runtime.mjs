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
import { readFileSync } from "node:fs";
import os from "node:os";
import { hookCore, serverModeLib, contentHashLib, provenance, offlineDefault, inboundLib } from "./core.mjs";
import { decideToolCall } from "./decide.mjs";
import { createReporter } from "./report.mjs";

const { buildEngine, decideText, loadVerifiedPolicy, readRootOwned, withSafer } = hookCore;
const { resolveServerMode, systemConfigPath, settleHeadlessAsk, serviceWho, normalizeServiceId, HEADLESS_MODES } = serverModeLib;
const { hashWithKey, deriveKey } = contentHashLib;
const { policyIdOf, REASON } = provenance;
const { OFFLINE_DEFAULT_POLICY } = offlineDefault;
const { decideInbound, surfaceOf, inboundText } = inboundLib;

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
  return { sm: { ...sm, serviceId, headless }, config, consoleConfigured, passThrough: optAsk === "pass-through" && !sm.headless.envDeny };
}

export async function createMoorAI(options = {}) {
  const env = options.env || process.env;
  const settings = resolveSettings(options, { env, system: options.systemConfig });
  const { sm, config } = settings;
  const key = deriveKey(config.installToken);
  const hash = (s) => hashWithKey(key, s);
  const who = serviceWho(sm);
  const identity = { user: who.user, device: who.device, platform: os.platform(), tenant: config.tenant, actor: hash(`${who.user}@${who.device}`), surface: options.surface || "agent-sdk" };
  const reporter = options.reporter || createReporter({ config, identity, fetchImpl: options.fetch });

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

  function report(s, findings, { tool, decision, event = "PreToolUse" }) {
    for (const f of findings) {
      reporter.post({ threatId: f.threatId, category: f.category, riskLevel: decision === "deny" ? "Blocked" : f.riskLevel, stage: f.stage, tool: `hook:${tool}`, contentHash: hash(f.match || "") }, { prov: prov(s, event) });
    }
  }
  function reportSignals(s, signals, tool, event = "PreToolUse") {
    for (const g of signals) {
      const { key: k, ...rest } = g;
      reporter.post({ ...rest, tool: `hook:${tool}`, contentHash: hash(k || "") }, { prov: prov(s, event) });
    }
  }
  const contentFree = (findings) => findings.map((f) => ({ threatId: f.threatId, category: f.category, riskLevel: f.riskLevel, stage: f.stage, ...(f.detectorId ? { detectorId: f.detectorId } : {}) }));
  const summary = (findings) => ({ threatIds: [...new Set(findings.map((f) => f.threatId).filter((id) => id > 0))].sort((a, b) => a - b), categories: [...new Set(findings.map((f) => f.category))] });

  // Server mode's headless rule applied to a verdict, exactly as the hook's emit() applies it.
  function settle(s, v, { tool, permissionMode = "" }) {
    if (v.decision !== "ask" || settings.passThrough) return { decision: v.decision, reason: v.reason, headlessAsk: null };
    const h = settleHeadlessAsk(sm, s.policy, { decision: v.decision, reason: v.reason, tool, permissionMode });
    if (h.alert) reporter.post({ ...h.alert, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED" }, { prov: prov(s, "PreToolUse") });
    return { decision: h.decision, reason: h.reason, headlessAsk: h.alert ? h.alert.headlessAsk : null };
  }

  // Content-free verdict on one string: decision, threat ids, categories, the hook's reasons ("#id
  // category"), safer alternatives (static hints from data/threats.json). The text is never returned.
  // meta (callers inside this package): { event, tool, settle } — the event the alert is filed under, the
  // tool label, and whether the headless rule applies (false for a PostToolUse observation).
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
    report(s, findings, { tool, decision: d.decision, event: meta.event || "Scan" });
    const st = meta.settle === false ? { decision: d.decision, headlessAsk: null } : settle(s, { decision: d.decision, reason: d.reasons.join(", ") }, { tool });
    return { decision: st.decision, configuredDecision: d.decision, ...summary(findings), reasons: d.reasons, alternatives: d.alternatives, kill: d.kill, findings: contentFree(findings), ...(st.headlessAsk ? { headlessAsk: st.headlessAsk } : {}), policyId: s.policyId };
  }

  // The verdict the hook reaches for one tool call (src/decide.mjs), settled for a headless run.
  async function toolCall({ tool, input, cwd, permissionMode = "" } = {}) {
    const s = await ready();
    const v = decideToolCall(s.engine, s.policy, { tool, toolInput: input, cwd, actor: identity.actor, serviceId: sm.serviceId });
    report(s, v.findings, { tool: v.tool, decision: v.decision });
    reportSignals(s, v.signals, v.tool);
    const st = settle(s, v, { tool: v.tool, permissionMode });
    const message = st.decision === "allow" ? "" : `MoorAI: ${withSafer(st.reason, v.alternatives)}`;
    return { decision: st.decision, configuredDecision: v.decision, ...summary(v.findings), reasons: v.decision === "allow" ? [] : [st.reason], alternatives: v.alternatives, kill: v.kill, message, findings: contentFree(v.findings), evaluated: v.evaluated, notEvaluated: v.notEvaluated, ...(st.headlessAsk ? { headlessAsk: st.headlessAsk } : {}), policyId: s.policyId };
  }

  return { identity, config: { serverUrl: config.serverUrl, tenant: config.tenant, enrolled: reporter.enrolled }, settings: { serviceId: sm.serviceId, serviceIdSource: options.serviceId ? "options" : sm.serviceIdSource, headless: sm.headless, passThrough: settings.passThrough }, ready, scan, toolCall, flush: () => reporter.flush(), reporter, hash, RANK };
}
