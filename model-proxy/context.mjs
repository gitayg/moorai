// Operator-authored context: the text the application itself puts in front of the model — Anthropic `system`,
// OpenAI system / developer messages, Gemini systemInstruction, Ollama system messages and /api/generate
// `system` (the provider files mark these items `context: true`).
//
// DEFAULT ("enforce"): operator context is judged like any other request content. The proxy's job includes
// DLP on what leaves for the provider, and a client controls its own system role: if a privacy finding
// there were never refused, moving PII or a secret from the user turn into the system prompt would send it
// out unblocked. So, unless opted in, a card number or an email address in a system prompt blocks or asks
// exactly as it would in a user turn.
//
// OPT-IN ("report"), by the verified signed policy or the root-owned admin binding only:
//   { "operatorContext": { "privacy": "report" } }
// A PII-class finding in operator context is then reported at stage "context", decision notify, and does
// not refuse the request (stamped enforcement LIMITED when the policy's action for it would have blocked
// or asked). A policy from --policy-file, from createProxy's `policy` option, the built-in baseline or the
// offline default never turns it on: none of those is a policy the console signed and this device verified,
// and the opt-in loosens DLP. The admin binding wins over the policy (either value).
//
// NEVER EXEMPT, even when opted in: secrets (#39 secret / credential, #65 local secret value) and every
// non-data finding (#3 injection, #54, #51, #71, content rules, …) are decided at stage "prompt", as in a
// user turn. A user turn, a tool result and the model's output are never operator context.
import { decideText } from "../cli/hook-core.mjs";
import { settleHeadlessAsk } from "../cli/server-mode.mjs";
import { REASON, ENFORCEMENT } from "../cli/provenance.mjs";

// PII-class threats ("this text contains personal or business data"), checked against data/threats.json and
// the runtime detectors (data/detectors.js):
//   1 sensitive data (payment card, IBAN, CVV) · 9 intellectual property (confidentiality markers) ·
//   15 employee / customer personal data (email, phone, national id, passport) · 18 sensitive data retained
//   in a conversation · 27 leakage via history / uploads · 36 cross-context leakage · 44 PHI.
// Not here: 39 (API keys, tokens, private keys, JWTs, DB connection strings) and 65 (a local secret value,
// credential-shaped egress) are secrets, never exempt. Nor is #1's clipboard-to-sink detector: it matches a
// command that sends the clipboard to a network sink, an exfiltration step, not data.
export const CONTEXT_REPORT_ONLY = Object.freeze(new Set([1, 9, 15, 18, 27, 36, 44]));
export const CONTEXT_NEVER_EXEMPT = Object.freeze(new Set([39, 65]));
const NOT_DATA_DETECTORS = new Set(["clipboard-to-sink"]);
export const isPrivacy = (f) => CONTEXT_REPORT_ONLY.has(f.threat.id) && !NOT_DATA_DETECTORS.has(f.detectorId);
// The runtime's policy sources that are a console-signed policy this device verified (cli/hook-core.mjs
// loadVerifiedPolicy). "options", "file", "builtin" and "offline-default" are not.
export const VERIFIED_SOURCES = Object.freeze(new Set(["fresh", "cache", "cache-offline", "last-known-good"]));
export const CONTEXT_MODES = Object.freeze(["enforce", "report"]);

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const modeIn = (src) => (isObj(src) && isObj(src.operatorContext) && CONTEXT_MODES.includes(src.operatorContext.privacy) ? src.operatorContext.privacy : null);

// → { mode: "enforce"|"report", source: "admin"|"policy"|"default", ignored? }. `admin` is the parsed
// root-owned admin binding (cli/server-mode.mjs systemConfig()); `policy` and `policySource` are the
// runtime's loaded policy and its source. `ignored: "unverified-policy"` when an unverified policy asked
// for an operatorContext mode. Never throws; anything unreadable is the default.
export function operatorContextMode({ policy = null, policySource = "", admin = null } = {}) {
  try {
    const a = modeIn(admin);
    if (a) return { mode: a, source: "admin" };
    const p = modeIn(policy);
    if (p && VERIFIED_SOURCES.has(policySource)) return { mode: p, source: "policy" };
    if (p) return { mode: "enforce", source: "default", ignored: "unverified-policy" };
  } catch { /* the default below */ }
  return { mode: "enforce", source: "default" };
}

export const CONTEXT_STAGE = "context";

// Two views of one engine: only the privacy detectors, and everything else. The engine's own scan runs once
// per view on the same text; a finding is never moved between them.
const views = new WeakMap();
function viewsOf(engine) {
  let v = views.get(engine);
  if (!v) {
    const privacy = Object.create(engine), rest = Object.create(engine);
    privacy.scan = (t, st, c) => engine.scan(t, st, c).filter(isPrivacy);
    privacy.scanContent = () => [];
    rest.scan = (t, st, c) => engine.scan(t, st, c).filter((f) => !isPrivacy(f));
    v = { privacy, rest };
    views.set(engine, v);
  }
  return v;
}

// The verdict for one operator-context item under the "report" opt-in, { decision, reasons }. With no
// PII-class finding it is rt.scan's, unchanged. With one: the PII-class findings are reported at stage
// context, and the verdict is the one the remaining findings (secrets included) reach, reported and settled
// as rt.scan reports and settles them. Under "enforce" (the default) the checker calls rt.scan instead.
export async function scanContext(rt, it, text, { settle }) {
  const s = await rt.ready();
  const { privacy, rest } = viewsOf(s.engine);
  const p = decideText(privacy, s.policy, text, "prompt", { ctx: it.ctx });
  if (!p.findings.length) return rt.scan(text, "prompt", it.ctx, { tool: it.kind, event: "ModelRequest", settle });
  const prov = { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } };
  const tool = `model-proxy:${it.kind}`;
  for (const f of p.findings) {
    rt.reporter.post({ threatId: f.threatId, category: f.category, riskLevel: f.riskLevel, stage: CONTEXT_STAGE, tool, decision: "notify", contentHash: rt.hash(f.match || ""), ...(p.decision !== "allow" ? { enforcement: ENFORCEMENT.LIMITED } : {}) }, prov);
  }
  const d = decideText(rest, s.policy, text, "prompt", { ctx: it.ctx });
  for (const f of d.findings) {
    rt.reporter.post({ threatId: f.threatId, category: f.category, riskLevel: d.decision === "deny" ? "Blocked" : f.riskLevel, stage: "prompt", tool, contentHash: rt.hash(f.match || "") }, prov);
  }
  if (d.decision !== "ask" || !settle || rt.settings.passThrough) return { decision: d.decision, reasons: d.reasons };
  const h = settleHeadlessAsk({ active: true, headless: rt.settings.headless }, s.policy, { decision: "ask", reason: d.reasons.join(", "), tool: it.kind });
  if (h.alert) rt.reporter.post({ ...h.alert, tool, reasonCode: REASON.HEADLESS_ASK, enforcement: h.decision === "deny" ? "STRENGTHENED" : "LIMITED" }, prov);
  return { decision: h.decision, reasons: d.reasons };
}
