// #1/#2/#3 — shared, side-effect-free core for the MoorAI PreToolUse hook. Kept separate from the
// stdin/stdout entrypoint (moorai-hook.mjs) so the decision logic is unit-testable without spawning a
// process. Governance, not a sandbox: on any error or missing policy the caller fails OPEN (allows).

import { readFileSync } from "node:fs";
import { createPublicKey, verify as cryptoVerify, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { extractEndpointHosts, endpointApproved } from "../data/model-endpoints.js";
import { TIER_OF } from "../data/data-tiers.js";
import { APPROVAL_THREATS } from "../data/human-approval.js";
import { compilePacks } from "../data/detector-packs.js";
import { DetectionEngine } from "../src/engine.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export function buildEngine(policy) {
  const threatData = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threatData, DETECTORS, CONTENT_RULES);
  try { engine.applyPacks(compilePacks(policy?.detectorPacks)); } catch { /* packs optional */ }
  return engine;
}

// Resolve the action for a threat exactly like the app/guard: per-threat → data-tier → approval-set
// → notify. So a secret in a read file defaults to "notify" (report, don't block) unless an admin
// explicitly escalates it — the safe default that keeps false positives from blocking work.
export function threatActionFor(policy, id) {
  const explicit = policy?.threatPolicy?.[id];
  if (explicit) return explicit;
  const tier = TIER_OF[id];
  const tierAct = tier && policy?.tierPolicy?.[tier];
  if (tierAct) return tierAct;
  if (APPROVAL_THREATS.has(id)) return "justify";
  return "notify";
}

const RANK = { allow: 1, ask: 2, deny: 3 };

// Coach-as-literacy (EU AI Act Art. 4). Every surface that SHOWS a developer the "why + what to do"
// for a finding is delivering a just-in-time AI-literacy touchpoint at the point of use. This builds
// the content-free record for that moment — topic + framework + actor, never any content — so the
// console's literacy coverage reflects ALL surfaces, not just the CLI guard. Shared here because the
// hook, the Claude Desktop MCP proxy, the browser extension and the Tauri host all coach, and a
// literacy number that counts only one of them under-reports evidence the console exports.
export function literacyTouchpoint({ threatId = 0, category = "", tool = "moorai" } = {}) {
  return {
    threatId,
    category: `Literacy: ${category}`,
    riskLevel: "Info",
    stage: "coach",
    tool,
    ts: new Date().toISOString(),
    contentHash: "coach:" + threatId
  };
}

// #10 — context-aware severity. The same pattern is more critical by WHERE it was caught: a secret
// read into an agent's context (stage "file") or shipped as an MCP tool-call argument (stage "mcp"/
// "egress") is worse than one typed into a prompt the user can still edit before sending. Label-only:
// this adjusts the reported riskLevel, never the allow/ask/deny decision.
const LEVELS = ["Low", "Medium", "High", "Critical"];
const SECRET_RE = /secret|credential|api[\s-]?key|token|password|private key/i;
export function isSecretCategory(category) { return SECRET_RE.test(String(category || "")); }
export function calibrateRisk(base, { stage, category } = {}) {
  if (!isSecretCategory(category)) return base;
  const i = LEVELS.indexOf(base);
  if (i < 0) return base;
  if (stage === "file" || stage === "mcp" || stage === "egress") return LEVELS[Math.min(i + 1, LEVELS.length - 1)];
  return base;
}

// Scan text and reduce all findings to a single decision (deny > ask > allow) plus content-free
// findings for reporting. Only "block" → deny; "justify" → ask; "notify"/"alert" → allow-but-report.
export function decideText(engine, policy, text, stage) {
  const out = { decision: "allow", reasons: [], findings: [], kill: false, killIds: [] };
  if (!text || !text.trim()) return out;
  const bump = (d) => { if (RANK[d] > RANK[out.decision]) out.decision = d; };
  for (const f of engine.scan(text, stage)) {
    const act = threatActionFor(policy, f.threat.id);
    if (act === "disabled") continue;
    const level = calibrateRisk(f.threat.riskLevel, { stage, category: f.threat.category });
    out.findings.push({ threatId: f.threat.id, category: f.threat.category, riskLevel: level, match: f.match });
    // #3 — "kill" terminates the whole session, not just this call. It still denies the call (Claude
    // Code only knows allow/ask/deny); the kill signal is carried out-of-band via out.kill for the host.
    // killOnCritical promotes any Critical block to a kill without per-threat config.
    const kill = act === "kill" || (policy?.killOnCritical && act === "block" && level === "Critical");
    if (act === "block" || act === "kill") { bump("deny"); out.reasons.push(`#${f.threat.id} ${f.threat.category}`); }
    else if (act === "justify") { bump("ask"); out.reasons.push(`#${f.threat.id} ${f.threat.category} (needs sign-off)`); }
    if (kill) { out.kill = true; out.killIds.push(f.threat.id); }
  }
  const cp = policy?.contentPolicy || {};
  const enabled = Object.keys(cp).filter((id) => cp[id] && cp[id] !== "disabled");
  if (enabled.length) for (const c of engine.scanContent(text, enabled)) {
    const act = cp[c.ruleId] || "disabled";
    if (act === "disabled") continue;
    out.findings.push({ threatId: 0, category: `Content: ${c.label}`, riskLevel: act === "block" ? "Blocked" : "High", match: c.match });
    if (act === "block") { bump("deny"); out.reasons.push(`content: ${c.label}`); }
    else if (act === "justify") bump("ask");
  }
  return out;
}

// #3 — MCP server allow/deny. Enforce only when an allow-list is set; otherwise report-only (preserve
// today's behavior). A denied server short-circuits before the arg scan.
export function decideMcpServer(policy, serverName) {
  const allow = policy?.mcpAllow;
  if (!Array.isArray(allow) || !allow.length) return { decision: "allow" };
  if (allow.includes(serverName)) return { decision: "allow" };
  return { decision: "deny", reason: `MCP server '${serverName}' is not on your organization's allow-list.` };
}

// #18 — per-tool MCP argument rules. policy.mcpToolRules[tool] = { deny:[regex], allow:[regex] }.
// A deny pattern matched in the serialized args → deny. If an allow-list is set for the tool, at least
// one allow pattern must match or it's denied. No rule for the tool → allow (unchanged behavior).
export function decideMcpArgs(policy, tool, argsText) {
  const rules = policy?.mcpToolRules?.[tool];
  if (!rules) return { decision: "allow" };
  const text = String(argsText || "");
  const mk = (p) => { try { return new RegExp(p, "i"); } catch { return null; } };
  if (Array.isArray(rules.deny)) for (const p of rules.deny) { const re = mk(p); if (re && re.test(text)) return { decision: "deny", reason: `${tool} argument matches a denied pattern` }; }
  if (Array.isArray(rules.allow) && rules.allow.length) {
    const ok = rules.allow.some((p) => { const re = mk(p); return re && re.test(text); });
    if (!ok) return { decision: "deny", reason: `${tool} argument is not on the allow-list` };
  }
  return { decision: "allow" };
}

// The on-device AI Agent Gateway — the single chokepoint every MCP tool-call passes through. Pure and
// unit-testable: composes the server allow-list (#3), per-tool argument rules (#18), and the argument
// content scan (#2) into ONE decision, in that order, short-circuiting on the first deny. Returns the
// decision plus a `gate` tag ("server"|"args"|"content"|null) so the caller can post the matching
// content-free alert, and the findings / kill signal from the content scan. The caller layers the
// impure gates (entitlement envelope, endpoint allow-list, secret-egress) and records the audit line.
export function mcpGateway(engine, policy, { tool, server, args }) {
  const sd = decideMcpServer(policy, server);
  if (sd.decision === "deny") return { gate: "server", decision: "deny", reason: sd.reason, findings: [], kill: false, killIds: [] };
  const ad = decideMcpArgs(policy, tool, args);
  if (ad.decision === "deny") return { gate: "args", decision: "deny", reason: ad.reason, findings: [], kill: false, killIds: [] };
  const d = decideText(engine, policy, args, "prompt");
  return { gate: d.decision === "allow" ? null : "content", decision: d.decision, reason: d.reasons.join(", "), findings: d.findings, kill: d.kill, killIds: d.killIds };
}

// T1-1 / #63 — model-endpoint allow-list. Enforce only when policy.endpointAllow is set; a referenced
// LLM endpoint host (base-URL override target or direct provider call) not on the list → deny. Loopback
// (local models) is always allowed. Content-free: operates on hosts, never content.
export function decideEndpoints(policy, text) {
  const allow = policy?.endpointAllow;
  if (!Array.isArray(allow) || !allow.length) return { decision: "allow", hosts: [] };
  const bad = extractEndpointHosts(text).filter((h) => !endpointApproved(h, allow));
  if (bad.length) return { decision: "deny", hosts: bad, reason: `model endpoint(s) not on the allow-list: ${bad.join(", ")}` };
  return { decision: "allow", hosts: [] };
}

// T1-5 / #64 — agent entitlement envelope. policy.entitlements = { tools:[], paths:[], mcp:[] } declares
// the agent's authorized surface; an observed tool / path-prefix / MCP server outside it is "drift".
// Returns the out-of-scope reasons (empty = in scope). Enforcement strictness is policy.entitlementMode
// ("off" | "alert" | "block"). Content-free: names/paths only. An empty/absent envelope → always in scope.
export function decideEnvelope(policy, { tool, paths = [], mcpServer, actor } = {}) {
  const env = policy?.entitlements;
  if (!env || typeof env !== "object") return { inScope: true, reasons: [], elevated: false };
  const reasons = [];
  if (Array.isArray(env.tools) && env.tools.length && tool && !env.tools.includes(tool)) reasons.push(`tool:${tool}`);
  if (Array.isArray(env.mcp) && env.mcp.length && mcpServer && !env.mcp.includes(mcpServer)) reasons.push(`mcp:${mcpServer}`);
  if (Array.isArray(env.paths) && env.paths.length) {
    for (const p of paths) { if (p && !env.paths.some((a) => String(p).startsWith(a))) reasons.push(`path:${p}`); }
  }
  // JIT elevation: an out-of-envelope reason covered by a live, non-expired grant for THIS actor is
  // allowed (time-boxed) rather than flagged. Grants are exact for tool:/mcp:, prefix for path:.
  const grants = (Array.isArray(policy?.elevations) ? policy.elevations : []).filter((g) => !actor || g.actor === actor);
  const covered = (r) => grants.some((g) => g.capability === r ||
    (g.capability.startsWith("path:") && r.startsWith("path:") && r.slice(5).startsWith(g.capability.slice(5))));
  const remaining = reasons.filter((r) => !covered(r));
  return { inScope: remaining.length === 0, reasons: remaining, elevated: remaining.length < reasons.length, usedGrants: reasons.length - remaining.length };
}

// Break-glass / offline fail-closed (#33) — pure posture helpers. The I/O (reading the policy cache,
// the durable posture sidecar, and the break-glass marker file) lives in moorai-hook.mjs; these only
// classify. The default posture is "fail-open" — today's behavior — and is NEVER flipped implicitly.

// Normalize a policy's offline posture. Anything other than an explicit "fail-closed" is "fail-open".
export function offlineMode(policy) {
  return policy && policy.offlineMode === "fail-closed" ? "fail-closed" : "fail-open";
}

// Break-glass marker authenticity. The marker forces FAIL-OPEN on a fail-closed device, so mere
// presence is not a trust test: the hook runs as the user, and the agent being governed can write
// ~/.curaiq/break-glass with one already-permitted Bash call. The pre-v2 format ("any content that
// parses to a future timestamp") therefore let a prompt-injected agent switch the enforcement layer
// off — `echo '{"expires":"2030-01-01"}' > ~/.curaiq/break-glass`. It is NOT accepted any more, and
// there is deliberately no backwards compatibility: the old format is unauthenticated by construction.
//
// A marker is now an ed25519 statement signed by an OPERATOR key the device holds only OUTSIDE the
// agent's write scope (see BG_ANCHOR in moorai-hook.mjs). Scope fields are inside the signature, so a
// marker minted for one device/tenant cannot be replayed onto another.
export const BREAK_GLASS_VERSION = 2;

// The exact bytes signed and verified — keep the operator's signing procedure and this in lockstep.
export function breakGlassCanonical(m) {
  return `moorai-break-glass|v${m.v}|${m.tenant}|${m.device}|${m.expires}|${m.nonce}`;
}

// Parse a trust-anchor blob into ed25519 public KeyObjects. Accepts PEM blocks (what `openssl pkey
// -pubout` emits) and/or one base64 SPKI DER key per line, with # comments. Unparseable entries are
// skipped rather than throwing — a corrupt anchor must degrade to "no key", never to a crash.
export function parseTrustedKeys(text) {
  const s = String(text || "");
  const out = [];
  const PEM = /-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g;
  for (const p of s.match(PEM) || []) { try { out.push(createPublicKey(p)); } catch { /* skip */ } }
  for (const line of s.replace(PEM, "").split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    try { out.push(createPublicKey({ key: Buffer.from(t, "base64"), format: "der", type: "spki" })); } catch { /* skip */ }
  }
  return out;
}

function expiryMs(exp) {
  const s = String(exp).trim();
  return /^\d+$/.test(s) ? Number(s) : Date.parse(s);
}

// Verify a break-glass marker. Returns { active, status } where status is one of:
//   absent | malformed | unsigned | no-anchor | untrusted | mismatch | expired | active
// Only "active" grants fail-open. Every other status — including the ambiguous ones (no trust anchor
// on the device, unparseable expiry) — keeps the device fail-closed, and every status other than
// "absent" is a tamper signal the caller reports to the SOC.
export function verifyBreakGlass(text, { now = Date.now(), keys = [], tenant = "", device = "" } = {}) {
  if (!text || !String(text).trim()) return { active: false, status: "absent" };
  let m;
  try { m = JSON.parse(text); } catch { return { active: false, status: "malformed" }; }
  if (!m || typeof m !== "object" || Array.isArray(m)) return { active: false, status: "malformed" };
  // No signature at all is reported as "unsigned" rather than "malformed" — that is the pre-v2 format
  // and the shape a forging agent produces, and a SOC should see it named for what it is.
  if (typeof m.sig !== "string" || !m.sig) return { active: false, status: "unsigned" };
  if (Number(m.v) !== BREAK_GLASS_VERSION || m.expires == null || m.expires === "") return { active: false, status: "malformed" };
  if (!keys.length) return { active: false, status: "no-anchor" };
  // Re-derive the signed bytes from the named fields only — never trust the file's own byte layout.
  const body = { v: BREAK_GLASS_VERSION, tenant: String(m.tenant ?? ""), device: String(m.device ?? ""), expires: String(m.expires), nonce: String(m.nonce ?? "") };
  const msg = Buffer.from(breakGlassCanonical(body));
  const sig = Buffer.from(m.sig, "base64");
  const ok = keys.some((k) => { try { return cryptoVerify(null, msg, k, sig); } catch { return false; } });
  if (!ok) return { active: false, status: "untrusted" };
  // Scope is inside the signature: only the operator can widen it to the "*" fleet-wide wildcard.
  if (body.tenant !== "*" && body.tenant !== String(tenant)) return { active: false, status: "mismatch" };
  if (body.device !== "*" && body.device !== String(device)) return { active: false, status: "mismatch" };
  const t = expiryMs(body.expires);
  if (!Number.isFinite(t)) return { active: false, status: "malformed" };
  if (t <= now) return { active: false, status: "expired" };
  return { active: true, status: "active" };
}

// Offline-posture RATCHET (#33 follow-up). Break-glass fixed the "forge the override file" door; the
// POSTURE itself was the other door into the same room. It used to be read from two sources the
// governed agent can write — MOORAI_OFFLINE_MODE and ~/.curaiq/offline-posture — so a prompt-injected
// agent with one already-permitted Bash call (`echo fail-open > ~/.curaiq/offline-posture`) silently
// returned a fail-closed device to fail-open. The asymmetry that fixes it: HARDENING is safe and needs
// no proof, WEAKENING is an enforcement bypass and must never be taken from the user's write scope.
//
// This classifies the already-read source values; the I/O — and the ownership check that makes the
// machine-wide source trustworthy — lives in moorai-hook.mjs. Inputs are raw strings ("" = absent):
//   system  — machine-wide latch, ALREADY ownership-checked (root-owned, not group/world-writable)
//   sidecar — ~/.curaiq/offline-posture   (user scope — the agent can write it)
//   latch   — ~/.moorai/posture           (user scope — second copy, in a different directory)
//   env     — MOORAI_OFFLINE_MODE         (user scope — the agent can export it)
//
// Rules: "fail-closed" from ANY source wins. "fail-open" from a user-scope source can only establish
// the never-configured default; it can never undo a ratchet, and asserting it against one is recorded
// as a refused downgrade for the SOC. Anything that is not one of the two literals is ignored outright
// — junk must never be read as "fail-open". evidenceMissing flags the erase-the-evidence move: one of
// the two user-scope copies still says fail-closed while the other no longer corroborates it.
export function ratchetPosture({ system = "", sidecar = "", latch = "", env = "" } = {}) {
  const norm = (v) => (String(v ?? "").trim() === "fail-closed" ? "fail-closed" : String(v ?? "").trim() === "fail-open" ? "fail-open" : "");
  const s = { system: norm(system), sidecar: norm(sidecar), latch: norm(latch), env: norm(env) };
  const hardenedBy = Object.keys(s).filter((k) => s[k] === "fail-closed");
  if (!hardenedBy.length) return { posture: "fail-open", hardenedBy, downgradeAttempt: [], evidenceMissing: false, sources: s };
  const userPair = [s.sidecar, s.latch];
  return {
    posture: "fail-closed",
    hardenedBy,
    downgradeAttempt: ["system", "sidecar", "latch", "env"].filter((k) => s[k] === "fail-open"),
    evidenceMissing: userPair.includes("fail-closed") && userPair.includes(""),
    sources: s
  };
}

// ---- Policy-cache authenticity ----
//
// The third door into the same room the break-glass marker and the posture ratchet closed. The policy
// cache (~/.curaiq/hook-policy.json) is in the governed agent's own write scope and carried no
// integrity check, so one already-permitted Bash call —
//
//     echo '{}' > ~/.curaiq/hook-policy.json
//
// — collapsed enforcement outright: `{}` is a "real policy", so it outranks the posture ratchet by
// design (a policy is an AUTHORIZED relaxation), AND it flattens every detector to "notify" via
// threatActionFor's fallback. Measured, not assumed: the exposure is not the 60s freshness window,
// because when the server is unreachable loadPolicy falls back to the SAME file ("cache-offline") for
// the whole outage.
//
// The fix mirrors break-glass exactly rather than inventing a second trust model: the console signs
// each tenant's policy with ed25519, and the device verifies against a key held OUTSIDE the agent's
// write scope (root-owned /etc/moorai/policy.pub, or MDM-injected MOORAI_POLICY_PUBKEY — see
// POLICY_ANCHOR in moorai-hook.mjs). tenant + issued-at are INSIDE the signed bytes, so a genuinely
// signed policy cannot be replayed onto another tenant.
export const POLICY_SIG_VERSION = 1;

// Deterministic serialization — key-sorted, so the digest does not depend on JSON key order or on the
// exact bytes the cache file happens to hold. Must stay byte-identical to the console's canonicalJson.
export function canonicalJson(v) {
  if (v === undefined) return "null";
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}

// sha256 over the whole policy MINUS the signature envelope — every field the engine reads is covered.
export function policyDigest(policy) {
  const { policySig, ...body } = policy || {};
  return createHash("sha256").update(canonicalJson(body)).digest("hex");
}

// The exact bytes signed and verified — a WIRE FORMAT shared with the console; changing it invalidates
// every policy already signed, so it is pinned literally in the tests on both sides.
export function policyCanonical(s) {
  return `moorai-policy|v${s.v}|${s.tenant}|${s.iat}|${s.digest}`;
}

// Verify a policy's signature. Returns { trusted, status }:
//   unanchored | ok            → trusted
//   unsigned | malformed | untrusted | mismatch → NOT trusted; the caller must treat the policy as if
//                                                 it did not exist (fall through to the posture ratchet)
//
// COMPATIBILITY — deliberate choice (a): verification is REQUIRED ONLY WHEN AN ANCHOR IS PRESENT.
// /etc/moorai is optional today and most installs have no anchor at all, so a hard requirement would
// brick every existing endpoint the moment it upgraded (its console may not sign yet either). An
// unanchored device therefore behaves exactly as before — it has no key, so it can verify nothing, and
// pretending otherwise would only convert a silent bypass into a silent outage. A device WITH an anchor
// never accepts an unsigned or unverifiable policy: shipping the anchor IS the opt-in to the guarantee,
// exactly like shipping /etc/moorai/breakglass.pub or the root-owned posture latch.
//
// No max-age check on `iat`: the offline path exists precisely to enforce the last-known policy through
// an outage, so expiring it would defeat #33. iat is inside the signature for audit + future rollback
// detection, not as a TTL.
export function verifyPolicySignature(policy, { keys = [], tenant = "" } = {}) {
  if (!keys.length) return { trusted: true, status: "unanchored" };
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return { trusted: false, status: "malformed" };
  const s = policy.policySig;
  // No envelope at all is named "unsigned" rather than "malformed" — that is both the pre-signing
  // format and the shape a forging agent produces, and a SOC should see it named for what it is.
  if (!s || typeof s !== "object" || typeof s.sig !== "string" || !s.sig) return { trusted: false, status: "unsigned" };
  if (Number(s.v) !== POLICY_SIG_VERSION || s.alg !== "ed25519" || !s.iat) return { trusted: false, status: "malformed" };
  // Re-derive the signed bytes from the named fields and a fresh digest of the body — never trust the
  // file's own byte layout, and never trust a digest the file supplies.
  const msg = Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: String(s.tenant ?? ""), iat: String(s.iat), digest: policyDigest(policy) }));
  let sig;
  try { sig = Buffer.from(s.sig, "base64"); } catch { return { trusted: false, status: "malformed" }; }
  // find, not some: the caller needs to know WHICH key verified so it can be pinned (see pinning below).
  const hit = keys.find((k) => { try { return cryptoVerify(null, msg, k, sig); } catch { return false; } });
  if (!hit) return { trusted: false, status: "untrusted" };
  // Tenant is inside the signature, so a genuinely signed policy cannot be replayed across tenants.
  if (String(s.tenant ?? "") !== String(tenant)) return { trusted: false, status: "mismatch" };
  return { trusted: true, status: "ok", keyId: publicKeyId(hit) };
}

// ---- Policy-key PINNING (Trust On First Use) ----
//
// The hole the signing change above left open, stated plainly: verification was "required only when an
// anchor is present", and the anchor has to be deployed by hand. So on every device WITHOUT
// /etc/moorai/policy.pub — the majority — `echo '{}' > ~/.curaiq/hook-policy.json` still collapsed
// enforcement, because a device with no key can verify nothing. Protection you have to switch on is
// protection most fleets never get.
//
// The fix is the SAME asymmetry ratchetPosture uses: arming is safe and needs no proof, DISarming is an
// enforcement bypass and must never be taken from the agent's write scope. The first time a device sees
// a policy its console really signed, it PINS that signing key (Trust On First Use — already how the
// console trusts device keys). From then on an unsigned policy, one signed by a different key, and one
// signed for a different tenant are all NO policy.
//
// WHAT THIS IS AND IS NOT — the hook runs AS THE USER, so say it straight:
//   * It is TAMPER-EVIDENT, not tamper-proof. An attacker who can write ~/.curaiq/hook-policy.json can
//     also delete the pin. Two copies in two directories (mirroring the posture latch) defeat the
//     one-liner and the `rm -rf ~/.curaiq` wipe, and any PARTIAL erasure or mangling is reported — but
//     an attacker who erases both copies is back at first contact. No key or HMAC can change that: any
//     secret this process can read to authenticate the pin, the attacker can read too.
//   * The root-owned /etc/moorai/policy.pub anchor remains the ONLY hard guarantee, and it still wins:
//     it outranks any pin, and it removes the first-contact window entirely. Ship it to fail-closed
//     fleets. The pin is what protects the devices that never got it.
export const POLICY_PIN_VERSION = 1;

// Canonical identity for a public key: base64 SPKI DER — the same shape MOORAI_POLICY_PUBKEY and the
// console's /api/policy/pubkey use, so a pin can be diffed against either by eye.
export function publicKeyId(key) {
  try {
    // Already a public KeyObject → export it directly; createPublicKey() only accepts a private one.
    const k = key && key.type === "public" ? key : createPublicKey(key);
    return k.export({ type: "spki", format: "der" }).toString("base64");
  } catch { return ""; }
}

// Parse ONE pin copy. Returns null for "not a pin" — absent, empty, unparseable, wrong version, or
// missing either field. The caller distinguishes absent from mangled (mangled is a tamper signal).
export function parsePolicyPin(text) {
  if (!text || !String(text).trim()) return null;
  let p;
  try { p = JSON.parse(text); } catch { return null; }
  if (!p || typeof p !== "object" || Array.isArray(p)) return null;
  if (Number(p.v) !== POLICY_PIN_VERSION) return null;
  if (typeof p.tenant !== "string" || !p.tenant) return null;
  const keys = Array.isArray(p.keys) ? p.keys.filter((k) => typeof k === "string" && k.trim()) : [];
  if (!keys.length) return null;
  return { tenant: p.tenant, keys, updated: typeof p.updated === "string" ? p.updated : "" };
}

// Reconcile the two user-scope copies. Deliberately mirrors ratchetPosture's evidenceMissing: a pin in
// ONE copy is still a pin (erasing one must not disarm the device), and the disagreement is reported.
//   pinned          — this device has, at some point, verified a real console signature
//   corrupt         — a pin file EXISTS but does not parse: we know a pin existed, so refuse rather than
//                     read it as "never pinned". Truncate-the-file is not a downgrade path.
//   evidenceMissing — one copy holds the pin and the other is gone (the erase-the-evidence move)
export function reconcilePolicyPins({ primary = "", secondary = "" } = {}) {
  const raw = { primary, secondary };
  const parsed = {}, states = {};
  for (const k of ["primary", "secondary"]) {
    const t = raw[k];
    if (t == null || !String(t).trim()) { states[k] = "absent"; parsed[k] = null; continue; }
    parsed[k] = parsePolicyPin(t);
    states[k] = parsed[k] ? "pin" : "corrupt";
  }
  const names = ["primary", "secondary"];
  const present = names.filter((k) => states[k] === "pin");
  const corrupt = names.some((k) => states[k] === "corrupt");
  const absent = names.filter((k) => states[k] === "absent");
  const keys = [...new Set(present.flatMap((k) => parsed[k].keys))];
  const tenants = [...new Set(present.map((k) => parsed[k].tenant))];
  return {
    pinned: keys.length > 0 || corrupt,
    keys,
    corrupt,
    tenant: tenants[0] ?? "",
    tenantConflict: tenants.length > 1,
    evidenceMissing: present.length > 0 && absent.length > 0,
    states
  };
}

// Resolve what this device verifies policies against, and how much it may learn. Modes:
//   anchored — an explicit trust anchor is present; it DECIDES, outranking any pin (it is the stronger
//              statement: root put it there, and it covers first contact too)
//   pinned   — no anchor, but this device has verified a real signature before → the pinned keys decide
//   rebind   — a pin exists for a DIFFERENT tenant than config.json now claims. ~/.curaiq/config.json is
//              in the same write scope as the cache, so if a tenant rename silently dropped the pin the
//              pin would be one `sed` away from useless. Refuse everything instead.
//   corrupt  — a pin file exists but is unusable (mangled, or holds keys that will not load). Refuse.
//   unpinned — never armed: verifies nothing, exactly as before this change (the no-brick property)
export function policyTrust({ anchorKeys = [], pin = null, tenant = "" } = {}) {
  if (anchorKeys.length) return { mode: "anchored", keys: anchorKeys };
  if (!pin || !pin.pinned) return { mode: "unpinned", keys: [] };
  if (pin.corrupt) return { mode: "corrupt", keys: [] };
  if (pin.tenantConflict || String(pin.tenant) !== String(tenant)) return { mode: "rebind", keys: [] };
  const keys = parseTrustedKeys(pin.keys.join("\n"));
  // A pin we cannot load keys out of must NOT collapse to "unpinned" — that would make "write garbage
  // into the keys array" a downgrade path.
  if (!keys.length) return { mode: "corrupt", keys: [] };
  return { mode: "pinned", keys };
}

// Read the console's GET /api/policy/pubkey body → the key id(s) it publishes for THIS tenant. Junk, a
// 404 page, and a body published for another tenant all yield [] (→ no pin forms; nothing breaks).
// `keys` (an array) is accepted alongside the single-key shape so a console that publishes an overlap
// pair during rotation works without a device change.
export function parsePublishedKeys(text, { tenant = "" } = {}) {
  let j;
  try { j = JSON.parse(String(text || "")); } catch { return []; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return [];
  if (tenant && j.tenant != null && String(j.tenant) !== String(tenant)) return [];
  const parts = [];
  const push = (x) => { if (typeof x === "string") parts.push(x); else if (x && typeof x === "object") { push(x.pem); push(x.publicKey); } };
  if (Array.isArray(j.keys)) j.keys.forEach(push);
  push(j.publicKey);
  push(j.pem);
  return [...new Set(parseTrustedKeys(parts.join("\n")).map(publicKeyId).filter(Boolean))];
}

// ---- Last-known-good VERIFIED policy ----
//
// The gap the signing/pinning work above left, stated plainly: refusing a poisoned cache means "no
// policy", and for a FAIL-OPEN org "no policy" means exit(0). So an attacker who poisons the cache on a
// pinned device still gets their bypass — the device merely alerts about it on the way out. Detection
// without enforcement is not enforcement.
//
// The fix keeps the last policy that ACTUALLY PASSED SIGNATURE VERIFICATION, delivered fresh over the
// network, and enforces with it when the live and cached copies are both refused. Two properties make
// this safe rather than a second poisoning surface:
//
//   1. It is stored WITH its signature envelope and RE-VERIFIED on load against the same anchor/pin.
//      The file is in the agent's own write scope; "we wrote it" is not a trust argument. A last-known-
//      good the attacker can rewrite is worthless unless the rewrite still verifies — and if they could
//      produce that, they would not need this file.
//   2. A verified FRESH policy always wins and replaces it, so an org that legitimately relaxes its
//      policy is never dragged back to an older, stricter one.
//
// Precedence: verified fresh → verified cache → verified last-known-good → offline default / posture.
// "No policy" is reached only when nothing verifies.
//
// This is a pure selector: the caller supplies the already-read copies (root-owned system copy first,
// then the two user-scope copies) and the same verify() it uses for the cache and the fresh fetch.
export function selectLastKnownGood(copies, verify) {
  for (const c of copies || []) {
    if (!c || !c.raw || !String(c.raw).trim()) continue;
    let v;
    try { v = verify(c.raw); } catch { continue; }
    if (v && v.policy) return { copy: c.source, policy: v.policy, raw: c.raw };
  }
  return null;
}

// ---- Pin absent on a device that shows prior operation ----
//
// The residual risk policy-pin.test.mjs already documents: erasing BOTH pin copies returns an
// unanchored device to first contact, and first contact trusts anything. That cannot be FIXED here —
// the hook runs as the user, and any secret it could read to authenticate the pin, the attacker reads
// too. What CAN be improved is tamper-EVIDENCE: distinguishing "genuinely fresh install" from "device
// that has demonstrably been operating and has now lost its pin".
//
// The discriminator has to be evidence of PRIOR PINNING, not merely of prior operation. That
// distinction is load-bearing and was arrived at by counter-example: "posture files or an action-audit
// log exist but the pin is gone" looks like a strong tamper signal, but it fires on a perfectly healthy
// fleet — a console that does not sign never forms a pin (the documented no-brick property), while its
// devices write posture copies and audit lines from their second run onward. That heuristic would raise
// a Critical alert on every hook invocation for every such device, which is worse than useless.
//
// So `pinningEvidence` is limited to artifacts a device can only hold if it once verified a REAL console
// signature: the pin breadcrumb (written in a third directory whenever a pin exists) and the
// last-known-good store (written only for a fresh policy whose signature actually verified, status
// "ok" — never for the trivially-trusted unanchored case). `operationEvidence` is carried alongside as
// SOC context only; it never decides, precisely because of the false positive above.
//
// Deliberately NOT a fail-closed trigger — see the reasoning recorded next to the caller.
export function assessPinAbsence({ enrolled = false, trustMode = "unpinned", pinningEvidence = [], operationEvidence = [] } = {}) {
  // Only an UNPINNED device is in this state at all. anchored/pinned have their key; corrupt/rebind are
  // already reported as their own, stronger tamper signals.
  const clean = (a) => [...new Set((a || []).filter(Boolean))].sort();
  if (trustMode !== "unpinned" || !enrolled) return { suspicious: false, evidence: [], context: [] };
  const evidence = clean(pinningEvidence);
  return { suspicious: evidence.length > 0, evidence, context: evidence.length ? clean(operationEvidence) : [] };
}

// ---- Windows ACL evaluation for readRootOwned ----
//
// On POSIX a "system" file is trusted only when the OS says the user cannot have written it: root-owned
// and not group/world-writable. On Windows there is no such thing to stat, and readRootOwned used to
// return %ProgramData%\MoorAI\* contents UNCONDITIONALLY — so on Windows the trust anchor, the policy
// anchor and the machine-wide posture latch were all trusted with no verification at all, even though
// %ProgramData% subtrees created by a non-elevated process inherit a permissive ACL.
//
// These functions evaluate `icacls <file>` output. Kept pure so they are testable off-Windows; the
// caller does the spawn and fails CLOSED (treats the file as untrusted) on any error.

// Inheritance/propagation flags icacls prints in their own parentheses — they are not rights.
const ICACLS_FLAGS = new Set(["OI", "CI", "IO", "NP", "I"]);

// Rights that let the holder change or replace the file's bytes. Covers both the simple rights icacls
// prints as a single letter group (F/M/W) and the comma-separated specific rights.
const ICACLS_WRITE = new Set(["F", "M", "W", "WD", "AD", "WA", "WEA", "D", "DE", "DC", "WDAC", "WO"]);

// Principals whose write access does NOT make a file user-writable, because holding them already
// requires administrator/SYSTEM privilege — the same bar POSIX root-ownership sets. Anything else with
// write access is treated as ordinary-user write, INCLUDING named user accounts: this is an allow-list
// on purpose. A denied-by-mistake ACL degrades the device to "no anchor" (its behavior before the file
// existed), which is the safe direction; an accepted-by-mistake ACL is a silent enforcement bypass.
// CREATOR OWNER is deliberately ABSENT: it is not an administrator, it is whoever created the file —
// which under %ProgramData%, in the exact scenario this check exists for, is the ordinary user. The
// standard inherited CREATOR OWNER ACE is harmless because it is inherit-ONLY (IO) and therefore does
// not apply to the file itself; that is handled below, and it is the right reason to ignore it.
const ICACLS_PRIVILEGED = new Set([
  "SYSTEM", "LOCAL SYSTEM", "ADMINISTRATORS", "ADMINISTRATOR", "TRUSTEDINSTALLER",
  "DOMAIN ADMINS", "ENTERPRISE ADMINS"
]);

// "NT AUTHORITY\\Authenticated Users" → "AUTHENTICATED USERS"; "BUILTIN\\Users" → "USERS".
export function normalizeAclPrincipal(name) {
  const s = String(name || "").trim();
  const i = s.lastIndexOf("\\");
  return (i >= 0 ? s.slice(i + 1) : s).trim().toUpperCase();
}

// Parse `icacls <path>` output into ACEs. The first line carries the path before the first ACE; pass
// filePath so it can be stripped exactly rather than guessed at.
export function parseIcacls(output, filePath = "") {
  const p = String(filePath || "");
  const aces = [];
  for (const rawLine of String(output || "").split(/\r?\n/)) {
    if (!rawLine || !rawLine.trim()) continue;
    if (/^(Successfully processed|Failed processing)/i.test(rawLine.trim())) continue;
    const line = p && rawLine.startsWith(p) ? rawLine.slice(p.length) : rawLine;
    // principal:(flag)(flag)(rights) — the principal is everything before the colon that is immediately
    // followed by the parenthesised groups that run to end of line.
    const m = line.match(/^\s*(.+?):((?:\([^()]*\))+)\s*$/);
    if (!m) continue;
    const groups = (m[2].match(/\(([^()]*)\)/g) || []).map((g) => g.slice(1, -1).trim());
    const rights = [];
    let inheritOnly = false;
    for (const g of groups) {
      const u = g.toUpperCase();
      if (ICACLS_FLAGS.has(u)) { if (u === "IO") inheritOnly = true; continue; }
      for (const t of u.split(",")) { const tok = t.trim(); if (tok) rights.push(tok); }
    }
    aces.push({ principal: m[1].trim(), rights, inheritOnly });
  }
  return aces;
}

// Decide whether an ACL leaves the file writable by someone who is not an administrator. Returns
// { permissive, reasons } — reasons name the offending principal + rights, never file content.
// An ACL with NO parseable entries is permissive: we could not establish the guarantee, so we do not
// claim it (fail closed), exactly as a POSIX stat failure reads as untrusted.
export function icaclsPermissive(output, filePath = "") {
  const aces = parseIcacls(output, filePath);
  if (!aces.length) return { permissive: true, reasons: ["no-acl-entries"], aces };
  const reasons = [];
  for (const a of aces) {
    if (a.inheritOnly) continue; // inherit-only ACEs govern children, not this file
    const w = a.rights.filter((r) => ICACLS_WRITE.has(r));
    if (!w.length) continue;
    const who = normalizeAclPrincipal(a.principal);
    if (ICACLS_PRIVILEGED.has(who)) continue;
    reasons.push(`${who}:${w.join("+")}`);
  }
  return { permissive: reasons.length > 0, reasons, aces };
}

// Fail-closed MCP floor: raise an otherwise-allowed MCP decision to policy.mcpFloor (e.g. "ask"). Inert
// unless the policy sets mcpFloor — normal policies never do, so this is backward-compatible.
export function mcpFloor(policy, decision) {
  const floor = policy && policy.mcpFloor;
  if (!floor || !RANK[floor]) return decision;
  return RANK[floor] > RANK[decision] ? floor : decision;
}

// Conservative file-path extraction from a Bash command — only for unambiguous leading file-readers.
// Anything with a pipe/redirect/subshell is left alone (fail-open); the strong guarantee is on Read.
export function extractReadPaths(command) {
  const cmd = String(command || "").trim();
  if (!cmd || /[|><`$(){}]|&&|\|\|/.test(cmd)) return [];
  const m = cmd.match(/^(?:cat|head|tail|less|bat|xxd|nl|more)\s+(.+)$/);
  if (!m) return [];
  return m[1].split(/\s+/).filter((t) => t && !t.startsWith("-")).slice(0, 8);
}
