// #1/#2/#3 — shared core for the MoorAI PreToolUse hook AND the Claude Desktop MCP proxy. Kept
// separate from the stdin/stdout entrypoints (cli/moorai-hook.mjs, mcp-proxy/moorai-mcp-guard.mjs) so
// the decision logic is unit-testable without spawning a process. Governance, not a sandbox: on any
// error or missing policy the caller fails OPEN (allows).
//
// Everything down to the "Policy TRUST + LOAD" banner near the bottom is pure. That last section owns
// the policy-trust I/O, and it is here rather than in one entrypoint precisely because BOTH need it.

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createPublicKey, verify as cryptoVerify, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import os from "node:os";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { extractEndpointHosts, endpointApproved, extractTransitOverrides, proxyApproved } from "../data/model-endpoints.js";
import { statePath, latchPath, breadcrumbPath } from "./state-dirs.mjs";
import { TIER_OF } from "../data/data-tiers.js";
import { APPROVAL_THREATS } from "../data/human-approval.js";
import { compilePacks } from "../data/detector-packs.js";
import { redosReason, safeRegex, unboundedQuantifiers } from "../src/safe-regex.js";
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

// ---- ReDoS gate for POLICY-SUPPLIED regexes ----
//
// policy.mcpToolRules[tool].deny/allow are pattern STRINGS shipped by the console and compiled here.
// They used to go straight into `new RegExp(p, "i")` with no gate at all, so one crafted pattern hung
// every MCP tool call on the device. Measured on this repo (node v22, `re.test()`, wall clock):
//
//   "(a+)+$"      vs 31 a's + "!"  →  56402 ms   (caught by data/detector-packs.js's guard)
//   "(a|a)+$"     vs 29 a's + "!"  →  28144 ms   (NOT caught by it — overlapping alternation)
//   ".*.*="       vs 1000 a's      →    188 ms   (NOT caught — quadratic, and 8546 ms at n=4000)
//   "a.*a.*a.*="  vs 1000 a's      →  55990 ms   (NOT caught — cubic)
//
// So the detector-pack guard's two rules are necessary but far from sufficient. The rule that actually
// separates the measured-fast from the measured-catastrophic is not "which shapes look nested" but
// HOW MANY unbounded quantifiers the pattern has: with at most one, and with no ambiguous quantified
// alternation, matching degrades to linear-per-start-position and the worst shapes measured at 50 KB
// were ~900 ms rather than minutes (see MAX_QUANTIFIED_SCAN below).
//
// The cost of the rule is over-rejection: a refused pattern is DROPPED (the same as today's `catch`
// on an uncompilable pattern), so a deny rule that needs two `.*` stops enforcing. That is acceptable
// here specifically because `decideMcpArgs` uses an UNANCHORED `.test()`: leading and trailing `.*`
// are redundant by construction (`.*foo.*` ≡ `foo`), and `deny` is a LIST, so "foo then bar" is
// naturally written as two entries rather than `.*foo.*bar.*`.
//
// The guard itself lives in ../src/safe-regex.js so data/detector-packs.js can share it without
// closing an import cycle (this file imports compilePacks from there). Re-exported here because both
// the MCP proxy and the tests import it from hook-core.
export { redosReason, safeRegex };

// Execution bound. A pattern that survives redosReason() still costs O(n²) in the worst case because
// `.test()` retries at every start position: measured at 50 KB, the worst surviving shapes ("a*b",
// ".*END", "(ab|cd)+z") took ~900 ms. Patterns with NO unbounded quantifier are linear and are given
// the FULL text — which is what real deny rules look like ("BLOCKME", "AKIA[0-9A-Z]{16}"), so the
// common case loses no coverage at all. Only a quantifier-bearing pattern sees a truncated view, at
// 16 KB — the same measurements scale to ~90 ms there. A length cap is preferred over a per-pattern
// timeout because regex execution in V8 is synchronous and cannot be interrupted in-process.
const MAX_QUANTIFIED_SCAN = 16384;
function boundedText(re, text) {
  return unboundedQuantifiers(re.source) === 0 || text.length <= MAX_QUANTIFIED_SCAN ? text : text.slice(0, MAX_QUANTIFIED_SCAN);
}

// #18 — per-tool MCP argument rules. policy.mcpToolRules[tool] = { deny:[regex], allow:[regex] }.
// A deny pattern matched in the serialized args → deny. If an allow-list is set for the tool, at least
// one allow pattern must match or it's denied. No rule for the tool → allow (unchanged behavior).
export function decideMcpArgs(policy, tool, argsText) {
  const rules = policy?.mcpToolRules?.[tool];
  if (!rules) return { decision: "allow" };
  const text = String(argsText || "");
  const hit = (p) => { const re = safeRegex(p); return re ? re.test(boundedText(re, text)) : false; };
  if (Array.isArray(rules.deny)) for (const p of rules.deny) { if (hit(p)) return { decision: "deny", reason: `${tool} argument matches a denied pattern` }; }
  if (Array.isArray(rules.allow) && rules.allow.length) {
    if (!rules.allow.some(hit)) return { decision: "deny", reason: `${tool} argument is not on the allow-list` };
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

// T1-1 / #67 — transit interception. decideEndpoints() asks WHERE the agent is sending and is
// therefore blind to this: a proxy override does not change the destination, so the host stays
// api.anthropic.com and the allow-list passes it while every byte transits an interceptor.
//
// Report-first, deliberately. A corporate egress proxy is legitimate and common, so an unset
// `transitAllow` reports rather than denies; only an explicit allow-list makes an unsanctioned proxy
// a deny. A CA override is reported on its own even with no proxy — on its own it is inert, but it
// is the half that makes interception SILENT (the forged chain validates), so it is worth surfacing.
export function decideTransit(policy, text) {
  const { proxies, caVars } = extractTransitOverrides(text);
  if (!proxies.length && !caVars.length) return { decision: "allow", proxies: [], caVars: [] };
  const allow = policy?.transitAllow;
  const bad = proxies.filter((h) => !proxyApproved(h, allow));
  const armed = Array.isArray(allow) && allow.length;
  const reason = [
    bad.length ? `proxy not on the allow-list: ${bad.join(", ")}` : "",
    caVars.length ? `CA trust override: ${caVars.join(", ")}` : ""
  ].filter(Boolean).join("; ");
  return { decision: armed && bad.length ? "deny" : "allow", proxies, caVars, bad, reason };
}

// T1-5 / #64 — agent entitlement envelope. policy.entitlements = { tools:[], paths:[], mcp:[] } declares
// the agent's authorized surface; an observed tool / path-prefix / MCP server outside it is "drift".
// Returns the out-of-scope reasons (empty = in scope). Enforcement strictness is policy.entitlementMode
// ("off" | "alert" | "block"). Content-free: names/paths only. An empty/absent envelope → always in scope.
//
// A path is in scope when it IS the allowed prefix or sits under it. The boundary check matters: a
// bare `startsWith` also put `/Users/dev/acme-app-secrets` inside an `/Users/dev/acme-app` envelope,
// so a sibling directory that merely shared a leading substring escaped the confinement entirely.
export function pathInScope(p, allowed) {
  const path = String(p), a = String(allowed).replace(/[/\\]+$/, "");
  if (!a) return true;
  if (path === a) return true;
  const next = path[a.length];
  return path.startsWith(a) && (next === "/" || next === "\\");
}

export function decideEnvelope(policy, { tool, paths = [], mcpServer, actor } = {}) {
  const env = policy?.entitlements;
  if (!env || typeof env !== "object") return { inScope: true, reasons: [], elevated: false };
  const reasons = [];
  if (Array.isArray(env.tools) && env.tools.length && tool && !env.tools.includes(tool)) reasons.push(`tool:${tool}`);
  if (Array.isArray(env.mcp) && env.mcp.length && mcpServer && !env.mcp.includes(mcpServer)) reasons.push(`mcp:${mcpServer}`);
  if (Array.isArray(env.paths) && env.paths.length) {
    for (const p of paths) { if (p && !env.paths.some((a) => pathInScope(p, a))) reasons.push(`path:${p}`); }
  }
  // JIT elevation: an out-of-envelope reason covered by a live, non-expired grant for THIS actor is
  // allowed (time-boxed) rather than flagged. Grants are exact for tool:/mcp:, prefix for path:.
  const grants = (Array.isArray(policy?.elevations) ? policy.elevations : []).filter((g) => !actor || g.actor === actor);
  // Same label-boundary rule as the envelope itself: a grant for path:/Users/dev/acme-app must not
  // silently cover path:/Users/dev/acme-app-secrets.
  const covered = (r) => grants.some((g) => g.capability === r ||
    (g.capability.startsWith("path:") && r.startsWith("path:") && pathInScope(r.slice(5), g.capability.slice(5))));
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
export function ratchetPosture({ system = "", state = "", latch = "", legacy = "", env = "" } = {}) {
  const norm = (v) => (String(v ?? "").trim() === "fail-closed" ? "fail-closed" : String(v ?? "").trim() === "fail-open" ? "fail-open" : "");
  const s = { system: norm(system), state: norm(state), latch: norm(latch), legacy: norm(legacy), env: norm(env) };
  const hardenedBy = Object.keys(s).filter((k) => s[k] === "fail-closed");
  if (!hardenedBy.length) return { posture: "fail-open", hardenedBy, downgradeAttempt: [], evidenceMissing: false, sources: s };
  // The two ACTIVE write legs — `state` (~/.moorai) and `latch` (~/.config/moorai), in different dirs.
  // `legacy` (pre-rebrand ~/.curaiq, read-only) still hardens and is still flagged if someone sets it
  // to fail-open, but its ABSENCE is normal on a post-rebrand install, so it must not count toward
  // evidenceMissing — only a partial erasure of the two active legs does.
  const activePair = [s.state, s.latch];
  return {
    posture: "fail-closed",
    hardenedBy,
    downgradeAttempt: ["system", "state", "latch", "legacy", "env"].filter((k) => s[k] === "fail-open"),
    evidenceMissing: activePair.includes("fail-closed") && activePair.includes(""),
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
// an outage, so expiring it would defeat #33. iat is inside the signature for audit and for ROLLBACK
// detection, not as a TTL. The rollback comparison itself is deliberately NOT here: this function is
// pure and stateless, and the high-water mark it would need is device state. It lives in
// loadVerifiedPolicy's verify(), against the mark reconciled from the pin and the root-owned copy — see
// the F-202 section above.
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
  // `iat` is the policy high-water mark (F-202). Optional and absent from every pin written before it
  // existed, so it must never be a parse requirement — an old pin stays a valid pin with no mark yet.
  return { tenant: p.tenant, keys, iat: Number.isFinite(iatOrder(p.iat)) ? String(p.iat) : "", updated: typeof p.updated === "string" ? p.updated : "" };
}

// Reconcile the two user-scope copies. Deliberately mirrors ratchetPosture's evidenceMissing: a pin in
// ONE copy is still a pin (erasing one must not disarm the device), and the disagreement is reported.
//   pinned          — this device has, at some point, verified a real console signature
//   corrupt         — a pin file EXISTS but does not parse: we know a pin existed, so refuse rather than
//                     read it as "never pinned". Truncate-the-file is not a downgrade path.
//   evidenceMissing — one copy holds the pin and the other is gone (the erase-the-evidence move)
export function reconcilePolicyPins({ primary = "", secondary = "", legacy = "" } = {}) {
  const raw = { primary, secondary, legacy };
  const parsed = {}, states = {};
  for (const k of ["primary", "secondary", "legacy"]) {
    const t = raw[k];
    if (t == null || !String(t).trim()) { states[k] = "absent"; parsed[k] = null; continue; }
    parsed[k] = parsePolicyPin(t);
    states[k] = parsed[k] ? "pin" : "corrupt";
  }
  const names = ["primary", "secondary", "legacy"];
  const present = names.filter((k) => states[k] === "pin");
  const corrupt = names.some((k) => states[k] === "corrupt");
  const keys = [...new Set(present.flatMap((k) => parsed[k].keys))];
  const tenants = [...new Set(present.map((k) => parsed[k].tenant))];
  // The MAX mark across ALL copies (incl. the read-only legacy leg), for the same reason a pin in ONE
  // copy is still a pin: erasing or rewinding one copy must not lower the device's high-water mark.
  const iat = present.reduce((acc, k) => maxIat(acc, parsed[k].iat), "");
  // evidenceMissing tracks only the two ACTIVE write legs — a post-rebrand device legitimately has no
  // legacy (~/.curaiq) copy, so its absence must not read as an erase-the-evidence move.
  const active = ["primary", "secondary"];
  const activePresent = active.filter((k) => states[k] === "pin");
  const activeAbsent = active.filter((k) => states[k] === "absent");
  return {
    pinned: keys.length > 0 || corrupt,
    keys,
    iat,
    corrupt,
    tenant: tenants[0] ?? "",
    tenantConflict: tenants.length > 1,
    evidenceMissing: activePresent.length > 0 && activeAbsent.length > 0,
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

// ---- Signing-key REVOCATION (F-201) ----
//
// The gap: the pin only ever GREW. writePolicyPin unioned every newly-learned key into the set and
// verifyPolicySignature accepts a signature from ANY key in it, so a leaked K1 stayed trusted forever on
// every already-pinned device — even after the operator completed the documented rotation to K2. That
// makes rotation a continuity mechanism and NOT a compromise-recovery one, which is the opposite of what
// an operator reaches for it for.
//
// The channel is a `revokedKeys` array INSIDE the policy body, so it is covered by policyDigest and
// therefore by the console's existing signature — no new key, no new endpoint, no new trust root. The
// console does not emit the field yet; absent ⇒ [] ⇒ behaviour is byte-identical to before.
//
// WHAT THIS IS AND IS NOT. Same honesty as the pin above: both pin copies live under the user's home, so
// on an UNANCHORED device an attacker who can write the policy cache can also rewrite the pin and undo a
// pruning. Revocation there is TAMPER-EVIDENT (a refusal raises a content-free alert), not enforced. On
// a device with the root-owned /etc/moorai/policy.pub anchor the pin does not decide at all, so a key
// removed from the anchor is genuinely gone — that is the hard guarantee, and it is the anchor's, not
// this function's. Nor does this stop a stolen key from acting WITH its stolen authority: a thief
// holding K1 can sign anything K1 could sign, revoking K2 included. What it does buy is that the
// operator, signing with K2, can take K1 out of the fleet's keyring without waiting for every device to
// be reprovisioned.
export function parseRevokedKeys(policy) {
  const r = policy && policy.revokedKeys;
  if (!Array.isArray(r)) return [];
  return [...new Set(r.filter((k) => typeof k === "string" && k.trim()).map((k) => k.trim()))];
}

// Prune revoked ids out of a pin set. `refused` is a content-free reason the caller reports as tampering;
// when it is set, NOTHING is pruned — a revocation we cannot apply safely is not applied at all.
//
//   self  — the policy carrying the list verifies under a key the list itself revokes (or under no
//           identified key at all). Honouring that would let a stolen K1 order K1's own replacement out
//           of the pin and lock the operator out of their own fleet.
//   empty — applying the list would leave the pin with NO keys. That is the most dangerous outcome in
//           this whole change and the reason it is checked explicitly: policyTrust would report the
//           device as "unpinned" and verifyPolicySignature answers { trusted: true, status: "unanchored" }
//           for an empty key set, so an over-broad revocation would not tighten the device, it would
//           turn every future unsigned policy into an accepted one. Refuse and alert instead.
export function applyKeyRevocation({ keys = [], revoked = [], verifiedBy = "" } = {}) {
  const list = parseRevokedKeys({ revokedKeys: revoked });
  const hit = keys.filter((k) => list.includes(k));
  if (!hit.length) return { keys, pruned: [], refused: "" };
  if (!verifiedBy || list.includes(verifiedBy)) return { keys, pruned: [], refused: "self" };
  const kept = keys.filter((k) => !list.includes(k));
  if (!kept.length) return { keys, pruned: [], refused: "empty" };
  return { keys: kept, pruned: hit, refused: "" };
}

// ---- Policy `iat` HIGH-WATER MARK (F-202) ----
//
// The gap: verifyPolicySignature checks the signature, the alg and the tenant, but nothing compared
// `iat` against anything, and no monotonic state existed anywhere. So an OLD but validly signed policy
// could be replayed — most directly by the governed agent itself, via an already-permitted write to
// ~/.curaiq/hook-policy.json — to roll a tightening back, silently, with a signature that verifies.
//
// The mark is the highest `iat` this device has ever ACCEPTED from a real console signature. A policy
// whose iat is STRICTLY older is refused. Strictly: an unchanged policy re-fetched with the same iat
// must keep being accepted, or every steady-state fetch breaks.
//
// HARD vs EVIDENT, again: the user-scope mark lives beside the pin and is as erasable as the pin, so on
// an unanchored device this is tamper-EVIDENT (refusal + content-free alert) and an attacker who rewinds
// both copies is back where they started. A root-owned /etc/moorai/policy-hwm.json (or the ProgramData
// equivalent) that an MDM ships is the hard version: the hook only ever reads it, and it wins whenever
// it is higher. An UNPINNED device gets nothing from this at all — it verifies no signatures, so it has
// no accepted-policy history to be monotonic about, and no mark is ever recorded for it.
export function iatOrder(iat) {
  const s = String(iat ?? "").trim();
  if (!s) return NaN;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : NaN;
}
// Unparseable or absent on EITHER side ⇒ no comparison is possible ⇒ not a rollback. A device that has
// never recorded a mark, and a console that dates its policies in some format Date.parse cannot read,
// both keep working exactly as before rather than refusing everything.
export function isPolicyRollback(iat, mark) {
  const a = iatOrder(iat), b = iatOrder(mark);
  return Number.isFinite(a) && Number.isFinite(b) && a < b;
}
export function maxIat(a, b) {
  const x = iatOrder(a), y = iatOrder(b);
  if (!Number.isFinite(y)) return Number.isFinite(x) ? String(a) : "";
  if (!Number.isFinite(x)) return String(b);
  return y > x ? String(b) : String(a);
}

// The root-owned mark's file format: the same shape as the pin, minus the keys. Wrong version or another
// tenant's mark reads as "no mark" rather than as an error — a stale MDM drop must not brick the device.
export function parsePolicyHwm(text, { tenant = "" } = {}) {
  let j;
  try { j = JSON.parse(String(text || "")); } catch { return ""; }
  if (!j || typeof j !== "object" || Array.isArray(j)) return "";
  if (Number(j.v) !== POLICY_PIN_VERSION) return "";
  if (tenant && String(j.tenant ?? "") !== String(tenant)) return "";
  return Number.isFinite(iatOrder(j.iat)) ? String(j.iat) : "";
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

// =============================================================================================
// Policy TRUST + LOAD (I/O).  SHARED, deliberately: this used to live only in cli/moorai-hook.mjs,
// and mcp-proxy/moorai-mcp-guard.mjs carried a verbatim COPY of the hook's pre-v0.51 loader —
// `JSON.parse(readFileSync(CACHE))`, no signature check, no anchor, no pin. So v0.53.0 closed
// `echo '{}' > ~/.curaiq/hook-policy.json` for Claude Code while leaving Claude Desktop wide open
// through the very same file. A copy is exactly how that door was left open, so there is now ONE
// implementation and both entrypoints call loadVerifiedPolicy().
//
// This section is the only part of hook-core that touches the filesystem, the network and the
// clock; everything above it is still pure. The pure primitives it composes (verifyPolicySignature,
// policyTrust, reconcilePolicyPins, selectLastKnownGood, assessPinAbsence, icaclsPermissive) live
// above and are unchanged.
// =============================================================================================

// Windows has no POSIX ownership to stat, and this function used to return %ProgramData%\MoorAI\*
// contents UNCONDITIONALLY there — so on Windows the break-glass anchor, the policy anchor and the
// machine-wide posture latch were all "trusted" with no verification that an ordinary user could not
// have written them. That is not a theoretical gap: a %ProgramData% subtree created by a non-elevated
// process inherits an ACL that lets its creator (and often BUILTIN\Users) write.
//
// So ask the OS. `icacls <file>` is present on every supported Windows and needs no dependency; the
// parsing lives in hook-core.mjs (icaclsPermissive) as a pure function so it can be tested off-Windows.
// Everything here is the thin part: spawn, cache, and FAIL CLOSED — if the check cannot be performed
// (icacls missing, access denied, timeout, unparseable output) or the ACL grants write to anyone who is
// not an administrator, the file is untrusted and reads as "", exactly as a user-writable POSIX file does.
//
// Cached for the life of the process: this runs on every hook invocation, and one hook invocation is
// one tool call — so the cache dedupes the anchor paths WITHIN one tool call and nothing across calls.
//
// VALIDATED on a real Windows 11 box (DESKTOP-JOL2MB8): 10 captures, 10 correct verdicts. The parser
// itself is exercised off-Windows by test/windows-acl.test.mjs, which now carries the real captures.
// The spawn wrapper right below is still not covered by a test.
//
// KNOWN GAP — `icacls` NEVER PRINTS THE FILE'S OWNER, and this check therefore does not consider it.
// Confirmed absent from all 10 real captures, and the icacls reference has no owner-display switch at
// all (only `/setowner`, which writes). That matters because an object's owner implicitly holds
// WRITE_DAC — "An object's owner implicitly has WRITE_DAC access to the object" — and the owner of a
// new object is "the default owner SID from the primary or impersonation token of the creating
// process" (learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). So a file whose
// DACL reads administrator-only can still be OWNED by an ordinary user, who can re-grant themselves at
// will. Concretely: create the anchor (C:\ProgramData inherits BUILTIN\Users:(CI)(WD,AD,WEA,WA) onto
// C:\ProgramData\MoorAI, so an unprivileged process can), then `icacls f /inheritance:r /grant
// SYSTEM:(F) Administrators:(F)` to scrub your own inherited CREATOR OWNER ACE. icacls then reports a
// clean admin-only DACL, this function returns true, and the forged anchor is trusted.
//
// DECIDED (deliberately): NOT fixed here, because the owner probe is the wrong place to fix it.
//   - It cannot be done cheaply. icacls has no owner switch, so it needs a second spawn per anchor
//     path — PowerShell Get-Acl (hundreds of ms, on a hot path that already spawns icacls up to 4x per
//     tool call) or `dir /q`, whose output is locale-dependent and cannot be parsed reliably blind.
//   - Its failure mode is worse than the gap. This code fails closed, so an owner probe that misparses
//     on some locale/host turns EVERY Windows anchor untrusted at once and silently drops policy and
//     break-glass enforcement fleet-wide.
//   - The precondition is removable for free, one level up. The whole attack needs an unprivileged
//     process to create a file under C:\ProgramData\MoorAI. packaging/mdm/intune/Install-MoorAI.ps1
//     creates that directory with `New-Item -Force` and NO ACL hardening, so it simply inherits
//     C:\ProgramData's user-writable ACE. One `icacls /inheritance:r /grant` there, at install time,
//     as SYSTEM, kills the DACL path and the owner path together at zero hot-path cost. Do that first.
// UNPROVEN, and the measurement that would settle it: on the real box, from a NON-elevated shell, run
// `New-Item C:\ProgramData\MoorAIOwnerProbe\p.pub -Force` then `(Get-Acl ...).Owner`. If that returns
// the user rather than BUILTIN\Administrators, the bypass above is reachable as written. (Files
// created there by an ELEVATED admin were measured as owned by BUILTIN\Administrators, which is the
// uninteresting case — a privileged owner. The non-elevated case was never run.)
const WIN_ACL_CACHE = new Map();
function windowsFileIsProtected(p) {
  if (WIN_ACL_CACHE.has(p)) return WIN_ACL_CACHE.get(p);
  let ok = false;
  try {
    const out = execFileSync("icacls", [p], { encoding: "utf8", timeout: 3000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
    ok = !icaclsPermissive(out, p).permissive;
  } catch { ok = false; }
  WIN_ACL_CACHE.set(p, ok);
  return ok;
}

// Read a file that is only trusted when the OS says the user cannot have written it: root-owned and
// not group/world-writable on POSIX, administrator/SYSTEM-only per its ACL on Windows. Anything else —
// missing, user-owned, loosely permissioned, or unverifiable — reads as "", because a "system" file the
// agent can rewrite is worth exactly as much as one under ~/.curaiq. statSync first, so a file that does
// not exist costs nothing and never spawns anything.
export function readRootOwned(p) {
  try {
    const st = statSync(p);
    if (process.platform === "win32") { if (!windowsFileIsProtected(p)) return ""; }
    else if (st.uid !== 0 || (st.mode & 0o022)) return "";
    return readFileSync(p, "utf8");
  } catch { return ""; }
}
export function readText(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }

// The policy cache is a SINGLE-location file (not a fallback read): a legacy fallback would let a
// stale ~/.curaiq cache shadow a freshly-written ~/.moorai one. It is ephemeral (re-fetched every 60s),
// so a pre-rebrand ~/.curaiq cache is simply ignored and replaced on the next fetch — no data to lose.
export const POLICY_CACHE = statePath("hook-policy.json");

// Two user-scope copies of the offline posture in DELIBERATELY-DIFFERENT directories, so a one-liner
// erasure (`rm ~/.moorai/posture`, `rm -rf ~/.moorai`) or a single-file `rm` cannot take the device's
// memory with it, and a PARTIAL erasure stays detectable (evidenceMissing). POSTURE_STATE (~/.moorai)
// was the pre-rebrand latch, so its value is continuous across the rebrand; POSTURE_LATCH is the fresh
// second directory. POSTURE_LEGACY is the pre-rebrand ~/.curaiq sidecar, kept READ-ONLY and folded
// into the primary leg on read (strongestPosture) so an install that predates the rebrand — where the
// only copy was in ~/.curaiq — is never silently downgraded to fail-open.
export const POSTURE_STATE = statePath("posture");
export const POSTURE_LATCH = latchPath("posture");
export const POSTURE_LEGACY = join(os.homedir(), ".curaiq", "offline-posture");
// Machine-wide posture latch — the trustworthy source. Root-owned and not group/world-writable, the
// same rule as breakglass.pub, and provisioned the same way (installer/MDM). It is the only posture
// source a same-user process genuinely cannot rewrite, so a fail-closed fleet should ship it:
//
//   # macOS/Linux, via MDM alongside /etc/moorai/breakglass.pub
//   sudo install -d -m 0755 -o root /etc/moorai
//   printf fail-closed | sudo tee /etc/moorai/offline-posture >/dev/null
//   sudo chown root /etc/moorai/offline-posture && sudo chmod 0644 /etc/moorai/offline-posture
//   # Windows → %ProgramData%\MoorAI\offline-posture (ACL: Administrators/SYSTEM write only)
//
// To retire it, remove the file (root) — the device then falls back to the user-scope copies, which a
// real policy keeps current. The hook never writes here; it only reads.
export const SYSTEM_POSTURE = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "offline-posture")
  : "/etc/moorai/offline-posture";

// Policy-key PIN (Trust On First Use) — the self-arming half of policy verification. Two copies in two
// DIFFERENT directories, exactly like the posture latch and for exactly the same reason: `rm
// ~/.curaiq/policy-pin.json` and `rm -rf ~/.curaiq` must not take the device's memory with them, and a
// partial erasure must be visible. There is deliberately no third, root-owned pin: the hook runs as the
// user and cannot write /etc, so a "system pin" it wrote would be a fiction. The root-owned path that
// does exist is POLICY_ANCHOR below — provisioned by MDM, outranking every pin. See the pinning section
// in hook-core.mjs for what this achieves (tamper-EVIDENCE) and what it does not (tamper-proofing).
const POLICY_PIN = statePath("policy-pin.json");           // ~/.moorai — primary (was the latch; continuous)
const POLICY_PIN_LATCH = latchPath("policy-pin.json");     // ~/.config/moorai — fresh second directory
const POLICY_PIN_LEGACY = join(os.homedir(), ".curaiq", "policy-pin.json"); // pre-rebrand, READ-ONLY

// Root-owned copy of the policy `iat` high-water mark (F-202). The user-scope mark rides inside the two
// pin copies above and is exactly as erasable as they are — tamper-EVIDENT. This one is the hard
// version, provisioned the same way as the posture latch and read the same way (readRootOwned: root-owned
// and not group/world-writable on POSIX, Administrators/SYSTEM-only per its ACL on Windows). The hook
// NEVER writes here; a mark this process could write would be a mark the attacker could write.
//
//   # macOS/Linux, via MDM alongside /etc/moorai/policy.pub
//   printf '{"v":1,"tenant":"acme","iat":"2026-08-21T00:00:00.000Z"}' | sudo tee /etc/moorai/policy-hwm.json >/dev/null
//   sudo chown root /etc/moorai/policy-hwm.json && sudo chmod 0644 /etc/moorai/policy-hwm.json
//   # Windows → %ProgramData%\MoorAI\policy-hwm.json  (ACL: Administrators/SYSTEM write only)
const POLICY_HWM_SYSTEM = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "policy-hwm.json")
  : "/etc/moorai/policy-hwm.json";

// Last-known-good VERIFIED policy — the copies that let a fail-open org ENFORCE through a poisoned
// cache instead of merely alerting about it. Same two-copy user-scope pattern as the pin and the
// posture latch, plus a root-owned system copy that is preferred when one exists (an MDM can drop a
// signed policy there; the hook only ever reads it). The stored bytes are the console's ORIGINAL signed
// body and are re-verified on load — see selectLastKnownGood in hook-core.mjs for why that matters.
const POLICY_LKG = statePath("policy-lkg.json");            // ~/.moorai — primary (was the latch; continuous)
const POLICY_LKG_LATCH = latchPath("policy-lkg.json");      // ~/.config/moorai — fresh second directory
const POLICY_LKG_LEGACY = join(os.homedir(), ".curaiq", "policy-lkg.json"); // pre-rebrand, READ-ONLY
const POLICY_LKG_SYSTEM = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "policy-lkg.json")
  : "/etc/moorai/policy-lkg.json";

// "This device has held a policy-key pin" — a breadcrumb in a THIRD directory, deliberately outside both
// ~/.curaiq and ~/.moorai so that `rm ~/.curaiq/policy-pin.json ~/.moorai/policy-pin.json` (and the
// `rm -rf ~/.curaiq` wipe) leaves something behind that contradicts "this is a fresh install". It holds
// no key and no secret — it could not usefully hold one, since the hook runs as the user and anything it
// can read the attacker can read. Its only job is to make an ERASED pin distinguishable from an absent
// one. Deleting it too is possible and is the stated residual risk.
const PIN_BREADCRUMB = breadcrumbPath("pinned");
// Pre-rebrand breadcrumb (POSIX only — on Windows BREADCRUMB_DIR is the same %LOCALAPPDATA%\MoorAI, so
// the crumb is continuous). READ-ONLY: a device that pinned before the rebrand still reads as "has
// pinned before", so an erased pin stays distinguishable from a genuinely fresh install.
const PIN_BREADCRUMB_LEGACY = process.platform === "win32" ? null : join(os.homedir(), ".config", "moorai", "pinned");

// Artifacts that exist ONLY on a device that has verified a real console signature. These decide whether
// a missing pin is suspicious — see assessPinAbsence for why "prior operation" artifacts cannot.
const PINNING_ARTIFACTS = [
  ["pin-breadcrumb", () => PIN_BREADCRUMB],
  ["pin-breadcrumb-legacy", () => PIN_BREADCRUMB_LEGACY],
  ["policy-pin-legacy", () => POLICY_PIN_LEGACY],
  ["policy-lkg", () => POLICY_LKG],
  ["policy-lkg-latch", () => POLICY_LKG_LATCH],
  ["policy-lkg-legacy", () => POLICY_LKG_LEGACY]
];
// Artifacts a device only produces by actually RUNNING. Reported as context on a suspicious pin absence
// so a SOC can see how long the device had been operating; never a trigger on their own.
const OPERATION_ARTIFACTS = [
  ["posture-state", () => POSTURE_STATE],
  ["posture-latch", () => POSTURE_LATCH],
  ["posture-legacy", () => POSTURE_LEGACY],
  ["action-audit", () => statePath("action-audit.jsonl")],
  ["exposure-ledger", () => statePath("exposure-ledger.jsonl")],
  ["agent-events", () => statePath("agent-events.jsonl")]
];
// Only the artifact NAMES ever leave the device, never a byte of their contents.
function presentArtifacts(list) {
  const out = [];
  for (const [name, path] of list) {
    try { if (statSync(path()).size > 0) out.push(name); } catch { /* absent */ }
  }
  return out;
}
function writePinBreadcrumb(config) {
  try {
    if (statSync(PIN_BREADCRUMB).size > 0) return; // already recorded; never rewritten
  } catch { /* absent — write it */ }
  try {
    mkdirSync(dirname(PIN_BREADCRUMB), { recursive: true });
    writeFileSync(PIN_BREADCRUMB, JSON.stringify({ v: POLICY_PIN_VERSION, tenant: String(config.tenant), first: new Date().toISOString() }));
  } catch { /* best-effort */ }
}

// Policy-signing trust anchor — the SAME two provisioning routes as break-glass (root-owned machine
// file first, MDM env var second), a DIFFERENT key: break-glass is the operator's incident key, this is
// the console's per-tenant policy-signing key. Both are held outside the agent's write scope; neither
// grants the other's power.
//
// OPERATOR PROCEDURE — deploying the policy public key to a fleet:
//
//   # 1. read the tenant's public key off the console (any enrolled device's install token works)
//   curl -H "X-Install-Token: $TOKEN" https://console.example.com/api/policy/pubkey
//   #    → {"tenant":"acme","alg":"ed25519","publicKey":"<base64 SPKI DER>","pem":"-----BEGIN PUBLIC KEY-----..."}
//
//   # 2. ship it via MDM, root-owned and not group/world-writable (same rule as breakglass.pub):
//   #   macOS/Linux → /etc/moorai/policy.pub   (root:wheel, 0644)
//   sudo install -d -m 0755 -o root /etc/moorai
//   printf '%s\n' "$PEM" | sudo tee /etc/moorai/policy.pub >/dev/null
//   sudo chown root /etc/moorai/policy.pub && sudo chmod 0644 /etc/moorai/policy.pub
//   #   Windows     → %ProgramData%\MoorAI\policy.pub  (ACL: Administrators/SYSTEM write only)
//   #   no root-writable path → MDM-inject MOORAI_POLICY_PUBKEY=<base64 SPKI DER> (weaker: an agent
//   #   that can edit the user's shell profile can influence a FUTURE host launch)
//
// Shipping this file is no longer the only route to the guarantee — a device now ARMS ITSELF the first
// time its console serves a signed policy (POLICY_PIN, above). The anchor is still strictly stronger
// and still worth deploying to fail-closed fleets: it outranks the pin, it removes the first-contact
// window, and being root-owned it survives an attacker who erases both user-scope pin copies. Roll the
// server first, then the anchor: the console must already be signing (v0.50+) before the anchor lands,
// or the device will reject every policy and fall to the offline default.
//
// OPERATOR PROCEDURE — ROTATING THE CONSOLE'S POLICY SIGNING KEY without bricking pinned devices.
// A pinned device refuses a policy signed by a key it has never trusted, so "generate K2 and start
// signing with it" would lock out the whole fleet. Use the overlap window instead:
//
//   1. Generate K2 on the console and PUBLISH it at /api/policy/pubkey, while still SIGNING with K1.
//   2. Wait one policy-refresh cycle (the device fetches at most every 60s, so minutes, not days; give
//      laptops that are offline or asleep however long your fleet actually needs). Each device fetches
//      a policy that verifies under its already-pinned K1, and that signature is what authorizes K2
//      joining its pin — an attacker who does not hold K1 can never reach this branch.
//   3. Cut over: sign with K2. Every device that completed step 2 already trusts it, offline included.
//   4. Devices that missed the window are not bricked, they are FAIL-SAFE: they refuse the K2 policy,
//      raise policy:cache:untrusted / policy:server:untrusted, and fall back to the last-known signed
//      policy or OFFLINE_DEFAULT_POLICY. Recover one by re-running step 1-2 with K1 restored, by
//      shipping the anchor (which outranks the pin), or — last resort, and it re-opens the
//      first-contact window — by deleting ~/.curaiq/policy-pin.json and ~/.moorai/policy-pin.json.
//
// On an ANCHORED device none of this applies: rotation there is "ship the new policy.pub via MDM".
const POLICY_ANCHOR = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "policy.pub")
  : "/etc/moorai/policy.pub";

function policyKeys() {
  try { return parseTrustedKeys(`${readRootOwned(POLICY_ANCHOR)}\n${process.env.MOORAI_POLICY_PUBKEY || ""}`); } catch { return []; }
}

// ---- policy-key pin I/O (the pure logic lives in hook-core.mjs) ----

function readPolicyPin() { return reconcilePolicyPins({ primary: readText(POLICY_PIN), secondary: readText(POLICY_PIN_LATCH), legacy: readText(POLICY_PIN_LEGACY) }); }

// Learn (or roll forward) the pin from a policy that was just delivered FRESH over the network and
// accepted. Three cases, and the difference between them is the whole security argument:
//
//   anchored — record the anchor key that actually verified this policy, so that pulling the MDM env
//              var out of a future shell (the one anchor route an agent can influence) cannot silently
//              return the device to "verifies nothing".
//   pinned   — the policy verified under an ALREADY-PINNED key. That signature is what vouches for the
//              fetch, so any key the server publishes alongside it may join the pin: this is the
//              key-ROTATION path, and an attacker cannot reach it without already holding a pinned key.
//              An unsigned or wrongly-signed fetch never gets here — it is `rejected` above.
//   unpinned — FIRST CONTACT (TOFU). Pin only if the key the server publishes actually verifies the
//              policy it served. A console that does not sign publishes nothing that verifies, so no
//              pin forms and the device keeps behaving exactly as it did before this change.
//
// The first-contact window is real and is not claimed away: an attacker who owns the device BEFORE it
// ever reaches its console can pin their own key. /etc/moorai/policy.pub removes that window; nothing
// this process can do by itself does.
//
// Returns whether a real console signature was established on this fetch (i.e. there was something to
// pin). The caller uses it as the bar for recording a last-known-good policy — see there.
// Revocation (F-201) and the iat high-water mark (F-202) both land here, and for the same reason: this
// is the one place that knows a signature was delivered FRESH over the network and actually verified.
// Neither may be learned from the cache — it is in the agent's own write scope, so a cached body could
// otherwise revoke the fleet's real key or park the mark in the future and refuse every real policy.
function armPolicyPin(config, trust, pin, verdict, policy, publishedRaw, rejected) {
  try {
    const published = parsePublishedKeys(publishedRaw, { tenant: config.tenant });
    let learn = [], verifiedBy = verdict.keyId || "";
    if (trust.mode === "anchored") learn = [verdict.keyId];
    else if (trust.mode === "pinned") learn = [verdict.keyId, ...published];
    else if (trust.mode === "unpinned" && published.length) {
      const t = verifyPolicySignature(policy, { keys: parseTrustedKeys(published.join("\n")), tenant: config.tenant });
      if (t.trusted && t.status === "ok") { learn = [t.keyId]; verifiedBy = t.keyId; }
    }
    learn = learn.filter(Boolean);
    const armed = learn.length > 0;
    const rev = applyKeyRevocation({
      keys: [...new Set([...(pin.keys || []), ...learn])],
      revoked: parseRevokedKeys(policy),
      verifiedBy
    });
    if (rev.refused) rejected.push({ source: "revocation", status: rev.refused });
    // Only a REAL console signature moves the mark. The trivially-trusted "unanchored" case has verified
    // nothing, so letting it set a mark would hand an unpinned device's attacker a permanent refusal.
    const mark = armed || verdict.status === "ok" ? maxIat(pin.iat, policy && policy.policySig && policy.policySig.iat) : pin.iat;
    writePolicyPin(config, pin, rev.keys, mark);
    return armed;
  } catch { return false; /* pinning is durability, never enforcement — a failure here must not change the decision */ }
}

// Write BOTH copies when there is something new to record, or when the copies disagree (which also
// HEALS a single erased copy — the caller has already reported it by then, so the signal is not lost).
// `keys` is the FINAL set, not a list of additions — revocation has to be able to make it smaller, and a
// union here would silently undo every pruning applyKeyRevocation just did. The empty case is still
// refused: an empty pin file reads as "unpinned", which is a downgrade, not a tightening.
function writePolicyPin(config, pin, keys, mark) {
  if (!keys.length) return;
  // Record "this device has pinned" in the third location on every run that HAS a pin, so the breadcrumb
  // self-heals if deleted while the pin still exists. It is never written when there is no pin, which is
  // what keeps it meaningful as evidence.
  writePinBreadcrumb(config);
  const same = (a, b) => [...a].sort().join("\n") === [...b].sort().join("\n");
  const stale = !same(keys, pin.keys || []) || String(mark || "") !== String(pin.iat || "") || pin.evidenceMissing || pin.corrupt || pin.tenant !== config.tenant;
  if (!stale) return;
  const body = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: String(config.tenant), keys, iat: String(mark || ""), updated: new Date().toISOString() });
  for (const p of [POLICY_PIN, POLICY_PIN_LATCH]) {
    try { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); } catch { /* best-effort */ }
  }
}

// Returns { policy, source, rejected } where source is:
//   "fresh"        — freshly fetched from the server (and re-cached)
//   "cache"        — served from the fresh-cache window without a fetch attempt
//   "cache-offline"— fetch FAILED, falling back to the last-known cached policy (offline; #33 point 2)
//   "last-known-good" — live AND cached copies were both refused (or absent); enforcing the last policy
//                       that actually passed signature verification, re-verified on the way in
//   "none"         — no policy at all (offline AND no cache, OR nothing that verified)
//
// Every candidate policy must carry a console signature this device's trust state verifies. One that
// does not is not "a weaker policy" — it is NO policy, and the caller falls through to
// durablePosture()/OFFLINE_DEFAULT_POLICY exactly as if the file were absent. Never fail OPEN on a
// verification error.
//
// The trust state comes from policyTrust(): the explicit anchor if one is deployed, else this device's
// own PIN if it has ever verified a real console signature, else nothing (a never-signed console keeps
// working exactly as before — the no-brick property). That last case is the only remaining opening, and
// it closes by itself the first time the console signs.
//
// The FRESH path is verified too, not just the cache: ~/.curaiq/config.json is in the same write scope
// as the cache, so `serverUrl` can be repointed at an attacker-run localhost that serves `{}` — the
// identical bypass wearing a different hat. `rejected` carries the content-free (source, status) pairs
// for the tamper alert; only those NAMES ever leave the device.
export async function loadVerifiedPolicy(config) {
  const anchorKeys = policyKeys();    // explicit anchor: root-owned /etc/moorai/policy.pub or MDM env
  const pin = readPolicyPin();        // this device's own TOFU record
  const trust = policyTrust({ anchorKeys, pin, tenant: config.tenant });
  // A device that has demonstrably been operating but holds NO pin and NO anchor is not a fresh install
  // — it is a device whose pin was erased. Computed here (not in main) because it also shortens the
  // window: while in that state the cache's 60s short-circuit is skipped so every invocation attempts a
  // fresh network fetch, which is the only thing that can re-pin the device.
  const absence = assessPinAbsence({
    enrolled: Boolean(config.installToken),
    trustMode: trust.mode,
    pinningEvidence: presentArtifacts(PINNING_ARTIFACTS),
    operationEvidence: presentArtifacts(OPERATION_ARTIFACTS)
  });
  // The effective high-water mark: this device's own record, or a root-owned one an MDM shipped,
  // whichever is HIGHER. The root-owned copy is the only one outside the agent's write scope, so it is
  // the only one that makes rollback refusal a guarantee rather than evidence.
  const mark = maxIat(pin.iat, parsePolicyHwm(readRootOwned(POLICY_HWM_SYSTEM), { tenant: config.tenant }));
  const rejected = [];
  const verify = (raw) => {
    let p;
    try { p = JSON.parse(raw); } catch { return { bad: "malformed" }; }
    if (!p || typeof p !== "object" || Array.isArray(p)) return { bad: "malformed" };
    // A pin we know existed but cannot use (mangled file, or config.json now naming another tenant)
    // refuses everything rather than degrading to "verify nothing" — otherwise corrupting the pin would
    // be a downgrade path, which is the very hole this whole mechanism closes.
    if (trust.mode === "rebind") return { bad: "pin-tenant-rebind" };
    if (trust.mode === "corrupt") return { bad: "pin-unusable" };
    const v = verifyPolicySignature(p, { keys: trust.keys, tenant: config.tenant });
    if (!v.trusted) return { bad: v.status };
    // A validly signed but SUPERSEDED body is not a weaker policy, it is no policy — same treatment as a
    // bad signature, so the caller falls through to the fresh fetch, then the last-known-good, and never
    // to "no policy". The LKG copy's own iat IS the mark (both are written from the same accepted fetch),
    // and the comparison is strict, so the fallback still verifies.
    if (isPolicyRollback(p.policySig && p.policySig.iat, mark)) return { bad: "rollback" };
    return { policy: p, status: v.status, keyId: v.keyId };
  };

  // One read + one verify of the cache, whatever path we end up taking — the file is the same file in
  // the "fresh window" and the "offline fallback" cases, so it must not be able to raise two alerts.
  let cacheRaw = null, withinWindow = false;
  try { const st = statSync(POLICY_CACHE); cacheRaw = readFileSync(POLICY_CACHE, "utf8"); withinWindow = Date.now() - st.mtimeMs < 60000; } catch { /* absent */ }
  const cached = cacheRaw == null ? null : verify(cacheRaw);
  if (cached && cached.bad) rejected.push({ source: "cache", status: cached.bad });
  // A CACHED policy never re-pins, however valid it looks: the cache file is in the agent's own write
  // scope, so letting it teach the device a key would hand the attacker the pin. Only a signature
  // delivered fresh over the network from the configured server can arm or roll the pin forward.
  if (withinWindow && !absence.suspicious && cached && cached.policy) return { policy: cached.policy, source: "cache", rejected, pin, trust, absence };

  try {
    const headers = config.installToken ? { "X-Install-Token": config.installToken } : {};
    const q = (p) => fetch(`${config.serverUrl}${p}`, { headers, signal: AbortSignal.timeout(1500) }).then((r) => (r.ok ? r.text() : "")).catch(() => "");
    // The published-key fetch runs in PARALLEL with the policy fetch, so it costs no extra latency, and
    // only on devices with no explicit anchor (an anchored device already has the stronger statement).
    const [raw, published] = await Promise.all([
      q(`/api/policy?tenant=${encodeURIComponent(config.tenant)}`),
      trust.mode === "anchored" || trust.mode === "rebind" || trust.mode === "corrupt" ? Promise.resolve("") : q("/api/policy/pubkey")
    ]);
    if (raw && raw.trim()) {
      const v = verify(raw);
      // Cache the server's ORIGINAL bytes — the signature covers the policy body, and re-serializing
      // gains nothing while risking a mismatch with whatever the console signed.
      if (v.policy) {
        try { mkdirSync(dirname(POLICY_CACHE), { recursive: true }); writeFileSync(POLICY_CACHE, raw); } catch {}
        // Non-empty result ⇒ a REAL console signature verified on this fetch — under the anchor, under
        // an already-pinned key, or (first contact) under the key the server published. That is the same
        // bar last-known-good needs, and it is NOT the same as v.status: on first contact the policy is
        // admitted as "unanchored" (the device holds no key yet) and only the TOFU re-check proves it.
        const armed = armPolicyPin(config, trust, pin, v, JSON.parse(raw), published, rejected);
        // A verified FRESH policy is the only thing allowed to become last-known-good, and it always
        // replaces the previous one. Fresh-only is the point: the cache is attacker-writable, so
        // promoting a merely-cached policy would let a planted (but still validly signed, e.g. rolled
        // back) body outlive the cache it was planted in. Always-replace is what keeps an org that
        // legitimately RELAXES its policy from being dragged back to an older, stricter one.
        //
        // A REAL signature only — never the trivially-trusted "unanchored" case. A last-known-good with
        // no real signature behind it could not survive its own re-verification anyway, and recording
        // one would destroy this file's second job: being proof the device once verified a real
        // signature (see assessPinAbsence).
        if (v.status === "ok" || armed) writePolicyLkg(raw);
        return { policy: v.policy, source: "fresh", rejected, pin, trust, absence };
      }
      // A body that PARSED but did not verify is the repointed-serverUrl variant of the same attack
      // (config.json sits in the same write scope as the cache). A non-JSON body is just a broken or
      // hijacked-into-uselessness server — the existing offline signal already covers that, and calling
      // it tampering would page a SOC every time a proxy returned an error page.
      if (v.bad !== "malformed") rejected.push({ source: "server", status: v.bad });
    }
  } catch { /* offline */ }

  if (cached && cached.policy) return { policy: cached.policy, source: "cache-offline", rejected, pin, trust, absence };
  // Nothing live and nothing cached verified. Before falling through to "no policy" — which for a
  // fail-open org means exit(0), i.e. the attacker's bypass — enforce with the last policy that really
  // did pass verification, re-verified now against the same anchor/pin. Read lazily: three extra file
  // reads must not sit on the happy path.
  const lkg = selectLastKnownGood([
    { source: "system", raw: readRootOwned(POLICY_LKG_SYSTEM) },
    { source: "primary", raw: readText(POLICY_LKG) },
    { source: "latch", raw: readText(POLICY_LKG_LATCH) },
    { source: "legacy", raw: readText(POLICY_LKG_LEGACY) }
  ], verify);
  if (lkg) return { policy: lkg.policy, source: "last-known-good", lkgCopy: lkg.copy, rejected, pin, trust, absence };
  return { policy: null, source: "none", rejected, pin, trust, absence };
}

// Record the last VERIFIED policy, byte-for-byte as the console served it (the signature covers the
// body, so re-serializing gains nothing and risks a digest mismatch). Both user-scope copies, in two
// different directories, for the same reason the pin and the posture latch have two: `rm -rf ~/.curaiq`
// must not take the device's memory with it. There is deliberately no write to POLICY_LKG_SYSTEM — the
// hook runs as the user and cannot write /etc, so a "system copy" it wrote would be a fiction.
function writePolicyLkg(raw) {
  for (const p of [POLICY_LKG, POLICY_LKG_LATCH]) {
    try { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, raw); } catch { /* best-effort */ }
  }
}
