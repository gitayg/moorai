#!/usr/bin/env node
// MoorAI PreToolUse hook (#1/#2/#3). Registered in the agent's settings.json for the Read, Bash, and
// mcp__* tools; runs BEFORE each matched tool call. Reads the tool input on stdin and, per policy,
// blocks (Claude Code deny) a secret/PII being read into context (#1), a secret shipped as an MCP
// tool-call argument (#2), or a call to an MCP server that isn't on the org allow-list (#3).
//
// Governance, not a sandbox: any error, missing policy, or unsupported tool → EXIT 0 (allow). Reports
// are content-free (category + risk + one-way hash), never the file/arg content or the matched span.
//
//   node moorai-hook.mjs            # hook mode (reads stdin)
//   node moorai-hook.mjs install    # register in ~/.claude/settings.json (idempotent)
//   node moorai-hook.mjs uninstall  # remove only MoorAI's entries

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname, basename } from "node:path";
import os from "node:os";
import { loadConfig } from "./config.mjs";
import { buildEngine, decideText, decideEndpoints, decideEnvelope, threatActionFor, extractReadPaths, mcpGateway, offlineMode, verifyBreakGlass, parseTrustedKeys, ratchetPosture, mcpFloor, literacyTouchpoint, loadVerifiedPolicy, readRootOwned, readText, POSTURE_STATE, POSTURE_LATCH, POSTURE_LEGACY, SYSTEM_POSTURE } from "./hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { egressHits } from "./secret-egress.mjs";
import { recordExposure, recordAgentEvent, readAgentEvents, recordAction, rulesBaseline, setRulesBaseline, recordDestination, readDestinations, requestKill } from "./signals.mjs";
import { readState } from "./state-dirs.mjs";
import { applyCaptureTier, commandShape } from "../data/capture-tiers.js";
import { isSkillSurface, skillSurfaceKind } from "../data/skill-surface.js";
import { skillIntents } from "./skill-analysis.mjs";
import { extractHosts } from "../data/model-endpoints.js";
import { isNewDestination } from "../data/destination-map.js";
import { signApproval, argsHash } from "../data/agency-sign.mjs";
import { contentTells, assessSession, assessTrifecta, assessCrossServerTrifecta, trifectaLegs, serverOf } from "../data/agent-behavior.js";
import { classifyOpportunistic } from "../data/model-escalation.mjs";
import { contentHash, fileFingerprint, NO_KEY } from "./content-hash.mjs";
import { emitOtel } from "./otel.mjs";
import { loadHoneytokens, checkHoneytokens } from "./moorai-honeytokens.mjs";

const SELF = fileURLToPath(import.meta.url);
const RANK = { allow: 1, ask: 2, deny: 3 };

// ---- install / uninstall (settings.json merge) ----
function settingsPath() { return join(os.homedir(), ".claude", "settings.json"); }
function isCuraiq(entry) { return JSON.stringify(entry).includes("moorai-hook"); }
function readSettings() { try { return JSON.parse(readFileSync(settingsPath(), "utf8")); } catch { return {}; } }
function writeSettings(s) { mkdirSync(dirname(settingsPath()), { recursive: true }); writeFileSync(settingsPath(), JSON.stringify(s, null, 2)); }

function installHooks() {
  const s = readSettings();
  s.hooks = s.hooks || {};
  const cmd = `node ${JSON.stringify(SELF)}`;
  const entry = (matcher) => ({ matcher, hooks: [{ type: "command", command: cmd }] });
  const cur = Array.isArray(s.hooks.PreToolUse) ? s.hooks.PreToolUse : [];
  s.hooks.PreToolUse = [...cur.filter((e) => !isCuraiq(e)), entry("Read"), entry("Bash"), entry("mcp__.*"), entry("Task")];
  writeSettings(s);
  console.error(`MoorAI hooks installed in ${settingsPath()}`);
}
function uninstallHooks() {
  const s = readSettings();
  if (Array.isArray(s.hooks?.PreToolUse)) { s.hooks.PreToolUse = s.hooks.PreToolUse.filter((e) => !isCuraiq(e)); writeSettings(s); }
  console.error("MoorAI hooks removed");
}

// ---- policy load ----
//
// The loader itself now lives in cli/hook-core.mjs (loadVerifiedPolicy), together with the trust
// anchors, the TOFU pin I/O, the last-known-good store and the root-owned-file reads it composes.
// It moved because mcp-proxy/moorai-mcp-guard.mjs carried a COPY of the pre-signing version of it and
// was therefore still fully bypassable via `echo '{}' > ~/.curaiq/hook-policy.json` — one
// implementation, two entrypoints, no second door. Everything below is the part that is genuinely
// hook-only: break-glass, the posture ratchet, and the content-free reports for both.
const CONFIG = loadConfig();
// #33 — break-glass marker (operator-created, holds an expiry) and the durable last-known posture the
// hook remembers so a fail-closed org stays fail-closed even if the policy cache is later deleted.

// #33 — remember the org's chosen posture durably, so it survives a later cache deletion. Written every
// time a real policy loads, to BOTH user-scope copies. For an org that never set offlineMode this is
// "fail-open" → no-cache stays exit(0)/allow (unchanged default). What is recorded is the RATCHETED
// posture, not the policy's alone: on an MDM-latched device the copies record fail-closed even while a
// fail-open policy is in force, so the next offline run sees no contradiction (and raises no false
// downgrade alert). Best-effort; a write error never affects enforcement.
function rememberPosture(policy) {
  const mode = readRootOwned(SYSTEM_POSTURE).trim() === "fail-closed" ? "fail-closed" : offlineMode(policy);
  for (const p of [POSTURE_STATE, POSTURE_LATCH]) {
    try { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, mode); } catch { /* best-effort */ }
  }
}
// Durable last-known posture for the NO-policy/no-cache case — a ONE-WAY RATCHET, not a lookup.
// Hardening is unauthenticated (any source may say fail-closed); weakening never comes from here at
// all. The only routes back to fail-open are the two authenticated ones, both handled by the caller:
// a real (fresh or cached) policy whose offlineMode is not fail-closed, and an operator-signed
// break-glass marker.
//
// WHAT A SAME-USER ATTACKER CAN STILL DO — stated plainly, because the hook runs as the user:
//   * On a device with the root-owned SYSTEM_POSTURE latch: nothing. The latch cannot be written or
//     deleted without root, so fail-closed survives any erasure of ~/.curaiq and ~/.moorai. This is
//     the configuration to ship in production, and it is why the fallback below is a fallback.
//   * WITHOUT that latch, an attacker who knows this code can still erase BOTH user-scope copies
//     (`rm ~/.curaiq/offline-posture ~/.moorai/posture`) and land back at the never-configured
//     default, fail-open. Two copies in two directories defeat the one-liner and the ~/.curaiq wipe,
//     and any partial erasure is reported (evidenceMissing) — but this is tamper-EVIDENCE, not
//     tamper-proofing, and no key or HMAC can change that: any secret this process can read to
//     authenticate the file, the attacker can read too.
//   * The policy cache (CACHE, above) is also user-writable, and a planted permissive
//     ~/.curaiq/hook-policy.json used to be an independent — and strictly wider — route to the same
//     outcome: a policy is an AUTHORIZED relaxation, so it outranks this ratchet by design, and `{}`
//     disabled the detectors too, not just the posture. CLOSED: the console now signs each tenant's
//     policy and loadPolicy verifies it against POLICY_ANCHOR before the policy is trusted at all, so
//     on an anchored device a planted cache is treated as NO cache and lands here, on this ratchet.
//     An UNANCHORED device closes the same door by itself the first time its console serves a signed
//     policy: the signing key is PINNED (POLICY_PIN, TOFU) and a planted cache stops verifying from
//     then on. Two windows remain, both stated rather than papered over — a device that never reaches
//     a signing console (no pin ever forms; unchanged legacy behavior), and an attacker who erases
//     BOTH pin copies to return the device to first contact. /etc/moorai/policy.pub closes both.
function durablePosture() {
  return ratchetPosture({
    system: readRootOwned(SYSTEM_POSTURE),
    state: readText(POSTURE_STATE),
    latch: readText(POSTURE_LATCH),
    legacy: readText(POSTURE_LEGACY),
    env: process.env.MOORAI_OFFLINE_MODE
  });
}
// A refused downgrade is one of the strongest tamper signals this hook can produce: something in the
// user's write scope actively asserted "fail-open" at a device that knows it is fail-closed. Content-
// free — only the NAMES of the disagreeing sources leave, never any file content.
function reportPostureTamper(pv) {
  if (pv.downgradeAttempt.length) return postPosture("Offline posture downgrade refused", `posture:downgrade-refused:${pv.downgradeAttempt.join(".")}`, "Critical");
  if (pv.evidenceMissing) return postPosture("Offline posture evidence missing", "posture:evidence-missing", "High");
  return Promise.resolve();
}
// #33 — the operator trust anchor for break-glass. ~/.curaiq/ is deliberately NOT a key source: the
// hook runs as the user, so anything the agent can write there it can also forge. Only two sources are
// accepted, both provisioned by the installer/MDM rather than by the agent:
//   1. BG_ANCHOR — a machine-wide file that must be root-owned and not group/world-writable on POSIX.
//      This is the only source a same-user process genuinely cannot rewrite; prefer it in production.
//   2. MOORAI_BREAKGLASS_PUBKEY — an MDM-injected env var, for hosts with no root-writable path.
//      Weaker: an agent that can edit the user's shell profile can influence a FUTURE host launch.
//
// OPERATOR PROCEDURE (the pre-v2 "write a future date into the file" flow is gone — it was forgeable
// by the very agent this product governs, so it is not accepted and there is no compatibility path):
//
//   # once per tenant, on the operator's machine — the private key NEVER goes on an endpoint
//   openssl genpkey -algorithm ed25519 -out moorai-operator.key
//   openssl pkey -in moorai-operator.key -pubout -out breakglass.pub
//   # ship breakglass.pub to the fleet via MDM:
//   #   macOS/Linux → /etc/moorai/breakglass.pub  (root:wheel, mode 0644)
//   #   Windows     → %ProgramData%\MoorAI\breakglass.pub
//
//   # per incident, mint a marker scoped to ONE device and a short expiry, then hand it to the user:
//   node -e 'const c=require("crypto"),f=require("fs");
//     const b={v:2,tenant:"acme",device:"laptop-17",expires:new Date(Date.now()+4*3600e3).toISOString(),nonce:c.randomBytes(8).toString("hex")};
//     const m=`moorai-break-glass|v${b.v}|${b.tenant}|${b.device}|${b.expires}|${b.nonce}`;
//     b.sig=c.sign(null,Buffer.from(m),c.createPrivateKey(f.readFileSync("moorai-operator.key"))).toString("base64");
//     process.stdout.write(JSON.stringify(b));' > break-glass
//   # the user drops that file at ~/.curaiq/break-glass — it is useless on any other device.
//
// `device` is os.hostname() and `tenant` is the enrolled tenant; "*" in either field is a signed
// fleet-wide grant. An unsigned, unverifiable, or out-of-scope marker never grants fail-open — and is
// itself reported as tampering (reportBreakGlassTamper below).
const BG_ANCHOR = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "breakglass.pub")
  : "/etc/moorai/breakglass.pub";

// A user-writable "system" anchor is no better than ~/.curaiq — readRootOwned rejects it rather than pretend.
function anchorText() { return readRootOwned(BG_ANCHOR); }
function trustedKeys() {
  try { return parseTrustedKeys(`${anchorText()}\n${process.env.MOORAI_BREAKGLASS_PUBKEY || ""}`); } catch { return []; }
}
// A cached/served policy that failed verification on an anchored device is one of the strongest signals
// this hook produces: something put material in MoorAI's own policy file that no console signed, and
// enforcement would have collapsed to whatever it said. Reported per rejected SOURCE, content-free —
// only the source name and the failure status leave, never one byte of the policy itself.
function reportPolicyTamper(rejected) {
  return Promise.all((rejected || []).map((r) => postPosture(`Policy signature rejected (${r.status})`, `policy:${r.source}:${r.status}`, "Critical")));
}
// The pin's own tamper signals — the exact analogue of posture:evidence-missing, and for the same
// reason: an ERASED pin is itself the attack, not the absence of one. A device that has verified a real
// console signature does not spontaneously forget it, so a missing, mangled, or re-tenanted pin is
// reported rather than quietly treated as a fresh install. Content-free: a fixed token, nothing else.
function reportPinTamper(pin, trust) {
  const out = [];
  if (trust.mode === "rebind") out.push(postPosture("Policy key pin tenant rebind refused", "policy:pin:tenant-rebind", "Critical"));
  if (pin.corrupt) out.push(postPosture("Policy key pin unreadable", "policy:pin:corrupt", "Critical"));
  else if (pin.evidenceMissing) out.push(postPosture("Policy key pin evidence missing", "policy:pin:evidence-missing", "High"));
  return Promise.all(out);
}
// The pin is GONE on a device that has demonstrably been operating. Distinct from pin:evidence-missing
// (one copy survived) and pin:corrupt (a copy exists but is unreadable): here BOTH copies are absent,
// which is the one pin state that is indistinguishable from a new device by the pin files alone — so it
// is named from the OTHER evidence instead. Content-free: artifact NAMES only, never their contents.
//
// WHY THIS DOES NOT ALSO FORCE FAIL-CLOSED, stated rather than assumed:
//   * The same state is reached legitimately. A fleet whose console never signed (the documented
//     no-brick property) operates for months and never forms a pin; the day the console starts signing,
//     every one of those devices looks exactly like this. So does a restored/migrated home directory.
//     Forcing fail-closed here would brick a healthy fleet at precisely the moment the org upgraded.
//   * A fail-CLOSED org is already protected in this state by the posture ratchet, which is independent
//     of the pin: durablePosture() keeps returning fail-closed and OFFLINE_DEFAULT_POLICY applies.
//   * For a fail-OPEN org, refusing the cache here would REDUCE enforcement, not raise it: the cached
//     policy (poisoned or not) is the only policy such a device has, and "no policy" for them is
//     exit(0). Fail-closed-by-heuristic would be strictly worse than the alert.
// What IS done instead is bounded and cannot brick anything: the 60s cache short-circuit is skipped
// while in this state, so every invocation attempts the fresh network fetch that is the only path back
// to a pin. Re-pinning already requires that network fetch — a cached policy never arms the pin.
function reportPinAbsence(absence) {
  if (!absence || !absence.suspicious) return Promise.resolve();
  return postPosture("Policy key pin absent on a device with prior operation", "policy:pin:absent-operational", "Critical", { pinEvidence: absence.evidence, pinEvidenceContext: absence.context });
}
// Read + verify the marker. `raw` is kept only to derive a one-way hash for the tamper alert.
function breakGlassVerdict() {
  const raw = readState("break-glass"); // ~/.moorai, falling back to the pre-rebrand ~/.curaiq
  if (!raw) return { active: false, status: "absent", raw: "" };
  return { ...verifyBreakGlass(raw, { keys: trustedKeys(), tenant: CONFIG.tenant, device: os.hostname() }), raw };
}
// #33 defense-in-depth — a break-glass marker that does not verify is itself a strong tamper signal:
// something wrote MoorAI's own operator-override file with material no operator signed. Reported in
// EVERY posture (including fail-open, where the marker grants nothing) so a SOC sees a planted marker
// before the outage it was planted for. Content-free: status + a one-way hash of the marker only.
function reportBreakGlassTamper(bg) {
  if (bg.active || bg.status === "absent") return Promise.resolve();
  const level = bg.status === "expired" ? "High" : "Critical"; // expired can be innocent; the rest cannot
  return postPosture(`Break-glass marker rejected (${bg.status})`, `breakglass:${bg.status}:${djb2(bg.raw)}`, level);
}
// #33 — content-free policy-posture signals (category/hash only; no file, arg, or content ever).
function postPosture(category, hash, riskLevel, extra) { return post({ threatId: 0, category, riskLevel, stage: "policy", tool: "hook:policy", ts: new Date().toISOString(), contentHash: hash, ...(extra || {}), ...IDENTITY }); }

// ---- content-free reporting ----
function djb2(s) { let h = 5381; for (let i = 0; i < String(s).length; i++) h = ((h << 5) + h + String(s).charCodeAt(i)) >>> 0; return "h" + h.toString(16); }
// #10 — every emitted action carries a stable, content-free actor fingerprint (one-way hash of
// user@device) so the console can tie actions to an operator without storing raw identity as the key.
const IDENTITY = { user: os.userInfo().username, device: os.hostname(), platform: os.platform(), tenant: CONFIG.tenant, actor: djb2(`${os.userInfo().username}@${os.hostname()}`) };
// Content-free lineage for the per-agent baseline / forensic detections (data/agent-detections.js).
// SESSION is the current agent/session id (Claude Code's session_id, one-way hashed), set in main().
// It groups an actor's events for trace-gap detection and is the source id for cross-agent handoffs.
let SESSION = "";
// #canary — registered honeytokens (hash-only; see cli/moorai-honeytokens.mjs). Loaded once. A hit is
// exact equality against a content hash the hook already computes, so no plaintext is involved.
const HONEYTOKENS = loadHoneytokens();
// A decoy value that exists only to be a trap showed up in a matched span — the strongest single
// signal the hook can raise. Content-free: only the token's own hash (and optional operator label)
// leave. Best-effort and advisory: the finding that produced this hash already carries the allow/deny;
// a canary is a signal, never the enforcement decision.
function checkHoneytoken(hash, stage, tool) {
  try {
    // NO_KEY guard: an unenrolled device hashes EVERY value to the same sentinel, so without it a
    // honeytoken (also nokey) would match every finding — a false canary on each event. A honeytoken
    // is only meaningful on an enrolled (keyed) device.
    if (!HONEYTOKENS.length || !hash || hash === NO_KEY) return;
    for (const h of checkHoneytokens([hash], HONEYTOKENS)) {
      post({ threatId: 0, category: "Honeytoken canary triggered", riskLevel: "Critical", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: h.hash, honeytoken: h.label ? { label: h.label } : {}, ...IDENTITY });
    }
  } catch { /* canary is a signal; never affects enforcement */ }
}
// ---- alert delivery + the exit gate ----
//
// MEASURED BUG (this is why the gate below exists). Every alert on the main enforcement path was
// fire-and-forget: report() called post() without awaiting, and emit() then called process.exit(0),
// which tears the process down before the HTTP request is written. A local listener on
// http://localhost:8788 driven with ONE Bash tool call containing an AWS key recorded:
//
//     local action-audit.jsonl : 1 line — "Information & Privacy"   (the finding DID fire)
//     ALERTS RECEIVED: 0       | policy fetches: 2
//
// Only the handful of AWAITED postPosture() calls survived, so the SOC saw policy/posture signals and
// nothing at all from Read / Bash / MCP / Task findings — the product's core telemetry.
//
// FIX: every post() registers its promise here, and every exit path drains PENDING first. Registering
// inside post() rather than threading return values through report()/logBehavior()/reportSkillFile()/
// reportEnvelope()/checkSecretEgress()/killSession()/maybeEscalate() is deliberate: those are eleven
// separate call sites, several inside best-effort try/catch blocks, and the next one added would have
// silently gone back to being lost. One chokepoint cannot be forgotten.
//
// BOUNDED, AND IT CANNOT CHANGE THE DECISION: post() carries AbortSignal.timeout(1500) and ends in
// .catch(() => {}), so each promise settles within ~1.5s and NEVER rejects; the drain additionally
// uses Promise.allSettled, so awaiting it cannot throw and cannot reject the decision path. The
// requests also run concurrently, so the worst case for a whole invocation is ~1.5s, not 1.5s each.
const PENDING = [];
function post(alert) {
  const p = fetch(`${CONFIG.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) }, body: JSON.stringify(alert), signal: AbortSignal.timeout(1500) }).catch(() => {});
  PENDING.push(p);
  // Content-free OTLP mirror of the same governance event — no-op unless an OTLP endpoint is
  // configured. Same chokepoint as the alert so it can't be forgotten; same bounded, drained,
  // never-rejects contract, so telemetry can't gate or delay the decision.
  const o = emitOtel(alert, { config: CONFIG, identity: IDENTITY });
  if (o) PENDING.push(o);
  return p;
}
// Drain in a loop: an awaited post() (the posture/tamper reports) is already settled by the time we
// get here, and nothing enqueues during the drain — the loop is cheap insurance, not a workaround.
async function flushAlerts() {
  while (PENDING.length) await Promise.allSettled(PENDING.splice(0));
}
// Every exit from the hook goes through here. The decision has already been written to stdout by the
// time this runs (see emit) — telemetry never gates the enforcement output.
async function exitHook() {
  await flushAlerts();
  process.exit(0);
}
function report(findings, stage, tool, blocked, tier, extras, agency) {
  for (const f of findings) {
    const base = { threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage, tool, ts: new Date().toISOString(), contentHash: contentHash(f.match || ""), ...IDENTITY };
    checkHoneytoken(base.contentHash, stage, tool); // #canary — a matched span equal to a registered honeytoken
    // #5 — attach only the fields the policy's capture tier permits (content-free by default). The
    // server independently re-strips above the device's stored tier, so this is one of two backstops.
    const alert = applyCaptureTier(base, { ...extras, matchText: f.match }, tier || "content-free");
    if (agency) Object.assign(alert, agency); // #20 — content-free signed approval token (metadata)
    post(alert);            // → server → SIEM (address configured server-side, #1)
    recordExposure(alert);  // → local content-free exposure ledger; ignores non-secret categories
    recordAction(alert);    // → local searchable action-audit log (#5), already tier-gated
    // Coach-as-literacy: a finding that reaches the developer (blocked, or surfaced as "ask" with the
    // why + what-to-do) is an AI-literacy touchpoint. Emit the content-free record so the console's
    // Art. 4 literacy coverage counts this surface too. Best-effort: never affects the decision.
    if (blocked || f.riskLevel === "High" || f.riskLevel === "Critical") {
      try { post({ ...literacyTouchpoint({ threatId: f.threatId, category: f.category, tool }), ...IDENTITY }); } catch { /* literacy is evidence, not enforcement */ }
    }
  }
}

// Autonomous-agent-behavior signature (CSA HF post-mortem §IV). Records one content-free event per
// tool call and, on a transition into the signature, emits a content-free alert (→ server → SIEM/SOC
// + timeline). Entirely side-effectful and wrapped: a failure here must never change the hook's
// allow/deny decision (governance, fail-open).
const RISK_RANK = { Low: 1, Medium: 2, High: 3, Critical: 4, Blocked: 5 };
function logBehavior(tool, identity, scannedText, d, stage, lineage = {}) {
  try {
    const risk = (d.findings || []).reduce((m, f) => (RISK_RANK[f.riskLevel] > RISK_RANK[m] ? f.riskLevel : m), "Low");
    const flags = contentTells(scannedText || "");
    const legs = trifectaLegs(tool, stage, d.findings || [], flags); // #1 — content-free trifecta legs
    const server = serverOf(tool); // which MCP server (or "local") contributed this event's legs
    const priorEvents = readAgentEvents();
    const beforeS = assessSession(priorEvents), beforeT = assessTrifecta(priorEvents), beforeX = assessCrossServerTrifecta(priorEvents);
    // `agent`/`session` (this actor, one-way hashed) group events for the per-agent baseline + trace-gap
    // detection; `lineage` carries a content-free handoff edge (role/to/parent) on a Task delegation for
    // cross-agent-messaging detection. All additive metadata — the signature assessors ignore them.
    recordAgentEvent({ ts: Date.now(), sig: `${tool}|${contentHash(identity || tool)}`, ok: d.decision !== "deny", risk, flags, legs, server, agent: SESSION, session: SESSION, ...lineage });
    const events = readAgentEvents(), afterS = assessSession(events), afterT = assessTrifecta(events), afterX = assessCrossServerTrifecta(events);
    if (afterS.level === "autonomous-signature" && beforeS.level !== "autonomous-signature") {
      post({ threatId: 0, category: "Autonomous-agent behavior", riskLevel: "Critical", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "sig:" + afterS.tells.map((t) => t.id).join("."), signature: { level: afterS.level, score: afterS.score, tells: afterS.tells.map((t) => t.id), events: afterS.events }, ...IDENTITY });
    }
    // #1 — the lethal trifecta just closed in this session (all three legs now present).
    if (afterT.present && !beforeT.present) {
      post({ threatId: 59, category: "Lethal trifecta exposure", riskLevel: "High", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "trifecta:read.ingest.callout", signature: { legs: afterT.legs }, ...IDENTITY });
    }
    // Cross-server confused-deputy — the trifecta just closed across ≥2 DISTINCT servers, so no single
    // server's tool profile looks lethal. Distinct content-free alert (reuses threat 59 with its own
    // category + a signature listing the contributing servers per leg). Server identifiers may leave the
    // device; content never does. Best-effort: still inside the enforcement-neutral try/catch.
    if (afterX.crossServer && !beforeX.crossServer) {
      post({ threatId: 59, category: "Cross-server toxic flow", riskLevel: "High", stage: "behavior", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "xserver:" + afterX.servers.join("+"), signature: { crossServer: true, servers: afterX.servers, legs: afterX.legs, serversByLeg: afterX.serversByLeg }, ...IDENTITY });
    }
  } catch { /* behavior signal is best-effort; never affects enforcement */ }
}

// Bold B1 / #21 — opportunistic model escalation. Only when the org enables it AND the regex pass was
// ambiguous (nothing already High+); consults the unified opportunistic classifier (local loopback
// model first, else the agent's OWN provider when the org opted in and a device key exists) and emits
// a content-free second-opinion alert (#58). No NEW egress/third party; a failure never changes
// enforcement (fail-open).
async function maybeEscalate(policy, text, stage, tool, d) {
  try {
    if (!policy || !policy.modelEscalation || !text || !text.trim()) return;
    const strong = (d.findings || []).some((f) => f.riskLevel === "High" || f.riskLevel === "Critical" || f.riskLevel === "Blocked");
    if (strong) return; // regex is already confident — skip the second opinion
    const v = await classifyOpportunistic(text, policy);
    if (v && v.flagged && v.confidence >= 0.6) {
      post({ threatId: 58, category: `Model-flagged: ${v.category}`, riskLevel: v.confidence >= 0.85 ? "High" : "Medium", stage, tool: `escalate:${tool}`, ts: new Date().toISOString(), contentHash: contentHash(text), ...IDENTITY });
    }
  } catch { /* escalation is advisory; fail-open */ }
}

// Skill Analysis (Backslash-inspired, content-free). Every file on the agent's auto-loaded SKILL
// SURFACE — skills, subagent definitions, slash commands, MCP server configs, hook-bearing settings
// files, instruction/memory files (data/skill-surface.js) — is high-value to poison: one injected
// directive steers every future prompt, and a hook entry in a settings file is straight code execution.
//
// Reports three things about each one, all content-free:
//   (a) INVENTORY — the file's kind, seen at the moment the agent actually loaded it.
//   (b) INTENT    — what the file instructs, as CATEGORY LABELS from the fixed vocabulary in
//                   cli/skill-analysis.mjs. Every label is a rename of a finding the detection engine
//                   already produced; no text, no matched span, no excerpt is ever attached.
//   (c) DRIFT     — divergence from the last-seen fingerprint of THAT file.
//
// The fingerprint stays the unkeyed djb2 of the whole file, deliberately. The keyed HMAC exists because
// a matched span (an SSN, a card) has a small enough candidate space to enumerate; a whole agent config
// file does not, so keying it would buy no confidentiality and would break the cross-device dedup the
// console gets from identical files fingerprinting identically. test/content-hash.test.mjs pins this.
//
// The BASELINE KEY is per-FILE (kind + path), not per-kind. It had to change with the widened surface:
// a device has one CLAUDE.md but a dozen .claude/agents/*.md, and a single "claude-agent" slot would
// have made every agent definition look like drift from the previous one on every read. The path stays
// on the device — the baseline file is local and only `kind` + the fingerprint are ever emitted.
function reportSkillFile(path, text, d) {
  try {
    const kind = skillSurfaceKind(path);
    if (!kind || !text) return;
    // KEYED, not djb2: this fingerprints the whole agent config file, which is content. Every other
    // surviving djb2 site hashes policy vocabulary (host names, server names, grant names) where
    // keying would break dedup for no confidentiality gain — this one was the exception that made
    // the classification guard's own "all remaining sites are non-content" claim untrue.
    const fp = fileFingerprint(text);
    const intents = skillIntents(text, d.findings);
    const injected = (d.findings || []).some((f) => [3, 40, 50, 51].includes(f.threatId));
    const key = `${kind}|${path}`;
    const base = rulesBaseline();
    const drift = base[key] != null && base[key] !== fp;
    setRulesBaseline(key, fp);
    if (injected || drift || intents.length) {
      post({
        threatId: 60,
        category: injected ? "Skill-file poisoning" : drift ? "Skill-file drift" : "Skill-file intent",
        riskLevel: injected ? "High" : drift ? "Medium" : "Info",
        stage: "file", tool: `skill:${kind}`, ts: new Date().toISOString(), contentHash: fp,
        skillKind: kind, skillIntents: intents, ...IDENTITY
      });
    }
  } catch { /* best-effort; never affects enforcement */ }
}

// Per-agent destination map — record, content-free, that this agent/tool reached these destinations and
// what the hook decided. `names` are hosts (data/model-endpoints.js never captures a URL path or query
// string) or MCP server names. An alert fires only the FIRST time an agent reaches a given destination,
// so a busy agent produces one signal per new destination rather than one per call; the running counts
// and first/last-seen live in the on-device ledger, read with `moorai-destinations`.
function recordDestinations(tool, kind, names, decision) {
  try {
    if (!names || !names.length) return;
    const prior = readDestinations();
    for (const name of [...new Set(names)]) {
      const row = { ts: new Date().toISOString(), tool, kind, name, decision, ...IDENTITY };
      const fresh = isNewDestination(prior, row);
      recordDestination(row);
      prior.push(row);
      if (fresh) post({ threatId: 0, category: "Agent destination: first seen", riskLevel: decision === "deny" ? "High" : "Info", stage: "egress", tool: `hook:${tool}`, ts: row.ts, contentHash: `dest:${kind}:${name}`, destination: { kind, name, decision }, ...IDENTITY });
    }
  } catch { /* the map is evidence, not enforcement */ }
}

function readFileCapped(fp) {
  try {
    if (!fp) return "";
    const slice = readFileSync(fp).subarray(0, 262144);
    if (slice.includes(0)) return ""; // skip binary
    return slice.toString("utf8");
  } catch { return ""; }
}

// #3 — kill enforcement for the interactive session. A "kill" verdict still denies THIS call (below),
// but also drops a content-free sentinel the Tauri host watches for to terminate the whole agent PTY —
// detect-and-prevent, not just deny-one-call. Emits a session-kill alert (→ server/SIEM). Only the
// terminating rule ids leave the device, never the tool input.
function killSession(tool, ids, stage) {
  if (!ids || !ids.length) return;
  requestKill({ tool, ids, stage });
  post({ threatId: 0, category: "Session terminated (kill)", riskLevel: "Blocked", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "kill:" + ids.join("."), ...IDENTITY });
}

// T1-5 / #64 — report agent entitlement drift content-free (only the out-of-scope reason tokens leave)
// and return whether policy says to block it. entitlementMode: "off" (default) | "alert" | "block".
function reportEnvelope(policy, tool, ctx, stage) {
  const mode = policy?.entitlementMode || "off";
  if (mode === "off") return false;
  const d = decideEnvelope(policy, { ...ctx, actor: IDENTITY.actor }); // JIT: honor this actor's live grants
  // A live grant covered an otherwise-out-of-envelope action — log the time-boxed elevation, content-free.
  if (d.elevated) post({ threatId: 0, category: "JIT elevation used", riskLevel: "Info", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "elev:" + djb2(String(d.usedGrants)), ...IDENTITY });
  if (d.inScope) return false;
  post({ threatId: 64, category: "Agent entitlement drift", riskLevel: mode === "block" ? "Blocked" : "High", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "drift:" + djb2(d.reasons.join("|")), driftReasons: d.reasons, ...IDENTITY });
  return mode === "block";
}

// Tier-2 / #65 — local secret-value egress. Fingerprints local secrets on-device and checks the
// outbound text for a verbatim match; only the matched hashes leave. Blocks when policy #65 is block/kill.
function checkSecretEgress(policy, text, tool, stage) {
  try {
    const hits = egressHits(text);
    if (!hits.length) return false;
    const act = threatActionFor(policy, 65);
    const block = act === "block" || act === "kill";
    post({ threatId: 65, category: "Local secret value egress", riskLevel: block ? "Blocked" : "Critical", stage, tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: "egress:" + hits.join("."), ...IDENTITY });
    return block;
  } catch { return false; }
}

// The decision is written to stdout BEFORE the telemetry drain, deliberately. Claude Code reads this
// process's stdout to completion, so writing early does not release the agent any sooner — what it
// does buy is that the enforcement verdict is already in the pipe if anything about the drain goes
// wrong, and that the async pipe write gets an await to complete in instead of racing process.exit
// (which is documented to truncate pending stdout writes). Telemetry must never be able to swallow a
// deny; a deny that is never reported is far better than a deny that is never delivered.
async function emit(decision, reason) {
  if (decision !== "allow") {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision === "deny" ? "deny" : "ask", permissionDecisionReason: `MoorAI: ${reason}` } }));
  }
  return exitHook();
}

async function readStdin() { const chunks = []; for await (const c of process.stdin) chunks.push(c); return Buffer.concat(chunks).toString("utf8"); }

async function main() {
  const cmd = process.argv[2];
  if (cmd === "install") return installHooks();
  if (cmd === "uninstall") return uninstallHooks();

  let input;
  try { input = JSON.parse((await readStdin()) || "{}"); } catch { process.exit(0); }
  const tool = input.tool_name || "";
  const ti = input.tool_input || {};
  SESSION = contentHash(input.session_id || ""); // content-free actor/session id for baseline + lineage
  let { policy, source, rejected, pin, trust, absence, lkgCopy } = await loadVerifiedPolicy(CONFIG);
  // Ratcheted posture read BEFORE rememberPosture rewrites the copies, so this run still sees what the
  // device knew on the way in (and any tampering with it) rather than what we are about to record.
  const posture = durablePosture();
  if (policy) rememberPosture(policy); // durable last-known posture survives a later cache deletion (#33)
  // #33 — break-glass / offline fail-closed. Wrapped so a bug here can never harden-then-crash: on ANY
  // error with no policy we fall through to the legacy exit(0) (fail-open), exactly as before.
  try {
    // Verified ONCE, in every posture: an unverifiable marker must be reported even where it grants
    // nothing, and a verified one must be operator-signed before it can disable enforcement.
    const bg = breakGlassVerdict();
    await reportBreakGlassTamper(bg);
    // Awaited for the same reason as the break-glass report: the fail-open exit below would otherwise
    // race the POST and lose the strongest signal of the run.
    if (rejected && rejected.length) await reportPolicyTamper(rejected);
    // Awaited for the same reason: an erased or mangled pin is a tamper signal in its own right, and the
    // fail-open exit below would otherwise race the POST.
    if (pin && (pin.corrupt || pin.evidenceMissing || trust.mode === "rebind")) await reportPinTamper(pin, trust);
    // Awaited for the same reason as the reports above: this is a Critical signal and the fail-open
    // exit below would otherwise race the POST and lose it.
    await reportPinAbsence(absence);
    if (!policy) {
      if (posture.posture !== "fail-closed") return exitHook(); // fail-open (default) — UNCHANGED behavior
      // The ratchet just refused a downgrade (or found a copy erased) — awaited so the signal cannot be
      // lost to the process.exit that follows, exactly like the break-glass tamper report above.
      await reportPostureTamper(posture);
      // Fail-closed posture with no policy: break-glass (if operator-signed and live) forces fail-open so
      // an operator can recover a locked-out machine; otherwise apply the reviewable built-in default.
      if (bg.active) { await postPosture("Break-glass active (fail-open override)", "breakglass:active", "High"); return exitHook(); }
      // Awaited: the SOC's ONLY signal that a device fell back to the built-in fail-closed default.
      // exitHook() now drains every post() before exiting, so this await is no longer what makes the
      // signal survive — it is kept because it also ORDERS the posture report ahead of the decision
      // path. post() is bounded (1500ms) and never throws, so it cannot hang either way.
      await postPosture("Offline: fail-closed default applied", "offline:fail-closed", "High");
      policy = OFFLINE_DEFAULT_POLICY;
    } else {
      // A fail-closed org can still break-glass out of its cached/live policy entirely.
      if (offlineMode(policy) === "fail-closed" && bg.active) { await postPosture("Break-glass active (fail-open override)", "breakglass:active", "High"); return exitHook(); }
      if (source === "cache-offline") await postPosture("Offline: enforcing last-known policy", "offline:last-known", "Info"); // #33 point 2 — awaited so the signal isn't lost on exit
      // The live AND cached copies were both refused (or absent) and this device fell back to the last
      // policy that genuinely verified. When `rejected` is non-empty that means enforcement is running
      // THROUGH an active poisoning attempt rather than collapsing to exit(0) — which is the whole point
      // of keeping it. Awaited for the same reason.
      if (source === "last-known-good") await postPosture("Enforcing last-known-good verified policy", "policy:lkg:applied", "High", { lkgCopy: lkgCopy || "", lkgReason: rejected && rejected.length ? "refused" : "absent" });
    }
  } catch { if (!policy) return exitHook(); /* preserve legacy fail-open on any error when no policy */ }
  const engine = buildEngine(policy);

  if (tool === "Read") {
    const text = readFileCapped(ti.file_path);
    const d = decideText(engine, policy, text, "file");
    report(d.findings, "file", "hook:Read", d.decision === "deny", policy.captureTier, { filePath: ti.file_path, toolName: "Read" });
    logBehavior("Read", ti.file_path || "file", text, d, "file");
    if (isSkillSurface(ti.file_path)) reportSkillFile(ti.file_path, text, d);
    if (d.kill) killSession("Read", d.killIds, "file");
    let rdec = d.decision;
    if (reportEnvelope(policy, "Read", { tool: "Read", paths: [ti.file_path] }, "file") && rdec !== "deny") rdec = "deny";
    // AFTER every check that can still deny, and skipped entirely on a deny: escalation can send the
    // text to the agent's own provider, so running it first meant content the policy was about to
    // block had already left the device. The mcp__/Task branches always denied before their external
    // calls; Read and Bash did not.
    if (rdec !== "deny") await maybeEscalate(policy, text, "file", "hook:Read", d);
    return emit(rdec, `${d.kill ? "killed session" : "blocked Read"} of ${basename(ti.file_path || "file")} — ${d.reasons.join(", ")}`);
  }
  if (tool === "Bash") {
    let dec = "allow", reasons = [], finds = [], btext = "", killIds = [];
    for (const p of extractReadPaths(ti.command)) {
      const t = readFileCapped(p); btext += t + "\n";
      const d = decideText(engine, policy, t, "file");
      finds.push(...d.findings);
      if (d.kill) killIds.push(...d.killIds);
      if (RANK[d.decision] > RANK[dec]) { dec = d.decision; reasons = d.reasons; }
      if (isSkillSurface(p)) reportSkillFile(p, t, d);
    }
    // T1-2/T1-1 — scan the COMMAND itself (not just files it reads) so command-level detectors enforce:
    // typosquat/hallucinated install (#62), destructive (#43), reverse shell (#54), untrusted install (#57).
    const cmdD = decideText(engine, policy, ti.command, "prompt");
    finds.push(...cmdD.findings);
    if (cmdD.kill) killIds.push(...cmdD.killIds);
    if (RANK[cmdD.decision] > RANK[dec]) { dec = cmdD.decision; reasons = cmdD.reasons; }
    // T1-1 — model-endpoint allow-list: a base-URL override / direct call to a non-approved LLM host.
    const epD = decideEndpoints(policy, ti.command);
    if (epD.decision === "deny") { dec = "deny"; reasons = [epD.reason]; post({ threatId: 63, category: "Unapproved model endpoint", riskLevel: "Blocked", stage: "egress", tool: "hook:Bash", ts: new Date().toISOString(), contentHash: djb2(epD.hosts.join(",")), ...IDENTITY }); }
    report(finds, "file", "hook:Bash", dec === "deny", policy.captureTier, { toolName: "Bash", cmdShape: commandShape(ti.command) });
    logBehavior("Bash", ti.command || "bash", btext, { decision: dec, findings: finds }, "file");
    if (killIds.length) killSession("Bash", killIds, "file");
    if (checkSecretEgress(policy, ti.command, "Bash", "egress") && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; }
    if (reportEnvelope(policy, "Bash", { tool: "Bash", paths: extractReadPaths(ti.command) }, "file") && dec !== "deny") { dec = "deny"; reasons = ["out-of-envelope (entitlement drift)"]; }
    // See the Read branch: escalation runs last and never on a deny, so a local-secret-egress or
    // out-of-envelope command cannot ship its content to the provider on its way to being blocked.
    if (dec !== "deny") await maybeEscalate(policy, btext, "file", "hook:Bash", { findings: finds });
    // Recorded last, so the destination map stores the verdict the call ACTUALLY got rather than the
    // interim one — a host reached by a command that was then denied must read as denied.
    recordDestinations("Bash", "host", extractHosts(ti.command), dec);
    return emit(dec, `${killIds.length ? "killed session" : "blocked"} via Bash — ${reasons.join(", ")}`);
  }
  if (tool.startsWith("mcp__")) {
    const server = tool.split("__")[1] || "";
    const args = JSON.stringify(ti);
    const argsH = argsHash(args); // #20 — content-free hash of the args (never the args themselves)
    // On-device AI Agent Gateway: one named chokepoint for every MCP tool-call — server allow-list (#3)
    // → per-tool arg rules (#18) → argument content scan (#2), same order and short-circuits as before.
    const g = mcpGateway(engine, policy, { tool, server, args });
    // Content-free gateway ledger: record ONE audit line per MCP call (pass, coach, or block) so the
    // console can prove what every agent was allowed to do — closing the gap where denials and clean
    // passes recorded nothing locally. Best-effort; never affects the allow/deny decision.
    // The destination map hangs off the SAME chokepoint for the same reason: this branch has six
    // separate return sites, and threading a recording call through each one is how the next one added
    // silently stops being recorded. Both the server and any host named in the args are destinations.
    const audit = (decision) => {
      try { recordAction(applyCaptureTier({ threatId: 0, category: "MCP tool call", riskLevel: decision === "deny" ? "Blocked" : "Info", stage: "mcp", tool: `hook:${tool}`, decision, mcpServer: server, ts: new Date().toISOString(), contentHash: argsH, ...IDENTITY }, {}, policy.captureTier || "content-free")); } catch { /* ledger is best-effort */ }
      recordDestinations(tool, "mcp", [server], decision);
      recordDestinations(tool, "host", extractHosts(args), decision);
    };
    if (g.gate === "server") { post({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(server), ...IDENTITY, ...(signApproval(tool, argsH, "deny") || {}) }); audit("deny"); return emit("deny", g.reason); }
    if (g.gate === "args") { post({ threatId: 0, category: "MCP: denied tool argument", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: contentHash(args), ...IDENTITY, ...(signApproval(tool, argsH, "deny") || {}) }); audit("deny"); return emit("deny", g.reason); }
    // T1-5 — entitlement envelope: an MCP server outside the agent's declared scope is drift.
    if (reportEnvelope(policy, tool, { tool, mcpServer: server }, "egress")) { audit("deny"); return emit("deny", `${tool} — out-of-envelope MCP server`); }
    // T1-1 — model-endpoint allow-list on the serialized args (a tool arg pointing at a rogue LLM host).
    const epD = decideEndpoints(policy, args);
    if (epD.decision === "deny") { post({ threatId: 63, category: "Unapproved model endpoint", riskLevel: "Blocked", stage: "egress", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(epD.hosts.join(",")), ...IDENTITY }); audit("deny"); return emit("deny", epD.reason); }
    // Tier-2 / #65 — a local secret value shipped as an MCP tool argument.
    if (checkSecretEgress(policy, args, tool, "egress")) { audit("deny"); return emit("deny", `${tool} — local secret egress`); }
    // #33 — fail-closed MCP floor: raise an otherwise-allowed MCP call to "ask" (justify). Inert unless
    // policy.mcpFloor is set (only the offline fail-closed default sets it), so normal policies are unaffected.
    const floored = mcpFloor(policy, g.decision);
    if (floored !== g.decision) { g.decision = floored; g.reason = g.reason || "fail-closed default: MCP requires justification"; }
    report(g.findings, "egress", `hook:${tool}`, g.decision === "deny", policy.captureTier, { toolName: tool, argText: args }, signApproval(tool, argsH, g.decision === "deny" ? "deny" : "allow"));
    logBehavior(tool, tool, args, { decision: g.decision, findings: g.findings }, "egress");
    if (g.kill) killSession(tool, g.killIds, "egress");
    audit(g.decision);
    return emit(g.decision, `${g.kill ? "killed session" : g.decision === "ask" ? "needs justification" : "blocked"} ${tool} — ${g.reason}`);
  }
  // Tier-2 / #66 — sub-agent spawn / A2A delegation (Claude Code's Task tool). Record the delegation
  // content-free, scan the delegated prompt for injection, apply the parent's entitlement envelope, and
  // block per policy. Extends blast-radius visibility to children that could otherwise bypass parent controls.
  if (tool === "Task") {
    const desc = JSON.stringify(ti);
    const act = threatActionFor(policy, 66);
    const block = act === "block" || act === "kill";
    post({ threatId: 66, category: "Sub-agent / A2A delegation", riskLevel: block ? "Blocked" : "Medium", stage: "behavior", tool: "hook:Task", ts: new Date().toISOString(), contentHash: contentHash((ti.subagent_type || "") + "|" + desc), subagentType: ti.subagent_type, ...IDENTITY });
    // Content-free handoff edge: this session (parent) is delegating to a child agent (subagent_type,
    // one-way hashed). Surfaces as cross-agent messaging in data/agent-detections.js.
    logBehavior("Task", "Task", desc, { decision: block ? "deny" : "allow", findings: [] }, "behavior", { role: "handoff", parent: SESSION, to: contentHash(ti.subagent_type || "") });
    const pd = decideText(engine, policy, ti.prompt || "", "prompt"); // scan the delegated prompt for injection
    report(pd.findings, "egress", "hook:Task", pd.decision === "deny", policy.captureTier, { toolName: "Task" });
    if (block || pd.decision === "deny" || reportEnvelope(policy, "Task", { tool: "Task" }, "behavior")) return emit("deny", `Task (sub-agent delegation) — ${block ? "blocked by policy" : pd.decision === "deny" ? pd.reasons.join(", ") : "out of envelope"}`);
    return emit("allow", "sub-agent delegation logged");
  }
  return exitHook(); // unknown tool → allow
}

main();
