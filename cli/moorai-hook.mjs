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

import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname, basename } from "node:path";
import os from "node:os";
import { loadConfig } from "./config.mjs";
import { buildEngine, decideText, decideEndpoints, decideEnvelope, threatActionFor, extractReadPaths, mcpGateway, offlineMode, verifyBreakGlass, parseTrustedKeys, ratchetPosture, mcpFloor, literacyTouchpoint, verifyPolicySignature, POLICY_PIN_VERSION, reconcilePolicyPins, policyTrust, parsePublishedKeys, selectLastKnownGood, assessPinAbsence, icaclsPermissive } from "./hook-core.mjs";
import { OFFLINE_DEFAULT_POLICY } from "../data/offline-default.js";
import { egressHits } from "./secret-egress.mjs";
import { recordExposure, recordAgentEvent, readAgentEvents, recordAction, rulesBaseline, setRulesBaseline, requestKill } from "./signals.mjs";
import { applyCaptureTier, commandShape } from "../data/capture-tiers.js";
import { isRulesFile, rulesFileKind } from "../data/rules-files.js";
import { signApproval, argsHash } from "../data/agency-sign.mjs";
import { contentTells, assessSession, assessTrifecta, assessCrossServerTrifecta, trifectaLegs, serverOf } from "../data/agent-behavior.js";
import { classifyOpportunistic } from "../data/model-escalation.mjs";

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

// ---- policy load (cached; per-call HTTP would be too slow) ----
const CONFIG = loadConfig();
const CACHE = join(os.homedir(), ".curaiq", "hook-policy.json");
// #33 — break-glass marker (operator-created, holds an expiry) and the durable last-known posture the
// hook remembers so a fail-closed org stays fail-closed even if the policy cache is later deleted.
const BREAK_GLASS = join(os.homedir(), ".curaiq", "break-glass");
const POSTURE_SIDECAR = join(os.homedir(), ".curaiq", "offline-posture");
// Second user-scope copy of the same fact, deliberately in a DIFFERENT directory so the one-liner
// erasures (`rm ~/.curaiq/offline-posture`, `rm -rf ~/.curaiq`) do not take the memory with them.
const POSTURE_LATCH = join(os.homedir(), ".moorai", "posture");
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
const SYSTEM_POSTURE = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "offline-posture")
  : "/etc/moorai/offline-posture";

// Policy-key PIN (Trust On First Use) — the self-arming half of policy verification. Two copies in two
// DIFFERENT directories, exactly like the posture latch and for exactly the same reason: `rm
// ~/.curaiq/policy-pin.json` and `rm -rf ~/.curaiq` must not take the device's memory with them, and a
// partial erasure must be visible. There is deliberately no third, root-owned pin: the hook runs as the
// user and cannot write /etc, so a "system pin" it wrote would be a fiction. The root-owned path that
// does exist is POLICY_ANCHOR below — provisioned by MDM, outranking every pin. See the pinning section
// in hook-core.mjs for what this achieves (tamper-EVIDENCE) and what it does not (tamper-proofing).
const POLICY_PIN = join(os.homedir(), ".curaiq", "policy-pin.json");
const POLICY_PIN_LATCH = join(os.homedir(), ".moorai", "policy-pin.json");

// Last-known-good VERIFIED policy — the copies that let a fail-open org ENFORCE through a poisoned
// cache instead of merely alerting about it. Same two-copy user-scope pattern as the pin and the
// posture latch, plus a root-owned system copy that is preferred when one exists (an MDM can drop a
// signed policy there; the hook only ever reads it). The stored bytes are the console's ORIGINAL signed
// body and are re-verified on load — see selectLastKnownGood in hook-core.mjs for why that matters.
const POLICY_LKG = join(os.homedir(), ".curaiq", "policy-lkg.json");
const POLICY_LKG_LATCH = join(os.homedir(), ".moorai", "policy-lkg.json");
const POLICY_LKG_SYSTEM = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "policy-lkg.json")
  : "/etc/moorai/policy-lkg.json";

// "This device has held a policy-key pin" — a breadcrumb in a THIRD directory, deliberately outside both
// ~/.curaiq and ~/.moorai so that `rm ~/.curaiq/policy-pin.json ~/.moorai/policy-pin.json` (and the
// `rm -rf ~/.curaiq` wipe) leaves something behind that contradicts "this is a fresh install". It holds
// no key and no secret — it could not usefully hold one, since the hook runs as the user and anything it
// can read the attacker can read. Its only job is to make an ERASED pin distinguishable from an absent
// one. Deleting it too is possible and is the stated residual risk.
const PIN_BREADCRUMB = process.platform === "win32"
  ? join(process.env.LOCALAPPDATA || join(os.homedir(), "AppData", "Local"), "MoorAI", "pinned")
  : join(os.homedir(), ".config", "moorai", "pinned");

// Artifacts that exist ONLY on a device that has verified a real console signature. These decide whether
// a missing pin is suspicious — see assessPinAbsence for why "prior operation" artifacts cannot.
const PINNING_ARTIFACTS = [
  ["pin-breadcrumb", () => PIN_BREADCRUMB],
  ["policy-lkg", () => POLICY_LKG],
  ["policy-lkg-latch", () => POLICY_LKG_LATCH]
];
// Artifacts a device only produces by actually RUNNING. Reported as context on a suspicious pin absence
// so a SOC can see how long the device had been operating; never a trigger on their own.
const OPERATION_ARTIFACTS = [
  ["posture-sidecar", () => POSTURE_SIDECAR],
  ["posture-latch", () => POSTURE_LATCH],
  ["action-audit", () => join(os.homedir(), ".curaiq", "action-audit.jsonl")],
  ["exposure-ledger", () => join(os.homedir(), ".curaiq", "exposure-ledger.jsonl")],
  ["agent-events", () => join(os.homedir(), ".curaiq", "agent-events.jsonl")]
];
// Only the artifact NAMES ever leave the device, never a byte of their contents.
function presentArtifacts(list) {
  const out = [];
  for (const [name, path] of list) {
    try { if (statSync(path()).size > 0) out.push(name); } catch { /* absent */ }
  }
  return out;
}
function writePinBreadcrumb() {
  try {
    if (statSync(PIN_BREADCRUMB).size > 0) return; // already recorded; never rewritten
  } catch { /* absent — write it */ }
  try {
    mkdirSync(dirname(PIN_BREADCRUMB), { recursive: true });
    writeFileSync(PIN_BREADCRUMB, JSON.stringify({ v: POLICY_PIN_VERSION, tenant: String(CONFIG.tenant), first: new Date().toISOString() }));
  } catch { /* best-effort */ }
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
async function loadPolicy() {
  const anchorKeys = policyKeys();    // explicit anchor: root-owned /etc/moorai/policy.pub or MDM env
  const pin = readPolicyPin();        // this device's own TOFU record
  const trust = policyTrust({ anchorKeys, pin, tenant: CONFIG.tenant });
  // A device that has demonstrably been operating but holds NO pin and NO anchor is not a fresh install
  // — it is a device whose pin was erased. Computed here (not in main) because it also shortens the
  // window: while in that state the cache's 60s short-circuit is skipped so every invocation attempts a
  // fresh network fetch, which is the only thing that can re-pin the device.
  const absence = assessPinAbsence({
    enrolled: Boolean(CONFIG.installToken),
    trustMode: trust.mode,
    pinningEvidence: presentArtifacts(PINNING_ARTIFACTS),
    operationEvidence: presentArtifacts(OPERATION_ARTIFACTS)
  });
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
    const v = verifyPolicySignature(p, { keys: trust.keys, tenant: CONFIG.tenant });
    return v.trusted ? { policy: p, status: v.status, keyId: v.keyId } : { bad: v.status };
  };

  // One read + one verify of the cache, whatever path we end up taking — the file is the same file in
  // the "fresh window" and the "offline fallback" cases, so it must not be able to raise two alerts.
  let cacheRaw = null, withinWindow = false;
  try { const st = statSync(CACHE); cacheRaw = readFileSync(CACHE, "utf8"); withinWindow = Date.now() - st.mtimeMs < 60000; } catch { /* absent */ }
  const cached = cacheRaw == null ? null : verify(cacheRaw);
  if (cached && cached.bad) rejected.push({ source: "cache", status: cached.bad });
  // A CACHED policy never re-pins, however valid it looks: the cache file is in the agent's own write
  // scope, so letting it teach the device a key would hand the attacker the pin. Only a signature
  // delivered fresh over the network from the configured server can arm or roll the pin forward.
  if (withinWindow && !absence.suspicious && cached && cached.policy) return { policy: cached.policy, source: "cache", rejected, pin, trust, absence };

  try {
    const headers = CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {};
    const q = (p) => fetch(`${CONFIG.serverUrl}${p}`, { headers, signal: AbortSignal.timeout(1500) }).then((r) => (r.ok ? r.text() : "")).catch(() => "");
    // The published-key fetch runs in PARALLEL with the policy fetch, so it costs no extra latency, and
    // only on devices with no explicit anchor (an anchored device already has the stronger statement).
    const [raw, published] = await Promise.all([
      q(`/api/policy?tenant=${encodeURIComponent(CONFIG.tenant)}`),
      trust.mode === "anchored" || trust.mode === "rebind" || trust.mode === "corrupt" ? Promise.resolve("") : q("/api/policy/pubkey")
    ]);
    if (raw && raw.trim()) {
      const v = verify(raw);
      // Cache the server's ORIGINAL bytes — the signature covers the policy body, and re-serializing
      // gains nothing while risking a mismatch with whatever the console signed.
      if (v.policy) {
        try { mkdirSync(dirname(CACHE), { recursive: true }); writeFileSync(CACHE, raw); } catch {}
        // Non-empty result ⇒ a REAL console signature verified on this fetch — under the anchor, under
        // an already-pinned key, or (first contact) under the key the server published. That is the same
        // bar last-known-good needs, and it is NOT the same as v.status: on first contact the policy is
        // admitted as "unanchored" (the device holds no key yet) and only the TOFU re-check proves it.
        const armed = armPolicyPin(trust, pin, v, JSON.parse(raw), published);
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
    { source: "latch", raw: readText(POLICY_LKG_LATCH) }
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

// ---- policy-key pin I/O (the pure logic lives in hook-core.mjs) ----

function readPolicyPin() { return reconcilePolicyPins({ primary: readText(POLICY_PIN), secondary: readText(POLICY_PIN_LATCH) }); }

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
function armPolicyPin(trust, pin, verdict, policy, publishedRaw) {
  try {
    const published = parsePublishedKeys(publishedRaw, { tenant: CONFIG.tenant });
    let learn = [];
    if (trust.mode === "anchored") learn = [verdict.keyId];
    else if (trust.mode === "pinned") learn = [verdict.keyId, ...published];
    else if (trust.mode === "unpinned" && published.length) {
      const t = verifyPolicySignature(policy, { keys: parseTrustedKeys(published.join("\n")), tenant: CONFIG.tenant });
      if (t.trusted && t.status === "ok") learn = [t.keyId];
    }
    learn = learn.filter(Boolean);
    writePolicyPin(pin, learn);
    return learn.length > 0;
  } catch { return false; /* pinning is durability, never enforcement — a failure here must not change the decision */ }
}

// Write BOTH copies when there is something new to record, or when the copies disagree (which also
// HEALS a single erased copy — the caller has already reported it by then, so the signal is not lost).
function writePolicyPin(pin, ids) {
  const keys = [...new Set([...(pin.keys || []), ...ids])];
  if (!keys.length) return;
  // Record "this device has pinned" in the third location on every run that HAS a pin, so the breadcrumb
  // self-heals if deleted while the pin still exists. It is never written when there is no pin, which is
  // what keeps it meaningful as evidence.
  writePinBreadcrumb();
  const stale = keys.length !== (pin.keys || []).length || pin.evidenceMissing || pin.corrupt || pin.tenant !== CONFIG.tenant;
  if (!stale) return;
  const body = JSON.stringify({ v: POLICY_PIN_VERSION, tenant: String(CONFIG.tenant), keys, updated: new Date().toISOString() });
  for (const p of [POLICY_PIN, POLICY_PIN_LATCH]) {
    try { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); } catch { /* best-effort */ }
  }
}

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
// one tool call. RUNTIME BEHAVIOR ON WINDOWS IS UNVERIFIED — no Windows host was available.
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
function readRootOwned(p) {
  try {
    const st = statSync(p);
    if (process.platform === "win32") { if (!windowsFileIsProtected(p)) return ""; }
    else if (st.uid !== 0 || (st.mode & 0o022)) return "";
    return readFileSync(p, "utf8");
  } catch { return ""; }
}
function readText(p) { try { return readFileSync(p, "utf8"); } catch { return ""; } }

// #33 — remember the org's chosen posture durably, so it survives a later cache deletion. Written every
// time a real policy loads, to BOTH user-scope copies. For an org that never set offlineMode this is
// "fail-open" → no-cache stays exit(0)/allow (unchanged default). What is recorded is the RATCHETED
// posture, not the policy's alone: on an MDM-latched device the copies record fail-closed even while a
// fail-open policy is in force, so the next offline run sees no contradiction (and raises no false
// downgrade alert). Best-effort; a write error never affects enforcement.
function rememberPosture(policy) {
  const mode = readRootOwned(SYSTEM_POSTURE).trim() === "fail-closed" ? "fail-closed" : offlineMode(policy);
  for (const p of [POSTURE_SIDECAR, POSTURE_LATCH]) {
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
    sidecar: readText(POSTURE_SIDECAR),
    latch: readText(POSTURE_LATCH),
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

// A user-writable "system" anchor is no better than ~/.curaiq — readRootOwned rejects it rather than pretend.
function anchorText() { return readRootOwned(BG_ANCHOR); }
function trustedKeys() {
  try { return parseTrustedKeys(`${anchorText()}\n${process.env.MOORAI_BREAKGLASS_PUBKEY || ""}`); } catch { return []; }
}
function policyKeys() {
  try { return parseTrustedKeys(`${readRootOwned(POLICY_ANCHOR)}\n${process.env.MOORAI_POLICY_PUBKEY || ""}`); } catch { return []; }
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
  let raw = "";
  try { raw = readFileSync(BREAK_GLASS, "utf8"); } catch { return { active: false, status: "absent", raw: "" }; }
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
function post(alert) { return fetch(`${CONFIG.serverUrl}/api/alerts`, { method: "POST", headers: { "Content-Type": "application/json", ...(CONFIG.installToken ? { "X-Install-Token": CONFIG.installToken } : {}) }, body: JSON.stringify(alert), signal: AbortSignal.timeout(1500) }).catch(() => {}); }
function report(findings, stage, tool, blocked, tier, extras, agency) {
  for (const f of findings) {
    const base = { threatId: f.threatId, category: f.category, riskLevel: blocked ? "Blocked" : f.riskLevel, stage, tool, ts: new Date().toISOString(), contentHash: djb2(f.match || ""), ...IDENTITY };
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
function logBehavior(tool, identity, scannedText, d, stage) {
  try {
    const risk = (d.findings || []).reduce((m, f) => (RISK_RANK[f.riskLevel] > RISK_RANK[m] ? f.riskLevel : m), "Low");
    const flags = contentTells(scannedText || "");
    const legs = trifectaLegs(tool, stage, d.findings || [], flags); // #1 — content-free trifecta legs
    const server = serverOf(tool); // which MCP server (or "local") contributed this event's legs
    const priorEvents = readAgentEvents();
    const beforeS = assessSession(priorEvents), beforeT = assessTrifecta(priorEvents), beforeX = assessCrossServerTrifecta(priorEvents);
    recordAgentEvent({ ts: Date.now(), sig: `${tool}|${djb2(identity || tool)}`, ok: d.decision !== "deny", risk, flags, legs, server });
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
      post({ threatId: 58, category: `Model-flagged: ${v.category}`, riskLevel: v.confidence >= 0.85 ? "High" : "Medium", stage, tool: `escalate:${tool}`, ts: new Date().toISOString(), contentHash: djb2(text), ...IDENTITY });
    }
  } catch { /* escalation is advisory; fail-open */ }
}

// Rules-file hygiene (Backslash-inspired, content-free). A coding-agent rules/config file the agent
// auto-loads is high-value to poison — one injected directive steers every future prompt. Flags two
// things, content-free: (a) injected/hidden instructions found in the file (reuses the injection
// detectors), and (b) drift from the last-seen fingerprint. Only the file KIND and a one-way hash leave.
function reportRulesFile(path, text, d) {
  try {
    const kind = rulesFileKind(path);
    if (!kind || !text) return;
    const fp = djb2(text);
    const injected = (d.findings || []).some((f) => [3, 40, 50, 51].includes(f.threatId));
    const base = rulesBaseline();
    const drift = base[kind] != null && base[kind] !== fp;
    setRulesBaseline(kind, fp);
    if (injected || drift) {
      post({ threatId: 60, category: injected ? "Rules-file poisoning" : "Rules-file drift", riskLevel: injected ? "High" : "Medium", stage: "file", tool: `rules:${kind}`, ts: new Date().toISOString(), contentHash: fp, ...IDENTITY });
    }
  } catch { /* best-effort; never affects enforcement */ }
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

function emit(decision, reason) {
  if (decision === "allow") process.exit(0);
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision === "deny" ? "deny" : "ask", permissionDecisionReason: `MoorAI: ${reason}` } }));
  process.exit(0);
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
  let { policy, source, rejected, pin, trust, absence, lkgCopy } = await loadPolicy();
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
      if (posture.posture !== "fail-closed") process.exit(0); // fail-open (default) — UNCHANGED behavior
      // The ratchet just refused a downgrade (or found a copy erased) — awaited so the signal cannot be
      // lost to the process.exit that follows, exactly like the break-glass tamper report above.
      await reportPostureTamper(posture);
      // Fail-closed posture with no policy: break-glass (if operator-signed and live) forces fail-open so
      // an operator can recover a locked-out machine; otherwise apply the reviewable built-in default.
      if (bg.active) { await postPosture("Break-glass active (fail-open override)", "breakglass:active", "High"); process.exit(0); }
      // Awaited: the SOC's ONLY signal that a device fell back to the built-in fail-closed default.
      // emit() calls process.exit(0), so a fire-and-forget POST here is lost whenever the decision
      // path finishes first. post() is bounded (1500ms) and never throws, so this cannot hang.
      await postPosture("Offline: fail-closed default applied", "offline:fail-closed", "High");
      policy = OFFLINE_DEFAULT_POLICY;
    } else {
      // A fail-closed org can still break-glass out of its cached/live policy entirely.
      if (offlineMode(policy) === "fail-closed" && bg.active) { await postPosture("Break-glass active (fail-open override)", "breakglass:active", "High"); process.exit(0); }
      if (source === "cache-offline") await postPosture("Offline: enforcing last-known policy", "offline:last-known", "Info"); // #33 point 2 — awaited so the signal isn't lost on exit
      // The live AND cached copies were both refused (or absent) and this device fell back to the last
      // policy that genuinely verified. When `rejected` is non-empty that means enforcement is running
      // THROUGH an active poisoning attempt rather than collapsing to exit(0) — which is the whole point
      // of keeping it. Awaited for the same reason.
      if (source === "last-known-good") await postPosture("Enforcing last-known-good verified policy", "policy:lkg:applied", "High", { lkgCopy: lkgCopy || "", lkgReason: rejected && rejected.length ? "refused" : "absent" });
    }
  } catch { if (!policy) process.exit(0); /* preserve legacy fail-open on any error when no policy */ }
  const engine = buildEngine(policy);

  if (tool === "Read") {
    const text = readFileCapped(ti.file_path);
    const d = decideText(engine, policy, text, "file");
    report(d.findings, "file", "hook:Read", d.decision === "deny", policy.captureTier, { filePath: ti.file_path, toolName: "Read" });
    logBehavior("Read", ti.file_path || "file", text, d, "file");
    await maybeEscalate(policy, text, "file", "hook:Read", d);
    if (isRulesFile(ti.file_path)) reportRulesFile(ti.file_path, text, d);
    if (d.kill) killSession("Read", d.killIds, "file");
    let rdec = d.decision;
    if (reportEnvelope(policy, "Read", { tool: "Read", paths: [ti.file_path] }, "file") && rdec !== "deny") rdec = "deny";
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
      if (isRulesFile(p)) reportRulesFile(p, t, d);
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
    await maybeEscalate(policy, btext, "file", "hook:Bash", { findings: finds });
    if (killIds.length) killSession("Bash", killIds, "file");
    if (checkSecretEgress(policy, ti.command, "Bash", "egress") && dec !== "deny") { dec = "deny"; reasons = ["local secret egress"]; }
    if (reportEnvelope(policy, "Bash", { tool: "Bash", paths: extractReadPaths(ti.command) }, "file") && dec !== "deny") { dec = "deny"; reasons = ["out-of-envelope (entitlement drift)"]; }
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
    const audit = (decision) => { try { recordAction(applyCaptureTier({ threatId: 0, category: "MCP tool call", riskLevel: decision === "deny" ? "Blocked" : "Info", stage: "mcp", tool: `hook:${tool}`, decision, mcpServer: server, ts: new Date().toISOString(), contentHash: argsH, ...IDENTITY }, {}, policy.captureTier || "content-free")); } catch { /* ledger is best-effort */ } };
    if (g.gate === "server") { post({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(server), ...IDENTITY, ...(signApproval(tool, argsH, "deny") || {}) }); audit("deny"); return emit("deny", g.reason); }
    if (g.gate === "args") { post({ threatId: 0, category: "MCP: denied tool argument", riskLevel: "Blocked", stage: "mcp", tool: `hook:${tool}`, ts: new Date().toISOString(), contentHash: djb2(args), ...IDENTITY, ...(signApproval(tool, argsH, "deny") || {}) }); audit("deny"); return emit("deny", g.reason); }
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
    post({ threatId: 66, category: "Sub-agent / A2A delegation", riskLevel: block ? "Blocked" : "Medium", stage: "behavior", tool: "hook:Task", ts: new Date().toISOString(), contentHash: djb2((ti.subagent_type || "") + "|" + desc), subagentType: ti.subagent_type, ...IDENTITY });
    logBehavior("Task", "Task", desc, { decision: block ? "deny" : "allow", findings: [] }, "behavior");
    const pd = decideText(engine, policy, ti.prompt || "", "prompt"); // scan the delegated prompt for injection
    report(pd.findings, "egress", "hook:Task", pd.decision === "deny", policy.captureTier, { toolName: "Task" });
    if (block || pd.decision === "deny" || reportEnvelope(policy, "Task", { tool: "Task" }, "behavior")) return emit("deny", `Task (sub-agent delegation) — ${block ? "blocked by policy" : pd.decision === "deny" ? pd.reasons.join(", ") : "out of envelope"}`);
    return emit("allow", "sub-agent delegation logged");
  }
  process.exit(0); // unknown tool → allow
}

main();
