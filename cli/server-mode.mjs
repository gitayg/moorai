// Server mode: the hook running without a developer's laptop — `claude -p` in CI, the Claude Code GitHub
// Action, an Agent SDK service in a container. Three things differ from a laptop, and all three live here
// so cli/moorai-hook.mjs only calls in:
//
//   1. WHERE THE BINDING COMES FROM. A container has no desktop app to write ~/.moorai/config.json, so the
//      console URL, tenant and install token can come from a root-owned system file or the environment.
//   2. WHAT "ASK" MEANS. A "justify" verdict asks a human; a headless run has none (settleHeadlessAsk).
//   3. WHO THE ACTOR IS. A container's hostname changes on every deploy, so user@host would mint a new
//      console pseudonym per deploy; a workload name is used instead (serviceWho).
//
// OFF UNLESS ASKED FOR. Server mode is on only when the root-owned system file says `"mode": "server"`
// or the environment says MOORAI_MODE=server. Otherwise loadConfig() returns exactly what it always did.
//
// ---------------------------------------------------------------------------------------------
// PRECEDENCE, AND WHY THE ENVIRONMENT IS NOT TRUSTED LIKE A FILE
// ---------------------------------------------------------------------------------------------
// Claude Code lets a settings file set the environment of the hook process. Its settings reference, `env`:
// "Set environment variables for every session and for the subprocesses Claude Code starts from it", "A
// value here overwrites the same variable exported in your shell", and, for project and local settings,
// they apply "after you trust the workspace, or at startup in `-p` mode, which never shows the trust
// dialog, and again when a saved change alters the merged `env`". So in CI a pull request's
// .claude/settings.json sets MOORAI_* for the hook before the first tool call, and in any session the
// agent can Write that file and change the next hook's environment. A MOORAI_SERVER_URL planted that way
// would receive the install token (X-Install-Token) and serve the policy; a MOORAI_SERVICE_ID would let a
// workload claim another workload's JIT grants (they are matched on the actor hash).
//
// Hence, per key, highest first:
//   system  — /etc/moorai/config.json (Windows: %ProgramData%\MoorAI\config.json), read only when root-
//             owned and not group/world-writable (hook-core readRootOwned). The agent's user cannot write
//             it. A Kubernetes secret volume or a root-written file in the image satisfies this.
//   env     — MOORAI_SERVER_URL / MOORAI_TENANT / MOORAI_INSTALL_TOKEN / MOORAI_SERVICE_ID, EXCEPT a name
//             that a user-, project- or local-scope settings file sets in its `env` block. Such a name
//             is refused (its value is the file's, not the launcher's) and reported as tampering. Managed
//             settings are trusted: "Only managed settings can disable managed hooks" and they sit above
//             every other scope, so a managed `env` value is the one the hook sees.
//   file    — ~/.moorai/config.json, as on a laptop. Below env in server mode because in a container the
//             operator's configuration arrives as env (CI secrets, a pod spec) and a user file is either
//             absent or baked stale into an image; both are equally writable by the agent's user.
//   default — http://localhost:8787, tenant "unprovisioned", no token (as today).
//
// Two settings are one-directional, because the environment must never be able to weaken enforcement:
//   * headless ask: env may only say "deny" (the default). "allow-with-report" is accepted only from the
//     system file or the org policy.
//   * server mode itself enforces without a token (the caller passes it as management evidence, like the
//     fail-closed posture). An env that turns server mode on only hardens a device; a settings file that
//     sets MOORAI_MODE is refused like any other name, so a repository cannot flip a laptop's identity.
//
// Never logged: the install token. Diagnostics carry a sha256 fingerprint of it at most (doctor).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import os from "node:os";
import { readRootOwned } from "./hook-core.mjs";
import { machinePath } from "./machine-dir.mjs";

export const ENV = {
  mode: "MOORAI_MODE",
  serverUrl: "MOORAI_SERVER_URL",
  tenant: "MOORAI_TENANT",
  installToken: "MOORAI_INSTALL_TOKEN",
  serviceId: "MOORAI_SERVICE_ID",
  headlessAsk: "MOORAI_HEADLESS_ASK",
  workloadId: "MOORAI_WORKLOAD_ID",
  oidc: "MOORAI_OIDC",
  cloudHost: "MOORAI_CLOUD_HOST"
};
// Cloud coding agents (CONTRACT-F28 §5). A cloud host runs MoorAI in server mode from its environment-setup
// step (cli/moorai-cloud-setup.mjs, examples/cloud/). The workload id selects the console's workload record;
// MOORAI_OIDC=github means the setup step exchanges a GitHub Actions OIDC ID token for a scoped workload
// token (cli/workload-token.mjs). All three are MOORAI_* names, so a settings file's `env` block setting one
// is refused like the rest.
export const CLOUD_HOSTS = Object.freeze(["copilot-coding-agent", "codex-cloud", "claude-code-web", "ci", "other"]);
export const WORKLOAD_ATTESTATIONS = Object.freeze(["github-oidc", "static-token"]);
export const OIDC_PROVIDERS = Object.freeze(["github"]);
export const WORKLOAD_ID_RE = /^wkl-[0-9a-f]{12}$/;
export const WORKLOAD_TOKEN_RE = /^mwt_[A-Za-z0-9_-]{43}$/;
// GitHub Actions default variables used for the fallback workload name. From GitHub's reference
// (docs.github.com/en/actions/reference/workflows-and-actions/variables): GITHUB_ACTIONS "Always set to
// `true` when GitHub Actions is running the workflow"; GITHUB_REPOSITORY "The owner and repository name";
// GITHUB_WORKFLOW "The name of the workflow ... If the workflow file doesn't specify a `name`, the value
// of this variable is the full path of the workflow file"; GITHUB_JOB "The job_id of the current job".
// GITHUB_RUN_ID is deliberately NOT used: it is "A unique number for each workflow run", i.e. one new
// actor per run — the same flood a per-deploy hostname causes.
export const GITHUB_ID_ENV = ["GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_JOB"];
export const HEADLESS_MODES = ["deny", "allow-with-report"];
export const DEFAULTS = { serverUrl: "http://localhost:8787", tenant: "unprovisioned", installToken: "" };
const MAX_ID = 128;

// Windows: <ProgramData from HKLM>\MoorAI\config.json, never %ProgramData% (cli/machine-dir.mjs).
export function systemConfigPath(platform = process.platform) {
  return machinePath("config.json", platform);
}
// The parsed root-owned machine config, or null. Read once per process: loadConfig() (the binding) and
// serverMode() both ask, and they must see the same file.
let SYSTEM = undefined;
export function systemConfig() {
  if (SYSTEM !== undefined) return SYSTEM;
  return (SYSTEM = parseObj(readRootOwned(systemConfigPath())));
}
export function _resetSystemConfigForTests() { SYSTEM = undefined; }
function managedSettingsPath(platform = process.platform) {
  if (platform === "darwin") return "/Library/Application Support/ClaudeCode/managed-settings.json";
  if (platform === "win32") return "C:\\Program Files\\ClaudeCode\\managed-settings.json";
  return "/etc/claude-code/managed-settings.json";
}
function parseObj(text) {
  if (!text || !text.trim()) return null;
  try { const v = JSON.parse(text); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; }
}
const readPlain = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };

// The laptop provision file, in the order cli/config.mjs has always searched it.
export function readUserConfig(home = os.homedir(), read = readPlain) {
  for (const dir of [".moorai", ".curaiq", ".raiseme"]) {
    const c = parseObj(read(join(home, dir, "config.json")));
    if (c) return { path: join(home, dir, "config.json"), data: c };
  }
  return null;
}

// A name is "guarded" when a settings file must not be the one setting it for the hook.
export const isGuarded = (name) => /^(MOORAI_|MoorAI_)/.test(name) || GITHUB_ID_ENV.includes(name);
// Variables that decide what code the hook process itself runs and where it looks for things, rather than
// MoorAI's own configuration: NODE_OPTIONS (--require / --import runs code inside the hook), NODE_PATH
// (where bare imports resolve), PATH (which `node` a bare hook command starts, and every bare tool name),
// ProgramData (where the Windows machine anchors used to be read from). A settings file that sets one of
// these for the hook is reported, and the hook does not rely on it: its registration names node by
// absolute path (hookEntry), its Windows anchors come from HKLM and its system tools are called by
// absolute path (cli/machine-dir.mjs), and its detached workers start without the NODE_* values the file
// set (workerEnv). PATH that the hook merely INHERITS (the shell's, the launcher's) is not a finding: only
// a name a settings file's `env` block sets is. Windows names are case-insensitive, so a block that sets
// "Path" or "PROGRAMDATA" counts.
export const HOOK_PROCESS_ENV = ["NODE_OPTIONS", "NODE_PATH", "PATH", "ProgramData"];
export function hookProcessEnvName(name) {
  const n = String(name || "").toLowerCase();
  return HOOK_PROCESS_ENV.find((h) => h.toLowerCase() === n) || "";
}
const isTrustRelevant = (name) => isGuarded(name) || Boolean(hookProcessEnvName(name));
const canonicalEnvName = (name) => hookProcessEnvName(name) || name;

// The settings files a repository or the agent can write, and which guarded names each one's `env`
// block sets. User scope: $CLAUDE_CONFIG_DIR or ~/.claude; project scope: $CLAUDE_PROJECT_DIR (the hooks
// reference: "the project root where the session started", exported to command hooks) or the cwd.
export function settingsEnvHits({ env = process.env, home = os.homedir(), cwd = process.cwd(), read = readPlain } = {}, pred = isGuarded) {
  const userDir = env.CLAUDE_CONFIG_DIR || join(home, ".claude");
  const proj = env.CLAUDE_PROJECT_DIR || cwd;
  const files = [...new Set([join(userDir, "settings.json"), join(userDir, "settings.local.json"), join(proj, ".claude", "settings.json"), join(proj, ".claude", "settings.local.json")])];
  const hits = [];
  for (const file of files) {
    const s = parseObj(read(file));
    const block = s && s.env && typeof s.env === "object" ? s.env : null;
    if (!block) continue;
    const keys = [...new Set(Object.keys(block).filter(pred).map(canonicalEnvName))].sort();
    if (keys.length) hits.push({ file, keys });
  }
  return hits;
}
// Guarded names a managed settings `env` block sets: those values win over every other scope.
export function managedEnvKeys(path = managedSettingsPath(), read = readRootOwned) {
  const s = parseObj(read(path));
  return s && s.env && typeof s.env === "object" ? Object.keys(s.env).filter(isTrustRelevant).map(canonicalEnvName) : [];
}

// ---- environment the hook may trust, in every mode ----
//
// The same rule as server mode's binding, applied to the security-relevant variables the rest of the hook
// reads (MOORAI_BREAKGLASS_PUBKEY, MOORAI_POLICY_PUBKEY, MOORAI_OFFLINE_MODE, the OTLP export endpoint),
// on a laptop as much as on a server: a value a user, project or local settings file sets in its `env`
// block is the file's, not the operator's, so it is treated as unset. A managed `env` value is trusted.
// Nothing is read unless the variable is actually set, so a laptop that sets none pays nothing.
let TRUST = null;
function untrustedNames({ env, home, cwd }) {
  if (TRUST) return TRUST;
  let managed = [];
  try { managed = managedEnvKeys(); } catch { /* none */ }
  const keep = new Set(managed);
  TRUST = new Set(settingsEnvHits({ env, home, cwd }, isTrustRelevant).flatMap((h) => h.keys).filter((k) => !keep.has(k)));
  return TRUST;
}
export function trustedEnv(name, { env = process.env, home = os.homedir(), cwd = process.cwd() } = {}) {
  const v = env[name];
  if (v === undefined || v === "") return v;
  try { return untrustedNames({ env, home, cwd }).has(name) ? undefined : v; } catch { return undefined; }
}
// Security-relevant names a settings file set and the hook therefore ignored (for the tamper report).
export const TRUST_ANCHOR_ENV = ["MOORAI_BREAKGLASS_PUBKEY", "MOORAI_POLICY_PUBKEY", "MOORAI_OFFLINE_MODE", "MOORAI_OTLP_ENDPOINT", "MOORAI_OTLP_HEADERS"];
// Plus every HOOK_PROCESS_ENV name a settings file sets (whatever the inherited value): the hook cannot
// un-apply NODE_OPTIONS to itself, so these are reported rather than ignored, and kept out of its workers.
export function refusedTrustEnv(opts = {}) {
  const env = opts.env || process.env;
  const anchors = TRUST_ANCHOR_ENV.filter((n) => env[n] !== undefined && env[n] !== "" && trustedEnv(n, opts) === undefined);
  let hookEnv = [];
  try { const u = untrustedNames({ env, home: opts.home || os.homedir(), cwd: opts.cwd || process.cwd() }); hookEnv = HOOK_PROCESS_ENV.filter((n) => u.has(n)); } catch { /* unreadable settings: nothing to report */ }
  return [...anchors, ...hookEnv];
}
// The environment for the hook's own detached workers (the same script, re-run): the parent's, minus
// NODE_OPTIONS / NODE_PATH when a settings file set them, so a planted --require does not follow the hook
// into every worker it starts. PATH is left alone: the workers start node by absolute path and call no
// bare tool name that matters, and stripping it would break the shell tools a user legitimately added.
export function workerEnv(env = process.env) {
  const out = { ...env };
  try {
    const u = untrustedNames({ env, home: os.homedir(), cwd: process.cwd() });
    for (const n of ["NODE_OPTIONS", "NODE_PATH"]) if (u.has(n)) for (const k of Object.keys(out)) if (k.toLowerCase() === n.toLowerCase()) delete out[k];
  } catch { /* keep the parent's */ }
  return out;
}
export function _resetEnvTrustForTests() { TRUST = null; }

const clean = (v) => (typeof v === "string" ? v.trim() : "");
function validUrl(v) {
  try { const u = new URL(v); return u.protocol === "http:" || u.protocol === "https:" ? v.replace(/\/+$/, "") : ""; } catch { return ""; }
}
// A workload name: printable, no whitespace runs, bounded. It is hashed into the actor and pseudonymised
// by the console, so this only keeps it stable and sane, not secret.
export function normalizeServiceId(v) {
  const s = clean(v).replace(/[\u0000-\u001f\u007f]/g, "").replace(/\s+/g, "-");
  return s.slice(0, MAX_ID);
}
export function githubServiceId(env) {
  if (env.GITHUB_ACTIONS !== "true" || !clean(env.GITHUB_REPOSITORY)) return "";
  return normalizeServiceId(`github:${clean(env.GITHUB_REPOSITORY)}:${clean(env.GITHUB_WORKFLOW) || "workflow"}:${clean(env.GITHUB_JOB) || "job"}`);
}

// Pure resolution. Every input is injectable; serverMode() below supplies the real ones.
//   system   parsed /etc/moorai/config.json (root-owned) or null
//   user     readUserConfig() result or null
//   hits     settingsEnvHits() result
//   managed  managedEnvKeys() result
export function resolveServerMode({ env = process.env, system = null, user = null, hits = [], managed = [] } = {}) {
  const sys = system || {};
  const refusedNames = new Set(hits.flatMap((h) => h.keys).filter((k) => !managed.includes(k)));
  const envVal = (name) => (refusedNames.has(name) ? "" : clean(env[name]));
  const envMode = envVal(ENV.mode).toLowerCase();
  const requestedBy = sys.mode === "server" ? "system" : envMode === "server" ? "env" : null;
  const tamper = hits.map((h) => ({ file: h.file, keys: h.keys.filter((k) => refusedNames.has(k)) })).filter((h) => h.keys.length);
  if (!requestedBy) return { active: false, requestedBy: null, tamper, refused: [...refusedNames].sort() };

  const u = (user && user.data) || {};
  const sources = {};
  const pick = (key, envName, valid = clean) => {
    const cands = [["system", sys[key]], ["env", envVal(envName)], ["file", u[key]]];
    for (const [src, raw] of cands) {
      const v = valid(typeof raw === "string" ? raw : "");
      if (v) { sources[key] = src; return v; }
    }
    return "";
  };
  let serverUrl = pick("serverUrl", ENV.serverUrl, validUrl);
  if (!serverUrl) { const legacy = validUrl(clean(refusedNames.has("MoorAI_SERVER") ? "" : env.MoorAI_SERVER)); serverUrl = legacy || DEFAULTS.serverUrl; sources.serverUrl = legacy ? "env-legacy" : "default"; }
  let tenant = pick("tenant", ENV.tenant);
  if (!tenant) { const legacy = clean(refusedNames.has("MoorAI_TENANT") ? "" : env.MoorAI_TENANT); tenant = legacy || DEFAULTS.tenant; sources.tenant = legacy ? "env-legacy" : "default"; }
  const installToken = pick("installToken", ENV.installToken);
  if (!installToken) sources.installToken = "none";

  let serviceId = pick("serviceId", ENV.serviceId, normalizeServiceId);
  let serviceIdSource = sources.serviceId || "";
  if (!serviceId) {
    const ghRefused = GITHUB_ID_ENV.some((k) => refusedNames.has(k));
    const gh = ghRefused ? "" : githubServiceId(env);
    serviceId = gh || "unnamed";
    serviceIdSource = gh ? "github-actions" : "unnamed";
  }

  // Cloud agent fields. workloadId: system > env. oidc: system > env, and only with a workload id. cloudHost:
  // system > env > detected: Claude Code's cloud sessions carry CLAUDE_CODE_REMOTE=true ("the session VM's
  // environment carries that variable as `true`, it's never `true` locally", code.claude.com/docs/en/
  // cloud-environments). That variable is not a MOORAI_* name, so a settings file can set it; it only labels
  // the heartbeat and decides nothing. The attestation is read from the root-owned file only: the setup step
  // records "github-oidc" there next to the token it minted; any other token in force reads "static-token".
  const workloadId = pick("workloadId", ENV.workloadId, (v) => (WORKLOAD_ID_RE.test(v) ? v : ""));
  const oidcRaw = pick("oidc", ENV.oidc, (v) => (OIDC_PROVIDERS.includes(v.toLowerCase()) ? v.toLowerCase() : ""));
  const oidc = workloadId ? oidcRaw : "";
  let cloudHost = pick("cloudHost", ENV.cloudHost, (v) => (CLOUD_HOSTS.includes(v) ? v : ""));
  if (!cloudHost && clean(env.CLAUDE_CODE_REMOTE) === "true") { cloudHost = "claude-code-web"; sources.cloudHost = "detected"; }
  const attestation = sys.workloadAttestation === "github-oidc" && sources.installToken === "system" && WORKLOAD_TOKEN_RE.test(installToken) ? "github-oidc" : "static-token";

  const sysAsk = HEADLESS_MODES.includes(sys.headlessAsk) ? sys.headlessAsk : "";
  const envAsk = envVal(ENV.headlessAsk).toLowerCase();
  const headless = { system: sysAsk, envDeny: envAsk === "deny", envRefused: envAsk !== "" && envAsk !== "deny" };

  return {
    active: true,
    requestedBy,
    config: { serverUrl, tenant, installToken },
    sources,
    serviceId,
    serviceIdSource,
    headless,
    workloadId,
    oidc,
    cloudHost,
    attestation,
    tamper,
    refused: [...refusedNames].sort()
  };
}

// The heartbeat's top-level `cloudAgent` field (CONTRACT-F28 §5.2): { host, attestation } for a cloud
// agent in server mode, null otherwise. Old consoles ignore the field.
export function cloudAgentPosture(sm) {
  if (!sm || !sm.active || !CLOUD_HOSTS.includes(sm.cloudHost)) return null;
  return { host: sm.cloudHost, attestation: WORKLOAD_ATTESTATIONS.includes(sm.attestation) ? sm.attestation : "static-token" };
}

// The one call the process makes, memoised: loadConfig() and the hook both ask, and it must not change
// between them within one invocation.
let MEMO = null;
export function serverMode() {
  if (MEMO) return MEMO;
  const env = process.env;
  const system = systemConfig();
  const wants = (system && system.mode === "server") || clean(env[ENV.mode]).toLowerCase() === "server";
  // Nothing is read beyond one stat on a laptop that never asked for server mode.
  if (!wants) return (MEMO = { active: false, requestedBy: null, tamper: [], refused: [] });
  MEMO = resolveServerMode({ env, system, user: readUserConfig(), hits: settingsEnvHits(), managed: managedEnvKeys() });
  return MEMO;
}
export function _resetServerModeForTests() { MEMO = null; }

// ---- headless ask ----
//
// What the host does with a hook's "ask" when nobody is there, per its own docs:
//   * `claude -p` with no permission host — headless docs, "Turn off permission prompts in unattended
//     runs": "In a `-p` run with no host, these requests are denied either way".
//   * Agent SDK — permissions docs, "How permissions are evaluated": the hook step "can deny the call
//     outright or pass it on", and an unresolved call goes to "your `canUseTool` callback" — application
//     code, which may approve anything. In `bypassPermissions`, "Claude Code approves everything that
//     reaches this step"; the only hook verdict those docs promise in every mode is deny: "a hook deny
//     applies even in `bypassPermissions` mode".
// So an "ask" in a headless run is at best a denial without MoorAI's reason and at worst an approval by
// code. Server mode makes it explicit: deny (default), or allow-with-report when a trusted source says so.
export function headlessAskMode(sm, policy) {
  if (!sm || !sm.active) return { mode: "ask", source: "interactive" };
  if (sm.headless.envDeny) return { mode: "deny", source: "env" };
  if (sm.headless.system) return { mode: sm.headless.system, source: "system" };
  const p = policy && HEADLESS_MODES.includes(policy.headlessAsk) ? policy.headlessAsk : "";
  if (p) return { mode: p, source: "policy" };
  return { mode: "deny", source: "default" };
}

export const HEADLESS_NOTE = "held for approval, but this is a headless run (MoorAI server mode) and no approver exists";

// decision/reason are what emit() was about to send. Returns what it should send instead, plus one
// content-free alert recording that an approval was settled without a human.
export function settleHeadlessAsk(sm, policy, { decision, reason, tool = "", permissionMode = "" }) {
  if (!sm || !sm.active || decision !== "ask") return { decision, reason, alert: null };
  const { mode, source } = headlessAskMode(sm, policy);
  // emit() reasons start "needs justification …" or, from the Bash branch, "blocked via Bash — …" even
  // for an ask; both verbs are replaced, and the sign-off marker with them (nothing will sign off).
  const rest = String(reason || "").replace(/^(?:needs justification|blocked)\s*/, "").replace(/ \(needs sign-off\)/g, "").trim();
  const pm = typeof permissionMode === "string" ? permissionMode.slice(0, 32) : "";
  const base = { threatId: 0, stage: "policy", tool: `hook:${tool}`, headlessAsk: { mode, source }, ...(pm ? { permissionMode: pm } : {}) };
  if (mode === "allow-with-report") {
    return { decision: "allow", reason: rest, alert: { ...base, category: "Headless approval released (allow-with-report)", riskLevel: "High", contentHash: "headless-ask:allow" } };
  }
  return {
    decision: "deny",
    reason: `denied ${rest ? `${rest} — ` : ""}${HEADLESS_NOTE}. Do not retry; an operator can allow it in the MoorAI policy`,
    alert: { ...base, category: "Headless approval denied (no approver)", riskLevel: "Blocked", contentHash: "headless-ask:deny" }
  };
}

// A host that has no approver even outside server mode (the MCP gateway answers an MCP client, not a
// person): an "ask" it forwarded would simply run. Settled like a headless ask — deny, unless policy
// headlessAsk is "allow-with-report" — with its own note. In server mode, settleHeadlessAsk as is.
export const NO_APPROVER_NOTE = "held for approval, but this host has no approver to ask";
export function settleNoApproverAsk(sm, policy, args) {
  if (sm && sm.active) return settleHeadlessAsk(sm, policy, args);
  const r = settleHeadlessAsk({ active: true, headless: { envDeny: false, system: "" } }, policy, args);
  return r.decision === "deny" ? { ...r, reason: r.reason.replace(HEADLESS_NOTE, NO_APPROVER_NOTE) } : r;
}

// Claude Code's bypass mode (--dangerously-skip-permissions, permission_mode "bypassPermissions") skips
// every permission prompt, so a PreToolUse "ask" is never shown and the call simply runs (measured live:
// a #55 "ask" on a credentials read let the read through). Like a headless ask, nobody will approve it:
// the caller (an enrolled, enforcing device; server mode settles its own asks first) denies instead.
export const BYPASS_NOTE = "held for approval, but permission prompts are bypassed (bypassPermissions) so no one would see it";
export function settleBypassAsk({ decision, reason, tool = "", permissionMode = "" }) {
  if (decision !== "ask" || permissionMode !== "bypassPermissions") return { decision, reason, alert: null };
  const rest = String(reason || "").replace(/^(?:needs justification|blocked)\s*/, "").replace(/ \(needs sign-off\)/g, "").trim();
  return {
    decision: "deny",
    reason: `denied ${rest ? `${rest} — ` : ""}${BYPASS_NOTE}. Do not retry; run without bypass mode to approve it, or an operator can allow it in the MoorAI policy`,
    alert: { threatId: 0, stage: "policy", tool: `hook:${tool}`, permissionMode: "bypassPermissions", category: "Approval denied (permission prompts bypassed)", riskLevel: "Blocked", contentHash: "bypass-ask:deny" }
  };
}

// ---- service identity ----
//
// The console-facing pair. `user` is one constant for every workload, so all of a tenant's workloads
// share one `usr-` pseudonym (a filter for "services"); `device` carries the workload name, so each
// workload keeps one `dev-` pseudonym across deploys and runs. The caller derives `actor` from this pair
// with actorHash, exactly as it does from user@host on a laptop — same key, same keyed hash.
export const SERVICE_USER = "service";
export function serviceWho(sm) {
  return { user: SERVICE_USER, device: `svc:${sm.serviceId}` };
}

// Content-free tamper alert: the refused NAMES and how many files set them, never a value. Raised even
// when the refusal leaves server mode off (a settings file asked for MOORAI_MODE): only reachable when the
// hook's environment asks for server mode at all, so a laptop that never does is unaffected.
export function tamperAlert(sm) {
  if (!sm || !sm.tamper || !sm.tamper.length) return null;
  const names = [...new Set(sm.tamper.flatMap((t) => t.keys))].sort();
  return { threatId: 0, category: "Server-mode configuration refused (set by a settings file)", riskLevel: "Critical", stage: "policy", tool: "hook:policy", contentHash: `server-env-tamper:${names.join(".")}`, refusedEnv: names, settingsFiles: sm.tamper.length };
}

// ---- workload identity (the `workload` object on alerts) ----
//
// Infrastructure identifiers a SIEM joins MoorAI verdicts with host-sensor events on: the container id,
// the Kubernetes pod / namespace / node, and the pid of the agent process the verdict is about. Every
// field is optional and omitted when unknown: nothing is guessed, and a value that fails its format check
// is dropped, not truncated. Sent only in server mode (the hook) or by the sidecar and the gateway; a
// laptop never sends it.
//
// CONTAINER ID. /proc/self/cgroup first. proc(5): "Each line in the file has the form
// hierarchy-ID:controller-list:cgroup-path" and, for cgroup v2, "the hierarchy-ID is 0 and the
// controller-list is empty". The runtime names the container's cgroup after its id: docker
// (`/docker/<id>`, systemd driver `docker-<id>.scope`), containerd under Kubernetes
// (`cri-containerd-<id>.scope`, cgroupfs driver `/kubepods/<qos>/pod<uid>/<id>`), CRI-O
// (`crio-<id>.scope`), podman (`libpod-<id>.scope`). On cgroup v2 a container usually gets a private
// cgroup namespace and the file reads `0::/` (MEASURED: Docker 29.6.1, node:22-slim), so the fallback
// is /proc/self/mountinfo, whose fourth field is the mount's root within its filesystem: docker
// bind-mounts /etc/hostname, /etc/hosts and /etc/resolv.conf from `.../containers/<id>/` (MEASURED:
// `/docker/containers/<id>/hostname /etc/hostname`), CRI-O from `.../overlay-containers/<id>/userdata/`.
// Only those three mount points are read, and a containerd `sandboxes/<id>` path is the pod's pause
// sandbox, not this container, so it never matches. Only a full 64-hex id is taken from either file.
// Those three files belong to the network namespace, so a container that joins another's
// (compose `network_mode: "service:agent"`) reads the AGENT container's id there (MEASURED: compose demo,
// alert containerId == `docker inspect` id of the agent, not of the sidecar) — the container the verdict
// is about. Under Kubernetes on cgroup v2 with a private cgroup namespace neither file is expected to
// name a container (kubelet's /etc/hosts, the sandbox's hostname; not measured on a cluster), so the
// pod / namespace / node below are the join keys there.
//
// KUBERNETES. MOORAI_K8S_POD / MOORAI_K8S_NAMESPACE / MOORAI_K8S_NODE, set by the pod spec from the
// downward API (metadata.name, metadata.namespace, spec.nodeName; examples/serve/k8s-sidecar.yaml).
// They are MOORAI_* names, so a settings file setting one for the hook is refused like every other
// (pass the resolved server mode's `refused` list).
export const WORKLOAD_ENV = { pod: "MOORAI_K8S_POD", namespace: "MOORAI_K8S_NAMESPACE", node: "MOORAI_K8S_NODE" };
const HEX64 = /^[0-9a-f]{64}$/;
const CGROUP_LEAF = /^(?:(?:docker|cri-containerd|crio|libpod)-)?([0-9a-f]{64})(?:\.scope)?$/;
const MOUNT_ID = /(?:^|\/)(?:containers\/([0-9a-f]{64})\/|overlay-containers\/([0-9a-f]{64})\/userdata\/)/;
const ID_MOUNTPOINTS = new Set(["/etc/hostname", "/etc/hosts", "/etc/resolv.conf"]);
const K8S_NAME = /^[a-z0-9.-]{1,253}$/;
const MAX_PID = 2 ** 32;

export function containerIdFromCgroup(text) {
  for (const line of String(text || "").split("\n")) {
    const parts = line.split(":");
    if (parts.length < 3) continue;
    const segs = parts.slice(2).join(":").split("/").filter(Boolean);
    for (let i = segs.length - 1; i >= 0; i--) {
      const m = CGROUP_LEAF.exec(segs[i]);
      if (m) return m[1];
    }
  }
  return "";
}
export function containerIdFromMountinfo(text) {
  for (const line of String(text || "").split("\n")) {
    const f = line.split(" ");
    if (f.length < 5 || !ID_MOUNTPOINTS.has(f[4])) continue;
    const m = MOUNT_ID.exec(f[3]);
    if (m) return m[1] || m[2];
  }
  return "";
}

// Keeps the contract's keys whose values pass the format check; returns null when none is left.
export function cleanWorkload(w) {
  if (!w || typeof w !== "object" || Array.isArray(w)) return null;
  const out = {};
  if (typeof w.containerId === "string" && /^[0-9a-f]{12,64}$/.test(w.containerId)) out.containerId = w.containerId;
  for (const k of ["pod", "namespace", "node"]) if (typeof w[k] === "string" && K8S_NAME.test(w[k])) out[k] = w[k];
  if (Number.isSafeInteger(w.pid) && w.pid > 0 && w.pid < MAX_PID) out.pid = w.pid;
  return Object.keys(out).length ? out : null;
}

// pid: the agent process the verdict is about (the hook passes process.ppid); the sidecar and the gateway
// pass none. refused: env names a settings file set (resolveServerMode().refused) — never read.
export function workloadIdentity({ env = process.env, procRoot = "/proc", pid, refused = [], read = readPlain } = {}) {
  const deny = new Set(refused);
  const val = (name) => (deny.has(name) ? "" : clean(env[name]));
  const containerId = containerIdFromCgroup(read(join(procRoot, "self", "cgroup"))) || containerIdFromMountinfo(read(join(procRoot, "self", "mountinfo")));
  return cleanWorkload({
    containerId: HEX64.test(containerId) ? containerId : "",
    pod: val(WORKLOAD_ENV.pod),
    namespace: val(WORKLOAD_ENV.namespace),
    node: val(WORKLOAD_ENV.node),
    pid
  });
}
