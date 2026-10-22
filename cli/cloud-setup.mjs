// Setup-step installer for cloud coding agents (F17, CONTRACT-F28 §5). Run from the host's own
// environment-setup step, before the agent starts, it binds MoorAI's server mode to the console and prints
// the host's hook registration. The CLI is cli/moorai-cloud-setup.mjs; the walkthrough is
// examples/cloud/README.md.
//
// What each host's documentation allows (quoted in examples/cloud/README.md):
//
//   copilot-coding-agent  SUPPORTED. `.github/workflows/copilot-setup-steps.yml`: "The steps in this job will
//                         be executed in GitHub Actions before Copilot starts working". Repository hooks in
//                         `.github/hooks/*.json` run under Copilot cloud agent, `preToolUse` fires there,
//                         "Command `preToolUse` hooks are fail-closed on errors" and "Under cloud agent,
//                         `"ask"` is treated as `"deny"`". MoorAI's Copilot adapter (cli/agent-hooks/
//                         copilot.mjs) is the hook; the setup step installs it and writes the binding.
//   claude-code-web       SUPPORTED. A cloud environment's setup script "runs when a new cloud session
//                         starts, before Claude Code launches" and "Scripts run as root on Ubuntu 24.04".
//                         Hooks run from "your organization's server-managed settings and, outside a project
//                         thread, from the repository"; a hooks block written on the VM by the setup script
//                         is not among the sources that page lists, so the registration goes in
//                         server-managed settings (or the repository's .claude/settings.json).
//   codex-cloud           BLOCKED. Codex cloud environments run a setup script, but Codex's hooks page says
//                         command hooks are "not supported with cloud orchestration, even when tools execute
//                         locally"; only admin-managed `mcp_tool` hooks run there. No MoorAI hook can see a
//                         Codex cloud task's tool calls, so this installer refuses (exit 3) and writes nothing.
//
// WHAT IT WRITES (as root; `--root DIR` prefixes every path, for tests and image builds):
//   /etc/moorai/config.json            {"mode":"server", serverUrl, tenant, installToken, cloudHost,
//                                      workloadAttestation, workloadId?, serviceId?} — root-owned, 0644, the
//                                      highest-precedence server-mode source (cli/server-mode.mjs).
//   <installDir>/bin/moorai-hook       sh wrappers that exec this machine's node by absolute path, so the
//   <installDir>/bin/moorai-agent-hook hook registration (written before the VM exists) names one fixed path.
//
// THE TOKEN. Either a static workload token (mwt_…, admin-issued, shown once) or any install token in
// MOORAI_INSTALL_TOKEN, or, with MOORAI_WORKLOAD_ID + MOORAI_OIDC=github, a token minted from the job's
// GitHub OIDC ID token (cli/workload-token.mjs). Printed only as a sha256 fingerprint.
//
// SCOPE, stated plainly. On these hosts the agent runs as root (Claude Code cloud sessions) or as a user with
// passwordless sudo (GitHub-hosted runners), so it can read and change the MoorAI binding and wrappers; the
// root-owned file is not a tamper boundary there. A workload token is scoped to telemetry and policy reads,
// which bounds what a copied token can do.
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, renameSync, chmodSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { install as copilotInstall } from "./agent-hooks/copilot.mjs";
import { normalizeServiceId, WORKLOAD_ID_RE } from "./server-mode.mjs";
import { mintWorkloadToken } from "./workload-token.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_INSTALL_DIR = REPO;
export const SYSTEM_CONFIG = "/etc/moorai/config.json";

export const CLOUD_SETUP_HOSTS = Object.freeze({
  "copilot-coding-agent": { label: "GitHub Copilot coding agent", hooks: "copilot" },
  "claude-code-web": { label: "Claude Code cloud sessions (Claude Code on the web)", hooks: "claude" },
  "codex-cloud": {
    label: "OpenAI Codex cloud",
    blocked: "Codex cloud environments run a setup script, but Codex's hooks documentation states that command hooks are not supported with cloud orchestration (only admin-managed mcp_tool hooks run there), so no MoorAI hook can see a Codex cloud task's tool calls. Nothing was written. Use a provider compliance-API connector for coverage evidence instead."
  }
});

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const fingerprint = (t) => `sha256:${createHash("sha256").update(String(t)).digest("hex").slice(0, 12)}`;
const clean = (v) => (typeof v === "string" ? v.trim() : "");
function validUrl(v) {
  try { const u = new URL(v); return u.protocol === "http:" || u.protocol === "https:" ? v.replace(/\/+$/, "") : ""; } catch { return ""; }
}

function wrapper(nodePath, script) {
  return `#!/bin/sh\nexec ${shq(nodePath)} ${shq(script)} "$@"\n`;
}

// The host's hook registration, calling the wrappers under <installDir>/bin. Produced by MoorAI's own
// installers (cli/moorai-hook.mjs install, the Copilot adapter's install) against a throwaway HOME, so the
// event and matcher set always match the hook this checkout ships.
export function hooksFor(host, installDir = DEFAULT_INSTALL_DIR) {
  const kind = CLOUD_SETUP_HOSTS[host] && CLOUD_SETUP_HOSTS[host].hooks;
  const bin = `${installDir.replace(/\/+$/, "")}/bin`;
  const home = mkdtempSync(join(tmpdir(), "moorai-cloud-hooks-"));
  try {
    if (kind === "copilot") {
      const file = copilotInstall({ home, command: `${bin}/moorai-agent-hook copilot` });
      const cfg = JSON.parse(readFileSync(file, "utf8"));
      for (const entries of Object.values(cfg.hooks || {})) for (const e of entries) delete e.powershell;
      return { target: ".github/hooks/moorai.json", content: JSON.stringify(cfg, null, 2) + "\n" };
    }
    if (kind === "claude") {
      const r = spawnSync(process.execPath, [join(REPO, "cli", "moorai-hook.mjs"), "install"], { env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home }, encoding: "utf8" });
      if (r.status !== 0) throw new Error("moorai-hook install failed");
      const hooks = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8")).hooks || {};
      const own = /^"[^"]*" "[^"]*[/\\]cli[/\\]moorai-hook\.mjs"(.*)$/;
      for (const entries of Object.values(hooks)) for (const e of entries) for (const h of e.hooks || []) {
        const m = own.exec(String(h.command || ""));
        if (m) h.command = `${bin}/moorai-hook${m[1]}`;
      }
      return { target: "server-managed settings (or the repository's .claude/settings.json)", content: JSON.stringify({ hooks }, null, 2) + "\n" };
    }
    return null;
  } finally { rmSync(home, { recursive: true, force: true }); }
}

// → { ok: false, exitCode, error | (blocked, reason) } or
//   { ok: true, files: [{ path, content, mode }], hooks: { target, content }, summary }
export async function planCloudSetup({ host, env = process.env, installDir = DEFAULT_INSTALL_DIR, nodePath = process.execPath, fetchImpl = fetch } = {}) {
  const def = Object.prototype.hasOwnProperty.call(CLOUD_SETUP_HOSTS, host) ? CLOUD_SETUP_HOSTS[host] : null;
  if (!def) return { ok: false, exitCode: 2, error: `unknown host '${host}' (known: ${Object.keys(CLOUD_SETUP_HOSTS).join(", ")})` };
  if (def.blocked) return { ok: false, exitCode: 3, blocked: true, reason: def.blocked };

  const serverUrl = validUrl(clean(env.MOORAI_SERVER_URL));
  if (!serverUrl) return { ok: false, exitCode: 2, error: "MOORAI_SERVER_URL is not set to an http(s) console URL" };
  const tenant = clean(env.MOORAI_TENANT);
  if (!tenant) return { ok: false, exitCode: 2, error: "MOORAI_TENANT is not set" };
  const workloadId = clean(env.MOORAI_WORKLOAD_ID);
  if (workloadId && !WORKLOAD_ID_RE.test(workloadId)) return { ok: false, exitCode: 2, error: "MOORAI_WORKLOAD_ID is not wkl- followed by 12 hex characters" };
  const oidc = clean(env.MOORAI_OIDC).toLowerCase();

  let installToken = "", attestation = "static-token", expiresAt = null;
  if (oidc === "github" && workloadId) {
    try { const m = await mintWorkloadToken({ env, serverUrl, tenant, workloadId, fetchImpl }); installToken = m.token; attestation = m.attestation; expiresAt = m.expiresAt; }
    catch (e) { return { ok: false, exitCode: 4, error: `workload token exchange failed: ${e && e.code ? e.code : "error"}: ${e && e.message ? e.message : ""}` }; }
  } else {
    installToken = clean(env.MOORAI_INSTALL_TOKEN);
    if (!installToken) return { ok: false, exitCode: 2, error: "no token: set MOORAI_INSTALL_TOKEN (a static workload token) or MOORAI_WORKLOAD_ID with MOORAI_OIDC=github" };
  }

  const serviceId = normalizeServiceId(env.MOORAI_SERVICE_ID || "");
  const cfg = { mode: "server", serverUrl, tenant, installToken, cloudHost: host, workloadAttestation: attestation, ...(workloadId ? { workloadId } : {}), ...(serviceId ? { serviceId } : {}) };
  const dir = installDir.replace(/\/+$/, "");
  const files = [
    { path: SYSTEM_CONFIG, content: JSON.stringify(cfg, null, 2) + "\n", mode: 0o644 },
    { path: `${dir}/bin/moorai-hook`, content: wrapper(nodePath, `${dir}/cli/moorai-hook.mjs`), mode: 0o755 },
    { path: `${dir}/bin/moorai-agent-hook`, content: wrapper(nodePath, `${dir}/cli/moorai-agent-hook.mjs`), mode: 0o755 }
  ];
  const summary = { host, serverUrl, tenant, attestation, token: fingerprint(installToken), ...(workloadId ? { workloadId } : {}), ...(expiresAt ? { expiresAt } : {}) };
  return { ok: true, files, hooks: hooksFor(host, dir), summary };
}

// Writes each planned file (atomic rename) under `root` ("" for the real filesystem). → the paths written.
export function applyPlan(plan, { root = "" } = {}) {
  const out = [];
  for (const f of plan.files || []) {
    const target = root ? join(root, f.path) : f.path;
    mkdirSync(dirname(target), { recursive: true });
    const tmp = `${target}.moorai-${process.pid}.tmp`;
    writeFileSync(tmp, f.content, { mode: f.mode });
    chmodSync(tmp, f.mode);
    renameSync(tmp, target);
    out.push(f.path);
  }
  return out;
}
