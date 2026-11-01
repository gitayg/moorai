#!/usr/bin/env node
// moorai-cloud-setup: bind MoorAI's server mode inside a cloud coding agent's setup step (cli/cloud-setup.mjs).
//
//   moorai-cloud-setup <copilot-coding-agent|claude-code-web|codex-cloud> [--install-dir DIR] [--root DIR]
//   moorai-cloud-setup <host> --print-hooks [--install-dir DIR]     # the host's hook registration (JSON)
//
// Reads MOORAI_SERVER_URL, MOORAI_TENANT and MOORAI_INSTALL_TOKEN (or MOORAI_WORKLOAD_ID with
// MOORAI_OIDC=github) and optionally MOORAI_SERVICE_ID. Writes /etc/moorai/config.json and the hook
// wrappers, so it runs as root (GitHub-hosted runners: `sudo -E`). Exit 0 done, 2 usage or missing binding,
// 3 host blocked, 4 token exchange refused. The token is printed only as a fingerprint.
import { planCloudSetup, applyPlan, hooksFor, CLOUD_SETUP_HOSTS, DEFAULT_INSTALL_DIR } from "./cloud-setup.mjs";

function arg(argv, name) { const i = argv.indexOf(name); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : null; }
const fail = (code, msg) => { process.stderr.write(`moorai-cloud-setup: ${msg}\n`); process.exit(code); };

async function main() {
  const argv = process.argv.slice(2);
  const host = argv[0];
  if (!host || host === "--help" || host === "-h") {
    process.stdout.write(`usage: moorai-cloud-setup <${Object.keys(CLOUD_SETUP_HOSTS).join("|")}> [--install-dir DIR] [--root DIR] [--print-hooks]\n`);
    return process.exit(host ? 0 : 2);
  }
  const def = CLOUD_SETUP_HOSTS[host];
  if (!def) fail(2, `unknown host '${host}' (known: ${Object.keys(CLOUD_SETUP_HOSTS).join(", ")})`);
  if (def.blocked) fail(3, `${def.label} is blocked: ${def.blocked}`);
  const installDir = arg(argv, "--install-dir") || DEFAULT_INSTALL_DIR;
  if (argv.includes("--print-hooks")) { process.stdout.write(hooksFor(host, installDir).content); return; }
  const root = arg(argv, "--root") || "";
  if (!root && typeof process.getuid === "function" && process.getuid() !== 0) fail(2, "run as root (it writes /etc/moorai/config.json); on a GitHub-hosted runner use `sudo -E`");

  const plan = await planCloudSetup({ host, env: process.env, installDir });
  if (!plan.ok) fail(plan.exitCode, plan.blocked ? `${def.label} is blocked: ${plan.reason}` : plan.error);
  const written = applyPlan(plan, { root });
  const s = plan.summary;
  process.stdout.write([
    `MoorAI server mode bound for ${def.label}`,
    `  console ${s.serverUrl}  tenant ${s.tenant}  token ${s.token}  attestation ${s.attestation}${s.workloadId ? `  workload ${s.workloadId}` : ""}${s.expiresAt ? `  expires ${s.expiresAt}` : ""}`,
    ...written.map((p) => `  wrote ${root ? `${root}${p}` : p}`),
    `  hook registration: ${plan.hooks.target} (moorai-cloud-setup ${host} --print-hooks)`,
    ""
  ].join("\n"));
}

main().catch((e) => fail(1, e && e.message ? e.message : "failed"));
