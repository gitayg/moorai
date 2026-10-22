# MoorAI in cloud coding agents

Cloud coding agents run in the vendor's VM, not on a device MoorAI is installed on. Where the host gives you a
setup step that runs before the agent and a hook the agent calls before each tool, MoorAI runs there in
server mode: the same policy, the same content-free alerts, under a workload identity. `moorai-cloud-setup`
([`cli/moorai-cloud-setup.mjs`](../../cli/moorai-cloud-setup.mjs)) does the setup-step part.

| Host | Setup step | Pre-tool hook in the cloud session | Status |
|---|---|---|---|
| GitHub Copilot coding agent | `.github/workflows/copilot-setup-steps.yml` | `.github/hooks/*.json`, `preToolUse` | Supported |
| Claude Code cloud sessions (Claude Code on the web) | environment setup script | hooks from server-managed settings or the repository's `.claude/settings.json` | Supported |
| OpenAI Codex cloud | environment setup script | none: command hooks are not run under cloud orchestration | Blocked |

Neither supported host has been run end to end with MoorAI yet: the installer, the hook registration and the
server-mode binding are tested locally against fakes, and no Copilot or Claude Code cloud task has been
watched producing a console alert.

## What the vendors' documentation says

**Copilot coding agent** ([customize the agent environment](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment),
[hooks reference](https://docs.github.com/en/copilot/reference/hooks-configuration)).
The setup job runs in GitHub Actions "before Copilot starts working", must be named `copilot-setup-steps`,
and must be on the default branch. Repository hooks in `.github/hooks/*.json` run in the agent's cloud
environment, and `preToolUse` fires there. Command `preToolUse` hooks fail closed on errors, a command hook
timeout fails open, and an `ask` answer is treated as `deny` because no user can answer. GitHub's own
Copilot MCP examples put `id-token: write` in the setup job, which is what the OIDC option below uses. The
firewall applies to the agent's Bash tool, not to setup-step processes; whether it applies to hook processes
is not stated, so add the console host to the custom allowlist.

**Claude Code cloud sessions** ([cloud environments](https://code.claude.com/docs/en/cloud-environments)).
The setup script runs before Claude Code launches, as root on Ubuntu 24.04, and its result is cached as a
filesystem snapshot (rebuilt about every seven days or when the script changes). A failing script stops the
session from starting. Hooks run from the organization's server-managed settings and, in a single-repository
session outside a project thread, from the repository; those are the only hook sources the page lists for
Anthropic-hosted environments. Cloud sessions set `CLAUDE_CODE_REMOTE=true`, which MoorAI uses to label the
host. Environment variables are readable by anyone who uses the environment, and the console host must be
in the environment's allowed domains (Custom network access).

**Codex cloud** ([cloud environments](https://developers.openai.com/codex/cloud/environments),
[hooks](https://developers.openai.com/codex/hooks)). There is a setup script, and secrets reach the setup
script only. Codex's hooks page says command hooks are not supported with cloud orchestration, even when
tools execute locally; only admin-managed `mcp_tool` hooks run there. MoorAI's pre-tool hook therefore cannot
see a Codex cloud task's tool calls, and `moorai-cloud-setup codex-cloud` refuses (exit 3) without writing
anything. Coverage evidence for Codex cloud has to come from the provider's compliance API instead.

## The token: a workload token, scoped

Create a workload in the console (host, label, attestation). Either:

- **Static token**: the console shows an `mwt_…` token once (expiry required, 90 days by default). Put it in
  the host's secret store as `MOORAI_INSTALL_TOKEN`.
- **GitHub OIDC** (Copilot coding agent): set `MOORAI_WORKLOAD_ID=wkl-…` and `MOORAI_OIDC=github`, and give
  the setup job `id-token: write`. The installer requests the job's GitHub ID token with audience
  `moorai:<tenant>` and exchanges it at `POST /api/workload/token` for a short-lived `mwt_…` token
  ([`cli/workload-token.mjs`](../../cli/workload-token.mjs)). The console checks the issuer, audience, expiry
  and the workload's allowed `repository` / `ref` claims.

A console with workload identity accepts an `mwt_` token only for policy reads and telemetry (alerts, posture, actions, token
usage, approval status); installers, claim, signup and device-key registration answer 403. The token is
printed only as a sha256 fingerprint. An OIDC-minted token lives as long as the workload's `tokenTtlSec`
(at most 6 hours); a session that runs longer stops reaching the console, and its alerts wait in the outbox.

## Copilot coding agent

1. Create the `copilot` environment's variables `MOORAI_SERVER_URL`, `MOORAI_TENANT` (and
   `MOORAI_WORKLOAD_ID` for OIDC) or the secret `MOORAI_INSTALL_TOKEN`.
2. Copy [`copilot-setup-steps.yml`](copilot-setup-steps.yml) to `.github/workflows/copilot-setup-steps.yml`
   on the default branch.
3. Copy [`copilot-hooks.json`](copilot-hooks.json) to `.github/hooks/moorai.json`. It calls
   `/opt/moorai/bin/moorai-agent-hook copilot`, a wrapper the setup step writes. Without the setup step the
   wrapper is missing, the command fails, and Copilot denies every tool call (command `preToolUse` hooks
   fail closed).
4. Add the console host to Settings > Copilot > Internet access > Custom allowlist.

## Claude Code cloud sessions

1. In the environment's settings: environment variables `MOORAI_SERVER_URL`, `MOORAI_TENANT`,
   `MOORAI_INSTALL_TOKEN` (a static workload token); network access Custom with the console host added;
   setup script [`claude-code-web-setup.sh`](claude-code-web-setup.sh).
2. Put [`claude-code-web-hooks.json`](claude-code-web-hooks.json) (the output of
   `moorai-cloud-setup claude-code-web --print-hooks`) in the organization's server-managed settings, where
   the agent cannot change it, or in the repository's `.claude/settings.json`. Server-managed settings also
   reach laptops: there `/opt/moorai/bin/moorai-hook` does not exist and Claude Code treats the failed
   command as a non-blocking hook error.

## What the installer writes

`moorai-cloud-setup <copilot-coding-agent|claude-code-web> --install-dir /opt/moorai`, run as root:

- `/etc/moorai/config.json` (root-owned, 0644): `mode: "server"`, the console URL, tenant, token,
  `cloudHost`, `workloadAttestation` (`github-oidc` or `static-token`), and `workloadId` / `serviceId` when
  set. This is server mode's highest-precedence source.
- `/opt/moorai/bin/moorai-hook` and `/opt/moorai/bin/moorai-agent-hook`: wrappers that run this machine's
  node by absolute path, so the hook registration names one fixed path.

The heartbeat then carries `cloudAgent: { host, attestation }`.

**Scope.** In these VMs the agent runs as root (Claude Code) or as a user with passwordless sudo
(GitHub-hosted runners), so it can read and change MoorAI's files there: the root-owned file is not a tamper
boundary in a cloud VM. Hooks from server-managed settings cannot be changed by the agent; a repository hook
file is in the agent's working tree. The scoped token bounds what a copied token can do.
