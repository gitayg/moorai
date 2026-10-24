# MoorAI — Capability Spec

**Version:** 0.6 · **Status:** architecture locked, refining capabilities · **UI language:** English (LTR)

## What it is

MoorAI is a **native desktop "Managed AI Host"** for office workers, paired with a **central
server** for policy and visibility. The employee does their AI work *inside* MoorAI — a native
app with an embedded, managed webview — so the host sees every prompt, response, paste, and
upload natively (no browser extension, no DOM hacks). It detects the 82-threat matrix in real
time, **coaches the employee** with the matrix's guidance, and **reports redacted alerts** to a
central server so the security team has visibility.

**Posture: adoption is voluntary; enforcement is policy-driven.** Adoption is opt-in
(self-install), but MoorAI does block. `threatActionFor` in [`cli/hook-core.mjs`](../cli/hook-core.mjs)
resolves every threat to one of `notify` · `justify` · `block` · `kill` (plus `mask` for data-tier
threats, where the caller can rewrite the payload), and
[`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs) turns those into real Claude Code `allow`/`ask`/`deny`
verdicts — up to terminating the session outright (`killSession`). The **default is report-first for
everything ambiguous**, but it is no longer report-*only*: an **enrolled** device with no organisation
policy at all now resolves through `BUILTIN_DEFAULT_ACTIONS`, which blocks threats **54** (reverse shell)
and **65** (local secret egress) and halts-for-sign-off on **55, 56, 57, 63, 44, 73**. Six threats — 11, 43,
46, 47, 48, 49 — keep the `justify` they already had from the approval set; everything else still
resolves to `notify`. An **unenrolled** device coaches: same detection, a note with the safer way,
nothing blocked or posted (`data/enforcement.js`). Central distributes
the policy that overrides any of this in either direction. MoorAI's value is
(a) **coaching** the employees who use it, (b) giving the security team **visibility** into AI-usage
risk, and (c) **deterministic prevention** where policy calls for it. Because adoption is voluntary,
it still does not prevent Shadow AI by construction; it reduces risk for those who opt in and
surfaces organization-wide risk signals.

- **Rule-base:** [`data/threats.json`](../data/threats.json) — 82 threats, 17 categories, English.
  Each threat is a rule: `example` = trigger context, `response` = intervention,
  `riskScore = severity × likelihood`.
- **Intervention model:** risk-tiered and policy-driven — `notify` (report) → `justify` (ask) →
  `block` (deny) → `kill` (terminate session), and `mask` (replace the span, let the call proceed) for
  secrets, PII, payment cards and PHI. Report-first by default, blocking when configured.
- **Claude Code install:** `moorai-hook.mjs install` writes the hooks into `~/.claude/settings.json`;
  the Claude Code plugin `moorai@moorai` ([`hooks/hooks.json`](../hooks/hooks.json)) registers the same
  events and matchers. Use one. The plugin copy stands down for any event a live `settings.json` install
  covers and never rewrites `settings.json`; its updates are pinned (`claude plugin update
  moorai@moorai`); under `allowManagedHooksOnly` it runs only when managed `enabledPlugins` force-enables
  it. A marketplace install runs `npm ci --ignore-scripts` in the plugin copy (about 20 MB of desktop-app
  packages the hooks do not use).

## Architecture

### Mental model — one brain, many eyes (don't re-litigate)
The **harness is a brain, not an eye.** It *decides*; it can only decide about wires it is actually
tapped into. Making it smarter never lets it see a wire it isn't connected to. AI activity crosses
**several wires that never converge** at one point on the device:

| Wire | Where it runs | Tap |
|---|---|---|
| Human ↔ AI (chat: prompts, pastes, uploads, responses) | inside the host webview | **Managed Host** — always |
| AI ↔ tools (agent tool-calls: send email, update CRM, delete file) | model backend / remote MCP server — **never crosses the webview** | **MCP gateway (or API/egress proxy)** — when agents act |
| AI outside the host (other browser, native app, phone) | a different process/device | **browser extension** (shipped) for browser AI; no tap for native apps / phones |
| Deepfake call / vishing | a phone line — no data wire | coach-only (no tap possible) |

**Why MCP is needed (conditionally):** agent tool-calls execute on the AI↔tools wire, which does
not pass through the chat webview, so the harness is *blind* to threats 14/22/23/24/25/38/40 no
matter how capable it is. MCP is the **eye on that second wire** (and the only point where a
tool-call can be deterministically blocked *before* it executes). It is **not a second brain** — it
feeds the same harness.

**The trigger:** harness + host is genuinely enough for *conversational* AI. Add the MCP/proxy tap
**only when agentic tool-use is in scope** — hence it shipped in v3, not the MVP.

**Why not just "see everything" from one tap:** no single tap sees everything. A TLS-intercepting
egress proxy still misses on-device/off-network AI and sees raw bytes without in-app context, so it
cannot replace the harness or the MCP gateway. "See everything" reduces to tapping every wire — the
multi-surface suite. The proxy is therefore an **additional** wire, never the only one.

### Local TLS inspection — permitted, opt-in, never the default
**Local TLS inspection is explicitly permitted** as an optional extra layer, offered during
installation and **off unless the user opts in**. It exists to cover the chat/egress surface the
harness and MCP gateway cannot reach — browser AI, cloud AI desktop apps, and any client that
speaks HTTPS without an integration.

The invariant it must satisfy is **content-free egress, not "never decrypt"**:

- Decryption and classification happen **entirely on the device** (Tier-1 regex → Tier-2 local
  model). The plaintext never leaves the machine.
- **Sending content to a third-party API to classify it is forbidden** — that is the line, and it
  is what separates this from a vendor whose "on-device" DLP calls a cloud model to read your
  prompts. On-device inspection with off-device classification is *not* content-free.
- Only the same redacted signal leaves the device as everywhere else: **category · risk level ·
  keyed one-way hash** (HMAC-SHA-256 under the tenant's enrollment token — see
  `cli/content-hash.mjs`; an unkeyed digest of a small-space value like a phone number or an SSN is
  enumerable and would not be one-way in practice).
- The root CA is generated **locally, per device**, never shared or escrowed, and its installation
  is disclosed and reversible. Uninstall removes it.
- Because the interceptor is **open source (MIT)**, this is auditable rather than asserted —
  anyone can verify that no content path leaves the device.

Default posture is unchanged: agent hook + MCP gateway, no certificate, no interception. Local TLS
inspection is the opt-in depth setting for teams that want the extra coverage and accept the
trade-offs (certificate trust, cert-pinning breakage, per-platform network extensions).

### Core principle — MoorAI is a pre-flight egress guard
MoorAI sits **in front of** the agent and reviews what is about to be sent **before** it leaves
for `claude -p` (or any downstream LLM/agent). The review is therefore **local by necessity** —
doing the review *via* a cloud call would itself be the egress we're trying to gate. Local review
(Tier-1 regex → Tier-2 local model) decides allow / redact / abort; only the **approved** prompt
egresses to the agent. This is what dissolves the privacy tension: MoorAI never sends raw content
to the cloud for its own reasoning.

### Components
- **MoorAI Client** — native desktop Managed AI Host (self-installed, voluntary). Hosts the
  managed webview, runs the detection brain locally, coaches the user, reports alerts up.
- **MoorAI Guard (CLI)** — `moorai-guard` wraps `claude -p`: captures the prompt at the submit
  boundary, runs the local review, and forwards only the approved/redacted prompt to the real
  `claude -p`. The runnable proof that the harness reviews egress before the agent. (`npm run guard`.)
  Its policy comes from the same verified loader as the hook and the MCP guard
  (`loadVerifiedPolicy`, [`cli/hook-core.mjs`](../cli/hook-core.mjs)): fetched with `X-Install-Token`,
  enforced only when its signature verifies (anchor, else TOFU pin), cache then last-known-good while the
  console is down, a refused policy reported as `policy:<source>:<status>`. No verified policy: the
  fail-closed default (`data/offline-default.js`) on a fail-closed posture or an admin binding that makes the
  hook fail closed, else no policy. Break-glass is not honoured by the guard. It resolves each finding from
  `threatPolicy` alone (else notify), not `tierPolicy` or the built-in default actions
  ([`test/guard-policy.test.mjs`](../test/guard-policy.test.mjs)).
- **MoorAI Server** — distributes policy + rule-base to clients, ingests redacted alerts, and serves
  the security-team dashboard. The client's default endpoint is `http://localhost:8787`, overridable
  via the `MoorAI_SERVER` env var or `serverUrl` in the config ([`cli/config.mjs`](../cli/config.mjs)).
  The server does not enforce directly — it distributes the **policy** that drives client-side
  enforcement. In server mode (below) the binding comes from a root-owned system file and the
  environment first.
- **In-process and sidecar forms** — `@moorai/agent-sdk` ([`packages/agent-sdk`](../packages/agent-sdk/))
  returns Claude Agent SDK hook callbacks, and `moorai-serve` ([`cli/moorai-serve.mjs`](../cli/moorai-serve.mjs))
  serves the same runtime on localhost for other agent loops; both run the hook's engine and policy in
  one long-lived process (server mode, below).
- **MCP HTTP gateway** — `moorai-mcp-gateway` ([`mcp-gateway/`](../mcp-gateway/README.md)), a local
  reverse proxy that applies the stdio proxy's checks to remote (Streamable HTTP / SSE) MCP servers, plus
  staged JSON-RPC / MCP validation, a response size cap, an opt-in per-client cool-down and declared
  workload profiles, and reports per-server and per-tool daily call counts to the console.
- **Model proxy** — `moorai-model-proxy` ([`model-proxy/`](../model-proxy/README.md)), a loopback proxy
  between an agent's model SDK and the provider (Anthropic Messages, OpenAI Chat Completions, Gemini
  `generateContent` / `streamGenerateContent`) that scans
  what the agent sends, the tool calls the model returns (decided, and judged against the person's task:
  intent alignment) and the text of the model's reply (secrets, personal data, card numbers, the system
  prompt). Report-only by default; `--mode enforce`
  refuses in the provider's own error shape. `--connect-timeout <ms>` (default 10000) bounds a new
  upstream connection (TCP connect, and the TLS handshake for https) and answers 504 with a reason that
  names no host; streaming after the connection is unaffected.
- **Cloud inventory** — `moorai-cloud-inventory` ([`cloud/`](../cloud/README.md)), a read-only,
  content-free inventory of an AWS account's Amazon Bedrock resources, posted to the console.

### Client form factor — native Managed AI Host
- Native desktop app (cross-platform from one codebase). All AI tools are reached through the host.
- In-band inspection points: **pre-submit** (prompt), **post-response** (AI output),
  **upload/drag-drop** (files), **paste/clipboard** (into the prompt box).
- *Companion surfaces (shipped):* a content-free browser extension ([`browser-ext/`](../browser-ext/))
  that guards prompts across 8 GenAI web apps (ChatGPT, Claude, Copilot, Gemini, Perplexity, Mistral,
  DeepSeek, Grok) to **detect** AI use *outside* the host, and an MCP middleware layer
  ([`mcp-proxy/`](../mcp-proxy/)) that guardrails agentic tool-calls.

### Server mode — headless deployments
The Claude Code hook also runs where there is no employee and no desktop app: `claude -p` in CI, the
Claude Code GitHub Action, an Agent SDK service in a container
([`cli/server-mode.mjs`](../cli/server-mode.mjs); examples in
[`examples/server/`](../examples/server/README.md)). On only when the root-owned
`/etc/moorai/config.json` (Windows `%ProgramData%\MoorAI\config.json`) says `"mode": "server"` or
`MOORAI_MODE=server`; off, nothing changes.

- **Binding**, per key: root-owned system file → environment (`MOORAI_SERVER_URL`, `MOORAI_TENANT`,
  `MOORAI_INSTALL_TOKEN`, `MOORAI_SERVICE_ID`) → `~/.moorai/config.json` → defaults. A `MOORAI_*` (or
  `MoorAI_*`, or GitHub workload) name that a user, project or local Claude Code settings file sets in its
  `env` block is refused for these settings and reported as tampering (content-free, names only), because
  a repository's `.claude/settings.json` sets the hook's environment; a managed settings `env` block is
  trusted.
- **Identity**: a workload, not `user@host`. `MOORAI_SERVICE_ID`, else on GitHub Actions
  `github:<repository>:<workflow>:<job>`, else `unnamed`; `service` / `svc:<name>` is hashed into the
  actor as `user@host` is, so one workload keeps one console pseudonym across deploys and runs.
- **Workload identity on alerts.** Alerts from the hook in server mode, `@moorai/agent-sdk`, `moorai-serve`,
  `moorai-mcp-gateway` and `moorai-model-proxy` carry an optional `workload` object (`containerId`, `pod`, `namespace`, `node`,
  `pid`) ([`cli/server-mode.mjs`](../cli/server-mode.mjs) `workloadIdentity`). `containerId` is the
  container the verdict is about: a 64-hex id from the container's cgroup name (Docker, containerd, CRI-O,
  podman), else from the source path of the `/etc/hostname`, `/etc/hosts` or `/etc/resolv.conf` bind mount
  in `/proc/self/mountinfo` (cgroup v2 with a private cgroup namespace reads `0::/`); a containerd
  `sandboxes/` path is the pod sandbox and never matches. Those mounts belong to the network namespace, so
  a sidecar sharing the agent's namespace reports the agent's container. `pod` / `namespace` / `node` come
  only from `MOORAI_K8S_POD` / `_NAMESPACE` / `_NODE` and must match `[a-z0-9.-]{1,253}`; a settings file
  setting one is refused like every other `MOORAI_*` name. `pid` is the agent process: the hook's parent
  pid, or the SDK's own pid in process; the sidecar, the gateway and the model proxy send none. Every field is optional and
  dropped on its own when malformed; the hook outside server mode sends none. The console stores these
  infrastructure ids as-is so a SIEM can join MoorAI verdicts with host and container sensor events.
  **Limits.** `containerId` is detected under Docker (cgroup v2, via `mountinfo`) and absent under
  Kubernetes with containerd, where the container sees only its pod's sandbox id (measured on kind,
  Kubernetes v1.37.0, containerd 2.3.4); there `namespace` + `pod` are the join key. CRI-O unobserved.
- **Enforcement**: server mode counts as management, so the hook enforces without a token (with no token
  it reports nothing and fetches no org policy). A `justify` verdict has no approver, so it is denied
  with a reason saying so and a content-free alert; `headlessAsk: "allow-with-report"` in the system file
  or the org policy allows and reports it instead, and the environment can only say `deny`.
- **Bypass mode** (any enrolled device, not only server mode): under Claude Code's
  `--dangerously-skip-permissions`, a `justify` verdict is denied (`BYPASS_ASK`) instead of asking a prompt
  nobody sees, with a content-free alert; hard denies hold in every mode; unenrolled devices coach.
- **Cloud coding agents** (F17; [`cli/cloud-setup.mjs`](../cli/cloud-setup.mjs),
  [`examples/cloud/`](../examples/cloud/README.md)). `moorai-cloud-setup <host>` runs in the host's setup
  step, as root, and writes `/etc/moorai/config.json` (`mode: "server"`, console, tenant, token,
  `cloudHost`, `workloadAttestation`, optional `workloadId` / `serviceId`; 0644) plus `<installDir>/bin/
  moorai-hook` and `moorai-agent-hook` (sh wrappers that exec this VM's node by absolute path), and prints the
  host's hook registration generated by MoorAI's own installers. Hosts: `copilot-coding-agent` (setup job
  `copilot-setup-steps`; repository hook file `.github/hooks/moorai.json` running the Copilot adapter, which
  gives no verdict where the wrapper is missing unless `GITHUB_ACTIONS=true`, and fails there so Copilot
  denies), `claude-code-web` (environment setup script; hooks in server-managed settings or the repository's
  `.claude/settings.json`), `codex-cloud` refused with exit 3 because Codex's hooks page says command hooks
  are not supported under cloud orchestration. Server mode reads three new names under the existing
  precedence and settings-file refusal: `MOORAI_WORKLOAD_ID` / system `workloadId` (`^wkl-[0-9a-f]{12}$`),
  `MOORAI_OIDC` / system `oidc` (`github` only, and only with a workload id), `MOORAI_CLOUD_HOST` / system
  `cloudHost` (`copilot-coding-agent`, `codex-cloud`, `claude-code-web`, `ci`, `other`), with
  `CLAUDE_CODE_REMOTE=true` detected as `claude-code-web` (a label only). `cloudAgentPosture(sm)` gives the
  top-level field `cloudAgent: { host, attestation }` that the hook's posturebeat worker adds to the
  `POST /api/agent-posture` body in server mode (absent otherwise; `test/cloud-agent-heartbeat.test.mjs`); `attestation` is `github-oidc` only when the root-owned
  file records it next to an `mwt_` token it supplies, else `static-token`. **OIDC exchange**
  ([`cli/workload-token.mjs`](../cli/workload-token.mjs)): with `MOORAI_WORKLOAD_ID` and `MOORAI_OIDC=github`
  the installer requests the job's GitHub ID token (`ACTIONS_ID_TOKEN_REQUEST_URL&audience=moorai:<tenant>`,
  bearer `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, field `value`; needs `id-token: write`) and posts
  `{ workloadId, idToken }` to `POST /api/workload/token` with no install token; a 401 reason is passed through
  only when it is `bad-signature`, `claim-not-allowed`, `expired` or `unknown-workload`; the answer must be an
  `mwt_` + 43 base64url token with a parseable `expiresAt`. Tokens are never printed (sha256 fingerprint).
  **Limits.** Neither host has been run end to end; tested locally against fake fetch and temp roots. The
  exchange runs in the setup step only, so an OIDC token outlives the session only up to the workload's TTL
  (at most 6 h), after which alerts wait in the outbox. In a cloud VM the agent is root (Claude Code) or has
  passwordless sudo (GitHub-hosted runners), so the root-owned file and wrappers are not a tamper boundary
  there, and the machine file holds the workload token. That `GITHUB_ACTIONS` is set in the Copilot agent's
  hook environment, that the setup job's files persist into the agent phase, and whether the Copilot firewall
  covers hook processes are not verified.
- **Not applicable on a server:** the desktop app, the AIBOM, the shadow-AI inventory and OS posture.
- **Proof and limits.** Observed live: one live run of Claude Code 2.1.284 (`claude -p`, the hooks added with `--settings`, server mode from the environment) showed UserPromptSubmit (117 ms) and PreToolUse (224 ms) firing, a `.env` read denied as a headless ask, and the console receiving content-free reports under the workload identity. An Agent SDK service and a GitHub Actions run have not
  been watched end to end.
- **In process.** `moorAIHooks(options)` from `@moorai/agent-sdk` returns the `hooks` record for
  `query({ options: { hooks } })`: one runtime, no process per tool call. `PreToolUse` returns the hook's
  own decision and reason (parity test: 214 payloads, two policy states, 0 mismatches). Prompts and tool
  results are observed by default (`prompts: "enforce"`, `toolResults: "advise"` to act on them).
  `moorai-serve` is the same runtime as a localhost sidecar: `POST /v1/scan`, `POST /v1/tool-call`,
  `POST /v1/index-scan` (chunks about to be embedded; B.12), `POST /v1/task` (the user's task for intent
  alignment, 11c), `GET /healthz`, content-free verdicts, loopback only unless `--allow-remote` plus a 16+ character
  bearer token (compared in constant time); it rejects a non-loopback `Host` (421), non-JSON (415) and a
  body over 1 MiB (413, after draining), with a 5 s header timeout and 256 connections. A stdlib-only
  Python client with LangGraph / CrewAI examples (not executed) is in
  [`clients/python`](../clients/python/README.md). p50 on 2 KB: SDK `PreToolUse` 1.99 ms, sidecar
  `/v1/scan` 6.4–11 ms, shell hook process p50 152–159 ms / p95 170–178 ms (docs/BENCHMARK.md). **Limits.** Not evaluated in process (listed in
  each result's `notEvaluated`): circuit breaker, session risk, deletion volume,
  learned drift, MCP reputation, escalation, honeytokens, the `mask` rewrite. The SDK's `PostToolUse`
  observes by default and resolves results under the same inbound rules as the hook
  ([DETECTION_ENGINE.md](DETECTION_ENGINE.md) §7). Declared workload profiles (17f) are evaluated in
  process. `/v1/tool-call` reads paths on the
  sidecar's own filesystem, so an authenticated client can learn whether a file holds secrets; the
  secret-egress fingerprint cache is filled once per directory in the long-lived process.
- **Container image.** `ghcr.io/gitayg/moorai-server` ([`docker/server/Dockerfile`](../docker/server/Dockerfile);
  `node:22-slim` plus the npm package's files, about 350 MB, no npm dependencies, uid 1000,
  `MOORAI_MODE=server`): `moorai-serve` on 127.0.0.1:8790 by default, `moorai-mcp-gateway` and
  `moorai-model-proxy` (127.0.0.1:8791; probe it with `MOORAI_HEALTH_PORT=8791`) as alternative commands. `.github/workflows/publish-server-image.yml` builds it for amd64 and arm64 on each
  `v*` tag and fails on a secret file in the image or a root user. It runs in the agent's network
  namespace (a second container in the pod, or compose `network_mode: "service:<agent>"`) with exec
  probes (`node /opt/moorai/docker/healthcheck.mjs`, a loopback GET), because the kubelet's `httpGet` goes to the pod IP and
  `moorai-serve` and the model proxy answer 421 to a non-loopback `Host` (the gateway 403). Kubernetes and compose examples in
  [`examples/serve/`](../examples/serve/README.md). **Limits.** Published for amd64 and arm64 by the
  workflow (first run: v1.3.0), run on arm64, the compose demo run end to end, and the Kubernetes manifest
  validated and run on a local cluster (kind, Kubernetes v1.37.0, containerd 2.3.4); the amd64 image has
  not been run on a host, and CRI-O and managed cloud clusters are unobserved.
- **Trust anchors from settings files are ignored on every device.** `MOORAI_BREAKGLASS_PUBKEY`,
  `MOORAI_POLICY_PUBKEY`, `MOORAI_OFFLINE_MODE` and the OTLP endpoint set by a user, project or local
  settings file's `env` block do not take effect and are reported (names only); managed settings, the
  launching environment and the root-owned anchor files are trusted. The registry mirrors
  (`MOORAI_NPM_REGISTRY`, `MOORAI_PYPI_URL`, `MOORAI_MCP_REGISTRY`, `MOORAI_GITHUB_RAW_URL`,
  `MOORAI_GITHUB_CODELOAD_URL`) and `MOORAI_OFFLINE` follow the same rule, without the report.

### Detection brain — tiered escalation cascade
Cheapest-and-most-private first; the escalation order *is* the privacy order.

1. **Tier 1 — deterministic rules** — always on, local, instant, zero egress. Owns the allow/deny
   decision.
2. **Tier 2 — local model** — on ambiguity, opportunistic and policy-gated
   ([`data/model-escalation.mjs`](../data/model-escalation.mjs)). Ollama on the loopback interface
   (`127.0.0.1:11434`, default model `llama3:latest`, set with `MOORAI_LOCAL_MODEL`) — deliberately not
   configurable to a remote host, so nothing leaves the device. Fail-open: no model, timeout or error
   yields no verdict and never changes enforcement. The configured model must be **installed**: an
   Ollama whose `/api/tags` does not list it is treated as unavailable (outcome `unavailable`) instead of
   paying a `/api/generate` call that fails with "model not found" (a bare name matches its `:latest`
   tag; an unreadable tag list counts as present). Verdicts are **cached on the device**
   ([`data/escalation-cache.mjs`](../data/escalation-cache.mjs), `~/.moorai/escalation-cache.json`,
   0600): the key is an HMAC of model + classifier-prompt id + text under a random per-device key
   (`~/.moorai/escalation-cache.key`), the value is the content-free verdict (flag, short category,
   confidence, time); entries expire after 24 hours and at most 2,000 are kept. The prompt id
   (`CLASSIFIER_PROMPT_ID`, a hash of the local classifier prompt) means a changed prompt never reuses
   an older prompt's verdicts. Only verdicts a model returned are cached, never a timeout or an error. A
   cache hit is recorded as outcome `answered` with backend `local-cache`. The cache covers the local
   backend only; the provider backend (Tier 2b) is not cached. The escalation worker is a new process per
   tool call, which is why the cache is on disk. `MOORAI_ESCALATION_CACHE=off` (or `0`, `false`, `no`)
   turns reads and writes off; `scripts/measure-variance.mjs` and the `--semantic` paths of
   `scripts/redteam-eval.mjs`, `score-heldout-v2.mjs`, `score-vectors.mjs` and `score-vector24.mjs` set it
   unless it is already set, so repeated measurement runs ask the model every time. Tests:
   `test/escalation-cache.test.mjs` (fake Ollama on 127.0.0.1, temporary HOME) and
   `test/measurement-cache-off.test.mjs` (each measurement script against a fake Ollama: every run
   reaches the model and no device cache file is written).
3. **Tier 2b — device-side provider inference** — when no local model is present
   ([`data/device-inference.mjs`](../data/device-inference.mjs)). Reuses the API key **already on the
   developer's machine** (`ANTHROPIC_API_KEY` or an admin key file), so no new third party and no new
   egress is introduced. **MoorAI's own cloud never holds an AI credential and never makes the LLM
   call.** No key → fall back to regex-only, fail-open.

There is no MoorAI-hosted inference tier: escalation is local-first, then the developer's own
credential, then nothing.

### Telemetry — redacted alerts only
Client → Server alerts carry **redacted metadata only**: threat id, category, risk tier, timestamp,
tool used, optional keyed content hash / redacted snippet. **Never raw sensitive content** — otherwise
MoorAI would itself commit threats #1 / #9 / #33 on every phone-home.

Further field families are permitted under this rule and are named here so the contract stays
enumerable rather than implicit: `skillKind` + `skillIntents` (a file kind and closed-vocabulary intent
labels — §B2 11a), `destination` (`{kind, name, decision}` — a host or MCP server name — §B2 11b),
`intent` (`{class, unmatched, targets, prompts, semantic, mode}` — a class name, counts and flags — §B3
11c), `reputation` (`{score, band, reasons}` — a number, a band and category codes, next to the MCP
server label — §B3 11e) and the mask record (`maskedThreats`, `maskedCount`, `maskedIn` — threat ids, a
count and `input`/`result` — Intervention tiers, `mask`), verdict provenance on every alert (`policyId`,
`policySource`, `reasonCode`, `basisCode`, `enforcement` — a policy id derived from its signature envelope
and digest, and enum codes — §C 17d), the session correlation key (`session` — the tenant-keyed
`contentHash` of the agent's own session id, the same value as the session summary's `summary:<session>`
suffix, omitted when no id or no key is known; from the Claude Code hook, the HTTP MCP gateway
(`Mcp-Session-Id`), `@moorai/agent-sdk` (hook input `session_id`) and `moorai-serve` (the request's
`session` field), never from the model proxy, which sees no conversation id — §C 17b), the agent name (`agentName` — a value from the console's `agent_name` vocabulary: `claude-code` from the Claude Code hook, the adapter's own id (`codex`, `cursor`, `gemini`, `copilot`) when `moorai-agent-hook` ran it, `gateway` from the HTTP MCP gateway, `claude-code` from `moorai-guard` (it wraps `claude -p`), the MCP client from the stdio MCP proxy's `--host` install stamp (`claude-code`, `cursor`, `claude-desktop`; `vscode` and an unstamped install send none), and omitted for a host it cannot name; `@moorai/agent-sdk`, `moorai-serve`, the model proxy and the inference-hooks server send both `surface` and `agentName` (`agent-sdk`, `serve`, `model-proxy`, `inference-hook`); the vocabulary is [`cli/agent-names.mjs`](../cli/agent-names.mjs), a subset of the console's `AGENT_NAMES`), the agent's own product version (`agentVersion` — e.g. `2.1.295`, never MoorAI's version; only where the agent states it in the process environment, read with no I/O: Claude Code's `AI_AGENT`, accepted only in its `claude-code_<v>_harness` form, on hook alerts and on stdio-proxy alerts with host `claude-code`; Cursor's `CURSOR_VERSION` on hook alerts run through `moorai-agent-hook cursor`; nothing for Codex, Gemini CLI, Copilot CLI, `moorai-guard`, the gateway or the SDK surfaces; a value outside `^[0-9A-Za-z.+-]{1,32}$` is dropped, and the console applies the same pattern), the sub-agent type on a #66 delegation (`subagentType` — a Claude Code built-in type in clear: `general-purpose`, `Explore`, `Plan`, `statusline-setup`, `claude-code-guide`, `fork`, `worker`, `claude`, `workflow-subagent`, `comment-thread-analyst` (read off the 2.1.295 binary) and an older build's `output-style-setup`, plus the Codex adapter's fallback `codex`; any other name, which is the user's own and can say what they work on, as the tenant-keyed `contentHash`, the value the handoff edge's `to` already carries; [`cli/subagent-type.mjs`](../cli/subagent-type.mjs)), the session summary (`summary` — counts — §C 17b), the claim check
(`claimCheck` — a claim-pattern id, an outcome word and counts — §C 17b), the session-risk and
circuit-breaker signatures (`signature`, `sessionRisk` — rule names, counts, scores, windows — §C 17c), and
the agent-posture body sent to `POST /api/agent-posture` (host ids, flag names, scope names, a hook-state
word, an hour-rounded timestamp, a host version string and a tested boolean — §C 17e), the prompt-scan origin (`promptOrigin`, `promptSource` — enum
words — §B3 11h), the MCP usage counts sent to `POST /api/mcp-usage` (a day, a path, a host id, server
labels and call counts, and from the HTTP gateway MCP tool names with their counts — Coverage & blind
spots) and the cloud inventory records (keyed-hash ids, closed-list
statuses, coarse attributes, risk-flag names — Coverage & blind spots), the origin of an action (`origin` —
enums, a keyed sub-agent type and seq numbers; Origin of an action), an egress destination's class
(`destClass` — `throwaway-host` or `other`, never the host), the outbox delivery stamp (`delivery` — `via`,
an `oid`, an attempt count, a queued time, `captureStripped` and a 32-hex `rhash`), the outbox drop report
(`outboxDropped` — counts and seq ranges) and the posture body's `alertOutbox` (counts, seq ranges and two
hour-rounded times; Alert outbox). All are names, categories and counts, never content. The invariant is asserted empirically rather than
declared: `test/skill-analysis.test.mjs` and `test/destinations.test.mjs` each plant a unique canary in
a fixture, capture every byte the hook POSTs plus the on-device ledgers, and fail if the canary, a
matched span, a verbatim source line, a URL path, a query string or a request header appears in either.

### Allow trail (opt-in)
Off by default. With `actionTrail: "allowed"` in the **signed** policy (an unsigned body, an environment
variable or a user config file cannot turn it on; the policy only comes from the console the binding names,
and an admin binding wins, `cli/config.mjs`), the hook records every PreToolUse call it allows, content-free,
and delivers the records to `POST /api/actions` as `{ v: 1, records: [ … up to 500 ] }`, with the install
token header `/api/alerts` uses ([`cli/action-trail.mjs`](../cli/action-trail.mjs)).

- **Record fields:** `ts`, `session` (the keyed session hash alerts carry), `seq` (a counter of its own,
  field `seq` on the wire and in the console's storage, +1 per record per device per OS user, separate from
  the alert `seq`), `event` (`PreToolUse`), `tool` (e.g. `Bash`, `mcp__github__list_issues`; sanitised to
  the console's rule before queueing: NFKC, each control, format, surrogate or whitespace character replaced
  by `_`, cut to 256 code points, `unknown` when empty, so no record is rejected for its name), `toolTags` (capability tags,
  `cli/tool-tags.mjs`), `mcpServer` (MCP tools only), `decision` (`allow`), `basis` (`exception` when a live
  exception covered something that would have fired, `rule` when a finding, a mask or a tag rule applied and
  the configured action still let the call run, `default` when nothing fired; a tool no branch reads counts
  as `default`), `policyIat`, `agentName`, `agentVersion`, `appVersion`, `user` / `device` / `platform` /
  `tenant` / `actor` as alerts stamp them, and `contentHash` (the tenant-keyed hash of the normalized call:
  tool name plus the whitespace-collapsed command, or the input as sorted-key JSON), and `origin` (where the
  call came from, enums only, kind and status re-derived from the basis table by `sanitizeOrigin`; Origin of
  an action).
- **Never included:** arguments, commands, paths, URLs, prompt text, file contents, the capture-tier
  extras. Denied and asked calls are not in the trail (they are alerts already), nor is PostToolUse.
- **No per-call network.** The hook appends the record to `~/.moorai/action-trail.jsonl` (0600) under a
  lock file. When 200 records are queued or the oldest is 30 s old, the call takes a flush lease and spawns
  the detached `actiontrail` worker; one flush is in flight at a time. Session end (Stop) also flushes. The
  worker never fetches policy, sends nothing while the console back-off (`cli/console-backoff.mjs`) is
  active, and never writes it. A 404 / 501 (the console's answer until its side ships), any other non-2xx
  or no answer keeps the records and waits 1, 2, 4, then 5 minutes before the next attempt. Delivery is
  at-least-once: the console de-duplicates on (device, user, `seq`). Measured on this branch (macOS,
  node 22.22, 40 interleaved spawns each, benign allowed `git status --short`, cached signed policy): p50
  137.3 ms on vs 136.9 ms off, p95 149.9 vs 146.2 ms; a second run 134.2 vs 133.2 ms, p95 144.5 vs 143.7 ms.
- **Volume and retention.** One record per allowed tool call, about 450 to 500 bytes as queued. The queue is
  bounded at 10,000 records and 5 MB; when full, the oldest are dropped down to 90% of the bound and the
  count is kept as `actionTrailDropped` (with a content-free line in the local action audit log). At flush
  time, records whose `ts` is older than 89 days are dropped and added to the same count rather than sent
  for the console to reject (it refuses past 90 days); like a full-queue drop, this leaves a gap in `seq`
  that the console reports, explained by `actionTrailDropped`. The
  session summary carries `actionsRecorded` (this session's queued records) and `actionTrailDropped` (the
  device's running count) while the trail is on. Records leave the queue once the console takes them;
  retention after that is the console's.
- **Limit.** The queue, the counter and the state file are user files, writable by the governed agent
  until the phase-3 anchor holds them. A naive deletion of queued records shows as a gap in `seq`; an agent
  that also rewinds the counter shows as a regression, unless it rewinds exactly to the last value the
  console saw. `@moorai/agent-sdk` and `moorai-serve` do not record the trail yet.

### Policy — server → client
Server distributes: approved-tools allowlist, risk thresholds, per-threat/per-tier enforcement
actions (`threatPolicy` / `tierPolicy`), model-escalation policy, and rule-base updates. Client
pulls on launch and periodically; works offline against the last-known policy.

**Console back-off** ([`cli/console-backoff.mjs`](../cli/console-backoff.mjs)). When the hook's policy
fetch gets no HTTP response (timeout, refused, DNS), it records the failure time in
`~/.moorai/hook-console-backoff.json`, next to the policy cache. Later calls skip the policy fetch for 60 s,
doubling per consecutive failure to at most 5 minutes, and the policy resolves exactly as after a failed
fetch (cache, then last-known-good, then the offline default). Inside the window one call in eight still
fetches, chosen by the hook's own crypto RNG. A call that gets no HTTP answer of its own (it skipped the
fetch, or its fetch failed) queues its alerts in the alert outbox (`~/.moorai/alert-outbox.jsonl`, 0600)
instead of waiting on them, and the detached `moorai-hook.mjs alertpost` worker delivers them (10 s per
request, never reading the back-off file; Alert outbox), so the decision path stays fast and every alert is
still sent. Any HTTP response clears the file. It is not used while the pin looks erased, where
every call fetches. Only the hook's decision path fetches the policy and writes the file: the detached scan workers
(`moorai-hook.mjs agentscan` / `indexscan`) re-check their gate from the verified local copies (cache, then
last-known-good) and never fetch, so a worker that outlives a console connection can no longer record a
back-off that makes the next tool call skip the fetch of a new policy (`test/console-backoff.test.mjs` WORKER). Measured, 40 calls each, same decisions, console at a packet-dropping address
(192.0.2.1): allow p50 0.12 s and deny p50 0.09 s, where the same calls take 3.17 s and 4.64 s when every
call fetches; p95 is 1.67 s and 1.63 s, the calls that draw the forced fetch and wait out its 1.5 s timeout. **Tamper
resistance.** The file has the policy cache's trust level: the agent can write it, and nothing on the
device can tell a hook-written file from a planted one. So it can only delay work. It has no say over alert
posts: no state of the file stops one. It can delay a policy refresh by about eight calls on average: a
failure time in the future, or a malformed file, is ignored, the window is measured from the recorded time
and capped at 5 minutes, and the forced draw fetches whatever the file says, and the answer clears it
(`test/console-backoff.test.mjs`). The cache's own freshness check
rejects a future mtime the same way: a cache dated in the future is stale and refetched
(`test/policy-cache-future-mtime.test.mjs`). The fresh window also needs the signed `iat`: a cache whose
signature was issued more than 15 minutes ago is refetched however recently the file was touched
(`test/policy-freshness.test.mjs`, trust anchors below). **Limits.** A cache with no signed `iat` (a console
that has never signed) keeps the mtime-only window, so touching it skips the fetch. On an unmanaged device,
rewriting `serverUrl` in `config.json`, in the same scope, still redirects the hook's console traffic;
on a managed device (an admin binding in the machine config) the rewrite is refused and reported.

The policy is an ed25519-signed envelope. The client trusts it via, in order: a root-owned anchor
(`/etc/moorai/policy.pub`, `%ProgramData%\MoorAI\policy.pub`, or MDM-injected `MOORAI_POLICY_PUBKEY`),
else a TOFU pin learned from the first verified fetch. The unsigned `GET /api/policy/pubkey` is read only
on that first contact; once pinned, the device neither fetches nor believes it. Three properties are
enforced on top of the signature itself:

- **Key rotation (v1.13.7).** A pinned device learns a new key only from a `nextKeys` array (base64 SPKI
  DER or PEM strings) inside the signed body, and only when that policy verifies under a key already in
  the pin and its `iat` is strictly greater than the high-water mark. An equal-`iat` replay is still
  accepted as the current policy but teaches nothing, and a not-newer `nextKeys` raises a content-free
  `policy:nextKeys:not-newer` alert. Before v1.13.7 a pinned device also learned whatever the pubkey
  endpoint published beside a verifying policy, so anyone who could answer as the console (on an unmanaged
  device, a rewritten `serverUrl`) could replay the current signed policy, get its own key pinned, and then
  sign any policy. The console emits `nextKeys` in policies signed by the old key for the transition window
  of a rotation (`POST /api/policy/rotate-key`), then signs with the new key. Same field and rule as the
  privileged helper (guardd contract §13.3 item 1); both are run against
  `test/fixtures/guardd/policy-rotation-vectors.json`. An anchored device does not take `nextKeys` into
  its pin; rotating it is shipping a new `policy.pub`.
- **Key revocation.** A `revokedKeys` list inside the signed body prunes matching keys from the
  device's pin, so an operator signing with K2 can evict a leaked K1 without reprovisioning. Two
  refusals guard it: a key may not revoke itself (otherwise a stolen key locks the operator out),
  and pruning may never empty the pin (an empty key set degrades to `unanchored`, which would turn
  a revocation into a total bypass). Both refusals emit a content-free tamper alert.
- **Rollback refusal.** The highest accepted `iat` is retained as a high-water mark; a strictly
  older — though validly signed — policy is refused and alerted, so a superseded policy cannot be
  replayed to undo a tightening. Equal `iat` is accepted, or steady-state re-fetch would break. A
  refusal falls back to last-known-good, never to "no policy", so #33 offline enforcement is intact.
  Only marks a same-user process cannot raise refuse: the root-owned `policy-hwm.json` and the signed
  `iat` of a last-known-good copy that verifies (`policy:<source>:rollback`). The mark recorded beside
  the pin is user-writable, so it is advisory: a policy behind it is still taken and reported
  (`policy:<source>:behind-pin-mark`), and one more than 10 minutes in the future is ignored and
  reported (`policy:pin:hwm-future`), then replaced by the next accepted policy. Before this, a future
  `iat` written into the pin refused every genuine policy and dropped the device to "no policy".

**Strength, stated honestly.** These mechanisms are HARD only where the state they depend on is
outside the agent's own write scope. Rollback refusal is hard when a root-owned
`/etc/moorai/policy-hwm.json` is present, because the hook reads but never writes it. The rotation rule
closes the remote route (an impersonating console cannot teach a key), but a local attacker who can write
both pin copies can still add a key to them directly, as before. Revocation is
**never** hard: it prunes the pin, and both pin copies live under the user's home directory, so a
local attacker who can poison the policy cache can rewind the pin too — and on an anchored device
the pin is not the deciding key set at all, so pruning changes no enforcement decision there. On an
anchored fleet the real revocation mechanism remains shipping a new root-owned `policy.pub`.
Everywhere else these are tamper-EVIDENT (alerted), not tamper-proof — which is the same posture as
the rest of the product: the hook runs as the user, so nothing under `~/` is a trust boundary.

### Trust anchors: what the agent cannot move (v1.13.0)

The agent runs as the same OS user as the hook, so every user-scope file and environment variable is
the agent's to write. What it cannot write: root/admin-owned files (hook-core `readRootOwned`, Rust
`read_owned_under`), macOS managed preferences, HKLM, and the ed25519 policy signature. Phase 1 of
[the trust-anchor design](proposals/trust-anchors.md) moves four decisions onto those:

- **Console binding (admin first).** `cli/config.mjs` reads the root-owned machine config
  (`/etc/moorai/config.json`; Windows `<ProgramData>\MoorAI\config.json`, administrator-only ACL) before
  any user file, on laptops too. When it names `serverUrl`, the device is managed: `serverUrl` and
  `tenant` are the machine file's, a user `config.json` naming another console or tenant is refused and
  reported (`reasonCode: BINDING_REFUSED`, the key names only), and the install token comes from the
  enrolled user's own 0600 file, never from the machine file (it is world-readable). The hook, the
  `claude -p` guard, the MCP guard and gateway and the doctor all read this one resolver. The desktop
  host does the same: an administrator's console (managed `ServerURL`, or the machine file) is the only
  credentialed origin, a planted `console.json` is not read, and `save_provision` cannot move a managed
  device (`console_binding::resolve`, `admin_config::effective_config`).
- **No coach mode on a managed device.** An admin binding is management evidence
  (`data/enforcement.js`), so deleting `installToken` from the user file no longer turns enforcement
  into coaching. Without a token the console rejects posts, so the hook keeps enforcing, records a
  content-free `binding:no-token` line in the local action audit, and still takes alert sequence numbers,
  so the console sees the gap once the token is back.
- **Windows anchors from HKLM.** Every machine anchor path (`policy.pub`, `breakglass.pub`,
  `offline-posture`, `policy-hwm.json`, `policy-lkg.json`, `exceptions.json`, `config.json`) is built
  from `HKLM\...\ProfileList\ProgramData` (read with `C:\Windows\System32\reg.exe` by absolute path,
  once per process), never from `%ProgramData%`, and `icacls` runs by absolute path
  (`cli/machine-dir.mjs`). The system root is the fixed `C:\Windows`; only a machine without
  `C:\Windows\System32\reg.exe` falls back to `%SystemRoot%`.
- **Freshness from the signed `iat`.** The cache short-circuit needs both a young mtime and a signed
  `iat` younger than 15 minutes (`policyMaxAgeMinutes` in the signed policy changes it, 1 to 10080). An
  older policy is refetched; if the refetch fails it is still enforced (it verified) and the hook raises
  `POLICY_STALE` with `ageMinutes`. While the console is unreachable the console back-off still applies to
  that refetch and the alert goes to the detached alert worker, so a stale cache costs the tool call no
  latency: measured, 20 sequential calls, pinned device, cache signed and touched 2 h before, console
  accepting connections and never answering, p50 176 to 223 ms on v1.12.1, v1.13.2 and v1.13.3 alike, and
  p95 about 1.7 s only in the runs where a call drew the one-in-eight forced fetch. Every hook alert raised after the policy loads carries `policyIat`
  (ISO 8601) when the enforced policy is signed, and every hook alert carries `appVersion`.
- **Hook command and environment.** Hook registrations name node by absolute path
  (`process.execPath`), and an older bare-`node` entry is rewritten on the next call. A user, project or
  local settings file whose `env` sets `NODE_OPTIONS`, `NODE_PATH`, `PATH` or `ProgramData` is reported
  (the refusal alert names them; PATH alone is High, the rest Critical), is the posture flag
  `hookEnvOverride`, and its `NODE_OPTIONS` / `NODE_PATH` are kept out of the hook's detached workers.
  PATH that the hook merely inherits is not a finding. `moorai-doctor` warns when the hook's code is
  writable by the user (a consumer install under `~/.moorai`).
- **Evidence on unmanaged devices.** Each alert carries a per-device `seq` (+1 per alert, user scope)
  and `chainHead` (a `cli/record-chain.mjs` chain over the alerts), and the session summary carries
  `alertsEmitted` / `alertsDeferred`. **This catches naive deletion only:** the counter, the chain head
  and the session ledger are user files, so an agent that also rewinds them to the last value the
  console saw is not caught.
- **Alert sequence numbers** (`cli/alert-seq.mjs`, `cli/record-chain.mjs`). `seq` is advanced only while
  holding the per-user lock file (`.chain-alerts.lock`, opened exclusive, holding the holder's pid), so two
  alerts never carry the same number. The lock is broken only when its holder is gone: older than 5 s with
  its pid no longer running, or older than 60 s whatever it holds. A number is handed out only once it is on
  disk: the head is replaced atomically (temp file, then rename, keeping the old file's mode, and its owner
  when written as root), after a copy of the same new head (`.chain-alerts.head.json.prev`) is replaced the
  same way. The alert chain's temp file is fsynced before the rename; the directory is not fsynced (a second
  fsync doubled the time the lock is held and left 8.5% of alerts unnumbered in bursts). A process crash
  therefore never repeats or restarts a number. A power cut can lose the last rename and hand out the last
  number once more, which the console reads as a counter reset. On macOS Node's `fsyncSync` is F_FULLFSYNC,
  about 4 ms (measured), once per alert.
- **Unnumbered alerts.** An alert whose stamper cannot take the lock within 200 ms, whose head cannot be
  saved (a full disk, a read-only directory), or whose head exists but neither it nor its copy can be read,
  is sent without `seq` and `chainHead`. It is never held back and never given a number another alert
  holds, and the counter never restarts at 1 on its own. A head and copy that both cannot be read leave the
  device sending unnumbered alerts until the files are repaired or removed (removing them restarts the
  counter, which the console records as a counter reset). The console reports a run of unnumbered alerts
  from a device that numbers its alerts (more than 20 in one hour, or at least 5 and more than 10% of its
  hook alerts) as the Low finding "Alerts sent without a sequence number". The local log chains (signals,
  session ledger, OTel span chain) are replaced atomically too but not fsynced, because they are written on
  every hook event: a crash leaves their head whole, a power loss can at worst leave it behind, which
  `moorai-verify-chain` reports as a fork. A local record whose head could not be read or saved is stamped
  `seq` 0, linked to the genesis, and shows there as a break. Tests: `test/record-chain-head.test.mjs`,
  `test/alert-evidence.test.mjs`.

**Limits.** The install token stays readable by the agent (it is the same OS user) until the privileged
helper of phase 2. A Jamf profile's `InstallToken` is read by the desktop app because managed
preferences are root-owned, but profile payloads are readable by local users; per-user delivery (the
deploy script writing the user's own `config.json`) is the recommended route. Removing the hook,
disabling hooks, or uninstalling MoorAI is visible only as silence (the console's device-quiet rule).
A version manager that later deletes the node binary a hook command names leaves the host unable to
start the hook; `moorai-doctor` and the posture heartbeat report the entry as broken. Whether Claude Code
applies a settings file's `env` to hook processes is taken from its documentation, not re-measured here.

## Risk distribution (from the matrix)

Counts are the shipped `riskLevel` labels in `data/threats.json` — the field the engine actually
ranks findings by ([`src/engine.js`](../src/engine.js)) — across all 82 threats.

| Level | Count | Nominal score band |
|---|---|---|
| Critical | 17 | ≥ 20 |
| High | 49 | 12–19 |
| Medium | 16 | 6–11 |

Note: 8 of the 82 threats carry a `riskLevel` label outside the nominal band their `riskScore`
would place them in (e.g. #65 scores 15 but is labeled Critical; #43 scores 6 but is labeled High).
The label wins at runtime; the bands in `meta.scoring` are documentation, not an invariant the data
is validated against.

## Capabilities

### A. Host / gateway (client)
1. **Approved-tools launcher** — the allowlisted AI tools, reached through the host. *Coaches on
   threats 4, 5, 7, 28; when an MCP allow-list is configured, an off-list server is denied outright
   (`decideMcpServer`, [`cli/hook-core.mjs`](../cli/hook-core.mjs)) — but a user who never installs
   MoorAI is still unreached. An empty `mcpAllow` (the console default, `[]`) is no allow-list: it blocks
   nothing and marks no server unapproved, on every surface that judges MCP calls (the hook, the stdio
   proxy, the HTTP gateway, `@moorai/agent-sdk` / `moorai-serve` and `moorai-ingest` replay all call
   `decideMcpServer`). With the approval gate (`mcpGate`) on, `mcpAllow` is the approved set: a server not on it
   is denied, and a policy with nothing approved yet denies every server.*
2. **Per-context sessions** — a separate conversation per customer / project / topic. *Threat 36.*

### B. In-band detection (client; mapped to threat clusters)
3. **Sensitive-data guard (DLP)** — pre-submit + paste inspection. *Threats 1, 9, 15, 33, 39.*
4. **Upload guard** — intercepts file uploads / drag-drop. *Threats 18, 27.* Pasted/dropped **images**
   are inspected by recovering their text with the **OS's own recognition engine** and running it
   through the same detectors — macOS `Vision.framework`, Windows `Windows.Media.Ocr.OcrEngine`, Linux
   `Tesseract` (via `leptess`, a second-class tier). No model is bundled and the image never reaches the
   MoorAI console. On macOS, Vision runs twice, accurate then fast, and a fast-pass line the accurate
   pass lacks is added: on macOS 27 the accurate recognizer misreads some secret characters (`7` → `Z` in
   `AKIAIOSFODNN7EXAMPLE`). On 224 rendered secrets that took detection from 212 to 219 and exact reads
   from 157 to 161, at about 20 ms more per image; when the passes disagree, one image can show two
   finding cards for one key. Three states, and the UI names the applicable one before the user pastes:

   | Device | Behaviour |
   |---|---|
   | macOS; Windows with an OCR language pack; Linux with the Tesseract package | **On-device.** Nothing leaves the machine. (Linux/Tesseract is second-class — below the OS engines.) |
   | No OS engine, but a provider key already on the device | **Disclosed fallback.** Sent **device → provider directly** (never via MoorAI), using the key already present — env `ANTHROPIC_API_KEY`, the admin key file, or the saved agent token, resolved exactly as [`data/device-inference.mjs`](../data/device-inference.mjs) does. Emits a content-free alert. |
   | No OS engine and no key | **Skipped**, and said so. Never a silent fallback to egress. |

   The fallback is structurally unreachable whenever a native engine exists: the host ignores the
   caller's opt-in in that case ([`src-tauri/src/ocr.rs`](../src-tauri/src/ocr.rs)). *Windows OCR is
   runtime-verified on a real Windows 11 host (8/8 sensitive strings off a clean render); the
   Linux/Tesseract tier is validated end-to-end but second-class — below the macOS/Windows OS engines.*
5. **Prompt-injection scanner** — inspects pasted/external content. *Threats 2, 3, 40.*
6. **Output-safety scanner** — dangerous links/scripts/macros + fake sources. *Threats 8, 17, 29, 32, 34, 35.*
7. **Social-engineering / BEC sentinel** — bank-detail/payment/invoice/deepfake patterns. *Threats 10–13, 30, 31.*
8. **Meeting & memory hygiene** — transcription warnings, risky AI-memory writes. *Threats 19, 20, 22.*
9. **Permissions-exposure watch** — over-broad / role-irrelevant results. *Threat 6.*
10. **Ethics check** — human-review nudge on AI-assisted screening. *Threat 16.*
11. **Output-sharing check** — scans summaries/screenshots before sharing. *Threats 20, 37.*
12. **Index / RAG payload inspection** — content headed for a vector store or retrieval index is scanned
    at the engine's `index` stage (`DetectionEngine.scanForIndex`: the prompt detectors plus the
    ingested-content ones that declare `index`) before it is embedded. *Threats 21, 22, 40, 50, 60, 70.*
    Shared decision in [`cli/index-scan.mjs`](../cli/index-scan.mjs); three integration points:
    `scanBeforeEmbed(chunks, { source })` and `guardEmbed(embedFn)` in `@moorai/agent-sdk`
    ([`packages/agent-sdk/src/embed.mjs`](../packages/agent-sdk/src/embed.mjs)); `POST /v1/index-scan`
    `{ chunks, source? }` on `moorai-serve`; and vector-store write tools in the MCP stdio proxy and the
    HTTP gateway ([`cli/index-tools.mjs`](../cli/index-tools.mjs): `policy.indexTools` names, or a
    write verb plus a store noun, a vector-store hint in the tool or server name, or a document-array
    argument; `policy.indexToolHeuristic: false` turns the heuristic off). Each chunk is `allow`,
    `flag` (reported, kept) or `deny`. **Report-first:** `policy.indexScanAction` is `"report"` by default;
    `"block"` denies a chunk carrying an instruction threat (the `promptScanAction` list) or a threat whose
    action is block / kill — `guardEmbed` drops it, the MCP surfaces refuse the call before the server
    sees it. Fail-open. Content-free alerts at stage `index`; `source` leaves only as a keyed hash.
    **Covered:** apps that call the SDK helper or the sidecar, and MCP vector-store tools that match.
    **Not covered:** an app that embeds without calling MoorAI, an in-process vector library with no MCP
    or API hook, a store tool whose name and arguments match nothing (until named in `indexTools`), and
    documents a store ingests on its own. MoorAI has no vector store or embedding writer of its own.

### B2. Skill-surface analysis (client)

11a. **Skill Analysis** — inventory + intent + drift for every file on the agent's **auto-loaded skill
   surface**, classified by PATH in [`data/skill-surface.js`](../data/skill-surface.js) and reported by
   `reportSkillFile` in [`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs). *Threat 60.* Three emissions,
   all content-free (kind + labels + a one-way fingerprint):

   - `Skill-file poisoning` (High) — the injection detectors fired inside the file (threats 3/40/50/51).
   - `Skill-file drift` (Medium) — the file changed since MoorAI last saw **that file**.
   - `Skill-file intent` (Info) — the file carries intent labels but is neither poisoned nor drifted.

   **The surface, and how each entry was verified.** "Observed" = confirmed against a real `~/.claude`
   layout on a developer machine. "Doc" = confirmed against the harness's own published documentation
   (`code.claude.com/docs/en/{memory,settings,mcp,hooks-guide,plugins,managed-settings}`) but not seen
   on disk here. Both are matched; the distinction is recorded rather than blurred.

   | kind | paths | verified |
   |---|---|---|
   | `claude-skill` | `.claude/skills/**`, any `SKILL.md` | observed |
   | `claude-agent` | `.claude/agents/**.md` | observed |
   | `claude-command` | `.claude/commands/**` (files **and** `<name>/SKILL.md` directories) | observed |
   | `claude-settings` | `.claude/settings.json`, `.claude/settings.local.json` — carry `hooks` | observed |
   | `claude-hook` | `.claude/hooks/**` | observed |
   | `claude-managed-settings` | `managed-settings.json`, `managed-settings.d/*.json` (macOS `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`) | doc |
   | `claude-user-config` | `~/.claude.json` — the user-scope `mcpServers` map | observed |
   | `.mcp.json` | project-scope MCP servers | doc |
   | `managed-mcp` | `managed-mcp.json` | doc |
   | `claude-desktop-config` | `claude_desktop_config.json` — Claude Desktop, guarded via [`mcp-proxy/`](../mcp-proxy/) | doc |
   | `claude-plugin` | `.claude-plugin/{plugin,marketplace}.json` | observed |
   | `plugin-hooks` / `plugin-monitors` / `plugin-lsp` / `plugin-agent` | `hooks/hooks.json`, `monitors/monitors.json`, `.lsp.json`, `plugins/**/agents/*.md` | doc |
   | `claude-rule` | `.claude/rules/**.md` (path-scoped rules) | doc |
   | `claude-memory` | `.claude/projects/<p>/memory/*.md` | observed |
   | `CLAUDE.md` / `CLAUDE.local.md` / `AGENTS.md` | project, nested, user and managed scopes | observed / doc / doc |
   | `.cursorrules`, `.cursor/rules`, `cursor-mcp`, `.windsurfrules`, `copilot-instructions`, `codex-config` | other vendors' equivalents | doc |
   | `AGENTS.override.md`, `GEMINI.md` | Codex's override of `AGENTS.md`; Gemini CLI's context file (`~/.gemini/GEMINI.md` and workspace dirs); `AGENTS.md` also matches Amp's `AGENT.md` fallback | doc |
   | `copilot-path-instructions`, `copilot-prompt`, `copilot-agent` | `.github/instructions/**/*.instructions.md` (recursive) and `~/.copilot/instructions`; `.github/prompts/*.prompt.md`; `.github/agents/*.md` and `~/.copilot/agents` | doc |
   | `windsurf-rule`, `windsurf-global`, `windsurf-workflow` | `.windsurf/rules`, `.devin/rules` and the system rules folders; `~/.codeium/windsurf/memories/global_rules.md`; `.windsurf/workflows`, `.devin/workflows`, `global_workflows` and the system workflow folders | doc |
   | `.clinerules`, `cline-rule`, `cline-workflow` | `.clinerules` as a file or a directory; `.cline/rules`, `~/Documents/Cline/Rules`, `~/.cline/rules`, `~/Cline/Rules`; `.clinerules/workflows`, `~/Documents/Cline/Workflows` | doc |
   | `cursor-command`, `codex-prompt`, `gemini-command`, `opencode-command`, `opencode-agent` | `.cursor/commands/*.md`; `~/.codex/prompts/*.md`; `.gemini/commands/**/*.toml`; `.opencode/commands`, `.opencode/agents` and their `~/.config/opencode` equivalents | doc |
   | `kiro-steering`, `kiro-spec`, `kiro-hook` | `.kiro/steering/` and `~/.kiro/steering/`; `.kiro/specs/**/*.md`; `.kiro/hooks/*` | doc |
   | `gemini-settings`, `amp-settings`, `opencode-config` | `.gemini/settings.json` (project, user, system and `system-defaults.json`) — carries `hooks` and `mcpServers`; `.amp/settings.json` and `~/.config/amp/settings.json`; `opencode.json` — names extra instruction files | doc |
   | `cline-mcp`, `windsurf-mcp`, `vscode-mcp`, `continue-mcp`, `amazon-q-mcp`, `kiro-mcp` | other clients' dedicated MCP-config files (`cline_mcp_settings.json`, `.codeium/windsurf/mcp_config.json`, `.vscode/mcp.json`, `.continue/mcpServers/*`, `.aws/amazonq` & `.amazonq/mcp.json`, `.kiro/settings/mcp.json`) | doc |
   | `openclaw-soul`, `openclaw-memory` | OpenClaw's `SOUL.md` ("Loaded every session"), `MEMORY.md` (curated long-term memory, loaded in the main session) and `~/.openclaw/workspace/memory/*.md` (docs.openclaw.ai/concepts/agent-workspace, checked 2026-10-23); matched by file name anywhere, after `claude-memory`, so Claude Code's own `memory/MEMORY.md` keeps its kind | doc |
   | `zed-mcp` | Zed `context_servers` — lives inside `~/.config/zed/settings.json` or project `.zed/settings.json` (a general settings file, anchored to the `zed` dir; no overlap with `.claude/settings.json`) | doc |

   **Intent labels** are a closed vocabulary (`INTENT_LABELS`,
   [`cli/skill-analysis.mjs`](../cli/skill-analysis.mjs)), each one a rename of an existing threat id, an
   existing content tell ([`data/agent-behavior.js`](../data/agent-behavior.js)) or the existing host
   extractor ([`data/model-endpoints.js`](../data/model-endpoints.js)). There is deliberately **no second
   detection engine**: a forked engine would sit outside `threatActionFor` and the org's detector packs.

   **Hiding-technique labels.** Five labels name one detector each rather than a threat, because the engine
   keeps one finding per threat and these share theirs with other detectors (data/detectors-skill-hiding.js,
   data/skill-hiding.js): `padded-hidden-content` (`skill-padded-hidden-content`, #40: a run of 60 or more
   blank lines, of whitespace, format or filler characters, with content after it), `hidden-html-instructions`
   (`skill-hidden-html-instructions`, #40: an HTML comment holding a shell command, a beacon `key=value` line
   with a URL or host, a URL next to a call verb, or an order to the agent; licence headers, TODO notes and
   lint/TOC directives excluded), `conceals-from-user` (`skill-conceals-from-user`, #40), `targets-reviewers`
   (`skill-targets-reviewers`, #3) and `persists-to-memory` (`skill-persists-to-memory`, #22). Stages `file`
   and `index`. Padding and HTML comments fire only when the caller names the file (`ctx.readPath` from the
   hook's Read and Bash branches, `moorai scan` and the MCP package scan; `ctx.targetPath` from the ingest
   worker) and it is on the skill surface; the three phrasing rules also fire when no path is given, and stay
   quiet on a named file off the skill surface. When two of them fire on one file, the engine's one finding
   names the last; `skillIntents` recovers the others by re-running the same detector objects over the text
   and its invisible-character views, and only for a threat the engine reported, so a policy that disables
   the threat removes the label.

   **Limits.** (a) Intent coverage *is* detector coverage — an instruction with no detector produces no
   label, so "no labels" means "nothing recognized", never "benign". (b) Files are seen when an agent
   loads them through the Read/Bash hooks; MoorAI does not walk the filesystem inventorying untouched
   skill files. (c) Classification is by PATH, so a skill reached via `skillDirectories`, a symlink farm,
   or a plugin root outside the known layout is still scanned by the detectors but is not labelled as
   skill surface. (d) The drift fingerprint is an unkeyed DJB2 of the whole file, not the keyed HMAC used
   for matched spans — a whole config file has no enumerable candidate space, and an unkeyed value is
   what lets the console see two devices holding the *same* poisoned file. Pinned by
   `test/content-hash.test.mjs`. (e) The baseline key is per **file** (`kind|path`), not per kind; the
   path stays on the device, only `kind` + the fingerprint are emitted.

11b. **Per-agent destination map** — an on-device aggregation of the external destinations each
   agent/tool actually reached: a **host** or an **MCP server name**, with counts, first/last-seen and
   the allow/ask/deny verdict that call actually received. Storage follows the exposure/intent ledger
   pattern (`destinations.jsonl` in [`cli/signals.mjs`](../cli/signals.mjs)); rollup is pure
   ([`data/destination-map.js`](../data/destination-map.js)); the viewer is
   [`cli/moorai-destinations.mjs`](../cli/moorai-destinations.mjs), exposed exactly like `moorai-ledger`.
   The console is notified over the **existing** `/api/alerts` path — `Agent destination: first seen`,
   emitted once per newly observed agent→destination pair, so a busy agent yields one signal per new
   destination rather than one per call. No new telemetry channel and no new endpoint.

   Recording points are chokepoints, not per-return-site calls: the Bash branch records after the final
   verdict (so a host reached by a command that was then denied reads as denied), and the MCP branch
   hangs off the same `audit()` closure the gateway ledger uses, which every one of its six return
   sites already goes through.

   **Content-free by construction:** `extractHosts` captures the host and stops — a URL path, query
   string, header or body is never captured, so there is nothing to strip downstream.

   **Limits.** The map sees what the hook sees: Bash commands and MCP tool calls. It is **not a network
   tap** — a compiled binary's raw socket, or an MCP server's own child process, is invisible to it.
   Hosts come from `http(s)://` URLs, so `curl example.com` (no scheme), an SSH remote, or a bare IP
   literal is not recorded; a **dotless** internal hostname is captured only via a base-URL env-var
   override (`OLLAMA_HOST=http://gpu-box:11434`; the variables are `BASE_URL_ENV_VARS` in
   [`data/model-endpoints.js`](../data/model-endpoints.js), including `GOOGLE_VERTEX_BASE_URL` and
   `GOOGLE_GEMINI_BASE_URL`, which the endpoint allow-list #63 judges too), not from a plain URL. The `decision` recorded is the
   hook's verdict for the call, not proof the connection succeeded or failed.

### B3. Task, instruction-file and MCP-server context (client)

11c. **Intent alignment** — does a risky agent action fit the task the user gave in this session?
   *Threat 64.* The hook registers `UserPromptSubmit` for this and for the prompt scan (11h); a prompt
   a person typed is not scanned by the detection engine. From prompts a person wrote (`system` and `poll_event` turns skipped), it keeps
   device-keyed HMACs (`~/.moorai/intent.key`, 0600) of the sites, paths, fixed-list service names and
   up to three labels (`credentials`, `destructive`, `mcp-write`) the prompt mentions, in
   `~/.moorai/intent-alignment.json` (0600; 64 sessions, 24 h TTL, 512 features). The prompt is never
   stored ([`cli/intent-alignment.mjs`](../cli/intent-alignment.mjs),
   [`data/intent-alignment.js`](../data/intent-alignment.js)).

   Only already-risky calls are judged: a `Bash` or `PowerShell` upload to a non-loopback host (egress;
   a UNC share's host counts), any upload to a loopback host whatever the port (`moorai-control`, never
   aligned), a #43 destructive command, a #55 credential read (`Read`, `Bash` or
   `PowerShell`), and an MCP tool whose name carries a write verb. Egress is aligned only if every destination site was named, and no label excuses it. The
   other classes are aligned by their label or by a named path or server. Sessions with no captured task
   are never judged, and a call already denied is not re-judged. A misaligned call posts one alert per
   session, class and target: category `Action outside the stated task`, stage `behavior`.
   `policy.intentAlignment`: `"report"` (default), `"ask"` (opt-in; raises allow to ask), `"off"`.
   Unenrolled devices coach. An optional semantic tier asks the **loopback** model for labels at prompt
   time, only when `modelEscalation` and `semanticEscalation` are both on, bounded by
   `MOORAI_INTENT_TIMEOUT_MS` (default 1500). The Codex (`UserPromptSubmit`), Cursor
   (`beforeSubmitPrompt`), Gemini (`BeforeAgent`) and Copilot (`userPromptSubmitted`) adapters forward
   the prompt for capture and answer with nothing the model sees.

   **Limits.** Lexical, not semantic: an upload to a host the user named passes. Pasted text widens the
   task. The agent can read the key and rewrite the state file, as it can every file under `~/`.
   `Write`/`Edit`, data in a GET query string and `git push` to a new remote are not judged. The Codex,
   Cursor, Gemini and Copilot hosts do not mark machine-injected turns, so there a hook-forced
   continuation counts as the task. Codex runs the prompt hook only after the user trusts it. Adapter
   installs from before the prompt event need `moorai-agent-hook.mjs <agent> install` re-run; only
   Claude Code's registration converges on its own. It adds one hook process per prompt.

   **Server surfaces (Agent SDK, `moorai-serve`).** The same pure logic runs over an in-memory store,
   [`data/intent-server.mjs`](../data/intent-server.mjs): per session, HMACs (random per-process key, never
   leaves the process) of the task's derived features and of the targets already judged; 1024 sessions,
   24 h TTL from last use (capture or judge), 512 features per session. The prompt is never stored. A risky
   call whose session has no live task under its owner (no session, never captured, evicted, expired)
   returns class `task-unknown`, not aligned, so ask/block fail closed and report alerts (once per session
   and target). This departs from the hook, which skips a session with no task: `"block"` requires the
   caller to supply the task, and without one every risky call is "task unknown". One exception: in
   `"report"` a call with no session id at all (absent or empty) is not judged and raises no alert; a
   supplied id with no task is `task-unknown` in every mode. Sessions are namespaced by an
   optional owner: on the sidecar, the bearer token presented (each line of `--token-file` is a
   principal), so a task can be set, replaced, judged or evicted only by its own principal; per principal
   at most `--intent-sessions-per-caller` (default 256), its own oldest out. The store's global cap evicts
   the LRU session of the owner holding the most, which can be another owner's; the sidecar sizes it to
   max(1024, principals × per-caller cap), so that never happens there. Without a token every local process
   is one principal. Only a task writer may `POST /v1/task`: with `--task-token-file` (one task token per
   `--token-file` line, writing for that line's principal) only those tokens; with no task token any
   authenticated caller for its own principal; with no token at all, in `"ask"` and `"block"`, nobody (403),
   so an agent's own shell cannot widen its task. A capture carries whether an authenticated writer sent it
   (`captureTask(..., owner, { authenticated })`, default true; the sidecar with no token passes false), and
   `"ask"`/`"block"` judge only against authenticated captures (`judge(..., owner, { authenticatedOnly })`), so
   a tokenless task written under `"report"` is `task-unknown` once the mode changes. The SDK records a prompt as the task only when its prompt
   scan did not deny it. The SDK captures the task at `UserPromptSubmit` (the `query()` prompt and later user turns;
   a machine-injected `source` is skipped); the sidecar at `POST /v1/task {session, prompt}`, which answers
   `{mode, captured, features}`. A `PreToolUse` / `/v1/tool-call` with that session is judged after the
   branch verdict and before the headless rule (`packages/agent-sdk/src/runtime.mjs`):
   `policy.intentAlignment` `"report"` (default; one alert per session and target, verdict unchanged),
   `"ask"` (allow to ask, then settled headless: deny unless `headlessAsk` allows or passes it through),
   `"block"` (allow or ask to deny; server surfaces only) or `"off"`. The alert is the hook's: #64,
   `Action outside the stated task`, stage `behavior`, reason code `INTENT_MISMATCH`, `contentHash` the
   keyed hash of the class, and `intent: {class, mode, targetHash}`. The verdict gains `intent: {class,
   mode}`; the reason it adds is fixed text per class.
   **Limits** (beyond the hook's lexical ones, which hold unchanged: whether the user named the destination,
   file or service, not whether the action serves the task; a pasted untrusted request puts its hosts in
   scope): the store is per process, so replicas do not share a task and a restart forgets it (risky
   calls are then `task-unknown` until the task is sent again); clients sharing a token share a principal; no loopback-model labels.

   **Task-bound tool calls** ([`data/task-bound.js`](../data/task-bound.js), held by
   [`data/intent-server.mjs`](../data/intent-server.mjs) `judgeBound` / `setTaskId` in memory and by
   [`cli/task-bound-hook.mjs`](../cli/task-bound-hook.mjs) on the device). *Motivation:* the public MuTRAP
   backdoor research and the PROTEA defense (Binghamton University) show a backdoored fine-tuned LLM planner
   that behaves normally until a trigger word appears, then turns the same request ("cut the apple") into a
   harmful plan step (`cut(hand)`); PROTEA checks each step with a second LLM. These checks are
   deterministic instead: no model guards a model.
   - *Object check* (`policy.intentArgs`: `{ "<tool>": ["<key>", …], synonyms: { "<term>": ["<term>", …] },
     caps: { "<tool>.<key>" | "<key>": <number> } }`). Runs on a high-impact call: a tool `intentArgs` names,
     an MCP write (`MCP_WRITE` on the tool part), a function in a business-impact class
     (`model-proxy/business-tools.mjs`), or another function whose name carries a write verb; the hook's own
     tool vocabulary stays with the classes above. Object fields: the keys `intentArgs` lists (dotted keys
     read nested fields), else the built-in `DEFAULT_OBJECT_KEYS` (recipients, accounts, destinations, paths,
     URLs, repositories, buckets). Every argument key equal to a field after folding case, `_`, `-` and spaces
     is read, and a dotted field both as the literal key and nested (`collectKey`); every value found must be
     named. The task is held as keyed
     hashes of its words, two- to five-word phrases, whitespace-delimited tokens (with the host, site and
     file name inside them) and numbers; both sides are folded with NFKC, case, punctuation, the articles
     a / an / the and simple plurals. A text value is named when its token, word phrase (≤ 5 words), URL host
     or site, or path file name or stem is among them, or a member of its synonym group is; an e-mail
     address only whole. A number (a JSON number, or a string that is only a number with an optional
     currency sign) is named when the same number is in the task, and is allowed at or under its cap. A miss
     is class `object-not-in-task`, decided by `policy.intentAlignment` (report / ask / block; on the hook
     `"block"` denies this class, where the older classes stop at ask). No captured task: `task-unknown` on
     the server surfaces, not judged on the hook. An unreadable `intentArgs` tool entry checks every top-level
     string or number argument; an unreadable synonym group or cap is dropped (only holds more).
   - *Task allowlists* (`policy.taskAllowlists: [{ task, match: { keywords } | { taskId }, tools: { "<tool>":
     true | {} | { args: { "<key>": [value | glob | number | { min?, max? }, …] } } }, default: "deny" |
     "ask" }]`). A keyword entry applies when any keyword is named in the task (on every capture, since a
     wider match only restricts more); a `taskId` entry applies when the session's explicit task id (sidecar
     `POST /v1/task {session, taskId}`, SDK `setTaskId`) is its id and an authenticated writer set it. An
     explicit task id beats keywords: entries naming it apply alone; when none does, the keyword entries
     apply. Several applicable entries: each judges the call and the strictest outcome wins. A tool not
     listed, or a listed key whose value (each element of an array) is not allowed, is held at the entry's
     default (default `"deny"`), whatever `intentAlignment` says: class `outside-task-allowlist`, reason
     `tool-not-listed` or `argument-not-allowed`. Globs are matched in linear time. Argument keys
     (`walkKeys` over the listed keys as a tree): a listed dotted key is read literally and nested, each one
     present must be allowed (a dotted key that runs below a listed leaf is cut off there, whatever the
     listing order, and none of its later segments is attached higher up); a key equal to a listed key or
     segment only after folding is held
     (`argument-key-collision`); with `unlistedArgs` `"deny"` (the default for every entry, an ask entry only
     asking) an argument the tool's `args` do not list, at the top level or under a listed dotted path, is held
     (`argument-not-listed`), and `"allow"` passes it; a tool listed as `true` / `{}` takes any arguments.
     *Selection cannot be lost:* at capture the keyword entries the WHOLE prompt names (`entriesNamedIn`) are
     recorded per session by a keyed hash of the entry's own text, apart from the capped term set; the model
     proxy keeps the person's turns uncut while an allowlist is configured. A recorded entry or one the held
     terms name applies. The model proxy and the
     hook match by keyword only. Tool names on both sides go through `foldName`; for `mcp__<server>__<tool>`
     the full name is tried, then the tool part.
   - *Fail closed.* `taskAllowlists` that is not an array, or an entry whose match, tools, arguments, default
     or name cannot be read, denies everything it would have covered (reason `invalid-policy`): an unreadable
     match covers every session, the rest cover the sessions the entry matches. The surface raises a
     `Task-bound policy invalid` alert (threat 0, stage `policy`, reason code `FAIL_CLOSED`,
     `taskBoundPolicy: {problems}` with fixed tokens): once per policy on the server surfaces, once per
     session on the hook. Source: the signed policy and the root-owned admin binding, the binding winning
     key by key; never user-writable state. The task is captured whenever `intentAlignment` is not `"off"`
     or an allowlist is configured.
   - *Hook state tamper.* `~/.moorai/task-terms.json` carries an HMAC-SHA256 over its contents, keyed by
     sha256 of the device signing key's (`data/agency-sign.mjs`) deterministic ed25519 signature over a fixed
     label. Missing (while `intent.key` exists, i.e. a capture happened on the device), unreadable, oversized,
     another version or an HMAC mismatch is tampered: every allowlist entry judges the call as if its task
     matched, anything one would hold is denied (reason `state-tampered`), and each such call raises
     `Task-bound state tampered` (threat 0, stage `policy`, `FAIL_CLOSED`, `taskBoundState: {problem}`:
     `missing` | `unverified` | `tamper-window`). The tampered file is never re-signed; the next capture writes
     a fresh signed state with `tamperedAt`, a fixed timestamp under the HMAC. For the whole 24 h after it,
     every session (an old one capturing a new prompt, one created after the tamper, any number of new ones)
     has every allowlist entry applied as if selected, as for a tampered file. There is no proof that a
     session is new (file timestamps fall back to ctime on some filesystems and the agent's user can change
     the files) and no per-session list to flood. **Trade-off:** legitimate new sessions are held for the
     window too; anything every entry allows still runs.
   - *Alerts and verdicts.* #64 `Action outside the stated task`, reason code `INTENT_MISMATCH`, `intent:
     {class, mode | outcome, task?, reason?}`; never an argument, a value or the task. Verdicts gain `intent:
     {class, mode}` (`task` for an allowlist). The model proxy in `--mode report` only alerts. Storage: in
     memory on the server surfaces (`maxTerms` 8192 per session, matched entries apart); on the device
     `~/.moorai/task-terms.json` (0600; per session 1536 words / tokens / numbers and 512 phrases in two tiers
     across prompts, 32 sessions; matched-entry hashes for 1024 sessions; 24 h; the `intent.key` device key).
   - *Measured* (`test/task-bound.test.mjs`, `test/task-bound-surfaces.test.mjs`): the store's `judgeBound`
     0.03 ms median of 50; 0.02 ms added to an SDK `toolCall`; 5.1 ms for the hook step cold in a fresh process (derived key, state read, HMAC); two end-to-end runs of 50 measured 3.0 and 10.5 ms over a 290–370 ms hook call.
   - **Limits.** Token matching is not semantics: it answers "did the person name this object", not "is
     this action on it safe" — "cut the apple" names `apple` whatever the action does to it, and a value the
     person typed is in scope even when the agent was steered into using it. It relies on the policy naming
     the object fields: a field neither `intentArgs` nor the built-in defaults cover is not checked, and a
     tool that is not high-impact is not object-checked at all. Pasted text widens the task. The hook judges
     MCP tool calls only (its built-in tools are not held by an allowlist); the model proxy judges the name
     the model sent, not a dispatcher's inner tool. The device
     state shares `intent-alignment.json`'s trust boundary: the agent runs as the same user, can read both
     keys, dictionary-attack the hashed words and re-sign an edited state; deleting `intent.key` together
     with the state returns the device to "never captured"; more than 1024 prompted sessions in 24 h evict the
     oldest matched-entry record (a privileged witness, `moorai-guardd`, is not installed). On the server
     surfaces an evicted or never-captured session has no recorded entry, so no keyword entry applies.
     Not observed in a live Claude Code, LangGraph or robot-planner session.

11d. **Protected-instruction leak** — the agent's own rules files leaving the device. *Threat 52.*
   Three detectors ([`data/detectors-instruction-leak.js`](../data/detectors-instruction-leak.js)):
   `instr-leak-output` (output stage), `instr-leak-egress` (prompt stage, only on text marked as
   leaving the device) and `instr-leak-upload-ref` (prompt stage, by path: `curl -d "$(cat CLAUDE.md)"`,
   `-F @AGENTS.md`, `gh gist create`, `scp`, `aws s3 cp`, …). The files are those listed in
   [`data/instruction-files.js`](../data/instruction-files.js) — Claude Code (`CLAUDE.md`,
   `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules/`, managed policy), Codex (`AGENTS.md`,
   `AGENTS.override.md`), Gemini (`GEMINI.md`), Copilot (`.github/copilot-instructions.md`,
   `.github/instructions/`), Cursor (`.cursor/rules/*.mdc`, `.cursorrules`), Windsurf and Cline. Each is
   fingerprinted as at most 2,048 keyed 40-bit hashes of its 7-word shingles in
   `~/.moorai/instruction-fp.json`, key in `~/.moorai/instruction-fp.key` (both 0600); only hashes are
   kept, never text. Wired on the write family (a write into the rules file itself is excluded), `Bash`
   commands that upload or name a host, `WebFetch` and MCP arguments; `PostToolUse` content is inbound and excluded. Report-only by
   default; coached on unenrolled devices.

   **Limits.** A paraphrase, translation or hex encoding is not matched. A staged copy
   (`cp CLAUDE.md /tmp/x`, then an upload) is not tied back. A rules file with fewer than 40
   distinctive shingles can never fire. `mcp-proxy`, the desktop app and the browser extension register
   no fingerprints; only the path-based detector runs there.

11e. **MCP server reputation** — a 0-100 score for an MCP server the first time it is seen, and again
   when its version changes ([`cli/mcp-reputation.mjs`](../cli/mcp-reputation.mjs),
   [`data/mcp-reputation.js`](../data/mcp-reputation.js)). Bands: good ≥ 80, fair ≥ 60, poor ≥ 35,
   bad. Scored offline from the package name, the launch command and the copy npx already installed;
   `mcpReputation.lookup: "registry"` and `mcpReputation.feed` (SkillTriage's published verdicts,
   downloaded whole) are opt-in and run in the MCP proxy. Cached per server and version. The alert
   (`MCP: server reputation`) carries the score, band and reason codes only, and is posted when the band
   is below good. `mcpReputation.blockBelow` refuses a server below the threshold on an enrolled device
   and coaches on an unenrolled one; `enabled: false` turns it off. `moorai-aibom` and `moorai-shadow`
   carry the reputation per server. Signals:
   [`mcp-proxy/README.md`](../mcp-proxy/README.md).

   The opt-in registry lookup also checks the **repository link**
   ([`cli/mcp-repo-link.mjs`](../cli/mcp-repo-link.mjs), [`data/repo-link.js`](../data/repo-link.js)):
   registry provenance first (npm `dist.attestations`, PyPI Trusted Publishing) compared with the
   declared repository, otherwise the repository's own manifest on github.com or gitlab.com must name the
   same package (up to 6 monorepo folders tried). `repo-mismatch` (30), `repo-unreachable` (15),
   `repo-missing` (5); a timeout, 5xx, 429 or an unreadable host is evidence only, never a signal. 4 s per
   request, 10 s and 12 requests in total, redirects only within the registries, github.com and
   gitlab.com, public names only. **Limits.** Sigstore signatures are not re-verified. It compares
   against `HEAD`, so a renamed package reads as a mismatch. bitbucket.org and codeberg.org are not
   verified.

   **Mirrors and offline.** The lookup's hosts follow `MOORAI_NPM_REGISTRY`, `MOORAI_PYPI_URL` (the JSON
   API at `pypi/` under it), `MOORAI_MCP_REGISTRY`, `MOORAI_GITHUB_RAW_URL` and `MOORAI_GITHUB_CODELOAD_URL`
   ([`cli/mcp-package/endpoints.mjs`](../cli/mcp-package/endpoints.mjs)): https only, no credentials,
   query or fragment. An invalid value disables that endpoint instead of falling back to the public
   host. With a mirror set, artifacts must come from the mirror's own host. `MOORAI_OFFLINE=1` skips the
   lookup (evidence `registry-not-checked-offline`, not cached, so it runs once the device is online) and
   the feed download (the copy on disk is used). There are no policy keys for mirrors: the variables are
   read from the proxy's environment under the trusted-environment rule, so a value that a user, project
   or local settings file sets in its `env` block, including `MOORAI_OFFLINE`, is ignored: a cloned
   repository cannot point the lookup at a mirror that vouches for a malicious package, or switch it off.
   Set mirrors in the launching environment or in managed settings. github.com and gitlab.com repository pages have no mirror. The
   SkillTriage feed has no signature, so it is fetched from a URL only and no local snapshot file is
   accepted. Registry metadata and artifact requests give up after 30 s without headers or body progress.

   The same lookup counts the **accounts that can publish** the package
   ([`cli/mcp-package/maintainers.mjs`](../cli/mcp-package/maintainers.mjs)): npm's top-level packument
   `maintainers` ("people with permission to publish this package; not authoritative but informational")
   or PyPI's `ownership.roles` (Owner / Maintainer users). Exactly one is `single-maintainer` (5): a weak
   signal, since 127 of 238 listed npm servers and 67 of 85 listed PyPI servers with roles have one
   (measured 2026-10-09), so on its own a server stays good. The accounts are counted and dropped: no
   name, username or email is cached or reported. Only the count is kept (see the device report's `pkg`
   below). Same 4 s request timeout and per-version cache as the rest of the lookup; an error gives no
   signal. **Limits.** PyPI's free-text `author` / `maintainer` fields are not used. A
   PyPI project owned by an organization is never called single-maintainer, because team access is not
   listed in `roles`; an empty `roles` list is unknown. npm calls its list informational, and whether it
   includes npm-organization team members is not documented.

   **Package details in the device report (`pkg`).** Each MCP server in the desktop host's device report
   (`mcp[]`, stored by the console as `mcp_servers`) carries
   `pkg: { eco, name, version, pinned, maintainers, maintainersOrg, scan }` so the console can show
   single-maintainer, unpinned, package-version and package-scan data. `eco` is `npm`, `pypi`, `docker`,
   `local` or `other`. `name` is the registry package name (214 characters or fewer). `version` is the
   version spec as configured (64 characters or fewer: `1.4.2`, `^1.4`, `latest`), or null when there is
   none. `pinned` is true only for an exact version (npm `1.4.2`, PyPI `==1.4.2` / `@1.4.2`) or a docker
   `@sha256:` digest; a tag or range is false, and a local or remote server is null. `maintainers` /
   `maintainersOrg` are the registry maintainer count and organization ownership above. `scan` is
   `{verdict: clean|warn|block, findings}` from the reputation score when the package's code was read
   (the installed npx copy, or the opt-in registry artifact). The bands map as good to clean, fair or poor
   to warn, and bad to block. `findings` are reason codes from a fixed vocabulary
   ([`data/mcp-pkg-findings.json`](../data/mcp-pkg-findings.json): the reputation reasons and package
   heuristic ids) or `threat-<n>`, 32 at most. Unknown codes are dropped.

   It is content-free. `pkg` is derived on the device from the launch config (npx / uvx / pipx / docker
   arguments, parsed locally) by [`src-tauri/src/mcp_pkg.rs`](../src-tauri/src/mcp_pkg.rs). That module
   mirrors [`cli/mcp-package/pkg-report.mjs`](../cli/mcp-package/pkg-report.mjs), and both are held to the
   shared fixtures `test/fixtures/mcp-pkg-cases.json` and `mcp-pkg-cache.json`. The command, its arguments,
   env, paths and URLs are never sent. A local script or file package is `eco: "local"` with `name: null`.
   A URL, git, alias, inferred (`python -m`) or remote server is `eco: "other"` with `name: null`. A
   docker image on a registry other than Docker Hub, ghcr.io, quay.io, gcr.io, mcr.microsoft.com,
   public.ecr.aws, registry.gitlab.com or registry.k8s.io keeps no name or tag. A digest reference sends
   the whole reference (`repo[:tag]@sha256:<hex>`) as `name`, with `version: null`. A name or version never
   contains whitespace, a backslash or `://`, and never starts with `/` or `.`. A version may start with
   `~` (`~1.4.2`, `~=1.4`, both `pinned: false`); a name may not. A spec with whitespace (`1.x || 2.x`) is
   sent with `version: null`. Every field is validated and bounded on both sides, and again when the cache
   is read back. The reputation score's `unpinned-version` reason uses the same exact-version rule, so
   `latest`, `^1.4` and `~1.4` raise it too.

   The maintainer count and scan verdict live in `~/.moorai/mcp-pkg.json`, keyed per `eco:name@version`.
   Each value has a 7-day TTL, a day of future clock skew at most, and 512 entries at most. The verdict is
   written whenever the reputation path scores a server (also on the hook path, which stays offline). The
   count is written by the opt-in registry lookup (`mcpReputation.lookup: "registry"`, proxy only). Once
   it expires, the proxy refreshes only the count, with one registry metadata request. No new request is
   made on the hook path. **Limits.** Without the opt-in lookup, `maintainers` is null. A version range is
   not resolved, so the count and verdict are joined on the spec as configured. A docker tag is never
   counted as pinned.

11e2. **Pre-install MCP check** — `moorai-mcp-check <package>`
   ([`cli/moorai-mcp-check.mjs`](../cli/moorai-mcp-check.mjs),
   [`cli/mcp-package/check.mjs`](../cli/mcp-package/check.mjs),
   [`cli/mcp-package/check-items.mjs`](../cli/mcp-package/check-items.mjs)). Ten checks on a server
   before it is installed, each pass, warn, fail or not checked with a one-line reason, from registry
   metadata and published manifests only: the artifact is never downloaded or run, a remote URL is
   parsed and never contacted, and the reputation cache is not written. (1) publisher: the name lists,
   `mcp-typosquat`, `name-not-published` and the repository link (fail on a typosquat, an unpublished
   name or `repo-mismatch`; warn when the publisher cannot be verified); (2) age: warn under 30 days; (3)
   maintainers: warn on one; (4) npm `preinstall` / `install` / `postinstall` in the version manifest
   (fail when it fetches or pipes remote code, warn otherwise); (5) authentication and (7) credential
   names from the package's `server.json` on registry.modelcontextprotocol.io, found by its npm
   `mcpName` / PyPI `mcp-name:` and used only when it lists this package (warn on an HTTP transport with
   no secret, and on broad credentials: cloud secret keys, kubeconfig, admin / root / service-role keys,
   passwords, database URLs, private keys, seed phrases); (6) a remote endpoint must be HTTPS to a
   hostname, and is judged against `egressRules` / `egressDefault` when the policy has them; (8) tool
   descriptions through the tool-stage engine (#60 and #50 fail, other findings warn) when a tools/list
   JSON is supplied with `--tools`; (9) the spec pins an exact version (warn on none, a tag or a range);
   (10) a MoorAI hook is registered (pass), only some MCP servers go through the stdio proxy or gateway
   (warn), or nothing does (fail). Plus a metadata-only reputation score and band from the same weights,
   and the SkillTriage verdict when `mcpReputation.feed` is on. `--json`; exit 1 when a check fails.
   `--offline` (or `MOORAI_OFFLINE=1`) makes no request: (1) keeps its name checks and otherwise reports
   the repository link not checked, (2)–(5) and (7) and the feed report `not-checked (offline)`; measured
   0.08 s (10.1 s before on a host with no route out). The mirror variables of 11e apply; an invalid one
   exits 2. `moorai-scan --package` / `--packages` take the same `--offline`: each package is
   `not-checked (offline)` and REVIEW (fail-closed), in 0.08 s (10.6 s before).
   **Limits.** Age, maintainers, auth, credentials and pinning have no fail state. PyPI install-time code
   is not visible in its JSON API (not checked; an sdist-only release is noted). Auth, credentials and
   transport for a package need a published `server.json`. MCP OAuth is not probed. An npm semver range is
   not resolved (the latest version's manifest is read, and the reason says so).

11f. **Tool-result scanning** — what comes back into the agent after a tool runs. The Claude Code hook's
   `PostToolUse` matchers are `WebFetch`, `WebSearch`, `Bash`, `PowerShell`, `Agent`, `Task` and `mcp__.*`; the result
   (first 64 KB) is scanned at the `output` stage as inbound content. The tool has already run: a block
   only adds a reason next to the result, and the model still sees the original output. Default
   report-only, except an injection finding (#3, #40, #60), which asks; `ask` becomes advisory
   `additionalContext`; unenrolled devices coach. Results are resolved by `cli/inbound.mjs`, shared with the
   SDK, `moorai-serve`, the model proxy, the MCP proxy and the gateway: sign-off acts and output- or
   prompt-only threats are dropped, data-class findings are reported at `Info`, `ingest-agent-directed` (#40)
   flags an instruction aimed at the agent, and on `Bash`/`PowerShell`, MCP and sub-agent results the
   generated-code threats (#44, #52, #54, #61, #62, #76) are dropped too and the #15/#17 gates are
   narrowed. Sub-agent results are judged on their report only. **Limits.** Output past 64 KB
   is unscanned; `cat .env` reports at both `PreToolUse` and `PostToolUse`;
   the Codex, Copilot, Gemini and Cursor adapters forward only web results; recall figures are
   in-sample. [DETECTION_ENGINE.md](DETECTION_ENGINE.md) §6–7.

11g. **Credential paths in MCP tool descriptions** — `mcp-tool-cred-path`
   ([`data/tool-credpaths.js`](../data/tool-credpaths.js)), `tool` stage, *Threat 60.* Fires only when a
   description or schema tells the model to read or move a credential file's content into a call, and
   stays silent on a negated verb, a capability infinitive, the server describing itself, the path as a
   destination, and public keys or certificate PEMs. Its #60 finding feeds the server's existing
   `tool-poisoning` reputation signal.

11g2. **MCP tool drift: block until re-approved** — policy `mcpToolDrift: "alert" | "block"`
   ([`mcp-proxy/tool-drift.mjs`](../mcp-proxy/tool-drift.mjs)), in both the stdio proxy and the HTTP
   gateway. `"alert"` (default) is the earlier behaviour: description / schema drift and shadowing alert,
   and the tool baseline moves to the new value. `"block"` quarantines a tool whose description or schema
   changed, a tool added to a server that already has a baseline, and a tool name owned by another
   server: the tool is left out of the `tools/list` the client receives and its calls are refused
   (`reasonCode: "MCP_TOOL_DRIFT"`, alerts with `decision: "quarantine"`). A removed tool only alerts.
   The baseline does not move until an admin re-approves the server in the console, which pins the
   tools' content-free fingerprints (`fp2:` hashes in the `toolIdentity` shape, reported by the agent to
   `POST /api/mcp/tools`) and ships them inside the signed policy as `mcpToolBaselines[<server>] =
   { version, tools }`. The device prefers an approved baseline, else its first-seen one, and refuses an
   approved baseline older than the highest version it has accepted for that server. A quarantined tool
   is re-judged at call time, so a re-approval releases it without a re-list. **Fails open** when there is
   no verified policy or no approved baseline (the first listing of a new server is accepted);
   **fails closed** on a call to a tool from a listing it could not check (over 1 MB, never listed).
   In the gateway a response with no request ids (a GET or resumed SSE stream) can answer an earlier
   `tools/list`, and so can the response to any other POST while a `tools/list` the route forwarded is
   still outstanding (tracked per route, at most 1,024 for 5 minutes; one that expires or is evicted
   unanswered clears the route's verdicts). Such a response is decoded (`gzip`/`deflate`/`br`) and each
   message judged, and one that goes out unscanned clears the route's verdicts. Any message with a
   `result.tools` array is judged as a listing whatever its id. Ids are matched as the MCP SDK client
   matches them (`Number(id)`), and only a well-formed response the client would dispatch takes an
   outstanding `tools/list`; every other listing, a late duplicate for an id already answered included,
   is judged tighten-only: it can quarantine a tool but never clear one
   ([`mcp-gateway/README.md`](../mcp-gateway/README.md)).
   Paginated servers are judged page by page and cannot be pinned. A stale client is judged against a
   fresh listing ([`mcp-proxy/tool-recheck.mjs`](../mcp-proxy/tool-recheck.mjs)): in block mode, when the
   last whole listing judged for a server is older than the signed policy's `mcpToolRecheckSeconds`
   (default 300, 0 = before every call, an integer of at least 0, capped at 86,400), or the server sent
   `notifications/tools/list_changed`, a `tools/call` first makes the guard or gateway send its own
   `tools/list` upstream (every page; a nonce id no client can collide with; the answer never reaches the
   client; the gateway's request carries the client's session headers), judge it, and then forward an
   unchanged tool or refuse one that drifted or vanished. One re-list per server is in flight, shared by
   concurrent calls, within a 2 s budget; a failed or timed-out re-list follows `failMode.mcpGateway`
   (closed refuses, `failWhy: "recheck"`; open forwards with a `MCP: tool list re-check failed` alert).
   Alerts from a re-list carry `driftCheck: "recheck"`, and its fingerprints are not reported. Alert mode
   never re-lists. The full failure table is in
   [`mcp-proxy/README.md`](../mcp-proxy/README.md).

11h. **Event-triggered and headless prompts** — [`cli/prompt-scan.mjs`](../cli/prompt-scan.mjs). A
   prompt a person typed is their instruction and is not scanned; one that arrives any other way can
   carry a third party's text. `policy.promptScan`: `"untrusted"` (default) scans a prompt whose `source`
   is present and not `user` (`sdk`, `system`, `poll_event`, `schedule_wakeup`, `loop_wakeup`) and every
   prompt in server mode; `"all"`; `"off"`. A prompt with no `source` (older Claude Code, the other
   agents' adapters) counts as typed. Scanned at stage `file` with `inbound: true`, reported at stage
   `prompt`, tool `hook:UserPromptSubmit`, with `promptOrigin` (`person` / `event` / `server`) and
   `promptSource`; always content-free, even under `full-capture`; cut at 64 KB (the ledger records the
   cut). `policy.promptScanAction`: `"report"` (default; prints nothing, because stdout on this event
   enters the model's context) or `"block"`, which blocks with a reason naming the threats, never quoting
   the prompt. Only instruction-carrying threats (2, 3, 21, 22, 25, 40, 50, 51, 60, 68, 70, 72, 74) or a
   finding whose configured action is block / kill block; PII and secrets report only. An unenrolled
   device never blocks; it shows a `systemMessage`. **Measured** (`promptScan: "all"`): benign-v2 21/602
   flagged, 6 would block; benign web content 97/311 flagged, 33 would block; Arabic 0/174, Russian
   0/180, Hebrew 16/179 (13 are #41). As event prompts: vector-2 27/45 (18 block), vector-5 22/25 (21
   block). p50: a `poll_event` prompt 170 ms scanned, 128 ms unscanned; a typed prompt 109 ms. **Limits.**
   Prompt findings do not feed session risk, the lethal trifecta, behaviour logging or model escalation.
   Not observed in a live Claude Code session.

### C. Runtime (client)
12. **Risk-prioritized alerting** — ranks findings by `riskLevel`, then `riskScore` as the tiebreak.
13. **In-context guidance** — surfaces the matching `response` + a source link.
14. **Local audit log** — on-device record of detections/decisions.
15. **Redacted alert reporting** — sends redacted alerts to the server (metadata only).
16. **Policy pull** — fetches allowlist/thresholds/rule-base from the server; offline-tolerant.
17. **Privacy-preserving** — inspection is local; only redacted metadata leaves the device.
17a. **Self-check and explain** — `moorai-doctor` reports whether MoorAI is registered in each agent
    host (compared with what the current installer writes; for Claude Code, in `settings.json` or as
    the `moorai` plugin, whose installed `hooks/hooks.json` is compared the same way, and a warning when
    both are present), whether Claude Code managed settings allow its hooks (a managed hook or a
    force-enabled `moorai@moorai` plugin under `allowManagedHooksOnly`), enrollment, console reachability, which policy is enforced and whether its signature
    verifies, posture, break-glass and state-file modes, and runs the real hook on a benign and a
    known-bad `Bash` command in a temporary copy of the state; read-only, exit 1 on any failed check.
    In server mode it also shows each setting's source (the token as a fingerprint), the headless-ask
    mapping, the workload identity and any refused settings-file name, and the self-test adds a
    credential read to check the headless answer.
    `moorai-explain` runs one string through the hook's engine and policy and shows each finding, the
    detectors dropped by their `refine` gate or by policy, the decision and the safer alternative; local
    only, engine and policy only. **Limits.** Claude.ai server-managed settings and Windows registry
    policy are not checked; the self-test covers the `Bash` `PreToolUse` branch only.
17b. **Lifecycle hooks, session ledger and claimed success** — the Claude Code hook also registers
    `PostToolUseFailure` (`Bash`, `PowerShell`, `mcp__.*`), `Stop`, `SubagentStop` and `PreCompact`
    (matcher `""`). Visibility only: they never block a stop or a compaction and print nothing the model
    reads (an unenrolled device shows the user a `systemMessage` at `Stop` when the claim check fires).
    Every hook run writes one content-free, chain-stamped row to `~/.moorai/session-ledger.jsonl`
    ([`cli/session-ledger.mjs`](../cli/session-ledger.mjs)), ids hashed under a device-local
    `session-ledger.key`, trimmed past about 1 MB. At `Stop` the console gets an `Agent session summary`
    (counts) when they changed, with `contentHash` `summary:<session>`. Every alert a hook run posts carries
    that same `<session>` as its `session` field (the tenant-keyed hash of Claude Code's `session_id`), so
    the console can group a session's alerts under its summary; no session id, no field. Tested through the
    real hook process in [`test/session-correlation.test.mjs`](../test/session-correlation.test.mjs). At `Stop` / `SubagentStop`, [`cli/claim-check.mjs`](../cli/claim-check.mjs)
    compares `last_assistant_message` (read in memory, never stored or sent) with the turn's recorded
    outcomes and posts `Agent reported success but tool calls failed` (Medium, `CLAIM_MISMATCH`) when the
    message claims success while tool calls failed, were denied or were interrupted and were not redone.
    A claim counts only against a failure of its own kind (verify, effect, edit or any). Report-only.
    **Measured** on a 181-case corpus labelled by agents that never read the detector, split 60/40 by a
    fixed seed before any detector output was seen: on the locked split, scored once, 100% precision (17
    of 17) and 54.8% recall (17 of 31); the v1.1.0 75-case corpus is kept as a regression set (92.3% /
    80.0%). `PreCompact` records that compaction happened.
17c. **Session-level escalation and the runaway circuit breaker** —
    [`data/session-risk.js`](../data/session-risk.js): taint (an injection-class finding on ingested content,
    then an outbound action or credential-file read within `windowMin` → #59 `Agent behavior: outbound
    action after untrusted content`), sequences within `seqSteps` (staged credential → outbound; archive →
    outbound; mass read → an upload of 4 KB or more to a new destination), slow exfiltration (5 or more
    transfers of up to 8 KB to one destination summing 16 KB or more), and a decaying score with a threshold
    alert. `policy.sessionRisk.mode` `report` (default) | `ask` | `off`; defaults threshold 12, `windowMin`
    30, `halfLifeMin` 15, `seqSteps` 10, `massReads` 30. [`data/circuit-breaker.js`](../data/circuit-breaker.js):
    the same call 15 times in 5 minutes with an unchanged result, or a 2–4 call cycle repeated 5 times
    unchanged → #38 `Agent behavior: runaway loop`; optional `ratePerMin` / `maxCalls`, off by default (a
    simulation could not separate a fast sub-agent from a runaway by rate); keyed per session and
    `agent_id`. `policy.circuitBreaker.mode` `report` (default) | `deny` (pauses the session for
    `cooldownMin`, default 15) | `off`. Token burn is not measured: no hook input carries usage. State in
    `~/.moorai` under a device-local `session.key` (0600): keyed hashes and counts only, 32 sessions, 24 h.
    **Measured** on scripted sessions: test-fix and build-watch loops raised no alert; runaway loops 3/3.
17d. **Verdict provenance** — [`cli/provenance.mjs`](../cli/provenance.mjs) stamps every alert and ledger
    row with `policyId` (`pol:<tenant>:<iat>:<digest12>`, `pol:unsigned:<digest12>`, `builtin-defaults`,
    `offline-fail-closed-default`, `none`, `not-loaded`), `policySource`, `reasonCode` (the branch that
    decided; enum in the module, including the MCP gateway's `SCHEMA_INVALID`, `RESPONSE_TOO_LARGE` and
    `CLIENT_COOLDOWN`, and `MCP_TOOL_DRIFT` for a tool quarantined under `mcpToolDrift: "block"`), `basisCode` when an override decided, and `enforcement`
    `AS_CONFIGURED` | `STRENGTHENED` | `LIMITED` | `UNEVALUATED`. A control that never ran — bad stdin, a
    hook error, no policy after an error, break-glass, an unsupported tool, an empty result, a size cap —
    is `UNEVALUATED`, never a pass.
17e. **Coverage integrity, agent side** — [`cli/agent-posture.mjs`](../cli/agent-posture.mjs) (read-only,
    built on `cli/doctor-hosts.mjs`) reports per host — Claude Code, Codex, Gemini, Cursor, Copilot — the
    hook state, `lastActive` (hour-rounded), the host's `version` and whether it is `tested`, and
    weakened-setting flags: `hooksDisabled`, `mooraiHookDisabled`, `managedHooksOnly`, `bypassPermissionsDefault`, `sessionBypassPermissions`,
    `approvalNever`, `approvalUnrestricted`, `autoEditDefault`, `sandboxFullAccess`, `sandboxOff`.
    **Version:** [`cli/agent-hooks/host-version.mjs`](../cli/agent-hooks/host-version.mjs) compares it with
    [`data/host-versions.json`](../data/host-versions.json); `tested` is true only when the numeric version
    matches the tested one exactly (a build suffix such as Cursor's `-fe9a6e2` is ignored), so older, newer
    and unknown versions are all untested. The version
    comes from the first source that gives one: (1) the calling host's hook env — Claude Code `AI_AGENT` =
    `claude-code_<v with dashes>_<source>` (undocumented; measured on 2.1.284), Cursor `CURSOR_VERSION` —
    read only for the host that is calling, because hook env is inherited by child processes; (2) a PATH
    probe that does not run the binary; (3) one cached `<bin> --version` with a 3-second timeout, run only
    in the heartbeat worker. None of this runs on the verdict path. The console drops `version` and
    `tested` on ingest (`sanitizePosture` whitelists host fields) until console v0.73.0, in progress. The hook
    sends a content-free heartbeat with this posture to `POST /api/agent-posture` at most once per host per
    UTC day (retried after 10 minutes on failure); enrolled devices only. The desktop app reports each
    host's last activity hourly (`device_agent_activity`), independent of every hook.
    **Containment (Windows only):** [`cli/mxc-detect.mjs`](../cli/mxc-detect.mjs) adds
    `containment: { kind: "mxc"|"other"|"none"|"unknown", scope: "commands"|"agent"|null, source }` to the
    Claude Code, Codex and Copilot entries, and `mxcCapable: true|false|null` to the report. Sources are
    a fixed list of tokens, such as `codex:windows.sandbox` and `copilot:unset`.
    - Codex: `windows.sandbox`, read from the user and project `config.toml`, with the project file
      winning. `"mxc"` gives `"mxc"`; `elevated`/`unelevated` and the legacy features give `"other"`;
      `danger-full-access`, `allow_mxc = false` or nothing set give `"none"`; `features.prefer_mxc` gives
      `"unknown"`.
    - Copilot CLI: `sandbox.enabled` in `~/.copilot/settings.json`. `true` gives `"mxc"`, `false` gives
      `"none"`, and unset or unreadable gives `"unknown"`.
    - Claude Code on win32: `"none"`.
    - Gemini and Cursor: no field. Non-Windows: neither field.

    `mxcCapable` is the build (`os.release()`) plus the registry `UBR`, compared with 26100/26200.9278,
    26300.9550 and 28000.2804. The heartbeat worker reads it with `reg.exe` and caches it for about a day
    per release. It is `null` for unlisted builds or a missing value. The hook reads it too, uncached,
    under `containmentRequired: "block"` (v1.18.0, see "Windows: requiring MXC for agent commands").

    Detected vs assumed:
    - The values come from config. Nothing observes a running container, and MXC documents no way to.
    - CLI flags, Codex profiles and enterprise-managed settings can override the config.
    - A capable build may still have MXC switched off by Microsoft's gradual rollout.
    - Codex and Copilot contain only the commands the agent runs, not the agent.

    The detection is report-only, fails open and changes no verdict. Enforcement is opt-in through
    `containmentRequired` / `containmentClaudeCode` (v1.18.0, "Windows: requiring MXC for agent commands").
    Not run on a real Windows host yet.
17f. **Declared workload profiles** — [`cli/workload-profile.mjs`](../cli/workload-profile.mjs). The signed
    policy may carry `workloadProfiles`: per workload (`match.serviceId`) or repository (`match.repo`, the
    normalised git remote of the call's cwd), the expected `tools`, `mcpServers` and `hosts` as allow-lists
    with `*` globs (an omitted list does not constrain; an empty one allows nothing; loopback is always in
    profile). On `PreToolUse`, a call outside the first matching profile raises a content-free
    `PROFILE_DRIFT` alert (`driftKind` tool | mcpServer | host, `driftItem`, `profileId`); `action: "block"`
    denies it, with a reason that names only the profile id and the kinds. Unenrolled devices coach and
    never block. Profiles come only from the verified console policy and the root-owned machine-wide
    config; a repository file, a settings-file `env` block, `~/.moorai/config.json` or the environment
    cannot supply one. Malformed profiles are ignored and reported once a day (the SDK: once per policy
    object). Evaluation never throws; an error allows. The hook, `@moorai/agent-sdk` and `moorai-serve`
    evaluate the same profile (parity test: 3 cases × 214 payloads, 0 mismatches), and so does the HTTP MCP
    gateway on every `tools/call`, naming the tool `mcp__<route>__<tool>` as the hook does (kinds `tool` and
    `mcpServer`). **Limits.** A repo match
    follows `.git/config`, which the agent can edit, and a hook `serviceId` taken from
    `~/.moorai/config.json` is agent-writable too; a `serviceId` from the system file or the launching
    environment is the match to rely on for a block. Hosts built at runtime are not seen. `PostToolUse`,
    prompts and `Stop` are not compared. The HTTP MCP gateway does not compare hosts. Tested on macOS
    only.
17g. **Egress rules** — [`cli/egress-rules.mjs`](../cli/egress-rules.mjs), evaluated inside
    `evaluateProfile()`. `egressRules: [{ id?, binary?, host | cidr, port?, method?, path?, action }]` and
    `egressDefault`, with `action` one of `allow`, `alert` or `block`. They can sit at the top level of the
    verified console policy or the root-owned machine-wide config, where they apply to every call, or
    inside a workload profile, where they apply when it matches and are read first. `host` is an exact
    name or `*.suffix`. `cidr` replaces `host` (exactly one of the two, else "host or cidr is required, not
    both"): one prefix or a list of up to 64, `a.b.c.d/n` (0-32) or IPv6 `x::/n` (0-128), normalised to
    network form; host bits set are refused ("cidr has host bits set"), `/0` only with `alert` or `block`, and
    an IPv4-mapped prefix (`::ffff:0:0/96` and longer) is the IPv4 prefix. From a call's text a cidr rule
    matches a target whose host is an address inside the range (IPv4, IPv6 with any zone id `%eth0` /
    `%25eth0` set aside, IPv4-mapped IPv6 read as IPv4, numeric IPv4 spellings WHATWG reads as an address;
    an address `net.isIP` accepts that the range parser cannot read matches `alert` and `block` cidr rules,
    never `allow`), including an unbracketed IPv6 `ssh` destination; a host name never matches it there (the hook does no
    DNS), a stated exception to the unknown-field rule. Network-layer surfaces judge the resolved connect
    address (below). Cidr rules are refused inside a workload profile ("cidr rules are not accepted inside a
    workload profile"): an agent older than 1.28.0 drops a whole profile that carries an unknown key, while a
    top-level rule it does not know is dropped alone (CONTRACT-F28 6.1). `binary` is the command word, or for a non-shell call the tool name. `path` is
    `/exact` or `/prefix*`. The first matching rule decides. With no match, the default applies, and
    loopback is allowed. An `allow` rule never matches a key the destination does not know, such as the
    method of `git clone` or the path of `ssh`. An `alert` or `block` rule does. On `PreToolUse`, the hook,
    `@moorai/agent-sdk` and `moorai-serve` read the destinations a Bash or PowerShell command, a WebFetch
    or an MCP call names. For a command, that means its URLs, the scheme-less hosts given to HTTP clients,
    and ssh, scp, rsync, git and nc hosts, along with the method curl, wget, httpie and Invoke-WebRequest
    would use. Nested scripts are read too: `sh -c`, `-EncodedCommand`, `$( … )` and `find -exec`.
    `alert` and `block` post a content-free `EGRESS_RULE` alert with the binary, host, port, method and
    deciding rule, never a path or query. `block` denies the call, and an unenrolled device coaches
    instead. Where curl and WHATWG URL disagree on a host, both hosts are judged. A call that names more
    destinations than can be judged gets the strictest action in force. Hook/SDK parity is 214 payloads
    with 0 mismatches. **Limits.** Only destinations written in the call are judged. The binary is the
    command word, not the socket's process. A URL that is only printed still counts. The HTTP MCP gateway
    (`mcp-gateway/profile.mjs`, the call's arguments passed to `evaluateProfile`) and the MCP stdio proxy
    (`evaluateEgress`, the egress half of `evaluateProfile`) judge the destinations a `tools/call`'s
    arguments name for `mcp__<server>__<tool>` by the same function as the hook, so a block on
    `10.0.0.0/8` refuses the same call in all three (`test/mcp-gateway-egress.test.mjs`,
    `test/mcp-guard-egress.test.mjs`). The gateway also judges its own connection to each remote server
    (`mcp-gateway/egress.mjs`): by name, port, method and path before the request is sent, and with a cidr
    rule in force on every address the socket's DNS lookup returns, refusing in the lookup so the socket
    only connects to a judged address (a reused keep-alive socket was judged when it connected). A blocked
    upstream is refused before the `tools/call` gate, so the block-mode tool re-list never reaches it. Tested
    on macOS only.

### D. Central server
18. **Policy & rule-base distribution** — central allowlist, thresholds, per-threat/per-tier
    enforcement actions, and versioned rule-base pushed to clients.
19. **Alert ingestion** — receives and stores redacted client alerts.
19a. **Account signup + device claim** — `POST /api/signup` with `claim: true` creates the tenant,
    mails the verification link, and returns a single-use claim token valid for 30 minutes. The
    client then polls `GET /api/signup/claim?claim=<token>` — `202` until the link is clicked, then
    one `200` carrying the tenant, the install token and the server URL, after which the claim token
    is dead. The client sends the claim token and nothing else: a claim-by-email lookup would be an
    unauthenticated account-enumeration oracle. Protocol in [`src/signup.js`](../src/signup.js);
    the ready claim is handed to the same `enroll()` the paste-a-token path uses, so provisioning
    lives in one place.
19b. **Coverage integrity, console side** (console v0.70.0) — stores each device's agent posture from
    `POST /api/agent-posture` and raises three content-free findings: `Coverage: agent active, no MoorAI
    hook traffic` (a host in use with no heartbeat covering that moment, found by a sweep after a grace
    period; server-mode workloads excluded), `Coverage: agent setting weakened` (a flag that appears;
    `sandboxOff`, a host default, only on a transition), and `Coverage: MoorAI hook removed or stale`.
20. **Security dashboard** — org-wide risk view: alerts by threat / category / risk tier / user,
    trends over time. The dashboard itself is **visibility**; enforcement happens on the client,
    driven by the policy this server distributes.

## Intervention tiers (policy-driven)

The action comes from policy, not from the risk level alone — `threatActionFor` resolves
per-threat → data-tier → **built-in prevention tier** → approval-set → `notify`.

- **`notify`** (the default for a threat none of the earlier tiers name) → prominent inline warning +
  the matrix's defensive-response text; the call proceeds and the finding is logged + reported.
- **`justify`** → surfaced as Claude Code `ask`: the developer must acknowledge/justify before the
  call proceeds (logged + reported). Built-in default for threats **55, 56, 57, 63, 44, 73**; approval-set
  default for **11, 43, 46, 47, 48, 49**.
- **`block`** → Claude Code `deny`; the tool call does not execute. Built-in default for threat **54**
  (reverse shell / RCE) and **65** (local secret-value egress).
- **`kill`** → denies the call *and* terminates the session (`killSession`). `killOnCritical`
  promotes any Critical `block` to a `kill` without per-threat configuration.
- **`mask`** → the matched span is replaced with `[MOORAI:<tier>:<8 letters>]` (from the keyed content
  hash; no part of the value survives), the rewritten text is re-scanned, and the call proceeds. Set per
  threat or per data tier, for the data-tier threats **15, 39, 1, 44** only, and applied only by span
  detectors. The Claude Code hook rewrites the `Bash` and `PowerShell` command, the write family's new content, the
  `WebFetch` url and prompt, MCP argument strings and the `Task` prompt through `PreToolUse`
  `updatedInput` (with no permission decision, so it never auto-approves), and the seven post-tool results
  through `PostToolUse` `updatedToolOutput`. Anywhere it cannot rewrite — `Read`, files a shell command
  reads, files an MCP call's arguments name, the other agents' adapters, Cursor's renamed tools, an unenrolled device, a failed re-scan, a
  value over 256 KB, and the MCP proxy and `claude -p` guard — the threat
  resolves to `policy.maskFallback` (`notify`/`justify`/`block`), else to its action without the mask
  entry. Each mask posts a content-free `Sensitive span masked` alert. **Limits.** Not yet observed in a
  live Claude Code session; another hook's `updatedToolOutput` can override it (the last one wins); the
  desktop app's own resolver treats `mask` as report-only; the console policy editor may not offer it
  yet.

**The built-in prevention tier** (`BUILTIN_DEFAULT_ACTIONS`, [`cli/hook-core.mjs`](../cli/hook-core.mjs))
is what an **enrolled** device stops with no organisation policy at all. It exists because the measured
truth before it was *prevention 0% out of the box* — the hook returned early on the fail-open posture and
`threatActionFor` was never consulted, so a device with no policy detected a reverse shell and let it run.
An **unenrolled** device runs the same tier but coaches instead of enforcing (see
[DETECTION_ENGINE.md](DETECTION_ENGINE.md#enrollment-is-the-line)).

Promotion is evidence-bound: an entry had to fire on **zero** benign samples across 890 benign prompts,
*and* the corpora had to actually exercise that detector's stages — otherwise "0 benign fires" is a
measurement artifact. Threat 60 looked like the strongest candidate by fire counts and was rejected on
exactly that ground. Threats 43, 39, 15, 2, 3, 40 and 50 did not clear the bar and were deliberately not
promoted. `block` is reserved for threats with no legitimate developer reading whatsoever; everything
high-harm with an everyday variant gets `justify`, so the call is halted for a human rather than killed.

**One documented exception.** On the **write path only**, threat 65 resolves to `justify`/ask rather than
`block` — copying `.env` → `.env.local` is routine and no benign corpus measures it, so the evidence that
justified the hard deny elsewhere does not exist here.

An org policy still wins in **both** directions, because `threatPolicy` / `tierPolicy` are consulted
before this tier: a tenant can soften any entry to `notify`/`disabled` or harden one the map omits.

## Windows: launching agents inside MXC (wxc-exec)

**Status: code and unit tests only. Nothing here has run on Windows.** Opt-in, default off. Contract:
microsoft/mxc @ 7cd00d1 (schema `1.0.0`). Files: [`src-tauri/src/mxc_launch.rs`](../src-tauri/src/mxc_launch.rs)
(detection, probe, spawn, denials → alerts), [`src-tauri/src/mxc.rs`](../src-tauri/src/mxc.rs) and
[`cli/mxc-policy.mjs`](../cli/mxc-policy.mjs) (policy builder, Rust and Node), [`src-tauri/src/mxc_denials.rs`](../src-tauri/src/mxc_denials.rs)
and [`cli/mxc-denials.mjs`](../cli/mxc-denials.mjs) (denial parser). The Rust and Node copies replay the same
golden files in `test/fixtures/mxc/`.

**Why wxc-exec.** BaseContainer starts a process through `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`.
portable_pty 0.8 holds one proc-thread attribute (the pseudoconsole), so MoorAI cannot pass it. Instead the
PTY runs `wxc-exec.exe`, and wxc-exec creates the contained child. This is how macOS `sandbox-exec` works,
and how MXC's own Node `spawnWithPty` handles ProcessContainer (mxc PR #1400). The real flags, from the mxc docs:
`--config <file>`, `--log-file <file>` and `--probe`. There is no `--policy` flag. The `--log-file` log is not
content-free: it holds the whole policy, including every granted and denied path and the command line; only env
values are redacted. It is written to the host-only run dir, next to `policy.json`, and deleted with that dir unless
`keepRuns` is set.
The agent command goes in `process.commandLine`, built and quoted by MoorAI using MSVC argv rules. It is not
passed after `--`, because how wxc-exec joins that tail is not in the published docs.

**Launch sequence (term_open).**
1. Read `%LOCALAPPDATA%\MoorAI Host\mxc.json`. If it is missing, MXC is off.
2. Build check: process isolation needs build 26100.9278, 26200.9278, 26300.9550 or 28000.2804. A build the
   table does not list is left to the probe.
3. Find `wxc-exec.exe`. It must be under Program Files or the MoorAI install directory, and Authenticode-signed
   with `O=Microsoft Corporation`.
4. Check that moorai-model-proxy answers on loopback. This applies to claude and codex. Copilot instead needs a
   numeric `egressAllow`.
5. Write the policy and run `wxc-exec --probe --config`. The tier must be `base-container`, and host-loopback
   allow must be supported. If the host lacks native FS deny or native denial capture, MoorAI rebuilds the
   policy without them and probes once more.
6. Spawn `wxc-exec --log-file <run>\audit.log --config <run>\policy.json` in the PTY. Then assign it to a Job
   Object that does not set `UILIMIT_HANDLES`/`GLOBALATOMS`, because nested job UI limits add up and would
   undo the PowerShell relaxation. The job is kept only if the assignment succeeded; otherwise it is closed
   and the session has no job.

Before step 2, the previous session in the terminal is stopped: its PTY child is killed and its Job Object
terminated (`TerminateJobObject`). The launch waits up to 5 s for the child to exit and the job to report
no active processes. If either is still running, the launch is refused. An MXC-contained previous session
with no job (not created, or wxc-exec not assigned to it) or a job whose process count cannot be read counts
as still running: wxc-exec can exit while the contained agent lives on, so nothing proves it gone. The
launch is then refused after the wait, saying the previous contained session cannot be confirmed stopped
(`mxc_launch::prior_running`). That lasts until MoorAI restarts, because the record of the previous
session is in memory only. A contained agent from that
session could otherwise swap a checked `ensureDirs` entry for a junction between the check and the spawn.
Right before step 6, every `ensureDirs` entry is checked again (`recheck_dirs`). If one is no longer a
plain directory, the launch is refused; this is never downgraded to the Job Object fallback. With MXC
off, neither step runs.

If any step fails, the agent is **not launched**: the terminal shows the reason in red and how to allow a
fallback. Some failures are under the contained agent's control (for example a file it planted where
`~/.moorai/agent-tmp` goes), so a failed plan never quietly drops isolation. Only `"fallback": "job-object"`
in `mxc.json` (default off, exact string) launches the agent with today's Job Object instead, with the
reason printed in yellow. Turning MXC on also turns the Job Object on for that fallback. With MXC off,
nothing changes.

Each `ensureDirs` entry (`~/.moorai`, `%APPDATA%\MoorAI`, `%LOCALAPPDATA%\MoorAI`, `~/.moorai/agent-tmp`, the
agent's state dir) must be a plain directory before and after the host creates it. A file, a symlink, a
junction or any other reparse point there, or a path the host cannot inspect, fails the plan.

**Policy.**

| Part | Value | Why |
|---|---|---|
| read-write | The workspace, the agent's own state (`~/.claude` + `~/.claude.json`, `~/.codex`, `~/.copilot`) and the hook's three state legs (`~/.moorai`, `%APPDATA%\MoorAI`, `%LOCALAPPDATA%\MoorAI`) | The agent and MoorAI's in-container hook can't run without them. The profile root is never granted. |
| read-only | Agent binary dir, `~/.local/share/claude`, node dir, `Program Files\{nodejs,Git,PowerShell\7}`, `~/.gitconfig`, `%ProgramData%\MoorAI`, verified hook roots, CA files | The toolchain the agent shells out to. Windows' own directories are already readable through ALL APPLICATION PACKAGES ACEs. |
| denied | Startup folders, scheduled tasks, shell profiles, DPAPI/credential stores, `.ssh`, cloud and package credentials, browser profiles, `%LOCALAPPDATA%\MoorAI Host`, the host install dir | Mirrors the macOS Seatbelt deny-list (persistence and credentials). Every path is listed when the probe reports native FS deny. Otherwise only paths under a grant are listed: an explicit deny would push MXC to the DACL tier, which `allowDaclMutation:false` refuses. |
| network | `egress.default: deny`, `ingress: {default: deny, hostLoopback: allow}`, optional numeric `egressAllow` on tcp/443 | `moorai-model-proxy` is a base-URL reverse proxy, not a CONNECT proxy, so it cannot be `runtimeConfig.networkProxy`. The agent reaches it on loopback through `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`. MXC rules are numeric only, so a hostname needs a CONNECT proxy. In direct mode, host loopback is not port-scoped. |
| UI | `ui.disable:false`, clipboard `none`, injection off; `processContainer.ui.isolation: "desktop"`, the rest at default-deny | PowerShell 5.1 and 7 fail with `STATUS_DLL_INIT_FAILED` under the default limits. `isolation: "desktop"` is the documented fix (playground-limitations.md). AppContainer's low integrity level still keeps UIPI between it and medium-IL windows. |
| fallback | `allowDaclMutation: false` | MoorAI never rewrites host ACLs. A host without BaseContainer fails the launch instead of degrading. |
| env | `TEMP`/`TMP` = `~/.moorai/agent-tmp`, which MXC overrides; `NODE_OPTIONS` = `--preserve-symlinks --preserve-symlinks-main`, appended to the host's own `NODE_OPTIONS`; `GIT_CONFIG_COUNT/KEY/VALUE` = `safe.directory` for the workspace only; `NODE_EXTRA_CA_CERTS` if configured | MXC sets `TEMP` and `TMP` to its AppContainer temp dir (`…\AppData\Local\Packages\sandbox.{guid}\AC\Temp`), so the policy's entries have no effect; `~/.moorai/agent-tmp` stays writable to the agent. Node resolves its main module with `realpathSync`, which `lstat`s every ancestor and gets `EPERM` on `C:\` in BaseContainer, so without the two flags no Node workload (the hook, Codex, Copilot) starts; granting enumeration on the ancestors is not used because listing `C:\` exposes the profile's entries. git rejects repos created while elevated, and command-scope config counts as protected config. BaseContainer does not inherit the CurrentUser Root store. `NODE_EXTRA_CA_CERTS` adds roots. `SSL_CERT_FILE` would replace OpenSSL's bundle, so it is only passed through when it is already set. |

**Denials → alerts.** `captureDenials.mode: "block"` keeps enforcement on. After the session exits, MXC writes
`denials.<run-id>.json` into the host-only run dir. The host parses only the documented fields
(`resource`, `resourceType`, `accessType`, `summary.deniedResourcesTruncated`) and deletes the file. It then posts
one content-free `/api/alerts` record per group: category `MXC: access denied`, `pathClass` (never a path),
`reasonCode` (`<class>-<access>`; a file in the `other` path class is `file-other-<access>`, so it never merges with a registry `other-<access>` group), `count`. `pid`, `filetime` and file names are dropped. Capability denials keep
the well-known capability name, or `custom-sid` for a SID. Denials arrive only after exit; MXC has no live feed
for the launcher.

**Trust boundary.** Nothing the host reads to *build* a launch may come from inside a read-write grant.
Otherwise a contained agent could choose the policy of its own next launch.
- **Launch settings** live in `%LOCALAPPDATA%\MoorAI Host\mxc.json`: `enabled`, `workspace`, `wxcExec`,
  `egressAllow`, `extraCaCerts`, `modelProxyPort`, `keepRuns`, `hookRoots`, `consoleUrl`, `installToken`,
  `tenant`, `fallback`. They are not in
  `~/.moorai/config.json`, which sits in the hook's read-write leg. `MoorAI Host` is a protected path class: it
  is never granted, it is denied explicitly where the host can, and a workspace inside it or containing it is
  refused. Run dirs and denial reports live there too, so the agent cannot plant a denial file.
- **The host's install directory** is never granted. It is denied explicitly with native FS deny, and a
  workspace that overlaps it is refused. A per-user NSIS install may sit at `%LOCALAPPDATA%\MoorAI`, the hook's
  breadcrumb leg. In that case the leg is not granted, and the terminal says so.
- **wxc-exec** runs with full user rights, so only Program Files or the install dir qualify, plus a Microsoft
  signature.
- **Hook roots** come from host-only `hookRoots`, or are discovered in agent-writable hook configs. A root is
  granted read-only only if it holds `cli\moorai-hook.mjs` (or `moorai-agent-hook.mjs`) and a `package.json`
  named `moorai`, and is not the profile, its parent, `AppData`, or `%APPDATA%`/`%LOCALAPPDATA%`.
- **The console binding for the host's denial alerts** comes only from `mxc.json` (`consoleUrl`,
  `installToken`, `tenant`), never from `config.json`. The host posts to the https origin rebuilt from
  `consoleUrl` plus `/api/alerts`. It rejects a URL that is not https, has no host, or carries credentials,
  and it does not follow redirects. With no host-only binding, the host posts nothing and only prints the
  path-free summary in the terminal.

Known gaps:
- `~/.moorai` stays read-write, `config.json` included, because the hook writes its ledger, latch and
  kill-session sentinel there.
- The host still reads `config.json` for non-MXC settings (`isolateAgent`, `allowedTools`, `serverUrl`), as it
  does without MXC. For example, `tool_allowed` sends `installToken` to `serverUrl` from `config.json`.
- Whether a nested read-only grant on `config.json` takes effect under a read-write `~/.moorai` is untested.
- An agent launched **without** MXC has the user's full rights, so it can write `mxc.json` like any other file.

**Not proven (all runtime-on-Windows).** None of the following has been run:
- ConPTY → wxc-exec → contained child: I/O, resize, Ctrl-C.
- Kill-on-close reaching the contained child. The Job Object is assigned after spawn, so wxc-exec may already
  have created the child. `portable_pty` 0.8 hardcodes the creation flags (no `CREATE_SUSPENDED`) and a
  one-slot attribute list (no `PROC_THREAD_ATTRIBUTE_JOB_LIST`), so assigning first needs a fork. Putting
  the MoorAI host in the job, so children inherit it, does not work: the host would count as an active
  process forever, `TerminateJobObject` would kill MoorAI, and the job's UI limits would apply to the app.
- The `--probe --config` argument form and its stdout shape.
- Whether the backend's default env is the launcher's (tokens are passed only on the launcher env).
- Claude Code under a `.claude.json` file grant (atomic rename in the profile root).
- `safe.directory` via `GIT_CONFIG_*`.
- PowerShell with `isolation: "desktop"`.
- The MXC binaries' signer subject.
- The per-user install path.

The plan is in the MXC test plan (scratchpad `mxc/TEST-PLAN.md`).

## Windows: requiring MXC for agent commands (v1.18.0, hardened in v1.18.2)

**Status: code and unit tests only. Nothing here has run on Windows.** Files:
[`cli/containment-enforce.mjs`](../cli/containment-enforce.mjs) (decision, wrap),
[`cli/containment-guard.mjs`](../cli/containment-guard.mjs) (write guard, v1.18.2),
[`cli/mxc-policy.mjs`](../cli/mxc-policy.mjs) (`scope: "commands"`), `cli/moorai-hook.mjs` (`wrapIntake`,
`containmentStep`, `emit`, `failClosedNow`, posture beat). Tests: `test/containment-enforce.test.mjs`,
`test/containment-hardening.test.mjs`, `test/containment-enforce-hook.test.mjs` and
`test/containment-hardening-hook.test.mjs` (the real hook, with the test-only preload
`test/fixtures/fake-win32.mjs` reporting `win32` / `10.0.26100`; shared harness `test/containment-hook-harness.mjs`).

**Contract (frozen with the console).**
- Signed policy fields: `containmentRequired`: `"off"` (default) | `"alert"` | `"block"`;
  `containmentClaudeCode`: `"off"` (default) | `"wrap"`. Source precedence is that of `failMode`: the root-owned
  admin binding (top-level key), then the verified policy (`VERIFIED_POLICY`, the copy `hookFailMode` reads),
  then `"off"`. On a pinned device (policy-key pin or root-owned `policy.pub`) a user-writable file cannot
  change them. On an unpinned device the verified policy is the user-scope `~/.moorai` copy, so the user, or an
  agent running as the user, can; that is `failMode`'s trust model too. Exact lowercase values only. An invalid value produces a warning that names the source and key,
  never the value, and the next source decides. On macOS and Linux both fields resolve to `"off"`
  (source `"platform"`).
- Reason codes (`cli/provenance.mjs` `REASON`): `CONTAINMENT_MISSING` (an agent that can use MXC is not set to)
  and `CONTAINMENT_UNAVAILABLE` (MXC cannot be used here while it is required). Categories:
  `Containment: agent commands not in MXC` and `Containment: MXC unavailable`. v1.18.2 adds two categories
  that carry `POLICY_TAMPER`: `Containment: agent launched wxc-exec` and `Containment: write to a protected
  location` (field `guardClass`: `moorai-host` | `shell-snapshots` | `shell-rc`).
- Posture heartbeat, top level: `containmentRequired` (effective mode) and `claudeCodeWrap` (`"on"` | `"off"` |
  `"unavailable"`, from static prerequisites only: `wxc-exec.exe`, Git Bash, and `mxcCapable !== false`).
- Alert fields: `host`, `containmentRequired`, `containmentKind`, `containmentSource` (mxc-detect's fixed lists),
  `mxcCapable`, `wrapWhy` (fixed token), `decision`, `reasonCode`. Alerts that are not denies are deduped once per
  session and reason (`seenOnce`, 24 h). Denies alert every call.

**Codex / Copilot (`containmentRequired`).** The agent-hook shim runs `cli/moorai-hook.mjs` with
`MOORAI_HOOK_HOST=shim` and `MOORAI_HOOK_AGENT=<id>` (`cli/moorai-agent-hook.mjs`). The adapters map Codex's command
tool to `Bash` (`cli/agent-hooks/codex.mjs` `MATCHER`), and Copilot's `bash` / `powershell` to `Bash` / `PowerShell`.
So the check runs at the top of the hook's `SHELL_TOOLS` branch, only for `PreToolUse` and only on win32.
Decision (`containmentDecision`, pure):

| containment kind | `mxcCapable` | alert mode | block mode |
|---|---|---|---|
| `mxc` | any | allow | allow |
| any but `mxc` | `false` | alert `UNAVAILABLE` | alert `UNAVAILABLE` |
| `none` / `other` | `true` / `null` | alert `MISSING` | **deny** `MISSING` |
| `unknown` | `true` | alert `MISSING` | **deny** `MISSING` |
| `unknown` | `null` | alert `MISSING` | alert `MISSING` |

Why: a device that cannot run MXC is never denied for it, because the user could not fix that. A host that is
not set to MXC at all is denied in block mode even when capability is unknown, because setting it is the fix.
`unknown` means the host may pick MXC at run time (Codex `prefer_mxc`), or the host's default is undocumented
(Copilot `sandbox.enabled` unset). That is denied only where MXC can certainly run.
Codex layers (`hostKind`): MXC counts only when the user layer alone and the user + project layers both say `mxc`.
Codex loads a project `.codex/config.toml` only when the project is trusted, which the hook cannot see.

**Capability cache.** `~/.moorai/mxc-capable.json` is user-writable. Under block, `capableForHook` passes no
state dir to `mxcCapable`, so the cache is neither read nor written. The build comes from `os.release()` (a
build below 26100 is `false` with no I/O), and the UBR comes from `reg.exe` at its absolute System32 path. That
call happens only when the host is not set to `mxc`, and it is memoised per process. Under alert the cache is
used, because there it can change only which reason an alert carries. Measured on macOS (Apple M5 Max): `hostKind`
for codex, both layers, p50 0.038 ms; copilot p50 0.011 ms; a `spawnSync` of `/usr/bin/true` p50 0.82 ms. The
hook wall time for a Codex Bash call set to `mxc` was p50 153 ms with containment off and p50 154 ms with block (15
runs each). `reg.exe`'s cost on Windows was **not** measured.

**Claude Code wrap (`containmentClaudeCode: "wrap"`).** Sources, fetched 2026-10-14:
- code.claude.com/docs/en/hooks, PreToolUse decision control, `updatedInput`: "Modifies the tool's input parameters
  before execution. Replaces the entire input object, so include unchanged fields alongside modified ones. Claude
  Code evaluates permission rules and a Bash command's auto-background eligibility against the input your hook
  returns, not the input Claude sent. Combine with `"allow"` to auto-approve, or `"ask"` to show the modified
  input to the user. For `"defer"`, ignored". And from the same page: "`PreToolUse`: `updatedInput` directly
  under `hookSpecificOutput` replaces a tool's arguments before it runs." The page does not say what happens
  with no `permissionDecision`. MoorAI already relies on that case for masks (cli/moorai-hook.mjs `emit`: the
  2.1.265 binary applies it and then runs the normal permission flow), and the wrap uses the same shape.
- Bash tool input fields (same page): `command`, `description`, `timeout`, `run_in_background`.
- code.claude.com/docs/en/tools-reference (fetched 2026-10-14), the tool table: `Bash` "Executes shell commands
  in your environment", `PowerShell` "Executes PowerShell commands natively", and `Monitor` "Runs a command in the
  background and feeds each output line back to Claude, so it can react to log entries, file changes, or polled
  status mid-conversation. Can also open a WebSocket and treat each incoming message as an event." The Monitor
  section: "When Monitor runs a command, it uses the same permission rules as Bash", and "A WebSocket watch takes
  a `ws` input in place of `command`". No other tool in the table runs a command (LSP talks to configured
  language servers; Workflow runs subagents, whose own tool calls reach the hook).
- code.claude.com/docs/en/setup: "**With Git for Windows**, Claude Code uses Git Bash for the Bash tool. If
  Claude Code can't find Git Bash, set the path" (`CLAUDE_CODE_GIT_BASH_PATH`); "**Without Git for Windows**,
  Claude Code runs shell commands via the PowerShell tool." code.claude.com/docs/en/tools-reference: "The Bash tool
  runs each command in a separate process." The page also says a `cd` carries over between commands, and that
  Claude Code sources the user's startup file and applies the captured aliases and functions to every command.

Flow (v1.18.2): `wrapIntake` runs before any check reads the call (before `exceptionStep`,
`selfExceptionAttempt`, `decoyUsed`, `observeLearnedDrift`, `circuitStep`, `profileStep` and the command scan). For a
Claude Code `Bash` call with the wrap on it runs `planWrap` and, if the command is in wrapped form, replaces
`tool_input.command` with the command recovered from the config, so every check judges that. It then refuses an
agent wxc-exec launch and applies the write guard (below). `containmentStep` (top of the shell branch) checks the
plan against the recovered command. `planWrap` That finds `wxc-exec.exe` on `PATH` under Program Files
only (the rule of `mxc_launch.rs wxc_location_allowed`, without the desktop host's install directory), Git Bash
(`CLAUDE_CODE_GIT_BASH_PATH`, else `%ProgramFiles%\Git\bin\bash.exe`), the workspace (`CLAUDE_PROJECT_DIR`, else
the hook's cwd) and the wrap directory. If the command is already in wrapped form, it is unwrapped (below). Then
the config is built once, to fail early. `emit` takes the final command (masked, if a mask applied), writes the
config and returns `updatedInput` = every original field plus the new `command`, with `additionalContext` and no
`permissionDecision`. On `"ask"` the rewrite rides with the ask. On a deny nothing is written.

Config (`buildMxcPolicy` `scope: "commands"`, Node-only; the Rust copy and the golden cases do not cover it):
read-write is the workspace only. Not `~/.claude` or `~/.moorai`, because a contained command that could write
them could remove the hook or rewrite its state. Read-only: the Git root, the node dir, the toolchain list and
CA files. Denied paths are as for agents. The network is `egress.default: deny` with host loopback, plus numeric
`egressRules` from the verified policy. `allowDaclMutation: false`. `process.cwd` is the hook's cwd when it is
inside the workspace, else the workspace. Env: `NODE_OPTIONS` preserve-symlinks, `safe.directory` for the
workspace, and `MOORAI_WRAP_CMD=<command>`. There is no `TEMP`/`TMP` and no model-proxy variable.

Quoting design. Three layers. The command runs only from the third, a JSON string; the first shows it:
1. Outer (what Claude Code's Git Bash runs): ``__moorai_show='<original>'; MSYS_NO_PATHCONV=1 '<wxc-exec, forward
   slashes>' --config '<config path>'``. All three are POSIX single-quoted words (`'` becomes `'\''`). The
   `__moorai_show='<original>'` statement is display only, so Claude Code's permission prompt shows what is being
   approved. It is an assignment with no command word: no function, alias, builtin or PATH lookup takes place, so
   nothing a shell snapshot defines can receive the text. It is its own statement, not a prefix of the launch, so the
   text is not exported into wxc-exec's environment (measured with a stand-in). v1.18.0/1 used ``: '<original>' ;``:
   measured under bash 3.2 and 5.3, a snapshot that defines `:() { eval "$1"; }` runs the original on the host
   (`test/containment-hardening.test.mjs` keeps that as its control). A single-quoted word is never expanded. The
   list's exit status is wxc-exec's. The executable uses
   forward slashes because bash looks up a name with no `/` on `PATH`. `MSYS_NO_PATHCONV=1` stops Git Bash from
   converting either argument. Length: the outer command, quoted once more as Claude Code's wrapper would,
   must fit 32,767 − 4,096 characters (`WRAP_OUTER_MAX`; the 4,096-character reserve for Claude Code's
   undocumented wrapper is an assumption). Otherwise the wrap is impossible (`command-line-too-long`).
2. `process.commandLine` (MSVC argv rules, `quoteArgWin` = `mxc_launch.rs quote_arg`):
   `"<bash.exe>" --noprofile --norc -c "__moorai_c=$MOORAI_WRAP_CMD; unset MOORAI_WRAP_CMD; eval \"$__moorai_c\""`.
   It is a fixed string with no user content and no backslash besides the `\"` escapes.
3. The command: `process.env` entry `MOORAI_WRAP_CMD=<command>`, JSON-encoded, so every byte except NUL survives.
   `eval` runs it the way `bash -c` would. A NUL byte, or a command longer than the 32,767-character variable
   limit, makes the wrap impossible.
Tests: under the real bash, 15 hostile originals in the display prefix stay inert (`$( )`, backticks, quotes
breaking out, newlines, `;`, `&&`, `|`, `&`, redirections, process substitution, `${IFS}`). This holds both run
directly and wrapped in `eval '<outer>'` as Claude Code would wrap it. A stand-in for wxc-exec runs exactly once,
with `MSYS_NO_PATHCONV=1` and `--config <path>`, and its exit code is the command's. `quoteArgWin` round-trips through an MSVC argv parser, and `innerCommandLine` parses to exactly
`[bash, --noprofile, --norc, -c, WRAP_SCRIPT]`. `bashQuote` reads back byte for byte under the real bash.
`WRAP_SCRIPT` gives the same stdout and exit code as `bash -c` under the real bash (5.3) for quotes, `&`, `|`, `%`,
`^`, `!`, newlines, CRLF, backslashes, `$( )`, backticks, heredocs, `exit n` and unicode. The variable does not
leak to children. Measured difference: macOS's bash 3.2 exits 1 under `eval` and 2 under `-c` for a command it
cannot parse; bash 5.3 exits 2 in both cases.

Config location: `%LOCALAPPDATA%\MoorAI Host\wrap`. The `moorai-host` path class is never granted and is denied
where the host can deny, so no contained command can pre-plant a file there. Both levels must be plain
directories before and after creation: not a file, a symlink or a junction (Node reports a junction as a link).
These are the v1.6.1 `ensureDirs` checks. Files are `wrap-<32 hex>.json`, created with `flag: "wx"` (nothing
pre-planted at the name is written through). They are swept after 10 minutes, because wxc-exec reads its config
at start. The `--log-file` is not passed: wxc-exec's log holds the whole policy.

Idempotence: `unwrapCommand` recognises only the exact outer shape (display statement included), with this
device's `wxc-exec` and a `wrap-<hex>.json` that is a regular file in the wrap dir. It returns the
`MOORAI_WRAP_CMD` the config carries. The displayed text is never read as the command: a display edited to `ls`
around a config holding a reverse shell is judged as the reverse shell (test). The launch without the display
statement, or one that smuggles a second statement, is not the wrapped form. That original is what the hook
scans, and it is wrapped again in a fresh config, one level only; the config that came with it never runs.
The wrap dir is user-writable, so a config there may be the agent's own (R1 of the v1.18.1 review): a
`MOORAI_WRAP_CMD` that is missing, empty, holds a NUL, or is too long for the environment or the command line
(`commandWrapWhy`, the same checks `wrapConfig` makes) is unrecoverable. A command in wrapped form that cannot
be recovered (another wxc-exec, a config elsewhere, missing or symlinked, or the above) or that `wrapConfig`
then refuses is **denied in every mode** (`wrapWhy: "wrapped-unrecoverable"`, or the `wrapConfig` token), in
`wrapIntake`, `containmentStep` and `emit`: allowing it would run that wxc-exec launch, with a config MoorAI never
judged, as it stands. A command that merely starts with the shape (`…json' ; curl x`) is not in wrapped form; it
names wxc-exec, so it is refused as an agent wxc-exec launch.

With `containmentClaudeCode: "off"` the unwrap path does not run at all (`wrapIntake` plans the wrap only when it
is on). v1.18.1 therefore judged an agent-built wrapped form, with the wrap off, as an ordinary command (the
display text and the wxc-exec launch), never the config's `process.commandLine`. v1.18.2 closes that with the
next rule, which does not depend on the wrap.

**Agent wxc-exec launches (v1.18.2).** On Windows, in every mode and with the wrap on or off, a command tool call
whose command (recovered, if it was in wrapped form) names `wxc-exec` is denied (`launchesWxcExec`, `POLICY_TAMPER`).
Chosen over reading and judging the config: wxc-exec takes its config by `--config`, positionally
(`wxc-exec.exe --log-file .\mxc-audit.log .\config.json`) or with a `--` tail that replaces `process.commandLine`
(`src-tauri/src/mxc_launch.rs`), the name can come from a variable, a `cd` or a glob, and the file can be rewritten
by a background command between the hook's read and wxc-exec's, so the hook would judge a different file than the
one that runs. The policy part of a config (grants, network) is not something a command scan can judge either.
MoorAI's own wrap never needs the agent to start wxc-exec. The test strips quotes, backslashes and backticks first
(`w''xc-exec`); a name the shell builds at run time walks past it. Off Windows the name alone is not a finding.

**Write guard (v1.18.2).** While `containmentRequired` is not `"off"` or `containmentClaudeCode` is `"wrap"`,
`wrapIntake` denies (`POLICY_TAMPER`) a `Write` / `Edit` / `MultiEdit` / `NotebookEdit` whose resolved target, or a
`Bash` / `PowerShell` / `Monitor` command that writes (`data/tool-tags.js` `shellWrites`, or an interpreter such as
`python`, `node`, `pwsh`) and names a path, under: `%LOCALAPPDATA%\MoorAI Host` (`moorai-host`); Claude Code's
shell snapshots, `~/.claude/shell-snapshots` or under `CLAUDE_CONFIG_DIR` (`shell-snapshots`), which Claude Code
sources on the host before each command, before the wrap's launch; and the bash startup files Git Bash reads
(`shell-rc`: `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.bash_logout`, and the Git root's
`etc\profile`, `etc\bash.bashrc`, `etc\profile.d`). The first three rc files are `mxc-policy.mjs`'s `shell-profile`
class, and `data/persistence.js` names the same files for #46 (it has no exported list to reuse). Paths are
resolved through `~`, `$HOME`, `${VAR}`, `%VAR%`, `$env:VAR` (profile and app-data variables), MSYS `/c/…`, the
call's cwd and `..`. A bare rc name after a `cd` counts. A string test, so a path built at run time walks past it,
and a command that reads one of these files while writing elsewhere is denied with it.

**Write guard path canonicalization (v1.18.3).** `resolveTarget` and the guard's comparison use
`cli/win-canon.mjs` (pure, no filesystem): `winCanon` gives the Win32-canonical absolute path and `canonUnder`
compares. Rules: `/` and `\` alike, repeated separators collapsed, case-insensitive comparison (upper-cased, case
kept in the string); `\\?\C:\`, `\\.\C:\`, `\??\C:\` to `C:\`; `\\?\UNC\s\sh` and `\\.\UNC\s\sh` to `\\s\sh`; an admin
share `\\<any host>\<letter>$` to `<letter>:\`; `\\?\Volume{guid}\` and `\\?\GLOBALROOT\Device\HarddiskVolumeN\` to the
wildcard root `*:\`, which matches every drive; any other device path is unknown; `\x` is rooted on cwd's drive and
`C:x` is relative to cwd only when cwd is on `C:`; trailing dots and spaces and an NTFS stream suffix (`:s`,
`::$DATA`, `:$I30:$INDEX_ALLOCATION`) are dropped from every segment (Win32 trims only the last segment and skips
normalisation under `\\?\`; trimming everywhere can only make more spellings meet); `.` and `..` fold and never climb
past the root; `%VAR%` (so `%HOMEDRIVE%%HOMEPATH%`), `$env:VAR` and `${env:VAR}` in any case, `${VAR}`, `$VAR` and a
leading `~` expand from env, `$HOME` and `~` meaning `USERPROFILE`; a variable that is unset or empty makes the path
unknown (`""`, not denied) unless folding drops it (inside a stream suffix, or a segment a `..` removes). A
`Write`/`Edit` path and every shell word is also read literally, as a file API would take it, so
`C:\Users\me\%USERPROFILE%\..\.bashrc` is seen. The protected paths themselves are canonicalized from env.
Shell words add each quoted string whole and a PowerShell `-Path:value`'s value. **8.3 short names:** a segment of
8.3 shape whose base ends in `~digits` (`MOORAI~1`, `BASHRC~1`, `BASH~1.BAS`) matches any segment at the same
position, on either side, since which long name it stands for is on disk. False-positive cost: a write to any
short-named entry directly in `%USERPROFILE%` or `%LOCALAPPDATA%`, or one level into `~\.claude` or the Git root's
`etc`, is denied, as is a write command with a `~digit` word (`git reset HEAD~1`) run from the profile directory. The
guard's gate adds, locally (`GUARD_WRITE`, not `data/tool-tags.js`), the write forms `shellWrites` misses:
`cp`/`mv`/`tee`/`install`/`rsync`/`dd` path-qualified, `.exe`, quoted or `\`-escaped; the PowerShell aliases `sc`,
`ac`, `ni`, `cpi`, `copy`, `mi`, `move` and `Tee-Object`; redirects after a digit or `&` and `>|`. Still not seen: a
path assembled at run time, a glob, a junction, symlink or `subst` drive, and Git Bash's own `/etc/...` mount
(resolved on cwd's drive, not the Git root). Tests: `test/containment-guard-paths.test.mjs`.

Wrap impossible (`wrapWhy`): `powershell-tool`, `monitor-tool` (v1.18.2), `host-cannot-rewrite` (coach, shim or
an aliased tool), `not-capable`, `no-wxc-exec`, `no-git-bash`, `no-workspace`, `workspace-overlaps-state` (v1.18.2:
the workspace is inside, or contains, `~/.claude`, `~/.claude.json`, `CLAUDE_CONFIG_DIR`, `~/.moorai`,
`%APPDATA%\MoorAI`, `%LOCALAPPDATA%\MoorAI`, `%LOCALAPPDATA%\MoorAI Host` or `%ProgramData%\MoorAI`),
`cwd-outside-workspace` (v1.18.2: Claude Code's cwd is an absolute path outside the workspace; the command would
otherwise run at the workspace root, which is not the command the user approved), `wrap-dir-unsafe`,
`wrapped-unrecoverable`, `command-nul`, `command-too-long`, `command-line-too-long`, `empty-command`,
`policy-<reasonCode>` (for example `policy-workspace-is-profile`), `wrap-error` and `unknown-host` (v1.18.2: a
command tool call with `MOORAI_HOOK_HOST=shim` and no known `MOORAI_HOOK_AGENT`, judged when either field is on).
`containmentRequired` then decides with `UNAVAILABLE`: `"block"` denies; `"alert"` and `"off"` allow and alert once
per session. Exception: a command that arrived in wrapped form is denied in every mode (above).

**Fail mode (v1.18.2).** Under `containmentRequired: "block"`, a `Bash` / `PowerShell` / `Monitor` PreToolUse from a
host it governs (Codex, Copilot CLI, an unknown host, or Claude Code with the wrap on) that the hook could not
decide is denied with `CONTAINMENT_UNAVAILABLE`, exit 2, deny JSON on stdout and the reason on stderr, and one
alert (`wrapWhy: "hook-error"`, `"hook-budget"` or `"hook-bad-input"`), whatever the fail mode
(`containmentBlockApplies` / `containmentFailDeny`, checked first in `failClosedNow`, so it covers an exception in
`wrapIntake` or `containmentStep`, an uncaught error anywhere in the call, and the decision-budget timer).
**Break-glass wins (v1.18.3).** An operator-signed, live break-glass marker lifts every `"block"` deny of a command
MoorAI cannot contain (`breakGlassLiftsContainment`): in `failClosedNow` (the call proceeds, ledger `BREAK_GLASS`,
the fail mode lifted with it), in `wrapUnavailableVerdict` (the wrap fallback and the emit-stage `wrap-error`), and
in `containmentStep` (`unknown-host` and every wrap-impossible token). The command runs uncontained and one alert per
call posts: category `Break-glass active (fail-open override)`, `containmentReason: "CONTAINMENT_UNAVAILABLE"`,
`containmentRequired: "block"`, `host`, `wrapWhy`. Not lifted: a command that arrived in wrapped form and cannot be
recovered or wrapped again (every mode), an agent wxc-exec launch and the write guard (`POLICY_TAMPER`), and
`CONTAINMENT_MISSING` (a Codex / Copilot configuration the policy decided on). An exception while `emit` builds or writes the config under `"block"` (or for a command that
arrived in wrapped form) is the wrap-fallback deny (`wrap-error`). Under `"alert"` / `"off"` the fail mode decides as
before: an exception in the check goes to `failClosedNow("error")` (closed: exit 2 `FAIL_CLOSED`; open: the call
proceeds), and one in `emit` is a `FAIL_CLOSED` deny when closed and "wrap impossible" (`wrap-error`, alert, the
command runs unwrapped) when open. Not covered: Claude Code's own hook timeout firing before the 15 s budget (the
default is 600 s, so it cannot unless a settings file lowers it), and a hook process that is killed.

**SDK.** Not mirrored. `NOT_EVALUATED` gains `"mxc-containment"`. The check depends on the host CLI that the shim
names, that host's config files and the Windows device, not on the call. The wrap is a rewrite, which the SDK
cannot do (`"mask-rewrite"`).

**Known gaps (by design or not fixable here).**
- Shipped as a documented limit, with no fix in v1.18.2 (the wrap is opt-in, default off). With the wrap on,
  Claude Code checks its own `Bash(...)` allow, ask and deny rules against the rewritten command, not the
  original one. A deny rule such as `Bash(curl *)` therefore no longer matches, whether it is the user's, the
  project's or a managed (enterprise) settings rule, and auto-allowed commands may prompt again. Claude Code's
  built-in validators that read the command (its path checks for commands touching files outside the working
  directory, read-only command detection) see the rewritten form too. "Don't ask again" on a wrapped command may
  save a rule for the wxc-exec launch that approves later wrapped commands without a prompt (unmeasured; the
  launch differs per command only in the config file name). MoorAI's own checks still judge the original
  command. The permission prompt shows the original through the `__moorai_show='…'` display statement; how
  Claude Code's prompt renders it was not observed on Windows.
- `Monitor` (v1.18.2): registered on PreToolUse (`hooks/hooks.json`, `PRETOOL_MATCHERS`) and scanned in the shell
  branch like `Bash` (also by the self-grant refusal, exceptions, the workload profile, egress rules and capability
  tags). Never wrapped, because whether `updatedInput` applies to it was not measured: denied under wrap + block,
  alerted under alert / off. Its output arrives as events, not a PostToolUse response, so it gets no PostToolUse
  matcher.
- With `containmentClaudeCode: "wrap"` and `containmentRequired: "block"`, every Claude Code `PowerShell` tool
  call is denied (`CONTAINMENT_UNAVAILABLE`, `wrapWhy: "powershell-tool"`; test). On Windows without Git Bash,
  that leaves Claude Code no shell tool.
- An unenrolled (coached) device is coached, as for every deny, and the wrap needs `canRewrite()`, which is false
  while coaching.
- The wrap covers `Bash` only, not `Read`/`Write`/`Edit`/`WebFetch`/MCP or the `PowerShell` / `Monitor` tools.
  Claude Code runs uncontained. Since v1.18.2 the write guard denies its `Write`/`Edit` tools and shell commands
  writing into the wrap dir, and a config planted there is not trusted anyway (a recovered command is re-wrapped
  in a fresh config, an unrecoverable one is denied). Residual (F5 of the review): between the hook writing a
  config and wxc-exec reading it, Claude Code's permission prompt may wait for the user, and any process running
  as the user that the guard does not see (a `PowerShell` call under alert, a program started earlier, another
  application) could replace the file. The guard narrows that to processes outside the agent's tool calls; it is
  a same-user race and is not closed. Unmeasured.
- Inside the container: `cd` does not carry over, the user's shell snapshot is not loaded, `--add-dir`
  directories and the rest of the profile are not readable, and hostnames are unreachable without a CONNECT
  proxy.
- Codex and Copilot are judged by their config files. `codex -c …`, `copilot --no-sandbox`, Codex profiles and
  managed settings are not visible.
- The hook does not check wxc-exec's Authenticode signature (the desktop host does), only that it is under
  Program Files.

**Not proven (runtime on Windows).** None of the following has been run:
- Claude Code on native Windows applying `updatedInput` with no `permissionDecision` to a Bash call, and passing
  the rewritten command to Git Bash unchanged.
- Git Bash running `: '…' ; MSYS_NO_PATHCONV=1 'C:/…/wxc-exec.exe' --config 'C:\…'`, and MSYS2 passing both
  arguments through unchanged. Claude Code's permission prompt rendering the display prefix legibly, and the
  real length of Claude Code's own wrapper (the 4,096-character reserve).
- wxc-exec relaying the contained child's stdout/stderr and exit code to Git Bash; its behaviour with no
  `--log-file`; whether it writes a log anywhere by default.
- MSYS2's command-line parser reading the fixed `-c` argument as `__moorai_c=…; eval "$__moorai_c"` (it is
  tested only against MSVC rules).
- An environment value with newlines passing through MXC's `process.env` to the child.
- Git for Windows' `bin\bash.exe` launcher, and `usr\bin\bash.exe`, running inside BaseContainer with only the
  Git root read-only.
- `reg.exe` cost on the hook path; registry UBR read from inside a contained Codex/Copilot hook process.
- Codex and Copilot hook payloads carrying `cwd` and `CODEX_HOME` / `COPILOT_HOME` as the adapters assume, on
  Windows.
- The posture fields reaching the console (the console side is built in parallel against this contract).

## Windows: JS agent exit and action-audit compaction

**Status: fixed in v1.9.1 and tested on Windows 11 (Node 24.15.0).** Two Windows-only bugs:

- **Process exit.** `process.exit()` soon after `fetch()` aborts a Windows process with `0xC0000409`
  (`Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76`). V8 compiles
  fetch's WebAssembly HTTP parser on a background thread, and `process.exit()` closes the libuv handle
  that job posts to. Measured: with two or more fetches before the exit it crashed 5 of 5 runs. A
  short-lived process now calls `exitWhenDrained(code)` ([`cli/exit-drain.mjs`](../cli/exit-drain.mjs))
  instead. It sets `process.exitCode`, destroys leftover TCP sockets and returns a promise that never
  settles, so the caller runs nothing more. The process ends when its event loop is empty, with an unref'd
  one-second `process.exit` as a backstop. Callers: `moorai-hook`, `mcp-usage-beat flush`,
  `moorai-guard`, `moorai-mcp-guard` (after its stdout drains; it also clears its stop timers and releases
  stdin), `moorai-agentwatch`, `moorai-redteam`, `moorai-backtest`, `moorai-scan`, `moorai-doctor` and
  `moorai-cloud-inventory`. Exit codes are unchanged.
- **Action-audit compaction** ([`cli/signals.mjs`](../cli/signals.mjs)). The compactor renamed its temp
  file over `action-audit.jsonl` while it still had the log open. Windows refuses that rename (EPERM), so
  the log was never trimmed on Windows and `MOORAI_RETENTION_DAYS` never applied there. The compactor now
  closes the log before the rename. It retries a refused rename (EPERM, EACCES or EBUSY) until two
  seconds after it took its lock, and after that it does not rename at all. The lock file names the
  compactor (`<pid>.<start ms>.<random>`). A writer that finds a lock, or finds its file replaced, right
  after its append closes its handle and waits for the compaction to end. It does not wait on a dead pid
  or on a lock more than five seconds old. If the log was replaced and the new log does not hold the
  writer's line, the writer writes the line again. Nothing is written into the log to mark a compaction,
  so a compaction that fails leaves the log unchanged.

`.github/workflows/windows-js.yml` runs the hook, gateway, egress, exit and ledger tests on
`windows-latest`, one file at a time: with four at once, MCP gateway tests failed now and then on
Windows (connection resets, and a gateway that exited `0xC0000409` before it listened), in v1.9.0 too.
**Not proven:** Node 22 on Windows (only Node 24 was run on the test machine); that the other CLIs
crashed before the fix (only the guard was seen to, as each makes a single fetch); and
`moorai-scan --package` (no test drives its registry fetch).

## Windows runtime validation (`moorai-windows-validate`)

**Status: built and run on macOS only. It has not run on Windows yet**, on a GitHub runner or on a
Windows 11 box. Until it has, the Windows rows below are a test plan, not evidence.

`node cli/moorai-windows-validate.mjs [--out <file>] [--strict] [--require-windows] [--only <ids>] [--json]`
runs the agent's enforced surfaces on the machine it is started on and writes a content-free report. It
needs only Node and the agent tree: no install, no account, no network beyond `127.0.0.1`. Files:
[`cli/moorai-windows-validate.mjs`](../cli/moorai-windows-validate.mjs) (CLI),
[`cli/windows-validate-probes.mjs`](../cli/windows-validate-probes.mjs) (probes),
[`cli/windows-validate-harness.mjs`](../cli/windows-validate-harness.mjs) (loopback console, sandboxes,
process helpers), [`cli/windows-validate-report.mjs`](../cli/windows-validate-report.mjs) (report and
verdict), [`cli/windows-validate-table.mjs`](../cli/windows-validate-table.mjs) (probe table).

**How a run works.** It starts a loopback console that serves a policy per probe, signed with an ed25519
key made for that run, and collects alerts. Each probe gets its own throwaway HOME, `USERPROFILE`,
`APPDATA` and `LOCALAPPDATA`, enrolled to that console. Every child process gets an environment built from
scratch, so none of the operator's `MOORAI_*` or proxy variables reach it. The operator's own MoorAI
state, policy and console are not read or written. One thing is shared with the real device: a
machine-wide binding or policy anchor (`<ProgramData>\MoorAI\config.json`, `policy.pub`) still applies to
the agent processes. The report says whether one is present (`machineBinding`, `machineAnchor`), because
an admin setting can change what a probe sees.

| Probe | Surface | Windows only | A pass means |
|---|---|---|---|
| `hook-bash-block` | hook | no | The hook process starts and denies a reverse-shell Bash command. |
| `hook-powershell-block` | powershell | no | The same command through the `PowerShell` tool is denied. |
| `hook-powershell-allow` | powershell | no | A benign PowerShell command is allowed (the hook does not deny everything). |
| `powershell-host` | powershell | yes | The hook launched through `powershell.exe` returns the same deny. |
| `mcp-gateway-hook` | mcp | no | An MCP call to a server outside `mcpAllow` is denied. |
| `mcp-gateway-http` | mcp | no | The HTTP MCP gateway refuses a call carrying a credential; the remote server sees no call. |
| `egress-hook` | egress | no | An egress block rule denies an upload command to the blocked host. |
| `egress-proxy` | egress | no | The egress proxy answers 403 for a blocked host and does not forward the request. |
| `mxc-detect-config` | mxc | no | The MXC detector reads Codex `windows.sandbox = "mxc"` as contained and an unset config as not. |
| `mxc-registry` | mxc | yes | `reg.exe` gives this build's UBR, so `mxcCapable` comes from the real registry. |
| `mxc-enforce` | mxc | yes | With `containmentRequired: "block"`, a Codex shell call whose config does not use MXC is denied (alerted only where `mxcCapable` is false). |
| `alert-delivery` | alerts | no | Each passing block probe's alert reached the console with the expected reason code (`MCP_SERVER_NOT_ALLOWED`, `EGRESS_RULE`, `CONTAINMENT_*`), and no alert contained the run's marker or a listed payload piece (see below). |

**What the content-free check looks for.** `alert-delivery` fails, and the report's `alerts.contentFree`
is false, if any alert's serialized form contains one of these strings:

- the run's random marker, which is appended to every command, URL and argument a probe sends;
- `PAYLOAD_NEEDLES` in `cli/windows-validate-probes.mjs`, the distinctive pieces of the payloads
  themselves: `bash -i`, `/dev/tcp/198.51.100.7`, `198.51.100.7`, the example AWS key id and secret,
  `@notes.txt` and `Get-ChildItem`.

The marker alone is not enough. It sits after each payload, outside the span a detector matches, so an
alert that carried the matched span (for example `/dev/tcp/198.51.100.7/4444`) would not contain it. With
`captureTier: "full-capture"` the hook's alert does carry that span, and a test runs the probes that way
and checks that `alert-delivery` reads `leaked` and the verdict is `fail`.

Scope of the check: it finds only these strings, not every possible rendering of a payload (a re-encoded
or truncated form would not match). The blocked destination host (`drop.paste.example`), the tool name and
the egress binary (`curl`) are not checked, because content-free egress and MCP alerts report them by
design (`egressHost`, `tool`, `egressBinary`). Neither the marker nor a payload piece is written to the
report.

**The report** (`moorai-windows-validation/1`) holds only: an hour-rounded `generatedAt`; `agentVersion`;
`platform`, `arch`, the Windows build number (`osBuild`), the Node major version and `mxcCapable`;
`machineBinding` and `machineAnchor` (booleans); and one row per probe. A row has `id`, `surface`,
`status` (`pass`, `fail`, `skipped` or `error`), `expected` and `observed` from a fixed list, a fixed
`reason`, `ms` and the probe table's `proves` sentence. It also has alert counts (received, deny,
`contentFree`, counts by reason code), a summary with a verdict, and the `notCovered` list. Every field
passes an allowlist, so free text from a probe (a path, a command, an error message) is dropped. No user
name, host name, path, command, URL or alert body is written.

**Verdict.** `fail` if any probe failed or errored, or if nothing ran. `incomplete` if `--require-windows`
was given and a probe was skipped. Otherwise `pass`. `--strict` exits 1 unless the verdict is `pass`. Off
Windows, the Windows-only probes are `skipped` (`not-windows`). Forcing them on another OS gives `error`
or `fail`, never `pass`. The hook has no platform switch, so Windows behaviour cannot be faked.

**Not covered by a run** (stated in every report): the clipboard guard (it is in the desktop app, in
Rust); the NSIS upgrade over the previous release (needs both installers and an interactive session); and
running a command inside an MXC container (the probes check detection and the hook's verdict, not
`wxc-exec`).

**CI.** [`.github/workflows/windows-validate.yml`](../.github/workflows/windows-validate.yml) runs on
`windows-latest` with Node 22 and 24. It runs the validator with `--strict --require-windows`, then
[`test/windows-runtime.test.mjs`](../test/windows-runtime.test.mjs) (Windows-only assertions: build and
UBR from the real registry, the full validation passing, the hook through `powershell.exe`),
`test/windows-validate.test.mjs`, and the MXC and PowerShell test files, one at a time. The report is
uploaded as an artifact even when a step fails. `test/containment-enforce*.test.mjs` are not in that list:
they fake Windows on POSIX and are not built to run on Windows itself. The `mxc-enforce` probe is their
real-host counterpart.

**Not proven.** No probe has run on Windows: the workflow has not run (the branch has not been pushed),
and no Windows machine was used. In particular these are unverified: `powershell.exe` piping the payload
to the hook (`[Console]::In.ReadToEnd() | & node hook`), `reg.exe` output on `windows-latest`, the
`mxc-enforce` decision on a real build, and whether the first Windows run of the MXC test files passes. The
`egress-proxy` probe does not show that the block comes before a DNS lookup: the proxy's code returns a
rule block before it resolves the address (`admit` in `egress-proxy/server.mjs`), but the blocked host
never resolves, so a run would look the same either way.

## Sandbox egress policies from egressRules

**Status: built and unit-tested (`test/sandbox-policy.test.mjs`, `cargo test` `mxc::egress`,
`mxc::tests::golden_policy_cases…`, `mxc_launch::tests::egress_rules_from_host_settings_reach_the_policy`,
`platform::sandbox_tests::machine_egress_ignores_a_user_owned_config`). None of it has run under a real MXC
container or OpenShell.**

The rule set MoorAI's own check judges (`egressRules` / `egressDefault`,
[`cli/egress-rules.mjs`](../cli/egress-rules.mjs)) is mapped into the network part of a sandbox policy.
[`cli/sandbox-policy.mjs`](../cli/sandbox-policy.mjs) is the single entry point:
`sandboxPolicy({ egressRules, egressDefault }, "mxc" | "seatbelt" | "openshell")` →
`{ ok, target, policy, unexpressed }`. [`src-tauri/src/mxc_egress.rs`](../src-tauri/src/mxc_egress.rs) mirrors
the MXC and Seatbelt halves for the desktop host. Both replay
[`test/fixtures/mxc/sandbox-cases.json`](../test/fixtures/mxc/sandbox-cases.json). A `cidr` rule (F23) is
expressed by MXC as `to: [{ cidr }]` with its ranges (an earlier allow that shares an address with a later
unconditional block is reported `narrowed`, `mxc-deny-precedence`, because MXC's deny takes precedence), and
reported `omitted` by Seatbelt (`seatbelt-cidr`; measured on macOS 27.0: `(remote ip "10.0.0.0/8:*")` →
"host must be * or localhost in network address") and OpenShell (`openshell-cidr`). The Rust mirror does not
read `cidr` yet: it reports such a rule `invalid-rule`, so the desktop host leaves it to MoorAI's check
(`test/egress-cidr.test.mjs` covers the JS side only). Rust uses the `url` crate,
the same WHATWG host parser as Node's `URL`, so `010.0.0.1` and `8.0.0.1` are one address in both, as they
are in MoorAI's check.

**Semantics carried over.**
- The first matching rule decides.
- `alert` lets the call through, so it counts as allow.
- No `egressDefault` means allow.
- Loopback with no matching rule is allowed.

A sandbox sees a connection (address, port), not the call, so per (address, port):
- An unconditional rule (host and port only) is exact.
- A conditional allow (it sets `binary`, `method` or `path`) makes the sandbox allow that address and port.
  The entry is reported as `coarsened`, and MoorAI's check still enforces the field.
- A conditional block is left to the default (`omitted`).
- An unconditional block always beats a coarsened allow. The allow is reported `narrowed`. A block is never
  let through by an over-broad expression.

**The report.** Each entry is `{ index, id?, action, fields, effect, reason }` (index `-1` is
`egressDefault`). It never carries a host, path or binary value. Effects:
- `omitted`: not in the sandbox; MoorAI's check is the only layer.
- `coarsened`: in the sandbox without these fields, so the sandbox is wider than the rule.
- `narrowed`: the sandbox is stricter than the rule.
- `approximated`: matched by a different notion.
- `may-be-inert`: emitted, but it may not take effect.
- `invalid`: MoorAI drops it too.

**MXC.** Schema fields used, from `test/fixtures/mxc/mxc-config.schema.1.0.0.json`:
- `NetworkEgress.deny`: "Optional explicit deny rules. Deny takes precedence over allow."
- `NetworkRule.to` / `NetworkPeer.cidr`: "The IPv4 or IPv6 CIDR this destination matches."
- `NetworkPort.port`, `endPort` ("Optional inclusive end of a destination-port range") and `protocol`.

How rules map:
- An IP literal becomes a `/32` or `/128` rule. Allows are `tcp`. Denies match any protocol, and "every port
  but these" is written as `endPort` ranges.
- `egress.default` stays `deny` whatever `egressDefault` says (reported as `mxc-default-deny`).
- `ingress` is unchanged.
- A block beats the host-only `egressAllow` CIDRs.

Not expressible:
- Hostnames and `*.suffix`. microsoft/mxc `networking.md` §1.1: "The egress schema selects numeric
  destinations, protocols, and ports, not durable DNS names or application payloads."
- Loopback, including 127.0.0.0/8. Host loopback is the single bidirectional `ingress.hostLoopback` switch
  that the model proxy needs.
- `binary`, `method` and `path`.

Private destinations (RFC 1918, 169.254/16, fc00::/7, fe80::/10) are emitted but flagged `may-be-inert`.
`networking.md`: ProcessContainer "requires `ingress.default: "allow"` before the container can communicate
with private-network addresses". MoorAI keeps ingress deny.

The desktop host reads `egressRules` / `egressDefault` from the host-only `mxc.json`. `plan_launch`
re-reads it through `Host::read_file`, because `LaunchRequest` is built in `lib.rs`. The terminal note
counts the unexpressed entries. The console policy and the machine-wide config are **not** fed to MXC yet.

**Seatbelt.** Measured with `sandbox-exec -p` on macOS 27.0 (26A428):
- `(remote ip "1.2.3.4:443")` and `(remote ip "example.com:443")` fail with "host must be * or localhost in
  network address".
- `"*:1-100"` fails with "invalid port in network address".
- `localhost:*` covers 127.0.0.1, ::1 and 0.0.0.0, but not 127.0.0.2.
- Between filtered rules the last match wins. An unfiltered `(deny network-outbound)` is the default wherever
  it sits.
- A bare deny also refuses `AF_UNIX` connects.

So only loopback can be named:
- `localhost`, `127.0.0.1` and `[::1]` all become `localhost`, reported as `seatbelt-localhost-alias`.
- `egressDefault: "block"` becomes `(deny network-outbound)` plus `(allow network-outbound (remote
  unix-socket))`, `localhost:*` per the loopback rules, and per-port lines after it.
- Every other host keeps the default and is reported `seatbelt-host`.

Fail-safe choice:
- Under a block default, an allowed hostname is not reachable inside Seatbelt. Route it through a loopback
  proxy.
- Under an allow default, a hostname block is enforced by MoorAI's check only.
- Measured widening: `localhost:*` also admits 0.0.0.0, which MoorAI's check does not count as loopback.

The desktop host reads the rules only from `/etc/moorai/config.json`, and only when it is root-owned and not
group- or world-writable, is not a symlink, and sits in directories that are root-owned and not group- or
world-writable, checked on the open file (`src-tauri/src/admin_config.rs` `read_admin_owned`, the reader of
every administrator source). It never reads them from `~/.moorai/config.json`.

**OpenShell** (the OpenShell repository @ b959bb6, `docs/how-it-works/policies/schema.mdx` and `network-rules.mdx`).
Relevant quotes:
- "OpenShell checks every outbound connection ... and denies any connection that no rule allows."
- "Network rules are not an ordered firewall list ... A matching deny rule takes precedence over any allow".
- Endpoint `host` is "Hostname, IP address, or wildcard pattern". It takes `port` or `ports` ("Set `port` or
  `ports`"), `protocol: rest`, `enforcement: enforce`, `rules` / `access` and `deny_rules`.
- "A wildcard host must have at least three DNS labels".
- Binary `path` is "Executable path or glob", and "A binary matches the executable that opens the connection
  or any of its parent processes".

How rules map:
- `*.suffix` becomes `**.suffix`: "`**` matches across separators", matching MoorAI's any-depth suffix.
- A binary name becomes `/**/<name>`, reported as `approximated`. No binary becomes `/**`.
- Tool names (`webfetch`, `mcp__…`, `invoke-webrequest`) are not executables, so the rule is omitted.
- Method and path become REST `rules`. A `/prefix*` path becomes `prefix**` (or `prefix*` plus
  `prefix*/**`), reported `narrowed` at the trailing-slash edge.
- An earlier MoorAI block that an allow would cover:
  - A method or path block becomes `deny_rules` on that endpoint. A prefix-path block is widened to `**`.
    The endpoint becomes inspected (`access: full`).
  - A host-level block removes the allow (`openshell-shadowed-by-block`, or `openshell-no-connection-deny`
    when it covers only part of the allow). OpenShell has no connection-level deny.

Not expressible:
- A default allow.
- Rules without a port.
- Loopback ("never authorizes an outbound endpoint whose destination is loopback").
- IPv6 literals: the bracket form is not confirmed by the docs.
- 169.254/16 and 0.0.0.0.
- Control-plane ports 2379, 2380, 6443, 10250 and 10255, reported `narrowed`.

Only `version` and `network_policies` are generated. Merge them into a complete policy; filesystem, Landlock
and process stay the operator's.

**gVisor / OCI.** Not a target. runsc does not enforce per-host egress itself. A gVisor workload's egress
comes from the deployment's network policy, which is being built separately under `deploy/`; nothing here generates a gVisor policy.

**Not proven.**
- No MXC container has loaded a policy with `egress.deny` or `endPort`. They validate against schema 1.0.0
  only.
- Whether WFP enforces a deny over an `egressAllow` CIDR as the schema states.
- Whether private-network allows take effect.
- No OpenShell build has parsed the generated YAML. In particular `/**` and `/**/<name>` binary globs, path
  `**`, and `access: full` together with `deny_rules` are taken from the docs, not run.
- Seatbelt rules were measured only for loopback ports and default deny (`test/sandbox-policy.test.mjs`
  runs the generated section under `sandbox-exec`).
- The macOS host path that reads `/etc/moorai/config.json` was tested for refusing a user-owned file, a
  symlink, a group- or world-writable file or directory, a path outside its directory and a FIFO, with the
  test's own uid standing in for root; reading a root-owned file was tested only on `/etc/hosts`.
- A `deny_rules` entry on one OpenShell endpoint can also deny requests that another overlapping rule
  allows (narrower, not reported).

## Native settings from one policy

**Status: built and unit-tested (`test/native-settings.test.mjs`, `test/native-settings-drift.test.mjs`,
`test/native-settings-cli.test.mjs`, goldens in `test/fixtures/native-settings/linux/`). One part was run
against a real host: Claude Code 2.1.295, given the compiled file through `--settings`, refused
`claude mcp add` for a server not on the compiled `allowedMcpServers` ("not allowed by enterprise policy") and
accepted it from a file that listed it. No compiled file has been placed at a managed path, and no Codex,
Copilot CLI, Gemini CLI or Cursor run has read one. The heartbeat field is not wired yet (below).**

[`cli/native-settings.mjs`](../cli/native-settings.mjs) `nativeSettings(policy, host, { platform, mcpIdentities })`
→ `{ ok, host, platform, files:[{ path, format, scope, merge, content }], unexpressed, notes }`. Pure. One module
per host in [`cli/native-settings/`](../cli/native-settings/); the portable subset is
[`intent.mjs`](../cli/native-settings/intent.mjs), the egress-to-domain-list mapping is
[`egress.mjs`](../cli/native-settings/egress.mjs). CLI: [`cli/moorai-native-settings.mjs`](../cli/moorai-native-settings.mjs)
(`compile`, `check`). Drift: [`cli/native-settings-drift.mjs`](../cli/native-settings-drift.mjs).

**The portable subset.** Tool names are Claude Code's, which every MoorAI host adapter translates into.
- `tagActions`: `block` → deny and `ask` → ask, for the built-in tools whose tag is fixed
  (`data/tool-tags.js BUILTIN_TOOL_TAGS`). Always reported `coarsened` (`tag-beyond-builtin-tools`): the tag also
  lands on MCP tools and on parsed shell commands. `read-private` is decided from content: `omitted`. A console
  exception for `tag:<tag>` lets calls through MoorAI that the native deny refuses: `narrowed`.
- `entitlements` with `entitlementMode: "block"`: `tools` → an allow-only list (each host denies every other
  built-in it can name; reported `coarsened` for tools the list cannot name); `mcp` narrows the MCP list. A JIT
  elevation in `elevations` is `narrowed`. `alert` mode allows, so nothing is compiled.
- `mcpAllow` / `mcpGate`: exactly `decideMcpServer` — gate on: the list (empty = none); gate off: a non-empty
  list, else no list.
- `egressRules` / `egressDefault`: validated by `validateEgressRule`. Rules are first-match; host domain lists
  are unordered with deny winning. So: an allow followed by an overlapping block is `narrowed`
  (`<host>-deny-wins`); a `binary`, `method` or `path` field makes an allow `coarsened` and a block `omitted`
  (a domain-wide block would refuse traffic the rule allows); a port on a host with no port syntax does the same.

**Per host, with the schema quoted in each module's header** (docs read 2026-10-21):

| Host | Path (darwin / linux / win32) | Merge | Carried | Not carried (reason codes) |
|---|---|---|---|---|
| Claude Code | `…/ClaudeCode/managed-settings.d/50-moorai.json` | whole (MoorAI's own drop-in) | `permissions.deny` / `ask`; `allowedMcpServers` `{ serverName }` + `allowManagedMcpServersOnly`; `sandbox.network.allowedDomains` / `deniedDomains` (`host:port` per port); `WebFetch(domain:…)` denies; with `egressDefault: "block"`: `sandbox.enabled`, `autoAllowBashIfSandboxed: false`, `failIfUnavailable`, `allowUnsandboxedCommands: false`, `network.allowManagedDomainsOnly` | names outside `[A-Za-z0-9_-]` (`claude-code-server-name-charset`, narrowed); WebFetch to unlisted hosts (`claude-code-webfetch-not-sandboxed`); the sandbox's file confinement (`claude-code-sandbox-filesystem`, narrowed); domain lists with the sandbox off (`claude-code-sandbox-off`, may-be-inert); `*.x` apex matching unstated (approximated) |
| Codex | `/etc/codex/requirements.toml`; `C:\ProgramData\OpenAI\Codex\requirements.toml` | whole | `allowed_web_search_modes = []`; `[allowed_permission_profiles] ":read-only" = true` when every write tool is refused (approximated: it also refuses shell writes); `[mcp_servers.<name>] identity = { command | url }` from `--mcp-identities`, `[mcp_servers]` empty for nothing approved; `[experimental_network]` + `.domains` | shell, read and agent tools have no deny (`codex-no-tool-deny`); asks (`codex-no-tool-ask`); a server with no identity (`codex-mcp-identity-required`: narrowed when others are listed, coarsened when none can be); ports (`codex-no-port-syntax`); unlisted-domain behaviour without the managed lock is unstated (approximated); the section is experimental |
| Copilot CLI | `/Library/Application Support/GitHubCopilot/managed-settings.json`; `/etc/github-copilot/…`; `C:\Program Files\GitHubCopilot\…` | keys | `permissions.deny` / `ask` (`Shell(*)`, `PowerShell(*)`, `Read(**)`, `Write(**)`, `Edit(**)`, `Domain(…)`); `permissions.limitTo` (allowed domains with a block default; `[]` when web tools are refused); `allowedMcpServers` | `Shell(*)` form unverified (approximated); `limitTo` and `Domain()` do not cover shell (coarsened); first-party servers exempt (coarsened); the managed `sandbox` network shape is unpublished |
| Cursor | `~/.cursor/cli-config.json` (user scope) | keys | `permissions.deny` (`Shell(*)`, `Read(**)`, `Write(**)`, `WebFetch(*)`, `WebFetch(host)`) | no managed file, no MCP allow-list file (`cursor-mcp-allowlist-no-file`), no ask list, no default deny (`cursor-no-default-deny`); allow entries are never written (they auto-approve) |
| Gemini CLI | `…/GeminiCli/policies/moorai.toml` (admin tier) and `…/GeminiCli/settings.json` | whole / keys | `[[rule]]` deny (priority 900) and `ask_user` (800) by tool name (`run_shell_command` + `read_many_files` for Bash, `read_file`, `write_file`, `replace`, `web_fetch`, `google_web_search`, `invoke_agent`); `mcpName = "*"` deny for nothing approved; `mcp.allowed` | no network policy (`gemini-no-network-policy`); server names with `_` (approximated); tools MoorAI's adapter does not map (`gemini-tool-not-mapped`) |

No host compiler writes an allow rule that removes a prompt (Gemini `allow`, Cursor `allow`, Copilot `allow`),
and no compiled switch removes one: Claude Code's sandbox auto-allow defaults to on ("`autoAllowBashIfSandboxed`
still defaults to `true`"), and with it a bare `Bash` ask rule is skipped for sandboxed commands, so the
Claude Code file sets it to `false` whenever it turns the sandbox on. Set in managed settings, a lower
settings level cannot change it. Copilot's empty `allowedMcpServers` is the documented deny-all ("an empty
array denies all of them").

**Drift.** `nativeDrift(compiled, { root, home, read })` reads each file (under `root` for tests) and compares:
whole-file TOML byte for byte (`content-changed`); JSON by owned key path, lists as sets (`missing-entries`,
`extra-entries`), scalars (`value-changed`), deleted keys (`key-absent`) and, for files MoorAI owns whole, keys
added by hand (`extra-key`). Each finding says whether it `weakens` the file (a missing deny or ask entry, an
extra allow-list entry, a changed switch, an added key). A missing owned file is state `absent` and a file
that is not JSON (or not a file) is `unreadable`; neither has findings, so `check` judges them by state: exit 3
for `drift` or `unreadable`, 4 for `absent`, 0 when in sync. `nativeSettingsPosture({ policy, platform })` →
`{ v:1, hosts:{ <host>: { state, files, findings, weakening, unexpressed } } }`, counts only.

**Not wired here.** The posture heartbeat is built in `cli/moorai-hook.mjs` and `cli/agent-posture.mjs`, which
this package does not edit. The one-line integration is `nativeSettings: nativeSettingsPosture({ policy,
platform: process.platform })` in the heartbeat body; until it lands, drift is reported by
`moorai-native-settings check` only, and the console shows nothing.

**Not proven.**
- Only the Claude Code MCP allow-list was read by a real host, and only through `--settings`, not from the
  managed drop-in directory. The permission, sandbox and drop-in keys are taken from the docs.
- `autoAllowBashIfSandboxed: false` keeping a Bash ask prompting under the sandbox is taken from the docs; no
  Claude Code session was run with the compiled sandbox on (that needs a model call).
- Codex `requirements.toml`, Copilot CLI managed settings and Gemini CLI policy files were not loaded by those
  hosts (none is installed here). `Shell(*)` / `PowerShell(*)` in Copilot and Cursor are unverified forms.
- The CLI verifies a signature only when `--pubkey` is given; it does not use the device's pin.
- Formats change often; the docs were read on 2026-10-21.

## MCP server network sandbox (`mcpServerSandbox`)

**Status: built; unit tests (`test/mcp-server-sandbox.test.mjs`) and real-guard tests
(`test/mcp-server-sandbox-guard.test.mjs`, the kernel check on macOS only). Linux and Windows have no backend.**
Files: [`mcp-proxy/sandbox-spawn.mjs`](../mcp-proxy/sandbox-spawn.mjs) (plan, notes, alerts, heartbeat field),
[`mcp-proxy/moorai-mcp-guard.mjs`](../mcp-proxy/moorai-mcp-guard.mjs) (`serverSpawnPlan`, the spawn), the
heartbeat in `cli/moorai-hook.mjs`. User docs: [`mcp-proxy/README.md`](../mcp-proxy/README.md) "Network sandbox
for the server process".

**Contract.**
- Policy field (signed policy, and the root-owned admin binding as a top-level key): `mcpServerSandbox`:
  `"off"` (default) | `"network"`. Precedence that of `failMode`: admin binding, then the verified policy,
  then `"off"`. Exact lowercase values only; an invalid value is warned about by source and key (never the
  value) and the next source decides. The stdio guard reads both before it starts the server, from local
  copies only (`loadVerifiedPolicy(CONFIG, { network: false })`).
- `"network"` on macOS with `/usr/bin/sandbox-exec`: the guard spawns `sandbox-exec -p <profile> <cmd>
  <args...>` with the same environment and stdio pipes. Profile: `(version 1)`, `(allow default)`, then
  `sandboxPolicy({ egressRules, egressDefault }, "seatbelt").policy` (section above). Rules: the policy's
  `egressRules`, then the admin binding's; default: the policy's `egressDefault`, else the admin binding's
  (the order of `cli/egress-rules.mjs` `egressFrom`).
- **Effect.** Seatbelt names loopback only. With `egressDefault: "block"` every non-loopback outbound
  connection is refused by the kernel (`EPERM`), including hosts an allow rule names (reported `omitted`,
  `seatbelt-host`): servers that need an internet API, and `npx -y` / `uvx` launches that fetch code at start,
  fail. In that mode only, the profile ends with (measured on macOS 27.0: without them a public name still
  resolves through mDNSResponder, and osascript / open reach other apps):
  `(deny mach-lookup (global-name "com.apple.mDNSResponder") (global-name "com.apple.mDNSResponderHelper")
  (global-name "com.apple.nsurlsessiond") (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.lsd.mapdb") (global-name "com.apple.lsd.open"))`, `(deny appleevent-send)`,
  `(deny network-outbound (literal "/private/var/run/mDNSResponder"))` (after the unix-socket allow; the last
  filtered match wins) and `(deny process-exec (literal "/usr/bin/open") (literal "/usr/bin/osascript"))`.
  Measured with them: a public `dns.lookup` is `ENOTFOUND`, python `getaddrinfo` fails, `localhost` resolves,
  loopback connects, node / python / `npx --version` and child processes start, exec of `open` / `osascript`
  is `EPERM`. Measured without the exec deny: `open -g -R /tmp` still exits 0 with the LaunchServices mach
  services denied. With any other default no non-loopback host and no DNS is restricted.
- **Scope, stated in the docs and on stderr.** Experimental. The sandbox restricts the server process's own network
  connections and DNS. It is not full containment: file and process access are not restricted (a server can
  still write a LaunchAgent or cron job, edit MCP-client or MoorAI config, or run `launchctl`, and that work
  runs later outside the sandbox), and handing
  work to another app is closed only for AppleEvents and exec of those two binaries (other routes to
  LaunchServices were not measured).
- **Unexpressed rules.** Each `unexpressed` entry is written to the server's stderr and listed in one alert,
  category `Containment: MCP server sandbox rules not expressed`, Medium, `decision: "notify"`, fields
  `unexpressed: [{ index, source: "policy" | "admin" | "default", id?, action?, fields, effect, reason }]`
  (at most 64), `unexpressedCount`, `blocksNonLoopback`. `index` is the rule's index in its own document.
- **No backend** (not darwin, `sandbox-exec` missing, profile not built): `failMode.mcpGateway` decides.
  Closed: the server is not started, the guard exits 1, alert category `Containment: MCP server sandbox
  unavailable`, `riskLevel: "Blocked"`, `decision: "deny"`, `reasonCode: CONTAINMENT_UNAVAILABLE`,
  `enforcement: STRENGTHENED`, `failMode: "closed"`. Open (default): the server starts unsandboxed, the same
  category with `riskLevel: "High"`, `decision: "notify"`, `failMode: "open"`, and a stderr line. Both carry
  `sandboxWhy` (`platform` | `no-sandbox-exec` | `profile-error`), `sandboxMode`, `sandboxSource`,
  `failModeSource`, `mcpServer`, `stage: "mcp"`, `tool: "desktop:mcp-sandbox"`. Coach mode never refuses.
  Why this and not the desktop host's behaviour (which runs unsandboxed when it cannot write its profile):
  every other guard capability that cannot run follows `failMode.mcpGateway`, and a silent fallback would
  hide that the requested protection is missing.
- Posture heartbeat, top level: `mcpServerSandbox: { mode: "off" | "network", state: "on" | "unavailable" |
  "off" }`, from static prerequisites (platform and `sandbox-exec` present), not from a running server. `"on"`
  means the network profile can be applied, not that the server is contained.

**Not covered.** Linux (a bwrap/landlock or network-namespace backend) and Windows (MXC) are not wired.
Servers a host starts without the guard. Remote (HTTP) servers behind `mcp-gateway`: no local process.
Files and processes inside the sandbox are unrestricted; app hand-off is closed only as above. A running
server keeps the profile it started with.
**Not proven:** a real third-party MCP server under the profile (only the fixture server was run); how a
real MCP client presents a server the guard refused (only the exit code was measured). The mDNSResponder
mach-lookup and `appleevent-send` denies are checked on the profile text only: in the real test the socket
deny alone already stops `dns.lookup`, and the exec deny already stops `osascript`, so neither line was
shown necessary on its own.

## Placeholder credentials (model proxy and MCP gateway)

**Status: built and unit-tested (`test/model-proxy-credentials.test.mjs`,
`test/mcp-gateway-credentials.test.mjs`). Opt-in; without a bindings file both components behave exactly as
before.**

The agent process holds a placeholder (`moorai-ph:<name>`) instead of an API key or MCP token. The two
network components hold the real secret and swap it in only when a request goes to the upstream it is
bound to:

- `moorai-model-proxy --credentials <file>` (or `MOORAI_MODEL_PROXY_CREDENTIALS`);
- `moorai-mcp-gateway --credentials <file>` (or `MOORAI_GATEWAY_CREDENTIALS`, or `"credentials"` in
  `--config`).

Both run as another user or in another container. The code is shared:
[`model-proxy/credentials.mjs`](../model-proxy/credentials.mjs) (bindings file and request gate) and
[`model-proxy/credential-mask.mjs`](../model-proxy/credential-mask.mjs) (response masking).

- **Bindings.** A host-only JSON file maps each placeholder to `{ secret, route, upstream, header, scheme? }`.
  - `secret` is `{ env }` or `{ file }`. A literal is refused, so the bindings file is never a second copy
    of the key.
  - `upstream` must equal the route's configured upstream exactly.
  - `header` cannot be one the component strips or owns.
  - Startup fails (exit 2) when the bindings file or a secret file is group- or world-writable, or on
    POSIX is owned by another non-root user. It also fails on a malformed binding, an unset env var, or a
    secret under 8 or over 4096 characters or with a control character.
  - No error, log line or alert carries a secret value.
- **Requests.** Checked before the body is read, content-free:
  - A placeholder in its bound header on its bound route (prefix **and** upstream origin + path) has the
    whole header value replaced by `[scheme ]secret`, after the hop-by-hop strip.
  - Another route (even one to the same host): 403. Another header: 403. Unknown, malformed, or the wrong
    scheme: 401. In the query string: 400.
  - A credential header (or any header carrying a placeholder) sent twice in any letter case: 400. This
    is checked on the raw headers, because Node keeps the first `Authorization` and drops the rest.
  - A raw, non-placeholder credential is forwarded and reported once per route (content-free). With
    `--require-placeholders` it is refused with 401. A non-empty `key` query parameter (the Gemini API's
    `?key=<API key>` auth) counts as a raw credential the same way, on the model proxy and the HTTP MCP
    gateway alike; the key is never logged or reported.
- **Responses.** Every upstream response is masked for every bound secret before anything reads it:
  - a verbatim copy in a header, the status line or the body becomes `*` of the same length;
  - this holds across chunk boundaries;
  - gzip, deflate and br bodies are decoded first, and any other content coding is answered 502.

**Limits, stated plainly:**

- It only protects keys used **through these two components**. A direct HTTPS call, an SDK pinned to the
  provider, a stdio MCP server with its own environment, or an OAuth flow the client completes itself is
  not covered.
- A key the agent can **read itself** is not protected. That includes `.env`, its environment, a config
  file, or the component's secret file or environment when both run as the same user
  (`/proc/<pid>/environ`).
- The agent can still **use** the placeholder through the component. Whatever the key allows on that
  route, the agent can do; policy decides what goes through.
- Masking catches a **verbatim** echo only. A key split across SSE events, JSON-escaped, encoded, or
  partly echoed passes. The bound upstream is trusted with the key.
- No secret-derived comparison is made, so none needs to be constant-time. A placeholder is a map lookup on
  its name. The masking hold-back, where a chunk tail that matches a secret's prefix waits for the next
  chunk, is an unmeasured timing signal.
- Secrets are read once, at startup, so rotating one needs a restart.
- Windows file ACLs are not checked.

## Model proxy: tool calls in responses

**Status: built and unit-tested (`test/model-proxy-toolcall.test.mjs`,
`test/model-proxy-toolcall-local.test.mjs`, `test/model-proxy-gemini.test.mjs`, `test/model-proxy-ollama.test.mjs`,
`test/model-proxy-function-rules.test.mjs`, `test/serve-unchecked.test.mjs`).
Replace mode and the skip alert are opt-in.**

`moorai-serve` is advisory: it judges a tool call only if the framework asks. The model proxy sits on the
path every agent action starts on, the model's response, so it judges every tool call there, whether or not
the framework ever asks.

- **Decision.** It is `runtime.toolCall`, the function `/v1/tool-call` calls. The model's tool name and
  input are mapped onto the hook's tool names (`model-proxy/check.mjs mapTool`): shell→`Bash`,
  read→`Read`, write→`Write`, fetch→`WebFetch`, Anthropic's `bash` and text-editor tools, `mcp__*` as named.
  An unknown function is content-scanned rather than named `mcp__…`, so that MCP allow-lists and
  `mcpFloor` do not deny every unknown function.
- **Parsed.** Anthropic `tool_use` and OpenAI `tool_calls` / `function_call`, both JSON and SSE. A streamed
  call is held until it is complete, then judged.
- **Gemini** (`model-proxy/gemini.mjs`, `gemini-replace.mjs`). `functionCall` parts of
  `…/models/<model>:generateContent` and `:streamGenerateContent` responses: JSON, the JSON array sent
  without `alt=sse`, and `alt=sse` events, on any route (the Gemini API and Vertex AI publisher-model and
  tuned-endpoint paths). A streamed turn is held from its first `functionCall` event until every candidate
  that started a call has sent its `finishReason`, then its calls are judged together. Refused: 403
  `PERMISSION_DENIED`, or mid-stream a bare `{"error":{"code":403,…}}` line, the shape both Google Gen AI
  SDKs raise on. Replaced: the turn's `functionCall` parts become one text part (the call's
  `thoughtSignature` goes with it) and `finishReason` is `STOP`. Requests: user text, `systemInstruction`
  and the string values of `functionResponse.response` are scanned; camelCase and snake_case both read.
  Vertex streamed `partialArgs` are refused in enforce mode (no documented assembly rule). The default
  routes include `/gemini` → `https://generativelanguage.googleapis.com`; `--route` replaces all defaults.
- **Ollama native API** (`model-proxy/ollama.mjs`, `ollama-replace.mjs`, `ndjson.mjs`). `POST …/api/chat`
  `message.tool_calls[]` `{id?, function: {name, arguments}}` (`arguments` an object), JSON and NDJSON, on
  any route. A streamed turn is held from its first tool-call line to its `done: true` line; a line that is
  not JSON, or an upstream `{"error"}` line inside a held turn, is refused. Refused: 403 `{"error": …}`, or
  mid-stream an `{"error": …}` line. Replaced: `tool_calls` removed, the refusal appended to the content.
  Requests: `system` / `user` / `tool` messages; `/api/generate` `prompt`, `system`, `suffix`, `template`.
  `/api/generate`'s generated text is scanned report-only (stage `output`, PostToolUse, never withheld). The
  default routes include `/ollama` → `http://127.0.0.1:11434` on a loopback bind only.
- **Function names** (`model-proxy/function-rules.mjs`). `policy.functionToolActions: { "<name>" | "<prefix>*":
  "block" | "ask" | "alert" | "allow" }`, exact and case-sensitive, strictest match wins, decided on the name
  before the arguments; `ask` is settled by the headless rule in enforce mode. Alert `tool:
  "model-proxy:<name>"`, never an argument. Read by the model proxy only.
- **Wrapped arguments** (`check.mjs unwrapArgs`). A call that does not map is retried with its arguments
  unwrapped when exactly one key is `arguments` / `parameters` / `args` / `input` holding an object and every
  other key is `function` / `name` / `tool` / `tool_name` equal to the tool's name (up to 4 levels).
- **Enforcement.** `--mode enforce` refuses the response by default. With `--denied-tool-call replace`,
  every client tool call of the turn is withheld and replaced by one text block naming the tool and the
  reasons. The turn ends with `end_turn` / `stop`, no tool-call id is orphaned, and block indexes stay
  contiguous. Report mode delivers the bytes unchanged and alerts.
- **Local models.** An OpenAI-compatible server on loopback is a `--route` with plain http. It is tested
  against a fake that streams a whole call in one chunk.
- **Skip alert** (`--unchecked-window-ms`, off by default). The proxy keeps an HMAC of each forwarded call
  id. `moorai-serve --model-proxy-url` passes each checked `toolCallId` back over loopback. An unmatched id
  raises `Model proxy: tool call forwarded with no framework check` (`notify`, content-free, counted per
  tool name). It is bounded by `--unchecked-max`.
- **Latency** (measured, n=150 paired): the hold plus the decision adds p50 1.5 ms and p95 2.0 ms to a
  streamed turn with one tool call. One decision is p50 1.3–3.1 ms.

**Limits:**

- Only traffic forced through the proxy is covered. Bedrock, Gemini's Interactions and Live APIs, Vertex
  partner models (`:rawPredict`), the OpenAI Realtime API, `GET …/responses/{id}` (Responses background mode)
  and Ollama's non-chat endpoints are forwarded unparsed.
- **OpenAI Responses API** ([`model-proxy/openai-responses.mjs`](../model-proxy/openai-responses.mjs), shapes
  from the official SDK's types): `instructions`, user / system / developer input and fed-back
  `function_call_output` / `custom_tool_call_output` / `local_shell_call_output` / `shell_call_output` /
  `apply_patch_call_output` are scanned (`computer_call_output` is a screenshot, not text); `function_call`,
  `custom_tool_call` (its free-text `input` scanned as `{ input }`) and `mcp_approval_request` (named
  `mcp__<server_label>__<name>`) are decided, and so are the built-in tools the client runs:
  `local_shell_call` (argv `action.command`, with `action.env`) and `shell_call` (`action.commands`) as
  `Bash`, `apply_patch_call` as `Write` (`create_file`, `delete_file`) or `Edit` (`update_file`) of
  `operation.path` with the diff as content, and `computer_call` content-scanned under the name `computer`
  (a workload profile's tool list does not restrict it). A shell call without a list of command strings, or
  an unknown patch operation, is refused in enforce mode. Server-run calls (`mcp_call`, web search, code
  interpreter) and reasoning items are not decided. A stream is
  held from the first event that carries a call until `response.completed` / `.incomplete` / `.failed`;
  every distinct reading of a call (the item as added and as done, the concatenated argument deltas, the
  `.done` arguments, a `shell_call`'s commands rebuilt from `response.shell_call_command.*` events and their
  `.done` values, the terminal response's output) is decided, and a denied one ends the stream with an
  `error` event (`code: "moorai_policy_denied"`). A stream that ends while a call is held is refused. With
  `--denied-tool-call replace`, a non-streaming response has its call items removed and a refusal message
  added; a stream is refused instead (rewriting the event sequence is not implemented). Measured with the
  official OpenAI Node SDK 4.104.0 (a copy already on the test machine, not a repo dependency) against the
  fake provider: an allowed call streamed through intact, a denied non-streaming call raised
  `PermissionDeniedError` (403, `moorai_policy_denied`) and a denied streamed call raised `APIError` after the
  text events. Not run against the real provider.
- **Embeddings** ([`model-proxy/openai-embeddings.mjs`](../model-proxy/openai-embeddings.mjs)): string inputs
  (a string or a list, up to 2048) are scanned as prompt content, so a secret sent for indexing is caught as
  it would be in a prompt. Token-id inputs are not text and are not scanned. Responses carry no tool call.
- Gemini is tested against a fake upstream only, never a real Gemini API or Vertex endpoint or the real
  `@google/genai` / `google-genai` packages. A placeholder in the `?key=` query string is refused (400),
  never swapped: bind it to the `x-goog-api-key` header instead. Server-side tools (`server_tool_use`, `mcp_tool_use`) are not judged.
- In replace mode, text the model wrote after a tool call in the same turn is dropped with the call.
- The skip alert detects a framework that skipped the check, not one that lies. Anything on loopback with
  the proxy token, the agent included, can mark an id as checked.
- No real LM Studio, llama.cpp or vLLM build has been run against it, nor a real Ollama on `/v1`. Ollama's
  native `/api/chat` was run live (0.15.6, `mistral-nemo`, enforce, JSON and NDJSON); replace mode,
  `/api/generate` and the wrapped-argument shape were tested against a fake upstream only.
- `functionToolActions` alerts carry the derived reason code `OBSERVATION_ONLY` (no dedicated code exists).

## Model proxy: intent alignment and reply text

**Status: built and unit-tested (`test/model-proxy-intent.test.mjs`, `test/model-proxy-response-scan.test.mjs`,
`test/model-proxy-intent-review.test.mjs`, `test/model-proxy-reply-scan-review.test.mjs`,
`test/intent-alignment-control.test.mjs`), in process against fake upstreams for Anthropic, OpenAI Chat Completions and Responses, Gemini and Ollama,
streaming and not. The intent store (`data/intent-server.mjs`) is a test double there; one test runs the
real module, and `test/servers-intent-e2e.test.mjs` runs the proxy CLI and moorai-serve on it end to end
against a fake upstream. Not run against a real provider or SDK.**

**Intent alignment** ([`model-proxy/intent.mjs`](../model-proxy/intent.mjs),
[`user-turns.mjs`](../model-proxy/user-turns.mjs)). Each tool call the model returns that maps to a hook tool
and is not already denied is judged by `data/intent-server.mjs` against the session's task.
- Session, first match: `X-MoorAI-Session-Id` (not sent upstream), `X-Claude-Code-Session-Id`, the trace-id
  of a valid incoming `traceparent`, a keyed hash of the conversation's first user turn, else the session
  `none`. No owner principal is passed to the store (the proxy has no per-client principal), so a proxy's
  clients share one session space.
- Task: the first and the latest real user turn of a session's first captured request; after that only each
  request's latest user turn (the proxy remembers captured sessions as keyed hashes, at most 1,024, 24 h), so
  a rewritten first turn is never learned again. A turn opening with Claude Code's compaction preamble ("This
  session is being continued from a previous conversation that ran out of context.") is never captured. System and developer text, tool results,
  function responses, documents, and the text blocks sent with Anthropic `tool_result` blocks are never
  the task. Harness blocks are stripped first (one stack scan per text; kept: the text before the first
  harness tag, plus the text after that block only when it closes cleanly and no further harness tag
  follows; an unclosed block, a tag with no closing `>`, a stray close or an interleaved close also drops the
  rest of the turn): `<system-reminder>` (Claude Code's CLAUDE.md, memory and session context),
  `<task-notification>`, `<bash-stdout>`, `<bash-stderr>`, `<local-command-stdout>`, `<local-command-stderr>`,
  `<user-prompt-submit-hook>`, `<ide_selection>`, `<ide_opened_file>`, `<mcp-resource server=… uri=…>` (a tag may
  carry attributes of any length) — identified in Claude Code 2.1.295's bundle. Captured only from a request that
  declares tools (a tool-less side request — WebFetch summarisation, compaction — adds nothing), and only
  when the provider's 2xx response begins. A body that does not parse (gzip, BOM) captures nothing and is
  judged in the header's session, else `none`.
- Whose turn: a sub-agent's first user turn is the parent model's prompt; the proxy judges a sub-agent's
  calls against it. For a task that is the person's by construction, use `X-MoorAI-Session-Id` with
  moorai-serve's `POST /v1/task` or the Agent SDK's capture.
- Judged on every reading of a call that maps to a hook tool (as sent, `cmd` read as `command`, a
  dispatcher's inner tool …), each with its own findings; the strictest verdict wins.
- `moorai-control`: every upload to a loopback host is judged, whatever the port (readable or not; MoorAI's
  moorai-serve 8790, proxy 8791, MCP gateway 8848, or any other local service); the port is only the
  target's detail. URL, bare `host:port`, `nc`, `socat`, UNC; the host normalised (any inet_aton IPv4
  spelling, `0`, `::1`, IPv4-mapped IPv6, a trailing dot). Risky and never aligned; remote hosts in the same
  command stay among its targets. A curl / wget destination given as a bare argument (or
  `--url=`) is an egress site; one whose host is unresolvable shell text, or whose authority cannot be
  read, is the site `unknown`, never aligned. Any upload form with no readable destination (scp / rsync /
  sftp to a dotless ssh alias, `Invoke-RestMethod -Uri $u`, nc / socat to a variable, `curl -K cfg`) is
  egress to `unknown`, and so is each host past the first 64 in one command; only a copy onto WSL's own
  file share and nothing else is not judged.
- Task unknown: a risky call in a session with no live captured task (no user turn ever seen, evicted,
  expired) is class `task-unknown`, handled as misaligned; `block` refuses it and `ask` asks.
- `intentAlignment`: `off`; `report` (default: one alert per target per session); `ask` (enforce: the
  headless ask, a deny unless `--headless-ask allow-with-report`; `--headless-ask pass-through` is refused
  at startup); `block` (enforce: the proxy's refusal or replacement text). In `--mode report` an ask or
  block outcome is stamped `enforcement: LIMITED`.
- Alert: the hook's `category: "Action outside the stated task"`, `reasonCode: "INTENT_MISMATCH"`,
  `threatId: 64`, `stage: "behavior"`, `intent: {class, mode}`, `contentHash` (tenant-keyed hash of the
  class and the store's keyed target hash). No prompt, host, path or argument.
- Key: `--intent-key-file` (64 hex characters, root-owned, not group- or world-writable), else 32 random
  bytes per process. Store limits: 1,024 sessions, 512 features each, 24 h.
- Limits: lexical (a named host is aligned even when it is the exfiltration target); unmapped functions are
  not judged.

**Reply text scanning** ([`model-proxy/response-scan.mjs`](../model-proxy/response-scan.mjs),
[`text-codecs.mjs`](../model-proxy/text-codecs.mjs), [`text-guard.mjs`](../model-proxy/text-guard.mjs)).
- Found: #39 secrets, #1 payment-card data, #15 personal data (the engine's output-stage detectors for
  those threats, policy-built, packs included; a `disabled` threat is skipped) and #52 a 24-word run of
  this request's system prompt (8-word shingles, HMAC-SHA256 with a per-process key, 48 bits kept, at most
  8,192; prompts under 24 words are not tracked; nothing but the hashes is kept).
- `responseScan`: `report` (default; forwarded byte-identical), `mask` (enforce: the match becomes
  `[REDACTED:#<threat>]` or `[REDACTED:system-prompt]`; changed events are re-serialized), `block` (enforce:
  403, or the provider's error event mid-stream). In `--mode report` mask and block are reported with
  `enforcement: LIMITED`.
- Streaming window per text channel: 256 characters already sent plus the unsent text. Report: nothing
  held, scanned each 4,096 characters. Mask / block: the last 256 characters held back, so a match of up to
  256 characters is found before any of it is sent; a longer one is found after its start was sent
  (`sent: "partial"`), and sent text cannot be recalled. Report mode keeps exactly the last 256 characters
  (a spaced card across a batch boundary is found). At most 64 channels; past that mask / block fail closed
  (the event is refused before any of it is taken; a closed fail mode stops the stream). A re-serialized
  event or body keeps every number's source text (an integer past 2^53 is not rounded); a Responses flush
  repeats the last delta's `sequence_number`. Measured: 18 µs of CPU per streamed piece in mask / block
  mode, 0.2 µs in report mode.
- Alert: `category` "Model proxy: <class> in the model's reply" / "… system prompt reproduced in the
  model's reply", `stage: "output"`, `tool: "model-proxy:response-text"`, `responseScan: {class, mode,
  applied, sent}`, `contentHash` (tenant-keyed hash of the match; for #1 and #15, low-entropy values, an
  HMAC under a per-process random key, `proc:…`, which the install token cannot enumerate). One per class
  and hash per response, at most 32.
- Token log-probabilities (`logprobs`, `top_logprobs`, Gemini `logprobsResult`) are removed from every event
  and body in mask / block; report mode changes nothing.
- Not scanned: reasoning (thinking, thought parts), refusal fields, log-probabilities in report mode, Anthropic
  `citations[].cited_text`, Gemini `executableCode` / `codeExecutionResult`, OpenAI `audio.transcript`, images,
  audio, embeddings.

## Local models with safety training removed (by name)

`cli/local-model-names.mjs`, reported by `moorai-aibom` as `localModelSafety`. A governance signal: an
admin learns that a device has a local model whose **name** says its safety training was removed.

- **Reads (in memory, never output):** Ollama `<models>/manifests/<registry>/<ns>/<model>/<tag>` and
  `GET http://127.0.0.1:11434/api/tags`; LM Studio `~/.lmstudio/models/<publisher>/<model>/` (and the
  pre-0.3 `~/.cache/lm-studio/models`); Jan `<data>/{llamacpp,mlx}/models/<org>/<repo>/`; GPT4All's model
  folder; the llama.cpp `-hf` cache; the Hugging Face hub cache `models--<org>--<name>`. Paths per OS and
  their env overrides (`OLLAMA_MODELS`, `LLAMA_CACHE`, `HF_HUB_CACHE`, `HF_HOME`) are quoted from each
  project's docs in the module header.
- **Emits:** `{ basis: "name", safetyRemovedByName, count, sources: [{ runtime, models, safetyRemovedByName }],
  truncated, timedOut }`. Runtime ids, integers and booleans only.
- **Tokens** (whole words of the name): `abliterated`, `obliterated`, `uncensored`, `decensored`,
  `unaligned`, `jailbroken`, `heretic`. Each has a public example and a reason in the module. Left out:
  `jailbreak` and `guardrails` (their top hub hits are detectors), `lexi` (an ordinary coder uses it; Lexi
  uncensored models also say "Uncensored"), `unfiltered` (EleutherAI uses it for unfiltered pretraining
  data in a safety study), `nsfw`, `dolphin`.
- **Bounds:** 2 s for the whole scan; `/api/tags` gets only the time left, with a total timer, 1 MiB and
  1,000 models (Rust refuses a chunk size over 1 MiB before any arithmetic; a chunk size of 2^64-1 gives
  no result in JS and Rust, pinned in `test/fixtures/local-ai/model-names.json`); 5,000 directory entries
  in all and 1,000 from one directory; fixed depth per runtime.
- **Left out on purpose:** a count of Hugging Face models from publishers outside a major-org allowlist.
  On this development machine all 3 cached models came from small publishers and all 3 were benign vision
  models. Quantizers who republish everyone's models (bartowski, mradermacher, unsloth, mlx-community)
  would also count, so the number would mostly mean "uses Hugging Face".
- **Limits:** it never looks at weights. It does not prove or disprove a backdoor (a backdoored fine-tune
  has an ordinary name), a renamed model is not caught, and a token glued to other lower-case letters
  (`llamauncensored`) is missed. An Ollama server on a non-default port whose models live outside the
  directories above is missed. Not mirrored in the desktop host (`src-tauri`) yet, so the console does not receive it.

## Download-then-run, secret-file upload and out-of-band collection hosts

Built against a published trigger-backdoor study whose model, inside a coding agent, downloaded a script
to a file, ran it, and posted `.env` to a public collection host. Command text is read structurally by
`data/net-exec.js` over `data/shell-parse.js` (the egress rules' shell reader, moved to `data/` so the
engine can use it in every surface).

- **#57 `fetch-then-exec`** — a download that writes a file, then that file (or a file in the download
  directory) run later in the same command. Default `justify`.
- **#57 `fetch-then-exec-session`** — the same across Bash calls of one session, from a per-session record
  of keyed hashes of normalised paths (`~/.moorai/fetch-exec.json`; 64 entries per session, 32 sessions,
  24 h). Hook only.
- Heredoc bodies (and PowerShell here-strings) are read as part of the command when what they feed runs
  stdin as code (`bash <<EOF`, `sh -s`, `python3 -`, `pwsh -Command -`, `cat <<EOF | sh`, `@'…'@ | iex`).
- **#55 `secret-file-upload`** — a network client (curl, wget, nc/ncat/socat, Invoke-RestMethod/-WebRequest)
  sending a file #55's `cred-file-access` already classes as a credential file. Default `justify`.
- **#78 `oast-exfil` / #79 `oast-contact`** (new threats) — data sent to, or a bare contact with, a curated
  list of public OAST and request-capture hosts, each verified against its vendor's documentation and
  cited in `data/oast-hosts.js`. Default `notify` for both: no benign corpus exercises them, so the
  promotion rule (zero benign fires in a corpus that exercises the stage) cannot be met yet.

Limits: renamed or copied downloads, variable paths, `scp`/`rsync`/`httpie` uploads, archives of a secret
file, and unlisted hosts are not seen. Benign corpora were unchanged (v2 20/602) but barely exercise these
shapes (2 of 610 samples contain curl/wget). Tested on macOS only.

## OT protocol clients from an agent shell (F30, agent side)

[`cli/ot-protocol-client.mjs`](../cli/ot-protocol-client.mjs) over
[`data/ot-protocol-clients.js`](../data/ot-protocol-clients.js) and `data/shell-parse.js`. MoorAI governs
agents that can reach controllers and never sits inside a PLC or safety system.

- **Input**: a Bash (`sh`) or PowerShell (`ps`) command, split by the shared shell reader, following
  wrappers (`sudo`, `env`, `timeout`, …), `sh -c`, PowerShell `-EncodedCommand` (`-e`, `-ec`, `-enc`, any
  prefix, with `-`, `--` or `/`), `-Command` (any prefix, `-CommandWithArgs`) and a first bare argument,
  `cmd /c` and `/k`, `eval`, `Invoke-Expression` / `iex`, `find -exec` / `-execdir` / `-ok`, runners
  (`uv run`, `poetry run`, `npx`, …) and heredocs fed to an interpreter. Native tools' options are scanned
  POSIX-style on every platform. The hook also passes the scripts it decoded from the command (`scripts`:
  `embeddedScripts` as PowerShell, `decodedCommandPayloads` as POSIX), read into the same result.
- **Interpreter options**: Python's short options are read character by character (`-Ic code`, `-Im mod`,
  `-Wignore`, `-mmod`); options it cannot parse fail closed: every argument is then scanned as code, as a
  module name and as a script path. Node: `--eval=` / `--print=`, short flags combined and ending in `e` or
  `p` (`-pe`), and `-r` / `--require` / `--import` / `--loader` values checked against the Node library list
  (op unknown) and, when given as a path (`./`, `../`, `/`, or a `.js` / `.mjs` / `.cjs` / `.ts` name), read as
  a script too. A long option Node's parser here does not know, written without `=`, may take the next
  argument as its value, so, as for Python, every remaining argument is then scanned as code, as a preload
  and as a script path.
- **Recognised**: `mbpoll` / `modpoll` (two or more positional arguments after options = write, one = read,
  none = unknown), modbus-cli `modbus read|dump|write`, OPC UA tools (`uaread`, `uals`, `uasubscribe`,
  `uahistoryread`, `uadiscover` read; `uawrite`, `uacall` write; `uaclient` unknown), BACnet stack clients
  (`bacrp`, `bacrpm`, `bacwi`, `bacepics` read; `bacwp`, `bacwpm`, `bacrd`, `bacdcc` write),
  `python -m cpppo.server.enip.client` (a `Tag=value` argument = write), `python -m pymodbus.console|repl`
  (unknown), and Python / Node code (`-c`, `-e`, `--eval`, `deno eval`, a heredoc, or a script file) that
  imports a listed library; the library's listed write calls make it a write, else its read calls a read,
  else unknown. A write anywhere in the command wins.
- **Script files**: read only through the reader the hook passes (`scriptReader(cwd)`): a path inside the
  session directory, a regular file, read whole up to 8 MiB. A larger file is streamed for the listed library
  names; each named library is an `unknown` hit marked incomplete, and an incomplete result takes the
  stricter of the read and write actions, since a write could sit in the part not read. A script or a tail
  left unread is never clean: it is an `unknown` hit (`otProtocol` `unknown` when nothing else was named)
  marked incomplete, so it reports by default and is denied when the policy blocks 82.
- **Read budget**: one check reads at most 64 MiB of script in all and starts no read after 2 s
  (`OT_SCAN_BUDGET`), shared by every script it reads (the command, nested shells and the decoded scripts the
  hook passes), with each path read and matched once and replayed after. A script the budget does not cover
  is an unread, incomplete hit, so a command naming many large scripts fails closed instead of pushing the
  hook past its timeout (which the host treats as allow; a synchronous scan also keeps the hook's own
  decision-budget timer from firing). Measured warm on an Apple-silicon laptop: one 8 MiB script 58 ms, a
  300 MiB script 72 ms (fails closed at the budget), 256 segments over 20 distinct 8 MiB scripts plus eight
  decoded copies of that command 444 ms; before the budget, 20 references to one 8 MiB script took 1.1 s and
  eight references to a 300 MiB script 2.1 s, growing linearly with the number of references.
- **Verdict**: `OT_THREAT.read` (81: read and unknown) and `OT_THREAT.write` (82), both resolved through
  `cli/hook-core.mjs threatActionFor` like every other threat (`threatPolicy`, `tierPolicy`, the `mask`
  fallback, the built-in table): `notify` → allow, `justify` → ask, `block` → deny, `kill` → deny and the
  session-kill request, `disabled` → nothing; a value that is not an action fails closed to `block`. With no
  entry both are `notify`: the built-in block tier needs zero measured
  benign fires first. The console's Industrial/OT preset is specified to set 82 to `block`, which its
  `ot-shell-write` approval rule holds (CONTRACT-F28 §6.2); that preset is not in a released console yet. The
  two ids are proposed, not yet in `data/threats.json`.
- **Alert** (content-free): `threatId`, `category` "OT protocol client run from a shell", `riskLevel`
  (Blocked on deny, High for a write, Medium otherwise), `stage` `prompt`, `tool` `hook:<tool>`, `decision`,
  `reasonCode` `OT_PROTOCOL_CLIENT`, `otProtocol` (a listed protocol, or `unknown` for a script left unread), `otOp`, `contentHash` `ot:<protocol>:<op>`.
- **Hook**: one call in the Bash/PowerShell branch of `cli/moorai-hook.mjs` posts the alert and raises the
  verdict when the check's decision ranks higher; `test/ot-protocol-client-hook.test.mjs` runs it end to end
  (a write denied under `threatPolicy` 82 `block`, a read reported and allowed, a write reported with no policy,
  a write inside a base64 payload piped to `sh` denied, and `kill` ending the session).

Limits: a client under another name, a script outside the session directory (a large script past the read
budget is reported as unknown, not identified), a PowerShell `-File` script, code assembled at
run time or imported indirectly, a read misread as a write when a library's generic `write(` name also matches
another object's call (the stricter direction), and connections without a shell are not seen; OT-subnet
connections are the egress rule `cidr` field (§ Egress proxy, owned by F23). Not run against real devices.

## Static model-file scanning (backlog #13, part a)

`cli/model-scan.mjs` and its format readers inspect model files without loading or executing them. One
verdict per file: format, findings `{ class, severity, count, details }`, severity, sha256. `details` are short
local strings for the CLI (an import name, an op name, a domain); they never leave the device.

- **Pickle** (`cli/model-scan-pickle.mjs`): an opcode walker for protocols 0-5 (table from CPython
  `Lib/pickletools.py`) with a symbolic stack and memo, so `STACK_GLOBAL` resolves memoised strings.
  Classes: `dangerous-import` critical (deny list of modules and `builtins` names, dunder segments, dotted
  `pathlib` methods), `indirect-call` high (a callable that is not an imported global),
  `unresolved-global` medium (`STACK_GLOBAL` on a computed string, `EXT*`), `nested-load` medium
  (`torch.load`, `torch.storage._load_from_bytes`, `numpy.load`), `unknown-import` low, `malformed` medium,
  `too-large` medium (20 M opcodes / 2 GiB), `partial-parse` medium (joblib inline array data).
- **PyTorch zip** (`cli/model-scan-zip.mjs`): central directory with ZIP64; every `*.pkl` entry, stored
  (walked in place) or deflated (inflated up to 1 GiB).
- **Keras** (`cli/model-scan-keras.mjs`): `.keras` `config.json`; HDF5 by a bounded byte search for
  `{"class_name"` in the first 256 MB and a balanced-JSON parse (no HDF5 library). `lambda-code` critical,
  `lambda-function` medium, `dangerous-import` critical, `custom-object` low, `lambda-layer` high (a Lambda
  name with no parseable config), `no-config` low.
- **TF SavedModel / ONNX** (`cli/model-scan-proto.mjs`): a protobuf walker that follows only the message
  paths naming ops, domains and external-data locations. `tf-python-op` high, `tf-file-op` medium,
  `custom-op-domain` medium, `runtime-contrib-domain` low, `external-data-escape` high. Heuristics.
- **GGUF** (`cli/model-scan-gguf.mjs`, `cli/model-scan-template.mjs`): header and metadata per the GGUF spec
  (v1-v3); chat templates get `jinja-python-internals` critical, `jinja-obfuscated-access` high,
  `jinja-gadget-global` medium, `template-instructions` high, `template-url` medium, `hidden-text` high,
  `obfuscated-text` medium; metadata gets `duplicate-key`, `bad-key`, `template-not-string`,
  `unknown-version`, `malformed`. `namespace()` alone is not flagged.
- **SafeTensors** (`cli/model-scan-safetensors.mjs`): header validation only (100 MB header cap, dtypes,
  offsets, sizes, overlaps, `offset-gap` low). A valid header is clean by design.
- **Caps** (`SCAN_LIMITS`): 64 GiB per file (over it: `unscanned`, `size-limit`, not hashed), 2000 files and
  256 GiB per walk, depth 12, 200 000 directory entries. Symlinked directories are not followed.

**Surfaces.**

- `moorai-model-scan <path|dir> [--json] [--allow <sha256>] [--policy file.json]` (`cli/model-scan-cli.mjs`).
  Exit 0 / 1 (unsafe or suspicious) / 2 (usage).
- **Downloads** (`data/model-download.js`, `data/detectors-model-download.js`): detector `model-download`
  → **#76** (stage prompt, Bash commands only, `notify`; it yields to `model-unsafe-load`). #76 was chosen over
  #57 (AML.T0010, default `justify`, which would ask on every `ollama pull` and is about package installs) and
  #80 (clone-and-run): a downloaded model is the unsafe artifact of AML.T0011.000, the scan's findings are
  exactly that technique, and #76 already reports by default. No threat in the catalogue carries AML.T0018,
  and none was added. The PreToolUse Bash branch only appends the target to `~/.moorai/model-scan-queue.json`
  (`cli/model-scan-queue.mjs`); `maybeModelScan` on a later event spawns `moorai-hook.mjs modelscan` once an
  entry is a minute old (at most once per 5 minutes), and the worker scans a target only after nothing in it
  changed for a minute and no partial file (`*.incomplete`, `*-partial*`, `*.part`) remains.
- **Posture** (`cli/model-scan-posture.mjs`, called from `inventoryPosture`): drains the queue and, with
  `modelScan.inventory: "scan"`, scans `modelStoreDirs` (`cli/local-ai-inventory.mjs`: `OLLAMA_MODELS` or
  `~/.ollama/models`, `/usr/share/ollama/.ollama/models` on Linux, `~/.lmstudio/models`,
  `~/.cache/lm-studio/models`, the Hugging Face hub cache). Verdicts are remembered in
  `~/.moorai/model-scan-state.json` keyed by a hash of path, size and mtime.

**Policy.** `modelScan: { inventory: "off" | "scan" (default off), downloads: "scan" | "off" (default scan),
allowHashes: [sha256], maxGiBPerRun: number (default 32) }`.

**What leaves the device.** Heartbeat `modelFiles: { inventory, downloads, stores, scanned, unsafe, suspicious,
clean, allowed, unscanned, pending, pendingDownloads, byFormat, byClass }`. Alerts once per sha256:
`threatId 76`, `reasonCode MODEL_FILE_UNSAFE | MODEL_FILE_SUSPICIOUS`, `stage "inventory"`, `tool
"download:model-scan" | "inventory:model-scan"`, `modelFile: { format, verdict, severity, classes, sha256 }`.
The memory is written after the posts, minus the alerts the console did not accept.

**Limits.** Static only: an input-triggered backdoor, and trojaned or tampered weights, are not detectable this
way, and the dynamic half of #13 is not built. The TF and ONNX checks are heuristics (names, not behaviour).
joblib files with inline numpy arrays are read up to the first array. HDF5 configs that are compressed or past
256 MB are not seen. A cached verdict is not re-evaluated when the allow-list changes until the file changes.
The console does not yet know the `modelFiles` field or the two reason codes. Tested on macOS only.

**Cost** (dev Mac, synthetic 1 GiB GGUF): 1.03 s with the sha256, under 1 ms for the header and template
parse alone. The hash dominates, so a store scan costs about one second per GiB the first time and nothing
for an unchanged file afterwards.

**Tests.** `test/model-scan.test.mjs`, `test/model-scan-posture.test.mjs` (fixtures in
`test/model-scan-fixtures.mjs`, all synthetic).

## Egress proxy (egressRules on real connections)

**Status: built and unit-tested (`test/egress-proxy.test.mjs`, `test/egress-proxy-address.test.mjs`,
`test/egress-proxy-limits.test.mjs`, `test/egress-proxy-harden.test.mjs`, `test/egress-proxy-cidr-sni.test.mjs`
(ClientHellos from Node's own TLS client), all in process with an injected
resolver and connector). Run in a
container (compose demo) and in a kind cluster whose CNI enforces NetworkPolicy. Not run against the
real internet or under load.**

`egress-proxy/moorai-egress-proxy.mjs` is a forward proxy (absolute-form HTTP and CONNECT), Node built-ins
only. It enforces the `egressRules` / `egressDefault` of [`cli/egress-rules.mjs`](../cli/egress-rules.mjs)
on the connections it carries, using that module's own parsing, matching and alert shape.

- **Trust sources.** The verified console policy (`loadVerifiedPolicy`, with the posture ratchet) and the
  root-owned machine-wide config (`readRootOwned`), refreshed at most once a minute. The posture ratchet
  runs on every refresh, also one whose load throws. A first load that throws leaves the proxy unloaded
  (503 to every connection, retried on the next); `OFFLINE_DEFAULT_POLICY` is not used for that case
  because it has no `egressRules` or `egressDefault`. A later load that throws keeps what the proxy held.
  The profile chain is matched on `serviceId` only. A `repo` profile never matches here.
- **Targets.** Plain HTTP gives `{ binary: null, host, port, method, path }`. CONNECT gives
  `{ binary: null, host, port, method: null, path: null }`. The binary is always unknown, and method and
  path are unknown on a tunnel. These are the module's UNKNOWN FIELDS semantics: an allow rule that sets
  an unknown field does not match, and a block rule does. On top of them, an alert rule that sets an
  unknown field cannot grant passage. The connection is re-judged without it, and the stricter outcome
  stands.
- **Address ranges (F23).** With any cidr rule in force (`hasCidrRules`), a name is resolved before it is
  judged and `judgeAddresses` judges it once per resolved address, each as `{ …target, addr }` (a host rule
  reads the name, a cidr rule the address, first match in order), the strictest action standing and a grant
  holding only if it holds for every address. A blocked name is refused before DNS when no cidr rule is in
  force, and also when one is but no cidr `allow` or `alert` rule precedes the deciding block rule (any rule,
  when egressDefault decided): `blockHoldsForEveryAddress`, as no address could lift the block. A
  cidr rule counts as exact for special ranges (`exactHost`); a cloud metadata address needs a host rule on
  the IP literal (`hostExact`, which sets cidr rules aside).
- **TLS server name (F23, [`egress-proxy/sni.mjs`](../egress-proxy/sni.mjs)).** After `200 Connection
  Established` the server's bytes flow at once, and the client's are held until its first bytes are
  classified: a TLS ClientHello (reassembled across records, RFC 8446 5.1) yields its `server_name`
  (RFC 6066 3). A server name that differs from a CONNECT host name is refused (`sni-mismatch`, also on an
  unenrolled device, like the other form checks); on a CONNECT to an IP literal the server name is judged by
  the rules beside that address. No server name, or a first byte that is not 0x16, is judged on the CONNECT
  line alone; a handshake record that is not a well-formed ClientHello (a repeated extension or host_name,
  a bad length) is refused (`tls-unparsed`). The ClientHello is read incrementally (`createHelloSniffer`:
  each byte is copied a bounded number of times however the client cuts its writes) and may span at most
  16 records (`MAX_HELLO_RECORDS`) and 65,576 bytes; more is `tls-unparsed`. From the client's first byte,
  a ClientHello still incomplete after `--hello-timeout-ms` (5 s) closes the tunnel (`tls-timeout`); a
  client that has sent nothing yet is not timed. Not read: an Encrypted Client Hello's inner name, and TLS
  that starts later in a plaintext tunnel (STARTTLS).
- **Addresses.** Resolve once and connect to that address. Special ranges and IP literals need an
  explicit allow or alert grant from a rule whose host is exact (a name or an IP literal):
  `judgeConnection` re-judges with every `*.suffix` allow / alert rule set aside, and the grant must
  survive (`exactHost`). A wildcard, a block rule, the default and the loopback exemption of
  `judgeTargets` never count. Cloud metadata addresses (`isMetadataAddress`, including the Azure
  WireServer 168.63.129.16) need an exact rule on the IP literal itself. NAT64 `64:ff9b::/96` and
  `64:ff9b:1::/48` are classed by the IPv4 address in the last 32 bits; the rest of `64:ff9b::/32` is
  special. The proxy's own listening port and `siblingPorts` (default 8790, 8791, 8848, 8850) on a
  loopback or local interface address are refused before any rule is consulted. The `never` class is
  never connected to. Odd host forms get 400.
- **Paths.** `egress-proxy/path.mjs` canonicalises the raw request path: unreserved escapes decoded, other
  escapes upper-case, `%2F` / `%5C` / `%00` / `%25` / malformed escapes / a raw backslash / `..;` and `.;`
  segments refused with 400, empty segments collapsed, dot segments resolved after decoding. That string
  is judged and forwarded unchanged. Rule paths compare case-sensitively; against a case-insensitive
  upstream a path block rule is evaded by changing case, so allow-list there. Node 22's HTTP parser
  passes a raw backslash to the handler (measured), so the proxy's own check is what refuses it.
- **Fails closed.** A judging error or a policy that cannot be loaded refuses the connection. The hook,
  which judges command text, fails open.
- **Hardening.** Loopback bind unless `--allow-remote` and a token are given. Proxy-Authorization uses
  Basic or Bearer. There are a connection cap, header, request, idle, connect and DNS timeouts, and a
  16 KB header cap.
- **Deployment.** `deploy/k8s/moorai-egress.yaml`: MoorAI pod plus agent pod and two NetworkPolicies. It is
  not a sidecar layout, because NetworkPolicy is pod-scoped. `deploy/compose/`: an internal network.
  Validated as follows. Both demos pass on this machine. `kubectl apply --dry-run=server --validate=strict`
  passed against a kind API server. In kind (kindnet), the agent pod reached the proxy, and the proxy
  applied the ConfigMap's `egressDefault: block`. Direct TCP from the agent to another pod and to the API
  server timed out, and it connected once the agent's NetworkPolicy was deleted.

**Finding in `cli/egress-rules.mjs` (not changed here; that module is not this component's).** An `alert`
rule that sets `binary` also matches a destination whose binary is unknown (a URL in a heredoc), and alert
counts as allow. So under `egressDefault: "block"` the rule `{ binary: "curl", host: "paste.example",
action: "alert" }` lets a heredoc's URL to `paste.example` through, while `wget https://paste.example/x`
is denied. Measured with `evaluateProfile`. Not knowing the binary widened what was allowed. The proxy
avoids this as described above.

## Inference hooks server (Claude Enterprise)

**Status: built and unit-tested (`test/inference-hook.test.mjs`, in process with a fake console, plus one
real-process run of `serve` against `test`). Tested against Anthropic's published protocol, not against
Anthropic's live service. Anthropic marks the feature beta: field names, request shapes and headers may
change.**

Protocol source: Anthropic's own pages,
[Develop an Inference hooks integration](https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint),
[Configure Inference hooks](https://platform.claude.com/docs/en/manage-claude/inference-hooks-configuration)
and the [overview](https://platform.claude.com/docs/en/manage-claude/inference-hooks). Anthropic POSTs a
signed JSON frame, `type` `"prompt"` or `"tool_call"`, with `request_id`, `tenant_id`, `actor`,
`source.application`, `session_id`, `model`, `messages` and `metadata`, to the configured `https://` URL on
port 443. It waits up to the admin's verdict timeout (1-10,000 ms, 5,000 by default) for HTTP 200 with
`action` `allow` or `deny`. Any other answer is a webhook failure, and the organization's failure handling
(default "Allow the request") applies. Shadow mode, the rollout percentage and role exclusions are
admin-console settings on Anthropic's side. The server never sees them.

`cli/moorai-inference-hook.mjs` (`serve`, `test`) and `cli/inference-hook/`:

- **`signature.mjs`.** Standard Webhooks HMAC-SHA256 over `{webhook-id}.{webhook-timestamp}.{raw body}`,
  standard-base64 `whsec_` secrets, any space-separated `v1,` value, `timingSafeEqual`. The tolerance is
  ±300 s. Several secrets are allowed, for rotation. The replay cache remembers each id until its
  timestamp leaves the window. It is bounded: past the cap, expired ids are swept first, then the ids
  nearest expiry are evicted.
- **`transcript.mjs` / `evaluate.mjs`.** Stages: `user` text → `prompt`; `tool_result` → `output` with
  `{inbound: true}`, where claude.ai's `web_fetch` / `web_search` map to the web rule set; `attachment`
  text → `file`. Assistant turns, unknown roles and unknown block types are skipped. Tool call frames: the
  last message's `tool_use` blocks are judged by content only. A shell command, through the model proxy's
  `mapTool`, or a WebFetch URL is judged as the hook judges it, and anything else as its argument JSON at
  `prompt`. `runtime.toolCall` is deliberately not used. Its Read, MCP-file-argument and secret-egress
  branches read local files, and here a model would choose a path on the security server. Each verdict is
  cached per conversation in a per-process HMAC-keyed LRU.
- **`server.mjs`.** Order: bounded raw read, signature, timestamp, replay, parse, judge. Unknown `type`
  → allow (documented forward compatibility). `--fail open|closed` applies to an authenticated frame that
  could not be judged in full: item over the 512 K-character cap (its prefix is still judged), more than
  512 new items, `--eval-timeout-ms` (default 4,000), an engine error, an unparseable frame. The default is
  `open`, because Anthropic's default failure handling is "Allow the request". For an unreadable body (over
  `--max-body`, default 64 MiB = protocol maximum, or over `--max-inflight`, 256 MiB), `closed` answers
  deny and `open` answers 413 / 503, so Anthropic's own failure handling decides. A body past twice the
  cap is dropped. `--shadow` answers allow to every frame it judged. Limits: headers 5 s, request 30 s,
  128 connections. Loopback bind unless `--allow-remote`. There is no Host check, because every request
  must be HMAC-signed.
- **`report.mjs`.** This is the runtime's reporter with surface `inference-hook`, tool label
  `inference-hook:<kind>`, `inferenceRef` (the `reference_id` returned to Anthropic, `moorai:` + 24 hex),
  `inferenceSource` (`source.application`, `[a-z0-9-]`), and, under `--shadow`, `enforcement: LIMITED` on
  would-be denials. A frame that could not be judged in full gets one `UNEVALUATED_*` alert. `session` is
  the keyed hash (`cli/content-hash.mjs`) of `session_id`. It is omitted when there is no id or no
  enrollment key.

Not covered: path-only judging of a tool call (for example a Read of `~/.aws/credentials`, which the hook
denies by path); per-end-user attribution (`actor.id` is not hashed into alerts; alerts carry the server's
workload identity); native TLS on the listener; accepting unsigned requests from an organization that
enabled the feature before signing secrets were required. The test cross-checks the signer and the
verifier against an independent Python `hmac` implementation of the documented steps, when `python3` is
present. They have not been checked against Anthropic's real signer.

## Fail mode (admin-chosen fail-open / fail-closed)

- **Contract.** `cli/fail-mode.mjs`: `FAIL_SURFACES = ["hook","modelProxy","mcpGateway","inferenceHook"]`;
  `resolveFailMode(policy, surface, { admin, fallback })` returns `{ mode, source }`;
  `effectiveFailModes()` returns all four. Precedence: admin binding `failMode[surface]`, then its
  `default`; then the signed policy's `failMode[surface]`, then its `default`; then `fallback`. Invalid
  values are warned about (source and key, never the value) and skipped. Never throws; never reads
  user-writable state.
- **Hook** (`cli/hook-fail.mjs`). Before main has the policy, the admin binding and the same verified
  load the decision path uses (the live policy when the console answers) decide; after, the admin binding and
  that verified policy (test/fail-mode-hook-preverify.test.mjs). Closed deny = exit 2 + PreToolUse deny
  JSON + stderr, on an uncaught error, `HOOK_DECISION_BUDGET_MS` = 15000 (below the agent-hook shim's 20 s),
  unparseable or unreadable PreToolUse input, an error in the no-policy block, and an allow over a capped
  Read. Admin-closed counts as management evidence; with no policy it selects `OFFLINE_DEFAULT_POLICY`.
  A live break-glass marker allows. Unsupported tools are out of scope, not "cannot decide".
- **Model proxy.** `resolveFailMode(policy, "modelProxy", { admin, fallback: enforce ? "closed" : "open" })`
  governs scan caps, engine errors and the evaluation budget. Not governed: a compressed response, an
  over-size SSE event or NDJSON line, a non-JSON non-stream response, ambiguous tool arguments (refused in
  enforce mode regardless).
- **MCP stdio guard and HTTP gateway** (`cli/mcp-fail.mjs`, `mcp-gateway/fail.mjs`). The gate's catch, a
  missing engine, a missing reputation score with `mcpReputation.blockBelow`, and on results a scan fault,
  a deadline miss or the overload window: refused when closed. Not governed: oversize lines or responses
  forwarded unscanned by design, `tools/list`. Fail-closed refusals never count toward the client cool-down.
- **Inference hooks server.** Per request: admin > policy > `--fail` > open.
- **Reason code.** `REASON.FAIL_CLOSED`, category prefix `Fail-closed: `; fields `basisCode`,
  `enforcement: STRENGTHENED`, `failMode`, `failModeSource`, `failWhy`.
- **Posture / doctor.** Heartbeat top-level `failMode: { hook, modelProxy, mcpGateway, inferenceHook }`, each
  `{ mode, source }`; doctor check `fail-mode`.
- **Input handling.** `cli/tool-input.mjs`: primitives are judged as text; objects in judged fields are
  `UNEVALUATED_BAD_INPUT`; objects in envelope fields are dropped and the call judged.

## Model proxy: operator context and business actions

| Capability | Behaviour | Evidence |
|---|---|---|
| Operator-context privacy findings | Default: judged like any request content (PII and secrets block or ask per policy). Opt-in `operatorContext.privacy: "report"` (verified signed policy or admin binding only): PII-class threats 1, 9, 15, 18, 27, 36, 44 reported at stage `context`, `decision: notify`, `enforcement: LIMITED` when the policy would block or ask. Secrets #39 / #65 and non-data findings never exempt. | test/proxy-context-system.test.mjs |
| Business-impact classes | `money`, `bulk-data`, `identity`, `destructive`, `delegation` by function-name words; built-in `alert`; `businessToolActions` per class; a specific `functionToolActions` key wins | test/proxy-business-tools.test.mjs |
| Model-proxy fail mode | see Fail mode above | test/proxy-fail-mode.test.mjs |

## Cloud file scanning before the model (v1.34.0)

**Contract.** Signed policy `fileScan` (`cli/file-scan-policy.mjs`); keys from the root-owned admin binding
`fileScanKeys`, `--file-scan-key-file <provider>=<path>` (root-owned) or `MOORAI_METADEFENDER_API_KEY` /
`MOORAI_VIRUSTOTAL_API_KEY`, never the policy. Providers behind one interface: MetaDefender Cloud API v4
(`cli/file-scan-metadefender.mjs`) and VirusTotal API v3 (`cli/file-scan-virustotal.mjs`).

| Field | Values | Default |
|---|---|---|
| `provider` | `metadefender` \| `virustotal` | `metadefender` |
| `mode` | `off` \| `hash` \| `upload` | `off` |
| `onMalicious` | `block` \| `report` | `block` |
| `onUnknown` | `allow` \| `ask` \| `block` | `allow` |
| `maxBytes` / `timeoutMs` | 1–681574400 / 100–120000 | 33554432 / 10000 |
| `iocHash`, `privateScan` | `true` | `false` |
| `region` (MetaDefender), `ratePerMinute` | a documented region name / 1–10000 | nearest / 60 MetaDefender, 4 VirusTotal |
| `minEngines` | 1–1000: a clean verdict from fewer engines is unknown (`few-engines`) | 3 |

| Capability | Behaviour | Evidence |
|---|---|---|
| What leaves, per mode | `off`: nothing. `hash`: one GET with the SHA-256 in the path (MetaDefender `/v4/hash/{h}`, VirusTotal `/api/v3/files/{h}`). `upload`: also the bytes of a file the lookup did not know (≤ `maxBytes`): MetaDefender `POST /v4/file` (results shareable with the community unless `privateScan` sends `samplesharing: 0`), VirusTotal `POST /api/v3/files` (report public; contents may be shared with premium customers) | test/file-scan-core.test.mjs, test/file-scan-proxy.test.mjs ("only GET by hash") |
| Model proxy parts | Anthropic image / document base64 (and in `tool_result`), OpenAI Chat `image_url` / `file` / `input_audio` (any role), Responses `input_image` / `input_file` (and `function_call_output`), Gemini `inlineData` / `inline_data` (contents, `systemInstruction`, nested `functionResponse.parts`), Ollama `images`; streaming and not; ≤ 32 per request | test/file-scan-proxy.test.mjs, test/file-scan-parts.test.mjs |
| Scanned = sent | Strict base64 (failures are `unscannable`, an error, never clean); Gemini dual spellings both scanned, differing ones refused as ambiguous; a body with a duplicate or case-colliding key refused (both: enforce or closed fail mode; else forwarded with `UNEVALUATED_BAD_INPUT`); with scanning on every parsed body forwarded re-serialised from the lossless parse; a part past 16 nesting levels is unscannable | test/file-scan-parts.test.mjs |
| Decision | malicious → `onMalicious`; unknown → `onUnknown` (`ask` = headless ask); error (timeout, 429 / 253, auth, no key, over the part cap, unscannable) → fail mode: closed refuses with `FAIL_CLOSED` (`Fail-closed: file not scanned`), open applies `onUnknown`. Proxy: `failMode.modelProxy`; moorai-serve: `failMode.default` | test/file-scan-core.test.mjs, test/file-scan-proxy.test.mjs, test/file-scan-serve.test.mjs |
| Cache / rate limit | per-process LRU by provider, mode and SHA-256 (1 h; unknown 5 min; errors never), single flight; per-provider token bucket with a 32-deep wait queue bounded by the deadline; a provider 429 pauses it until its reset | test/file-scan-core.test.mjs |
| Sidecar | `POST /v1/file-scan` `{data \| sha256, mediaType?, session?}`, token auth as `/v1/tool-call`, body cap `--max-file-body` | test/file-scan-serve.test.mjs |
| Alert | `File scan: malicious file` (threat #17, `FILE_SCAN`), `File scan: unknown file` / `File scan: file not scanned` (threat 0, `FILE_SCAN`); `fileScan: {provider, verdict, mode, detections?, engines?, threat?, mimeClass, sizeBucket, uploaded, why?}`; `contentHash` keyed; raw `sha256` only for malicious with `iocHash` | test/file-scan-core.test.mjs, test/file-scan-proxy.test.mjs |
| Key handling | sent only in the provider's header to its own origin (`redirect: "error"`; VirusTotal's `upload_url` must be same-origin); never in a log, alert, error or refusal | test/file-scan-providers.test.mjs, test/file-scan-proxy.test.mjs |

| Unreadable bodies and other endpoints | A parsed-path body with a content coding or not a JSON object, and the upload endpoints (`/files`, `/uploads`, Gemini `/upload/…`, `:batchGenerateContent`): refused in enforce or closed fail mode, else `UNEVALUATED_BAD_INPUT` (`model-proxy:file-scan-body` / `file-scan-endpoint`). Anthropic `/messages/batches`, `/messages/count_tokens` and Gemini `cachedContents` are parsed and scanned. Any other unparsed path with a non-JSON POST / PUT / PATCH body (multipart, binary, or a `Content-Type` other than `application/json` / `application/*+json`): refused or `model-proxy:file-scan-unparsed`. A path with any `%` escape: refused or `model-proxy:file-scan-path`. Paths normalised (dot segments, `//`, trailing `/`) before matching and forwarding, matched case-insensitively. Every JSON body on any path walked for every API's file shapes (64 levels, 200000 objects) | test/file-scan-bypass.test.mjs |
| References | URL and file-id references (and Responses `computer_call_output` by id) alert with `why: "reference"` and apply `onUnknown`; a non-data-URL `file_data` / `image_url` value is unscannable | test/file-scan-bypass.test.mjs |

**Not built.** Deep CDR; fetching files sent by reference; scanning upload endpoints; scan-before-embed for files (`/v1/index-scan`).

## Living off the AI detectors (v1.15.0)

**Threat.** An LLM-operated implant that "lives off the AI" uses the AI already on the device. It drives the
victim's AI coding CLIs (`claude -p`, `codex exec`, Gemini CLI, Copilot CLI) from a process it injected into,
uses local model servers directly, steals AI API keys, and calls AI APIs from its own process. The agent then
runs with the user's own credentials and the hook sees ordinary-looking calls. Four detectors answer those
moves. Every alert and heartbeat field is content-free: class names, image basenames, runtime ids, ports,
bind classes, provider names, counts and opaque ids. A path, a command line, an address or a token never
leaves the device.

**Contract** (agent v1.15.0, console v0.86.0). All policy fields are optional and read from the verified
policy only.

| Signed policy field | Values | Default |
|---|---|---|
| `aiCliParents` | `{ mode: "off" \| "alert" \| "block", allow: [image names] }` | mode `"alert"`, allow `[]` |
| `decoyKeys` | `{ mode: "off" \| "place" }` | `"off"` |
| `localModelExposure` | `"off" \| "alert"` | `"alert"` |
| `aiApiCallers` | `"off" \| "alert"` | `"alert"` |

| `reasonCode` | Category | Risk | Fields |
|---|---|---|---|
| `AI_CLI_PARENT` | AI CLI started by an unexpected parent | High (Blocked in block mode) | `agentName`, `parentImage` (basename), `parentClass` (`system-host`, `office`, `script-host`, `temp-or-system-path`), `chainDepth` (1 = the agent's own parent) |
| `DECOY_KEY_USED` | Decoy AI key used | Critical | `decoyId`, `where` (`hook:PreToolUse`, `hook:PostToolUse`, `model-proxy:request`) |
| `LOCAL_MODEL_EXPOSED` | Local model server reachable without MoorAI | Medium | `runtime` (`ollama`, `lmstudio`, `llamacpp`, `vllm`, `other`), `port`, `bind` (`loopback`, `all-interfaces`, `lan`) |
| `AI_API_CALLER_UNKNOWN` | Unknown process calling an AI provider API | High | `processImage` (basename), `provider` (`openai`, `anthropic`, `google`, `mistral`, `other`), `connections` |

Posture heartbeat (`POST /api/agent-posture`), top-level like `failMode`:
`aiCliParents: { mode, lastParentClass }`, `localModelServers: [{ runtime, port, bind, viaProxy }]`,
`aiApiCallers: [{ processImage, provider, known }]`, `decoyKeys: { placed, source: "admin" | "agent" | "none" }`,
`mcpServerSandbox: { mode, state }` ("MCP server network sandbox" above).

### AI CLI started by an unexpected parent (`cli/ai-cli-parents.mjs`)

- **When.** On PreToolUse and UserPromptSubmit, once per agent session (cached by session id). The hook skips
  the shell it runs in (and, for the Codex / Gemini / Copilot / Cursor adapters, the adapter's node) to reach
  the agent process, then walks up through shells, wrappers and interpreters (so sihost.exe → python → claude
  still reads as sihost.exe) to the first ancestor that is neither, at most 6 levels above the agent.
  macOS and Linux walk on the call. Windows never walks on a call (`cli/ai-cli-parents-win-walk.mjs`): the
  first call of a session with no cached class starts one detached PowerShell and leaves its own parent pid
  as a request; the PowerShell warms WMI and polls for requests for 30 s; every later call of the session
  leaves its parent pid as soon as it knows the session (before its policy load), because the shell an agent
  runs its hook command in lives only as long as that call; the first walk that reads past that pid is
  written as the result, and the call that finds it classifies, caches and alerts. Calls before that one are
  judged without the parent class. A call with no session id is not walked on Windows.
- **Classes.**

  | Class | What it covers | Outcome |
  |---|---|---|
  | normal | a terminal (Terminal, iTerm2, Windows Terminal, conhost, WezTerm, kitty, …) or an IDE (VS Code, Cursor, JetBrains, Xcode, Zed, …) whose image path ends in its own name at an expected install location (below); explorer.exe at C:\Windows\ or C:\Windows\System32\; tmux / screen / sshd, launchd / systemd, an AI desktop app, another AI CLI, a CI runner in server mode, an image on `aiCliParents.allow` (all by name) | nothing |
  | system-host | sihost, RuntimeBroker, svchost, dllhost, taskhostw, WmiPrvSE and other Windows system hosts; an explorer.exe outside C:\Windows or started by one of these | alert |
  | office | Word, Excel, Outlook, PowerPoint (Windows and macOS) | alert |
  | script-host | wscript, cscript, mshta, rundll32, regsvr32, msbuild, installutil, regasm, regsvcs, cmstp, hh, osascript | alert |
  | temp-or-system-path | any image in a temp directory (/tmp, /var/tmp, /dev/shm, the macOS per-user TMPDIR, %TEMP%, C:\Windows\Temp), or an image under C:\Windows whose name is not a known Windows program | alert |
  | unknown | anything else, including a terminal or IDE name with no readable path or off its expected location | recorded (`lastParentClass`), never alerted |

  Expected install locations of a terminal or IDE (`inLocation`; the path must be absolute, have no `.` or `..`
  segment and end in the image's own name; containment is by path segments with the shared rule below,
  "Path containment"): Windows, conhost.exe directly in `C:\Windows\` or
  `C:\Windows\System32\`, Windows Terminal / OpenConsole under `Program Files\WindowsApps\`, any other under
  `Program Files\`, `Program Files (x86)\` or `%LOCALAPPDATA%\Programs\`; macOS, inside a `.app` bundle's
  `Contents/…/MacOS/` under `/Applications`, `/System/Applications` or `~/Applications`; Linux (and macOS
  command-line installs), under `/usr/{bin,sbin,share,lib,lib64,libexec}`, `/usr/local/{bin,share,lib}`, `/bin`,
  `/sbin`, `/opt`, `/snap`, `/var/lib/flatpak`, `/nix/store`, `~/.local/bin` or `~/.local/share`. A terminal or
  IDE name under C:\Windows off its location is `temp-or-system-path`.

- **Policy.** `"block"` denies every PreToolUse call of a flagged session with a content-free reason naming
  the class; an unenrolled device is coached (alerts, never denies). The allow-list matches image names
  case-insensitively, with or without `.exe`, and is re-applied on every call, so it also releases a session
  already classified. The alert is raised once per session. On Windows the denial starts at the call that
  finds the background walk's result (normally the session's second or third call), not at its first.
- **Process table and measured cost.**

  | Platform | Method | Cost |
  |---|---|---|
  | macOS | `/bin/ps -o ppid=,comm= -p <pid>` per level | 7.4 ms for a 5-level chain on a quiet machine; 21 ms at load average 56; 82 ms under heavy load from parallel test suites |
  | macOS | `ps -axo pid=,ppid=,comm=` once (not used) | 58 ms quiet, 70 ms at load 56, 142 ms heavy load |
  | Linux | /proc/<pid>/stat and /proc/<pid>/exe | 0.08 ms for 3 levels (node:22-slim, arm64, Docker); used whether or not `ps` is installed |
  | Linux | `ps` per level (fallback when /proc is absent) | 122 ms (amd64 under emulation; not representative) |
  | Windows | one detached `powershell.exe -NoProfile -NonInteractive` per session, walking with filtered `Get-CimInstance Win32_Process` queries in the background; a parent created after its child is a reused pid and ends the chain | on the call: 3.2 ms for the call that starts the walk, 0.9 ms median after (a request file write; measured on macOS with an 8 s stand-in for PowerShell). The walk itself is not measured on Windows; on GitHub's windows-latest runners a walk on the call ran to its 8 s timeout |
  | any | a session already classified (cache read) | 0.04 ms Linux, 0.05 ms macOS |

- **Limits.** The per-session cache (`~/.moorai/ai-cli-parents.json`) is the user's own file, so a process
  running as the same user can pre-seed a session as normal before the agent's first call; the root-owned
  helper is where this check moves to. A parent that has exited cannot be classified: on Unix the agent is
  re-parented to launchd / systemd and reads as normal; on Windows the chain ends and the class is unknown.
  An implant that starts the agent and exits at once is therefore not flagged. Classification is by image
  name and path: a program renamed to a terminal's or IDE's name reads as normal only when it is also placed
  at that product's install location, which on Windows (Program Files, WindowsApps, C:\Windows) needs
  administrator rights but `%LOCALAPPDATA%\Programs`, `~/Applications` and `~/.local` do not. A renamed
  multiplexer, sshd, launchd / systemd or AI desktop app name is not location-checked, and any name on the
  allow-list reads as normal. A session whose ancestry cannot be read (unreadable process table) is cached as
  unreadable and never alerted. On Windows a session whose calls all end before the background PowerShell
  reads past their shell is not classified; after 30 s without a result the next call starts another walk.
  The request and result files sit next to the session cache, with the same trust. `wmic` is not
  used (deprecated, absent by default on current Windows 11).
- **Tests.** `test/ai-cli-parents.test.mjs`, `test/ai-cli-parents-hook.test.mjs`, `test/location-gates.test.mjs`.

### Decoy AI keys (`cli/decoy-keys.mjs`, `model-proxy/decoy.mjs`)

- **Opt-in placement.** Only with `decoyKeys: { mode: "place" }` in a VERIFIED signed policy, applied by the
  posture worker. Placement and removal run only when that policy verified under a real key (the anchor or this
  device's pin). An unpinned device (a console that does not sign) and a device with no policy leave decoy
  files untouched: no policy never reads as `"off"` and never removes anything. A same-user rewrite of the
  cached policy on a pinned device is refused and the verified last-known-good applies.
- **Sites.** Each decoy is a new file, created only when nothing exists at the path, mode 0600:

  | File | Content | Harvest pattern it baits |
  |---|---|---|
  | `~/.env.backup` | `OPENAI_API_KEY=sk-proj-…` | dotenv sweeps of `.env*` files; dotenv loads `.env`, and Vite / Next.js / dotenv-flow load `.env.<mode>`, none of them `backup` |
  | `~/.zshrc.bak` (macOS), `~/.bashrc.bak` (Linux, Windows) | `export ANTHROPIC_API_KEY="sk-ant-api03-…"` | shell-rc export harvesting; a shell sources `.zshrc` / `.bashrc`, never the `.bak` copy |
  | `~/.config/gemini/credentials.bak` | `GEMINI_API_KEY = AIza…` | AI-CLI config harvesting; Gemini CLI uses `~/.gemini`, which MoorAI does not touch |

- **Tokens.** The provider key shapes the public gitleaks rules match: `sk-proj-<74>T3BlbkFJ<74>`,
  `sk-ant-api03-<93>AA`, `AIza<35>` (`[A-Za-z0-9_-]`). Random and never issued, so they authenticate nowhere.
  Nothing in a token or a file name marks it as a decoy.
- **Registries.** `~/.moorai/decoys.json` (0600) for decoys the agent placed;
  `<machine dir>/decoys.json` (`/etc/moorai/decoys.json`, `<ProgramData>\MoorAI\decoys.json`) for decoys an
  administrator placed, `{ "decoys": [{ "id", "kind": "openai" | "anthropic" | "google", "token" }] }`, which
  MoorAI only reads and never removes. An entry whose token lacks its kind's full shape is ignored (a short
  token would match everything). The AIBOM's keys-at-rest scan does not report MoorAI's own decoys.
- **Removal.** Mode back to `"off"` deletes each file MoorAI placed while its bytes are unchanged (sha256 in
  the registry) and removes the directories MoorAI created once they are empty. A file the user edited, and
  every admin decoy, stays.
- **Where use is checked.**

  | Surface | Content | On a match |
  |---|---|---|
  | Hook, PreToolUse | the whole tool input (a Bash or PowerShell command, Write / Edit content, a WebFetch URL, MCP arguments, a sub-agent prompt) | deny (a decoy being sent somewhere is exfiltration); coached on an unenrolled device |
  | Hook, PostToolUse | the tool result (command output, a fetched page, an MCP result, a sub-agent report) | alert (the call has already run) |
  | Model proxy | every request header value, the query string and the body, before anything is forwarded | 403 in report and enforce mode alike; the registry is re-read at most once a minute |

  One Critical `DECOY_KEY_USED` per match, with `decoyId` and `where`. Cost: a substring search per decoy,
  0.07 ms per call for 10 decoys against a 256 KiB input (M-series Mac, n=200).
- **Limits.** A decoy re-encoded before use (base64, split, reversed) is not matched. The hook's Read tool is
  not checked: reading the file a decoy sits in is not a use; a decoy read through the shell (`cat`) is seen in
  the command's output. A decoy used from a process neither the hook nor the proxy sees is left to the
  AI-API-caller detector and to provider-side or network controls.
- **Tests.** `test/decoy-keys.test.mjs`, `test/decoy-use.test.mjs`, `test/decoy-use-real.test.mjs`.

### Inventory detectors on the posture heartbeat (`cli/agent-posture.mjs` `inventoryPosture`)

- **Where.** The detached posture worker (once per agent host per UTC day, on an enrolled device, never on the
  decision path) takes ONE TCP-table sample (`cli/local-ai-inventory.mjs` `tcpTable`) for both socket
  detectors. The same verified load (`loadVerifiedPolicy(CONFIG, { network: false })`) that feeds `failMode`
  and `aiCliParents` gates `localModelExposure`, `aiApiCallers` and `decoyKeys.mode`.

  | Platform | Source | Sees |
  |---|---|---|
  | macOS | `lsof +c 0 -nP -iTCP` (one spawn) | this user's processes only |
  | Linux | `/proc/net/tcp{,6}` plus `/proc/<pid>/fd` (no spawn) | every socket; the owner only for processes this user can read |
  | Windows | `netstat -ano` plus `tasklist /FO CSV /NH` | all processes' sockets, image names |

- **Dedupe and delivery.** The once-per-change memory (`~/.moorai/inventory-detectors.json`) is written AFTER
  the alerts post, minus every alert the console did not accept (non-2xx or no answer), so a failed post is
  raised again on the next beat. Alerts carry the identity fields plus `agentName`, `appVersion`, `seq` and
  `chainHead`.
- **Cost** (dev Mac, real lsof and DNS, throwaway HOME, stub console): worker wall time median 122 ms cold /
  120 ms warm without the detectors, 400 ms cold / 382 ms warm with them; `lsof +c 0 -nP -iTCP` alone is about
  250 ms.
- **`moorai-doctor`.** The `[inventory]` group has three read-only rows (Local model servers, Decoy AI keys,
  AI API callers): they place nothing, remove nothing, keep no state and raise nothing. The callers row is
  skipped with `--offline` because it needs DNS.
- **Stated limit.** The scan runs `lsof` (macOS) and `netstat` / `tasklist` (Windows) through PATH, so a
  same-user PATH change can hide sockets from both socket detectors. Linux reads /proc and spawns nothing.
- **Tests.** `test/posture-inventory-beat.test.mjs`, `test/local-model-exposure.test.mjs`,
  `test/local-model-exposure-doctor.test.mjs`, `test/ai-api-callers.test.mjs`.

### Local model server reachable without MoorAI (`cli/local-model-exposure.mjs`)

- **Discovery.** Listening sockets matched to a runtime by process name, or by a distinctive default port alone
  (Ollama 11434, GPT4All 4891, Docker Model Runner 12434), over the runtimes the AIBOM inventory knows (Ollama,
  LM Studio, llama.cpp server, vLLM and others; the rest report as `other`). Bind: `loopback`,
  `all-interfaces` (`*`, `0.0.0.0`, `::`) or `lan` (a specific non-loopback address); several sockets for one
  runtime and port report the widest.
- **viaProxy.** `true` only when the server listens on loopback alone AND a TCP connect from the scan, which
  runs as the same user an implant would, is refused (nothing is sent). Any other server is reachable without
  MoorAI. A non-loopback bind is always `false`: whether other hosts can reach it cannot be measured from the
  device.
- **Alert.** `LOCAL_MODEL_EXPOSED` once per new or changed exposure (runtime, port, bind) unless
  `localModelExposure: "off"`.
- **Limit.** A listener whose owning process the scan cannot name (another account's process on Linux) is
  matched by the default port only, so a model server under an account of its own on a non-default port is not
  listed.

**Proxy-only local models (Ollama).** Ollama binds 127.0.0.1:11434 by default and takes its bind address from
`OLLAMA_HOST` ([Ollama FAQ](https://docs.ollama.com/faq)). It has no unix-socket mode (its `envconfig.Host`
parses host:port only), so the proxy-only setup is a loopback port only MoorAI's model proxy may reach:

1. Run Ollama on a loopback port of its own, for example `OLLAMA_HOST=127.0.0.1:11435`, set as the FAQ
   documents per platform:
   - macOS app: `launchctl setenv OLLAMA_HOST "127.0.0.1:11435"`, then restart Ollama.
   - Linux systemd: `systemctl edit ollama.service`, add `Environment="OLLAMA_HOST=127.0.0.1:11435"` under
     `[Service]`, then `systemctl daemon-reload` and `systemctl restart ollama`.
   - Windows: Ollama inherits the user and system environment. Quit it from the taskbar, set `OLLAMA_HOST`
     under "Edit environment variables for your account", then start it from the Start menu.
   Never bind `0.0.0.0` (the FAQ's own exposure example does).
2. Put the model proxy in front on Ollama's usual route, so clients keep working:
   `moorai-model-proxy --route /ollama=http://127.0.0.1:11435`. A `--route` replaces the default routes, so
   repeat `--route` for every provider route still in use (for example
   `--route /anthropic=https://api.anthropic.com`). Clients use `OLLAMA_HOST=http://127.0.0.1:8791/ollama`.
3. Run the proxy under its own service account and let only that account connect to the Ollama port. Without
   that rule every process the user runs, an implant included, can open 127.0.0.1:11435 directly, and MoorAI
   reports `viaProxy: false`.
   - Linux (iptables `owner` match, OUTPUT chain, which matches the creator of locally generated packets):
     `iptables -A OUTPUT -o lo -p tcp --dport 11435 -m owner ! --uid-owner moorai-proxy -j REJECT`.
   - macOS / BSD pf has a `user` rule option. MoorAI has not verified a loopback `user` rule on macOS, and pf
     is off until something enables it (`pfctl -E`).
   - Windows: MoorAI has not verified a per-account loopback rule.
4. Check it: `moorai-doctor` shows "Local model servers: ollama :11435 reachable only through MoorAI". On
   Linux this needs Ollama to run as the scanning user; under an account of its own on port 11435 it is not
   listed (see the limit above).

### Unknown process calling an AI provider API (`cli/ai-api-callers.mjs`)

- **Hosts.** api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, aiplatform.googleapis.com,
  api.mistral.ai, codestral.mistral.ai, and as `other`: Groq, xAI, DeepSeek, OpenRouter, Cohere, Perplexity,
  Together, Fireworks and the Hugging Face router. Resolved at scan time (all addresses, both families) and
  cached for an hour; an established connection to one of those addresses is attributed to the owning
  process's image basename.
- **Ambiguous addresses.** An address that also answers for a non-AI control host on the same front end
  (www.googleapis.com, storage.googleapis.com, oauth2.googleapis.com, www.cloudflare.com, discord.com), or that
  two providers share, is counted (the doctor row shows the count) but never attributed and never alerted on.
  Gemini on generativelanguage.googleapis.com resolves to the same Google front-end addresses as every
  googleapis.com API, so it is ambiguous; Anthropic, OpenAI and Mistral resolve to addresses of their own and
  are attributed. The check runs on every resolution, so a provider that moves onto a shared address stops
  alerting rather than alerting on everything.
- **Known callers** (`known: true`, never alerted):
  - MoorAI's own pids: the scanning process and its parent, and a node process listening on the model proxy's
    or moorai-serve's port.
  - A process named like an AI app, agent CLI, editor or browser (`data/ai-catalog.json`, `KNOWN_AGENTS`,
    `BROWSERS`, `MOORAI_IMAGES`; Electron helpers count as their app) ONLY when its executable, as the OS
    reports it, is inside that product's expected install location (table below). The executable is read
    locally for those pids only: macOS `codesign -d <pid>` (the kernel's path for the running pid; measured
    16 to 21 ms per pid, 113 to 149 ms for the 7 named pids on the dev Mac), Linux `/proc/<pid>/exe`, Windows
    `ExecutablePath` from the same single `Win32_Process` query that reads command lines. At most 64 pids per
    scan. No executable path, or a path anywhere else, is unknown and alerts.
  - macOS only: a named process off its location is also known when the running process satisfies its
    product's signing identity, `codesign --verify -R='(anchor apple generic and (identifier "<id>" or …) and
    certificate leaf[subject.OU] = "<team>")' <pid>`. Checked only when the location does not match, once per
    pid per scan. Measured on the dev Mac: 13 to 16 ms (Claude Helper), 212 to 236 ms (ChatGPT), 392 to 399 ms
    (Claude Code) when it passes; 18 to 26 ms when it fails. Identities, measured on installed copies:

    | Names | Team | Signing identifiers |
    |---|---|---|
    | claude (desktop) | Q6L2SF6YDW | com.anthropic.claudefordesktop, com.anthropic.claudefordesktop.helper |
    | claude (Claude Code) | Q6L2SF6YDW | com.anthropic.claude-code |
    | codex | 2DC432GLL2 | codex, com.openai.codex, com.openai.codex.helper |
    | chatgpt | 2DC432GLL2 | com.openai.chat, com.openai.codex, com.openai.codex.helper |
    | chatgpt atlas | 2DC432GLL2 | com.openai.atlas, com.openai.atlas.web, com.openai.atlas.web.helper |
    | copilot, github-copilot | UBF8T346G9 | com.microsoft.copilot-mac |
    | google chrome, chrome | EQHXZ8M8AV | com.google.Chrome, com.google.Chrome.helper, com.google.Chrome.helper.renderer |
    | firefox | 43AQ936H96 | org.mozilla.firefox |

    Safari's `com.apple.WebKit.Networking` is located by path only (a SIP-protected system folder); its dynamic
    signature check fails on the dev Mac ("resource envelope is obsolete").
  - A named process whose executable is a script host (`node`, `bun`, `deno`, `python*`; a Linux `#!` script
    keeps the script's name, so pipx's aider runs as `aider` under python) is judged by the program it runs,
    as for a script host below. Gemini CLI, Qwen Code and aider have no install location of their own for this
    rule.
  - **Expected install locations** (`PRODUCTS` in `cli/ai-install-locations.mjs`). `<dir>` means anything
    below that folder; `<dir>|<file>` means only that file in a shared folder. `~` is the home, `%L` is
    `~\AppData\Local`, `%PF` / `%PF86` / `%WA` are `<any drive>:\Program Files`, `Program Files (x86)` and
    `Program Files\WindowsApps`. `app:X.app` is `/Applications/X.app` and `~/Applications/X.app`; `brew:n` is
    `/opt/homebrew/{Cellar,Caskroom}/n` and `/usr/local/{Cellar,Caskroom}/n`; `npm:pkg` is
    `<root>/node_modules/pkg` under every npm-style and pnpm global root listed below for script hosts.

    | Product (names) | macOS | Windows | Linux |
    |---|---|---|---|
    | Claude desktop (claude) | app:Claude.app | %L\AnthropicClaude, %L\Programs\Claude | none |
    | Claude Code (claude; version-named images below) | ~/Library/Application Support/Claude/claude-code, ~/Library/Application Support/Claude-Teams/claude-code, brew:claude-code, npm:@anthropic-ai/claude-code | ~\.local\bin\|claude.exe, npm:@anthropic-ai/claude-code | npm:@anthropic-ai/claude-code |
    | Codex (codex) | app:ChatGPT.app, app:Codex.app, brew:codex, npm:@openai/codex | npm:@openai/codex | npm:@openai/codex |
    | ChatGPT (chatgpt) | app:ChatGPT.app | %L\Programs\ChatGPT, %WA\OpenAI.ChatGPT-Desktop_* | none |
    | ChatGPT Atlas (chatgpt atlas) | app:ChatGPT Atlas.app | %L\Programs\ChatGPT Atlas | none |
    | Cursor (cursor) | app:Cursor.app | %L\Programs\cursor | /usr/share/cursor, /opt/cursor, /opt/Cursor |
    | Cursor Agent (cursor-agent) | ~/.local/share/cursor-agent | %L\cursor-agent | ~/.local/share/cursor-agent |
    | VS Code (code, code - insiders) | app:Visual Studio Code.app, app:Visual Studio Code - Insiders.app | %L\Programs\Microsoft VS Code, %PF\Microsoft VS Code, and the Insiders folders | /usr/share/code, /usr/share/code-insiders, /snap/code, /snap/code-insiders, /var/lib/flatpak/app/com.visualstudio.code |
    | Windsurf (windsurf) | app:Windsurf.app | %L\Programs\Windsurf | /usr/share/windsurf |
    | Copilot app and Copilot CLI (copilot, github-copilot) | app:Copilot.app, brew:copilot-cli, npm:@github/copilot | %L\Programs\Copilot, %WA\Microsoft.Copilot_*, %L\Microsoft\WinGet\Packages\GitHub.Copilot_*, npm:@github/copilot | npm:@github/copilot |
    | Ollama (ollama, ollama app) | app:Ollama.app, brew:ollama | %L\Programs\Ollama | /usr/local/bin\|ollama, /usr/bin\|ollama, /usr/local/lib/ollama, /usr/lib/ollama, /snap/ollama |
    | LM Studio (lm studio, lms, llmster) | app:LM Studio.app, ~/.lmstudio | %L\Programs\lm-studio, %L\Programs\LM Studio, ~\.lmstudio | ~/.lmstudio |
    | opencode | ~/.opencode, brew:opencode, npm:opencode-ai | ~\.opencode, npm:opencode-ai | ~/.opencode, npm:opencode-ai |
    | goose | app:Goose.app, ~/.local/bin\|goose | none | ~/.local/bin\|goose |
    | amp | ~/.amp, npm:@sourcegraph/amp | npm:@sourcegraph/amp | ~/.amp, npm:@sourcegraph/amp |
    | crush | brew:crush, npm:@charmland/crush | npm:@charmland/crush | npm:@charmland/crush |
    | Kiro (kiro) | app:Kiro.app | %L\Programs\Kiro | /usr/share/kiro |
    | Trae (trae) | app:Trae.app | %L\Programs\Trae | none |
    | Zed (zed) | app:Zed.app | none | ~/.local/zed.app |
    | MoorAI (moorai, moorai-desktop) | app:MoorAI.app | %L\MoorAI | /usr/bin\|moorai, /usr/bin\|moorai-desktop |
    | Chrome (google chrome, chrome) | app:Google Chrome.app | %PF\Google\Chrome, %PF86\Google\Chrome, %L\Google\Chrome | /opt/google/chrome |
    | Chromium (chromium) | app:Chromium.app | %L\Chromium | /usr/lib/chromium, /usr/lib/chromium-browser, /usr/lib64/chromium-browser, /snap/chromium |
    | Firefox (firefox) | app:Firefox.app | %PF\Mozilla Firefox, %PF86\Mozilla Firefox, %L\Mozilla Firefox | /usr/lib/firefox, /usr/lib64/firefox, /opt/firefox, /snap/firefox |
    | Safari (safari, com.apple.webkit.networking) | /Applications/Safari.app, WebKit.framework under /System/Library/Frameworks, /System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks and /System/Cryptexes/OS/System/Library/Frameworks | none | none |
    | Edge (msedge, microsoft edge) | app:Microsoft Edge.app | %PF86\Microsoft\Edge, %PF\Microsoft\Edge | /opt/microsoft/msedge |
    | Brave (brave, brave browser) | app:Brave Browser.app | %PF\BraveSoftware, %PF86\BraveSoftware, %L\BraveSoftware | /opt/brave.com/brave, /snap/brave |
    | Arc (arc) | app:Arc.app | %WA\TheBrowserCompany.Arc_* | none |
    | Opera (opera) | app:Opera.app | %L\Programs\Opera | /usr/lib/x86_64-linux-gnu/opera, /snap/opera |
    | Vivaldi (vivaldi) | app:Vivaldi.app | %L\Vivaldi | /opt/vivaldi |
    | Dia (dia) | app:Dia.app | none | none |
    | Comet (comet) | app:Comet.app | %L\Perplexity\Comet | none |
    | Internet Explorer (iexplore) | none | %PF\Internet Explorer, %PF86\Internet Explorer | none |

    Every app in `data/ai-catalog.json` (ChatGPT, ChatGPT Atlas, Claude, Copilot, Cursor, Windsurf, Perplexity,
    Ollama, LM Studio, Msty, Jan, Raycast) also counts at its catalog location: its `.app` under
    `/Applications` or `~/Applications`, and on Windows the catalog folder under `%LOCALAPPDATA%`,
    `Program Files` and `Program Files (x86)`, the roots the AIBOM searches.
  - `node`, `nodejs`, `bun`, `deno` and `python*` are known only by the program they run
    (`cli/script-host-argv.mjs`, `cli/ai-install-locations.mjs`):
    - **Grammar.** argv is read with the runtime's own option grammar. Every option is on a per-runtime
      allowlist, and anything unlisted is unparseable and so unknown. A value option counts only in the form
      the runtime itself reads (node: `--title=x`; measured on node 22: `--title t a.js` consumes `t`, and
      V8's `--max-old-space-size 100` is refused). Python short options cluster (`-Bu`, `-Wd`, `-Im aider`),
      and `-c`/`-m`/`-W`/`-X` take the rest of the token or the next argument. Option names fold `_` to `-`.
    - **Other code.** Each of these makes the caller unknown.
      - node: `-r`/`--require`, `--import`, `--loader`, `-e`/`-p`, `-` or no script (stdin), `-i`,
        `--env-file` (it can set `NODE_OPTIONS`; measured: a `--require` in it ran), a config file, a
        snapshot, `--run`/`--test`/`--watch`, `--inspect*`, `--preserve-symlinks*`, `-C`.
      - bun: `--preload`, `-e`, `--config`/`--cwd` (another bunfig.toml), `--env-file`, auto-install, `x`.
      - deno: `--preload`, `--import-map`, `-c`, `--env-file`, `--node-modules-dir`, `--vendor`, subcommands
        other than `run`.
      - python: `-c`, `-i`, `-` or no script, a dotted `-W` category (measured: imported), an unlisted `-X`
        (`pycache_prefix`, `presite`).
    - **Location and entry.** The main script must be an absolute path that resolves (realpath) to
      `<root>/node_modules/<pkg>/<bin>`. `<root>` is a global install root, `<pkg>` is the first package
      under it (one nested in another package's `node_modules` does not count), `<pkg>/package.json` names
      `<pkg>`, and `<bin>` is one of its `bin` entries. The roots:
      - npm prefixes: `/usr/local/lib`, `/usr/lib`, `/opt/homebrew/lib`, `/home/linuxbrew/.linuxbrew/lib`,
        `~/.npm-global/lib`, `~/.npm-packages/lib`, `~/.local/lib`, and on Windows `%APPDATA%\npm` and
        `C:\Program Files\nodejs`.
      - Version managers: `~/.nvm/versions/node/*/lib`, fnm (`~/.local/share/fnm`,
        `~/Library/Application Support/fnm`, `~/.fnm`, `%APPDATA%\fnm`), `~/.volta/tools/image/packages/<pkg>/lib`
        (`%LOCALAPPDATA%\Volta`), `~/.asdf/installs/nodejs/*/lib`, `~/.local/share/mise/installs/node/*/lib`,
        `%APPDATA%\nvm\*`.
      - Global folders: yarn `~/.config/yarn/global` (`%LOCALAPPDATA%\Yarn\Data\global`), bun
        `~/.bun/install/global`, and pnpm `~/Library/pnpm/global/*`, `~/.local/share/pnpm/global/*`,
        `%LOCALAPPDATA%\pnpm\global\*` (resolving into `.pnpm/<id>/node_modules/<pkg>`).
      - deno's npm cache `<cache>/deno/npm/registry.npmjs.org/<pkg>/<version>/<bin>` (`~/Library/Caches`,
        `~/.cache`, `%LOCALAPPDATA%`), with `--no-config` on the command line, since otherwise deno reads a
        `deno.json` from the working directory, whose import map can replace any module.
      - aider: `<venv>/bin/aider` (`<venv>\Scripts\aider.exe`) for a venv named `aider-chat` under
        `~/.local/pipx/venvs`, `~/.local/share/pipx/venvs`, `~/Library/Application Support/pipx/venvs`,
        `~/.local/share/uv/tools`, or on Windows `%USERPROFILE%\pipx\venvs`, `%USERPROFILE%\.local\pipx\venvs`,
        `%LOCALAPPDATA%\pipx\pipx\venvs`, `%APPDATA%\uv\data\tools`. `python -m aider` counts only with `-I` or
        `-P` and argv[0] in that venv; measured on python 3.14, a planted `./json_tool` ran under
        `-m json_tool` and not under `-P` or `-I`.
      - Package specs (`deno run npm:…`, `bun x …`), relative scripts and other locations stay unknown.
    - **Windows.** `Win32_Process.CommandLine` reaches MoorAI base64-encoded (UTF-16LE), one record per pid, so
      a line break inside a command line cannot forge another record, and a pid seen twice is dropped. It is
      split by CommandLineToArgvW's rules: argv[0] runs to the next quote or blank with no escapes; then 2n
      backslashes before a quote give n and toggle quoting, and 2n+1 give n and a literal quote. node,
      python, bun and deno split with their own runtime code, which disagrees with CommandLineToArgvW on a
      doubled quote and on a quote inside or right after argv[0]. Such a line, or an unclosed quote, is
      unknown.
    - **macOS.** `ps` joins argv with spaces. A script path with spaces counts only when exactly one join of
      the following arguments exists on disk. ps prints a newline as `\012` and a backslash as itself
      (measured), so a backslash before or in the script path makes the line undecodable and unknown.
  - Claude Code's native install runs as an image named like its version (for example `2.1.295`). It is known
    only when the executable the kernel reports is `$HOME/.local/share/claude/versions/<that image>`: on macOS
    `codesign -d <pid>`, on Linux `/proc/<pid>/exe`. argv[0] is not consulted. On macOS the running process
    must also pass `codesign --verify -R='anchor apple generic and identifier "com.anthropic.claude-code" and
    certificate leaf[subject.OU] = "Q6L2SF6YDW"' <pid>`; measured on the dev Mac, the installed versions
    pass in about 0.4 s and an Apple-signed shell exits 3. On Linux the location alone decides. On Windows the
    native install runs as `claude.exe` and is known by name.
  - Command lines are read locally for script-host pids only (`ps -ww -o pid=,args=` on macOS,
    `/proc/<pid>/cmdline` on Linux, one PowerShell `Get-CimInstance Win32_Process … CommandLine` on Windows),
    and executables for named and version-named pids only. Neither is posted or stored.
  - Rows are per (image, provider, known): an unknown node script is never folded into a known node process,
    or MoorAI's own node, on the same provider.
- **Alert.** `AI_API_CALLER_UNKNOWN` at most once per image and provider per UTC day, unless
  `aiApiCallers: "off"`. The connection count rides on the alert only.
- **Limits.** Only the listed provider hosts are recognised: a command server of the attacker's own behind
  TLS, a provider reached through a relay, a corporate proxy or VPN, or a provider address the device's
  resolver did not return is not identified. On macOS and Linux only processes the user may inspect are
  attributed. The scan sees connections open at the moment of the daily beat, not every connection. The
  command line is the process's own claim: a process started with a forged argv (`exec -a`, or on macOS an
  argument holding spaces), or one that rewrites its own argv, is classed by what it claims. `NODE_OPTIONS`,
  `PYTHONPATH`, `.pth` files and a `bunfig.toml` preload in bun's working directory are not read. A relocated
  prefix (`npm config prefix`, `DENO_DIR`, `PIPX_HOME`, a moved AppData) is not recognised. A pip `--user`
  console script for aider stays unknown. The per-user install locations and the native versions folder are
  writable by the user, so the location rule tells an installed CLI from a script elsewhere but does not prove
  the installed files are unmodified. On Linux any program copied into `~/.local/share/claude/versions/`
  under a version name counts as Claude Code. The checks run as the user, so a process running as the same
  user that installs software into the user's own install locations is indistinguishable from that software;
  the privileged helper is the planned fix. A product installed outside the listed locations (a portable
  copy, an AppImage mounted under /tmp, a relocated prefix, a Store package name not listed) is reported,
  unless on macOS it satisfies a listed signing identity. More than 64 named pids in one scan: the rest are
  reported. On Intel Macs an unsigned program gives codesign no path and is reported.

### Path containment (`cli/path-within.mjs`)

Every location gate in these detectors asks one question, "is path P inside root R", with one helper,
`isWithin(path, root, platform)` (and `within`, which returns the segments below the root). It is used by the
terminal and IDE gate (`inLocation`, the temp-folder and C:\Windows tests in `cli/ai-cli-parents.mjs`) and by
the install-location gate (`cli/ai-install-locations.mjs`: npm, pnpm and deno roots, pipx and uv venvs, the
native Claude Code folder, the product table above).

- **Segments, never prefixes.** Both paths are split into segments and compared segment by segment:
  `/usr/local/lib-old/…` is not inside `/usr/local/lib`, `C:\Program Files Extra\…` is not inside
  `C:\Program Files`. A root is not inside itself.
- **Case.** Windows: case-insensitive (`toLowerCase`). macOS: case-insensitive, NFC-normalised, matching the
  default APFS volume (a case-sensitive volume is still compared insensitively). Linux: case-sensitive.
- **Separators.** `/` everywhere and `\` on Windows; repeated and trailing separators are dropped.
- **`.` and `..`.** A path holding a `.` or `..` segment (on Windows any all-dots segment) is refused, never
  resolved: lexical resolution is wrong across symlinks, and kernel and realpath paths have none.
- **Windows forms.** `\\?\C:\…`, `\\.\C:\…` and `\??\C:\…` read as `C:\…`; `\\?\UNC\server\share\…` reads as
  `\\server\share\…`. Other device paths (a volume GUID, a pipe), drive-relative `C:x`, rooted `\x` and a
  segment holding `:` (an alternate data stream) are inside nothing. A Windows-shaped path is judged with
  Windows rules on any host.
- **Root globs.** In a root, `*` inside a segment matches within that one segment (`*` alone is any one
  segment), and a `*:` drive matches any drive letter, never a UNC share. A home path holding `*` gives no
  per-user roots.
- **Tests.** `test/path-within.test.mjs` (canned root/path pairs per platform), `test/location-gates.test.mjs`
  (both gates on the same pairs), `test/ai-api-callers-identity.test.mjs` (known by location, one case per
  product, signing identity, script-host executables).

## End-to-end trace (v1.16.0)

**Status: built and tested (`test/trace-context.test.mjs`, `test/trace-hook.test.mjs`, `test/trace-proxy.test.mjs`,
`test/trace-proxy-trail.test.mjs`, `test/trace-gateway.test.mjs`, `test/trace-mcp-guard.test.mjs`,
`test/action-trail.test.mjs`).** One trace per agent session, W3C Trace Context (Recommendation, 23 November
2021). Content-free: hex ids and an agent name from `cli/agent-names.mjs` only.

**Contract** (agent v1.16.0, console v0.87.0). `cli/trace-context.mjs` is the only W3C implementation; the model
proxy, the HTTP MCP gateway and the stdio guard use it through `model-proxy/trace-w3c.mjs` (which re-exports
`parseTraceparent` / `mergeTracestate` and builds `createTracer` on `continueOrStart`), the hook and the egress
proxy directly.

| Export | Behaviour |
|---|---|
| `traceIdFor({ tenantKey, sessionKey })` | HMAC-SHA-256(deriveKey(installToken), `"moorai/trace-id/v1\n" + sessionId`), first 32 hex (an all-zero result ends in `1`). `tenantKey` is the install token or the derived key; both give the same id. Null without a key or a session id. |
| `newTraceId()` / `newSpanId()` | random 32 / 16 hex, never all zeros |
| `parseTraceparent(header)` | `{ traceId, parentSpanId, flags, sampled }` or null. Spaces and tabs around the value are ignored. Version `00`: exactly `00-<32 hex>-<16 hex>-<2 hex>`, lowercase, 55 characters. A higher version (2 lowercase hex, not `ff`) is read by the `00` layout (W3C 3.2.4): at least 55 characters, the flags followed by the end or `-`. All-zero trace-id or parent-id: null. |
| `formatTraceparent({ traceId, spanId, sampled })` | `"00-<traceId>-<spanId>-01"` or `-00`; null for a bad id |
| `tracestateMoorai({ agentName })` | `"moorai=a:<agentName>"` for a name in the `cli/agent-names.mjs` vocabulary, else null |
| `mergeTracestate(incoming, entry)` | W3C 3.3.1 grammar; spaces, tabs and empty members ignored. An incoming header with an invalid member or more than 32 members is discarded whole (W3C 4.3). A repeated key keeps its first, left-most entry. The entry goes first and an earlier entry with its key is removed. Over 32: the right-most entry over 128 characters goes, else the right-most entry; the entry itself is never dropped. |
| `continueOrStart({ traceparent, tracestate, traceId, sampled, agentName })` | a valid incoming `traceparent` continues (its trace-id and sampled flag kept, `parentSpanId` = its span, a new span sent on as version `00`, `tracestate` merged); else `traceId` (from `traceIdFor`); else a new random trace. A `tracestate` is never sent on without a valid `traceparent`. |

- **TRC-1 Records.** Every hook alert and allow-trail record carries `traceId` (32 hex), `spanId` (16 hex, fresh
  per record) and, on a sub-agent's records, `parentSpanId`. Device inventory alerts (`LOCAL_MODEL_EXPOSED`,
  `AI_API_CALLER_UNKNOWN`) and the detached workers' alerts (posture beat, index scan, model escalation, agent
  scan) carry none. The allow-trail builder keeps a trace field only when it is valid lowercase hex.
- **TRC-2 Session trace.** The hook's `traceId` is `traceIdFor(installToken, session_id)`, computed only when the
  invocation sends a record. No install token or no session id: a random trace for that invocation.
- **TRC-3 Sub-agents (Claude Code).** `parentSpanId` is the `spanId` of the spawning call's delegation record
  (#66). Exact from `PostToolUse(Agent|Task).tool_response.agentId`; else inferred from exactly one unbound
  pending spawn in the session whose `subagent_type` equals the child's `agent_type`; else absent. An exact
  binding replaces a wrong inference. A delegation that is denied (outside coach mode) records no spawn. Spawn
  map: `~/.moorai/trace-spawns.json` (0600, temp + rename under a lock), ids keyed with the device-local key,
  span ids random, entries kept 24 hours, at most 256 spawns and 512 bindings.
- **TRC-4 OTLP.** Spans use the record's `traceId`, `spanId` and `parentSpanId`; a record without a valid
  `traceId` gets a random one.
- **TRC-5 Model proxy → provider.** `traceparent` / `tracestate` headers on every route. Trace: a valid incoming
  `traceparent`; else `traceIdFor` over `X-Claude-Code-Session-Id` (at most 256 characters); else new, sampled.
  `tracestate` entry `moorai=a:model-proxy`. Alerts of the request carry the trace fields plus `provider`
  (`anthropic` | `openai` | `google` | `ollama` | `other`) and `model` (`[A-Za-z0-9._:/@-]{1,64}`, else omitted).
- **TRC-6 HTTP MCP gateway → upstream.** `traceparent` / `tracestate` headers; a valid incoming `traceparent`,
  else a new trace (no session is known; `Mcp-Session-Id` belongs to the transport). Entry `moorai=a:gateway`.
  The body, `_meta` included, is forwarded as sent.
- **TRC-7 MCP stdio guard → server.** `params._meta.traceparent` / `params._meta.tracestate` on a forwarded
  `tools/call`; MCP 2026-07-28 reserves `traceparent`, `tracestate` and `baggage` in `_meta` for OpenTelemetry
  trace context. Trace: a valid `_meta.traceparent`; else `traceIdFor` over `CLAUDE_CODE_SESSION_ID` when
  `AI_AGENT=claude-code_<v>_harness`; else new. Entry `moorai=a:<--host agent name>`. The line is edited in
  place (`mcp-proxy/trace-meta.mjs`); a line with a repeated `params`, `_meta`, `traceparent` or `tracestate`
  key, a `_meta` that is not an object, a refused call and a fail-open forward go as sent.
- **TRC-8 Egress proxy, plain HTTP.** A valid incoming `traceparent` and its `tracestate` go on unchanged (a
  higher version included); alerts carry its trace-id, a fresh span and `parentSpanId` = its span. Otherwise a
  new sampled `traceparent` is set and `tracestate` removed. No `moorai` entry. `CONNECT` tunnels are not
  modified; their alerts carry the `CONNECT` request's trace, else a new one. A repeated `traceparent` header is
  invalid.
- **TRC-9 Model proxy allow trail.** With `actionTrail: "allowed"` in the verified signed policy on an enrolled
  device, one record per forwarded request: `event: "ModelRequest"`, tool `model-proxy:<provider>`, decision
  `allow`, basis `default`, `agentName` (`claude-code` when the request names a Claude Code session, else
  `model-proxy`), the trace fields, `provider`, `model`; the hook's queue, `seq` and `POST /api/actions`.
  `buildActionRecord` validates `provider`, `model` and `event` (letters only, at most 32, default
  `PreToolUse`) and leaves out a value that fails.
- **No value logged.** No header or `_meta` value is logged, stored or reported on any surface.

**Session signals (measured, Claude Code 2.1.295)** against a local fake Messages API, a fake HTTP MCP server
and a fake stdio MCP server, with hooks that dumped their stdin:

| Where | Session id | Sub-agent id | Call id |
|---|---|---|---|
| Hook stdin | `session_id` | `agent_id` + `agent_type` inside a sub-agent | `tool_use_id` |
| Messages API request | `x-claude-code-session-id` = `session_id`; `metadata.user_id` (JSON string with `session_id`, `device_id`, `account_uuid`) | `x-claude-code-agent-id` = `agent_id` | none |
| Stdio MCP server | `CLAUDE_CODE_SESSION_ID` = `session_id` (one server process per session) | none | `params._meta["claudecode/toolUseId"]` = `tool_use_id` |
| HTTP MCP server | none | none | `params._meta["claudecode/toolUseId"]` |

Claude Code sends no `traceparent`. Codex and Gemini CLI put no sub-agent id on tool calls, and Codex
sub-agents share the parent's session id.

**Cost.** One HMAC per recording invocation (about 2 µs). Spawn map: about 0.1 ms read with 50 pending spawns,
0.03 ms once bound, 0.3 ms per delegation write; hook latency unchanged within noise (40 interleaved spawns per
case). Proxies: about 2 µs per request, 4 µs with a session-derived id (n=100k). Guard edit: 1.3 µs for a
124-byte call, 192 µs for 112 KB.

**Limits.**
- Session ids the proxies see are caller-asserted: any process that can reach a MoorAI proxy can put its
  requests in another session's trace. It cannot change or remove that session's hook records.
- The spawn map is user-writable; it can misdirect a sub-agent's `parentSpanId` within a session, never its
  `traceId` or a decision.
- Parallel spawns of one sub-agent type leave a foreground child's records without `parentSpanId` until its
  spawning call returns.
- Codex, Gemini CLI and Copilot CLI sub-agents' records have the session's trace and no parent.
- Model-proxy and stdio-guard spans join the session's trace without a `parentSpanId` naming a hook record.
- The HTTP MCP gateway starts its own trace unless the client sends a `traceparent`. HTTPS through the egress
  proxy carries nothing MoorAI adds.

## context.tree forensic anchor (v1.16.0)

**Status: built and tested (`test/context-tree-leaf.test.mjs`, `test/context-tree-merkle.test.mjs` with the CT
known-answer vectors in `test/context-tree-ct-vectors.json`, `test/context-tree-store.test.mjs`,
`test/context-tree-hook.test.mjs`, `test/context-tree-hook-frontier.test.mjs`, `test/context-tree-cli.test.mjs`).**
`cli/context-tree.mjs`, CLI `moorai-context-proof`. A per-session Merkle tree of what entered an agent's
context, so an investigator can show which source carried an injected instruction.

**Leaf.** `leafOf({ stage, sourceKind, source, bytes, tenantKey, ts })` →
`{ stage, sourceKind, sourceHash, blobHash, blobHashKind, size, ts }`.
- `stage`: `prompt` | `file` | `web` | `mcp` | `subagent` | `tool-output` | `skill` | `system`.
- `sourceKind`: `path` | `url` | `mcp` | `skill` | `name` | `none`.
- `sourceHash`: the tenant-keyed hash (the HMAC `contentHash` uses) of the canonical source: a normalised
  absolute path under the platform's case rule (`cli/path-within.mjs`); a URL without fragment or credentials,
  scheme and host lower-cased, query kept; `mcp:<server>/<tool>`; `skill:<path>`; `name:<name>`; empty for
  `none`.
- `blobHash`: plain SHA-256 hex when `size` ≥ 256 bytes (`blobHashKind: "sha256"`), else the tenant-keyed hash
  (`"keyed"`). Without a tenant key the keyed fields are `h2:nokey`.

**Merkle tree (RFC 6962 2.1).** Leaf hash = SHA-256(0x00 ‖ canonical JSON of the leaf), node hash =
SHA-256(0x01 ‖ left ‖ right), empty root = SHA-256(""); canonical JSON = sorted keys, no whitespace.
`ContextTree`: `append(leaf)` → `{ index, root }`, `root()`, `rootAt(size)`, `size()`, `proof(index[, size])`, static
`verify(leaf, index, size, proof, root)`. Inclusion proofs work for any index at any earlier size; a proof is
checked against a stated size, so records carry `contextSize` next to `contextRoot`.

**Storage.**
- One append-only JSONL file per session, `~/.moorai/context-tree/<keyed session id>.jsonl` (`:` written as
  `-`), 0600 in a 0700 directory; leaves only, the root recomputed. Each leaf is one write of one line.
- Lock: per session, `cli/alert-seq.mjs` `withFileLock`, 200 ms wait. An append that cannot get it writes its
  line without it and reports no index.
- Frontier: `<file>.frontier` caches the leaf count, the session file's byte length and one subtree hash per
  set bit of the count. An append reads it, writes its line, folds the leaf in and replaces it (temp + rename),
  all under the lock. Missing, unreadable, wrongly shaped or with another byte length: rebuilt once from the
  file. When a lock-less line lands between a locked append's stat and its write, that append takes its index
  and root from the file and leaves the frontier for the next append to rebuild.
- Recovery: a torn last line or a line that is not a valid leaf is skipped and reported, never rewritten.
- Cap: 50,000 leaves per session; at the cap appends stop and report `capped`, no earlier leaf is dropped.
- Retention: session, frontier, upload and lock files older than 30 days are deleted by a sweep that runs when a
  session's first leaf is written.

**Hook wiring.** The tree id is the keyed session id (the alerts' `session`); a sub-agent's tree id is
`contentHash(session_id + "\0agent:" + agent_id)`. Leaves are built from bytes the hook already holds, before
the item is judged; the hook reads no file to build one.

| Event | Item | Stage | Source |
|---|---|---|---|
| UserPromptSubmit | the prompt | prompt | none |
| PreToolUse Read | the buffer read for scanning | file, or skill for a skill surface | path / `skill:<path>` |
| PostToolUse WebFetch | the result | web | URL |
| PostToolUse WebSearch | the result | web | `name:<query>` |
| PostToolUse `mcp__*` | the result | mcp | `mcp:<server>/<tool>` |
| PostToolUse Bash / PowerShell | the output | tool-output | `name:<tool>` |
| PreToolUse Task / Agent | `tool_input.prompt` | subagent | `name:<subagent_type>` |
| PostToolUse Task / Agent | the report | subagent | `name:<subagent_type>` |

The result blob is a string result as it is, a shell call's stdout when stderr is empty, or a single text
block's text; any other shape is the text MoorAI judged.

**Records.**
- Every alert and allow-trail record: `contextRoot` (64 hex) and `contextSize` (leaf count) at decision time,
  sent together or not at all.
- `contextSession` (`^[A-Za-z0-9_:]{1,128}$`, never `h2:nokey`): the keyed id of the tree `contextRoot` belongs
  to, only on a sub-agent's records, only with `contextRoot`, only when it differs from `session`. It equals
  the `sessionHash` of that tree's upload. Look up a record's leaves under `contextSession ?? session`.
- Content and injection alerts (detector findings on the item, skill-file poisoning, a decoy key in a tool
  result): `contextLeaf { index, stage, sourceHash, blobHash, blobHashKind }`.
- Hashes, enums and integers only.

**Policy.** `contextTree: "off" | "local" | "console"` from the verified policy, default `"local"`. `"console"`
needs a policy with a signature envelope (`policySig.sig`); without one it reads `"local"`. `"off"` writes
nothing and stamps nothing.

**Console upload (`"console"`).** `POST /api/context-tree { v: 1, sessionHash, leaves: [{ index, ...leaf }] }`,
up to 500 leaves per request, sent by the allow trail's detached worker, never on the decision path. Per-session
state in `<file>.upload`; `sent` advances only on a 2xx. Triggers: 50 unsent leaves, an unsent leaf older than
30 seconds, or Stop / SubagentStop; the trigger takes a lease. Retries 1, 2 and 4 minutes, capped at 5; nothing
is sent during the console back-off.

**CLI `moorai-context-proof`.**
- `--session <keyed id> --index <n> [--size <m>]`: JSON `{ session, index, size, leaf, leafHash, proof, root,
  verified }`; `--size` proves against the root of the first `m` leaves (a recorded `contextSize`).
- `--verify <file|-> (--session <keyed id> | --all)`: hashes the blob the way `leafOf` does and lists every
  matching leaf with its proof against the session's current root. A blob under 256 bytes on a device with no
  key is refused (it would match every short leaf). The argument is never echoed.
- `--home <dir>`. Exit 0 printed or found, 1 no leaf or no match, 2 usage.

**Cost** (Apple M5 Max). Append p50 0.26 ms / p95 0.38 ms at 5,000 leaves, p50 0.28 ms / p95 0.40 ms at 50,000
(a full reload per append took 14.9 ms and 146 ms). Frontier rebuild: 18 ms at 5,000, 149 ms at 50,000.

**Limits.**
- Tamper-evident, not tamper-proof: the session file is in the user's home, where the agent can write. A
  rewritten history yields a root that no longer matches the roots on records; nothing stops the rewrite
  itself until the privileged helper signs roots.
- The SHA-256 of a blob of 256 bytes or more lets anyone holding the original confirm it entered the context.
- Short blobs and sources need the tenant key; keyed hashes are 64 bits, as `contentHash`. An unenrolled
  device keeps no tree.
- The tree names the source kind, not the source: naming it takes a candidate path or URL hashed under the
  tenant key.
- Files a host loads without a tool call (CLAUDE.md at start-up, rules files) get no leaf; a Read of them does.
- A web leaf matches the host's processed text (WebFetch's result), not the page on the server. A file leaf
  matches the file on disk.
- PreToolUse is the only Read event, so a Read MoorAI then denies keeps its leaf; so do a Task / Agent prompt
  and a prompt a prompt-scan policy blocks.
- A sub-agent's first prompt is a leaf in the caller's tree.
- A session's `.upload` state remains after the policy moves from `"console"` to `"local"`; the leaves recorded
  while `"console"` was in force are still sent.

## Capability tags and exceptions

**Status: built and tested (`test/tool-tags.test.mjs`, `test/tool-tags-hook.test.mjs`,
`test/exceptions.test.mjs`, and a tag-action case in `test/agent-sdk-parity.test.mjs`). Hook and Agent SDK.**

**Tags** (`data/tool-tags.js`, `cli/tool-tags.mjs`): `read-private`, `read`, `write`, `network`, `exec` per
tool call. Built-in tools by name; Bash/PowerShell from `extractReadPaths`, `netDestinations`,
`urlDestinations` and a list of remote CLIs and package managers; MCP tools from `_meta["moorai/tags"]`
(added, never subtracted) plus name words and known remote servers (inferred). `read-private` also comes
from a stage-"file" finding of #1, #15, #39, #44 or #55 on a read.

**Policy keys** (verified policy and root-owned system config only):
- `tagActions: { <tag>: "block" | "ask" | "alert" | "allow" }`: static per call; stricter of the two sources.
- `tagRules: [{ id?, if: { sessionHas: [tags] }, deny: [tags], action?: "block" | "alert" }]`: session tags
  include the current call; alert-only hits once per session and rule. At most 64 rules; invalid ones are
  skipped and reported once a day as "Capability tag policy rejected".
- Merged with the branch verdict in `emit()` before session-risk escalation and headless settlement;
  stricter wins. Reason code `BEHAVIOR_SIGNAL`. Alerts: "Capability tag action" / "Capability tag rule"
  with `tagRule: { kind, id, action, tags, sessionHas?, source?, inferred? }`.
- Session record `~/.moorai/session-tags.json` through `cli/session-state.mjs` (keyed hash, tag names, 32
  sessions, 24 h). Tags of a call the host was told to deny are not recorded.
- Agent SDK: `tagActions` and console exceptions in `decideToolCall`; `tagRules` are listed in
  `NOT_EVALUATED` ("tag-rules").

**Exceptions** (`cli/exceptions.mjs`, `cli/moorai-allow.mjs`): `{ id, threat | rule, pattern, expires }`;
the subject is the absolute path with `.` and `..` folded (file tools), the command with runs of blanks
collapsed and line breaks kept (shell), the URL as `new URL().href` reads it, dot segments resolved
(WebFetch), or the tool name (MCP). `*` is the only wildcard and the whole subject must match; over a shell
command (`matchCallExceptions`, Bash and PowerShell) a `*` never matches `;` `&` `|` `(` `)` `<` `>`, a
backtick or a line break, quoted or not, so an operator in the command must be literal in the pattern and a
multi-line command matches nothing. A match sets that threat to `notify` in a per-call copy of the policy, or skips that
tag rule (`rule: "<id>"`, `rule: "tag:<tag>"`). Sources: `policy.exceptions` (console, always) and
`/etc/moorai/exceptions.json` read through `readRootOwned` when `localExceptions: "allow"` is in the
console policy (enrolled), or in it or the root-owned config (unenrolled). Local entries need `created` and
at most 24 h to `expires`. User-scope files are never read. Ledger and alerts: "Local exception granted"
(first sight), "Exception applied" (it changed the outcome), "Local exception ignored (local exceptions are
off)", "Agent attempted to grant a MoorAI exception"; each carries the exception id and a keyed pattern
hash, never the pattern. "Granted" and "ignored" post once per exception id (`cli/seen-once.mjs`, records kept 7 days);
before v1.18.1 a missing record read as seen, so neither ever posted.

**Deny/ask message**: `Exception: …` appended after the safer line, naming the threat ids from the reason
(#65 for the two secret-egress reasons) or the tag rule ids, and a suggested pattern that masks quoted
strings, values after `=`, header/auth/data arguments, long opaque tokens and opaque URL path segments, with
`?*` for a query. No pattern (and no line) when the command spans lines, when a value is masked and the
command holds any of the shell characters above (a composite command is suggested verbatim or not at all),
when a mask falls at or before the command word, when the URL carries userinfo, or when the pattern would
exceed 1024 characters or not match its own call; it is never cut short. Not printed in server mode or on a
coached device.

**Not proven / limits**: the hook has no copy of an MCP tool's definition, so declared `_meta` tags are only
seen when a host forwards `_meta` in the tool input. The root-owned store path was never exercised end to
end (the tests cannot create a root-owned file; `readExceptionStore` is tested with an injected reader).
Passwordless or cached sudo defeats the local-exception boundary. Tested on macOS only.

## Transcript ingest (moorai-ingest)

`cli/moorai-ingest.mjs` (modules in `cli/ingest/`) replays the agent transcripts already on the device
through the live hook's decision functions, so a new install shows what MoorAI would have flagged, and
what enforce mode would have blocked, in sessions that ran before it was installed. `moorai-backtest`
cannot do this: it replays the content-free action-audit log, which holds threat ids and no content, so
it can test a policy change but not score a detector.

**Formats.**
- *Claude Code*: `$CLAUDE_CONFIG_DIR` or `~/.claude` → `projects/<project>/<session>.jsonl` and
  `<session>/subagents/**/agent-*.jsonl` (the file the hook input names as `transcript_path`). Records:
  `assistant` with `message.content[].tool_use {id, name, input}`; `user` with `tool_result
  {tool_use_id, content, is_error}` and the structured `toolUseResult`; typed prompts as `user` records
  (not `isMeta`, `isCompactSummary` or `isSidechain`); hook traces as `system/stop_hook_summary.hookInfos[].command`
  and `attachment.command`. Read off real transcripts on a developer machine, structure only.
- *Codex*: `$CODEX_HOME` or `~/.codex` → `sessions/YYYY/MM/DD/rollout-<ts>-<id>.jsonl`,
  `archived_sessions/`, and `.jsonl.zst` (codex-rs `rollout/src/lib.rs`, `rollout_file_name.rs`,
  `compression.rs`). Lines are `{timestamp, type, payload}` (`history/src/rollout_payload.rs`);
  calls are `response_item` `function_call` (`exec_command {cmd}`, `shell {command: argv}`,
  `shell_command`, `apply_patch {input}`, `view_image`, `spawn_agent`, MCP as `namespace` + `name`),
  `custom_tool_call` (`apply_patch`) and `local_shell_call`; prompts are `event_msg` `user_message` or
  `item_completed` `UserMessage`. Each call becomes the payload Codex hands a PreToolUse hook and goes
  through the same adapter the live Codex hook uses (`cli/agent-hooks/codex.mjs toClaude`).
- *Gemini CLI*: `~/.gemini/tmp/<project_hash>/chats/session-<ts>-<id8>.jsonl`, the legacy `session-*.json`
  (one ConversationRecord, read whole within the per-file and total byte bounds) and sub-agent sessions
  `chats/<parent session>/<id>.jsonl`; only files under a `chats` folder count
  (`cli/ingest/discover.mjs`). Format from gemini-cli `packages/core/src/services/chatRecordingTypes.ts`
  and `chatRecordingService.ts`: a metadata line `{sessionId, projectHash, startTime, lastUpdated, kind?,
  directories?}`, message lines `{id, timestamp, type, content, toolCalls?}` with ToolCallRecord `{id, name,
  args, result?, status, timestamp}`, and `$set`, `$patch` and `$rewindTo` lines. Tool calls are merged by
  id (a call recorded before it finished and patched later counts once) and emitted at end of file; each
  goes through `cli/agent-hooks/gemini.mjs toClaude` as `BeforeTool`, and a successful `web_fetch` result
  is replayed as the `AfterTool` scan. User turns in a `kind: "subagent"` session are the parent's
  delegation and are not replayed as prompts. Read from source and tested on fixtures
  (`test/ingest-gemini.test.mjs`); no session file from an installed Gemini CLI was read.
- *Not read*: Antigravity and Windsurf document where their transcripts are (`<app_data_dir>/brain/
  <conversationId>/.system_generated/logs/transcript.jsonl`; `~/.windsurf/transcripts/<trajectory_id>.jsonl`)
  but not their line format; Kiro uses an undocumented SQLite file in `~/.kiro/`; Cline's
  `~/.cline/data/sessions/` format is not documented; Cursor, Copilot CLI and Droid document none.

**Decision path.** `cli/ingest/replay.mjs` calls the hook's functions — `decideText`,
`decideCredFileRead`, `decideAgentStateWrite`, `decideEndpoints`, `decideEnvelope`, `mcpGateway`,
`mcpFloor`, `threatActionFor` (`cli/hook-core.mjs`), `decideInbound` (`cli/inbound.mjs`) and
`promptScanPlan` / `promptBlockers` (`cli/prompt-scan.mjs`) — composed per tool the way
`cli/moorai-hook.mjs` composes them for PreToolUse, PostToolUse and UserPromptSubmit. A call that enforce
mode would have denied gets no result scan (it never ran), and neither does a failed one. Claude Code
calls may resolve to `mask`; Codex calls cannot (the shim does not rewrite). The policy is the one
`loadVerifiedPolicy` returns (or the built-in baseline the hook uses when there is none), or a
`--policy` candidate. `test/ingest-parity.test.mjs` runs the real hook process on the same inputs and
asserts the same decision.

**Output.** Content-free by default: counts by threat, agent and decision, sessions affected, the
most-flagged categories, and hook coverage per session (MoorAI hook seen / other hooks only / unknown).
`--show-local` adds the content and refuses unless stdout is a terminal. `--report` (off by default,
enrolled devices only) posts one alert per finding: the live alert's content-free fields plus
`replayed: true`, `source: "ingest"`, `agent`, the original `ts`, `ingestedAt`, `wouldDecision`,
`enforcement: "UNEVALUATED"`, a keyed `replayId`, and `session` computed as the hook computes it
(`contentHash` of the raw session id, omitted with no id or no key). `riskLevel` is never `Blocked`.

**Bounds.** Files (200 newest in the `--days` window, default 30), total bytes (512 MiB), bytes per file
(64 MiB), line length (8 MiB; longer lines skipped and counted, never buffered whole), wall time (120 s),
and a bounded directory walk. Malformed lines and unparseable Codex arguments are skipped and counted.

**Not proven / limits.**
- The per-tool composition in `replay.mjs` is a second copy of the hook's glue; parity is tested on 15
  inputs, not proven in general. Extracting a pure `decidePreToolUse` from `cli/moorai-hook.mjs` would
  remove the copy.
- Not replayed: files a command reads, file metadata (#72), MCP file arguments, local secret-value
  egress (#65 by value), MCP reputation, cross-call fetch-then-exec, deletion volume, circuit breaker,
  learned drift, session escalation, intent alignment, capability tags, model escalation, and the
  ask-to-deny settlement of server mode and `bypassPermissions`.
- A Read is judged on the content the transcript recorded (`toolUseResult.file.content`), which is the
  file as it was then, not as the hook would read it now.
- Codex and Gemini CLI hook coverage cannot be told: neither persists hook runs to its transcript. Claude
  Code coverage is "unknown" for a session that recorded no hook trace at all.
- Gemini CLI `google_web_search` results are not replayed: the live hook registers that tool after the
  call only, and the replay loop scans a result only behind a replayed call.
- The legacy Codex `shell` argv is turned into a command string by this tool; what the Codex hook sent
  for it was not observed. Prompts are scanned only as `promptScan` allows, as in the live hook: a typed
  prompt is not scanned under the default.

## Hook adapters built from vendor docs: Antigravity, Windsurf, Kiro, Cline

`cli/moorai-agent-hook.mjs <antigravity|windsurf|kiro|cline>` runs the same shim as the other adapters
(`cli/agent-hooks/shim.mjs evaluateAll`: one Claude-shaped payload per call or per path, most restrictive
verdict wins, bounded at 32 checks and 20 s). None of these hosts is installed on the build machine, so no
adapter has been run against its host; each is tested on payloads in the documented shape
(`test/fixtures/agent-hooks/<host>/`, `test/agent-hook-<host>.test.mjs`), and `data/host-versions.json` records
no tested version for any of them.

| Host | Hook contract (source) | Input → MoorAI | Answer | Install |
|---|---|---|---|---|
| Antigravity | antigravity.google/docs/hooks: PreToolUse input `toolCall {name, args}`, `conversationId`, `workspacePaths`; output `decision` allow / auto_approve / deny / ask / force_ask / deny_unless_prior_grant, `reason`, `overwrite`, `permissionOverrides` | `run_command` → Bash, `view_file` → Read, `write_to_file` → Write, `replace_file_content` → Edit, `multi_replace_file_content` → MultiEdit (every string scanned), `read_url_content` → WebFetch, `invoke_subagent` → Task, `mcp_<s>_<t>` → `mcp__s__t` | deny → `deny`; ask → `force_ask`; allow → `allow` (hands the call to Antigravity's policy); never `auto_approve`, `overwrite` or `permissionOverrides`; exit 0 | hook `moorai` in `~/.gemini/config/hooks.json` |
| Windsurf | docs.devin.ai/desktop/cascade/hooks: `agent_action_name`, `trajectory_id`, `tool_info`; exit 2 blocks a pre-hook and the agent sees stderr; other non-zero exits let the action run | `pre_run_command` → Bash, `pre_read_code` → Read, `pre_write_code` → MultiEdit, `pre_mcp_tool_use` → `mcp__s__t`, `pre_user_prompt` → UserPromptSubmit (captured) | deny and ask → exit 2 with the reason on stderr (ask's reason tells the agent to get the user's confirmation); allow → exit 0 | appended to the five pre-hook events in `~/.codeium/windsurf/hooks.json`, with `powershell: "& <command>"` |
| Kiro | kiro.dev/docs/hooks, /docs/cli/v3/hooks-migration, /docs/cli/2x-reference, and the predecessor's docs/hooks.md: stdin `hook_event_name`, `cwd`, `tool_name`, `tool_input`; exit 2 blocks PreToolUse and stderr goes to the model | `execute_bash`/`shell` → Bash, `fs_read`/`read` → Read per operation path, `fs_write`/`write` → Write or Edit per command, `web_fetch` → WebFetch, `use_aws` → Bash `aws <service> <op> ...`, `use_subagent`/`delegate` → Task, `@s/t` or `mcp_<s>_<t>` → `mcp__s__t`; `UserPromptSubmit` captured | deny and ask → exit 2 with the reason on stderr; allow → exit 0 and empty stdout; coach → stdout | `~/.kiro/hooks/moorai.json` (V3 file: PreToolUse on `*`, UserPromptSubmit) |
| Cline (partial) | The answer `{cancel, errorMessage, contextModification}` is in cline.bot/blog/cline-v3-36-hooks; the rest is from Cline's source (github.com/cline/cline main at c441897, read 2026-10-22), as the docs no longer describe it. Extension (`apps/vscode/src/sdk/hooks-adapter.ts`, `core/hooks/hook-factory.ts`): `hookName` `PreToolUse` / `UserPromptSubmit`, `taskId`, `workspaceRoots`, `preToolUse {toolName, parameters}`, `userPromptSubmit {prompt}`. ClineCore (`sdk/packages/core/src/hooks/subprocess.ts`, `hook-file-hooks.ts`): `hookName` `tool_call` with `tool_call {id, name, input}` plus the same `preToolUse` copy, and `prompt_submit` (run detached). `parameters` is a string record: non-string values are JSON-stringified (`toStringRecord`, `mapParams`). Tool names and input shapes: `sdk/packages/core/src/extensions/tools/constants.ts`, `schemas.ts` | `run_commands`/`execute_command` → Bash per command (string or `{command, args}`), `read_files`/`read_file` → Read per path (`files[]`, `paths`, `file_paths`, `path`), `editor` → Edit when `old_text` or `insert_line`, else Write (`new_text`; the older `command`/`file_text`/`old_str`/`new_str` too), `write_to_file` → Write, `replace_in_file` → MultiEdit (SEARCH/REPLACE blocks + whole diff), `apply_patch` → per-file calls, `use_mcp_tool` → `mcp__s__t`, `fetch_web_content` `requests[]` (`url`, with every other string field as the prompt) / `web_fetch` / `browser_action` → WebFetch, `search_codebase`/`search_files` → Grep per query per path, `list_files`/`list_code_definition_names` → LS per path (the path from `_` for list tools and `path`, `file_path`, `files`, `paths`, `file_paths` for both, like `read_files`; cwd only when no path is given; any non-empty value in any other field of a list or search call, other than `recursive`, the query keys and `file_pattern`, holds the call with `cancel: true`, since a bare relative name is a path too), `skills` → Skill; only the list-valued keys (`files`, `paths`, `file_paths`, `commands`, `requests`, `urls`, `queries`, and a non-object `tool_call.input`) are decoded from JSON, and the raw text is judged as well; a scalar key (`command`, `cmd`, `path`, `url`) is judged exactly as typed; every string field of a decoded object is judged; a structured command `{command, args}` is judged both as the line rebuilt with each element shell-quoted whatever its type and as the plain space-joined line (what a shell would run if the runtime joins the argv), and each element is judged on its own; MCP `arguments` that do not decode to an object are judged as `{arguments}`. Any other tool name (except `ask_question`, `submit_and_exit` and the older `ask_followup_question`, `attempt_completion`, `plan_mode_respond`) is held: `cancel: true` with a reason that asks the agent to get the user's confirmation | deny and ask → `cancel: true` with the reason in `errorMessage` (both runtimes use it as the stop reason and never inject a cancelling hook's `contextModification`, which carries the same text as the fallback); allow → `cancel: false`; exit 0. Both runtimes fail open on a crashed, timed-out or unparseable hook | executable `PreToolUse` and `UserPromptSubmit` scripts in `~/Documents/Cline/Hooks/` (macOS, Linux), the global folder both runtimes read (extension: `disk.ts` `getGlobalHooksDir`; ClineCore: `sdk/packages/shared/src/storage/paths.ts` `resolveHooksConfigSearchPaths`, which also reads `~/.cline/hooks/`); MoorAI's own scripts in `~/.cline/hooks/` are removed so ClineCore does not run them twice; never replaces a user's script |

**Discovery.** `moorai-doctor` checks each host's registration (Antigravity: a `moorai` hook with
`enabled: false` fails; Kiro: a MoorAI hook with `enabled: false` fails; Cline: reads the hook scripts in `~/Documents/Cline/Hooks/`, and a MoorAI script left in `~/.cline/hooks/` fails),
and the posture heartbeat includes them through the same host table. `agy`, `kiro-cli` and `cline` are
agent processes for the AI-CLI parent walk, and `Kiro` / `Kiro Helper` count as an IDE at its install
location; `cli/ai-install-locations.mjs` lists the documented install locations of `agy`
(`~/.local/bin`, `%LOCALAPPDATA%\agy\bin`), `kiro-cli` (Homebrew, `~/.local/bin`) and `cline` (npm). The
hosts' hook and MCP config files are on the skill surface (`antigravity-hooks`, `antigravity-mcp`,
`windsurf-hooks`, `cline-hook`), their transcript stores are agent state (Antigravity `brain/`, Windsurf
`~/.windsurf/transcripts/`, Cline `~/.cline/data/sessions/`), and `moorai-aibom` lists them in
`agentHosts` and reads their MCP configs. The alerts these adapters raise carry no `agentName` until the
console's agent list has these hosts.

**Not proven.** No live run of any of the four hosts; Antigravity's exit-code and failure semantics and its
MCP tool naming; Kiro V3's stdin field names (taken from 2.x and its predecessor); whether the Kiro IDE reads
`~/.kiro/hooks/` (the docs say Kiro CLI V3 does, and describe workspace `.kiro/hooks/` for the IDE), and which of
Kiro's conflicting failure rules a build follows (the hook actions page: any non-zero exit blocks a Pre Tool Use;
the IDE 1.0 page and the CLI 2.x reference: only exit 2 blocks); Cline's payloads and hook folders are read from
its source, not from a running Cline, and the Linux XDG documents folder case is not handled; the
process names the parent walk uses for these hosts (documented binaries, not measured in a process table).

## Clipboard guard (desktop app)

The desktop host stops sensitive text being pasted into a native AI app the organisation has not approved,
and reports it without content. Code: [`clip_guard.rs`](../src-tauri/src/clip_guard.rs) (decisions),
[`clip_guard_policy.rs`](../src-tauri/src/clip_guard_policy.rs) (signed policy),
[`clip_guard_apps.rs`](../src-tauri/src/clip_guard_apps.rs) (AI-app list),
[`clip_guard_mac.rs`](../src-tauri/src/clip_guard_mac.rs) / [`clip_guard_win.rs`](../src-tauri/src/clip_guard_win.rs)
(OS providers), [`clip_guard_run.rs`](../src-tauri/src/clip_guard_run.rs) (loop, console, status),
[`src/clipguard.js`](../src/clipguard.js) (scanner, status line, banner).

**Policy.** `clipboardGuard: { mode: "off" | "alert" | "coach" | "clear", approvedApps: [ids], aiApps: [ids],
detectors: [detector ids] }`. Default and any unknown value: `off`. No environment variable, user file or
webview value is read. Sources, in order:
- **Administrator:** the macOS managed preference `ClipboardGuard` (a dict in the `run.glick.moorai`
  profile), else `clipboardGuard` in the root/admin-owned machine file, read through the ownership checks
  in `admin_config.rs`. When present it decides.
- **Live policy:** `/api/policy`, fetched by the host itself from the console the binding names (an
  administrator's console first, `console_http::target`), every 5 minutes (every minute without an answer).
  It is taken only when its `policySig` envelope verifies: against the root-owned `policy.pub` when present
  (anchored), else the hook's TOFU pin for this tenant (pinned; `~/.moorai/policy-pin.json` and
  `~/.config/moorai/policy-pin.json`, Windows `~\AppData\Roaming\MoorAI\policy-pin.json`, built from the
  home directory only). **The weak case:** with no anchor and no pin there is no key to check, so only the
  presence of an envelope is required (the `actionTrailMode` rule) and trust rests on the TLS fetch from the
  bound console. The envelope format is `cli/hook-core.mjs`'s (`policyCanonical`, `policyDigest`,
  `canonicalJson`), reimplemented in Rust with `ring` and tested against a Node-signed fixture
  (`test/fixtures/clipboard-guard-policy.json`).
- **In memory:** the policy that verified earlier in this process. On an anchored device it must verify
  under the anchor too, like everything else: one taken under the pin, or on the envelope alone, before
  `policy.pub` was installed is dropped (`memory-policy-untrusted`) and the anchor-signed saved copy, or off,
  takes over.
- **Saved copy:** `<MoorAI Host>/clipboard-guard-policy.json` (the host's own state directory), written when
  a live policy verifies. It is a convenience for the next launch only: it is taken only when it verifies
  under a key that is still trusted (the anchor, or a valid pin for this tenant), never on an envelope check.

**Rollback.** The hook's `isPolicyRollback` rule ([`clip_guard_hwm.rs`](../src-tauri/src/clip_guard_hwm.rs)):
strictly older only (the same policy re-fetched is taken), and an `iat` that does not parse on either side is
not compared. Only marks that user-writable state cannot raise refuse anything, and each refusal leaves a
verified policy enforcing or follows an administrator's mark:
- a live policy older than the root-owned `policy-hwm.json` (beside `policy.pub`), the guard's in-process
  mark or the in-memory policy's `iat` (these two only while that policy is in force, and it stays), or the
  signed `iat` of a saved copy that verifies under a trusted key (that copy then enforces) is refused
  (`policy-rollback`);
- a saved copy older than the root-owned mark is refused (`stored-policy-rollback`). That mark is the only
  hard protection against an old signed copy put back in place of the saved one at launch.
The hook's pin `iat` is user-writable, so it is advisory: a policy or copy behind it is still taken and
reported (`policy-behind-pin-mark`, `stored-policy-behind-pin-mark`), and a pin `iat` more than 10 minutes
in the future is ignored, reported (`hwm-future`) and named in the status line. The saved copy carries no
free-standing mark. Only a policy verified under a real key (anchor or pin) moves the guard's in-process
mark; the envelope-only case never sets one.

**User-writable state never turns the guard off.** A pin that does not parse or names another tenant is
ignored; while it is there nothing new is taken without an anchor, and the in-memory policy stays in force.
A live policy that is unsigned, carries a bad signature or is signed for another tenant is refused the same
way. Off happens only when a verified policy says off, or nothing has verified yet: at launch with a refused
pin and no anchor, nothing on disk can be trusted, so the guard stays off. Each refusal raises one
content-free tamper alert per run (`reasonCode: "CLIPBOARD_GUARD_POLICY_REFUSED"`, `clipboardGuard: {
refused: "pin-other-tenant" | "pin-unreadable" | "policy-unsigned" | "policy-untrusted" | "policy-mismatch" |
"policy-malformed" | "policy-rollback" | "policy-behind-pin-mark" | "stored-policy-unverifiable" |
"stored-policy-untrusted" | "stored-policy-rollback" | "stored-policy-behind-pin-mark" |
"memory-policy-untrusted" | "hwm-future" | …, kept: <mode> }`).
**Not a hard guarantee:** the saved copy and the pin are in the user's scope. An agent running as the user
can delete or replace the saved copy (the guard is then off after a restart until the console answers, or,
on a device with no anchor and no pin, until the next live policy), and a replacement must still verify
under a trusted key; an older validly signed copy put back is taken at launch (and reported when the pin's
`iat` is newer) unless a root-owned `policy-hwm.json` is newer. The phase-2 root-owned helper is the real fix; today the root-owned `policy.pub` and
an administrator's setting are the hard parts.

**Modes.** `alert`: a content-free alert. `coach`: the alert and a local notification (macOS: `osascript
display notification`; Windows: a toast) plus an in-app banner, naming the kind of data, the app and why.
`clear`: the alert, the notification, and the clipboard text replaced with
`[MoorAI removed this from the clipboard: it contained <kind>, and <app> is not approved for it.]`.

**What is read, and when.**
- macOS polls `NSPasteboard.changeCount` every 500 ms (the general pasteboard has no change notification) and
  reads the frontmost app's bundle id from `NSWorkspace`. Windows listens for `WM_CLIPBOARDUPDATE`
  (`AddClipboardFormatListener` on a message-only window) and reads `GetForegroundWindow` → process image
  name on a 500 ms timer. Neither carries clipboard content. With the mode `off` nothing is polled but the
  in-memory policy (every 2 s).
- The text is read only when the frontmost app is on the AI-app list (`data/ai-catalog.json` `macBundle`
  and the file names of `win`, plus `aiApps`), is not in `approvedApps`, and either the clipboard changed
  or that app just came to the front. The second trigger catches the "copied earlier, then opened the AI
  app" order. Switching back to the app with the same clipboard reuses the last result and does not read
  again.
- Text only: macOS reads `public.utf8-plain-text` and skips a pasteboard that also holds a file URL;
  Windows reads `CF_UNICODETEXT` and skips one that holds `CF_HDROP`. Images are never read.
- No keystroke capture, no accessibility API, no WinEvent hook.
- The scan runs in the app's webview with the app's own detectors (`secret-*` and `dlp-*` from
  `data/detectors.js`, except `secret-file-upload`; `detectors` narrows the set). The host sends the text
  to the webview as an in-process event and gets back detector ids, threat ids and risk levels. No answer
  within 2 s (the webview still loading) means no action, and the next tick asks again.

**What is sent and stored.** The alert (`stage: "clipboard"`, `tool: "clipboard-guard"`,
`reasonCode: "CLIPBOARD_GUARD"`) carries `threatId`, `riskLevel`, `contentHash` (tenant-keyed, the hook's
`h2:` hash of the whole clipboard text), `clipboardGuard: { mode, action, trigger, app, detectors }` and the
identity fields every alert carries. `action` is `alerted`, `coached`, `cleared` or `clear-failed`; `trigger`
is `clipboard-change` or `app-activation`. The same alert is appended to the app's local `audit.jsonl`.
Never the text, a matched span or its length. One alert per (content, app) per 10 minutes (an in-memory,
per-process keyed digest, so different texts never share an entry even unenrolled). In `clear` mode the
clipboard is cleared and the user notified every time. The test
`no_alert_or_notification_contains_clipboard_text` (`clip_guard.rs`) plants a canary and checks every alert,
notification and notice for it.

**Status line.** "Clipboard guard: off | alert | coach | clear" (`clipguard_status`), with the policy's
trust state and, on macOS, the app's pasteboard-access setting in the tooltip. No content.

**Platforms and limits.**
- macOS and Windows. Linux: off, and "not supported" on the status line when the policy asks for it.
- macOS 15.4 introduced pasteboard privacy: a programmatic read of the general pasteboard that does not
  follow a user paste can alert the user, and `NSPasteboard.accessBehavior` reports the per-app choice
  (default / ask / alwaysAllow / alwaysDeny). `changeCount` and the type list are not content reads, so the
  guard reads content only in the case above.
- The guard works only while the app runs. It does not stop typing the data by hand, a paste into a
  browser tab (the browser extension's job), or a paste through another clipboard manager's history.
- Windows is compile-checked only; the toast needs the installer's AppUserModelID, else it falls back to
  PowerShell's.

## Alert outbox (store-and-forward)

[`cli/alert-outbox.mjs`](../cli/alert-outbox.mjs). An alert the hook could not deliver on its own invocation
is kept until the console acknowledges it.

- **Entries.** One JSON line per alert in `~/.moorai/alert-outbox.jsonl` (0600): `v`, `oid` (32 random hex),
  `seq` (the alert's own, or null when it went out unnumbered), `queuedAt`, `via` (`deferred`: the call got
  no HTTP answer from the console; `direct-failed`: its direct POST got no answer, a 5xx, a 429, a 401 or a
  403; a 400 is never retried), `attempts`, `lastAttemptAt`, `captureStripped`, `rhash` (when stripped) and the
  `alert` as stamped. The dedup key is `seq` when it is a positive integer, else `oid`: a key already queued
  is not queued again. State (counts, lease, retry time, drop counters, last delivered seq) is in
  `alert-outbox-state.json` (0600); the file is the truth, and a size that does not match the state resyncs it.
- **Content-free on disk.** The capture-tier fields (`matchText`, `filePath`, `cmdShape`, `argText`) are
  removed before an entry is written; `rhash` = `recordRhash` of the alert minus `seq` and `chainHead`, so the
  chain link stays checkable.
- **Delivery.** The detached worker (`moorai-hook.mjs alertpost`) takes a 60 s lease (single-flight, renewed
  per batch), sends in ascending `seq` with unnumbered entries after them by `queuedAt`, at most 64 alerts and
  256 KiB per `POST /api/alerts/batch`, each alert with `delivery: { v: 1, via: "outbox", oid, attempt,
  queuedAt, captureStripped, rhash? }`. Per-entry results `stored` / `duplicate` remove the entry; `rejected`
  removes it and counts it (`dropped.rejected`, with its seq range). A result counts only when its index names
  an entry of the batch and it names that entry's `oid` or `seq`. A 404 or 405, or a 2xx whose body has no
  `results` array, falls back to one `POST /api/alerts` per entry (2xx stored, 400 rejected, anything else
  kept), remembered for 24 h. No answer, a 5xx, a 429, a 401, a 403, or a batch only partly acknowledged
  keeps what is left (attempts + 1) and retries it after `backoffDelay(rejects)` (1, 2, 4, then 5 minutes).
  A retry waits; a first attempt does not: inside the retry window, and after a failed batch in the same
  run, the worker still sends every entry never attempted, and a hook call that queued one may claim the
  lease for it. A whole batch taken ends the window. Delivery is at-least-once: a lost 2xx is re-sent and the
  console de-duplicates it. The hook appends after the decision is written and spawns the worker when it
  takes the lease; one `statSync` per exit otherwise.
- **The back-off file has no say.** The worker never reads `hook-console-backoff.json`. Its own `retryAt` and
  lease are honoured only when no further ahead than this module writes (5 minutes, 60 s), so a planted
  value cannot hold the queue until it ages out (`test/alert-outbox.test.mjs`, `test/alert-outbox-hook.test.mjs`).
- **Bounds.** 5,000 entries, 4 MiB, 16 KiB per entry, 30 days. Full: the oldest go down to 90% of each bound
  (`dropped.full`). Older than 30 days at send time: dropped (`dropped.aged`). Over 16 KiB after stripping:
  never queued (`dropped.oversize`). A malformed line: removed and counted in `dropped.full`. The counters are
  cumulative; the newest 8 merged dropped seq ranges are kept. New drops go to the console once as "Alert
  outbox: entries dropped before delivery" (Medium, `OUTBOX_DROPPED`, `contentHash alert-outbox:dropped:<n>`,
  `outboxDropped: { full, aged, rejected, oversize, ranges }`) and to the local action audit.
- **Heartbeat.** The posture body carries `alertOutbox: { v, state (empty | pending | retrying | full),
  pending, bytes, oldestQueuedAt, lastDeliveredSeq, lastDeliveredAt, dropped, droppedRanges }`, times rounded
  down to the hour.
- **Device bundle** (`moorai-outbox export --out <file.zip> [--include-trail]`, [`cli/moorai-outbox.mjs`](../cli/moorai-outbox.mjs)).
  A stored zip: `manifest.json` (`schema: "moorai.device-bundle/1"`, tenant, identity as on the wire, seq
  summary with the chain head at export, the drop counters, each file's SHA-256), `manifest.mac` (base64
  HMAC-SHA256 keyed with the install token over `moorai-device-bundle|v1|<sha256 hex of manifest.json>`),
  `VERIFY.txt` (the OpenSSL commands), `alerts.jsonl` (each entry's alert with `delivery.via: "bundle"`) and,
  with `--include-trail`, `actions.jsonl`. Token-authenticated, the same assurance as a live POST: the device
  holds no signing key. Export copies; it removes nothing. Golden fixture: `test/fixtures/device-bundle/golden.json`.
- **Trust.** Agent-writable, at the level of the alert counter (`cli/alert-seq.mjs`): an agent can delete or
  edit a queued entry, and a deleted numbered entry shows at the console as a seq gap. `moorai-guard` posts
  carry `X-Install-Token` and queue their failures here unnumbered.

## Origin of an action

[`cli/origin.mjs`](../cli/origin.mjs). `origin: { v: 1, kind, status, basis, thread, hostPrompt?,
parentBinding?, subagentType?, exception?, intent?, resolves? }` on hook alerts (stamped in `post()` before
the seq, so the chain covers it) and on allow-trail records. `ORIGIN_BASES` fixes the kind and status of
each basis; the console pins the same literal and downgrades a stronger claim.

- **Bases.** `bypass-mode` (agent, observed: Claude Code `permission_mode` `bypassPermissions`, `hostPrompt:
  not-shown`), `headless` (agent, observed: server mode), `no-moorai-ask` (agent, inferred: Claude Code main
  thread otherwise, `hostPrompt: unknown`), `host-no-thread-id` (agent, inferred: every shim host, `thread:
  not-distinguishable`), `subagent-id` (delegated, observed: `agent_id` in the payload; `parentBinding` exact
  when PostToolUse(Agent) bound the child, inferred when the only pending spawn of its type matched, none
  otherwise; `subagentType` per `cli/subagent-type.mjs`), `policy-exception` (override, observed: a console
  exception excused the finding), `local-exception` (override, inferred: who wrote the root-owned store is not
  provable), `break-glass` and `jit-elevation` (override, observed), `guard-tty` (override, observed) and
  `guard-flag` (override, inferred), `post-after-ask` and `failure-after-ask` (approved-ask, inferred),
  `no-execution-before-stop`, `ask-pending`, `ask-not-trackable` and `unrecognised` (unknown, not
  established; the agent sends neither `ask-pending` nor `unrecognised`, which the console uses). Precedence:
  override, then delegated, then agent. `intent: "mismatch"` only when `INTENT_MISMATCH` fired.
- **Ask outcomes** ([`cli/ask-outcome.mjs`](../cli/ask-outcome.mjs)). Claude Code only, tracked tools only
  (WebFetch, WebSearch, Bash, PowerShell, Agent, Task, `mcp__*`): an ask is remembered in
  `~/.moorai/ask-pending.json` (ids keyed with the device-local key, 256 at most, 24 h) with its seq range,
  and resolved by PostToolUse (`post-after-ask`) or PostToolUseFailure (`failure-after-ask`) with the same
  `tool_use_id`, one-shot, or by Stop / SubagentStop (`no-execution-before-stop`, at most 16 records, the rest
  as the summary's `asksUnresolved`). Each is an Info alert with `reasonCode: ASK_OUTCOME` and
  `origin.resolves: { seqFrom, seqTo }`. Any other ask posts one `ask-not-trackable` record at once. The
  PostToolUse matchers are not widened (a hook process per edit). No call fingerprint is used to infer an
  approval on a shim host.
- **Finding alerts** are stamped before the call's verdict is known: on a call MoorAI then asked about, a
  finding still reads its thread basis (`no-moorai-ask` on the Claude Code main thread). The ask-outcome
  record for its seq range records the ask.
- **destClass.** Egress alerts with `EGRESS_RULE` (over the rule's parsed host), `ENDPOINT_NOT_ALLOWED` (the
  hosts the endpoint check found) and `SECRET_EGRESS` (hosts `extractHosts` finds in the same text) carry
  `destClass: "throwaway-host" | "other"` from `data/throwaway-hosts.js`; with no parsed host the field is
  left out.

## Privileged helper install path (`moorai-guardd`)

[`guardd/packaging/`](../guardd/packaging/), [`cli/guardd-install.mjs`](../cli/guardd-install.mjs),
[`cli/moorai-helper.mjs`](../cli/moorai-helper.mjs). The installers for the helper of
[`docs/proposals/guardd-contract.md`](proposals/guardd-contract.md) §4.3, and the agent-side check of whether it
is installed and healthy.

- **Linux.** `guardd/packaging/linux/install.sh <abs binary>` (root) installs `/usr/sbin/moorai-guardd` (0755),
  `moorai-guardd.service` and `moorai-guardd.socket` under `/usr/lib/systemd/system` (0644) and `/etc/moorai`
  (root 0755), tightens an existing `secret.json` to root 0600 and `config.json` to root 0644, then runs
  `systemctl daemon-reload`, `enable --now` on both units and a restart, and waits up to 10 s for both to be
  active. The socket unit listens on `/run/moorai/hook.sock` (root, 0666, directory 0755). The service runs as
  root with no arguments and no `Environment=`, under `ProtectSystem=strict`, `ProtectHome=read-only`,
  `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `RestrictNamespaces`, `MemoryDenyWriteExecute`,
  `StateDirectory=moorai` (0700), `RuntimeDirectory=moorai` (0755, preserved across restarts because the socket
  lives there), `UMask=0077`, `ReadWritePaths=-/etc/moorai` (the helper removes `enrollSecret` after a bound
  registration) and `CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN`. That
  set is proposed for quarantine and is not yet reviewed against a Linux platform layer. Exit 3 means the files
  are installed but systemd is not running (a container). `uninstall.sh` removes the binary and units and keeps
  `/etc/moorai` and `/var/lib/moorai`. The units go under `/usr/lib/systemd/system`, not the `/lib/systemd/system`
  of contract §4.3, so a `.deb` does not ship files under an aliased `/lib`; the agent-side check accepts both.
- **macOS.** `guardd/packaging/macos/install.sh <abs binary>` (root) installs
  `/Library/PrivilegedHelperTools/moorai-guardd` (root:wheel 0755), the LaunchDaemon plist in
  `/Library/LaunchDaemons` (root:wheel 0644; `RunAtLoad`, `KeepAlive`, `ThrottleInterval` 10, no `UserName`, no
  `EnvironmentVariables`, one program argument), `/Library/Logs/MoorAI` (root:admin 0750, log 0640) and
  `/etc/moorai`, then `launchctl bootout` / `bootstrap` / `enable` / `kickstart -k` and waits for `state =
  running`. `build-pkg.sh <abs binary> <out.pkg> [version]` builds an installer package whose payload is what
  `install.sh` stages, with a `preinstall` that boots a running daemon out and a `postinstall` that sets owners
  and modes and bootstraps it. The package is unsigned (signing needs a Developer ID Installer identity).
- **Windows.** `guardd/packaging/windows/install.ps1 -Binary <exe>` (elevated) copies the binary to
  `<Program Files>\MoorAI\moorai-guardd.exe` (SYSTEM and Administrators full, Users read and execute) and
  sets up `<ProgramData>\MoorAI`, with `<ProgramData>` read from HKLM ProfileList (never `%ProgramData%`).
  Before it changes anything (the service included) it refuses a pre-existing `<ProgramData>\MoorAI`, or any
  entry under it, that is a reparse point (junction or symbolic link), is owned by anyone but SYSTEM or
  Administrators, has no DACL, or grants anyone else a right to add, change, delete or re-permission entries
  (inherit-only entries included); it names the entry and leaves its ACLs alone, and the administrator removes
  the directory and reruns. A missing directory is created with its DACL in place. Each DACL is then written
  whole, so no earlier or extra entry survives: `<ProgramData>\MoorAI` owner SYSTEM,
  `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120089;;;BU)` (Users read the folder itself, never inherited),
  then every ACL under it is reset to inherit that; `state` owner SYSTEM, `D:P(A;OICI;FA;;;SY)` with its
  contents reset to inherit it; `run` owner SYSTEM, SYSTEM and Administrators full and Users read, inherited by
  `device.pub`; an existing `secret.json` owner SYSTEM, `D:P(A;;FA;;;SY)(A;;FA;;;BA)`, with a warning to issue
  a new install token and enrolment secret when it was readable by anyone else before the run. Each existing
  public admin input the agent reads as the signed-in user (`config.json`, `policy.pub`, `breakglass.pub`,
  `offline-posture`, `policy-hwm.json`, `policy-lkg.json`, `exceptions.json`, `decoys.json`) gets an explicit
  Users read; one MDM writes later needs that grant from MDM, because the folder no longer hands Users read
  down. It then reads the descriptors back and stops unless they match. The checks are in
  `guardd/packaging/windows/acl-checks.ps1`. It registers `MoorAIGuard` (auto start, LocalSystem, restart after
  1 s, 5 s, then every 60 s), sets the service DACL
  `D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)` (only SYSTEM and
  Administrators can start, stop, reconfigure or re-permission it; any signed-in user can query it), starts it
  and waits for Running. `-DryRun` prints the plan. `moorai-guardd.exe` does not yet call the Service Control
  Manager's dispatcher (`guardd/src/main.rs`), so Windows reports a start timeout for it until that is added.
  The script is checked by reading its text (`test/guardd-install-scripts.test.mjs`); it has not been run on
  Windows here, and the test that runs the ACL checks on real descriptors runs on Windows only.
- **Every installer** refuses a relative or missing binary path and a binary whose `--build-info` does not say
  `test-injection=false` (contract §10.2, §11.2), and none writes the content of `config.json` or `secret.json`
  (the administrator's or MDM's, §4.1; the Windows script sets their ACLs as above). `MOORAI_GUARDD_STAGE=<dir>` (Linux and macOS scripts) lays the files out under
  `<dir>` without chown or a service manager and prints the skipped steps as `plan:` lines; the helper itself
  still reads no environment.
- **Is it installed and healthy.** `helperInstallStatus()` returns a content-free object:
  `{state, binary, service, endpoint, devicePub, hello, helperVersion?}`. `endpoint` and `devicePub` come from
  the contract §3.6 ownership walk, `checkOwnedPath` in `cli/guardd-client.mjs` (the same function behind the
  hook-side `verifyEndpointOwnership`, uid 0 only): from `/` to the file, no symlinks, every directory owned by root and not
  writable by group or others (group-writable only for gid 0, or gid 1 on macOS for `/private/var/run`), the
  endpoint a socket owned by root, `device.pub` a regular root-owned file that is not group- or world-writable
  and holds an ed25519 SPKI key. Only then does it send one `hello` (default budget 250 ms; the status command
  uses 1000 ms) and check that the reply names that key's id and that the proof verifies. States:
  `not-installed`, `partial`, `installed-not-running`, `running-unprobed`, `healthy`, `not-ready` (no console
  binding yet), `unreachable`, `untrusted` (a failed ownership check, an invalid `device.pub`, a wrong key id or
  a bad proof), `unverified` (no `device.pub`). On Windows the service state comes from `sc.exe query
  MoorAIGuard` by absolute path and the endpoint check is the proof alone (a pipe has no owner walk). No path,
  tenant, device id or key id is in the result. `moorai-helper status [--json]` prints it; it takes no path or
  root option. The posture heartbeat does not carry it yet: that is one insertion in `cli/moorai-hook.mjs`
  (field `helperInstall`).
- **What runs today.** The helper's per-OS platform layer (`guardd/src/platform/*`: process table, boot and
  machine ids, suspend, network block) is still a stub that panics, so on every OS the installed service
  exits at start (on macOS and Linux after it has created its state directory and device key; on Windows
  before, while resolving ProgramData) and its service manager's restart policy applies. The install path, the unit and plist contents and the
  agent-side check are tested; a running helper is not. Proven by tests with temp roots (`test/guardd-install-scripts.test.mjs`,
  `test/guardd-install-status.test.mjs`) and, on Debian 12 in Docker, by installing the packages as root and
  running `moorai-helper status` as an unprivileged user against a stand-in helper that root started at
  `/run/moorai/hook.sock` (`healthy`), one signing with another key (`untrusted`, `bad-proof`) and one a
  non-root user started at a path that user owned (`untrusted`, endpoint refused before any connect). The
  PowerShell script has not been run or parsed by PowerShell; its ACL lines are checked as text only.
- **Not demonstrated.** That a non-admin user cannot delete the alert chain or read the device key is the goal
  of this helper and is not shown on any OS yet, because no real `moorai-guardd` has run.
- **CI.** `.github/workflows/guardd-install.yml` installs a release build as root and waits for the service.
  Its gate, `scripts/guardd-ci-ready.mjs <linux|macos|windows>`, says ready only when that OS's install script
  exists, no `todo!()` or `unimplemented!()` is left in the code compiled for it (its `guardd/src/platform/<os>`
  directory and shared code not `cfg`-gated to another OS), and on Windows `main.rs` has a service control
  dispatcher. Today it reports not ready on all three, so the install and agent-side steps skip with a notice
  and the agent-side step is still a placeholder (`test/guardd-ci-ready.test.mjs`).

## Linux agent package

[`scripts/build-linux-package.mjs`](../scripts/build-linux-package.mjs), [`packaging/linux/`](../packaging/linux/).
`node scripts/build-linux-package.mjs [--out dist/linux] [--guardd <binary> --guardd-arch amd64|arm64]` writes:

- **`moorai_<version>_all.deb`.** The files `package.json` `files` ships (tracked files only), plus
  `package.json`, `README.md` and `LICENSE`, under `/usr/lib/moorai`; one `/usr/bin` link per `package.json`
  `bin` plus `moorai-install-hooks`; the helpers `moorai-node` (runs a script with the first Node 18 or newer it
  finds: PATH, then `/usr/bin/node`, then `/usr/local/bin/node`) and `moorai-install-hooks` (runs
  `moorai-hook install` for the calling user from the package's copy); and two systemd user units,
  `moorai-hooks.service` (oneshot at login that registers the hooks) and `moorai-serve.service` (the loopback
  engine sidecar, restart on failure). `Recommends: nodejs (>= 18)`, not `Depends`, because fleets often install
  Node from a tarball or a version manager; the postinst warns when no Node 18 is found. The postinst creates
  `/etc/moorai` (0755) and enables no unit; the prerm takes the user units out of the global enablement. Every
  entry is uid 0 / gid 0, every timestamp is `SOURCE_DATE_EPOCH` (else the last commit's time), gzip carries no
  timestamp, and `md5sums` is included, so a rebuild of the same commit gives the same bytes.
- **`moorai-<version>-linux.tar.gz`.** The same tree under `root/`, with `install.sh` (into `/` as root, or into
  `MOORAI_ROOT`) and `uninstall.sh`.
- **`moorai.spec`.** An rpmbuild spec (`noarch`, `Recommends: nodejs >= 18`) that packages the tarball with the
  same post-install message. Not built here: no `rpmbuild` was available.
- **`moorai-guardd_<v>_<arch>.deb`** (with `--guardd`). The files `guardd/packaging/linux/install.sh` stages, so
  the package and the script cannot differ; the binary must pass the same `--build-info` check. The postinst
  enforces the `/etc/moorai` modes and runs `systemctl enable --now` only when `/run/systemd/system` exists;
  prerm disables on removal; purge deletes `/var/lib/moorai`.
- **Hooks block only with management evidence.** As on every OS, an unenrolled device coaches; it enforces once
  enrolled or when the administrator writes `fail-closed` to the root-owned `/etc/moorai/offline-posture`.
- **Measured.** `test/linux-package.test.mjs` reads the archives back with the system `tar`, installs the
  tarball into a temp root, runs the installed hook installer and runs the installed hook on a credential-file
  Read (`deny` under the fail-closed posture) and a source-file Read (allowed). In Docker (images already on the
  build machine, arm64): on Debian 12 with Node 22, `dpkg -i` of both packages, `moorai-install-hooks` as a
  non-root user, a credential-file Read denied under the root-owned fail-closed posture and a source-file Read
  allowed, then `dpkg --purge` / `dpkg -r`; on Ubuntu 24.04 without Node, `dpkg -i` succeeds with the warning,
  `moorai-install-hooks` refuses with a clear message, and the tarball installs into `/` and uninstalls. Not run:
  systemd (no container ran it), RHEL or any rpm, Ubuntu 22.04, amd64, Wayland or X11 (there is no Linux
  clipboard guard or desktop app).
## Live conformance tier (agent hosts, MCP clients, AI Servers)

An opt-in tier (`npm run test:live`; full description in [`HOST_CONFORMANCE.md`](HOST_CONFORMANCE.md))
drives the installed software against MoorAI and writes one signed, content-free report per target and
version into `docs/conformance/`.

- **Agent hosts** (`scripts/host-conformance.mjs`): each case is one headless turn of the real host binary
  in a throwaway HOME, MoorAI installed by its own installer and enrolled to a loopback stand-in console
  serving a signed policy. The model is a scripted Anthropic Messages endpoint on loopback
  (`scripts/conformance/scripted-anthropic.mjs`), so the host runs its real hook pipeline, permission layer
  and tools while no provider is called and no key is read; on macOS the host runs under `sandbox-exec`
  (localhost-only egress, no writes to the real `~/.claude.json`, `~/.claude`, `~/.cursor`). Claude Code
  cases: `shell-allow`, `shell-deny` (PreToolUse deny, command never runs, Blocked alert), `prompt-block`
  (UserPromptSubmit block under `promptScan: "all"` + `promptScanAction: "block"`; the prompt never reaches
  the model), `mcp-allow` and `mcp-deny` (Claude Code as an MCP client through the stdio guard; the denied
  call never reaches the server). Cursor: the MCP client handshake through the stdio guard and the bundle
  markers run; an agent turn needs a Cursor account (`auth-required`), and the installed build refuses its
  local-model `--base-url` flag. Desktop MCP clients (Claude Desktop, VS Code, Cursor desktop) are recorded
  as installed or not, with version, and never launched (`no-headless-mode`).
- **AI Servers** (`scripts/server-conformance.mjs`): a real `moorai-model-proxy --mode enforce` in front of
  a real Ollama, with an upstream recorder between them, through Ollama's OpenAI-compatible
  (`/v1/chat/completions`, JSON and SSE), Anthropic-compatible (`/v1/messages`) and native (`/api/chat`)
  APIs: allowed requests forwarded, a credential refused before the model (the recorder confirms the model
  never saw it), and a real model tool call to a policy-blocked function withheld; a credential on the
  Responses API path is refused before the model (`pass`), and a proxy that forwards it unparsed is
  recorded as `gap`. The MCP gateway case runs the official MCP TypeScript SDK as
  client and server through a real gateway process (benign forwarded, denied refused and never received).
  The official provider SDKs and the linux/amd64 server image are recorded as present or not; the tier
  installs and pulls nothing.
- **Report** (`cli/conformance-report.mjs`): types `moorai.host-conformance/v1` and
  `moorai.server-conformance/v1`; enums, booleans, integers, version strings and the alert's category /
  risk / decision / reason code only, behind an allowlist that verification re-applies; ed25519 over the
  SHA-256 of the canonical JSON; `--key` / `MOORAI_CONFORMANCE_KEY` for a stable pinnable key, otherwise an
  ephemeral key and `signature.ephemeral: true`. Statuses `pass`, `fail`, `skip`, `inconclusive` (the real
  model did not produce what the case needs), `gap` (a documented limit, observed).
- **Recorded run, 2026-10-21, macOS arm64:** Claude Code 2.1.295 5/5 pass (sandboxed); cursor-agent
  2026.05.27-fe9a6e2 MCP handshake and bundle markers pass, agent turn skipped (`auth-required`); Claude
  Desktop 2.37337.1 installed, not run; Codex, Copilot, Gemini, Droid, VS Code and Cursor desktop not
  installed; model proxy with Ollama 0.40.3 / `llama3.2:latest` 11 pass, 1 gap (Responses, agent 1.27, before
  the proxy parsed the Responses API); MCP gateway with the MCP TypeScript SDK 1.32.1 2/2 pass; provider SDKs
  not installed; amd64 image not present. Re-run 2026-10-22 on agent 1.28.0 (model proxy only, ephemeral
  signing key, not committed): 12/12 pass, the Responses credential case refused before the model.
- **Blind spots:** agent turns in Cursor, Codex, Copilot, Gemini and Droid; desktop clients as live MCP
  clients; a paid model (Claude Code's turns are scripted); the official OpenAI, Anthropic and Google SDKs
  (not installed; the cases send each API's documented request shape over HTTP); a real remote MCP server
  in the gateway case; the amd64 image; Windows and Linux; no nightly schedule (the tier is not in CI).

## Signed MCP server and skill catalogue (`cli/mcp-catalogue.mjs`)

- **Format.** `data/mcp-catalogue.js`: `{ catalogue: "moorai-mcp-catalogue", v: 1, seq, issuedAt, expiresAt,
  publisher, entries[], sig }`. An entry is `{ kind: mcp-server|skill, ecosystem: npm|pypi|docker|remote|skill,
  name, status: listed|do-not-install, source: official-registry|reference-servers|vendor|community|advisory,
  repository?, license?, registryName?, advisories?, reputation: {score, band, reasons}, versions: [{ version,
  verdict: no-findings|caution|review|do-not-install|not-scanned, reasons?, sha256?, treeSha256?, scannedAt?,
  engine? }] }`, versions newest first. There is no "safe" or "clean" verdict.
- **Signature.** ed25519 over `moorai-mcp-catalogue|v1|<seq>|<issuedAt>|<sha256 of canonicalJson(everything but
  sig)>`; `sig = { v: 1, alg: "ed25519", keyId (base64 SPKI DER), sig }`. `verifyCatalogue` returns `ok`,
  `no-anchor`, `unsigned`, `malformed`, `untrusted` or `expired`. `expiresAt` is mandatory and must be later
  than `issuedAt` (a catalogue without it is `malformed`); it is covered by the digest, so it cannot be
  extended without breaking the signature. The generator sets it (`--expires-days`, default 90).
- **Trust.** Keys from the signed policy's top-level `mcpCatalogue.publicKeys`, `MOORAI_CATALOGUE_PUBKEY`,
  root-owned `/etc/moorai/catalogue.pub`, and `data/mcp-catalogue-keys.js` (empty: the publisher key is
  generated and published by the owner). No key means the catalogue is not used (unlike a policy, which is
  "unanchored"): nothing depends on it, so accepting an unverifiable one buys nothing.
- **Fetch and cache.** Policy `mcpCatalogue: { url, publicKeys, enabled }`. The MCP stdio guard and the HTTP
  gateway pass it to `assessServer`, which fetches an https (or loopback http) URL with one bare GET, at most
  once in 24 h, `redirect: "error"`, 5 s timeout, 16 MB cap; `MOORAI_OFFLINE=1` serves the cache. The verified
  file is cached in `~/.moorai/mcp-catalogue.json` and re-verified on every read (it is in the user's writable
  state). Nothing in that file decides freshness on its own: the cache is fresh only when its `url` matches,
  its `fetchedAt` is at most 5 minutes in the future and under 24 h old. `~/.moorai/mcp-catalogue.seq.json` holds the highest `seq` accepted per publisher keyId (raised on
  every accepted fetch and every verified read). A cached catalogue below it reads `rollback-refused` (no
  catalogue, so the next refresh fetches), and a fetched catalogue below it or below the verified cache is
  refused (`refresh: "rollback-refused"`). The mark is in the same writable directory: a local user who
  rewrites both files can hold an older signed catalogue until the next refresh, at most 24 h.
  A catalogue past its signed `expiresAt` is refused at the device clock, cached or fetched: `readCatalogue`
  reads `expired` with no catalogue (so every refresh fetches), a fetched expired catalogue is not cached
  (`refresh: "expired"`), reputation evidence names `catalogue-expired`, and `moorai-mcp-catalogue verify` and
  `status` report `expired`. An old signed catalogue therefore cannot be replayed past its expiry for its
  positive verdicts. Its deny side does not fail open: the cached copy that last verified (and is not below
  the seq mark) keeps its `do-not-install` entries and its negative per-version verdicts (`do-not-install`,
  `review`, `caution`; an advisory entry is kept through either), returned as `expiredDeny`, and MCP
  reputation still applies them, with `catalogue-expired` as the only catalogue evidence (no
  `catalogue-verified`, no `catalogue-scanned-no-findings`). Withholding a refresh therefore cannot clear a
  denylist; until a current catalogue arrives the device has its no-catalogue verdicts plus those deny
  signals.
- **Tool-stage re-score.** The stdio guard and the gateway pass the same `mcpCatalogue` to `addToolSignals`,
  so a re-score after `tools/list` keeps the catalogue verdict (before, it read the cache with no policy
  keys, and a server whose only anchor was the policy dropped `catalogue-do-not-install` on re-score).
  Tested end to end through the stdio guard (`test/mcp-catalogue-wiring.test.mjs`). The gateway's servers are
  remote: `catalogueSignals` matches npm and PyPI only, so for the gateway the pass-through changes evidence,
  not the score, and no test observes it.
- **Reputation.** `catalogueSignals`: a name-level `do-not-install` adds `catalogue-do-not-install` to any
  version; a version's `do-not-install` / `review` / `caution` adds `catalogue-do-not-install` (70) /
  `catalogue-review` (20) / `catalogue-caution` (5); `no-findings`, `not-scanned`, an unlisted version and an
  unresolved version are evidence only (`catalogue-scanned-no-findings`, `catalogue-listed-not-scanned`,
  `catalogue-other-version`, `catalogue-listed`). Evidence also names `catalogue-verified`, or
  `catalogue-<status>` for a cached catalogue that does not verify. A catalogue can only add risk.
- **Hook path.** `hookReputation(label, { catalogue })` takes the top-level `mcpCatalogue` object, and
  `cli/moorai-hook.mjs` passes the policy's `mcpCatalogue`, so a cached catalogue signed by a key the policy
  anchors verifies in the hook too (tested end to end, `test/mcp-catalogue-hook.test.mjs`). The hook never
  fetches the catalogue; it reads the cached copy only. With no `mcpCatalogue` in the policy the hook uses a
  cached catalogue verified by the environment, root-owned or built-in keys.
- **Skills.** `skillTreeDigest(dir)` (sha256 over sorted `relative path NUL sha256(file)` rows, symlinks and
  `.git` / `node_modules` skipped) and `catalogueSkillStatus(cat, name, digest)` →
  `listed-match | digest-mismatch | listed | do-not-install | unknown`. Not yet wired into the AIBOM.
- **Generator.** `scripts/mcp-catalogue-build.mjs --source --key --out [--seq] [--issued] [--expires-days 90]
  [--scan <npm|pypi>:<name>@<version>=<dir>] [--format moorai|mcp-registry] [--include-not-scanned]`. `--scan`
  runs `scanPackageFiles` + `packageHeuristics` over a local copy: any block tier → `do-not-install`, justify →
  `review`, notify → `caution`, none → `no-findings`. Reputation fields come from `nameFindings`,
  `classifyMcpName`, the name status and the newest version's verdict, scored by `data/mcp-reputation.js`.
  `--format mcp-registry` writes a map of v0.1 registry routes (`/v0.1/servers`,
  `/v0.1/servers/<name>/versions/latest|<version>`) for listed npm/PyPI versions whose verdict is
  `no-findings` or `caution`, with `_meta["dev.moorai/catalogue"]`; serving it needs a router with CORS.
- **CLI.** `moorai-mcp-catalogue verify <file> [--pubkey]` (exit 0 only when the signature verifies) and
  `status` (the cached copy); JSON, counts only.

## Installed IDE-extension scanning (`cli/ide-extensions.mjs`)

- **Roots.** `~/.vscode`, `~/.vscode-insiders`, `~/.vscode-server`, `~/.vscode-oss` and `~/.vscodium`
  (VSCodium), `~/.cursor`, `~/.windsurf`, `~/.kiro` (`/extensions`); JetBrains plugins under
  `~/Library/Application Support/JetBrains/<product>/plugins` (macOS), `%APPDATA%\JetBrains\<product>\plugins`
  (Windows), `~/.local/share/JetBrains/<product>` (Linux).
- **Identity.** VS Code family: `publisher.name` and `version` from the extension's `package.json` (folder name
  as fallback); install source from `extensions.json` `metadata.source`. JetBrains: `<id>` (or `<name>`) and
  `<version>` from `META-INF/plugin.xml` inside the plugin's `lib/*.jar` (or a single-jar plugin), read with
  the model scanner's zip reader; folder name as fallback.
- **Checks (VS Code family).** `ide-ext-known-malicious` (critical): exact id + version in
  `data/ide-extension-advisories.js` (OSV MAL-2025-191157 to 191170, CVE-2025-8217).
  `ide-ext-invisible-code` (high): a `.js`/`.cjs`/`.mjs` file with a run of >= 16 code points in
  U+FE00-FE0F or U+E0000-E01EF. `ide-ext-typosquat` (medium): Damerau-Levenshtein distance <= 2 (ids of 12+
  characters, else 1) from `data/popular-ide-extensions.js`. `ide-ext-publisher-impersonation` (medium): a
  listed extension name of 8+ characters under another publisher (an editor's own publisher is exempt inside
  that editor: `anysphere` in Cursor, measured on a real install where Cursor ships `anysphere.remote-ssh`).
  `ide-ext-sideloaded` (low): install source `vsix`. AI classification from `data/ai-catalog.json` keywords.
- **Bounds.** 2,000 extensions per root, 400 script files and depth 10 per extension, 8 MB per file, 48 MB
  per extension, 512 MB per run; a skipped file sets `truncated`.
- **Output.** `{ scanned, ai, flagged, truncated, extensions: [{ editor, id, version, ai, source?, codes,
  risk, advisories? }] }`. No path, file name or file content. Report-only: no alert is posted and nothing is
  blocked. Surfaces: `moorai-ide-extensions [--format json|md] [--flagged]` and the AIBOM's `ideExtensionScan`
  with `summary.ideExtensionsScanned` / `ideExtensionsFlagged`.

## Browser Guard store build and managed force-install

- **Config precedence** (`browser-ext/config.js`): `chrome.storage.managed` (admin policy, schema
  `managed-schema.json`: `serverUrl`, `installToken`, `mode` coach|block, `reportEnabled`, `lockSettings`)
  over `chrome.storage.sync` (options page). Mistyped values are ignored. `lockSettings` makes the options
  page read-only.
- **Reporting path.** The content script builds the alerts and sends them with `chrome.runtime.sendMessage`;
  `background.js` (MV3 service worker) accepts messages from its own extension id only, at most 32 alerts,
  rebuilds each from the allow-list `threatId, category, riskLevel, stage, tool, ts, contentHash, host,
  source` with type and length checks, and POSTs each to `<serverUrl>/api/alerts` with `X-Install-Token`
  only when reporting is on, the URL is https (or loopback http) and `chrome.permissions.contains` says the
  extension holds that origin. Before this change the content script posted directly, which Chrome treats as
  a request from the page's origin.
- **Packaging.** `scripts/browser-ext-package.mjs` zips exactly the files the manifest and options page
  reference (fixed timestamp, sorted, deflate); `--console-origin https://…` adds that origin to the packaged
  manifest's `host_permissions` for a self-hosted build. `scripts/browser-ext-icons.mjs` draws the icons.
- **Policy.** `scripts/browser-ext-policy.mjs --id` renders `browser-ext/policy/*.tmpl`:
  `ExtensionInstallForcelist` (`<id>;<update URL>`, store URLs
  `https://clients2.google.com/service/update2/crx` and
  `https://edge.microsoft.com/extensionwebstorebase/v1/crx`, or `--update-url`) and the managed settings under
  `3rdparty\extensions\<id>\policy` (Windows), `<domain>.extensions.<id>` (macOS, `com.apple.ManagedClient.preferences`
  payload), `3rdparty.extensions.<id>` (Linux), plus an ADMX/ADML pair for the managed settings.
- **Owner steps.** Developer accounts, store submission and review, hosting `store/PRIVACY.md`, and rendering
  the templates with the assigned ids. The Edge managed-storage locations follow the Chromium layout; Microsoft
  Learn documents only the force-list.

## Agent identity inputs

The console derives each agent's identity, `agentId = "agt-" + HMAC(tenantKey, "agent:" + agentName + "|" + anchor)`,
from fields the agent already sends: `agentName` (the `cli/agent-names.mjs` vocabulary) and the device, actor or
workload anchor. The agent sends no new identity field. The records added below name the agent the same way: the
credential exposure read log keys each read by the hook's agent host (`claude-code`, an adapter's host, or
`unknown`), and each usage bucket carries `agentName` (`claude-code` for transcript usage and for proxy requests
that name a Claude Code session, else the proxy's own `model-proxy`). Pinned by `test/agent-identity-inputs.test.mjs`.

## Credential exposure map (`cli/credential-exposure.mjs`)

A content-free map of which credential **classes** an agent on the device can reach, which ones an agent read,
and to which destination class that session sent data next. It rides the daily posture heartbeat
(`POST /api/agent-posture`) as the top-level field `credentialExposure`:

```json
{ "v": 1, "coverage": "heuristic", "window": { "from": "…T11:00:00Z", "to": "…T11:00:00Z" },
  "items": [ { "kind": "aws", "locationClass": "home-config", "scope": "home", "reachable": true, "keyHash": null,
               "envNames": [], "envOtherCount": 0, "prodLike": true,
               "byHost": { "claude-code": { "reads": 1, "lastReadAt": "…T10:00:00Z", "outsideProjectReads": 0, "sentTo": ["throwaway-host"] } } } ],
  "truncated": false }
```

- **Kinds:** `aws`, `ssh`, `kube`, `npm`, `git`, `docker`, `gcloud`, `azure`, `env`, `gh`, `netrc`, `pgpass`,
  `mcp-config`, `ai-key`. Location classes `home-config`, `project-file`, `system`, `env`, `mcp-config`; scopes
  `home`, `project`, `outside-project`, `system`, `env`.
- **Reachable** is a stat plus `access(R_OK)` on a fixed list of home-config files per kind (for example
  `~/.aws/credentials`, `~/.ssh/id_*` without `.pub`, `~/.kube/config`, `~/.config/gh/hosts.yml`, `~/.netrc`), the
  session cwd's top-level `.env*` (templates excluded), `.npmrc`, `.netrc`, `.pgpass` and `.git-credentials`, and
  the MCP client configs (`~/.claude.json`, `~/.cursor/mcp.json`, Windsurf, Gemini CLI, Claude Desktop, and the
  project's `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`).
- **Read only for a derived bit:** section headers and `name:` lines of `~/.aws/config`, `~/.aws/credentials` and
  `~/.kube/config`, and the file names under `~/.config/gcloud/configurations`, for `prodLike` (a name matching
  `/prod/i`); the key names under each MCP server's `env` and `headers`, to tell whether one is credential-shaped.
  Names and values stay on the device. AI keys at rest come from the existing keys-at-rest scan
  (`cli/aibom-keys.mjs`), one item per keyed `keyHash` (`h2:`).
- **Env names:** only the allow-list in `data/credential-env-names.js` is sent by name; any other name ending in
  TOKEN, SECRET, PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY or CREDENTIALS is counted in `envOtherCount`.
- **Reads:** at PreToolUse, a Read path, a shell command or an MCP call's string arguments that name a credential
  location (#55's kind table plus `gh`, `netrc`, `pgpass`) are logged by kind, scope class, agent host, the
  session's keyed hash and time in `~/.moorai/credential-exposure.jsonl` (0600; at most 2000 entries after
  compaction, 8 days). A call MoorAI then denied still counts as a read attempt. Scope: under the session cwd is
  `project`; a dot entry at the top of home is `home`; `/etc`, `/var`, `/usr` and the like are `system`; anything
  else, including another project under home, is `outside-project`.
- **Sent to:** the destination classes (`throwaway-host`, `ai-provider`, `private-range`, `other`) of every
  egress target the same session names within 10 minutes after a read. Hosts are classed on the device and never
  stored.
- **Bounds and size:** at most 64 items (`truncated: true` past that), 16 env names per item, 6 hosts per item.
  The console refuses a posture body over 16384 bytes, so the worker drops items from the lowest priority (no
  reads, not prod-like, no outside-project reads) until the body is at most 15360 bytes, and drops the field when
  nothing fits. Measured in throwaway homes: 957 bytes of heartbeat without the field (one host), 1299 bytes with
  four hosts, and 10441 bytes for a 58-item map (every kind, 40 AI keys at rest), 11762 bytes in total.
- **Scope:** heuristic. Credentials in other locations, in the OS keychain or behind a credential helper are not
  seen; a shell command that builds a path at run time is not resolved.

## Token usage and usage budgets

Token counts (metadata only) go to `POST /api/token-usage` as cumulative hourly buckets
(`cli/token-usage.mjs`):

```json
{ "v": 1, "user": "…", "device": "…", "platform": "darwin", "source": "model-proxy", "instance": "mp-7f3a9c2e",
  "buckets": [ { "hour": "2026-10-21T10:00:00Z", "agentName": "claude-code", "provider": "anthropic", "model": "claude-opus-5-5",
                 "projectKey": null, "requests": 14, "requestsNoUsage": 1, "in": 120345, "out": 8012, "cacheRead": 90000, "cacheWrite": 4000 } ] }
```

- **Cumulative:** a bucket is the running total for (hour, agentName, provider, model, projectKey) within one
  instance, so the console's MAX upsert never double-counts a resend. At most 500 buckets and 60000 bytes per
  body. A 404 or 405 (a console without the route) pauses posting for 24 hours; other failures are resent with
  the running total.
- **Field mapping** (from each provider's documentation): Anthropic `input_tokens`, `output_tokens`,
  `cache_read_input_tokens`, `cache_creation_input_tokens` ("The token counts shown in the usage field of the
  message_delta event are cumulative", so a stream's largest value per field is its total); OpenAI
  `prompt_tokens − prompt_tokens_details.cached_tokens` → `in`, `completion_tokens` → `out`, `cached_tokens` →
  `cacheRead`; Gemini `promptTokenCount − cachedContentTokenCount` → `in`, `candidatesTokenCount +
  thoughtsTokenCount` → `out`; Ollama `prompt_eval_count` → `in`, `eval_count` → `out` (final `done: true`
  object). `in` never includes cached input.
- **Model proxy** (`model-proxy/token-usage.mjs`): usage is read from the JSON body, SSE events or NDJSON lines the
  proxy already parses; an event's text is parsed only when it can hold a usage field. Instance `mp-<8 hex>`,
  random per process start; buckets are flushed every 5 minutes and at shutdown; enrolled proxies only. The proxy
  does not add `stream_options.include_usage`: an OpenAI stream without it, an error answer or a response cut
  short counts in `requestsNoUsage`. `projectKey` is null.
- **Claude Code transcripts** (`cli/transcript-usage.mjs`): a detached hook worker, at most once an hour on an
  enrolled device and only from Claude Code's own hook, reads `~/.claude/projects/**/*.jsonl` (and
  `$CLAUDE_CONFIG_DIR/projects`) from a saved offset in 1 MiB chunks, up to 64 MiB a run, files touched in the last
  35 days. Each assistant message is one request by `message.id`, counted at its field-wise maximum usage. Claude
  Code writes one line per content block; measured on one developer machine (2026-10-21, 1034 transcripts touched
  in the last 3 days, counts only): of 31801 messages written as more than one line, input and cache counts never
  differed between lines, `output_tokens` differed in 7371, never fell from one line to the next, and the last
  line always held the largest; the first line alone gave 38% of the output tokens. A later line adds only its
  growth to the first line's bucket, in the same run or a later one (the last 64 ids per file are kept, the last
  4 with the usage counted so far). Over the 2000 most recent transcripts on that machine (4.65 GB) the reader's
  totals matched an independent per-message maximum count except for 533 messages whose id reappeared after
  more than 64 other messages in the same file; those are counted again (about 0.3% of requests and output
  tokens). `<synthetic>` messages are skipped. Source
  `transcript`, instance `tr-<8 hex>` fixed, `projectKey` is the keyed hash of the message's `cwd`. The state file
  (`~/.moorai/token-usage-transcript.json`, 0600) keys files by a digest of their path. Codex and other hosts'
  transcripts are not read.
- **Budgets** (`model-proxy/budget.mjs`): the signed policy's `usageBudgets` and the console-computed
  `budgetState`. In enforce mode, a model request while a budget with `action: "block"` is `exceeded` is answered
  HTTP 429 `{ "error": { "type": "budget_exceeded", "budgetId": "…", "message": "…" } }` with
  `x-should-retry: false`, is not forwarded, and raises one `BUDGET_EXCEEDED` alert (Medium, `budgetId`) per budget
  and period from each proxy process (kept in memory: a restarted proxy alerts again, and after 257 budget-period
  pairs in one process no further budget alert is raised). Report mode forwards the request and the alert says `notify`. A policy that is not the verified
  signed policy, no state, a state older than 1 hour or dated in the future, an ended period, `warn`/`ok`, or
  `action: "alert"` never blocks, whatever failMode says. Hooks never block on budget.

## Approval receipts (device side)

[`cli/approval-receipts.mjs`](../cli/approval-receipts.mjs), [`cli/receipt-step.mjs`](../cli/receipt-step.mjs),
[`cli/canonical-json.mjs`](../cli/canonical-json.mjs), wired into [`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs)
(Claude Code `PreToolUse`); full specification, hub verification steps and trust rule in
[`approval-receipts.md`](approval-receipts.md). Tests: `test/approval-receipts.test.mjs`,
`test/approval-receipts-hook.test.mjs`; vectors `test/fixtures/approval-receipts/vectors.json`
(`node scripts/gen-receipt-vectors.mjs`).

- **Policy key.** Top-level `approvalReceipts: { v: 1, audiences: [{ aud, mcpServer, tools? }], ttlSec }`, at most
  16 audiences; `mcpServer` is the server segment of `mcp__<server>__<tool>`, matched exactly; `tools` are anchored
  globs over the bare tool name; `ttlSec` defaults to 60 and is capped at 120. Read from the verified policy only.
  Absent: nothing changes.
- **Receipt.** Payload `{ v: 1, typ: "moorai.receipt", aud, tool (bare name), argsSha256, device (keyed actor),
  session (keyed session hash), nonce, iat, exp (≤ 120 s), basis, approvalId?, approver?, keyId, keySource }`;
  ed25519 over `"moorai-receipt|v1|" + canonicalJson(payload)`; wire `base64url(payload).base64url(sig)` under
  the input's `_moorai.receipt`. `argsSha256` is SHA-256 of the canonical JSON of the parsed arguments without
  `_moorai`. keyId is the first 32 hex of SHA-256 over the raw 32-byte public key.
- **Delivery.** On a final allow of an MCP call to a listed server / tool, `updatedInput` = the complete input +
  `_moorai`, with no `permissionDecision` (measured: Claude Code 2.1.295 delivers it to the MCP server, also past
  `additionalProperties: false`). Device receipts (keySource `device`, basis `allowed`) are signed with the device
  key `~/.moorai/agency-ed25519.key`; the console's receipt from an approval grant's `receipt` field is attached
  unchanged on the grant's first use. Never on an ask or a deny. The console serves `receipt` only to a fetch signed
  by a bound `moorai-guardd` key. Once the helper is installed and bound (macOS), the hook reads its policy through
  the helper (`cli/guardd-policy.mjs`) and the receipt reaches it. Without the helper, the hook's fetch uses the
  token only and an approved call carries a device receipt. No receipt for `click`, `type_text`, `press_key`,
  `upload_file`, `download_file`, `push_file`.
- **Reserved key.** A model-supplied `_moorai` is stripped before any check; the stripped input goes on with an
  allow or an ask. On a host that cannot rewrite input (the agent-hook shim, Cursor, an aliased tool name) a call
  carrying it is denied (`RECEIPT_KEY_INJECTED`) and no receipt is attached.
- **Approvals.** For a covered MCP call the `APPROVAL_REQUESTED` alert carries `approval.receiptArgsDigest`
  (`contentHash(argsSha256)`) and `approval.receiptRequest { aud, tool, argsSha256 }` (raw hash: the console mints
  from it and strips the raw hash before alert storage and SIEM; the alert chain and the outbox `rhash` cover its
  `aud` and `tool` but not `argsSha256`, `cli/alert-seq.mjs` `alertChainView`), and its `actionHash` =
  `contentHash("approval\0" + canonicalJson({ argsSha256, aud, tool }))`.
- **Trust.** Advisory: any process of the agent's OS user can sign a device receipt. A hub pins keys with their
  keySource and skips its queue only for a key pinned as `console` (basis `approved`, an `approvalId`) or `helper`,
  with integer-only arguments; the payload's own keySource is never trusted alone.
- **Hub tools.** `HUB_RECEIPT_TOOLS` (19 tools) is the example list; `click`, `type_text`, `press_key`,
  `upload_file`, `download_file` and `push_file` are never listed (`HUB_EXCLUDED_TOOLS`).

## Just-in-time approval routing (device side)

[`cli/approval-routing.mjs`](../cli/approval-routing.mjs), wired into [`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs)
(Claude Code `PreToolUse`); full description in [`APPROVAL_ROUTING.md`](APPROVAL_ROUTING.md). Tests:
`test/approval-routing.test.mjs`, `test/approval-routing-hook.test.mjs`.

- **Policy key.** Top-level `approvalRouting: { v: 1, rules: [{ id, label, match, holds, group, timeoutSec,
  onTimeout: "deny", grant: "once" | "ttl", grantTtlSec }] }`, at most 64 rules; `match` keys `threatId`,
  `mcpTool`, `egressRuleId`, `reasonCode` (`EGRESS_RULE`, `OT_PROTOCOL_CLIENT`, `MCP_TOOL_ARGS`), `otOp`,
  `functionTool`, every key set must match, and every threat id and egress rule id on the call must be covered.
  The hook supplies no function name and no OT operation, and its only reason code is `EGRESS_RULE`, so a rule
  that needs `functionTool`, `otOp`, `OT_PROTOCOL_CLIENT` or `MCP_TOOL_ARGS` never matches in the hook. A
  malformed rule is dropped with a stderr warning naming its id or index. An older agent ignores the key.
- **Hold and request.** A `deny` or `ask` that matches a rule with that verdict in `holds` is answered with a deny
  at once. The device generates `apr_` + 26 Crockford base32 characters and posts one `APPROVAL_REQUESTED` alert
  (`approval{ v: 1, requestId, ruleId, surface: "hook", verdict, actionHash, requestedAt, expiresAt, destClass? }`; `actionHash` is
  the keyed per-tenant hash of the tool name and the key-sorted input). Pending requests: `~/.moorai/approvals.json`
  (0600, at most 256), deduped per rule and action.
- **Decision.** The policy fetch names the device's keyed actor (`actor=h2:…`); grants come only from the
  signed policy's `approvals`, verified under the anchor or the pinned key (unsigned, altered, foreign-key,
  locally cached or first-contact bodies give no grant). `once` is consumed on use, `ttl` holds until
  `validUntil`; `APPROVAL_USED` on first use, `APPROVAL_EXPIRED` once for a pending request past its expiry.
  An egress grant is honoured at the egress check only; a detector block on the same call still stands.
- **Not held:** fail-closed denies, policy tamper, containment, decoys, behaviour signals, profile drift, session
  kills and unenrolled (coached) calls. Capability-tag rules, session-risk escalation and MXC wrapping still apply
  to an approved call.
- **Limits.** Decision latency is at least the 60-second policy cache; `moorai-guard` and the MCP guard do not
  name the actor, so a cache they wrote carries no approvals. A `once` grant can be replayed for the identical
  action until its signed `validUntil`. The model proxy, MCP gateway and egress proxy do not hold verdicts for
  approval.

## Weakening oversight (#84)

[`cli/oversight-signals.mjs`](../cli/oversight-signals.mjs) (Write / Edit / MultiEdit, judged on the file before
and after), [`cli/oversight-shell.mjs`](../cli/oversight-shell.mjs) (Bash / PowerShell),
[`cli/oversight-vocab.mjs`](../cli/oversight-vocab.mjs) (the key, identifier and path words),
[`cli/oversight-surfaces.mjs`](../cli/oversight-surfaces.mjs) (policy), [`cli/oversight-disclosure.mjs`](../cli/oversight-disclosure.mjs)
(Stop / SubagentStop), wired into [`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs) through `decideOversight`
([`cli/hook-core.mjs`](../cli/hook-core.mjs)). Tests: `test/oversight-signals.test.mjs`,
`test/oversight-disclosure.test.mjs`, `test/oversight-hook.test.mjs`, `test/oversight-hardening.test.mjs`,
`test/oversight-paths.test.mjs` (symlinks, `cd`, moves; real symlinks in a temp dir) (fixtures in
`test/oversight-fixtures.mjs`).

- **What it catches.** An agent's own write or command that weakens the project's monitoring, alerting, audit
  logging or safety tests. Signals (local only, on the session-ledger row as `ov`; never on an alert):
  suppression flag set or made a requirement (`no_notify = True`, `alerting.enabled: false`, a raise on the flag,
  `amtool silence add`); recipient list or on-call / pager route emptied or deleted; monitor, alerting, audit-log
  or telemetry wiring removed or commented out (identifiers with an oversight stem that the write drops and does
  not replace), a monitor module deleted or moved away (see Where a path lands), a monitoring CRD deleted,
  a monitoring component stopped, scaled to zero, uninstalled or removed; a test that guards oversight deleted,
  skipped or changed to assert absence; a key or persistent env var (`setx`, `launchctl setenv`, `kubectl set
  env`, `heroku config:set`, `fly secrets set`, `SetEnvironmentVariable`) that turns monitoring, audit logging or
  tracing off, or a monitoring sink emptied; a policy-protected path or key touched.
- **Path handling.** Docs, fixtures and examples are never judged (only protected surfaces are). Test files
  (`cli/mcp-package/paths.mjs` `notRuntimeReason` "test-code", plus `conftest.py`, `*_test.go`, `.env.test`, …)
  get only the test signal. Repository tooling (`.github`, `.gitlab`, …) and UI component files (`.tsx`, `.vue`,
  `.html`, …) are not judged. A new file (nothing before) gets only the protected-surface check. The current file
  is read up to 1 MiB; an Edit whose `old_string` is not in it, or of a file over 1 MiB, is judged on the snippets.
- **Where a path lands.** The class is read from the path as written (relative to cwd) and from the target's
  real path relative to cwd's real path (`oversight-surfaces.mjs` `realOf`: the real path, or for a path that
  does not exist yet its nearest existing ancestor's plus the rest; absolute when outside cwd). When the two
  differ both are judged, so the stricter wins: a doc- or fixture-named symlink to runtime code gets the runtime
  signals, a code-named symlink to a doc keeps them. The same applies to shell redirect, `sed -i` / `perl -pi`,
  `tee`, `yq -i` and `Set-Content` targets. In a command, the working directory is tracked across segments:
  `cd`, `chdir`, `pushd` / `popd`, `Set-Location` / `sl`, `Push-Location` / `Pop-Location` with a literal target
  move the paths of the later segments, per subshell scope (`shell-parse.js` `seg.scope`: a `cd` inside `( … )`,
  `$( … )` or backticks stays inside it; in POSIX a `cd` first in a pipeline or in a background job moves
  nothing). A `cd` carries only over `&&` (and `|`, and the end of a `$( … )` back into its command): once a
  scope has run a `cd`, a `;`, newline, `||`, `&`, `(`, `{` or `}` after one of its segments makes that scope's
  directory unknown, and a `)` makes the enclosing scopes' unknown too (the parser drops the separator after it);
  a later `cd` to an absolute path makes it known again. A segment is a `cd` only when the `cd` word is the
  first command word (after env assignments, `command` or `builtin`); a `cd` behind any other wrapper (`sudo`,
  `env`, `time`, `nohup`, `exec`, `xargs` …), an `eval` whose arguments start with a `cd` word, and in POSIX a
  `cd` that ends a pipeline (zsh, bash `lastpipe`) make the directory unknown. Every sink (deleted and moved
  paths, redirect, `sed -i` / `perl -pi`, `tee`, `yq -i`, `Set-Content` targets) is judged and added to the
  protected-path check both as resolved against the tracked directory and as written relative to the project.
  A `cd` with no target or to one that is not literal (`$`, a glob, `{ }`, a subshell, a leading `~`, `-`), or a
  `popd` with nothing pushed, or an `eval` / `source` / `.` / `iex` / `Invoke-Expression` (which re-parse text in this shell), also
  makes the directory unknown, and a move of oversight is judged a removal when any segment of the command can
  make a link (`ln`, `mklink`, `New-Item -ItemType SymbolicLink`, `cp`/`rsync` link or archive flags, archive
  extraction, interpreter `-c`/`-e`/`-Command` one-liners) or runs in the background; judging a relative path under it raises
  `analysis-incomplete` (a later segment that judges no path, `cd "$DIR" && git status` or `cd x; npm test`,
  stays clean). A move (`mv`, `git mv`, `move`,
  `Move-Item`, `Rename-Item`; `-t DIR`, `-tDIR`, `--target-directory[=]DIR`, `-T`, `-S SUFFIX`, PowerShell
  `-Destination` / `-NewName` / `-Path` read; a directory destination is a trailing slash, several sources or an
  existing directory) of a monitor or a guarding test is a rename only when the destination is literal, keeps an
  oversight word, resolves inside the project, keeps the source's class (code or test) and does not end in
  `.bak`, `.disabled`, `.old`, `.orig` or `~`, both lexically and through its real path (`realOf`, relative to
  the project's real path: a destination under a symlink to a directory outside the project or to `docs/` is
  judged where it leads), and for both the resolved source / destination pair and the as-written pair.
  Anything else (`/tmp`, `../`, `/dev/null`, `docs/`, `$TRASH`, `~/…`) is a removal.
- **Bounds (fail closed).** Every pattern is linear: the `sed` / `perl` `s///` and `/re/d` parsers are scanners
  (a backslash takes the next character, the first unescaped delimiter ends a field, a backslash or line
  terminator is never a delimiter) and the quoted-prose scanner remembers each position per quote kind; the
  tests time 50 KB pathological inputs under 50 ms in a child process. A command over 256 KiB, a `sed` / `perl`
  script over 64 KiB, a command check past 250 ms, a command the shell parser throws on (`cli/oversight-shell.mjs`
  passes `splitShell` its `heredocs` list, so a heredoc parses), a write whose before or after is over 1 MiB, a
  Write over an existing runtime / test file the hook does not read (over 1 MiB), and, when `protectedPaths` are
  declared or `memoryFiles` is `ask` / `block` / #84's action (`opts.strictWrites`), a write position whose
  target is not literal (with only the built-in memory-file protection on it raises `write-target-unknown`
  instead, decided like `memory-file`: notify, an alert and no prompt, unless #84 is configured; not counted by
  the Stop disclosure check. Unless its visible payload, an `echo` / `printf` / heredoc / `tee` / `Set-Content`
  text or `sed -i` / `perl -pi` edits, would raise a signal against any built-in path class (`PAYLOAD_PROBES`:
  YAML, JSON, TOML, env, Python and JS config or code, and a test): then it is `analysis-incomplete` whatever is
  watched) (`$`, `$( … )`, a glob or brace, a
  `~user`; a redirect, a copy / install / download / `dd` / `git restore` / `patch` destination, an `mv`
  destination, a non-literal source copied or moved into a directory, `patch` with no file operand) raise the
  local signal `analysis-incomplete` instead of being cut and judged. `decideOversight` asks on it even when
  `threatPolicy["84"]` is `notify`, turns `kill` into `block` when it is the only signal, and honours `disabled`.
  An incomplete-only call is not an oversight change for the Stop disclosure check.
- **Precision.** Measured on `test/oversight-fixtures.mjs`: every positive (the two report cases as 6 edits and 7
  commands, plus 10 other shapes) fires its signal, and 0 of 42 benign near-misses fire (adding an alert,
  renaming or adding a recipient, tuning a threshold, a dead unrelated feature flag removed, README / CHANGELOG /
  docs / comment / fixture mentions, re-enabling notifications, vendor telemetry opt-outs, `.env.test`, a UI
  `<Alert>`, `notify_on_success: false`, `disable_web_page_preview`, an inline env prefix for one test run,
  `export`, a rename via `git mv`, reads). The set is hand-built; no field corpus has been run. The path tests
  also hold clean a same-directory rename, a move into another runtime monitoring directory (also through an
  in-project symlink), `cd` into a directory followed by `&&` and an unrelated edit or removal, and a doc
  symlink to a doc. A `cd` followed by `;` and a path-judging command (`cd build; rm -rf dist`) asks by design.
- **Threat id.** 84. Not 81: 81 (read and unknown) and 82 (write) are the OT protocol client ids that shipped
  in 1.28.0, which live agents send and console policies may set; `threatPolicy["81"]` never changes this verdict.
- **Default and action.** `APPROVAL_THREATS` includes 84, so `threatActionFor` resolves it to `justify` (ask);
  `threatPolicy["84"]` / `tierPolicy` override it (`notify`, `block`, `kill`, `disabled`). An `approvalRouting`
  rule with `match.threatId: [84]` holds it. Server mode settles the ask like any other (headless deny).
- **Alert.** Category `Weakening oversight`, reason code `OVERSIGHT_WEAKENED`, threat 84, stage `output` (a
  write) or `prompt` (a command). No signal name, path, key or value. A sub-agent's alert carries
  `parentSession` (`SESSION_TAG`; Claude Code gives a sub-agent its parent's `session_id`, so it equals
  `session`) and an origin with `thread: "subagent"`; the verdict is the same as the main agent's.
- **Built-in memory files.** With no policy, the agent's persistent-instruction files are watched
  (`PERSISTENT_INSTRUCTION_KINDS`, data/skill-surface.js: `CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules/`,
  `AGENTS.md` / `AGENT.md` / `AGENTS.override.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/`, `.windsurfrules`,
  Windsurf and Cline rules, `.github/copilot-instructions.md`, `.github/instructions/`, Kiro steering, Claude Code's
  `.claude/projects/<p>/memory/`, OpenClaw `SOUL.md` / `MEMORY.md` / `memory/`), and git's run-later files
  (`cli/oversight-surfaces.mjs` `gitRunLaterPath`: a hook under `.git/hooks/`, a bare `*.git/hooks/`, or a
  worktree's or submodule's gitdir; `.git/config`, `config.worktree`, `~/.gitconfig`, `~/.config/git/config`,
  `/etc/gitconfig`; the `.git` file, since a `.git` file naming another gitdir makes git read that gitdir's config,
  whose `core.fsmonitor` runs on status, measured on 2.39.5 and 2.54.0; a gitdir's `commondir` — `.git/commondir`,
  `.git/worktrees/<w>/commondir`, `.git/modules/<m>/commondir` — since git reads the config and runs the hooks of the
  directory it names, `core.fsmonitor` and `post-index-change` measured to run on 2.39.5 and 2.54.0; a worktree's
  `.git/worktrees/<w>/gitdir`, since `git worktree repair` writes a `.git` file where it points, measured on both;
  `objects/info/alternates`, `info/` files, `.git/gitdir` and `.git/modules/<m>/gitdir` were measured to run nothing
  and are not watched). A Write / Edit of one, an MCP filesystem
  write tool's path (below), or a shell command that writes, moves or deletes one, raises the signal `memory-file`
  under #84, and so does `git config` setting a key outside `GIT_SAFE_CONFIG` (`cli/oversight-shell-writes.mjs`
  `gitConfigWrite`: `git config [--global | --system | --local | --worktree | -f file] [--add | --replace-all]
  <key> <value>`, git 2.46+ `git config set`, `--edit` / `edit`, `--rename-section`; `--get*`, `--list`, `get`,
  `list`, a lone key, `--unset` and `unset` are reads or removals and stay clean; `-f <file>` is also a write to
  that file). It reads the command line as git does (`GIT_CONFIG` in `cli/oversight-shell-options.mjs`, the options
  of `git config --get -h` and of `git config set -h` / `unset -h` / `rename-section -h` / `remove-section -h` /
  `edit -h` on 2.54.0): a subcommand only as the first word (`git config --global set k v` is the key `set`),
  options only up to the first other word or `--` (measured, 2.39.5 and 2.54.0: `git config core.pager --get-x`,
  `alias.x --get`, `core.fsmonitor --list` / `-l` / `--unset` each set the key to that word), a long option by a
  unique prefix (`--fil=f` writes `f`, `--glob` the global file, 2.54.0's `--comm` takes the next word as its
  comment), `--no-global` / `--no-file` putting the scope back, and short letters clustered (`-zf <file>`,
  `-f<file>`). An option it does not have, an ambiguous one or one missing its value (git refuses each) leaves the
  write unknown. With `-f <file>`, `--unset`, `--unset-all`, `unset`, `--remove-section`, `remove-section`,
  `--rename-section` and `rename-section` rewrite `<file>` (measured, 2.39.5 and 2.54.0) and are a write to it, judged
  by the path checks; a removal arms nothing, and without `-f` it stays clean. Shell writes (`cli/oversight-shell-writes.mjs`): a redirect (a bare `> path` with no
  command word too, read from the raw text, quote-aware, heredoc bodies skipped, since the parser keeps no segment
  for it), `tee` (a word after `--` too), `sed -i` / `--in-place` / BSD `-I`, `perl -pi`, `yq -i`, `Set-Content`, the
  destination of `cp` / `install` / `rsync` (a local one; `-t`, `--target-directory`, `-T` for cp; into a directory,
  each source under its own name, under its whole path with `cp --parents`) and `mv`, `curl -o` / `--output` / `-O`
  (the URL's name; both under `--output-dir`), `curl -D` / `-c` / `--trace` / `--trace-ascii` / `--stderr` /
  `--libcurl` / `--etag-save` / `--hsts` / `--alt-svc`, `wget -O` / `--output-document`, its log `-o` / `-a`,
  `--save-cookies` / `--rejected-log` / `--hsts-file`, and without `-O` the URL's own name (`%`-escapes but `%2F`
  decoded, as wget 1.21.3 does; `index.html` or `--default-page` for a bare host) under `-P`; a URL with no scheme
  is read as http, as both tools do; `dd of=`, `git checkout [<tree-ish>] [--] <path>` (without `--` every word
  but an `@{…}` revision is judged as a path, since git decides at run time), `git restore <path>` (`-C dir`
  applied) and `patch <file>` / `patch -o <file>` / `patch -r <rejects>`. Options are read as each tool reads them
  (`cli/oversight-shell-options.mjs`, the union of the tools' own `--help` lists: GNU coreutils 9.1 / 9.7, sed
  4.9, patch 2.7.6, git 2.39.5 / 2.47.3, Wget 1.21.3 / 1.25.0, curl 7.88.1 / 8.7.1 / 8.14.1, rsync 3.4.4, and the
  macOS BSD letters): a unique prefix of a long option resolves to it (`data/shell-parse.js` `longName`, as GNU
  `getopt_long`, git and curl 7.x accept; curl 8.7.1 and rsync 3.4.4 reject abbreviations, and rsync's are read as
  full names only), `--no-<option>` for curl, wget, rsync and git. A write position is unknown (write-target-unknown
  / analysis-incomplete, as for a non-literal target) when the tool picks the name at run time — wget `-r` / `-m` /
  `-i` / `-p` / `-x` / `--protocol-directories` / `--content-disposition` / `--trust-server-names` / `-e` /
  `--config` with no `-O`, curl `-O` with `-J`, curl `-K`, curl `-o` naming a `#N` URL glob without `-g`, a curl
  config picked by `CURL_HOME` / `XDG_CONFIG_HOME` / `HOME` set on the command (unless `-q` / `--disable` is its
  first argument) or a wgetrc picked by `WGETRC` / `SYSTEM_WGETRC` / `HOME` (unless `--no-config`), git
  `--work-tree` / `GIT_WORK_TREE`, and `--git-dir` / `GIT_DIR`, which pick a repository whose own config may set
  `core.worktree`, and `GIT_INDEX_FILE`, the index git writes (resolved against the top of the work tree and
  created when absent), for `git checkout`, `restore`, `rm` and `mv` alike (`cli/oversight-shell-writes.mjs`
  `gitInvocation`, the one reader of git's global options) — measured with git 2.39.5, 2.47.3 and 2.54.0: a
  `core.worktree` given by `-c`, `--config-env`, `GIT_CONFIG_COUNT`, `GIT_CONFIG`, `GIT_CONFIG_GLOBAL` or
  `GIT_CONFIG_SYSTEM` is ignored, and `GIT_COMMON_DIR`, `GIT_CEILING_DIRECTORIES` and
  `GIT_DISCOVERY_ACROSS_FILESYSTEM` leave every path where it is, so they change nothing — a git command line
  whose command cannot be told: git's global options are read from git 2.54.0 `git help git` (and 2.39.5's
  `--super-prefix`), those that take the next word (`-C`, `-c`, `--git-dir`, `--work-tree`, `--namespace`,
  `--config-env`, `--attr-source`, `--super-prefix`) skipping it (`cli/oversight-shell-options.mjs` `GIT_GLOBAL`);
  any other word starting with `-` before the subcommand, a non-literal word there (the search goes on, so `git
  $OPTS rm f` is still judged as a git rm), `--exec-path=<dir>` or `GIT_EXEC_PATH` (git then runs non-builtins from
  that directory, measured), or a command outside `GIT_BUILTINS` (the words in `git --list-cmds=builtins` on each of
  2.39.5, 2.47.3 and 2.54.0, as spelt: an alias, a script such as `git svn` or `git send-email`, which an `alias.*`
  shadows where it is not installed, measured, an external `git-<name>` such as `git lfs`, a typo, or a builtin in
  another case, which 2.39.5 runs as `alias.<name>` and is still judged as the builtin) is unknown, and so is a
  config key set by `-c`, `--config-env` or `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` outside `GIT_SAFE_CONFIG`
  (keys that run nothing and write nowhere: `user.*`, `color.*`, `advice.*`, `log.*`, `core.quotepath`,
  `core.autocrlf`, `init.defaultBranch`, `safe.directory`, `protocol.version`, `http.sslVerify` …; any other key,
  `alias.*` included, may run a command: `-c core.fsmonitor=…` runs on status, checkout and `rm --cached`, and `-c
  core.pager` / `pager.log` on a terminal, measured on 2.39.5 and 2.54.0), `GIT_CONFIG_PARAMETERS`, and a config file
  picked by `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `HOME` or `XDG_CONFIG_HOME` (its `core.fsmonitor` runs,
  measured; `GIT_CONFIG` is not read), `GIT_OPAQUE_ENV` (`GIT_COMMON_DIR`, whose hooks run; `GIT_TEMPLATE_DIR` and
  `init` / `init-db` / `clone --template`, whose hooks are copied in and run by the clone; `GIT_OBJECT_DIRECTORY`,
  which `git add` writes; `GIT_REDIRECT_STD*`), `clone -c` / `--config` with a key outside `GIT_SAFE_CONFIG`
  (`core.hooksPath` there runs hooks during the clone) — clone's and init's options read as git reads them
  (`GIT_CLONE` / `GIT_INIT`, from `git clone -h` / `git init -h` on 2.54.0): anywhere before `--`, a long one by a
  unique prefix (`--templ=d`, `--temp d`, `--conf k=v`, `--co k=v`, init `--t d`), `-c` inside a cluster (`-qc
  k=v`, `-qck=v`), all measured to copy or run the hooks on 2.39.5 and 2.54.0, and an option they do not have or an
  ambiguous one (`clone --t`: template or tags) opaque —, a program for the other end of a transfer
  (`GIT_PACK_PROGRAM` and `clone -u` / `--upload-pack`: `fetch`, `pull`, `ls-remote` and `fetch-pack --upload-pack`,
  `ls-remote --exec` (a hidden alias of `--upload-pack`), `push` and `send-pack --receive-pack` / `--exec`, `archive
  --exec`; a command value measured to run with a local repository on 2.39.5 and 2.54.0) — each command's options read
  with its own table (`GIT_FETCH`, `GIT_PULL`, `GIT_LS_REMOTE`, `GIT_PUSH`, `GIT_SEND_PACK`, `GIT_ARCHIVE`, from `git
  <cmd> -h` on 2.54.0 plus the options git's source marks hidden: `ls-remote --exec` / `-h` / `--heads`, `fetch
  --submodule-prefix` / `--recurse-submodules-default`, `pull --summary`, `clone --naked`), as git reads them: anywhere,
  a long one by a unique prefix, a valued option taking the next word even when it is `--` (`push -o -- --receive-pack=<cmd>`,
  `fetch -o -- --upload-pack=<cmd>`, `archive -o -- --exec=<cmd> --remote=<repo>` measured to run on 2.39.5 and
  2.54.0), an optional value only from the rest of its cluster (`pull -So --upload-pack=<cmd>` runs), and an option
  the command does not have or an ambiguous one opaque; `archive` also as its first pass reads `-o` / `--output`,
  `--remote` and `--exec` (no prefix, every other option kept without its value: `--prefix --exec=<cmd>` runs);
  `fetch-pack`, which reads its options by hand with `=` values only and refuses `--`, by any long option before `--`
  that is a prefix of one —, and `GIT_EXEC_ENV` set with a value outside `GIT_HARMLESS_PROGRAMS` (empty,
  `cat`, `less`, `more`, `true`, `:`; for `GIT_EDITOR`, `EDITOR`, `VISUAL` and `GIT_SEQUENCE_EDITOR` also `vi`,
  `vim`, `nano`, `code --wait`): `GIT_PAGER` / `PAGER` (log, diff on a terminal), `GIT_EDITOR` / `EDITOR`
  (commit), `GIT_SSH_COMMAND` / `GIT_SSH` / `GIT_PROXY_COMMAND` (fetch) and `GIT_EXTERNAL_DIFF` (diff) measured to
  run on 2.39.5 and 2.54.0, none of them for checkout, restore, rm, mv or status; `VISUAL`,
  `GIT_SEQUENCE_EDITOR`, `GIT_ASKPASS` and `SSH_ASKPASS` by git's documentation. A `GIT_TRACE*` naming an
  absolute path is a write to that file (written by status for `GIT_TRACE`, `_PERFORMANCE`, `_SETUP`, `_REFS`,
  `GIT_TRACE2`, `_EVENT`, `_PERF`, measured; a relative word is ignored with a warning; `1` / `2` / `true` / `0`
  go to a stream), and so is one naming `~` or `~/…`, resolved under the home directory (bash 5.3.15 / 5.2.15 /
  3.2.57, zsh 5.9 and dash expand it after `=` in an assignment word, measured), while `~user/…` is unknown; a `GIT_TRACE2*` path may be a directory and is also unknown — `--pathspec-from-file` — and when a write tool (cp, mv, install, rsync, curl, wget, tee,
  sed, patch, git checkout / restore) is given a long option that is ambiguous or that it does not have, a short
  letter it does not have, or a letter whose arity differs between GNU and BSD (`shortConflict`: cp -S, install
  -S / -D / -T, sed -l) followed by more letters of its cluster or by an option word. The `NAME=value` words a
  command sets (before it, or after `env` / `sudo`) come from `data/shell-parse.js` `commandOf` (`env`); their
  names are matched in any case on every platform (`git_work_tree=/x`, `curl_home=/x`), since Windows environment
  names are case-insensitive and on POSIX the extra match only over-reports. git `-C` is cumulative (`git -C a -C
  b` is `a/b`; a rooted one starts over), and the paths of `git checkout`, `restore`, `rm` and `mv` resolve under
  it, as `patch <file>` resolves under `-d`. Rooted (`rooted` in `cli/oversight-shell-writes.mjs`) is `/…`
  everywhere and, on Windows only, also `\…`, a UNC `\\host\share` or a drive letter (`C:\…`, `C:/…`,
  drive-relative `C:…`). Elsewhere, PowerShell included, those shapes are relative names to git (`git -C a -C C:x
  checkout -- f` writes `a/C:x/f`, measured with git 2.39.5 and 2.54.0 from sh and with pwsh 7.4.2 on Linux and
  git 2.34.1), and under a base their place is unknown. A PowerShell segment's `cp` / `curl`
  (cmdlet aliases) is not held to these lists. MCP filesystem write tools
  (`cli/oversight-mcp.mjs`, wired in the hook's `mcp__*` branch): a tool named by a write verb (write, edit, move,
  rename, create, append, replace, insert, patch, save, overwrite, update) and a file noun (file, text_file,
  directory, dir, folder, block, text, content, path, document), or a bare `write` / `edit`, except a named
  remote-repository tool (`REMOTE_REPO_TOOL`: a github / gitlab / gitea / bitbucket server's
  `create_or_update_file`, `create_file`, `update_file`, `push_files`, `delete_file`). Remote is decided by tool
  identity only: an `owner`, `repo`, `url` or `bucket` argument on any other tool changes nothing, and a relative
  path is resolved against the session cwd. A path with a known remote
  scheme (`http`, `https`, `s3`, `gs`, `git`, `ssh`) is not local; any other `scheme:` path is judged as written
  and without the scheme and raises `analysis-incomplete`. Its path arguments map onto the Write / Edit check:
  `content` / `text` → Write (append mode: the file's text plus it), `edits: [{ oldText, newText }]` → MultiEdit,
  `old_string` / `new_string` → Edit, a move's destination → a Write of the source's text and its source → a
  path-only check (a source that is not exactly one readable local file for any reason other than "does not
  exist": several sources, a path with several or no local readings, over 1 MiB, unreadable; onto runtime code
  or a test, it is `analysis-incomplete`, as an oversized Write is), anything else (`create_directory`) → a path-only check; the
  alert is reported at stage `output`. `decideOversight`
  resolves it: with nothing configured for #84 (no `threatPolicy["84"]`; #84 has no data tier, so no `tierPolicy`
  reaches it) and no `memoryFiles`, `notify` (an alert, no prompt); with #84 configured, the stricter of
  `memoryFiles` (`notify`, `ask` = justify, `block`) and #84's action, `killOnCritical` untouched; with
  `memoryFiles` set and #84 not configured, `memoryFiles`. An invalid `memoryFiles` (warned) or
  `protectMemoryFiles: true` takes #84's action (built-in justify); `"off"` or `protectMemoryFiles: false` turns
  the set off. With both keys set the stricter wins: `protectMemoryFiles: false` turns the set off only when
  `memoryFiles` is not set, and `protectMemoryFiles: true` raises `"off"` or `"notify"` to #84's action. With another #84 signal beside it the stricter decision stands, and `threatPolicy["84"]:
  "disabled"` disables it. A path that is also a declared `protectedPaths` entry raises
  `protected-surface` instead. Skills, commands and agent definitions are not in the set. The Stop / SubagentStop
  disclosure check does not count a `memory-file` row.
- **Policy key.** Top-level `oversight: { v: 1, protectedPaths, protectedKeys, stopDisclosure, memoryFiles }`.
  `protectedPaths`: up to 64 globs (`**`, `*`, `?`), matched against the path relative to the session's cwd and
  at any directory boundary of an absolute path; `dir/**` also matches `dir`. `protectedKeys`: up to 64 key or
  env var names, whole-word, as written (a dotted key is not resolved through YAML nesting). A write that changes
  any line naming a protected key, and a command that names one together with a write verb (`sed -i`, `yq -i`,
  `tee`, `>`, `setx`, `kubectl set env|patch|edit|apply`, …), is held. `stopDisclosure`: `"alert"` (default) or
  `"block"`. A path is matched as written, as `path.resolve(cwd, p)`, and (Write / Edit targets and shell
  paths) as its `realpathSync`, or for a path that does not exist yet the real path of its nearest existing
  ancestor plus the rest; each relative to cwd and to cwd's real path, and absolute. A malformed entry is dropped
  with a stderr warning naming its position, never its value; an older agent ignores the key.
- **Stop / SubagentStop.** The rows in scope (a sub-agent's own calls; for the main agent, every call since the
  user's last prompt, its sub-agents' included) with an `ov` signal count when the call was allowed, ran after an
  ask (a PostToolUse / PostToolUseFailure with the same `tool_use_id`), or was asked on a tool Claude Code does
  not report back on (Write, Edit, MultiEdit: `not-established`). A Bash / MCP ask with no outcome did not run
  and does not count. `last_assistant_message` is judged in memory (never stored or sent): a sentence naming
  monitoring, alerting, notification, paging, audit logging, telemetry, a recipient list or a test together with
  a change verb is a disclosure, unless the verb is negated ("did not remove", "was not changed"). Undisclosed:
  one alert per scope, category `Undisclosed oversight change`, reason code `OVERSIGHT_UNDISCLOSED`,
  `oversightDisclosure: { executed: "allowed" | "ran-after-ask" | "not-established", delegated, scope: "turn" |
  "subagent", blocked }` (a SubagentStop alert also carries `parentSession`). With `stopDisclosure: "block"`,
  Claude Code only, the hook prints `{ "decision": "block", "reason": "MoorAI: this turn made a change that weakens
  oversight … state plainly to the user what was changed …" }`. The Claude Code hooks reference: `"block"`
  "prevents Claude from stopping", the reason "Tells Claude why it should continue", and `stop_hook_active` "is
  `true` when Claude Code is already continuing as a result of a stop hook. Check this value or process the
  transcript to avoid blocking on a condition that will never resolve". So it never blocks when
  `stop_hook_active` is true or a block already happened in the scope; Claude Code's own cap of eight consecutive
  continuations is a second bound. Shim hosts: alert only. The check is heuristic and precision-first (doubt
  reads as disclosed); it cannot tell a true statement from a false one.
- **Not covered.** It judges the agent's own tool calls on this device. Changes made elsewhere (CI, a person,
  another tool, an MCP write tool whose name has no write verb and file noun or that takes no path argument, a
  write through the Claude Desktop MCP proxy, a web console), a monitor renamed or rewritten so that no
  oversight word remains, a test that weakens an assertion without an absence form or a skip, the full text of
  an Edit to a file over 1 MiB (only its snippets are judged), NotebookEdit cells (no before), paths held in shell variables (a `cd` to one fails closed when a later path is judged), a move to a new name in
  the same directory that keeps an oversight word (`alerting.py` to `alerting_unused.py`), and an unenrolled device's Stop (no console, no
  coaching message) are not covered. No engine detector carries #84, so the MCP proxy, model proxy and
  `scan.mjs` do not raise it.

## Trust boundary changed without a threat-model update (#85)

[`cli/boundary-signals.mjs`](../cli/boundary-signals.mjs) (Write / Edit / MultiEdit, judged on the file before and
after), [`cli/boundary-shell.mjs`](../cli/boundary-shell.mjs) (install commands),
[`cli/boundary-model.mjs`](../cli/boundary-model.mjs) (threat-model detection, the `threatModel` policy key,
threatcl), [`cli/boundary-stop.mjs`](../cli/boundary-stop.mjs) (ledger fields and the Stop / SubagentStop decision),
wired into [`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs). Tests: `test/boundary-signals.test.mjs`,
`test/boundary-hook.test.mjs` (fixtures in `test/boundary-fixtures.mjs`). The idea is from Serval's "Agentic Threat
Modeling" (2026-10-21): a material trust-boundary change by a coding agent should come with a threat-model update in
the same change, with threat models kept as code ([threatcl](https://github.com/threatcl/threatcl)) and validated
in CI.

- **What it catches.** Four local, content-free signals (and `analysis-incomplete`, see "Linear time, fail
  closed"), recorded on the PreToolUse session-ledger row as `tb`
  (never on an alert by name of file, package, host, key or value):
  `new-dependency` (a manifest gains a dependency: `package.json` `dependencies` / `optionalDependencies` /
  `peerDependencies`, `requirements*.txt`, `pyproject.toml` `[project] dependencies`, non-dev
  `[project.optional-dependencies]` and poetry dependency tables, `go.mod` `require`, `Cargo.toml` `dependencies` /
  `build-dependencies` (also `workspace.` and `target.*.`), `Gemfile` `gem`, `pom.xml` `<dependency>` outside test
  scope, gradle `implementation` / `api` / `compileOnly` / `runtimeOnly` / `annotationProcessor` / `kapt` / `ksp`;
  or a command `npm` / `pnpm` / `bun` `add|install <pkg>`, `yarn add`, `pip install <pkg>` (also `python -m pip`,
  `uv pip`), `uv` / `poetry add`, `pipenv install <pkg>`, `cargo add`, `go get`, `bundle add`, `composer require`,
  `dotnet add package`, for a package that cwd's manifest does not already declare);
  `new-egress-host` (an http(s) URL host in runtime code or config that the file did not contain);
  `new-credential-path` (a newly read env var whose name is in `data/credential-env-names.js`
  `CREDENTIAL_ENV_NAMES`, matches its `CREDENTIAL_ENV_SHAPE`, or ends in `SECRET_KEY` / `SIGNING_KEY` /
  `ENCRYPTION_KEY` / `MASTER_KEY` / `PRIVATE_KEY` / `SERVICE_ACCOUNT_KEY`, read through `process.env`,
  `import.meta.env`, `os.environ`, `getenv` / `Getenv` / `LookupEnv`, `ENV[]`, `env::var`,
  `GetEnvironmentVariable` or `$env:`; a string literal naming a credential file by the
  `data/cred-alternatives.js` kinds, certificates and `.pub` excluded; dotenv loading added; or a new key in a real
  `.env` file);
  `new-route` (the count of route registrations goes up: `app` / `router` / `server` / `fastify` / `api` / `mux` /
  `r` / `e` / `g` / `*Router` / `*App` `.get|post|put|patch|delete|all|options|head|use|route` or Go
  `.GET|POST|…|Handle|HandleFunc` with a literal path, fastify `route({ url })`, `http.Handle[Func]`, Flask /
  FastAPI decorators, Spring `@*Mapping`, ASP.NET `Map*` and `[Http*]` / `[Route]`, Django `path` / `re_path` /
  `url` in `urls.py`, Rails verbs and `resources` in `routes.rb`, Next.js `export function GET|POST|…` in
  `app/**/route.*` and `pages/api/**`).
- **Diff, not mention.** Each signal is a set difference (hosts, credential references, dependency names, `.env`
  keys) or a count increase (routes) between the file before and after the write, so a version bump, a second read
  of an env var the file already read, a new path on a known host and a renamed route are not new. The current
  file is read up to 1 MiB; an Edit of an unreadable file is judged on its snippets (a `package.json` snippet that
  does not parse as JSON raises nothing). Comments are removed per language (a quote scanner that cuts at `//`,
  `/* */` or `#` outside a string), and Python docstrings that open a statement are dropped.
- **Path handling.** `cli/oversight-signals.mjs` `pathClasses`: a path is judged when it, or its real target, is
  runtime code; docs, fixtures, examples, tests, CI tooling and UI components (`.jsx`, `.tsx`, `.vue`, `.html`, …)
  are not. Manifests are judged by file name in the same classes (`requirements*.txt` is a manifest, not a doc;
  `test/fixtures/**/package.json` and `examples/**` are not judged). Egress, credential and route checks run on
  source and config extensions only; lockfiles are skipped. Ignored hosts: loopback, `*.localhost`, `*.local`,
  `*.test`, `*.example`, `*.invalid`, `example.com|net|org`, and XML / JSON schema namespace hosts (`w3.org`,
  `json-schema.org`, `json.schemastore.org`, …); lines with `$schema`, `xmlns` or `xsi:schemaLocation` are skipped.
- **Threat-model awareness.** A repository (the nearest ancestor of cwd holding `.git`, else cwd) has a threat
  model when a bounded walk (20,000 entries, depth 8, 1 s; `node_modules`, `.git`, `vendor`, `dist`, `build`,
  `target`, virtualenvs and caches skipped) finds an `.hcl` file of at most 256 KiB with a top-level
  `threatmodel "<name>" {` block, or a file matching `threatModel.paths`. A threat-model write is a Write / Edit /
  MultiEdit of such a file (the block before or after the write, or a declared path) or a shell command that
  writes one (a redirect target, `tee`, `sed` / `gsed` / `perl -i`, the last argument of `cp` / `mv` / `install` /
  `rsync`; an `.hcl` target counts when it is a spec now or the command carries a `threatmodel "` block). The row
  carries `tm: 1` and `tmk`, keyed hashes (`localHash`) of the files' real paths, never the path.
- **Stop / SubagentStop.** The rows in scope are the ones the #84 disclosure check reads (a sub-agent: its own; the
  main agent: every call since the user's last prompt, its sub-agents' included). A `tb` row counts when the call
  was allowed, ran after an ask, or was asked on a tool the host does not report back on; a denied call does not.
  A threat-model write clears the check only when it is established, belongs to this repository and is a real
  update ("What counts as an update" below): the `tm` row
  was allowed, or asked and then reported run (PostToolUse / PostToolUseFailure with the same `tool_use_id`; an
  ask on Write / Edit, whose outcome Claude Code never reports, does not clear it), and one of its `tmk` keys
  (the real path, or for a new file its nearest existing ancestor's real path plus the rest) matches a file the
  walk finds under the repository root. The walk lists regular files only and follows no symlink, so a decoy
  threatcl file outside the repository, another repository's model, and an in-repository symlink named like a
  model that points elsewhere clear nothing. Boundary change, threat model present, no threat-model write: one alert per
  scope, threat 85, category `Trust boundary changed without a threat-model update`, reason code
  `BOUNDARY_UNMODELLED`, risk Medium, stage `lifecycle`, `trustBoundary: { kinds, count, threatModel: "present" |
  "absent" | "created", scope: "turn" | "subagent", delegated, blocked }` (a SubagentStop alert also carries `parentSession`).
  The Stop row carries `tbFlag` (and `tbBlock`), so a second Stop in the same scope adds nothing.
- **Default and action.** Notify: `threatActionFor` resolves 85 to `notify` (no built-in default, not an approval
  threat); `threatPolicy["85"]: "disabled"` turns both the recording and the Stop check off. The PreToolUse verdict
  of the call is never changed.
- **Policy key.** Top-level `threatModel: { v: 1, paths, require, reportWithoutModel, threatclPath }`, read from the signed
  policy only (the hook's verified policy, never `~/.moorai`). `paths`: up to 64 globs, matched like
  `oversight.protectedPaths`, as written, resolved against cwd and through the real path. `require`: `"notify"`
  (default) or `"block-stop"`: Claude Code only, and only when the repository has a threat model, the hook prints
  `{ "decision": "block", "reason": "MoorAI: this turn changed a trust boundary (a new dependency, outbound host,
  credential path or HTTP route) and did not update the project's threat model. Before you stop, update the
  threat model to cover the change, or tell the user plainly why it does not need one." }`, never when
  `stop_hook_active` is true, never twice in a scope, never on an unenrolled device; when #84 blocks in the same
  Stop the two reasons are joined in one answer. `reportWithoutModel`: `true` reports boundary changes in a
  repository with no threat model (`threatModel: "absent"`, never blocks). `threatclPath`: the absolute path of
  the threatcl executable (POSIX: rooted; Windows: a drive-letter or UNC path), at most 1024 characters without
  control characters; the only way threatcl validation runs (see below); a relative or malformed value is dropped
  with a warning and validation is not run. A malformed entry is dropped with a
  stderr warning naming its position; an older agent ignores the key.
- **threatcl validation.** Only when the signed policy sets `threatModel.threatclPath` and the turn wrote a
  threat-model file; without `threatclPath` it is not run (`tmv: "unset"`), and threatcl is never looked up on
  PATH, installed or downloaded. `threatcl validate <file>` for each written file found by the walk (keyed-hash
  match, at most 8), `spawnSync` without a shell, output discarded, 3 s total. Exit 0 for every file is `pass`, a
  non-zero exit `fail`, past the budget or killed `timeout`, a spawn error `error`; a binary not run is `unset`,
  `absent` or `untrusted`, a refused model `untrusted-input` (below); Windows records `unsupported` and never runs it. The result is the Stop row's `tmv`; `fail` posts `Threat model failed
  validation` (`BOUNDARY_MODEL_INVALID`, Low, `threatModelValidation: { result, files }`). threatcl's README
  documents the command ("used to validate a `threatcl` spec HCL file") but not its exit codes;
  non-zero-is-failure is assumed and was tested with fakes and root-owned stand-ins (`/usr/bin/true`,
  `/usr/bin/false`) only.
- **Which threatcl runs.** The hook runs it, possibly outside the agent's sandbox, so an agent running as the same
  user must not be able to plant or replace it (`whichThreatcl`, `rootOwnedChain`, cli/boundary-model.mjs). Only
  `threatclPath` is considered. POSIX: the path is walked from `/` the way the kernel resolves it (`..` taken
  physically, at most 32 symlinks followed, each target walked the same way), and every component visited, `/`
  and each directory, each symlink and the final file, must be owned by uid 0; every directory and the file must
  have no group or world write bit (`mode & 0o022`); the final component must be a regular executable file.
  Neither the path nor its real path may be the repository root (`repoRoot(cwd)`), the session cwd or below either
  (as written and through `realpathSync.native`, case-folded on macOS and Windows). The binary is run by the real
  path the walk ends at. A failed ownership, mode, symlink-loop or inside-project check is `untrusted`; a missing
  component, a non-regular file or a non-executable file is `absent`; nothing falls back to PATH or anything else.
  The admin must install threatcl to a root-owned location: Homebrew's user-owned prefix (`/opt/homebrew`, or
  `/usr/local` after a default Homebrew install), `~/bin` and `~/go/bin` do not qualify. Windows: the hook never
  runs threatcl (`unsupported`): no owner or ACL check exists there and none could be validated without a Windows
  box, so a user-writable path would run; `%ProgramFiles%`-style heuristics are not used because those values come
  from an environment the agent can influence. Tested in `test/boundary-threatcl.test.mjs` (marker-writing fakes for
  "not run", `/usr/bin/true` and `/usr/bin/false` for "run", and an injected `lstat` / `readlink` for the
  ancestor cases).
- **What threatcl is given** (`cli/boundary-threatcl-input.mjs`, `validateThreatModels`). The model is agent-written
  and threatcl runs outside the agent's sandbox and egress controls. threatcl's documentation for `imports` and
  `including` could not be checked offline (nothing on disk), so both are assumed able to fetch remote content
  or read files. Models that use imports or including, or contain a URL, are not validated by the hook: every
  file is read once (at most 1 MiB; larger is refused) and refused, threatcl never started, when it contains
  `imports` or `including` as a word anywhere in any case (`(?:^|[^A-Za-z0-9_-])(?:imports|including)(?![A-Za-z0-9_-])`,
  so attributes, blocks, single-line blocks, after a comment, and prose all match: when unsure, refuse), `://`,
  a `\u` / `\U` escape or a `${` / `%{` template (either could spell a URL or key past the text checks), an HCL
  file function before `(` (`file`, `templatefile`, `fileexists`, `fileset`, `filebase64`, `filemd5`, the
  `filesha*` and `filebase64sha*` functions, `abspath`, `pathexpand`), a NUL or a U+FFFD. The result is
  `untrusted-input` on the Stop row (`files: 0`) and nothing is posted. Linear-time patterns (about 3 ms on 1 MiB
  of adversarial text). A clean file's checked bytes are written (`wx`, 0600) to a fresh `mkdtemp` directory under
  the OS temp directory, which is threatcl's working directory, and that copy is validated (so a later change to
  the agent's file is not what runs); the directory is removed afterwards. Environment, nothing inherited:
  `PATH=/usr/bin:/bin`, `HOME` = that empty directory (set, not omitted: a child with no `HOME` resolves the real
  one from the password database), `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and their lower-case forms =
  `http://127.0.0.1:9`, `NO_PROXY` / `no_proxy` empty (the Windows form of this environment exists in
  `threatclEnv` but is never used, since Windows never runs threatcl). macOS: when `/usr/bin/sandbox-exec` passes the root-ownership
  walk, threatcl runs as `sandbox-exec -p "(version 1)(allow default)(deny network*)" <threatcl> validate <copy>`
  (measured: a direct `curl` to a live 127.0.0.1 server from inside fails, the same `curl` outside succeeds).
  Linux has no wrapper: the content gate and the environment are what hold. Tested in
  `test/boundary-threatcl-input.test.mjs`.
- **What counts as an update** (`cli/boundary-update.mjs`). A threat-model write clears the check only when it is a
  real update. At UserPromptSubmit the hook walks the repository (the same bounded walk) and records on the prompt
  row `tms: { modelKey: contentDigest }` for at most 64 model files (`tmt: 1` when the walk was truncated or there
  were more); each threat-model write's PreToolUse row carries `tmb: { modelKey: digest | "" | 0 }`, the file before
  that call (a fallback for a turn with no prompt row). A digest is a keyed hash (`localHash`) of the content with
  comments (`#`, `//`, `/* */` outside strings per extension; `<!-- -->` in Markdown and HTML) and all whitespace
  removed (linear: one quote-scanner pass and an `indexOf` loop; files over 1 MiB are unreadable). At Stop, per
  written file of this repository: `existed` when its key is in the turn's `tms` (or, without `tms`, its
  earliest `tmb` is not 0); `declared` when it matches `threatModel.paths`; `substantive` when its digest now
  differs from the turn-start one (a declared file new in the turn: when its digest is not the empty one); an
  unreadable state on either side is never substantive. With no validation configured (`threatclPath` unset, or
  Windows): cleared when some file existed or is declared and is substantive. With a `threatclPath`: cleared only
  when validation is `pass` and some file is such an update or was created in the turn. Not cleared: the alert
  fires (when a boundary change is in scope), `trustBoundary.threatModel` is `"created"` when a written model was
  new in the turn, and the Stop row's `tmr` says why: `"validation"` (configured, not `pass`; `tmv` holds the
  result), `"created"` (only new models, no validation pass) or `"not-substantive"`. The hook does not judge
  whether an update is adequate. Tested in `test/boundary-update.test.mjs`.
- **Linear time, fail closed.** The signals run inside PreToolUse on agent-written text, where a slow scan would
  time the hook out and the host would let the call through. No line-anchored pattern lets `\s` span a newline
  (`[ \t]` instead), TOML table headers are read with the non-overlapping `/^\[([^\]]*)\]$/` and trimmed after,
  identifier runs in the route pattern are bounded (`{0,63}`, starting only where no identifier character
  precedes), and the go module-path check is a linear scan. Lines over 4 KiB (`LINE_MAX`) are blanked before any
  pattern runs, in every file read line by line (all but `package.json`, parsed by `JSON.parse`, and `pom.xml`,
  read by splitting); manifests in cwd read to check whether an install is new are blanked the same way (a name
  on such a line is not seen, so the install counts as new). A write is `analysis-incomplete`, the fifth `tb`
  kind, when the file is over 1 MiB before or after it, or when it adds a line over 4 KiB that was not there
  before; a shell command over `MAX_CMD` (256 KiB) is too, and so is a command the shell parser (or reading one of
  its segments) fails on (`cli/boundary-shell.mjs`; `threatModelCommand` credits no threat-model write for it). It is never judged clean: like any signal it counts at
  Stop and appears in `trustBoundary.kinds`. The PreToolUse verdict is not changed (85 is notify-only, unlike
  #84, which asks on its `analysis-incomplete`). Measured by `test/boundary-redos.test.mjs`: each adversarial
  input (a `[` and 200,000 spaces, 4,000-space headers, 200,000-newline runs before a non-matching line,
  `a$` x 2,000 per line, a 1,000,000-character line, over 1 MiB, a 200,000-dot `go get`, a command over 256 KiB)
  is judged in a child process and finishes in under 200 ms; the v1.31.0 patterns took over 10 s (killed) on
  eight of them.
- **Precision.** Measured on `test/boundary-fixtures.mjs`: 29 positive edits and 8 positive commands each raise
  exactly their signal, and 0 of 49 benign near-misses fire (dependency bumps, dev / test dependencies, a new
  script, fixture and example manifests, URLs in a README, docs, tests and fixtures, localhost / 127.0.0.1 /
  `example.com` URLs, a URL in a comment, a new path on a known host, a `$schema` URL, re-reading a secret env var,
  non-secret env vars, a changed `.env` value, `.env.example`, a certificate path, renamed routes, routes in
  comments, docstrings and READMEs, `cache.get("/users")`, `npm install` / `npm ci` / `pip install -r` /
  `pip install -e .`, global and dev installs, bumps of declared packages, and `echo` / `grep` mentioning an
  install). The set is hand-built; no field corpus has been run.
- **Not covered.** Only the agent's own tool calls on this device. Whether a new endpoint is authenticated,
  authorised, rate-limited or audit-logged, and whether the threat-model update is adequate, are static-analysis
  and review questions this check does not answer. Not seen: changes by a person, CI or another tool; a dependency
  added through a lockfile alone, a shell write to a manifest, or a manifest edit that does not parse; an install
  after a `cd` is counted without the manifest check; hosts built at runtime or held in variables; UI component
  files and NotebookEdit cells; frameworks and route styles not listed (a router mounted under another name, a
  route table built from data); a threat model outside the walk's bounds (a truncated walk with nothing found
  reads as no threat model). No engine detector carries #85, so the MCP proxy, model proxy and `scan.mjs` do not
  raise it.

## Coverage & blind spots

- **Supply chain (F16, F19, F20).** The MCP catalogue has no published publisher key or hosted feed yet, and
  its seed lists 12 names with no MoorAI scan behind any listed version. IDE-extension checks other than
  inventory and AI classification cover the VS Code family only; the known-bad list is ids and versions from
  public advisories, with no file digests; invisible-code detection is one technique, not a malware scan.
  Browser Guard is not in either store yet; a store build reports only after the user grants the console
  origin, and the extension was not run in a browser by the tests (a fake `chrome` object in Node).
- **Origin and ask outcomes on shim hosts and untracked tools are unknown.** Codex, Copilot, Cursor, Gemini,
  Droid, Antigravity, Windsurf, Kiro and Cline forward no agent id and no call id back, so their records read `host-no-thread-id` and every ask
  there reads `ask-not-trackable`; on Claude Code, an ask on Write, Edit, MultiEdit, Read or NotebookEdit
  reads `ask-not-trackable` too. Device-level alerts from the detached workers (posture inventory, index scan,
  the outbox drop report) carry no origin.

- **Strong, native, in-band** for AI work done *inside* the host.
- **Agentic tool-calls** are covered by the shipped MCP middleware ([`mcp-proxy/`](../mcp-proxy/)),
  and **browser AI** by the companion extension ([`browser-ext/`](../browser-ext/)) — both are the
  taps the "one brain, many eyes" model calls for, and both can deny, not merely observe. The proxy
  now watches **both directions**: `tools/call` arguments agent→server, and — new — `tools/list`
  metadata (report-first; the listing is altered only under `mcpToolDrift: "block"`, to leave out a
  tool that changed since approval) and `tools/call` **results** server→agent,
  where an explicit `deny` replaces the result with a tool error.
- **The reach of that, measured rather than asserted.** Against a 12-action malicious set the proxy
  refused **12/12** while enforcing (8 by the argument scan, 2 by the result scan) and forwarded
  **4/4** benign actions — but only **4 of those 12 actions natively traverse MCP at all**. The
  installer covers Claude Desktop, project `.mcp.json`, Cursor and VS Code / Copilot; Codex's TOML MCP
  config is not written by it. Codex, Copilot CLI, Gemini CLI and Cursor tool calls are covered by
  pre-tool hooks instead (`cli/moorai-agent-hook.mjs`; README, *Other agents*).
- **Files an MCP call names by path.** An argument that names a local file (absolute, `~`, `file://`,
  or relative to the agent's cwd; in the proxy, its cwd and then the client's MCP roots) gets the file's
  content scanned at `file`, its metadata (#72) and its location (#55), in both the Claude Code hook and
  the proxy ([`cli/mcp-file-args.mjs`](../cli/mcp-file-args.mjs)). Only regular files; at most 12 files,
  256 KB each, 1 MB and 1 s per call. **Blind spots:** files past the caps are skipped silently; a
  relative path in a call that names a remote `owner`/`repo`/`repository`/`project_id`/`bucket` is not
  resolved unless the tool's name sends; a relative argument that is really a destination name is
  scanned if a local file by that name exists; whether a tool sends is read from its name; #65 runs on
  the arguments, not on file content; `mask` cannot rewrite a file, so it falls back. Not tested against
  a live MCP server or on Windows.
- **Content headed for an index** (B.12) is inspected only where something calls MoorAI first: an app
  using `scanBeforeEmbed` / `guardEmbed` or `/v1/index-scan`, or a vector-store write over MCP whose
  tool matches `policy.indexTools` or the name / argument heuristic. **Blind spots:** ingestion that
  never calls MoorAI, an in-process vector library, an unrecognised store tool, and bulk imports a store
  runs itself. Not tested against a real Chroma, Qdrant, Pinecone, Weaviate or mem0 MCP server; tested
  against the fake MCP server and fake remote upstream with tool names modelled on theirs.
- **Headless agents** (CI, containers, Agent SDK services) are covered by the same hook in server mode
  (above), observed in one live `claude -p` run, or in process by `@moorai/agent-sdk` and the
  `moorai-serve` sidecar. **Blind spot:** an Agent SDK service and a CI run have not been watched end to
  end, and the in-process forms leave the session-level controls unevaluated.
- **Cloud coding agents** run the same hook in server mode where the host has a setup step and a pre-tool
  hook: the Copilot coding agent and Claude Code cloud sessions (`moorai-cloud-setup`, not yet run end to
  end). **Blind spot:** OpenAI Codex cloud tasks (command hooks do not run under cloud orchestration), and any
  cloud session whose setup step or hook registration was not configured.
- **Remote MCP servers** go through the HTTP gateway ([`mcp-gateway/`](../mcp-gateway/README.md)): the
  stdio proxy's call and result checks, a refusal returned as an `isError: true` tool result (HTTP 200),
  both MCP spec eras' headers passed through, staged JSON-RPC / MCP validation (`SCHEMA_INVALID`, refused
  by default), a 4 MiB response cap (`RESPONSE_TOO_LARGE`), a per-client cool-down (`CLIENT_COOLDOWN`, off
  by default because loopback clients share one address) and declared workload profiles on `tools/call`
  (`PROFILE_DRIFT`); about 4.7–5 ms added at p50, 98 tests against a fake upstream and a fake console.
  Run against a real remote MCP server (an AppCrane MCP endpoint over Streamable HTTP: initialize, tools/list with 62 tools and a read-only tools/call passed through intact; a malformed message and an over-cap response were refused).
  Real clients (2026-10-06, macOS): Claude Code 2.1.284, cursor-agent, the MCP TypeScript SDK 1.32.1 and the
  MCP Inspector 2.9.0 completed the handshake and listed tools through the gateway and the stdio proxy,
  and each showed a gateway method allow-list refusal; with no model, the SDK and the Inspector made a
  benign `tools/call` (forwarded) and a policy-denied one (refused, never reached the server) through
  both; three live `claude -p` runs passed (benign through each, denied through the stdio proxy)
  (`scripts/mcp-client-matrix.mjs`, opt-in `test/mcp-live-client.test.mjs`, `scripts/mcp-live-toolcall.mjs`).
  **Blind spot:** real clients have been run only against the fake upstream, so a real client and a real
  remote server in the same run, a session id from a real remote server, OAuth discovery through the
  gateway with a real client and a real authorization server, a completed 2026-07-28 session with a real
  client and a live denied call through the gateway are unproven; so are Claude Desktop, VS Code, Cursor's
  desktop app, Windows and Linux. The live
  conformance tier (above) has since run the official MCP TypeScript SDK as both client and server
  through the gateway in one run (benign forwarded; denied refused, never received by the server, Blocked
  alert); the server is an SDK server on loopback, not a third-party remote server.
  **MCP 2026-07-28 (F25, `test/mcp-gateway-2026.test.mjs`).** [`mcp-gateway/headers-2026.mjs`](../mcp-gateway/headers-2026.mjs):
  `Mcp-Param-<Name>` values are checked against the body for tools whose `x-mcp-header` annotations the
  route learned from a judged `tools/list` ("Any server that processes the message body MUST validate that
  encoded header values, after decoding if Base64-encoded, match the corresponding values in the request
  body"), integers numerically; a header with no body value, a missing header with a body value, a bad
  sentinel or a different value answers 400 / `-32020`; an unrecognized `Mcp-Param-*` header is forwarded
  ("MUST forward it and otherwise ignore it"); an annotation off a `properties` chain, on a `number`, not a
  token, or repeated case-blind makes the tool's annotations unused and is reported once. A 2026-era request
  (header or body `_meta` protocol version ≥ 2026-07-28) missing `MCP-Protocol-Version`, `Mcp-Method` or
  `Mcp-Name` answers 400 / `-32020` ("A required standard header ... is missing"), `server/discover` included
  (the revision lists no exemption).
  [`mcp-gateway/oauth-discovery.mjs`](../mcp-gateway/oauth-discovery.mjs): `/.well-known/oauth-protected-resource/<route>`
  serves the remote's RFC 9728 metadata after checking its `resource` against the remote URL (RFC 9728 3.3;
  502 when it names another resource, 404 when there is none), with `resource` set to the gateway route; a
  remote 401 / 403 Bearer challenge's `resource_metadata` is rewritten to it (added when absent). The remote
  metadata is read from the remote's own origin only (the challenge's URL when same-origin, else the
  path-inserted and root well-known URIs), through the route's egress checks, cached 5 minutes. `access_token`
  in the query string is refused (400). The gateway runs no authorization flow and stores no token. The token
  the client obtains names the gateway route as its RFC 8707 resource, so a remote server that validates the
  audience strictly refuses it unless its authorization server issues tokens for that resource.
- **Model calls** go through the model proxy ([`model-proxy/`](../model-proxy/README.md)) when the agent's
  SDK base URL points at it: prompts and fed-back tool results are scanned, and the tool calls the model
  returns are decided as the sidecar decides them. Report-only by default (byte-identical pass-through,
  checks after delivery, about 0 ms added at p50); enforce mode refuses a denied request with a
  provider-shaped 403, refuses what it could not scan, and withholds a denied tool call.
  Response-side enforcement (withholding a denied tool call, streaming and non-streaming, Anthropic and OpenAI shapes, including truncated streams, arguments that are not a JSON object and a dropped upstream connection) is tested against a fake provider; it has not been run with the real SDKs or a real provider. In Anthropic streams a tool call is held one block at a time, so an allowed call that comes before a denied one in the same turn has already been released when the turn is refused. **Blind spots:** an SDK that talks HTTPS to the provider directly bypasses
  it (no TLS interception); Anthropic Messages, OpenAI Chat Completions, the OpenAI Responses API
  (`POST …/responses`) and embeddings are parsed, while Bedrock, Vertex and `GET …/responses/{id}` pass
  unchecked (see the Responses API and embeddings entries); assistant turns, images, PDFs, tool definitions and
  server-side tools are not scanned; not exercised with the real SDKs or a paid provider. The live
  conformance tier (above) has run it in enforce mode against a real local model server (Ollama 0.40.3,
  `llama3.2:latest`) through the OpenAI-compatible (JSON and SSE), Anthropic-compatible and native Ollama
  APIs: allow, credential refusal and real tool-call withholding all passed.
- **Cloud AI platforms.** `moorai-cloud-inventory bedrock` reads an AWS account's Bedrock agents,
  knowledge bases, guardrails, custom models, provisioned throughput, application inference profiles and
  AgentCore runtimes, read-only, with the customer's own AWS CLI, and posts content-free records to the
  console's Inventory view ([`cloud/`](../cloud/README.md)). **Blind spot:** inventory only, no runtime
  enforcement on Bedrock; tested against documented response shapes and a fake AWS CLI, not a real
  account.
- **Whether MoorAI is in the path at all** is reported per host (17e, 19b): a daily heartbeat with the
  weakened settings, and the desktop app's hourly activity report independent of every hook. **Blind
  spots:** a host disabled after the day's heartbeat shows the next day; a device without the desktop app
  has no hook-independent activity source. The hook and the stdio proxy each post per-day MCP call counts
  per host and server label (`POST /api/mcp-usage`; the HTTP gateway posts them too, per tool as well, for
  the console's MCP map), and the console compares the hook and proxy paths, so MCP
  traffic one path sees and the other does not shows a bypass or a gap; a proxy entry wrapped before the
  installer's `--host` stamp reports host `unknown` until the installer is re-run.
- **Host format drift.** Each pre-tool hook depends on its host's hook format. `scripts/host-drift.mjs`,
  run nightly by `.github/workflows/host-drift.yml`, installs each host's latest release, compares it with
  `data/host-versions.json`, runs the adapter's conformance tests and a no-model smoke check (Codex: the
  published hook schemas; Gemini: MoorAI's settings against the published settings schema; Cursor: bundle
  markers; Claude Code: a headless start against a dead model endpoint; Copilot: none, conformance tests
  only), and opens or updates one issue per host when the version moves or a check fails. At runtime the
  posture heartbeat reports each host's `version` and `tested` (17e), so a device on an untested host
  version is visible before a format change is confirmed. The MCP gateway, the stdio proxy and the model
  proxy depend on no hook format, so MCP and model traffic stay covered while an adapter catches up
  (README, *Coverage layers*). **Blind spots:** the workflow has not run on GitHub yet; its live tier (one
  real agent turn per host) skips because no API-key secret exists, and Codex has no live tier; the
  console shows neither field until console v0.73.0. The separate live conformance tier (above) runs
  Claude Code turns against a scripted model with no key and has passed on 2.1.295.
- **Across a session** (17b, 17c): the claim check and the session summary need `Stop`, which only Claude
  Code sends (the other agents' adapters forward no stop event). The claim check, session risk and the
  circuit breaker are report-only by default, and have been driven through the real hook with scripted
  input, not watched in a live session.
- **Blind spot:** AI use on surfaces with no tap at all — native AI desktop apps without an
  integration, other devices, phones — plus anything on a machine where the user never installed
  MoorAI. Adoption remains voluntary, so the security dashboard reflects *opt-in population* risk,
  not total org risk — a limitation to state plainly to stakeholders.

## Build phasing

- **MVP** — native host shell + approved-tools launcher + Tier-1 rules + pre-submit DLP +
  output-safety + warn-and-override UI, driven by `data/threats.json`. Local audit log.
- **v2** — central server (policy distribution + alert ingestion + dashboard); client policy-pull
  and redacted alert reporting; Tier-2 local model; upload/paste guards; per-context sessions.
- **v3** *(shipped)* — out-of-host detection companion ([`browser-ext/`](../browser-ext/)); MCP
  agentic guardrails ([`mcp-proxy/`](../mcp-proxy/)); on-device model escalation. The Tier-3
  cloud-SDK escalation originally planned here was **dropped**: escalation is local-first, then the
  developer's own on-machine credential, and MoorAI's cloud never makes the LLM call.

## DECIDED

- **Native runtime/toolkit** — **Tauri** (see [`src-tauri/`](../src-tauri/)), chosen over Electron
  for size, auditability and a clean local-model sidecar.
- **Local model** — **nothing is bundled.** Tier 2 is opportunistic: it uses an Ollama model already
  present on the machine (default `llama3:latest`, set with `MOORAI_LOCAL_MODEL`), else the developer's own provider credential, else
  regex-only. This keeps the installer small and avoids shipping a model in the notarized build.

## OPEN DECISIONS

- **Server stack** — hosting target and dashboard framework (likely Node + SQLite per AppCrane
  conventions). The client defaults to `http://localhost:8787` until this lands.

## Sources

NIST AI 600-1 · OWASP LLM Top 10 · OWASP Agentic Threats & Mitigations · NCSC · FBI AI Data
Security · Microsoft (Copilot architecture; AI-as-tradecraft) · FBI IC3 2025 Report. Full URLs
in [`data/threats.json`](../data/threats.json).
