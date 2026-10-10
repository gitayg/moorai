# MoorAI — Capability Spec

**Version:** 0.6 · **Status:** architecture locked, refining capabilities · **UI language:** English (LTR)

## What it is

MoorAI is a **native desktop "Managed AI Host"** for office workers, paired with a **central
server** for policy and visibility. The employee does their AI work *inside* MoorAI — a native
app with an embedded, managed webview — so the host sees every prompt, response, paste, and
upload natively (no browser extension, no DOM hacks). It detects the 77-threat matrix in real
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

- **Rule-base:** [`data/threats.json`](../data/threats.json) — 79 threats, 17 categories, English.
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
  between an agent's model SDK and the provider (Anthropic Messages, OpenAI Chat Completions) that scans
  what the agent sends and the tool calls the model returns. Report-only by default; `--mode enforce`
  refuses in the provider's own error shape.
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
- **Not applicable on a server:** the desktop app, the AIBOM, the shadow-AI inventory and OS posture.
- **Proof and limits.** Observed live: one live run of Claude Code 2.1.284 (`claude -p`, the hooks added with `--settings`, server mode from the environment) showed UserPromptSubmit (117 ms) and PreToolUse (224 ms) firing, a `.env` read denied as a headless ask, and the console receiving content-free reports under the workload identity. An Agent SDK service and a GitHub Actions run have not
  been watched end to end.
- **In process.** `moorAIHooks(options)` from `@moorai/agent-sdk` returns the `hooks` record for
  `query({ options: { hooks } })`: one runtime, no process per tool call. `PreToolUse` returns the hook's
  own decision and reason (parity test: 214 payloads, two policy states, 0 mismatches). Prompts and tool
  results are observed by default (`prompts: "enforce"`, `toolResults: "advise"` to act on them).
  `moorai-serve` is the same runtime as a localhost sidecar: `POST /v1/scan`, `POST /v1/tool-call`,
  `POST /v1/index-scan` (chunks about to be embedded; B.12), `GET /healthz`, content-free verdicts, loopback only unless `--allow-remote` plus a 16+ character
  bearer token (compared in constant time); it rejects a non-loopback `Host` (421), non-JSON (415) and a
  body over 1 MiB (413, after draining), with a 5 s header timeout and 256 connections. A stdlib-only
  Python client with LangGraph / CrewAI examples (not executed) is in
  [`clients/python`](../clients/python/README.md). p50 on 2 KB: SDK `PreToolUse` 1.99 ms, sidecar
  `/v1/scan` 6.4–11 ms, shell hook process 164–309 ms. **Limits.** Not evaluated in process (listed in
  each result's `notEvaluated`): circuit breaker, session risk, deletion volume, intent alignment,
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
  launching environment and the root-owned anchor files are trusted.

### Detection brain — tiered escalation cascade
Cheapest-and-most-private first; the escalation order *is* the privacy order.

1. **Tier 1 — deterministic rules** — always on, local, instant, zero egress. Owns the allow/deny
   decision.
2. **Tier 2 — local model** — on ambiguity, opportunistic and policy-gated
   ([`data/model-escalation.mjs`](../data/model-escalation.mjs)). Ollama on the loopback interface
   (`127.0.0.1:11434`, default `llama3.2:1b`) — deliberately not configurable to a remote host, so
   nothing leaves the device. Fail-open: no model, timeout or error yields no verdict and never
   changes enforcement.
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
`session` field), never from the model proxy, which sees no conversation id — §C 17b), the session summary (`summary` — counts — §C 17b), the claim check
(`claimCheck` — a claim-pattern id, an outcome word and counts — §C 17b), the session-risk and
circuit-breaker signatures (`signature`, `sessionRisk` — rule names, counts, scores, windows — §C 17c), and
the agent-posture body sent to `POST /api/agent-posture` (host ids, flag names, scope names, a hook-state
word, an hour-rounded timestamp, a host version string and a tested boolean — §C 17e), the prompt-scan origin (`promptOrigin`, `promptSource` — enum
words — §B3 11h), the MCP usage counts sent to `POST /api/mcp-usage` (a day, a path, a host id, server
labels and call counts, and from the HTTP gateway MCP tool names with their counts — Coverage & blind
spots) and the cloud inventory records (keyed-hash ids, closed-list
statuses, coarse attributes, risk-flag names — Coverage & blind spots). All are names, categories and
counts, never content. The invariant is asserted empirically rather than
declared: `test/skill-analysis.test.mjs` and `test/destinations.test.mjs` each plant a unique canary in
a fixture, capture every byte the hook POSTs plus the on-device ledgers, and fail if the canary, a
matched span, a verbatim source line, a URL path, a query string or a request header appears in either.

### Policy — server → client
Server distributes: approved-tools allowlist, risk thresholds, per-threat/per-tier enforcement
actions (`threatPolicy` / `tierPolicy`), model-escalation policy, and rule-base updates. Client
pulls on launch and periodically; works offline against the last-known policy.

The policy is an ed25519-signed envelope. The client trusts it via, in order: a root-owned anchor
(`/etc/moorai/policy.pub`, `%ProgramData%\MoorAI\policy.pub`, or MDM-injected `MOORAI_POLICY_PUBKEY`),
else a TOFU pin learned from the first verified fetch. Two properties are enforced on top of the
signature itself:

- **Key revocation.** A `revokedKeys` list inside the signed body prunes matching keys from the
  device's pin, so an operator signing with K2 can evict a leaked K1 without reprovisioning. Two
  refusals guard it: a key may not revoke itself (otherwise a stolen key locks the operator out),
  and pruning may never empty the pin (an empty key set degrades to `unanchored`, which would turn
  a revocation into a total bypass). Both refusals emit a content-free tamper alert.
- **Rollback refusal.** The highest accepted `iat` is retained as a high-water mark; a strictly
  older — though validly signed — policy is refused and alerted, so a superseded policy cannot be
  replayed to undo a tightening. Equal `iat` is accepted, or steady-state re-fetch would break. A
  refusal falls back to last-known-good, never to "no policy", so #33 offline enforcement is intact.

**Strength, stated honestly.** Both mechanisms are HARD only where the state they depend on is
outside the agent's own write scope. Rollback refusal is hard when a root-owned
`/etc/moorai/policy-hwm.json` is present, because the hook reads but never writes it. Revocation is
**never** hard: it prunes the pin, and both pin copies live under the user's home directory, so a
local attacker who can poison the policy cache can rewind the pin too — and on an anchored device
the pin is not the deciding key set at all, so pruning changes no enforcement decision there. On an
anchored fleet the real revocation mechanism remains shipping a new root-owned `policy.pub`.
Everywhere else these are tamper-EVIDENT (alerted), not tamper-proof — which is the same posture as
the rest of the product: the hook runs as the user, so nothing under `~/` is a trust boundary.

## Risk distribution (from the matrix)

Counts are the shipped `riskLevel` labels in `data/threats.json` — the field the engine actually
ranks findings by ([`src/engine.js`](../src/engine.js)) — across all 79 threats.

| Level | Count | Nominal score band |
|---|---|---|
| Critical | 17 | ≥ 20 |
| High | 47 | 12–19 |
| Medium | 13 | 6–11 |

Note: 8 of the 79 threats carry a `riskLevel` label outside the nominal band their `riskScore`
would place them in (e.g. #65 scores 15 but is labeled Critical; #43 scores 6 but is labeled High).
The label wins at runtime; the bands in `meta.scoring` are documentation, not an invariant the data
is validated against.

## Capabilities

### A. Host / gateway (client)
1. **Approved-tools launcher** — the allowlisted AI tools, reached through the host. *Coaches on
   threats 4, 5, 7, 28; when an MCP allow-list is configured, an off-list server is denied outright
   (`checkServer`, [`cli/hook-core.mjs`](../cli/hook-core.mjs)) — but a user who never installs
   MoorAI is still unreached.*
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
   | `zed-mcp` | Zed `context_servers` — lives inside `~/.config/zed/settings.json` or project `.zed/settings.json` (a general settings file, anchored to the `zed` dir; no overlap with `.claude/settings.json`) | doc |

   **Intent labels** are a closed vocabulary (`INTENT_LABELS`,
   [`cli/skill-analysis.mjs`](../cli/skill-analysis.mjs)), each one a rename of an existing threat id, an
   existing content tell ([`data/agent-behavior.js`](../data/agent-behavior.js)) or the existing host
   extractor ([`data/model-endpoints.js`](../data/model-endpoints.js)). There is deliberately **no second
   detection engine**: a forked engine would sit outside `threatActionFor` and the org's detector packs.

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
   override (`OLLAMA_HOST=http://gpu-box:11434`), not from a plain URL. The `decision` recorded is the
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
   a UNC share's host counts), a #43 destructive command, a #55 credential read (`Read`, `Bash` or
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
   Paginated servers are judged page by page and cannot be pinned. The full failure table is in
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
    26300.9550 and 28000.2804. It is read with `reg.exe` in the heartbeat worker only and cached about a
    day per release. It is `null` for unlisted builds or a missing value.

    Detected vs assumed:
    - The values come from config. Nothing observes a running container, and MXC documents no way to.
    - CLI flags, Codex profiles and enterprise-managed settings can override the config.
    - A capable build may still have MXC switched off by Microsoft's gradual rollout.
    - Codex and Copilot contain only the commands the agent runs, not the agent.

    Report-only, fail-open, and changes no verdict. Not run on a real Windows host yet.
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
    `evaluateProfile()`. `egressRules: [{ id?, binary?, host, port?, method?, path?, action }]` and
    `egressDefault`, with `action` one of `allow`, `alert` or `block`. They can sit at the top level of the
    verified console policy or the root-owned machine-wide config, where they apply to every call, or
    inside a workload profile, where they apply when it matches and are read first. `host` is an exact
    name or `*.suffix`. `binary` is the command word, or for a non-shell call the tool name. `path` is
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
    and the MCP stdio proxy do not judge egress rules. Tested on macOS only.

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
`--config <file>`, `--log-file <file>` (content-free audit records) and `--probe`. There is no `--policy` flag.
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
| env | `TEMP`/`TMP` → `~/.moorai/agent-tmp`; `GIT_CONFIG_COUNT/KEY/VALUE` = `safe.directory` for the workspace only; `NODE_EXTRA_CA_CERTS` if configured | git rejects repos created while elevated, and command-scope config counts as protected config. BaseContainer does not inherit the CurrentUser Root store. `NODE_EXTRA_CA_CERTS` adds roots. `SSL_CERT_FILE` would replace OpenSSL's bundle, so it is only passed through when it is already set. |

**Denials → alerts.** `captureDenials.mode: "block"` keeps enforcement on. After the session exits, MXC writes
`denials.<run-id>.json` into the host-only run dir. The host parses only the documented fields
(`resource`, `resourceType`, `accessType`, `summary.deniedResourcesTruncated`) and deletes the file. It then posts
one content-free `/api/alerts` record per group: category `MXC: access denied`, `pathClass` (never a path),
`reasonCode` (`<class>-<access>`), `count`. `pid`, `filetime` and file names are dropped. Capability denials keep
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
[`test/fixtures/mxc/sandbox-cases.json`](../test/fixtures/mxc/sandbox-cases.json). Rust uses the `url` crate,
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
group- or world-writable (the hook's `readRootOwned` rule). It never reads them from `~/.moorai/config.json`.

**OpenShell** (NVIDIA/OpenShell @ b959bb6, `docs/how-it-works/policies/schema.mdx` and `network-rules.mdx`).
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
- The macOS host path that reads `/etc/moorai/config.json` was tested only for refusing a user-owned file.
- A `deny_rules` entry on one OpenShell endpoint can also deny requests that another overlapping rule
  allows (narrower, not reported).

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
    `--require-placeholders` it is refused with 401.
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
`test/model-proxy-toolcall-local.test.mjs`, `test/serve-unchecked.test.mjs`). Replace mode and the skip alert
are opt-in.**

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

- Only traffic forced through the proxy is covered. The Responses API, Bedrock, Vertex and Ollama's native
  API are forwarded unparsed. Server-side tools (`server_tool_use`, `mcp_tool_use`) are not judged.
- In replace mode, text the model wrote after a tool call in the same turn is dropped with the call.
- The skip alert detects a framework that skipped the check, not one that lies. Anything on loopback with
  the proxy token, the agent included, can mark an id as checked.
- No real Ollama, LM Studio, llama.cpp or vLLM build has been run against it.

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

## Egress proxy (egressRules on real connections)

**Status: built and unit-tested (`test/egress-proxy.test.mjs`, `test/egress-proxy-address.test.mjs`,
`test/egress-proxy-limits.test.mjs`, `test/egress-proxy-harden.test.mjs`, all in process with an injected
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

## Coverage & blind spots

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
  gateway, a completed 2026-07-28 session with a real client and a live denied call through the gateway
  are unproven; so are Claude Desktop, VS Code, Cursor's desktop app, Windows and Linux.
- **Model calls** go through the model proxy ([`model-proxy/`](../model-proxy/README.md)) when the agent's
  SDK base URL points at it: prompts and fed-back tool results are scanned, and the tool calls the model
  returns are decided as the sidecar decides them. Report-only by default (byte-identical pass-through,
  checks after delivery, about 0 ms added at p50); enforce mode refuses a denied request with a
  provider-shaped 403, refuses what it could not scan, and withholds a denied tool call.
  Response-side enforcement (withholding a denied tool call, streaming and non-streaming, Anthropic and OpenAI shapes, including truncated streams, arguments that are not a JSON object and a dropped upstream connection) is tested against a fake provider; it has not been run with the real SDKs or a real provider. In Anthropic streams a tool call is held one block at a time, so an allowed call that comes before a denied one in the same turn has already been released when the turn is refused. **Blind spots:** an SDK that talks HTTPS to the provider directly bypasses
  it (no TLS interception); only Anthropic Messages and OpenAI Chat Completions are parsed (the Responses
  API, embeddings, Bedrock and Vertex pass unchecked); assistant turns, images, PDFs, tool definitions and
  server-side tools are not scanned; not exercised with the real SDKs or a real provider.
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
  console shows neither field until console v0.73.0.
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
  present on the machine (default `llama3.2:1b`), else the developer's own provider credential, else
  regex-only. This keeps the installer small and avoids shipping a model in the notarized build.

## OPEN DECISIONS

- **Server stack** — hosting target and dashboard framework (likely Node + SQLite per AppCrane
  conventions). The client defaults to `http://localhost:8787` until this lands.

## Sources

NIST AI 600-1 · OWASP LLM Top 10 · OWASP Agentic Threats & Mitigations · NCSC · FBI AI Data
Security · Microsoft (Copilot architecture; AI-as-tradecraft) · FBI IC3 2025 Report. Full URLs
in [`data/threats.json`](../data/threats.json).
