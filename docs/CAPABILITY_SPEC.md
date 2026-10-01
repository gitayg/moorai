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

- **Rule-base:** [`data/threats.json`](../data/threats.json) — 77 threats, 17 categories, English.
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
- **Enforcement**: server mode counts as management, so the hook enforces without a token (with no token
  it reports nothing and fetches no org policy). A `justify` verdict has no approver, so it is denied
  with a reason saying so and a content-free alert; `headlessAsk: "allow-with-report"` in the system file
  or the org policy allows and reports it instead, and the environment can only say `deny`.
- **Not applicable on a server:** the desktop app, the AIBOM, the shadow-AI inventory and OS posture.
- **Proof and limits.** Observed live: one live run of Claude Code 2.1.284 (`claude -p`, the hooks added with `--settings`, server mode from the environment) showed UserPromptSubmit (117 ms) and PreToolUse (224 ms) firing, a `.env` read denied as a headless ask, and the console receiving content-free reports under the workload identity. An Agent SDK service and a GitHub Actions run have not
  been watched end to end. Agent SDK in-process hook callbacks are not provided; an SDK service runs the
  shell hook.
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
and digest, and enum codes — §C 17d), the session summary (`summary` — counts — §C 17b), the claim check
(`claimCheck` — a claim-pattern id, an outcome word and counts — §C 17b), the session-risk and
circuit-breaker signatures (`signature`, `sessionRisk` — rule names, counts, scores, windows — §C 17c), and
the agent-posture body sent to `POST /api/agent-posture` (host ids, flag names, scope names, a hook-state
word, an hour-rounded timestamp — §C 17e). All are names, categories and counts, never content. The invariant is asserted empirically rather than
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
ranks findings by ([`src/engine.js`](../src/engine.js)) — across all 77 threats.

| Level | Count | Nominal score band |
|---|---|---|
| Critical | 17 | ≥ 20 |
| High | 47 | 12–19 |
| Medium | 13 | 6–11 |

Note: 8 of the 77 threats carry a `riskLevel` label outside the nominal band their `riskScore`
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
   *Threat 64.* The hook registers `UserPromptSubmit` for this alone; the prompt is not scanned by the
   detection engine. From prompts a person wrote (`system` and `poll_event` turns skipped), it keeps
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
   the prompt for capture only and answer with nothing the model sees.

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
   report-only; `ask` becomes advisory `additionalContext`; unenrolled devices coach. On `Bash`/`PowerShell`, MCP and
   sub-agent results, the action and generated-code threats (#29, #44, #45, #52, #54, #55, #57, #61,
   #62, #63, #69, #76) are dropped, because `PreToolUse` enforces them when attempted, and the #15/#17
   gates are narrowed. Sub-agent results are judged on their report only. **Limits.** Output past 64 KB
   is unscanned; `cat .env` reports at both `PreToolUse` and `PostToolUse`;
   the Codex, Copilot, Gemini and Cursor adapters forward only web results; recall figures are
   in-sample. [DETECTION_ENGINE.md](DETECTION_ENGINE.md) §6–7.

11g. **Credential paths in MCP tool descriptions** — `mcp-tool-cred-path`
   ([`data/tool-credpaths.js`](../data/tool-credpaths.js)), `tool` stage, *Threat 60.* Fires only when a
   description or schema tells the model to read or move a credential file's content into a call, and
   stays silent on a negated verb, a capability infinitive, the server describing itself, the path as a
   destination, and public keys or certificate PEMs. Its #60 finding feeds the server's existing
   `tool-poisoning` reputation signal.

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
    (counts) when they changed. At `Stop` / `SubagentStop`, [`cli/claim-check.mjs`](../cli/claim-check.mjs)
    compares `last_assistant_message` (read in memory, never stored or sent) with the turn's recorded
    outcomes and posts `Agent reported success but tool calls failed` (Medium, `CLAIM_MISMATCH`) when the
    message claims success while tool calls failed, were denied or were interrupted and were not redone.
    Report-only. **Measured:** 81.8% precision blind; after tuning on half of a 75-case labelled corpus,
    70.0% precision and 46.7% recall on the held-out half. `PreCompact` records that compaction happened.
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
    decided; enum in the module), `basisCode` when an override decided, and `enforcement`
    `AS_CONFIGURED` | `STRENGTHENED` | `LIMITED` | `UNEVALUATED`. A control that never ran — bad stdin, a
    hook error, no policy after an error, break-glass, an unsupported tool, an empty result, a size cap —
    is `UNEVALUATED`, never a pass.
17e. **Coverage integrity, agent side** — [`cli/agent-posture.mjs`](../cli/agent-posture.mjs) (read-only,
    built on `cli/doctor-hosts.mjs`) reports per host — Claude Code, Codex, Gemini, Cursor, Copilot — the
    hook state, `lastActive` (hour-rounded), and weakened-setting flags: `hooksDisabled`,
    `mooraiHookDisabled`, `managedHooksOnly`, `bypassPermissionsDefault`, `sessionBypassPermissions`,
    `approvalNever`, `approvalUnrestricted`, `autoEditDefault`, `sandboxFullAccess`, `sandboxOff`. The hook
    sends a content-free heartbeat with this posture to `POST /api/agent-posture` at most once per host per
    UTC day (retried after 10 minutes on failure); enrolled devices only. The desktop app reports each
    host's last activity hourly (`device_agent_activity`), independent of every hook.

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

## Coverage & blind spots

- **Strong, native, in-band** for AI work done *inside* the host.
- **Agentic tool-calls** are covered by the shipped MCP middleware ([`mcp-proxy/`](../mcp-proxy/)),
  and **browser AI** by the companion extension ([`browser-ext/`](../browser-ext/)) — both are the
  taps the "one brain, many eyes" model calls for, and both can deny, not merely observe. The proxy
  now watches **both directions**: `tools/call` arguments agent→server, and — new — `tools/list`
  metadata (report-first, the listing is never mutated) and `tools/call` **results** server→agent,
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
- **Headless agents** (CI, containers, Agent SDK services) are covered by the same hook in server mode
  (above), observed in one live `claude -p` run. **Blind spot:** an Agent SDK service and a CI run have not
  been watched end to end.
- **Whether MoorAI is in the path at all** is reported per host (17e, 19b): a daily heartbeat with the
  weakened settings, and the desktop app's hourly activity report independent of every hook. **Blind
  spots:** a host disabled after the day's heartbeat shows the next day; a device without the desktop app
  has no hook-independent activity source; the proxy-versus-hook comparison for the same MCP server is not
  computed (the console stores no MCP server name and the proxy does not know its host).
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
