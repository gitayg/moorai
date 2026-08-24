# MoorAI — Capability Spec

**Version:** 0.6 · **Status:** architecture locked, refining capabilities · **UI language:** English (LTR)

## What it is

MoorAI is a **native desktop "Managed AI Host"** for office workers, paired with a **central
server** for policy and visibility. The employee does their AI work *inside* MoorAI — a native
app with an embedded, managed webview — so the host sees every prompt, response, paste, and
upload natively (no browser extension, no DOM hacks). It detects the 67-threat matrix in real
time, **coaches the employee** with the matrix's guidance, and **reports redacted alerts** to a
central server so the security team has visibility.

**Posture: adoption is voluntary; enforcement is policy-driven.** Adoption is opt-in
(self-install), but MoorAI does block. `threatActionFor` in [`cli/hook-core.mjs`](../cli/hook-core.mjs)
resolves every threat to one of `notify` · `justify` · `block` · `kill`, and
[`cli/moorai-hook.mjs`](../cli/moorai-hook.mjs) turns those into real Claude Code `allow`/`ask`/`deny`
verdicts — up to terminating the session outright (`killSession`). The **default is report-first**:
an unconfigured threat resolves to `notify`, so a finding is reported rather than blocked unless an
admin escalates it via `threatPolicy` / `tierPolicy` (six threats — 11, 43, 46, 47, 48, 49 — default
to `justify` instead). Central distributes the policy that selects those actions. MoorAI's value is
(a) **coaching** the employees who use it, (b) giving the security team **visibility** into AI-usage
risk, and (c) **deterministic prevention** where policy calls for it. Because adoption is voluntary,
it still does not prevent Shadow AI by construction; it reduces risk for those who opt in and
surfaces organization-wide risk signals.

- **Rule-base:** [`data/threats.json`](../data/threats.json) — 67 threats, 14 categories, English.
  Each threat is a rule: `example` = trigger context, `response` = intervention,
  `riskScore = severity × likelihood`.
- **Intervention model:** risk-tiered and policy-driven — `notify` (report) → `justify` (ask) →
  `block` (deny) → `kill` (terminate session). Report-first by default, blocking when configured.

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
- Because the interceptor is **open source (AGPL-3.0)**, this is auditable rather than asserted —
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
  enforcement.

### Client form factor — native Managed AI Host
- Native desktop app (cross-platform from one codebase). All AI tools are reached through the host.
- In-band inspection points: **pre-submit** (prompt), **post-response** (AI output),
  **upload/drag-drop** (files), **paste/clipboard** (into the prompt box).
- *Companion surfaces (shipped):* a browser extension ([`browser-ext/`](../browser-ext/)) to
  **detect** AI use *outside* the host, and an MCP middleware layer
  ([`mcp-proxy/`](../mcp-proxy/)) that guardrails agentic tool-calls.

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

Two further field families are permitted under this rule and are named here so the contract stays
enumerable rather than implicit: `skillKind` + `skillIntents` (a file kind and closed-vocabulary intent
labels — §B2 11a) and `destination` (`{kind, name, decision}` — a host or MCP server name — §B2 11b).
Both are names and categories, never content. The invariant is asserted empirically rather than
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
ranks findings by ([`src/engine.js`](../src/engine.js)) — across all 67 threats.

| Level | Count | Nominal score band |
|---|---|---|
| Critical | 17 | ≥ 20 |
| High | 40 | 12–19 |
| Medium | 9 | 6–11 |

Note: 8 of the 67 threats carry a `riskLevel` label outside the nominal band their `riskScore`
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
   through the same detectors — macOS `Vision.framework`, Windows `Windows.Media.Ocr.OcrEngine`. No
   model is bundled and the image never reaches the MoorAI console. Three states, and the UI names
   the applicable one before the user pastes:

   | Device | Behaviour |
   |---|---|
   | macOS; Windows with an OCR language pack | **On-device.** Nothing leaves the machine. |
   | No OS engine, but a provider key already on the device | **Disclosed fallback.** Sent **device → provider directly** (never via MoorAI), using the key already present — env `ANTHROPIC_API_KEY`, the admin key file, or the saved agent token, resolved exactly as [`data/device-inference.mjs`](../data/device-inference.mjs) does. Emits a content-free alert. |
   | No OS engine and no key | **Skipped**, and said so. Never a silent fallback to egress. |

   The fallback is structurally unreachable whenever a native engine exists: the host ignores the
   caller's opt-in in that case ([`src-tauri/src/ocr.rs`](../src-tauri/src/ocr.rs)). *Windows OCR is
   compile-verified only — not yet run against a real image on a real Windows host.*
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
   | `.cursorrules`, `.cursor/rules`, `cursor-mcp`, `.windsurfrules`, `.clinerules`, `copilot-instructions`, `codex-config` | other vendors' equivalents | doc |

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

### C. Runtime (client)
12. **Risk-prioritized alerting** — ranks findings by `riskLevel`, then `riskScore` as the tiebreak.
13. **In-context guidance** — surfaces the matching `response` + a source link.
14. **Local audit log** — on-device record of detections/decisions.
15. **Redacted alert reporting** — sends redacted alerts to the server (metadata only).
16. **Policy pull** — fetches allowlist/thresholds/rule-base from the server; offline-tolerant.
17. **Privacy-preserving** — inspection is local; only redacted metadata leaves the device.

### D. Central server
18. **Policy & rule-base distribution** — central allowlist, thresholds, per-threat/per-tier
    enforcement actions, and versioned rule-base pushed to clients.
19. **Alert ingestion** — receives and stores redacted client alerts.
20. **Security dashboard** — org-wide risk view: alerts by threat / category / risk tier / user,
    trends over time. The dashboard itself is **visibility**; enforcement happens on the client,
    driven by the policy this server distributes.

## Intervention tiers (policy-driven)

The action comes from policy, not from the risk level alone — `threatActionFor` resolves
per-threat → data-tier → approval-set → `notify`.

- **`notify`** (the default for an unconfigured threat) → prominent inline warning + the matrix's
  defensive-response text; the call proceeds and the finding is logged + reported.
- **`justify`** → surfaced as Claude Code `ask`: the developer must acknowledge/justify before the
  call proceeds (logged + reported). Default for threats 11, 43, 46, 47, 48, 49.
- **`block`** → Claude Code `deny`; the tool call does not execute.
- **`kill`** → denies the call *and* terminates the session (`killSession`). `killOnCritical`
  promotes any Critical `block` to a `kill` without per-threat configuration.

## Coverage & blind spots

- **Strong, native, in-band** for AI work done *inside* the host.
- **Agentic tool-calls** are covered by the shipped MCP middleware ([`mcp-proxy/`](../mcp-proxy/)),
  and **browser AI** by the companion extension ([`browser-ext/`](../browser-ext/)) — both are the
  taps the "one brain, many eyes" model calls for, and both can deny, not merely observe.
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
