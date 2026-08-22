# MoorAI — Capability Spec

**Version:** 0.6 · **Status:** architecture locked, refining capabilities · **UI language:** English (LTR)

## What it is

MoorAI is a **native desktop "Managed AI Host"** for office workers, paired with a **central
server** for policy and visibility. The employee does their AI work *inside* MoorAI — a native
app with an embedded, managed webview — so the host sees every prompt, response, paste, and
upload natively (no browser extension, no DOM hacks). It detects the 40-threat matrix in real
time, **coaches the employee** with the matrix's guidance, and **reports redacted alerts** to a
central server so the security team has visibility.

**Posture: voluntary and awareness-first — nothing is blocked.** Adoption is opt-in (self-install),
the user is warned but can always override, and central is alerted but does not enforce. MoorAI's
value is (a) **coaching** the employees who use it and (b) giving the security team **visibility**
into AI-usage risk — *not* hard prevention. Because adoption is voluntary, it does not prevent
Shadow AI by construction; it reduces risk for those who opt in and surfaces organization-wide
risk signals.

- **Rule-base:** [`data/threats.json`](../data/threats.json) — 40 threats, 14 categories, English.
  Each threat is a rule: `example` = trigger context, `response` = intervention,
  `riskScore = severity × likelihood`.
- **Intervention model:** **warn + allow override**, risk-tiered (awareness-first, non-blocking).

## Architecture

### Mental model — one brain, many eyes (don't re-litigate)
The **harness is a brain, not an eye.** It *decides*; it can only decide about wires it is actually
tapped into. Making it smarter never lets it see a wire it isn't connected to. AI activity crosses
**several wires that never converge** at one point on the device:

| Wire | Where it runs | Tap |
|---|---|---|
| Human ↔ AI (chat: prompts, pastes, uploads, responses) | inside the host webview | **Managed Host** — always |
| AI ↔ tools (agent tool-calls: send email, update CRM, delete file) | model backend / remote MCP server — **never crosses the webview** | **MCP gateway (or API/egress proxy)** — when agents act |
| AI outside the host (other browser, native app, phone) | a different process/device | optional out-of-host monitor |
| Deepfake call / vishing | a phone line — no data wire | coach-only (no tap possible) |

**Why MCP is needed (conditionally):** agent tool-calls execute on the AI↔tools wire, which does
not pass through the chat webview, so the harness is *blind* to threats 14/22/23/24/25/38/40 no
matter how capable it is. MCP is the **eye on that second wire** (and the only point where a
tool-call can be deterministically blocked *before* it executes). It is **not a second brain** — it
feeds the same harness.

**The trigger:** harness + host is genuinely enough for *conversational* AI. Add the MCP/proxy tap
**only when agentic tool-use is in scope** — hence it sits in v3, not the MVP.

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
  one-way hash**.
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
- **MoorAI Guard (CLI)** — `raiseme-guard` wraps `claude -p`: captures the prompt at the submit
  boundary, runs the local review, and forwards only the approved/redacted prompt to the real
  `claude -p`. The runnable proof that the harness reviews egress before the agent. (`npm run guard`.)
- **MoorAI Server** — web app on **crane.glick.run** (AppCrane). Distributes policy + rule-base
  to clients, ingests redacted alerts, and serves the security-team dashboard. Does **not** enforce.

### Client form factor — native Managed AI Host
- Native desktop app (cross-platform from one codebase). All AI tools are reached through the host.
- In-band inspection points: **pre-submit** (prompt), **post-response** (AI output),
  **upload/drag-drop** (files), **paste/clipboard** (into the prompt box).
- *Later companion (optional):* a browser extension / native monitor to **detect** AI use *outside*
  the host, and an SDK/MCP middleware layer to guardrail agentic tool-calls.

### Detection brain — 3-tier escalation cascade
Cheapest-and-most-private first; the escalation order *is* the privacy order.

1. **Tier 1 — deterministic rules** — always on, local, instant, zero egress.
2. **Tier 2 — local LLM** — on ambiguity, local, private. Nothing leaves the device.
3. **Tier 3 — cloud SDK** — hardest cases, **policy-gated, if available**. Anthropic SDK, **only
   when org policy allows and only on redacted/structured signals — never raw sensitive content.**

### Telemetry — redacted alerts only
Client → Server alerts carry **redacted metadata only**: threat id, category, risk tier, timestamp,
tool used, optional content hash / redacted snippet. **Never raw sensitive content** — otherwise
MoorAI would itself commit threats #1 / #9 / #33 on every phone-home.

### Policy — server → client
Server distributes: approved-tools allowlist, risk thresholds, Tier-3 egress policy, and rule-base
updates. Client pulls on launch and periodically; works offline against the last-known policy.

## Risk distribution (from the matrix)

| Level | Count | Score |
|---|---|---|
| Critical | 16 | ≥ 20 |
| High | 23 | 12–19 |
| Medium | 1 | 6–11 |

## Capabilities

### A. Host / gateway (client)
1. **Approved-tools launcher** — the allowlisted AI tools, reached through the host. *Coaches on
   threats 4, 5, 7, 28 (cannot prevent them, since adoption is voluntary).*
2. **Per-context sessions** — a separate conversation per customer / project / topic. *Threat 36.*

### B. In-band detection (client; mapped to threat clusters)
3. **Sensitive-data guard (DLP)** — pre-submit + paste inspection. *Threats 1, 9, 15, 33, 39.*
4. **Upload guard** — intercepts file uploads / drag-drop. *Threats 18, 27.*
5. **Prompt-injection scanner** — inspects pasted/external content. *Threats 2, 3, 40.*
6. **Output-safety scanner** — dangerous links/scripts/macros + fake sources. *Threats 8, 17, 29, 32, 34, 35.*
7. **Social-engineering / BEC sentinel** — bank-detail/payment/invoice/deepfake patterns. *Threats 10–13, 30, 31.*
8. **Meeting & memory hygiene** — transcription warnings, risky AI-memory writes. *Threats 19, 20, 22.*
9. **Permissions-exposure watch** — over-broad / role-irrelevant results. *Threat 6.*
10. **Ethics check** — human-review nudge on AI-assisted screening. *Threat 16.*
11. **Output-sharing check** — scans summaries/screenshots before sharing. *Threats 20, 37.*

### C. Runtime (client)
12. **Risk-prioritized alerting** — uses `riskScore` to rank interventions.
13. **In-context guidance** — surfaces the matching `response` + a source link.
14. **Local audit log** — on-device record of detections/decisions.
15. **Redacted alert reporting** — sends redacted alerts to the server (metadata only).
16. **Policy pull** — fetches allowlist/thresholds/rule-base from the server; offline-tolerant.
17. **Privacy-preserving** — inspection is local; only redacted metadata leaves the device.

### D. Central server (crane.glick.run)
18. **Policy & rule-base distribution** — central allowlist, thresholds, Tier-3 egress policy, and
    versioned rule-base pushed to clients.
19. **Alert ingestion** — receives and stores redacted client alerts.
20. **Security dashboard** — org-wide risk view: alerts by threat / category / risk tier / user,
    trends over time. **Visibility, not enforcement.**

## Intervention tiers (warn + allow override)

- **Critical / High** → prominent inline warning + the matrix's defensive-response text + an
  explicit "proceed anyway" acknowledgement (logged + reported). Never hard-blocks.
- **Medium** → passive nudge.

## Coverage & blind spots

- **Strong, native, in-band** for AI work done *inside* the host.
- **Blind spot:** AI use *outside* the host (other browsers, native AI apps, agentic tool-calls) —
  unobserved, because adoption is voluntary and nothing is enforced. Surfaced only if/when the
  optional later companion monitor ships. The security dashboard therefore reflects *opt-in
  population* risk, not total org risk — a limitation to state plainly to stakeholders.

## Build phasing

- **MVP** — native host shell + approved-tools launcher + Tier-1 rules + pre-submit DLP +
  output-safety + warn-and-override UI, driven by `data/threats.json`. Local audit log.
- **v2** — central server on crane.glick.run (policy distribution + alert ingestion + dashboard);
  client policy-pull and redacted alert reporting; Tier-2 local LLM; upload/paste guards; per-context sessions.
- **v3** — Tier-3 cloud-SDK escalation (policy-gated); out-of-host detection companion; SDK/MCP
  agentic guardrails; richer dashboard analytics.

## OPEN DECISIONS

- **Native runtime/toolkit** — cross-platform from one codebase: **Tauri** (small, auditable,
  clean local-LLM sidecar; OS-webview quirks) vs **Electron** (consistent Chromium rendering;
  heavy). Lean Tauri. Native Swift/WinUI is *not* cross-platform.
- **Local LLM** — which small model to bundle for Tier 2; size/perf budget.
- **Server stack** — the crane.glick.run app (likely Node + SQLite per AppCrane conventions);
  dashboard framework.

## Sources

NIST AI 600-1 · OWASP LLM Top 10 · OWASP Agentic Threats & Mitigations · NCSC · FBI AI Data
Security · Microsoft (Copilot architecture; AI-as-tradecraft) · FBI IC3 2025 Report. Full URLs
in [`data/threats.json`](../data/threats.json).
