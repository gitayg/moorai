# MoorAI — Competitive Landscape (5 new players) + 30 Improvement Ideas

_Research + ideation memo. Compiled Sept 2026. Focus stays in MoorAI's own domain: runtime AI-agent security, content-free evidence, and the multi-tenant console. SDLC / spec / requirements-governance ideas are deliberately out of scope (they belong to a separate product)._

**MoorAI in one line:** on-device, content-free, action-layer security + attestation for AI coding agents — a PreToolUse hook + MCP stdio gateway + browser extension that evaluates a ~67-threat matrix locally, emits content-free evidence (category · risk · keyed one-way hash) into a tamper-evident prev-hash chain, and exports OTel + STIX 2.1 + in-toto/SLSA + CycloneDX/SPDX to a multi-tenant console.

---

## Part 1 — Five adjacent companies not previously analyzed

These are distinct from the vendors MoorAI already has vs-pages for (Zscaler, Netskope, Cycode, Endor, Socket, Snyk, Sonatype, SentinelOne, Lakera, Operant, dope.security, Zenity, BigID, Harmonic, Salt, Forcepoint, Bifrost) and from AgentDFIR / HackAgent / the KuppingerCole SSCS leaders.

| # | Company (URL) | What they do (one line) | Overlap vs MoorAI | Difference vs MoorAI | Relationship |
|---|---|---|---|---|---|
| 1 | **Straiker** — straiker.ai | Agentic-first AI security suite: Discover AI (inventory), Ascend AI (adversarial testing), Defend AI (runtime detection/enforcement). | Both do runtime detection + enforcement on agent behavior and tool calls; both emphasize agent-native (not just LLM-prompt) security. | Straiker is a cloud/SaaS runtime engine trained on agent traces (content-inspecting, ~300ms inline); MoorAI is on-device, content-free, evidence/attestation-first. Straiker has no tamper-evident chain or SLSA/in-toto exports. | **Direct competitor** (closest to MoorAI's action-layer thesis). |
| 2 | **Noma Security** — noma.security | Enterprise AI security platform: continuous AI/agent discovery, posture, red-teaming, runtime protection, plus Agentic Access Control for AI agents and MCP servers. | Runtime protection analyzes tool calls + MCP interactions; MCP governance overlaps MoorAI's MCP gateway. | Noma is a broad content-inspecting enterprise platform (prompt/response masking/blocking) sold to CISO teams; MoorAI is developer-installed, content-free, coding-agent-specific, with cryptographic evidence Noma doesn't produce. | **Competitor** (broader scope; overlaps at the MCP/agent runtime layer). |
| 3 | **Pillar Security** — pillar.security | End-to-end AI security lifecycle: asset/agent discovery, RedGraph red-teaming, and adaptive runtime guardrails ("AI firewall") against prompt injection, data leakage, tool abuse. | Adaptive runtime guardrails on agent inputs/outputs and tool abuse map onto MoorAI's action-layer verdicts. | Pillar's guardrails are content-aware and gateway-embedded (e.g. TrueFoundry); MoorAI's differentiator is content-free evidence + tamper-evident attestation, which Pillar does not offer. | **Competitor / adjacent** (guardrails competitor, but complementary on evidence). |
| 4 | **Astrix Security** — astrix.security | Non-human-identity (NHI) and AI-agent identity governance: discovery of shadow + enterprise agents, least-privilege authorization, audit trails. (Reportedly being acquired by Cisco; ended new standalone licenses mid-2026.) | Both discover agents and care about what an agent is permitted to do; identity is the natural key for MoorAI's per-agent baseline. | Astrix operates at the identity/authorization layer (who the agent is, what it can access) — not at MoorAI's per-action tool-call layer, and produces no content-free per-action evidence chain. | **Adjacent / potential partner** (identity context feeds MoorAI policy; MoorAI supplies the action-level evidence Astrix lacks). |
| 5 | **Knostic** — knostic.ai | Need-to-know access controls for the "knowledge layer" of LLMs — stops enterprise AI (Copilot/Glean) from oversharing data a user shouldn't reach, feeding user-specific policy to guardrails. | Both sit between an AI system and a sensitive action/answer and enforce policy in real time. | Knostic targets RAG/enterprise-assistant data oversharing by human users; MoorAI targets autonomous coding-agent actions. Little product overlap — different threat surface. | **Adjacent / potential partner** (complementary layer; not a competitor). |

**Sources:** [straiker.ai/products/defend-ai](https://www.straiker.ai/products/defend-ai), [Help Net: Straiker runtime](https://www.helpnetsecurity.com/2026/03/23/straiker-discover-ai/), [noma.security](https://www.noma.security/), [Help Net: Noma MCP access governance](https://www.helpnetsecurity.com/2026/06/02/noma-brings-visibility-and-access-governance-to-ai-agents-and-mcp-servers/), [pillar.security/platform](https://www.pillar.security/platform), [The Hacker News: Pillar walkthrough](https://thehackernews.com/2025/07/product-walkthrough-look-inside-pillars.html), [astrix.security](https://astrix.security/), [Help Net: Astrix agent security](https://www.helpnetsecurity.com/2026/03/23/astrix-security-ai-agent-security-platform-expansion/), [knostic.ai/what-we-do](https://www.knostic.ai/what-we-do).

_Notes on accuracy: Astrix's reported Cisco acquisition and mid-2026 license change are from press coverage; treat as reported, not confirmed by MoorAI. Straiker's quantitative claims (detection accuracy, false-positive multiples, latency) are vendor-stated. Invariant Labs (well-known MCP tool-poisoning research) was deliberately not chosen as one of the five because it was acquired by Snyk, who is already on MoorAI's analyzed list._

---

## Part 2 — 30 improvement ideas

Tags: `[detection]` `[evidence/attestation]` `[console/fleet]` `[integrations]` `[UX]` `[GTM/positioning]` `[compliance]`. Priority = product impact vs. differentiation; Effort is rough (S / M / L).

### `[detection]`

1. **Cross-call attack-sequence detection** — Score chains of tool calls (recon → privilege change → external write/exfil), not just isolated actions; emit a content-free sequence signature. Catches multi-step agent compromise a per-call matrix misses. _Priority: High · Effort: L_
2. **MCP tool-poisoning / description-drift guard** — Hash each MCP tool's name, schema, and description at first registration; flag when a tool's definition silently changes between sessions. Directly counters the Invariant-class tool-poisoning attack, content-free via hash diff. _Priority: High · Effort: M_
3. **Hidden-instruction canary in tool metadata** — Detect zero-width / Unicode TAG-block / homoglyph concealment inside tool descriptions and args locally, before they reach the agent. Addresses the documented "approval-view fidelity gap." _Priority: High · Effort: M_
4. **Directive-in-untrusted-content signal** — Flag when tool _outputs_ from untrusted sources (web fetch, PR titles, issue bodies, file contents) contain imperative/instruction patterns before they feed the next tool call. Counters the JHU PR-title secret-exfil class. _Priority: High · Effort: M_
5. **Credential-shaped egress heuristic** — Detect the _shape_ (entropy, known token/key formats) of secrets in outbound tool args without storing the value; emit `credential-shaped-egress`. Stays content-free while catching leak attempts. _Priority: High · Effort: M_
6. **First-seen network-destination flagging** — Raise risk when an agent calls a domain/endpoint never seen in that agent's history; novelty is a cheap, content-free exfil signal. _Priority: Med · Effort: S_
7. **Velocity / burst anomaly per agent** — Escalate risk on abnormal bursts of writes or rapid successive external calls relative to the per-agent baseline. _Priority: Med · Effort: S_
8. **Blast-radius weighting for verdicts** — Weight each verdict by target sensitivity (system dirs, persistence paths, CI secrets) × action type, so "write to `~/.ssh`" outranks "write to `/tmp`". _Priority: High · Effort: M_
9. **Confused-deputy / trust-boundary detection** — Flag when a high-privilege tool is invoked driven by low-trust input in the same session (untrusted content → privileged action). _Priority: Med · Effort: M_
10. **Subagent fan-out anomaly** — Extend the existing lineage baseline into anomaly detection: alert on spawn depth or fan-out beyond an agent's normal envelope (worm-like self-propagation signal). _Priority: Med · Effort: M_

### `[evidence/attestation]`

11. **Signed per-verdict decision receipts** — Sigstore/cosign keyless signature on each PreToolUse verdict so any single decision is independently verifiable, not just the chain. _Priority: High · Effort: M_
12. **Merkle-batch external anchoring** — Periodically Merkle-root the hash chain and anchor the root to an RFC-3161 timestamp / transparency log; cheap third-party proof the chain existed at time T. _Priority: High · Effort: M_
13. **Policy-version binding in every record** — Stamp each evidence record with the threat-matrix/policy version that rendered it, so an audit can reproduce exactly why a verdict was reached. _Priority: High · Effort: S_
14. **Standalone offline verifier CLI** — A tiny signed binary that verifies chain integrity + anchors + receipts with no console/network. Lets auditors trust MoorAI without trusting the SaaS. _Priority: High · Effort: M_
15. **Shareable read-only attestation link** — Time-bounded, scoped verification URL an auditor or customer can open to confirm a fleet's evidence integrity without console access. _Priority: Med · Effort: M_
16. **C2PA-style provenance manifests for agent-authored files** — Emit content-free provenance (which agent, which policy, chain pointer) for files an agent writes, so downstream systems can trace artifact origin. _Priority: Med · Effort: L_
17. **Content-free "no-content-stored" attestation** — A machine-verifiable proof that only category · risk · keyed-hash left the device — turning the content-free design into an exportable privacy guarantee, not just a claim. _Priority: High · Effort: M_

### `[console/fleet]`

18. **Fleet risk heatmap + top-N risky agents** — Console view ranking agents/tenants by rolling risk, surfacing the worst actors first. _Priority: High · Effort: M_
19. **Baseline-drift alerting across the fleet** — Alert when an agent deviates from its per-agent baseline (new tools, new destinations, new fan-out) — turns the baseline from passive record into active signal. _Priority: High · Effort: M_
20. **Policy-as-code with canary rollout + diff** — Version policies, roll a change to a subset of agents first, and show a before/after verdict diff before fleet-wide apply. _Priority: High · Effort: L_
21. **Console-driven quarantine / kill-switch** — One click to quarantine an agent identity (deny all high-risk actions) fleet-wide from the console for live incident response. _Priority: High · Effort: M_
22. **Content-free incident timeline replay** — Reconstruct a session's action sequence from the chain (categories, risks, timings, hashes — no content) for DFIR without ever exposing data. _Priority: Med · Effort: M_
23. **Anonymized cross-tenant benchmarks** — "Your agents' risk vs. peer cohort," built only from content-free aggregates; a sticky console feature no content-inspecting competitor can safely offer. _Priority: Med · Effort: L_

### `[integrations]`

24. **Native SIEM/SOAR apps + detection rules** — Beyond raw OTel/STIX: a Splunk/Sentinel app with prebuilt dashboards and correlation rules mapped to the 67-threat matrix. _Priority: High · Effort: M_
25. **ChatOps alert routing with justify workflow** — Slack/Teams/PagerDuty routing where a blocked action can be justified/approved in-channel, with the approval written into the evidence chain. _Priority: High · Effort: M_
26. **Broaden agent-runtime coverage** — First-class hooks for Cursor, Windsurf, Copilot, Gemini CLI, and OpenAI-style agent runtimes, so the same content-free evidence spans every coding agent a dev uses. _Priority: High · Effort: L_
27. **Identity-aware policy via NHI/IdP** — Map MoorAI's per-agent identity to Okta/Entra/Astrix NHI records so policy can key off least-privilege identity context (natural partner play with the Astrix/NHI category). _Priority: Med · Effort: M_

### `[UX]`

28. **Explainable verdicts + remediation** — Human-readable "why blocked," mapped to the exact threat-matrix entry with a suggested safe alternative, plus one-click promote-benign-action-to-baseline to cut false-positive fatigue. _Priority: High · Effort: M_
29. **Dry-run / shadow mode** — "What would MoorAI have blocked?" observe-only mode for frictionless onboarding and policy tuning before enforcement. _Priority: High · Effort: S_

### `[compliance]`

30. **One-click framework evidence packs** — Map the 67-threat matrix + chain evidence to NIST AI RMF, EU AI Act, ISO 42001, and SOC 2 controls, and export a signed, time-bounded auditor bundle. Makes MoorAI's evidence directly usable in an audit. _Priority: High · Effort: L_

---

### Idea summary by priority

- **High (17):** 1, 2, 3, 4, 5, 8, 11, 12, 13, 14, 17, 18, 19, 20, 21, 24, 25, 26, 28, 29, 30 _(core detection depth, verifiable/offline attestation, fleet response, broad coverage, and audit-ready compliance)._
- **Med (12):** 6, 7, 9, 10, 15, 16, 22, 23, 27 _(anomaly refinements, provenance, benchmarks, identity context)._

_All ideas are content-free-compatible and stay within runtime AI-agent security / evidence / console — none touch SDLC, spec, or requirements governance, and none restate what MoorAI already ships (tamper-evident chain, STIX, in-toto/SLSA, honeytokens, SBOM, shadow-AI discovery, per-agent baseline)._
