# MoorAI — Backlog

## Profanity masking — a "mask" action (#53)

**Idea:** Instead of blocking, soften the AI's reply for younger kids by masking profanity
(replace with `****`) in what's displayed, rather than stopping the message.

**Why deferred:** needs (1) a new action type "mask" alongside disabled/alert/notify/block in the
policy model + dashboard, and (2) host-side rewriting of claude's live PTY output stream before
xterm renders it — which risks the TUI ghosting we just fixed. Higher-risk than its value.

**To do when picked up:**
- Add "mask" as a content-category action (response side only).
- Intercept `term-data` (AI output) in the host; for masked categories replace matched profanity
  with `****` before `term.write`, without breaking escape sequences / cursor positioning.
- Surface masked events in the Detection drawer.

## Cross-AI coverage — one on-device filter for every AI (the wedge)

**Idea (#80 from the competitor sweep):** Build/position MoorAI as a single on-device guard that
reviews prompts *and* responses across **every** AI surface — ChatGPT, Claude, Gemini, Copilot,
Character.AI, and any CLI/agent — not just the bundled `claude` terminal. No parental or DLP product
today does cross-AI, on-device, prompt-level review; that gap is the core differentiation.

**Why it matters:** families and orgs use many AIs at once. A guard tied to one app misses the rest.
On-device + cross-AI + prompt-level is the open niche to own.

**To do when picked up:**
- Capture per surface: browser AIs (extension/proxy hook), desktop apps (ChatGPT/Character.AI),
  CLIs/agents (the existing `claude` path).
- Run the same threat + content + DLP policy on every captured prompt/response.
- Unify findings + the device/tenant inventory across all surfaces in one view.

## Multilingual detection via the LLM tier

**Status:** deferred (proper fix identified).

**Gap:** Tier-1 detection is split by match type. Pattern-based detectors (emails, national IDs,
payment cards, IBANs, API keys, private keys, JWTs, phone numbers, code blocks, URLs) are
**language-agnostic** and already work in any language. But **keyword/phrase** detectors are
**English-only** and miss non-English content: prompt-injection (`"ignore previous instructions"`),
BEC ("change bank details"), IP markers ("roadmap/confidential"), and **all parental content
categories** (profanity, sexual, violence, etc.). A Hebrew/Spanish/etc. injection or profanity
prompt slips past.

**Why not per-language keyword lists:** brittle, unbounded maintenance, poor recall.

**Fix — escalate to the LLM tier:** use the spec's **Tier-2 local LLM** to classify a prompt/response
against the threat + content policy **across languages**, no keyword lists. Keep it **local-first**
(no egress) — and we already detect **Ollama on-device** in the inventory, so the local model is
often already present. Flow: Tier-1 regex (fast, language-agnostic) → on ambiguity / for
behavioral+content categories, Tier-2 local LLM judges in any language → verdict feeds the same
disabled/alert/block policy. Cloud (Tier-3) only if policy allows, on redacted signals.

**Also (separate, smaller):** UI i18n — extract strings to locale files (en/he/…), language switch,
RTL handling for Hebrew/Arabic.

## SIEM export — per-account, from the MoorAI server

**Status:** deferred (spec'd).

The MoorAI **server** (not the client) forwards each tenant's redacted detection feed to that
tenant's SIEM. Defined **per account** in the dashboard: each tenant configures its own destination
(Splunk HEC / Microsoft Sentinel / generic JSON webhook URL + token). On each ingested alert, the
server POSTs the redacted event to the tenant's configured endpoint. Borrowed from Cequence's
"exportable logs to SIEM." Secrets (HEC tokens) stored server-side per tenant; never in the client.

**To do:** a `siemConfig:<tenant>` setting (URL + token + format), a dashboard config panel under the
tenant, and a forwarder in the alert-ingest path with retry/backoff.

## Agent Personas + MCP trusted registry (from Cequence AI Gateway)

**Status:** deferred. Plain-language agent role → auto least-privilege tool set; per-tenant trusted
MCP-server registry with per-tool risk scoring. Pairs with the v3 MCP-gateway enforcement layer.

## Images (paste / drag-drop / upload) — host wiring remains (#9)

**Status:** server side DONE (v0.8.29). The **vision/OCR tier exists**: the admin configures a
bring-your-own vision key in the console (encrypted, per tenant), and `POST /api/ocr` (install-token
auth) extracts an image's text via the org's own provider (Anthropic/OpenAI) and returns it. The
key stays server-side; `/api/policy` advertises `imageInspection.enabled`. **Remaining: the
host-side wiring** so a pasted/dropped image is actually inspected + delivered.

**Remaining gaps:**
1. **Host inspection flow.** On image paste/drop, if `imageInspection.enabled`, the host should
   base64 the image → `POST /api/ocr` → run the existing detection engine on the returned text →
   apply the policy (disabled/alert/notify/block) just like text.
2. **Delivery.** The terminal can't ingest an image through MoorAI. On a clean image: write it to a
   temp file and feed `claude` the path (claude reads image files), or wire native image-paste.

**To do when picked up:**
- Wire `src/app.js` image handling to call `/api/ocr` (via `src/api.js`) and run `engine` on the text.
- Surface image findings in the Detection drawer like other detections.
- Temp-file + path delivery for approved images.

**Current behavior (interim):** dropped/pasted images show an "Image — content not inspected
(needs a vision/OCR tier)" card and are logged; nothing is sent to the agent.

## AI proficiency / prompt-quality score — on-device, coaching-first

**Idea:** Score how skilled each person is at using AI — an "AI proficiency" / prompt-engineering
quality metric — computed **on the device** (where the prompt is already in cleartext for detection)
and emitted **content-free**: only the score and sub-scores leave, never the prompt. Extends the
"AI-enabled employees / AI-accelerated team" positioning from "are they leaking?" to "are they using
AI *well*?" No security competitor (Glow, Salt, Cycode, Zscaler) measures skill — this is open ground.

**Signals (all derivable locally, no egress):**
- **Structure** — role/context set, constraints, few-shot examples, explicit output format, task
  decomposition (engineered prompt vs. one-liner).
- **Iteration / rework** — retries & reformulations before a usable result; turns per task (novices
  thrash, skilled users converge).
- **Hygiene** — secrets/PII/policy-hit rate, block & override rate (*already collected today*).
- **Context discipline** — targeted context vs. pasting giant blobs; sensible MCP/tool use.
- **Outcome proxies** — refusal/error rate, output accepted vs. discarded.
Roll into a 0–100 score + sub-scores.

**Local-model tier (pairs with the Tier-2 local LLM, "Multilingual detection" above):** a small
on-device model grades each prompt against a clarity/specificity/context/safety rubric and emits only
the score — nuanced quality with zero prompt egress. Best use case for local inference: it needs
cleartext, and on-device is the only place that's allowed.

**Guardrails (brand-critical — do NOT skip):** this is one design choice away from employee-
productivity surveillance, which "governance without surveillance" exists to reject. Build it as:
1. **Coaching, not ranking** — the score drives inline tips shown *to the user* (like coach mode).
2. **Aggregate to the org** — fleet proficiency trends and where enablement is needed, *not*
   per-person leaderboards (per-person only with explicit opt-in).
3. **Framed as enablement** — a board-level adoption metric, sibling to the AI-readiness score.
A named per-person leaderboard is a brand landmine; do not ship one.

**To do when picked up:** on-device signal extraction in the engine/hook; a proficiency scorer
(heuristic first, local-LLM rubric later); coach-mode tips keyed to the weakest sub-scores; an
aggregate "AI proficiency" panel in the console beside AI-readiness.

## OWASP LLM Top 10 posture scorecard — in the admin console

**Idea (from the GuardAI competitive sweep):** an assessment/scorecard that rates the org's AI setup
against the **OWASP LLM Top 10** (+ NIST AI RMF, ISO/IEC 42001) and outputs specific fixes — e.g.
"MCP server X has no allow-list → LLM06 Excessive Agency." **Surfaces to the ADMIN in the console**
(not a per-device CLI): it rolls up the content-free device signals + the AIBOM inventory the fleet
already reports. Pairs cleanly with what exists: **AIBOM inventories, AI-readiness scores, this
assesses against a named standard auditors know.** GuardAI's whole product is this check-up; MoorAI
can do it content-free from data it already has.

**To do:** a `/api/assessment` endpoint mapping existing signals → OWASP LLM items; a console
"Assessment" tab with per-item pass / warn / fail + remediation text; export alongside the AIBOM and
readiness report. We already have the positioning page (`owasp-llm-top-10-tooling.html`) with no tool
behind it — this is the tool.

## Expose the red-team suite as a customer trust test

**Idea (from the GuardAI ML-testing angle):** `scripts/redteam.mjs` (57/57 internal) proves the engine
catches its attack corpus — but only we see it. Expose it (`moorai-redteam`, or a console "Test my
policy" action) so a customer runs the adversarial corpus against **their own ACTIVE policy on their
own machine** and sees the coverage. Turns an internal test into a trust feature: "verify, don't
trust." Content-free; maps results to the OWASP LLM attack classes.

**To do:** a CLI that loads the tenant policy + runs the corpus + reports pass/fail per threat class;
optionally a console button that shows the same coverage grid per tenant.

## "AI-integrated development pipeline" positioning (copy)

**Idea (from the dev-pipeline GuardAI):** frame MoorAI as securing the **AI-integrated development
pipeline at the endpoint** — the pipeline starts on the developer's machine, upstream of the CI/SCA
tools (Cycode, Salt) that only see risk once code is committed. MoorAI is the *first* control point.
Copy-only; lands on the MoorAI hero/positioning and as a vs-page angle. Sharpens the developer story
without overclaiming a full pipeline/CI product.

## Autonomous remediation (guarded)

**Idea (from GuardAI "autonomously neutralizes threats"):** beyond block — high-severity auto-actions.
Flag exposed credential classes for rotation (ties to the **exposure ledger**), auto-disable an
unapproved MCP server, or freeze an agent fleet-wide. **Same guardrails as the AI-proficiency item are
mandatory:** opt-in, per-policy, reversible, fully audited, and human-in-the-loop for anything
destructive (rotation/disable). Powerful, but the blast radius is real — keep it gated.

## Deferred from the Endor / Bold competitive build (2026-08-05)

Shipped in this pass: detect→prevent detectors (reverse-shell/cred-file/mcp-destructive/pkg-install),
content-free actor hash (#10), `npm run benchmark` (#16), one-line installer (#17), console **Event
Flow** data-lineage screen, and the Bold set — on-device model escalation (**B1**, `data/model-escalation.mjs`,
opportunistic Ollama, off by default), UBA + agent-vs-human (**B2/B4**, `/api/actors`), alert
correlation metric (**B3**), evidence retention (**B5**, `MOORAI_RETENTION_DAYS`). Deferred:

- **Endor #4 — Custom regex policy DSL.** Admin-authored allow/block/audit rules over commands/files/
  prompts/tools. Plugs into `engine.applyPacks()` (already exists) + a server `policyRules:<tenant>` KV.
- **Endor #11 — Default policy packs.** Ship opinionated starter packs (à la Endor's 29 defaults),
  compiled via the same `detectorPacks` path.
- **Endor #18 — Per-tool MCP argument allow/deny lists.** Extend Agency Enforcement: per-tool arg
  schemas beyond the current allow-list + arg scan.
- **Endor #5 — Capture toggle + content-free action audit log.** Full file-level plan already produced
  (agent: `data/capture-tiers.js` + gate `moorai-hook`/`moorai-guard`/`signals`; server: `policyCapture`
  KV + tier-gated ingest + governance log). Off-by-default `content-free → metadata-plus → full-capture`,
  consent-visible. Pairs with **B5**.
- **Endor #20 — Cryptographic MCP call signing.** Sign approved tool calls, block unsigned — hardens
  Agency Enforcement past a name allow-list. Rust host (`src-tauri/.../lib.rs` `tool_allowed`).
- **Bold B6 — Per-actor behavioral anomaly / insider-risk.** Extend the autonomous-agent-behavior
  signature to per-actor baselines; feed the UBA score/anomaly in the Event Flow "Actor" tab.
- **Fix — threat #39 OWASP tag.** The secrets engine (18 detectors) maps to threat 39, tagged
  **LLM07** ("Prompt Leakage"); secrets are **LLM02** (Sensitive Information Disclosure). One-line data
  fix (`threat 39.owasp: LLM07 → LLM02`), corpus-safe. Surfaced by `npm run benchmark`.

---

## Deep-market sweep (2026) — Tier-2/Tier-3 + GTM + Tier-1 deferrals

Sourced from the 2026 competitive analysis (ServiceNow AICT, Endor, Backslash, Certiv, MCP-security
tooling, AI-SPM, AI-governance + non-human-identity, GTM). Tier-1 Top 5 already shipped in v0.43.0
(agent) / v0.34.0 (console): model-endpoint allow-list, slopsquat firewall, MCP hardening (invisible-
payload + rug-pull drift), jailbreak detectors, entitlement envelope.

### Shipped in this batch (v0.44.0 agent / v0.35.0 console)
- **Secret-egress fingerprinting** (#65) — fingerprints local secret values (project `.env`, cloud creds)
  as one-way hashes on-device; flags/blocks when a value appears verbatim in an outbound command / MCP
  arg. `cli/secret-egress.mjs`; wired in the hook (Bash + MCP). Content-free (only the hash + verdict leave).
- **Insecure-defaults / expanded-sink pack** (#61) — SSRF, path traversal, XXE, JWT `alg=none`/verify-off/
  hardcoded-secret, TLS-verify-off, permissive CORS, `debug=True`/`ALLOWED_HOSTS=*`, insecure randomness,
  hardcoded creds, `chmod 0777`, insecure cookies, CSRF-off, open redirect, public cloud storage. ~27
  regexes in `code-insecure-defaults`, output-stage, keyword-gated / placeholder-excluded.
- **A2A / sub-agent delegation detection** (#66) — hook intercepts the `Task` tool: records the delegation
  content-free, scans the delegated prompt for injection, applies the parent's entitlement envelope.
- **agent→server MCP config-hash reporting** — `/api/device-report` now feeds each reported server's
  config hash into the registry, so a silently-changed server flags as drift (drift UI shipped v0.34.0).
- **Cross-server toxic-flow correlation** (v0.46.0) — SHIPPED. Each content-free agent event now carries a
  `server` attribution (parsed from `mcp__<server>__<tool>`; `local` for Read/Bash/Task).
  `assessCrossServerTrifecta(events)` in `data/agent-behavior.js` attributes each trifecta leg to the
  server that produced it and reports `crossServer:true` when the three legs cannot be pinned on any single
  server (confused-deputy the single-server scanner misses). The hook (`logBehavior`) emits a distinct
  content-free alert reusing threat 59 with `category: "Cross-server toxic flow"` and a signature listing
  the contributing servers per leg. Same-session trifecta alert unchanged; enforcement-neutral (fail-open).

### Deferred (refinements / heavier)
- **Fleet AI-BOM export** — ALREADY SHIPPED (`/api/aibom` + `/aibom/export` JSON+CSV, `store.aibom()`);
  no work needed. Listed here only to record it's covered.

### Deferred — data / model / infra pipelines (not a coding-session task)
- **Full registry Bloom filter** (slopsquat completeness) — answer "does this npm/PyPI/crates name exist?"
  fully offline. Needs a build pipeline that downloads ~4M names + ships a binary Bloom filter in the
  notarized DMG (size decision). Today: curated popular-list + edit-distance covers the high-value squat
  *targets*. Design doc produced (see the market-sweep agent output); implement the BUILD script + loader.
- **PromptGuard-2 (22M) on-device classifier** — bundle the ONNX weights + a JS/Rust inference runtime
  into the DMG for ML jailbreak escalation. Detectors shipped; local-model escalation already runs via
  the existing Ollama hook. Blocker: DMG size + notarization + runtime choice.
- **Tool-description injection scan** (MCP) — needs the agent to capture MCP `tools/list` schemas (not
  currently fetched); then run the injection engine + invisible-payload scan on tool descriptions at
  discovery time (line-jumping defense). Pairs with schema-hash pinning.
- **Intra-file taint-lite** — tree-sitter source→sink dataflow to confirm injection detectors and cut
  false positives. Deferred: tree-sitter is a heavy dep; scope to intra-file (whole-repo reachability is
  on-device-hard).
- **JIT capability elevation** — minimal standing entitlement envelope + time-boxed, auto-expiring grants
  ("write to /deploy for 30 min") instead of per-call prompts. Needs a TTL grant state machine (server
  policy + agent honoring). Medium; sequence after the envelope beds in.

### GTM / positioning track (content + external — see the glick.run repo draft)
- **Reposition** the site to "content-free, open-core AI coding-agent security — at the endpoint"; lead
  with content-free-vs-tokenization (drafted in glick-run-website, pending review + deploy).
- **Shadow-agent discovery wedge** messaging; **per-device pricing** (free AGPL agent + paid per-device
  console) — drafted.
- **Trust pack** — (a) publish a versioned, reproducible detection benchmark (docs/BENCHMARK.md → public
  page); (b) commission a **third-party zero-egress audit** (external engagement — the AGPL agent makes
  it cheap); (c) **SOC 2 Type II** for the console (org process). (b) and (c) are not code — track as
  business tasks. Court the Gartner AI-SPM Market Guide (H2 2026) as the content-free/open-core entrant.
- **Beachhead** — regulated/high-IP verticals (fintech, defense, pharma, legal) where "content never
  leaves the device" is a hard requirement.
