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
