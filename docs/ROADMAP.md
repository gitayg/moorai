# MoorAI roadmap

Tracked work items that are known and deliberate, not yet built. Keep this honest — it's where the
gaps we've named in positioning go so they don't get lost. Close an item by shipping it and moving the
note into the changelog/commit history.

## Evidence-layer gaps (from the "AI's Evidence Problem" framing)

Context: the content-free OTel export (v0.62.0, `cli/otel.mjs`) makes MoorAI a content-free *source*
into a SIEM/telemetry pipeline. Two honest gaps remain against the bar that governance frameworks
(OWASP Agentic 2026) and the Hughes "AI's Evidence Problem" piece set. We should not overclaim past
these in marketing (the blog posts are careful to say "tamper-evident" and "signed," never "immutable"
on-device).

### 1. Immutable evidence via the stream (not just tamper-evident on-device)

**Today:** on-device signal logs (`~/.moorai/action-audit.jsonl`, exposure ledger, agent-events) and
the anti-rollback latch are **tamper-EVIDENT** — signed (ed25519 agency trail) and written across
multiple deliberately-different directories so erasure is *detectable*, and the ratchet fails closed.
They are **not tamper-PROOF**: a local actor with the right access can delete them; we detect the
erasure, we don't prevent it.

**The gap:** "immutable logging" as the frameworks mean it (WORM / append-only, un-deletable evidence).

**Direction:** make the **off-device stream the immutable record** rather than trying to make the
endpoint a WORM store. The OTel/SIEM copy already leaves the device append-only from the endpoint's
point of view; position and document *that* as the durable evidence store.

- **DONE (v0.62.2):** per-record tamper-evidence in the stream — every emitted span carries
  `moorai.record_hash`, a **tenant-keyed HMAC** over the record's canonical content-free fields
  (`cli/otel.mjs` `canonicalRecord` / `recordHash`). An attacker who alters a field in the SIEM copy
  can't recompute a matching hash without the tenant key, so a *modified* record is detectable.
- **DONE (v0.64.0) — gap/reorder detection:** a linked **prev-hash chain + monotonic sequence**
  (`cli/record-chain.mjs`, borrowed from AgentDFIR's hash-chained custody log). Every on-device
  evidence-log line (`cli/signals.mjs` `append`) and every emitted OTel span (`cli/otel.mjs`,
  `moorai.record_seq` / `record_prev` / `record_chash`) now carries a keyless SHA-256 chain link over
  the previous record, so a *removed*, *reordered*, or *inserted* record breaks the chain — detectable
  by `moorai-verify-chain` locally and by seq-gap on the SIEM stream. The cross-process race is handled
  fail-open (lock-free head advance; a rare fork is surfaced by `verifyChain` as an anomaly, never
  dropped or blocking). The two hashes are complementary: keyed `record_hash` proves per-record
  authenticity, keyless `chash` proves cross-record continuity once the stream anchors the head.
- **TODO (optional):** local append-only hardening (platform WORM/immutable-flag where available) as
  defense-in-depth.

The honest line is now "signed + per-record tamper-evident, chained for gap/reorder detection, and
immutable once streamed." Still **not** tamper-PROOF on-device (a local actor can delete; the chain
makes the deletion detectable once the head has been streamed off-device).

### 2. Learned per-agent behavioral baseline (non-human digital actor)

**Today:** behavioral detection is **signature/heuristic** — the 8-tell autonomous-agent signature
(`data/agent-behavior.js`), the lethal-trifecta and cross-server toxic-flow detectors. Fixed rules,
not a learned norm.

**The gap:** a **per-agent learned baseline** — treat each agent as a non-human digital actor and flag
deviation from *its own* established behavior (tool mix, cadence, destination set, data classes), not
just matches against fixed signatures. This is what the "behavioral baseline for a non-human actor"
language in the agentic-security guidance is asking for.

**Direction:** build it on the content-free event history that now flows through OTel + the local
`agent-events.jsonl` window — per-actor profiles over hashed features (tool, server, risk, destination
class, timing), with deviation scoring. Content-free by construction (features are already hashes/metadata).
Pairs naturally with #1: the streamed history is the training/evaluation substrate.

**Status:**
- **DONE (v0.63.0) — the compute engine:** `data/agent-baseline.js` (`buildBaseline`, `scoreDeviation`,
  `scoreWindow`) builds per-actor content-free profiles (tool / risk / server / legs distributions +
  robust median/IQR cadence) and scores how anomalous an event/window is FOR THAT ACTOR, with
  explainable top factors and cold-start damping. Pure, deterministic, no deps, no I/O.
- **DONE (v0.64.0) — consumed + surfaced + forensic detections:** `data/agent-baseline.js` now reads
  the `agent-events.jsonl` window (`agentBaselineReport`) and `cli/moorai-agentwatch.mjs` renders the
  per-actor baseline. Added three content-free AgentDFIR-style detectors (`data/agent-detections.js`):
  **orphan agents** (child event with no parent lineage), **cross-agent messaging** (handoff to a
  different agent / shared destination), and **trace gaps** (missing monotonic `seq`/`step`, truncated
  session, or a cadence break). Trace-gap's step branch is live today because `append` now stamps the
  chain `seq` on every event row (see #1).
- **TODO — activate lineage + tune:** orphan / cross-agent detectors only fire once the hook emits the
  content-free lineage fields (`parent` / `session` / `agent` / `target`) — today `recordAgentEvent`
  (`cli/moorai-hook.mjs`) emits `{ts, sig, ok, risk, flags, legs, server}`. Add those fields in the hot
  path, then tune weights/thresholds on real recorded traffic. Until then, signature detection plus the
  now-live trace-gap and baseline surfacing are the shipping story.

## Adjacent / optional (tracked here so they don't get lost; not agent-repo core)

- **Release gate — identifier flip validation.** v0.61.0+ must not be tagged/released until the
  bundle-ID flip (`run.glick.curaiq` → `run.glick.moorai`) is validated on a real **Windows (NSIS
  upgrade/side-by-side)** box + a **Mac**. Mac validated (a real build produces `MoorAI.app` /
  `run.glick.moorai` / binary `moorai`); Windows is BLOCKED on an offline Atom/Windows box. See
  [[moorai-identifier-flip-gate]] and packaging/mdm/README.md §9.
- **Cost / token / latency dashboards** — a competitor table-stakes gap, but **console-side**: the
  usage/cost *signal* already exists on-device (`cli/moorai-aibom.mjs` `usage()`), and the OTel export
  (v0.62.0) can feed any dashboard. The dashboard UI itself belongs to the proprietary management
  console (separate repo), NOT this agent repo. No agent-repo work; build it in the console.
- **`moorai-vs-zscaler` marketing page** (glick.run / `glick-run-website`) — recommended in the
  competitor review, not built. Lower priority: many `moorai-vs-*` pages already exist. Website repo,
  not this one; clone an existing `moorai-vs-*.njk` if/when wanted.
- **Deeper competitor gaps already covered elsewhere:** shadow-AI discovery, content-free trace/
  session replay, and compliance-evidence packs all shipped in v0.63.0. Semantic/embedding detection
  and a learned baseline (#6 above) remain the open detection items.
