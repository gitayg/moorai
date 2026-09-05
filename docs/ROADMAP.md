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
- **DONE (v0.65.0) — evidence interchange:** the same content-free record now exports in the formats the
  wider ecosystem consumes — OTLP spans (v0.62.0), **STIX 2.1** (v0.64.0), and now an **in-toto
  attestation / SLSA provenance predicate** (`cli/moorai-attest.mjs`) built only from the content-free
  fields, so the agent's action evidence answers the software-supply-chain attestation gap. The AIBOM
  also exports as a standard **CycloneDX 1.6** / **SPDX 2.3** SBOM (`moorai-aibom --format …`).
- **DONE (v0.66.0) — obfuscation-evasion hardening + coverage benchmark:** a bounded, DoS/ReDoS-capped
  decode/normalize pre-pass (`data/normalize.js`, wired additively into `src/engine.js` `scan()`) re-runs
  the detectors over decoded/reversed variants, so encoded/obfuscated payloads (CipherChat base64/hex/
  rot13/caesar, FlipAttack reversal, h4rm3l composed transforms) that defeat plain-text scanning are now
  caught; plus a content-free `inj-jailbreak-templates` detector for DAN/AutoDAN/AdvPrefix artifacts. A
  deterministic, LLM-free red-team coverage benchmark keyed to the HackAgent taxonomy (`scripts/redteam-eval.mjs`,
  `test/redteam/corpus.json` `hackagent` set) measures it: **detection coverage 35% → 61%**, precision 95%
  (1 benign FP to chase), with **PAP / TAP** left BLIND by design (semantic/multi-turn → model-escalation,
  not a faked regex). `scripts/moorai-validate-blocking.mjs` proves the ACTION layer holds even after a
  hijack: **12/12 malicious tool calls denied (100%)** under an enforcing policy.
- **DONE (v0.67.0) — coverage lift + productionized detectors:** six additive content-free detectors
  (`inj-untrusted-directive`, `mcp-tool-poisoning`, `mcp-hidden-canary`, `egress-credential-shaped`,
  `inj-perturbed`, `inj-jailbreak-autodan`) took deterministic coverage **61% → 77%** (BoN 1/4→4/4,
  AutoDAN 2/4→4/4), and the on-device semantic-escalation path (`--semantic`) became functional,
  recovering the PAP family with a live local model (~94% with the model at the time).
- **DONE (v0.68.0) — 100% HackAgent coverage, deterministically:** a weighted persuasion-tell +
  crescendo-trajectory analyzer (`data/crescendo.js`; `persuasion-jailbreak` + `semantic-persuasion`
  detectors) closes the last three families — **PAP, PAIR, TAP** — keying on rule-suspension /
  false-authorization / fiction-disclaimer framings rather than keywords. **Deterministic coverage
  35% → 100% (31/31)** at 97% precision (the same single pre-existing benign FP; zero new FPs). Two
  honest caveats remain: (a) precision is measured on only 7 benign controls — real-corpus FP behavior
  of the persuasion detector still needs tuning against a larger benign distribution; (b) **RESOLVED in
  v0.69.0** — `escalate()` / `scanSemantic` (the `d.semantic:"detect"` gate) now has a production caller.
- **DONE (v0.69.0) — semantic layer wired into the enforcement hot path:** both `maybeEscalate`
  entrypoints (`cli/moorai-hook.mjs`, `cli/moorai-guard.mjs`) now run the engine's `escalate` (detect/
  confirm gate) + `escalateMiss` (miss-recovery) orchestration instead of calling `classifyOpportunistic`
  directly, so the `semantic-persuasion` detect gate fires in production and a model-flagged persuasion is
  attributed to its taxonomy threat (#2) rather than only the generic #58. Gated by **both**
  `policy.modelEscalation` AND `semanticEnabled(policy)` (AND — can only narrow, never widen; OFF by
  default), a single bounded model call shared across both levers, fully fail-open, F-301 ordering intact
  (escalation strictly after any deny). Proven by `test/hook-escalation.test.mjs` (7 tests, structural +
  behavioral through the real engine) with deterministic coverage unchanged at 100%. Also repaired
  `test/semantic-coverage.test.mjs`, which v0.68.0 left red: its miss-recovery tests assumed PAP/PAIR/TAP
  were deterministically BLIND (true before v0.68.0) — they now use a synthetic guaranteed-miss span so the
  mechanism stays under test as the detectors improve.
  Remaining open follow-up: the still-open precision-tuning item (a) — a larger benign corpus + held-out
  attack split, so the 100% is a generalization claim, not an in-sample one.
- **DONE (v0.70.0) — generalization + precision measured honestly:** built a **178-prompt benign corpus**
  (`test/redteam/benign-corpus.json`, incl. 61 adversarially-shaped hard negatives) and a **29-sample
  held-out attack set** (`test/redteam/heldout.json`, fresh per-family paraphrases the detectors were never
  tuned on). `scripts/redteam-eval.mjs` now reports **in-sample vs held-out recall separately** and
  precision over the full benign corpus. The in-sample 100% was masking the real picture: **precision was
  actually 83%** against a realistic benign set and **held-out recall is 90%** (26/29). Three principled,
  evidence-driven tuning edits to `data/crescendo.js` (scoping-preposition negative-lookahead on
  `no-restrictions`; demoting `rules-suspended` and `off-limits` from fire-alone to corroborating) removed
  8 false positives with **zero recall lost** → **93% precision** (4 FP/178, 2% FP rate), tune 31/31,
  held-out 26/29. The defensible claim is now **"90% held-out recall @ 93% precision on the HackAgent
  taxonomy."** The 3 held-out misses are novel DAN/AutoDAN/AdvPrefix phrasings in the `inj-*` detectors
  (not `crescendo.js`) — the remaining generalization gap, tracked. On-device `--semantic` recovered 2/3 in
  a sampled run (~97% held-out) but is opt-in/environment-dependent, so not the headline.
- **DONE (v0.71.0) — inj-* generalized from literals to structural slots (Wave A):** the three v0.70.0
  held-out misses shared one root cause — the `inj-*` detectors matched enumerated literals, not concepts.
  `data/injection-tells.js` (NEW) replaces the literal lists with **slot patterns + weighted corroboration**
  (the model ported from `crescendo.js`): {override verb}×{authority object} (incl. system/developer
  message, your own ruleset), prefix-forcing in either word order with a vocabulary-free quoted-opener
  path, and persona-bypass as a co-occurrence gate (named persona AND policy negation). Three new detectors
  in `data/detectors.js` (`inj-override-structural` #3, `inj-prefix-forcing` #2, `inj-persona-bypass` #2),
  content-free, `safeRegex`-compiled, memoised, size-capped. All 3 prior misses now caught with **precision
  unchanged (4 FP/178)**; `test/injection-tells.test.mjs` proves generalization on novel phrasings not in
  any corpus (and caught a real case-sensitivity bug in the persona verb during integration).
  **CAVEAT — the held-out number is now BURNED:** those 29 samples were the target of this fix, so the
  post-Wave-A "held-out 29/29" is NOT a valid generalization measure. The public claim stays **90% held-out
  @ 93% precision** until **Wave B** builds a FRESH held-out set (adversarial mutation generator + 100+ new
  samples) and re-measures the real out-of-sample number — which may honestly land below 100%.
- **DONE (v0.67.0) — signed decision receipts + offline verifier:** `cli/moorai-receipt.mjs` emits a
  content-free per-verdict receipt (strict field allowlist → SHA-256 digest → ed25519 signature via the
  existing `agency-sign` per-device key), and `moorai-verify-chain --offline <file>` verifies a receipt or
  an in-toto attestation with no network (recompute digest → reject tampered payloads → check signature
  against a pinned key). Generation fail-open, verification fail-closed; 13 falsify-first tests including a
  planted-secret content-free assertion.
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
- **DONE (v0.64.1) — lineage wired + honeytoken canary:** `cli/moorai-hook.mjs` now stamps every
  agent event with a content-free `agent`/`session` id (hashed `session_id`), and a `Task` delegation
  emits a handoff edge (`role:"handoff"`, `parent`, `to:<hashed subagent_type>`). That activates
  **cross-agent-messaging** detection on real delegations and gives **trace-gap** per-session grouping.
  Honeytokens are wired into the enforcement path: each matched span's content hash is checked against
  the registered canaries (`checkHoneytoken`), firing a Critical alert on a hit — guarded against the
  `NO_KEY` sentinel so an unenrolled device is inert rather than noisy.
- **DONE (v0.65.0) — subagent lineage wired:** the earlier assumption was wrong — Claude Code's
  PreToolUse payload DOES expose subagent lineage: a subagent's own tool-call hook stdin carries
  `agent_id` + `agent_type` (verified against the hooks docs and real `~/.claude/projects/.../subagents/`
  transcripts; `session_id` stays equal to the parent, so `agent_type` is the distinguishing key).
  `cli/moorai-hook.mjs` now attributes a subagent's events to the subagent as a **distinct actor**
  (`agent = contentHash(agent_type)`, keyed on type so it joins the Task handoff edge), with the spawning
  session as `parent` and `role:"subagent"`. This also fixed a real bug: `data/agent-baseline.js` was
  grouping by the `sig` target slot (so the "per-agent" baseline was per-*target*) — it now groups by the
  `agent` id, so each subagent type is profiled separately and cross-agent-messaging / trace-gap group
  correctly. Content-free (all ids one-way hashed); inert on unenrolled devices (`NO_KEY`).
- **DONE (v0.67.0) — first learned-deviation detectors:** `data/agent-detections.js` gained three
  content-free behavioral detectors scored against each actor's *own* window — **velocity-burst** (cadence
  above the actor's robust median/IQR), **confused-deputy** (an injection tell followed by a sensitive
  action in the same actor's window), and **fan-out-anomaly** (a spawning actor delegating to abnormally
  many subagents) — wired into `agentBaselineReport`. This is the first cut of the "flag deviation from an
  actor's own norm" bar; thresholds are chosen for explainability and still need tuning against a real
  recorded distribution.
- **TODO — orphan detector + tune:** orphan-agent detection stays inert for real subagents — a subagent
  self-attests its own session (= parent id) and the payload exposes no parent-*agent* chain (only the
  leaf `agent_id`/`agent_type` + root session), so `missing-parent` cannot fire without fabrication; left
  intact rather than forced. Weights/thresholds remain chosen for explainability — tuning still needs a
  real recorded corpus (none exists yet).

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
