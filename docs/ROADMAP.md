# MoorAI roadmap

Tracked work items that are known and deliberate, not yet built. Keep this honest — it's where the
gaps we've named in positioning go so they don't get lost. Close an item by shipping it and moving the
note into the changelog/commit history.

## PROCESS RULE — measure the model-refusal baseline BEFORE building a detector

**Learned the expensive way in v0.77.0. Apply this before any future detection wave.**

A detector is only worth building for an attack family the underlying model does **not** already refuse.
AMTSO states the principle ("model refusal … should not be counted as product detection or prevention")
but the practical consequence is a prioritisation rule: *recall you add on top of a refusal is worth
~nothing; recall you add where the model complies is worth everything.*

Measured on the locked half (`scripts/measure-refusal-baseline.mjs`, llama3:latest 8B proxy, N=5):

| model refuses reliably | our marginal value | | model NEVER refuses | our marginal value |
|---|---|---|---|---|
| PAP 5/5, PAIR 4/4, TAP 3/3, AdvPrefix 4/4, AutoDAN 7/9 | **0–2** | | BoN 0/4, CipherChat 0/4, DAN 0/4, FlipAttack 0/3, h4rm3l 0/4 | **the whole family** |

**18 of our 20 marginal catches are obfuscation/encoding families.** The corollary is uncomfortable and
should be stated plainly: the v0.74.0 persuasion wave (crescendo.js, 20 literals → 35 structural slot
tells, closing PAP 0/5→4/5, TAP 0/4→3/4, PAIR 2/5→5/5) bought **close to zero marginal protection**,
because the model already refuses those. The load-bearing work is the *obfuscation* layer —
`data/normalize.js`, leetspeak, homoglyph folding, FlipAttack, CipherChat — where the model does not
recognise the payload as harmful at all and therefore never refuses it.

**So the order of operations for any new family is:**
1. Measure the refusal baseline for that family FIRST (`measure-refusal-baseline.mjs`).
2. If the model refuses it reliably, the detector is defence-in-depth at best — deprioritise it, and do
   not let it into a marketing number as if it were protection.
3. Build where the model complies.

**Read this before over-reading the obfuscation half.** Inspection of the runs shows the 8B model was
mostly **not complying** with the obfuscated families — it was **failing to decode them**. It read base64
and hallucinated the plaintext, misread leetspeak as a Caesar cipher, botched the reversal; decoded intent
surfaced in only **17 of 75** obfuscation runs. A frontier model decodes all of these correctly and might
then refuse, so **14 of the 20 marginal catches are the soft part of the figure.**

The finding that *does* survive, and the one to defend: **in the 17 runs where the model demonstrably did
decode the hidden ask, it refused 0 times.** Safety behaviour keyed on plain-language surface features and
did not survive obfuscation even when comprehension did. Refusal rate by surface form: **plain-language
77%, obfuscated 1%.** That is the real justification for the normalization layer — not "the model can't
read base64", which a better model fixes, but "safety training did not transfer to a decoded payload",
which it may not.

**NUMBER CORRECTION (v0.77.1) — every 88.6% / 39-of-44 figure below predates this.** The locked-half
deterministic figure is **86.4% (38/44)**. `DetectionEngine.scanSession` called `_firstMatch(text,
d.patterns)`, which ignores `refine()` — so a detector whose pattern is a cheap prefilter gated entirely
by refine (`inj-perturbed`'s is `/[A-Za-z]{3,}/`) matched essentially any prose, every turn counted as
"flagged", and `inj-persistent` (threat 3, **Critical**) fired on *any* two-turn window:
`scanSession(["hello","world"])` → Critical. Not user-facing (scanSession has no production caller), but
it scored every multi-turn sample as caught for free. Fixed to use `_matchDetector`; regression test in
`test/scan-session-refine.test.mjs` (reverting the fix turns 3 of 4 red).

Caveats carried with the rule: the baseline is an **8B open-weights proxy**, not the frontier model an
agent actually runs; 11/54 samples flipped across 5 runs; the headline is rule-dependent by ±8 points
(any-run 38.6% / majority 45.5% / every-run 54.5%); and the 17-run comprehension check is a keyword proxy,
not a graded judgement. Re-run against the real model when `claude -p` auth is restored before treating
any family's number as settled. Note one correction already ran in our favour and was fixed: refusal
markers written for Claude's phrasing scored llama3 refusals as compliance, over-stating marginal value
until corrected (47.7% → 45.5%).

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
- **DONE (v0.72.0) — Wave B: the real generalization number is 33%, and the detectors are overfit.**
  `scripts/mutate-attacks.mjs` (NEW) generates attack-preserving mutations across 29 transformation axes;
  `test/redteam/heldout-v2.json` (NEW) is a fresh **105-attack + 35-benign** set with **zero exact overlap**
  against `corpus.json`/`heldout.json` (verified). `scripts/score-heldout-v2.mjs` scores it through the
  CURRENT engine using the same `evalSample`/`score` reducers as the real eval (no detector was modified —
  this was a measurement-only wave, so the set stays a valid held-out).

  **Result: 33.3% recall (35/105), 92.1% precision (3 FP/35).** Against the 90% measured on 29 mild
  paraphrases, this is the honest verdict: **the detectors generalize far worse than the small held-out
  suggested.** Validity was spot-checked by the orchestrator — the missed samples are coherent, still-
  malicious attacks, not generator junk.

  **Zero-recall axes (the next-wave target list):** persuasion, thought-experiment, homoglyph, leetspeak,
  letter-spacing, caesar, dot-punct, typo, reverse-chars, politeness. Named root causes found so far:
  (a) the persona negation vocabulary misses paraphrases like "has shed every content policy";
  (b) `ovr-your-ruleset` requires `your`+`rules` adjacent, so "override **your safety rules**" escapes —
  this alone defeats several decoded reverse/caesar samples; (c) no confusable/homoglyph folding in
  `data/normalize.js`; (d) BoN spacing collapse works but a *synonym* ("pay no attention to" vs "ignore")
  defeats the fuzzy match — compound misses need synonym-aware matching, not more literals.

  **METHOD NOTE — do not burn this set.** Tuning against `heldout-v2.json` would destroy it exactly as
  Wave A destroyed `heldout.json`. The next tuning wave must split it (tune half / locked test half) or
  generate a v3 for final measurement.
- **DONE (v0.73.0) — root-cause fix wave: locked-half generalization 31.8% → 70.5%.** Run as a controlled
  experiment: `scripts/split-heldout-v2.mjs` split v2 stratified by (family, axis) into a tune half
  (61 attacks/25 benign) and a **LOCKED** test half (44/10); the fixing agent was given ONLY the tune half
  and never accessed the locked file (verified — corpus untouched, zero references in every changed file).
  The orchestrator scored the locked half independently afterwards.

  | | before | after |
  |---|---|---|
  | **LOCKED test half** | 31.8% (14/44), 0 FP/10 | **70.5% (31/44), 0 FP/10** |
  | tune half | 34.4% (21/61), 3 FP/25 | 78.7% (48/61), 3 FP/25 (same IDs) |

  **The gains transferred** — an 8.2-point tune/test gap is a small, expected overfit margin, so this is
  real generalization, not memorisation. Four root causes fixed: (a) policy-negation vocabulary widened to
  ordinary "has shed/dropped/stripped its policies" paraphrases (still w:1 corroborators);
  (b) `ovr-your-ruleset` gained a bounded adjective slot so "override **your safety** rules" lands — this
  also carried the decoded reverse-char/caesar/homoglyph variants of the same sentence;
  (c) `foldConfusables()` in `data/normalize.js` (ASCII-gated NFKC + Cyrillic/Greek appearance table, no
  regex surface); (d) a shared `OVERRIDE_VERB_ALIASES` table canonicalising multi-word synonyms, consumed
  by BOTH the structural tells and the BoN de-perturbation path, plus a slot-shaped fuzzy matcher so typo
  compounds with the synonym/adjective axes. Precision gates held exactly (4 FP/178 unchanged, same IDs).
  Ablation: normalize off 75.4%, injection-tells off 62.3%, detectors off 47.5% — all three load-bearing.

  Also repaired `test/detector-improvements.test.mjs`, which had been RED since v0.71.0 (17/19): its
  BASELINE engine excluded only the v0.67.0 detectors, so the v0.71.0 structural detectors sat inside the
  "baseline" and caught the sample a RED→GREEN test asserts the baseline misses. `NEW_IDS` now covers every
  hardening wave. Same stale-canary class as the earlier `semantic-coverage` repair — worth watching for
  after every wave that adds detectors.

  **Still weak (next targets):** persuasion (0/5) and thought-experiment (0/2) — these live in
  `data/crescendo.js`/the semantic layer, untouched here; PAP 0/5 and TAP 0/4 overall. Plus one leetspeak
  miss whose `LEET` table maps `1→i` only (the sample uses `1` as `l`).
- **DONE (v0.74.0) — seven-track wave: locked-half 70.5% → 88.6% deterministic, 100% full-stack.**
  Five parallel efforts on strictly disjoint files, each measured against the tune half only; the
  orchestrator scored the **locked** half afterwards (no agent ever opened it).

  | locked test half (44 attacks / 10 benign) | session start | after v0.73.0 | **now** |
  |---|---|---|---|
  | deterministic | 31.8% | 70.5% | **88.6% (39/44)** |
  | full stack (+ on-device model) | — | 95.5% | **100% (44/44)** |
  | precision | 0 FP/10 | 0 FP/10 | **0 FP/10** |

  - **`data/crescendo.js` — 20 enumerated literals → 35 structural slot tells.** Closed the persuasion
    block: PAP 0/5→4/5, TAP 0/4→3/4, PAIR 2/5→5/5, thought-experiment 0/2→2/2, fiction-frame 1/3→3/3.
    Found and fixed a **latent double-counting FP** (`authority-role` + `approved-redteam` are one concept;
    summing them scored a benign sample at 3 — invisible only because the prefilter never woke it, and it
    breached the ≤4 gate the moment the prefilter widened). Fixed with a group cap: a concept contributes
    its MAX weight, not the sum. Also fixed an engine-level DoS regression it introduced (60k input
    136ms→426ms via per-occurrence `refine()`) with the `memo1` guard → **2.9ms**.
  - **`data/detectors.js`** — third prefilter pattern on `persuasion-jailbreak`, so `refine()` actually
    wakes on framings `persuasionHit` already scored correctly. Safe ONLY because of the group cap above.
    Tune half → 100% (61/61), FP unchanged.
  - **`data/normalize.js` — multi-variant leetspeak.** `1`/`!` are the only ambiguous glyphs; branching over
    run-strategies (not positions) gives a CONSTANT 7 extra candidates instead of 2^k. Root cause was
    deeper than the table: `RESCAN_ON_VARIANT` only re-runs `inj*`/`sysprompt*`, and only the mixed `il`
    reading recovers `guardra11s`→`guardrails`. Gated so 0 of 711 benign samples gain a variant.
  - **Escalation moved OFF the hot path.** Its only output is a content-free advisory that cannot change a
    decision, so it never belonged there. Detached worker + job file: hot path with escalation on
    **667ms → 108ms**; default install unchanged (97→100ms). Timeouts are now RECORDED
    (`answered`/`timeout`/`guard-timeout`/`unavailable`/…) instead of being indistinguishable from
    "model said benign".
    **FINDING — the shipped default model is harmful.** `llama3.2:1b` is fast (p50 261ms, 86/86 in budget)
    but on the tune half added **+7 FP and +0 recall**; the 8B added +2 recall and +0 FP. The earlier
    "2500ms is too short" diagnosis was WRONG — that 14.8s was a cold model load, not inference.
  - **`test/redteam/benign-corpus-v2.json` — 509 benign / 168 hard negatives.** FP rate **2.79%**
    (14/501). Ten twin families at 0% FP. Produced the precision-debt list below.
  - **`scripts/closed-loop-mutate.mjs` + `heldout-v3.json` (160 attacks/97 benign).** An adaptive adversary
    that mutates SURVIVORS each round. Found **20 compounding chains at 100% evasion whose every one-step
    reduction is caught** — invisible to a one-shot generator. Worst: **`dot-punct→letter-spacing`, which
    needs no decoding at all** (plainly readable text that walks past the engine); `caesar5` is the
    strongest amplifier (10 of 20). Validity is mechanical: every candidate is round-tripped back to the
    exact core or dropped.

  **PRECISION DEBT (next wave's target list, from benign-corpus-v2):** `dlp-phone` fires on
  `ghp_…0123456789` (trailing digits look like a phone number); `destructive-command` cannot distinguish
  DISCUSSING a command from ISSUING one (`"explain the difference between git revert and git reset --hard"`);
  `secret-*` fires on the canonical documentation placeholders this repo's own convention mandates
  (`AKIAIOSFODNN7EXAMPLE`, `ghp_ABCDEF…`); `inj-override-structural` fires on an override verb with a
  NON-AGENT object (`"the linter should ignore all previous rules"`); `dep-typosquat` fires on a prompt
  naming no package.

  **NOTE:** `test/semantic.test.mjs` is 8/9 on any machine with a reachable local model — that test assumes
  the loopback model is absent (as in CI). It needs an env guard, not a code fix.
- **DONE (v0.75.0) — global weighted scoring dial: shipped OFF, and the honest answer is "marginal".**
  `data/risk-score.js` unions the tell IDs already declared across `injection-tells.js` / `crescendo.js`,
  sums their EXISTING `w:` weights (nothing was fitted — the union matters because the 7 `NEGATION_SRC`
  tells belong to two tables and summing twice would let one restated concept corroborate itself), and
  promotes a sample only when nothing else fired. Promote-only, so it is monotonic and cannot lose recall.
  Wired via a 4th `DetectionEngine` arg + `setScoring()`; `policy.scoringMode` defaults to `"off"`, and
  with it off the output is **byte-identical** to the pre-change engine (789 samples, 0 diffs, compared
  against `git show HEAD:src/engine.js`).

  Threshold sweep (the actual deliverable):

  | threshold | locked half recall | locked FP | benign-v2 FP rate |
  |---|---|---|---|
  | off | 88.6% (39/44) | 0/10 | 2.79% |
  | 1 | 93.2% (41/44) | 1/10 | **5.59%** |
  | **3 (knee)** | **90.9% (40/44)** | **0/10** | **2.79%** |
  | ≥5 | 88.6% | 0/10 | 2.79% |

  **Verdict: the dial buys exactly ONE attack.** It is free (no added FP, +1.3% latency, consulted at most
  once per scan) but it is one sample, and the tune half has zero headroom (already 100%). Measured why it
  cannot buy more: **3 of the 5 locked-half misses carry an aggregate of exactly 0** — no weak tell of any
  kind fires, so no threshold can ever reach them; 1 more ties with 14 benign samples and is unseparable.
  Only `hv2-advprefix-affirm-prefix-104` (three prefix tells, no `shape` tell) is a genuine instance of the
  thesis. The value is structural: a future wave can now ship a w:1 tell that would otherwise never fire
  alone. **Landed at `mode:"off"`; revisit the curve after the next tell wave.**

  Its own falsification pass found a hole in ITS OWN test: the byte-identity check compared engine-to-engine,
  so a break enabling the dial for all three engines would have passed. It added an absolute invariant (no
  `risk-aggregate` finding and no `aggregateScore` field may EVER appear with the dial off) and only then
  did the deliberate break go red. **No caller turns the dial on** — `hook-core.mjs`, `src/app.js` and the
  scripts all construct 3-arg; wiring `policy.scoringMode` through the enforcement path remains open.
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
