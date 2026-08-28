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
point of view; position and document *that* as the durable evidence store, and consider:
- a monotonic sequence number + running hash-chain on emitted records so a gap/reorder in the SIEM
  copy is detectable (tamper-evidence that survives into the pipeline);
- optional local append-only hardening (e.g. platform WORM/immutable-flag where available) as
  defense-in-depth, opportunistic and fail-open like the rest of the on-device signals.

Do **not** claim "immutable" for the on-device logs until/unless this lands; the honest line is
"signed + tamper-evident on the device, immutable once streamed."

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

**Status:** signature detection ships and is the baseline story until this lands; don't market a
"learned per-agent baseline" before it exists.
