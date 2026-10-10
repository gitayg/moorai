# Pre-screen drop rate

`node scripts/drop-rate.mjs` sorts every attack into one of three buckets, on every surface the attack can arrive through:

- **(a) caught**: the corpus scorer's own definition of "detected" fired.
- **(b) eligible**: the rules missed, and the shipped code would hand the text to the semantic path (on-device model).
- **(c) dropped**: the rules missed, and no code path would hand the text to a model. The output names the gate that dropped it.

Eligibility is a question about code paths. The script calls no model and no network.

The question comes from a published two-stage design (regex pre-screen, then an LLM judge). That design's pre-screen decided which texts reached the judge, and it capped detection at 34%. So measuring what the cheap first stage drops matters as much as measuring what the judge catches.

## Gates (file:line as of v1.11.0 work in progress)

| Gate | Where |
|---|---|
| Opt-in. The hook and guard need `modelEscalation` and `semanticEscalation != off`. The default is off. | `cli/moorai-hook.mjs:1092`, `cli/moorai-guard.mjs:82`, `data/semantic-escalation.js:24`, `src/semantic.js:76,137` |
| A strong (High/Critical/Blocked) finding skips escalation. | `cli/moorai-hook.mjs:1093`, `cli/moorai-guard.mjs:83` |
| Miss-recovery runs only when the decision credited nothing. `maybeEscalate` hands the worker the threat ids the decision kept (`credited`), and the worker restricts its raw re-scan to them, so a threat `decideInbound` drops (outbound-only on inbound content) no longer blocks it. | `cli/moorai-hook.mjs` `maybeEscalate`, `runEscalationWorker` |
| The detect gate is the only path when `base` is non-empty. Only `semantic-persuasion` (#2) uses it, and it applies at the prompt stage, so also at file and index (`_wantStages`) but not at output. | `src/semantic.js:78,100`, `data/detectors.js:1472-1478`, `src/engine.js:45` |
| Escalation call sites. PostToolUse output, Read, the write family and WebFetch input escalate. Bash escalates only the files a command reads, never the command. | `cli/moorai-hook.mjs:1818,2180,2345,2376,2276` (`btext` built at `:2198`) |
| Surfaces with no escalation call: UserPromptSubmit, a Task prompt, MCP arguments, the index worker, the Agent SDK / moorai-serve, the MCP gateway, the model proxy and the inference hook. | `cli/moorai-hook.mjs:1867-1901,2461,2382-2450,1009`, `packages/agent-sdk/src/decide.mjs:42` |
| A person's own prompt is not scanned (default `promptScan: "untrusted"`). | `cli/moorai-hook.mjs:1870`, `cli/prompt-scan.mjs` |
| Model window. The model sees only the first 4000 chars. This doesn't drop the text, but it hides anything past char 4000. | `data/model-escalation.mjs:139`, `data/device-inference.mjs:102` |
| Scan window. Text past 64 KB is neither scanned nor escalated. | `mcp-proxy/tool-scan.mjs:47`, `cli/moorai-hook.mjs:1806,1872` |
| Runtime, not eligibility: a model must be present, finish within 2500 ms (with a 3500 ms guard), flag the text and return confidence of at least 0.5. | `data/model-escalation.mjs:52,181`, `src/semantic.js:19,142` |

## Results on tune data (opted-in posture)

- **heldout-v2 tune (61), hackagent (31), heldout v1 (29), redteam cases (83).** The rules catch every attack on every scanning surface, so nothing is left to escalate. The person-typed UserPromptSubmit surface drops 100% by design: the prompt is never scanned.
- **Inbound tune (95), hook PostToolUse.** 86 caught, 5 eligible, 4 dropped (4.2%). All 4 drops are a strong uncredited finding (#17 High is reported and escalation is skipped). Before the worker gated on the credited set it was 2 eligible and 7 dropped: the other 3 were a suppressed finding (the decision reported nothing while the raw re-scan fired an outbound-only threat, #61, #55/#17, #32), so `escalateMiss` never ran and they were silent, with no alert and no model.
- **Inbound, Agent SDK / MCP gateway.** Every miss is dropped, 9 and 13 respectively, because neither surface has an escalation path.
- **Default posture.** Every deterministic miss is dropped (`policy-off`).

## How the script was checked

- The per-id inbound misses match `scripts/score-inbound.mjs --split tune` (real hook subprocess): hook 9, SDK 9, gateway 13, same ids.
- heldout-v2 tune scores 61/61 against `score-heldout-v2.mjs`. hackagent and heldout v1 score 60/60 against `redteam-eval.mjs`, and the redteam cases score 102/102.
- The real hook and its escalation worker were driven with a loopback fake model on the 9 inbound tune misses (PostToolUse, opted-in posture). They made a model call and posted #58 for exactly the 5 attacks classified eligible, and none for the 4 strong-finding drops. With the old worker gate (an empty raw re-scan) the same run made 2 calls. `test/escalation-credited-base.test.mjs` pins the case.

## Locked data

`--file` of a heldout-v2 test or full file, and `--split locked|all`, both require `--i-am-scoring-the-locked-split`, and only the orchestrator runs those. `--misses` never prints ids on a locked run.
