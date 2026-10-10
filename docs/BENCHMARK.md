# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with `npm run benchmark`.
> Generated: 2026-10-10T19:18:47.034Z

- **Detectors:** 109
- **Threats:** 80
- **Adversarial corpus:** 102/102 passed (100.0%)
- **OWASP LLM Top 10:** 10/10 items covered by ≥1 on-device detector
- **OWASP Top 10 for Agentic Applications:** 1/10 covered, 6 partial, 3 uncovered
- **OWASP MCP Top 10:** 1/10 covered, 5 partial, 4 uncovered

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
| LLM01 | Prompt Injection | 8 | 21 | ✅ covered |
| LLM02 | Sensitive Information Disclosure | 20 | 39 | ✅ covered |
| LLM03 | Supply Chain | 8 | 5 | ✅ covered |
| LLM04 | Data & Model Poisoning | 1 | 1 | ✅ covered |
| LLM05 | Improper Output Handling | 7 | 15 | ✅ covered |
| LLM06 | Excessive Agency | 15 | 6 | ✅ covered |
| LLM07 | System Prompt Leakage | 3 | 6 | ✅ covered |
| LLM08 | Vector & Embedding Weaknesses | 3 | 11 | ✅ covered |
| LLM09 | Misinformation | 13 | 4 | ✅ covered |
| LLM10 | Unbounded Consumption | 2 | 1 | ✅ covered |

## OWASP Top 10 for Agentic Applications (2026) coverage

| Item | Name | Threats | Partial | Detectors | Status |
|------|------|--------:|--------:|----------:|--------|
| ASI01 | Agent Goal Hijack | 9 | 7 | 28 | ✅ covered |
| ASI02 | Tool Misuse and Exploitation | 9 | 9 | 7 | ◐ partial |
| ASI03 | Identity and Privilege Abuse | 4 | 4 | 4 | ◐ partial |
| ASI04 | Agentic Supply Chain Vulnerabilities | 3 | 3 | 10 | ◐ partial |
| ASI05 | Unexpected Code Execution (RCE) | 6 | 6 | 14 | ◐ partial |
| ASI06 | Memory & Context Poisoning | 4 | 4 | 4 | ◐ partial |
| ASI07 | Insecure Inter-Agent Communication | 1 | 1 | 0 | — |
| ASI08 | Cascading Failures | 0 | 0 | 0 | — |
| ASI09 | Human-Agent Trust Exploitation | 1 | 1 | 1 | ◐ partial |
| ASI10 | Rogue Agents | 1 | 1 | 0 | — |

## OWASP MCP Top 10 (2025, beta) coverage

| Item | Name | Threats | Partial | Detectors | Status |
|------|------|--------:|--------:|----------:|--------|
| MCP01 | Token Mismanagement & Secret Exposure | 3 | 3 | 23 | ◐ partial |
| MCP02 | Privilege Escalation via Scope Creep | 3 | 3 | 2 | ◐ partial |
| MCP03 | Tool Poisoning | 2 | 2 | 10 | ◐ partial |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | 0 | 0 | 0 | — |
| MCP05 | Command Injection & Execution | 2 | 2 | 3 | ◐ partial |
| MCP06 | Intent Flow Subversion | 8 | 6 | 19 | ✅ covered |
| MCP07 | Insufficient Authentication & Authorization | 0 | 0 | 0 | — |
| MCP08 | Lack of Audit and Telemetry | 1 | 1 | 1 | ◐ partial |
| MCP09 | Shadow MCP Servers | 1 | 1 | 0 | — |
| MCP10 | Context Injection & Over-Sharing | 0 | 0 | 0 | — |

For the two agentic lists, **Threats** counts the rules that credit the item (`owaspAgentic` / `owaspMcp`
in `data/threats.json`) and **Partial** how many of those credits are bounded. An item is *covered* when a
rule crediting it in full has an on-device detector, *partial* when only bounded credits do, and *—*
otherwise. Rules whose mechanism is not a detector in `data/detectors.js` (drift, delegation, session
risk, the MCP allow-list) are counted under Threats but add no detectors. Sources:
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [OWASP MCP Top 10](https://github.com/OWASP/www-project-mcp-top-10).

Coverage is measured, not asserted: every number above is produced by running the shipped detection
engine (`src/engine.js`) against the shipped threat matrix (`data/threats.json`) and the adversarial
corpus (`test/redteam/corpus.json`). Content-free by construction — the benchmark reasons over
categories and threat ids, never prompt content.

## Latency

> Latency not measured in this run (`--no-latency`).

| Path | One sample | n | Warm-up | p50 | p95 | p99 | max |
|------|------------|--:|--------:|----:|----:|----:|----:|
| In process: `engine.scan` at `prompt` | one benign-corpus-v2 text | — | 50 | — | — | — | — |
| In process: `engine.scan` at `file` | one benign-corpus-v2 text | — | 50 | — | — | — | — |
| In process: `engine.scan` at `output` | one benign-corpus-v2 text | — | 50 | — | — | — | — |
| In process: Agent SDK tool-call decision | one `PreToolUse` from the ten-call mix | — | 200 | — | — | — | — |
| Process: hook end-to-end (`PreToolUse`) | spawn → stdin JSON → exit | — | 5 | — | — | — | — |
| Process: Node startup floor (`node -e ""`) | spawn → exit, interleaved with the hook | — | 5 | — | — | — | — |

The cost a Claude Code user pays per tool call is the **hook end-to-end** row: one `node
cli/moorai-hook.mjs` process spawned per `PreToolUse`, timed from spawn to exit, in a throwaway home
with no console (unenrolled, built-in policy). The **Node startup floor** row is `node -e ""` spawned
the same way, interleaved call for call with the hook, so the gap between the two rows is the hook's own
module loading and decision. The **in-process** rows are what the Agent SDK and `moorai-serve` pay per
call in a long-lived process: `engine.scan` per stage over every text in
`test/redteam/benign-corpus-v2.json`, and `createMoorAI().toolCall` (the decision code the parity test
holds to the hook's verdicts) over a fixed mix of ten `PreToolUse` calls, six benign and four attack-shaped.
All rows run sequentially, one call at a time; machine load is not controlled.

Percentiles are nearest-rank over the raw per-call timings, never interpolated and never derived from a
mean. p95 is published from 20 samples and p99 from 1,000; a — means the row has
fewer. Timings vary between runs and machines, so `npm run test:generated` regenerates this file with
`--no-latency` and ignores only the latency rows and the conditions line; every coverage number above is
still diffed byte for byte.
