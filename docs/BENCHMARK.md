# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with `npm run benchmark`.
> Generated: 2026-10-09T16:32:08.705Z

- **Detectors:** 107
- **Threats:** 79
- **Adversarial corpus:** 102/102 passed (100.0%)
- **OWASP LLM Top 10:** 10/10 items covered by ≥1 on-device detector
- **OWASP Top 10 for Agentic Applications:** 1/10 covered, 6 partial, 3 uncovered
- **OWASP MCP Top 10:** 1/10 covered, 5 partial, 4 uncovered

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
| LLM01 | Prompt Injection | 8 | 20 | ✅ covered |
| LLM02 | Sensitive Information Disclosure | 20 | 39 | ✅ covered |
| LLM03 | Supply Chain | 7 | 4 | ✅ covered |
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
| ASI01 | Agent Goal Hijack | 9 | 7 | 27 | ✅ covered |
| ASI02 | Tool Misuse and Exploitation | 9 | 9 | 7 | ◐ partial |
| ASI03 | Identity and Privilege Abuse | 4 | 4 | 4 | ◐ partial |
| ASI04 | Agentic Supply Chain Vulnerabilities | 3 | 3 | 10 | ◐ partial |
| ASI05 | Unexpected Code Execution (RCE) | 5 | 5 | 13 | ◐ partial |
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
| MCP06 | Intent Flow Subversion | 8 | 6 | 18 | ✅ covered |
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
