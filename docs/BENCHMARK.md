# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with `npm run benchmark`.
> Generated: 2026-09-24T22:12:28.312Z

- **Detectors:** 88
- **Threats:** 72
- **Adversarial corpus:** 102/102 passed (100.0%)
- **OWASP LLM Top 10:** 9/10 items covered by ≥1 on-device detector

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
| LLM01 | Prompt Injection | 7 | 18 | ✅ covered |
| LLM02 | Sensitive Information Disclosure | 17 | 34 | ✅ covered |
| LLM03 | Supply Chain | 6 | 2 | ✅ covered |
| LLM04 | Data & Model Poisoning | 1 | 0 | — |
| LLM05 | Improper Output Handling | 6 | 14 | ✅ covered |
| LLM06 | Excessive Agency | 14 | 5 | ✅ covered |
| LLM07 | System Prompt Leakage | 3 | 3 | ✅ covered |
| LLM08 | Vector & Embedding Weaknesses | 3 | 7 | ✅ covered |
| LLM09 | Misinformation | 13 | 4 | ✅ covered |
| LLM10 | Unbounded Consumption | 2 | 1 | ✅ covered |

Coverage is measured, not asserted: every number above is produced by running the shipped detection
engine (`src/engine.js`) against the shipped threat matrix (`data/threats.json`) and the adversarial
corpus (`test/redteam/corpus.json`). Content-free by construction — the benchmark reasons over
categories and threat ids, never prompt content.
