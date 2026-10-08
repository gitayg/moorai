# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with `npm run benchmark`.
> Generated: 2026-10-08T05:41:26.788Z

- **Detectors:** 103
- **Threats:** 77
- **Adversarial corpus:** 102/102 passed (100.0%)
- **OWASP LLM Top 10:** 10/10 items covered by ≥1 on-device detector

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
| LLM01 | Prompt Injection | 8 | 20 | ✅ covered |
| LLM02 | Sensitive Information Disclosure | 18 | 36 | ✅ covered |
| LLM03 | Supply Chain | 7 | 3 | ✅ covered |
| LLM04 | Data & Model Poisoning | 1 | 1 | ✅ covered |
| LLM05 | Improper Output Handling | 7 | 15 | ✅ covered |
| LLM06 | Excessive Agency | 15 | 6 | ✅ covered |
| LLM07 | System Prompt Leakage | 3 | 6 | ✅ covered |
| LLM08 | Vector & Embedding Weaknesses | 3 | 11 | ✅ covered |
| LLM09 | Misinformation | 13 | 4 | ✅ covered |
| LLM10 | Unbounded Consumption | 2 | 1 | ✅ covered |

Coverage is measured, not asserted: every number above is produced by running the shipped detection
engine (`src/engine.js`) against the shipped threat matrix (`data/threats.json`) and the adversarial
corpus (`test/redteam/corpus.json`). Content-free by construction — the benchmark reasons over
categories and threat ids, never prompt content.
