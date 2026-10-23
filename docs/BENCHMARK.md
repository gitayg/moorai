# MoorAI Agent Security Benchmark

> Reproducible coverage of MoorAI's on-device detection engine. Regenerate with `npm run benchmark`.
> Generated: 2026-10-23T02:14:37.962Z

- **Detectors:** 120
- **Threats:** 82
- **Adversarial corpus:** 102/102 passed (100.0%)
- **OWASP LLM Top 10:** 10/10 items covered by ≥1 on-device detector
- **OWASP Top 10 for Agentic Applications:** 1/10 covered, 6 partial, 3 uncovered
- **OWASP MCP Top 10:** 1/10 covered, 5 partial, 4 uncovered
- **MITRE ATT&CK v20.0 (AI-agent scope):** 2/71 covered, 55 partial (9 bounded by design, 46 open gap), 14 uncovered (agent lane: 2/58 covered, 53 partial (8 bounded by design, 45 open gap), 3 uncovered)

## OWASP LLM Top 10 (2025) coverage

| Item | Name | Threats | Detectors | Status |
|------|------|--------:|----------:|--------|
| LLM01 | Prompt Injection | 8 | 21 | ✅ covered |
| LLM02 | Sensitive Information Disclosure | 20 | 44 | ✅ covered |
| LLM03 | Supply Chain | 8 | 6 | ✅ covered |
| LLM04 | Data & Model Poisoning | 1 | 1 | ✅ covered |
| LLM05 | Improper Output Handling | 7 | 16 | ✅ covered |
| LLM06 | Excessive Agency | 17 | 8 | ✅ covered |
| LLM07 | System Prompt Leakage | 3 | 6 | ✅ covered |
| LLM08 | Vector & Embedding Weaknesses | 3 | 13 | ✅ covered |
| LLM09 | Misinformation | 13 | 4 | ✅ covered |
| LLM10 | Unbounded Consumption | 2 | 1 | ✅ covered |

## OWASP Top 10 for Agentic Applications (2026) coverage

| Item | Name | Threats | Partial | Detectors | Status |
|------|------|--------:|--------:|----------:|--------|
| ASI01 | Agent Goal Hijack | 9 | 7 | 29 | ✅ covered |
| ASI02 | Tool Misuse and Exploitation | 9 | 9 | 7 | ◐ partial |
| ASI03 | Identity and Privilege Abuse | 4 | 4 | 6 | ◐ partial |
| ASI04 | Agentic Supply Chain Vulnerabilities | 3 | 3 | 11 | ◐ partial |
| ASI05 | Unexpected Code Execution (RCE) | 6 | 6 | 15 | ◐ partial |
| ASI06 | Memory & Context Poisoning | 4 | 4 | 6 | ◐ partial |
| ASI07 | Insecure Inter-Agent Communication | 1 | 1 | 0 | — |
| ASI08 | Cascading Failures | 0 | 0 | 0 | — |
| ASI09 | Human-Agent Trust Exploitation | 1 | 1 | 1 | ◐ partial |
| ASI10 | Rogue Agents | 2 | 2 | 0 | — |

## OWASP MCP Top 10 (2025, beta) coverage

| Item | Name | Threats | Partial | Detectors | Status |
|------|------|--------:|--------:|----------:|--------|
| MCP01 | Token Mismanagement & Secret Exposure | 3 | 3 | 28 | ◐ partial |
| MCP02 | Privilege Escalation via Scope Creep | 3 | 3 | 3 | ◐ partial |
| MCP03 | Tool Poisoning | 2 | 2 | 11 | ◐ partial |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | 0 | 0 | 0 | — |
| MCP05 | Command Injection & Execution | 2 | 2 | 3 | ◐ partial |
| MCP06 | Intent Flow Subversion | 8 | 6 | 20 | ✅ covered |
| MCP07 | Insufficient Authentication & Authorization | 0 | 0 | 0 | — |
| MCP08 | Lack of Audit and Telemetry | 1 | 1 | 2 | ◐ partial |
| MCP09 | Shadow MCP Servers | 1 | 1 | 0 | — |
| MCP10 | Context Injection & Over-Sharing | 0 | 0 | 0 | — |

For the two agentic lists, **Threats** counts the rules that credit the item (`owaspAgentic` / `owaspMcp`
in `data/threats.json`) and **Partial** how many of those credits are bounded. An item is *covered* when a
rule crediting it in full has an on-device detector, *partial* when only bounded credits do, and *—*
otherwise. Rules whose mechanism is not a detector in `data/detectors.js` (drift, delegation, session
risk, the MCP allow-list) are counted under Threats but add no detectors. Sources:
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [OWASP MCP Top 10](https://github.com/OWASP/www-project-mcp-top-10).

## MITRE ATT&CK v20.0 coverage (AI-agent scope)

| Technique | Name | Lane | Threats | Detectors | Status |
|-----------|------|------|--------:|----------:|--------|
| T1698 | Indirect Prompt Injection | agent | 8 | 18 | ✅ covered |
| T1699 | Direct Prompt Injection | agent | 2 | 9 | ✅ covered |
| T1700 | AI-Enabled Exfiltration | agent | 4 | 4 | ◐ partial (open gap) |
| T1685.007 | Impair Autonomous Defenses | agent | 1 | 5 | ◐ partial (open gap) |
| T1608.007 | AI Result Poisoning | agent | 1 | 1 | ◐ partial (by design) |
| T1027.018 | Invisible Unicode | agent | 1 | 8 | ◐ partial (open gap) |
| T1195.001 | Compromise Software Dependencies and Development Tools | agent | 5 | 5 | ◐ partial (open gap) |
| T1059.001 | PowerShell | agent | 1 | 1 | ◐ partial (by design) |
| T1059.004 | Unix Shell | agent | 1 | 1 | ◐ partial (by design) |
| T1059.006 | Python | agent | 1 | 1 | ◐ partial (by design) |
| T1059.013 | Container CLI/API | agent | 1 | 2 | ◐ partial (open gap) |
| T1027.010 | Command Obfuscation | agent | 1 | 8 | ◐ partial (open gap) |
| T1105 | Ingress Tool Transfer | agent | 1 | 2 | ◐ partial (by design) |
| T1204.001 | Malicious Link | agent | 3 | 3 | ◐ partial (open gap) |
| T1204.002 | Malicious File | agent | 1 | 2 | ◐ partial (open gap) |
| T1204.004 | Malicious Copy and Paste | agent | 1 | 2 | ◐ partial (by design) |
| T1204.005 | Malicious Library | agent | 2 | 3 | ◐ partial (open gap) |
| T1176.002 | IDE Extensions | agent | 1 | 2 | ◐ partial (open gap) |
| T1677 | Poisoned Pipeline Execution | agent | 1 | 2 | ◐ partial (open gap) |
| T1053.003 | Cron | agent | 1 | 2 | ◐ partial (open gap) |
| T1543.001 | Launch Agent | agent | 1 | 2 | ◐ partial (open gap) |
| T1546.004 | Unix Shell Configuration Modification | agent | 1 | 2 | ◐ partial (open gap) |
| T1552.001 | Credentials In Files | agent | 1 | 3 | ◐ partial (open gap) |
| T1552.003 | Shell History | agent | 1 | 3 | ◐ partial (open gap) |
| T1552.004 | Private Keys | agent | 1 | 3 | ◐ partial (open gap) |
| T1552.005 | Cloud Instance Metadata API | agent | 1 | 3 | ◐ partial (open gap) |
| T1552.008 | Chat Messages | agent | 1 | 24 | ◐ partial (by design) |
| T1555.001 | Keychain | agent | 1 | 3 | ◐ partial (open gap) |
| T1555.003 | Credentials from Web Browsers | agent | 1 | 3 | ◐ partial (open gap) |
| T1003.008 | /etc/passwd and /etc/shadow | agent | 1 | 3 | ◐ partial (open gap) |
| T1528 | Steal Application Access Token | agent | 1 | 3 | ◐ partial (open gap) |
| T1074.001 | Local Data Staging | agent | 1 | 0 | ◐ partial (open gap) |
| T1560.001 | Archive via Utility | agent | 2 | 1 | ◐ partial (open gap) |
| T1030 | Data Transfer Size Limits | agent | 1 | 0 | ◐ partial (open gap) |
| T1016.001 | Internet Connection Discovery | agent | 1 | 1 | ◐ partial (by design) |
| T1567 | Exfiltration Over Web Service | agent | 2 | 2 | ◐ partial (open gap) |
| T1567.001 | Exfiltration to Code Repository | agent | 0 | 0 | — |
| T1567.002 | Exfiltration to Cloud Storage | agent | 0 | 0 | — |
| T1567.003 | Exfiltration to Text Storage Sites | agent | 0 | 0 | — |
| T1567.004 | Exfiltration Over Webhook | agent | 2 | 2 | ◐ partial (open gap) |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | agent | 1 | 1 | ◐ partial (open gap) |
| T1485 | Data Destruction | agent | 2 | 2 | ◐ partial (open gap) |
| T1561 | Disk Wipe | agent | 1 | 1 | ◐ partial (open gap) |
| T1490 | Inhibit System Recovery | agent | 1 | 1 | ◐ partial (open gap) |
| T1070 | Indicator Removal | agent | 1 | 2 | ◐ partial (open gap) |
| T1070.003 | Clear Command History | agent | 1 | 2 | ◐ partial (open gap) |
| T1690 | Prevent Command History Logging | agent | 1 | 2 | ◐ partial (open gap) |
| T1685 | Disable or Modify Tools | agent | 2 | 2 | ◐ partial (open gap) |
| T1686 | Disable or Modify System Firewall | agent | 1 | 2 | ◐ partial (open gap) |
| T1553.001 | Gatekeeper Bypass | agent | 1 | 2 | ◐ partial (open gap) |
| T1553.004 | Install Root Certificate | agent | 2 | 2 | ◐ partial (open gap) |
| T1557 | Adversary-in-the-Middle | agent | 1 | 0 | ◐ partial (open gap) |
| T1098.001 | Additional Cloud Credentials | agent | 1 | 1 | ◐ partial (open gap) |
| T1098.003 | Additional Cloud Roles | agent | 1 | 2 | ◐ partial (open gap) |
| T1098.004 | SSH Authorized Keys | agent | 1 | 1 | ◐ partial (open gap) |
| T1136.001 | Local Account | agent | 1 | 1 | ◐ partial (open gap) |
| T1136.003 | Cloud Account | agent | 1 | 1 | ◐ partial (open gap) |
| T1548.003 | Sudo and Sudo Caching | agent | 1 | 2 | ◐ partial (open gap) |
| T1176.001 | Browser Extensions | edr | 2 | 0 | — |
| T1078.004 | Cloud Accounts | identity | 1 | 0 | — |
| T1697 | Steal Application Specific Passwords | identity | 1 | 24 | ◐ partial (by design) |
| T1496.004 | Cloud Service Hijacking | identity | 1 | 0 | — |
| T1566 | Phishing | email | 1 | 0 | — |
| T1566.004 | Spearphishing Voice | email | 1 | 0 | — |
| T1684.001 | Impersonation | email | 2 | 1 | — |
| T1657 | Financial Theft | email | 1 | 1 | ◐ partial (open gap) |
| T1682 | Query Public AI Services | pre | 0 | 0 | — |
| T1683.001 | Written Content | pre | 2 | 0 | — |
| T1683.002 | Audio-Visual Content | pre | 2 | 0 | — |
| T1588.007 | Artificial Intelligence | pre | 0 | 0 | — |
| T1696 | Anti-Automation Evasion | pre | 0 | 0 | — |

The rows are the v20.0 techniques an AI agent on an endpoint, server or AI runtime can perform or be
aimed at (`ATTACK_SCOPE` in `data/attack.js`). **Lane** says who can see the technique: `agent` is an action
an AI agent takes that a MoorAI hook, proxy or gateway sees; `edr`, `identity`, `email` and `pre` (the
adversary's own infrastructure) are outside every MoorAI surface. Each credit in `data/threats.json` (`attack`)
states its level and a one-line reason; a technique is *covered* when a rule credits it in full, *partial* when
the best credit is bounded, and *—* otherwise. A partial technique is *by design* when one of its partial credits
carries `bound: "design"`: the forms it does not catch are indistinguishable from an agent's legitimate work, or
outside anything an agent-side hook, proxy or gateway observes, and `boundReason` says which. Every other partial
technique is an *open gap*: detection MoorAI has not built yet. Coverage is a mechanism claim, not a detection rate. Technique ids
and names: [MITRE ATT&CK Enterprise v20.0](https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.0), released 2026-10-13.

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
