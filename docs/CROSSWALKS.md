# Framework crosswalks

MoorAI's rule base ([`data/threats.json`](../data/threats.json)) already carries the OWASP LLM Top 10, MITRE
ATLAS, the OWASP Top 10 for Agentic Applications and the OWASP MCP Top 10 on each rule (see
[`DETECTION_ENGINE.md`](DETECTION_ENGINE.md) §16). Three more frameworks are crosswalked the other way round,
from the framework's own list to MoorAI, each in its own file under [`data/crosswalks/`](../data/crosswalks):

| File | Framework | What is mapped |
|---|---|---|
| [`saf-mcp.json`](../data/crosswalks/saf-mcp.json) | SAF-MCP (OpenSSF SIG) | the 78 active techniques |
| [`careful-adoption-of-agentic-ai-services.json`](../data/crosswalks/careful-adoption-of-agentic-ai-services.json) | Careful adoption of agentic AI services (ASD's ACSC, CISA, NSA, Canadian Centre for Cyber Security, NCSC-NZ, NCSC-UK) | the 140 recommended best practices and Appendix A prerequisites |
| [`agentic-trust-framework.json`](../data/crosswalks/agentic-trust-framework.json) | Agentic Trust Framework (published through the Cloud Security Alliance) | the 25 core requirements |

```bash
node scripts/crosswalk-report.mjs              # covered / partial / not covered / not applicable per framework
node scripts/crosswalk-report.mjs --json
node scripts/crosswalk-report.mjs --markdown   # the tables below
node --test --import ./test/hermetic-env.mjs test/crosswalks.test.mjs
```

## Sources

Each source was read at its official location on 2026-10-09. Nothing here is mapped from memory or from a
third-party summary.

| Framework | Version | Date | Read from | Ids |
|---|---|---|---|---|
| **SAF-MCP: Secure Agentic Framework for Model Context Protocol**, OpenSSF SIG-SAF-MCP | "Framework Model v2"; no release tag. Commit `d3d4029` | commit 2026-09-02 | <https://github.com/secure-agentic-framework/saf-mcp>, `research/framework-model.yml` (the canonical catalog), checked against the README's generated catalog | official `SAF-T` ids |
| **Careful adoption of agentic AI services**, ASD's ACSC with CISA, NSA, the Canadian Centre for Cyber Security, NCSC-NZ and NCSC-UK | no version number | 1 May 2026 | cited as <https://www.cyber.gov.au/publication/careful-adoption-of-agentic-ai-services>; text read from the PDF NCSC-NZ publishes, <https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf> (SHA-256 `d41bc59c…b74d`, 29 pages, author metadata ASD) | none in the source; MoorAI locators, below |
| **Agentic Trust Framework (ATF)**, Josh Woodruff (MassiveScale.AI), published through the Cloud Security Alliance | 0.9.1 Public Review Draft (tag `v0.9.1`, commit `c494c6b`); `CONFORMANCE.md` is headed 0.9.0 | 2026-04-03 | <https://github.com/massivescale-ai/agentic-trust-framework>, `CONFORMANCE.md` and `SPECIFICATION.md`; announced at <https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents> | official `I-1`…`R-5` |

Notes on the sources:

- **SAF-MCP.** `github.com/SAFE-MCP/safe-mcp` redirects to the repository above (observed with
  `gh repo view`). The catalog registers 86 technique ids; 8 are deprecated and point at their replacements,
  which the crosswalk lists and does not map. The repository has no release tags, and `CITATION.cff` still
  reads version 1.0.0 (2025-01-07); the commit is the version. `ID-MAP.md` lists 73 ids and is behind the
  catalog.
- **The agentic AI guidance.** The cyber.gov.au page and its PDF timed out from this network, so the text
  was read from the authoring agency NCSC-NZ's copy of the PDF. CISA's resource page
  (<https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services>, Publish Date
  May 01, 2026) links to the cyber.gov.au publication. The Canadian Centre for Cyber Security's HTML edition
  (<https://cyber.gc.ca/en/guidance/careful-adoption-agentic-ai>) uses Canadian spelling and shortens or
  rewords 51 of the 140 items; the PDF wording is used. The guidance numbers nothing, so each item's id is a
  locator, `<stage>/<subsection>/<n>`: the stage and subsection the "Recommended best practices" list sits
  under, and the item's position in it (for example `operate/human-in-the-loop/4`). The text is copied
  verbatim under the guidance's CC BY 4.0 licence. The risk descriptions and the "Further information"
  reading list are not controls and are not mapped.
- **ATF.** ATF governs the organisation that runs an agent; MoorAI is a third-party guard beside it. A
  credit says MoorAI can supply that requirement for an agent it watches, not that MoorAI is ATF conformant.
  The maturity levels and promotion gates are organisational processes and are not mapped.

## Method

The same rules as the ATLAS and OWASP mappings:

- **Every id on the list gets exactly one status.** `covered`: a shipped mechanism addresses the whole
  definition (a mechanism claim, not a detection rate). `partial`: it addresses part, and `limit` says
  which part. `not-covered`: no shipped mechanism does, and `reason` says what is missing.
  `not-applicable`: the item is not a runtime tool's job, and `naKind` says why: `organisational`
  (governance, procurement, staffing, assessment, research) or `agent-build` (done inside the agent
  itself: its model training, prompts, evaluation, error handling, infrastructure). SAF-MCP has no
  not-applicable entries: every technique is a runtime attack, so one MoorAI misses is a gap.
- **Credit only real coverage, and prefer a gap to an overclaim.** Credits the review considered and turned
  down are kept, with the reason, under `rejected`, and the test keeps them uncredited.
- **Evidence.** Every credit names the MoorAI components that earn it, from
  [`data/crosswalks/components.json`](../data/crosswalks/components.json): a name, a file and a symbol in
  that file. The test fails if the file is gone or no longer contains the symbol. `threats` lists the
  rule-base ids the credit rests on, and the test checks each against `data/threats.json`.
- **Some credits carry no rule id.** The tool-drift and shadowing alerts, the quarantine of a drifted tool,
  MCP server reputation, the egress proxy and `moorai-agentwatch` post `threatId: 0`: no rule in
  `data/threats.json` owns them. A credit that rests only on them has `threats: []` and its evidence. Seven
  SAF-MCP credits are like that (SAF-T1111, T1201, T1207, T1401, T1405, T1406, T1506).

## Coverage

| Framework | Items | Covered | Partial | Not covered | Not applicable | Covered or partial, of applicable |
|---|--:|--:|--:|--:|--:|--:|
| SAF-MCP | 78 | 2 | 43 | 33 | 0 | 45 of 78 (58%) |
| Careful Adoption of Agentic AI Services | 140 | 7 | 56 | 16 | 61 | 63 of 79 (80%) |
| CSA Agentic Trust Framework | 25 | 2 | 14 | 8 | 1 | 16 of 24 (67%) |

"Covered or partial, of applicable" leaves the not-applicable items out of the denominator. Most credits
are partial: a MoorAI mechanism addresses part of the item, and the limit in the table says which part.

### The most notable gaps

- **Identity and authentication.** MoorAI issues no identity to an agent, authenticates no agent and
  verifies no API caller. In the guidance, the first four identity-management practices and
  privileges-and-authentication 5, 6, 7 and 9 are gaps; in ATF, I-1 and I-2.
- **OAuth.** MoorAI is not in the MCP authorization flow, so none of SAF-MCP's OAuth techniques is covered
  (SAF-T1007, T1009, T1202, T1308, T1408, T1507, T1706, T1707), nor token relay or confused-deputy
  intermediaries (SAF-T1304, T1307).
- **Server-side compromise.** A patched server binary (SAF-T1203), a stdio server reading its own
  environment (SAF-T1503), a server's own control channel (SAF-T1903), sandbox escape and host RCE
  (SAF-T1303, T1305) and an exposed MCP endpoint (SAF-T1005) happen where MoorAI does not look.
- **Sampling.** Server-to-client `sampling/createMessage` requests are deliberately left out of the result
  scan (`resultOfResponse` in `mcp-proxy/tool-scan.mjs`), so SAF-T1112 is a gap.
- **Data harvesting through MCP.** Mass-read detection counts distinct local files, not MCP resource reads
  or query results (SAF-T1803, T1804), and directory listing and path traversal through a file tool are not
  judged against the server's scope (SAF-T1105, T1606).
- **Incident response.** No manual kill switch, session revocation or rollback (ATF R-2, R-3, R-4; the
  guidance's resilience 3). The kill verdict ends a session automatically; it is not a switch an operator
  pulls.
- **Output truth.** Outputs are not checked against other sources or redundant agents (guidance validate
  outputs 1 and 2); disinformation is not judged (SAF-T2105).

## Detail

### SAF-MCP

| Id | Title | Status | MoorAI threats | Evidence | Limit or reason |
|---|---|---|---|---|---|
| SAF-T1001 | Tool Poisoning Attack | Partial | #60, #50 | tools/list scan (tool stage); Tool-poisoning scan (#60, mcp-tool-poisoning); Tool description asking for a credential file (#60, mcp-tool-cred-path); Hidden content in tool metadata (#50, mcp-hidden-canary); MCP stdio proxy; HTTP MCP gateway; Approved tool baselines and quarantine (mcpToolDrift: block) | lexical scan of descriptions and schema text; report-first, a tool is quarantined only under a blocking policy |
| SAF-T1002 | Supply Chain Compromise | Partial | #57, #62 | MCP server reputation scoring; MCP server reputation at first launch and version change; Registry provenance and repository link check; Install from an untrusted source (#57, pkg-install-untrusted); Hallucinated or typosquatted dependency (#62, dep-typosquat) | MCP server packages scored at first launch (provenance, repository link, install scripts) and install commands; artifact signatures are not verified, and reputation reports unless mcpReputation.blockBelow is set |
| SAF-T1003 | Malicious MCP-Server Distribution | Partial | #25 | MCP server reputation scoring; MCP server reputation at first launch and version change; MCP server allow-list (policy.mcpAllow) | known-malicious and typosquatted names and opt-in catalogue verdicts at first launch, plus the server allow-list; a new malicious package with a clean name scores good |
| SAF-T1005 | Exposed Endpoint Exploit | Not covered |  |  | MoorAI does not discover or close an MCP endpoint exposed to an untrusted network or origin |
| SAF-T1004 | Server Impersonation / Name-Collision | Partial | #25 | MCP server reputation scoring; Tool-drift baselines (description, schema, shadowing); MCP server allow-list (policy.mcpAllow) | lookalike package names against the popular-server list, and a tool name claimed by a second server; server identity is never authenticated |
| SAF-T1006 | User-Social-Engineering Install | Partial | #25 | MCP server reputation at first launch and version change; MCP server allow-list (policy.mcpAllow) | the installed server is scored at its first launch and refused only off the allow-list or under blockBelow; the deception itself is not seen |
| SAF-T1007 | OAuth Authorization Phishing | Not covered |  |  | MoorAI is not in the OAuth authorization flow |
| SAF-T1207 | Hijack Update Mechanism | Partial |  | MCP server reputation at first launch and version change; Tool-drift baselines (description, schema, shadowing) | a new version is re-scored and its tool listing compared with the baseline; the update channel itself is not verified |
| SAF-T1008 | Cross-Server Tool Shadowing | Partial | #60 | tools/list scan (tool stage); Tool-poisoning scan (#60, mcp-tool-poisoning) | cross-tool directive phrasing in a description ('when using X, also send ...'); there is no provenance boundary between servers' descriptors |
| SAF-T1101 | Command Injection | Partial | #54, #57, #43 | Argument checks: detectors over tools/call arguments; Reverse shell / remote exec (#54, exec-reverse-shell); Download-then-run (#57, fetch-then-exec); Destructive shell command (#43, destructive-command) | known malicious command shapes in tool arguments and in the agent's own shell commands; injection inside a server's own process launcher is not observed |
| SAF-T1009 | Authorization Server Mix-up | Not covered |  |  | MoorAI is not in the OAuth authorization flow |
| SAF-T1102 | Prompt Injection (Multiple Vectors) | Partial | #2, #3, #40, #50, #60 | Instruction-override detectors (#3, inj-ignore); Directives in ingested content (#40, inj-untrusted-directive); Invisible or smuggled instructions (#50, obf-invisible-instructions); Tool-result scan (file stage); tools/list scan (tool stage) | text channels: prompts, MCP prompts and resources, tool descriptions and results; image and audio blocks in results are skipped |
| SAF-T1103 | Fake Tool Invocation (Function Spoofing) | Not covered |  |  | nothing checks that a tool-call record came from the trusted workflow |
| SAF-T1105 | Path Traversal via File Tool | Not covered |  |  | no check compares a path argument with the server's configured file scope |
| SAF-T1106 | Autonomous Loop Exploit | Partial | #38 | Runaway-loop circuit breaker (#38) | identical calls and short cycles with unchanged results, plus opt-in rate and call budget; token cost is not measured |
| SAF-T1111 | AI Agent CLI Weaponization | Partial |  | Autonomous-agent behaviour signature (moorai-agentwatch) | recent agent activity scored against eight autonomous-attack tells; report-only and after the fact |
| SAF-T1110 | Multimodal Prompt Injection via Images/Audio | Partial | #2, #3 | On-device OCR of pasted images | text recovered by on-device OCR from images pasted into the desktop app; audio, and images inside tool results, are not inspected |
| SAF-T1201 | Post-Approval Tool Mutation | Partial |  | Tool-drift baselines (description, schema, shadowing); Approved tool baselines and quarantine (mcpToolDrift: block); Tool fingerprint (description, schema, annotations) | description, schema and annotations; a changed implementation behind unchanged metadata is not seen |
| SAF-T1202 | OAuth Token Persistence | Not covered |  |  | MoorAI does not see OAuth refresh-token use |
| SAF-T1203 | Backdoored Server Binary | Not covered |  |  | nothing fingerprints a server's executable |
| SAF-T1204 | Context Memory Implant | Partial | #22, #21 | Instructions written into agent memory (#22, memory-poisoning); Vector-store and memory writes (index stage); Instructions headed into a knowledge base (#21, rag-poisoning) | writes that carry an instruction, into agent memory and instruction files and into MCP memory or vector-store tools; factual implants are not detected |
| SAF-T1206 | Credential Implant in Config | Partial | #60 | Skill-surface file drift, MCP configs included (#60); Skill-surface file list (.mcp.json and host MCP configs) | a changed MCP config file is reported as skill-file drift when the hook reads it; the credential inside it is not judged |
| SAF-T1302 | Agentic Confused Deputy | Partial | #64, #59 | Intent alignment: risky call vs the stated task (#64); Session risk: taint, sequences, slow exfiltration (#59); High-impact actions default to human approval | lexical check that a risky call's targets were named in the task, and outbound calls after untrusted content; no requestor authorization is bound to the call |
| SAF-T1304 | Credential Relay Chain | Not covered |  |  | credentials a server forwards downstream are not seen |
| SAF-T1303 | Sandbox Escape via Server Exec | Not covered |  |  | server-side process launch is not observed |
| SAF-T1305 | Host OS Priv-Esc (RCE) | Not covered |  |  | exploitation of a host-side MCP component is not detected |
| SAF-T1307 | Confused Deputy Attack | Not covered |  |  | the initiating principal's identity is not carried through an intermediary |
| SAF-T1308 | Token Scope Substitution | Not covered |  |  | token audience and scope are not inspected |
| SAF-T1406 | Metadata Manipulation | Partial |  | Tool-drift baselines (description, schema, shadowing); Tool fingerprint (description, schema, annotations) | a changed description, schema or annotation after the baseline; a misleading descriptor on first sight is judged only for directive text |
| SAF-T1401 | Line Jumping | Partial |  | Tool-drift baselines (description, schema, shadowing); Approved tool baselines and quarantine (mcpToolDrift: block) | a tool name claimed by a second server is flagged, and quarantined in block mode; prompts and resources are not compared |
| SAF-T1403 | Consent-Fatigue Exploit | Not covered |  |  | repeated approval prompts to a person are not counted |
| SAF-T1402 | Instruction Steganography | Partial | #50, #72 | Hidden content in tool metadata (#50, mcp-hidden-canary); Invisible or smuggled instructions (#50, obf-invisible-instructions); Directives in file metadata (#72) | invisible Unicode, control characters, rendering-hidden markup and file metadata; images and opaque model-state fields are not decoded |
| SAF-T1404 | Response Tampering | Not covered |  |  | responses carry no integrity check MoorAI verifies |
| SAF-T1405 | Tool Obfuscation/Renaming | Partial |  | Approved tool baselines and quarantine (mcpToolDrift: block); Tool fingerprint (description, schema, annotations) | on a server with an approved baseline a renamed tool is quarantined as added (block mode); the tool title is not fingerprinted and lookalike names are not judged |
| SAF-T1408 | OAuth Protocol Downgrade | Not covered |  |  | MoorAI is not in the OAuth authorization flow |
| SAF-T1407 | Server Proxy Masquerade | Not covered |  |  | a remote server's identity is not authenticated beyond its configured route |
| SAF-T1503 | Env-Var Scraping | Not covered |  |  | a stdio server reads its own environment without crossing anything MoorAI watches |
| SAF-T1501 | Full-Schema Poisoning (FSP) | Partial | #60, #50 | tools/list scan (tool stage); Tool-poisoning scan (#60, mcp-tool-poisoning); Hidden content in tool metadata (#50, mcp-hidden-canary) | schema strings (descriptions, titles, defaults, enums, property names) by the same lexical detectors; coordination across paths is not modelled |
| SAF-T1502 | File-Based Credential Harvest | Partial | #55, #39, #60 | Credential-file access (#55, cred-file-access); Files named in MCP arguments; Secret-file upload (#55, secret-file-upload); Tool description asking for a credential file (#60, mcp-tool-cred-path); Tool-result scan (file stage); Secret-shape detectors (#39) | known credential locations (SSH, cloud, .env, git, keychain) and secret-shaped values in results |
| SAF-T1504 | Token Theft via API Response | Partial | #39 | Tool-result scan (file stage); Secret-shape detectors (#39) | token shapes the secret detectors know, in MCP results; forwarded by default (#39 notifies) unless policy denies |
| SAF-T1505 | In-Memory Secret Extraction | Partial | #55, #59 | Credential-file access (#55, cred-file-access); Environment dump staged for egress (session-risk sequence); Session risk: taint, sequences, slow exfiltration (#59) | environment dumps the agent runs (printenv piped to grep for secrets; env to a file or /proc/*/environ, then outbound); process memory and runtime state are not read |
| SAF-T1507 | Authorization Code Interception | Not covered |  |  | MoorAI is not in the OAuth authorization flow |
| SAF-T1506 | Infrastructure Token Theft | Partial |  | Egress proxy: cloud metadata addresses refused | the egress proxy refuses cloud metadata addresses unless a rule names the IP literal; projected service-account tokens are not covered |
| SAF-T1601 | MCP Server Enumeration | Partial | #69 | Capability reconnaissance in ingested content (#69, recon-agent-capabilities) | ingested content asking the agent to list its tools, servers or permissions; enumeration by the host is not flagged |
| SAF-T1602 | Tool Enumeration | Not covered |  |  | tools/list is issued by the host and is never flagged |
| SAF-T1603 | System Prompt Disclosure | Covered | #51, #52 | System-prompt extraction (#51, sysprompt-extract); Instruction-file leakage (#52, instr-leak-output) |  |
| SAF-T1604 | Server Version Enumeration | Not covered |  |  | version metadata release is not observed |
| SAF-T1605 | Capability Mapping | Partial | #69 | Capability reconnaissance in ingested content (#69, recon-agent-capabilities) | ingested content asking the agent to list its tools, servers or permissions; enumeration by the host is not flagged |
| SAF-T1606 | Directory Listing via File Tool | Not covered |  |  | directory listings through a file tool are not judged |
| SAF-T1701 | Cross-Tool Contamination | Partial | #59 | Session risk: taint, sequences, slow exfiltration (#59); Tool-result scan (file stage) | an injection-class finding on a result followed by an outbound call or credential read in the same session; other follow-on calls are not linked |
| SAF-T1703 | Tool-Chaining Pivot | Partial | #59, #64 | Session risk: taint, sequences, slow exfiltration (#59); Intent alignment: risky call vs the stated task (#64) | outbound calls after untrusted content, and risky calls whose targets the task never named |
| SAF-T1704 | Compromised-Server Pivot | Partial | #40, #3, #59 | Tool-result scan (file stage); Directives in ingested content (#40, inj-untrusted-directive); Session risk: taint, sequences, slow exfiltration (#59) | instructions in a server's results are detected, and blocked under a deny policy; the server's own side effects are not seen |
| SAF-T1706 | OAuth Token Pivot Replay | Not covered |  |  | bearer-token replay at a resource is not observed |
| SAF-T1112 | Sampling Request Abuse | Not covered |  |  | server-to-client sampling requests are not scanned |
| SAF-T1705 | Cross-Agent Instruction Injection | Partial | #66, #40 | Sub-agent delegation gate (#66); Directives in ingested content (#40, inj-untrusted-directive) | sub-agent prompts and returns inside one Claude Code session; remote agent peers are not seen |
| SAF-T1801 | Automated Data Harvesting | Partial | #59 | Session risk: taint, sequences, slow exfiltration (#59) | a mass read of distinct local files followed by an upload of 4 KB or more to a new destination; MCP resource reads are not counted |
| SAF-T1803 | Database Dump | Not covered |  |  | a database export is not recognised |
| SAF-T1707 | CSRF Token Relay | Not covered |  |  | MoorAI is not in the OAuth authorization flow |
| SAF-T1804 | API Data Harvest | Not covered |  |  | MCP resource reads and query results are not counted against the task |
| SAF-T1910 | Covert Channel Exfiltration | Partial | #71, #65, #78 | Data in a rendered image URL (#71, egress-rendered-image); Local secret value fingerprint matched on egress (#65); Credential-shaped token in egress (#65, egress-credential-shaped); Out-of-band collection hosts (#78, oast-exfil) | data in rendered-image URLs, known local secret values and credential-shaped tokens in egress, and listed collection hosts; obscured prose in an ordinary argument is not recognised |
| SAF-T1911 | Parameter Exfiltration | Partial | #39, #65, #1, #15 | Argument checks: detectors over tools/call arguments; Secret-shape detectors (#39); Personal and payment data detectors (#1, #15); Local secret value fingerprint matched on egress (#65); HTTP MCP gateway local-secret egress check (#65) | secret, payment and personal-data shapes and known local secret values in tool arguments; arbitrary confidential text is not recognised |
| SAF-T1904 | Chat-Based Backchannel | Not covered |  |  | a chat identity steering the agent is not recognised |
| SAF-T1915 | Cross-Chain Laundering via Bridges/DEXs | Not covered |  |  | no financial-tool or chain-transaction analysis |
| SAF-T2101 | Data Destruction | Covered | #43, #56 | Destructive shell command (#43, destructive-command); Destructive tool / MCP call (#56, mcp-destructive-call); High-impact actions default to human approval |  |
| SAF-T1903 | Malicious Server Control Channel | Not covered |  |  | a server's own outbound control channel is not identified |
| SAF-T2102 | Service Disruption | Partial | #38, #53 | Runaway-loop circuit breaker (#38); Oversized input (#53, oversized-input); HTTP MCP gateway response size cap; HTTP MCP gateway per-client cool-down | runaway loops, oversized inputs, the gateway's response-size cap and opt-in per-client cool-down; volumetric attacks on a server are not seen |
| SAF-T2104 | Fraudulent Transactions | Not covered |  |  | transaction tools are not recognised and value is not bounded |
| SAF-T2105 | Disinformation Output | Not covered |  |  | false assertions and fabricated provenance are not judged |
| SAF-T2103 | Code Sabotage | Partial | #61 | Insecure code the agent writes (#61, code-* detectors) | exploitable constructs in code the agent writes; whether an edit is authorised is not judged |
| SAF-T2106 | Context Memory Poisoning via Vector Store Contamination | Partial | #21 | Vector-store and memory writes (index stage); Instructions headed into a knowledge base (#21, rag-poisoning) | instruction-carrying content on its way into a store (SDK, sidecar, MCP writes); the store is not read at retrieval and factual poisoning is not detected |
| SAF-T3001 | RAG Backdoor Attack | Partial | #21, #40 | Vector-store and memory writes (index stage); Instructions headed into a knowledge base (#21, rag-poisoning); Directives in ingested content (#40, inj-untrusted-directive) | inserts that carry an instruction, at write time, and instructions in retrieved content; a trigger-conditioned factual answer is not detected |
| SAF-T2107 | AI Model Poisoning via MCP Tool Training Data Contamination | Not covered |  |  | training-corpus contamination is outside the runtime path |
| SAF-T1901 | Outbound Webhook C2 | Partial | #78, #79, #47 | Out-of-band collection hosts (#78, oast-exfil); External email / message / webhook sends (#47, action-external-comms); Egress rules (binary, host, port, method, path) | listed request-capture hosts, webhook sends gated as external comms, and egress rules where an org sets them; a fresh attacker host is judged only by rules |
| SAF-T1805 | Context Snapshot Capture | Not covered |  |  | reads of agent transcripts or session state are not flagged |
| SAF-T1802 | File Collection | Partial | #55, #59 | Files named in MCP arguments; Credential-file access (#55, cred-file-access); Session risk: taint, sequences, slow exfiltration (#59) | credential files, the contents of files an MCP argument names (scanned at the file stage), and mass read then upload; other approved-path breaches are not judged |
| SAF-T1902 | Response-Borne Covert Channel | Partial | #50, #71 | Hidden text in fetched or generated content (#50, obf-invisible-output); Data in a rendered image URL (#71, egress-rendered-image); Tool-result scan (file stage) | hidden text and rendered-image URLs in responses; other encodings are not decoded |
| SAF-T1913 | HTTP POST Exfil | Partial | #39, #65 | HTTP MCP gateway; Argument checks: detectors over tools/call arguments; HTTP MCP gateway local-secret egress check (#65) | secret shapes and known local secret values in tools/call arguments through the HTTP gateway; other confidential content is not recognised |
| SAF-T1914 | Tool-to-Tool Exfil | Partial | #59, #65 | Session risk: taint, sequences, slow exfiltration (#59); Local secret value fingerprint matched on egress (#65) | taint-then-outbound and staged-credential sequences in one session, and known local secret values in the sink call |

Rejected credits:

| Id | Credit considered | Why it was rejected |
|---|---|---|
| SAF-T1005 | HTTP MCP gateway | the gateway binds loopback by default to protect itself; it does not detect or close an exposed MCP endpoint |
| SAF-T1008 | Tool-drift baselines (description, schema, shadowing) | the shadow signal is a second server claiming the same tool NAME (SAF-T1004, SAF-T1401), not one descriptor steering a different tool |
| SAF-T1105 | #55, Files named in MCP arguments | the file-argument check judges a path that lands on a credential file (credited under SAF-T1502); it does not compare the path with the server's configured scope |
| SAF-T1105 | #64, Entitlement envelope (#64) | the entitlement envelope's paths apply to the hook's Read, Bash and Write branches; an MCP call is checked by server name only |
| SAF-T1203 | MCP server reputation at first launch and version change | reputation is cached per server identity and version; a binary patched in place keeps both and is not re-scored |
| SAF-T1304 | Placeholder credentials (model proxy, MCP gateway) | keeps a bound secret on its own gateway route; tokens a server forwards downstream are outside it |
| SAF-T1307 | #64, Intent alignment: risky call vs the stated task (#64) | judges the model's call against the user's task (SAF-T1302); it does not carry the initiating principal's identity through an intermediary |
| SAF-T1403 | #38, Runaway-loop circuit breaker (#38) | counts repeated identical tool calls, not repeated approval prompts to a person |
| SAF-T1404 | HTTP MCP gateway staged message validation | validates message structure, not integrity; a well-formed substituted response passes |
| SAF-T1503 | #65, Local secret value fingerprint matched on egress (#65) | the local-secret fingerprint watches the agent's egress; a stdio server reading its own environment never crosses it |
| SAF-T1602 | #69, Capability reconnaissance in ingested content (#69, recon-agent-capabilities) | #69 catches content asking the model to recount its tools (credited under SAF-T1601 and SAF-T1605); the host's tools/list is not flagged |
| SAF-T1112 | Tool-result scan (file stage) | server-to-client requests (sampling/createMessage) are excluded from the result scan by design (resultOfResponse in mcp-proxy/tool-scan.mjs) |
| SAF-T1803 | #59, Session risk: taint, sequences, slow exfiltration (#59) | the archive-then-outbound sequence needs an outbound step; a dump kept local, or read through a database tool, raises nothing |
| SAF-T1804 | #59, Session risk: taint, sequences, slow exfiltration (#59) | mass reads count distinct local files, not MCP resource reads or query results |
| SAF-T1904 | #47, External email / message / webhook sends (#47, action-external-comms) | gates the agent sending a message; it does not see a chat identity steering the agent |
| SAF-T1903 | Sandbox network policy from egress rules (MXC, Seatbelt, OpenShell) | egress rules confine whatever is routed through them, but nothing identifies a server's control channel, and an MCP server process behind them was not measured |
| SAF-T2104 | #11 | bec-payment is a coach-mode match on a few payment-change phrases; it neither recognises transaction tools nor bounds value |
| SAF-T2105 | #75, Deceptive link in output (#75, out-link-deceptive) | catches a link whose shown address differs from its target; false assertions and fabricated provenance are not judged |
| SAF-T1805 | #73, Agent transcript tampering (#73, agent-history-tamper) | deliberately silent on reads of transcripts; it fires on deletion and rewriting |
| SAF-T1206 | #65 | the local-secret fingerprint matches known values leaving the device; a credential written into config is not egress |

### Careful Adoption of Agentic AI Services

| Id | Title | Status | MoorAI threats | Evidence | Limit or reason |
|---|---|---|---|---|---|
| design/controlled-context/1 | Structure prompt context using a clear instruction hierarchy to ensure agent behaviour aligns with intended priorities and constraints | Not applicable |  |  | (agent-build) how the agent's own prompt context is structured |
| design/controlled-context/2 | Implement grounding by providing relevant contextual information using retrieval augmented generation and prompt engineering to mitigate hallucinations and other LLM-related errors | Not applicable |  |  | (agent-build) grounding the agent's model with retrieval and prompt engineering |
| design/oversight-mechanisms/1 | Include mechanisms to facilitate human control and oversight to ensure that agentic AI systems approved for non-sensitive, low-risk tasks cannot autonomously progress into higher-risk activities | Partial | #64 | Entitlement envelope (#64); Declared workload profiles | declared envelopes and workload profiles refuse out-of-scope tools, paths, MCP servers and hosts; the risk level of a task is not modelled |
| design/oversight-mechanisms/2 | Implement human control points throughout the agent workflow, such as live monitoring and interruption during task execution, mandatory human approval for decision-making steps, auditing and reversibility following task execution to ensure security | Partial | #11, #43, #46, #47, #48, #49 | High-impact actions default to human approval; Kill verdict terminates the agent session; Content-free action audit log | approval (justify) for listed high-impact action classes, a kill verdict that ends the session, and a content-free audit; no live interruption on demand and no reversibility |
| design/oversight-mechanisms/3 | Define explicit control flows to bound autonomous planning and prevent agents from deviating beyond authorised objectives or actions | Partial | #64 | Entitlement envelope (#64); Declared workload profiles | bounds the actions an agent may take, not its plan |
| design/identity-management/1 | Embed strong identity management mechanisms into agents using manage identity services, decentralised identifiers or public key infrastructure | Not covered |  |  | MoorAI does not issue or manage agent identities |
| design/identity-management/2 | Authenticate all inter-agent and agent-to-service API calls using mutual transport layer security to ensure non-repudiation | Not covered |  |  | MoorAI does not terminate or authenticate agent-to-service TLS |
| design/identity-management/3 | Maintain a trusted registry and bind identities to authorised roles; periodically reconcile the registry against the live set of agents | Not covered |  |  | no registry of agent identities bound to roles |
| design/identity-management/4 | Deny access for any agent or cryptographic key that is not present in the trusted registry | Not covered |  |  | no registry of agent identities or keys to deny against |
| design/identity-management/5 | Apply role-based identity management and limit agent permissions to the minimum scope required for approved tasks | Partial | #64 | Entitlement envelope (#64); Per-tool argument rules (policy.mcpToolRules) | per-agent envelope of tools, paths and MCP servers, and per-tool argument rules; roles and the agent's own permissions are not managed |
| design/identity-management/6 | Enforce identity-based boundaries to restrict agents’ to authorised actions only | Partial | #64 | Declared workload profiles | workload profiles keyed on a service id or repository; the strongest match is a service id from the system file or launch environment |
| design/defence-in-depth/1 | Avoid reliance on a single security mechanism by implementing multiple, overlapping layers of security controls | Partial |  | MCP stdio proxy; HTTP MCP gateway; Model proxy; Egress proxy: cloud metadata addresses refused | MoorAI adds independent layers (hook, MCP proxy and gateway, model proxy, egress proxy) that overlap on MCP and model traffic; it is one product, not the whole defence |
| design/defence-in-depth/2 | Apply security controls at all points where information enters or exits the system, including user inputs, tool calls, data pre-processing and model inference | Partial | #2, #3, #40, #21 | Instruction-override detectors (#3, inj-ignore); Argument checks: detectors over tools/call arguments; Tool-result scan (file stage); Vector-store and memory writes (index stage) | prompts, tool calls and results, content headed for an index, and model calls through the model proxy; only on hooked hosts and routed traffic |
| design/defence-in-depth/3 | Separate agents for different functions and apply strict boundaries and operational controls to the handoffs from one agent to another | Partial | #66 | Sub-agent delegation gate (#66); Entitlement envelope (#64) | a sub-agent delegation gets the parent's envelope and its prompt is scanned; one host only |
| develop/comprehensive-testing/1 | Use reward modelling and adversarial testing to detect specification gaming, explicitly incorporating security constraints alongside performance goals | Not applicable |  |  | (agent-build) training and testing the agent's model |
| develop/comprehensive-testing/2 | Train LLM agents in simulated, controlled environments to learn the implications of actions without causing real security harm | Not applicable |  |  | (agent-build) training the agent's model |
| develop/comprehensive-testing/3 | Leverage synthetic data generation to create adversarial training examples that reflect real-world operating scenarios | Not applicable |  |  | (agent-build) training data generation for the agent's model |
| develop/comprehensive-testing/4 | Apply active learning to adversarial training scenarios to expose agents to high uncertainty inputs and more efficiently discover unexpected behaviours | Not applicable |  |  | (agent-build) training the agent's model |
| develop/appropriate-evaluation/1 | Use relevant threat models to define evaluation scenarios, including edge cases beyond typical training conditions | Not applicable |  |  | (agent-build) evaluating the agent before deployment |
| develop/appropriate-evaluation/2 | Use techniques, such as Best-of-N sampling (selecting the best output from multiple model responses to the same prompt), multistep reasoning prompts and inference time scaling to draw out the full range of agent behaviours and skills | Not applicable |  |  | (agent-build) evaluating the agent before deployment |
| develop/appropriate-evaluation/3 | Evaluate systems across different levels of autonomy to understand performance and risk under changing environmental conditions, including changes in tool, models and resource access, such as web search or code execution | Not applicable |  |  | (agent-build) evaluating the agent before deployment |
| develop/appropriate-evaluation/4 | Vary contextual conditions, such as presence or absence of other agents and the timing of evaluation, to understand their impact on task performance | Not applicable |  |  | (agent-build) evaluating the agent before deployment |
| develop/appropriate-evaluation/5 | Conduct capability evaluations continuously across the agent development lifecycle | Not applicable |  |  | (agent-build) evaluating the agent across its development lifecycle |
| develop/input-management/1 | Implement robust input validation and sanitisation for all agent inputs | Partial | #2, #3, #40, #50 | Instruction-override detectors (#3, inj-ignore); Directives in ingested content (#40, inj-untrusted-directive); HTTP MCP gateway staged message validation; Masking a finding in place (Claude Code hook) | detection on prompts, files and tool results on hooked surfaces, and message validation through the HTTP gateway; sanitisation is masking on the Claude Code hook only |
| develop/input-management/2 | Integrate prompt injection filters and semantic analysis to detect malicious instructions | Covered | #2, #3, #40, #50, #70, #72, #74, #58 | Instruction-override detectors (#3, inj-ignore); Directives in ingested content (#40, inj-untrusted-directive); Invisible or smuggled instructions (#50, obf-invisible-instructions); On-device model second opinion (#58) |  |
| develop/input-management/3 | Validate context to ensure the system correctly interprets intent before execution | Partial | #64 | Intent alignment: risky call vs the stated task (#64) | a lexical check that a risky call's targets were named in the task; interpretation of intent in general is not checked |
| develop/red-teaming/1 | Deploy sandbox environments to test agent behaviour before production deployment | Not applicable |  |  | (organisational) pre-production testing practice |
| develop/red-teaming/2 | Conduct red teaming exercises to identify potential loopholes and unintended behaviour | Not applicable |  |  | (organisational) red-team exercise against the agent |
| develop/red-teaming/3 | Use capability elicitation techniques to probe for unexpected or emergent abilities, especially any that could create substantial resource or environment risks | Not applicable |  |  | (organisational) capability elicitation against the agent |
| develop/red-teaming/4 | Implement agent simulation tests, such as multi-agent red teaming or chaos testing. | Not applicable |  |  | (organisational) simulation testing of the agent |
| develop/resilience/1 | Embed agentic AI systems with fail-safe defaults and containment mechanisms that limit the blast radius of unexpected behaviours | Partial |  | Kill verdict terminates the agent session; Desktop host agent isolation (macOS Seatbelt); Offline fail-closed posture (opt-in) | a kill verdict ends the agent session on the desktop host, macOS isolation is opt-in, and MoorAI itself fails open unless the fail-closed posture is set |
| develop/resilience/2 | Implement data loss prevention controls specifically tuned to AI agent behaviours | Covered | #1, #15, #39, #44, #55, #59, #65, #77 | Secret-shape detectors (#39); Personal and payment data detectors (#1, #15); Protected health information (#44, phi-hipaa); Secret-file upload (#55, secret-file-upload); Local secret value fingerprint matched on egress (#65); Session risk: taint, sequences, slow exfiltration (#59) |  |
| develop/resilience/3 | Implement versioning and rollback mechanisms to safely revert a system to known-good agent behaviours when unpredictability is observed | Not covered |  |  | MoorAI does not version or roll back agent behaviour |
| develop/accountability/1 | Integrate comprehensive artefact logging mechanisms by default | Partial |  | Content-free action audit log; Chain-stamped session ledger; Tamper-evident record chain | content-free records of every tool call MoorAI sees, by default; no content or reasoning is kept |
| develop/accountability/2 | Integrate unified audit logs for all inter-agent interactions to maintain observability of all agent exchanges | Partial | #66 | Sub-agent delegation gate (#66); Chain-stamped session ledger | sub-agent handoffs on one host are logged; remote agent-to-agent exchanges are not seen |
| develop/accountability/3 | Use interpretability tools to ensure observability of and reasoning behind agent decisions | Not applicable |  |  | (agent-build) interpretability of the agent's model |
| develop/accountability/4 | Require specific information referencing for agents that show where key aspects of their response originated from. | Not applicable |  |  | (agent-build) source referencing in the agent's responses |
| develop/third-party-components/1 | Verify all external third-party components originate from trusted sources and are up to date before inclusion in agentic AI systems | Partial | #57, #62 | MCP server reputation scoring; Registry provenance and repository link check; Install from an untrusted source (#57, pkg-install-untrusted); Hallucinated or typosquatted dependency (#62, dep-typosquat) | MCP server packages scored at first launch (provenance, repository link, known-malicious and typosquat names) and install commands judged; whether a component is up to date is not checked |
| develop/third-party-components/2 | Maintain a trusted registry of third-party components | Partial | #25 | MCP server allow-list (policy.mcpAllow); Approved tool baselines and quarantine (mcpToolDrift: block) | an allow-list of MCP servers and console-approved tool fingerprints; other component types are not registered |
| develop/third-party-components/3 | Reference CISA’s A Shared Vision of Software Bill of Materials (SBOM) for Cybersecurity and 2025 Minimum Elements for a Software Bill of Materials (SBOM) when procuring agentic AI systems | Not applicable |  |  | (organisational) a procurement reference to CISA SBOM documents |
| develop/third-party-components/4 | Restrict tool use to an approved allow list of tools and versions that are regularly verified as secure | Partial | #25 | MCP server allow-list (policy.mcpAllow); Approved tool baselines and quarantine (mcpToolDrift: block); Entitlement envelope (#64) | servers by label and approved tool fingerprints; versions are not pinned and the tools are not verified as secure |
| develop/third-party-components/5 | Verify agent behaviour related to tool usage aligns with documented security policies | Partial | #64, #25 | Argument checks: detectors over tools/call arguments; Entitlement envelope (#64); Signature-verified policy | each tool call is judged against the signed policy on hooked hosts and on MCP traffic routed through the proxy or gateway |
| develop/third-party-components/6 | Log agent tool usage and ensure results are captured in system logs in a human-readable format | Partial |  | Content-free action audit log; Verdict provenance (policy id, reason code) | content-free records (tool, server, decision, reason code, hash); results are not captured |
| develop/third-party-components/7 | Establish trigger-action protocols that automatically restrict agent permissions when unexpected behaviour emerges | Partial | #38, #59 | Runaway-loop circuit breaker (#38); Session risk: taint, sequences, slow exfiltration (#59) | the circuit breaker can pause a session and session risk can raise outbound calls to ask; permissions themselves are not changed |
| develop/third-party-components/8 | Codify separation of duties by defining roles, such as ‘Orchestrator’, ‘Reader’ and ‘Actuator’ with clear boundaries, consensus mechanisms and delegations expiry | Not covered |  |  | no Orchestrator / Reader / Actuator roles or consensus mechanism |
| develop/third-party-components/9 | Implement consensus controls for actions based on risk; use multi agent approval for moderate stakes actions and human in the loop approval in addition to multi agent consensus for high stakes actions | Not covered |  |  | no multi-agent consensus control |
| develop/third-party-components/10 | Prohibit agents from modifying their own privileges or initiating unapproved delegation without explicit expiry timers and recorded grant chains | Partial | #46, #48, #66 | Security / IAM / firewall change (#46, action-security-config); User, token or API-key creation (#48, action-credential-create); Sub-agent delegation gate (#66); Agent posture: hook state and weakened settings; Time-boxed JIT elevation grants | IAM and credential changes gated, delegation held to the parent's envelope, weakened agent settings reported, elevation grants time-boxed; grant chains are not recorded |
| develop/third-party-components/11 | Standardise tool descriptions using a consistent format that avoids persuasive language | Partial | #60 | tools/list scan (tool stage); Tool-poisoning scan (#60, mcp-tool-poisoning) | directive and hidden content in third-party tool descriptions is flagged; descriptions are not standardised |
| deploy/threat-modelling/1 | Perform realistic threat modelling using up-to-date risk taxonomies for agentic AI systems, such as OWASP GenAI Security Project and MITRE ATLAS™ | Not applicable |  |  | (organisational) threat modelling practice |
| deploy/threat-modelling/2 | Design and implement security controls that address emerging and evolving agent capabilities | Not applicable |  |  | (organisational) control design process |
| deploy/threat-modelling/3 | Harmonise agentic AI controls with existing security frameworks, national guidance and allied agreements, such as common Zero Trust principles and the National Institute of Standards and Technology’s Zero Trust Architecture guidance | Not applicable |  |  | (organisational) harmonising controls with frameworks |
| deploy/threat-modelling/4 | Develop and test incident response procedures to detect, contain and recover from agent compromise | Not applicable |  |  | (organisational) incident response procedure |
| deploy/threat-modelling/5 | Establish regular third-party reviews of privileged architectures, share actionable intelligence with trusted partners and update risk models to reflect emerging malicious trends | Not applicable |  |  | (organisational) third-party review and intelligence sharing |
| deploy/governance/1 | Implement and maintain governance policies to manage autonomous agents | Not applicable |  |  | (organisational) governance policy |
| deploy/governance/2 | Define legal accountability and risk ownership for agentic AI systems in policies | Not applicable |  |  | (organisational) legal accountability and risk ownership |
| deploy/governance/3 | Upskill the organisation to build AI literacy | Not applicable |  |  | (organisational) training staff |
| deploy/progressive-deployment/1 | Implement phased deployment with progressively increasing access and autonomy, limiting the action space where required, such as restricted APIs or sandboxing | Partial | #64 | Entitlement envelope (#64); Declared workload profiles; Desktop host agent isolation (macOS Seatbelt) | the action space can be restricted (envelope, profiles, opt-in isolation); phasing is the operator's |
| deploy/progressive-deployment/2 | Use graduated autonomy to incrementally increase agent independence whilst maintaining human oversight and understanding | Not applicable |  |  | (organisational) how far to extend autonomy is an operator decision |
| deploy/progressive-deployment/3 | Use continuous evaluation to determine when to expand system scope or when to roll back autonomy and access in response to failures | Not applicable |  |  | (organisational) deciding to expand or roll back scope |
| deploy/secure-by-default/1 | Set system configurations to fail-safe by default requiring agents to stop and escalate issues to human reviewers in uncertain scenarios | Partial | #64, #59 | Intent alignment: risky call vs the stated task (#64); Session risk: taint, sequences, slow exfiltration (#59); High-impact actions default to human approval; Offline fail-closed posture (opt-in) | uncertain risky calls can be raised to ask a person; MoorAI itself fails open unless the fail-closed posture is set |
| deploy/secure-by-default/2 | Use error-handling and failover management to reduce the impact of system failures | Not applicable |  |  | (agent-build) the agent's own error handling |
| deploy/secure-by-default/3 | Implement graceful degradation models so that agents maintain partial functionality even if some functions fail | Not applicable |  |  | (agent-build) the agent's own degradation design |
| deploy/guardrails-and-constraints/1 | Specify clear, constrained objectives with explicit ‘do-not-do’ rules | Not applicable |  |  | (agent-build) specifying the agent's objectives |
| deploy/guardrails-and-constraints/2 | Implement guardrails and hard constraints, such as deny lists and API-level safety policies | Covered | #25, #63, #64 | MCP server allow-list (policy.mcpAllow); Per-tool argument rules (policy.mcpToolRules); Egress rules (binary, host, port, method, path); Model-endpoint allow-list (#63); Entitlement envelope (#64) |  |
| deploy/guardrails-and-constraints/3 | Establish declarative safety contracts with constraints and guardrails that agents cannot override | Partial |  | Signature-verified policy; Agent posture: hook state and weakened settings | the policy is signed and an edited cache counts as no policy; the hook runs as the user, so removing it is reported, not prevented |
| deploy/guardrails-and-constraints/4 | Apply a layered set of guardrail mechanisms, ranging from anomaly detection and rule-based filtering to specialised machine learning algorithms that detect and filter prohibited behaviour | Covered | #58, #59, #64 | Instruction-override detectors (#3, inj-ignore); Session risk: taint, sequences, slow exfiltration (#59); Learned per-agent first-seen drift (#64); On-device model second opinion (#58) |  |
| deploy/guardrails-and-constraints/5 | Prioritise review of high-risk incidents, including cases where guardrails are triggered or actions are denied by human reviewers | Partial |  | Verdict provenance (policy id, reason code); Content-free OpenTelemetry export | alerts carry risk level and reason code for triage in the console or a SIEM; the review itself is the operator's |
| deploy/guardrails-and-constraints/6 | Deploy a secondary agent to validate new tasks against policy before execution | Not covered |  |  | no secondary agent validates tasks before execution |
| deploy/isolation/1 | Implement isolation and segmentation to limit blast radius of agent failure scenarios | Partial |  | Desktop host agent isolation (macOS Seatbelt); Sandbox network policy from egress rules (MXC, Seatbelt, OpenShell); Egress proxy: cloud metadata addresses refused | opt-in Seatbelt isolation for agents the macOS desktop host launches, sandbox network policy generated from egress rules, and the egress proxy |
| deploy/isolation/2 | Separate high-risk agents into distinct domains | Not applicable |  |  | (organisational) deployment topology |
| deploy/isolation/3 | Isolate agents into enclaves with no write access to logs | Partial | #73 | Tamper-evident record chain; Signed MCP enforcement decisions; Agent transcript tampering (#73, agent-history-tamper); Desktop host agent isolation (macOS Seatbelt) | chain-stamped and signed records make edits detectable, and the isolated host denies the agent its console record; without isolation ~/.moorai stays in the agent's write scope |
| operate/monitoring-and-auditing/1 | Employ monitoring tools that enhance human oversight of agentic AI systems | Covered |  | Content-free OpenTelemetry export; Verdict provenance (policy id, reason code); Content-free action audit log |  |
| operate/monitoring-and-auditing/2 | Monitor all agent operations, including internal processes, not just the inputs and outputs | Partial |  | Content-free action audit log; Sub-agent delegation gate (#66); Claimed success vs failed tool calls | tool calls, sub-agents, failures and end-of-turn claims; internal reasoning is not seen |
| operate/monitoring-and-auditing/3 | Monitor and log identity and privilege changes and audit regularly for drift, impersonation or misconfiguration | Partial | #46, #48, #64 | Security / IAM / firewall change (#46, action-security-config); User, token or API-key creation (#48, action-credential-create); Entitlement envelope (#64); Agent posture: hook state and weakened settings | IAM and credential changes the agent makes, out-of-envelope actions, and weakened agent settings; identity impersonation is not detected |
| operate/monitoring-and-auditing/4 | Monitor agent outputs and behaviour for indicators of bias, emerging data drift and other anomalous patterns, including user prompts, tool calls, memory interactions, internal reasoning, decisions made and actions taken | Partial | #64, #59, #22 | Learned per-agent first-seen drift (#64); Session risk: taint, sequences, slow exfiltration (#59); Instructions written into agent memory (#22, memory-poisoning) | prompts, tool calls, memory writes and outputs; bias and internal reasoning are not monitored |
| operate/monitoring-and-auditing/5 | Maintain comprehensive logs and real-time monitoring of live agent behaviour and decision-making | Partial |  | Content-free action audit log; Chain-stamped session ledger; Content-free OpenTelemetry export | content-free logs and live alerts; decision-making is not logged |
| operate/monitoring-and-auditing/6 | Implement runtime monitoring and anomaly detection using rules or behavioural baselines to identify unusual patterns and trigger alerts or pauses | Covered | #64, #59, #38 | Learned per-agent first-seen drift (#64); Learned per-agent behavioural baseline; Session risk: taint, sequences, slow exfiltration (#59); Runaway-loop circuit breaker (#38) |  |
| operate/monitoring-and-auditing/7 | Establish anomaly detection mechanisms that flag discrepancies between stated intentions and observed behaviours | Partial | #64 | Intent alignment: risky call vs the stated task (#64); Claimed success vs failed tool calls | a lexical task-to-target check on risky calls, and success claims compared with failed calls |
| operate/monitoring-and-auditing/8 | Use multiple independent monitoring systems that cross-validate agent reports and system logs | Partial |  | Hook vs proxy vs gateway MCP usage cross-check; Claimed success vs failed tool calls | hook, proxy and gateway MCP counts are compared per device and day, and the agent's success claim is compared with tool outcomes |
| operate/monitoring-and-auditing/9 | Monitor for goal drift by comparing active objectives against approved baseline specifications before execution | Partial | #64 | Entitlement envelope (#64); Declared workload profiles | actions are compared with an approved envelope before they run; objectives are not |
| operate/monitoring-and-auditing/10 | Integrate source checks with agent logs to record which tools the system used and what information it retrieved | Partial |  | Content-free action audit log; Content-free destination log | the tools used and the destinations reached are recorded content-free; what was retrieved is not stored |
| operate/monitoring-and-auditing/11 | Implement auditing practices that combine human review with automated analysis of system logs | Partial |  | Compliance evidence packs; Tamper-evident record chain | automated evidence packs and chain verification support the review; the human review is the operator's |
| operate/monitoring-and-auditing/12 | Support adaptive defences by using monitoring data to enable rapid responses, such as patches based on problems identified in system logs | Not applicable |  |  | (organisational) operator response process |
| operate/monitoring-and-auditing/13 | Use storage-efficient logging methods to manage log volume without losing critical information | Partial |  | Chain-stamped session ledger; Content-free action audit log | content-free, capped logs; the oldest rows are trimmed |
| operate/monitoring-and-auditing/14 | Conduct regular security assessments, including penetration testing and red team exercises specifically targeting agentic behaviours | Not applicable |  |  | (organisational) security assessment practice |
| operate/validate-outputs/1 | Validate agent outputs by confirming accuracy of critical aspects against multiple sources | Not covered |  |  | agent outputs are not checked against other sources |
| operate/validate-outputs/2 | Validate agents through cross-checking in environments with redundant agents that validate each other’s outputs | Not covered |  |  | no redundant agents |
| operate/validate-outputs/3 | Validate tool responses to prevent malicious or unsafe instructions and standardise tool descriptions to avoid persuasive language | Partial | #40, #3, #60 | Tool-result scan (file stage); Directives in ingested content (#40, inj-untrusted-directive); tools/list scan (tool stage); Tool-poisoning scan (#60, mcp-tool-poisoning) | tool results and descriptions are scanned, results blocked under a deny policy (report-first by default); descriptions are not standardised |
| operate/human-in-the-loop/1 | Ensure decisions about when human approval is required are determined by system designers or operators, not delegated to the agentic AI system | Covered |  | High-impact actions default to human approval; Signature-verified policy |  |
| operate/human-in-the-loop/2 | Prevent agents from autonomously executing high impact actions or outputs without prior human approval | Partial | #11, #43, #46, #47, #48, #49 | High-impact actions default to human approval | listed action classes, matched by pattern; the Claude Code hook asks, while the MCP proxy treats justify as allow and record |
| operate/human-in-the-loop/3 | Insert human-in-the-loop review or approval checkpoints for actions where the cost of error is high, such as system resets, network egress or deletion of critical records. | Partial | #43, #56, #47 | Destructive shell command (#43, destructive-command); Destructive tool / MCP call (#56, mcp-destructive-call); External email / message / webhook sends (#47, action-external-comms); Egress rules (binary, host, port, method, path) | deletion and external sends can require approval; network egress is allowed, alerted or blocked by rule, not held for approval |
| operate/human-in-the-loop/4 | Quarantine requests to delete logs or audit records until reviewed and approved by a human | Partial | #73, #43 | Agent transcript tampering (#73, agent-history-tamper); Destructive shell command (#43, destructive-command) | deleting agent transcripts and destructive commands; system and audit logs are not recognised as such |
| operate/human-in-the-loop/5 | Clearly assign responsibility and accountability for errors or adverse outcomes caused by the system | Not applicable |  |  | (organisational) assigning responsibility |
| operate/human-in-the-loop/6 | Conduct risk assessments to classify agent actions by potential impact, likelihood and reversibility, and apply appropriate safeguards | Partial |  | Rule base: severity x likelihood per threat | the rule base scores each action class by severity and likelihood; reversibility is not scored, and assessing the organisation's own actions stays with it |
| operate/performance-monitoring/1 | Assess agents’ ability to evade security measures particularly in sensitive or high-impact systems | Not applicable |  |  | (organisational) assessment of the agent |
| operate/performance-monitoring/2 | Conduct regular assessments of an agent’s ability to bypass safeguards, such as communication barriers, guardrails, monitors, human-in-the-loop processes and input filters | Not applicable |  |  | (organisational) assessment of the agent |
| operate/performance-monitoring/3 | Use the results from these evaluations to validate existing controls and guide the development of stronger security measures | Not applicable |  |  | (organisational) using assessment results |
| operate/performance-monitoring/4 | Limit agent resource usage by applying controls, such as rate-limit components to interrupt long-running tasks and disrupt malicious workflows | Partial | #38, #53 | Runaway-loop circuit breaker (#38); Oversized input (#53, oversized-input) | runaway loops pause a session in deny mode, oversized input is flagged; rate and call budget are opt-in |
| operate/privileges-and-authentication/1 | Limit privileges of AI agents to the minimum required for its task | Partial | #64 | Entitlement envelope (#64) | MoorAI confines what the agent does; it does not grant privileges |
| operate/privileges-and-authentication/2 | Restrict scope of privileges to narrowest possible level to allow fine-grained control over allowed actions | Partial | #64 | Per-tool argument rules (policy.mcpToolRules); Entitlement envelope (#64) | per-tool argument rules and path-prefix envelopes |
| operate/privileges-and-authentication/3 | Implement agent reputation and trust scoring mechanisms and reduce trust levels when anomalous behaviour is detected | Partial | #59 | Session risk: taint, sequences, slow exfiltration (#59); MCP server reputation scoring | a decaying session risk score raises outbound calls to ask; reputation scores MCP servers, not agents |
| operate/privileges-and-authentication/4 | Require just-in-time credentials for high-impact or privileged actions | Partial | #64 | Time-boxed JIT elevation grants | time-boxed elevation grants for out-of-envelope capabilities; MoorAI issues no credentials |
| operate/privileges-and-authentication/5 | Verify API caller identity against a user or agent groups | Not covered |  |  | API caller identity is not verified |
| operate/privileges-and-authentication/6 | Authenticate agents with fresh cryptographic proofs before every privileged call | Not covered |  |  | agents are not authenticated |
| operate/privileges-and-authentication/7 | Require cryptographic signing for authorised commands and instructions | Not covered |  |  | agent commands are not required to be signed |
| operate/privileges-and-authentication/8 | Apply cryptographic integrity checks for task definitions and constraints | Partial |  | Signature-verified policy | the constraints (MoorAI's policy) are signed and verified on the device; task definitions are not |
| operate/privileges-and-authentication/9 | Require agents to perform cryptographic attestation where agents must prove that they are running expected and unmodified code | Not covered |  |  | no code attestation of the agent |
| operate/privileges-and-authentication/10 | Continuously verify identity and authorisation at runtime using a centralised policy decision point for each request | Partial |  | Argument checks: detectors over tools/call arguments; Signature-verified policy | every hooked call is decided against a centrally distributed, verified policy; identity is not verified |
| future/threat-intelligence/1 | Strengthen collaboration between stakeholders to keep pace with evolving threats to agentic AI systems | Not applicable |  |  | (organisational) collaboration |
| future/threat-intelligence/2 | Coordinate with major AI developers and government organisations to compile and maintain threat information | Not applicable |  |  | (organisational) collaboration |
| future/threat-intelligence/3 | Adopt a collaborative security approach, such as those described in CISA’s AI Cybersecurity Collaboration Playbook | Not applicable |  |  | (organisational) collaboration |
| future/threat-intelligence/4 | Implement alerting, data collection and tracking methods for malicious actors and techniques | Partial |  | Content-free OpenTelemetry export; STIX 2.1 export of findings | content-free alerts to the console or a SIEM and STIX 2.1 export; actor tracking is not done |
| future/threat-intelligence/5 | Conduct targeted analysis of threats and capabilities over time to improve situational awareness | Not applicable |  |  | (organisational) threat analysis practice |
| future/threat-intelligence/6 | Harmonise threat intelligence across industries to build shared threat taxonomies that improve threat modelling and support more effective mitigation design | Not applicable |  |  | (organisational) shared taxonomies |
| future/agent-specific-evaluations/1 | Develop robust evaluation methods to address the gaps in validating agentic AI systems | Not applicable |  |  | (organisational) research |
| future/agent-specific-evaluations/2 | Generate benchmark datasets to cover new domains and represent realistic deployment contexts | Not applicable |  |  | (organisational) research |
| future/agent-specific-evaluations/3 | Use evaluation results to validate emerging security practices and identify failure points in agents | Not applicable |  |  | (organisational) research |
| future/agent-specific-evaluations/4 | Share evaluation findings to strengthen security assessments and support the development of improved security practices across the field | Not applicable |  |  | (organisational) research |
| future/system-theoretic-analysis/1 | Use system-theoretic approaches to analyse agentic AI systems and identify appropriate security measures | Not applicable |  |  | (organisational) analysis method |
| future/system-theoretic-analysis/2 | Apply System Theoretic Process Analysis (STPA) and its security extension, STPA for Security (STPA-Sec), to analyse notional or operational systems, identify security issues, assess mission risk and inform potential mitigations | Not applicable |  |  | (organisational) analysis method |
| future/system-theoretic-analysis/3 | Use Causal Analysis using System Theory (CAST) to investigate security incidents and identify underlying root causes at the system level | Not applicable |  |  | (organisational) analysis method |
| future/system-theoretic-analysis/4 | Apply STPA and CAST to address safety and security concerns concurrently across agentic AI system lifecycles | Not applicable |  |  | (organisational) analysis method |
| appendix-a/design/1 | Implement strong authentication by following Secure by Design principles | Not applicable |  |  | (agent-build) authentication design of the agent system |
| appendix-a/design/2 | Design transparency requirements into the system architecture to enable detection of deception indicators | Partial |  | Claimed success vs failed tool calls; Autonomous-agent behaviour signature (moorai-agentwatch) | success claims over failed calls and autonomous-attack tells; transparency is not designed into the agent |
| appendix-a/design/3 | Use frameworks, such as zero trust, the Application Security Verification Standard or OAuth2 | Not applicable |  |  | (organisational) choice of frameworks |
| appendix-a/design/4 | Build system infrastructure in a secure, sandboxed environment with encryption, rate limiting and sanitisation | Not applicable |  |  | (agent-build) building the agent's infrastructure |
| appendix-a/design/5 | Apply the principle of least privilege, assigning only the minimum access required for each role | Partial | #64 | Entitlement envelope (#64) | MoorAI confines what the agent does; it does not assign access |
| appendix-a/design/6 | Limit entitlements to the exact resources, operations and timeframes needed | Partial | #64 | Entitlement envelope (#64); Time-boxed JIT elevation grants | resources and operations by envelope; timeframes by time-boxed elevation grants only |
| appendix-a/design/7 | Replace static, long-lived secrets with ephemeral credentials that expire when the job is complete | Not covered |  |  | MoorAI issues no ephemeral credentials |
| appendix-a/design/8 | Dynamically scope privilege for sub-tasks and revoke elevated rights immediately when finished, mitigating scope creep | Partial | #66, #64 | Sub-agent delegation gate (#66); Time-boxed JIT elevation grants | a sub-agent gets the parent's envelope and elevation grants expire; privilege is not scoped per sub-task |
| appendix-a/design/9 | Build applications with secure protocols and safe defaults that adhere to communication standards and security policies | Not applicable |  |  | (agent-build) building the agent's protocols |
| appendix-a/design/10 | Implement message validation by default so that message components include integrity and freshness checks before use | Not covered |  |  | no integrity or freshness check on messages |
| appendix-a/development/1 | Apply secure development principles from U.S. Department of War Enterprise DevSecOps Fundamentals | Not applicable |  |  | (organisational) secure development principles |
| appendix-a/development/2 | Minimise application scope and monitor components for unusual or unexpected behaviour | Partial |  | Tool-drift baselines (description, schema, shadowing); MCP server reputation at first launch and version change; Tool-result scan (file stage) | MCP servers are watched for tool drift, reputation and their results; other components are not |
| appendix-a/development/3 | Enforce application understanding and only incorporate components into systems that the owner fully understands and accepts the risks of (including possible external effects and processes that it may trigger) | Not applicable |  |  | (organisational) owner risk acceptance |
| appendix-a/development/4 | Refer to frameworks, such as the NIST Secure Software Development Framework or SLSA’s Safeguarding artifact integrity across any software supply chain | Not applicable |  |  | (organisational) choice of frameworks |
| appendix-a/development/5 | Use supply chain risk management practices for third-party dependencies | Partial | #57, #62 | MCP server reputation scoring; Install from an untrusted source (#57, pkg-install-untrusted); Hallucinated or typosquatted dependency (#62, dep-typosquat) | install commands and MCP server packages are judged at the point of use; supply-chain risk management is the organisation's |
| appendix-a/development/6 | Apply existing governance and organisational management policies | Not applicable |  |  | (organisational) governance policy |
| appendix-a/development/7 | Conduct threat modelling using frameworks, such as OWASP Top 10:2025, MITRE ATT&CK® and MITRE D3FEND™ and use the results to inform mitigations tailored to the operational environment | Not applicable |  |  | (organisational) threat modelling practice |
| appendix-a/development/8 | Plan and regularly test incident response plans and teams | Not applicable |  |  | (organisational) incident response planning |

Rejected credits:

| Id | Credit considered | Why it was rejected |
|---|---|---|
| design/identity-management/3 | Agent posture: hook state and weakened settings | agent posture inventories which agent hosts run on a device; it is not a registry of agent identities bound to roles |
| design/identity-management/4 | #25, MCP server allow-list (policy.mcpAllow) | the allow-list denies MCP servers, not agents or keys |
| develop/red-teaming/2 | moorai-redteam: the adversarial corpus against the live policy | moorai-redteam tests MoorAI's own policy against its corpus, not the agent |
| develop/third-party-components/3 | AI bill of materials (moorai-aibom) | the AIBOM is an inventory MoorAI produces; the recommendation is about procurement |
| develop/third-party-components/8 | Time-boxed JIT elevation grants | elevation grants expire, but there are no roles, boundaries between them or consensus |
| develop/third-party-components/9 | High-impact actions default to human approval | human approval for listed actions exists (credited under human-in-the-loop); multi-agent consensus does not |
| deploy/guardrails-and-constraints/6 | #58, On-device model second opinion (#58) | the on-device model gives a second opinion on flagged text; it does not validate tasks against policy |
| operate/validate-outputs/1 | #29 | out-citation coaches on every citation marker; it checks nothing against a source |
| operate/privileges-and-authentication/7 | Signed MCP enforcement decisions | signs MoorAI's own enforcement decisions for the audit trail; it does not require the agent's commands to be signed |
| operate/privileges-and-authentication/9 | moorai-attest: in-toto export of governance records | moorai-attest exports governance records as in-toto statements; it does not attest the agent's code |
| appendix-a/design/7 | Placeholder credentials (model proxy, MCP gateway) | the agent holds a placeholder instead of the secret, but the real secret is neither ephemeral nor expiring |
| appendix-a/design/10 | HTTP MCP gateway staged message validation | validates JSON-RPC and MCP structure; there is no integrity or freshness check |

### CSA Agentic Trust Framework

| Id | Title | Status | MoorAI threats | Evidence | Limit or reason |
|---|---|---|---|---|---|
| I-1 | Unique Identifier | Not covered |  |  | MoorAI labels what it observes (a keyed actor hash per device and user, a keyed session hash) but issues no identity to an agent instance |
| I-2 | Credential Binding | Not covered |  |  | agent identities are not bound to credentials |
| I-3 | Ownership Chain | Not applicable |  |  | (organisational) documentation of ownership and responsibility |
| I-4 | Purpose Declaration | Partial | #64 | Entitlement envelope (#64); Declared workload profiles | the operational scope is declared machine-readably (envelope, workload profiles) and enforced; the intended use is not recorded |
| I-5 | Capability Manifest | Partial |  | AI bill of materials (moorai-aibom); Tool fingerprint (description, schema, annotations) | the AIBOM inventories each device's agents, models and MCP servers; the tools a server advertises are fingerprinted, not listed |
| B-1 | Structured Logging | Partial |  | Content-free action audit log; Chain-stamped session ledger; Content-free OpenTelemetry export | every tool call MoorAI sees (hook, MCP proxy and gateway) is logged content-free; actions outside those surfaces are not |
| B-2 | Action Attribution | Partial |  | Content-free action audit log; Verdict provenance (policy id, reason code) | each record carries a keyed actor hash and, for known agent sessions, a keyed session hash; there is no agent identity to tie it to |
| B-3 | Behavioral Baseline | Partial | #64 | Learned per-agent first-seen drift (#64); Learned per-agent behavioural baseline | first-seen tools, paths, servers and hosts per agent, and a learned behavioural baseline; latency and token metrics are not baselined |
| B-4 | Anomaly Detection | Partial | #64, #59, #38 | Learned per-agent first-seen drift (#64); Session risk: taint, sequences, slow exfiltration (#59); Runaway-loop circuit breaker (#38); Autonomous-agent behaviour signature (moorai-agentwatch) | rule- and baseline-based deviations; no statistical model of latency, tokens or error rates |
| B-5 | Explainability | Not covered |  |  | the agent's rationale is not captured |
| D-1 | Schema Validation | Partial |  | HTTP MCP gateway staged message validation | JSON-RPC and MCP schema validation for messages through the HTTP MCP gateway only |
| D-2 | Injection Prevention | Covered | #2, #3, #40, #50, #60, #70, #72, #74 | Instruction-override detectors (#3, inj-ignore); Directives in ingested content (#40, inj-untrusted-directive); Invisible or smuggled instructions (#50, obf-invisible-instructions); tools/list scan (tool stage); Tool-result scan (file stage) |  |
| D-3 | PII/PHI Protection | Partial | #1, #15, #44 | Personal and payment data detectors (#1, #15); Protected health information (#44, phi-hipaa); Masking a finding in place (Claude Code hook) | pattern detectors for the listed entity types; masking on the Claude Code hook only |
| D-4 | Output Validation | Partial | #39, #52, #71, #75, #61 | Secret-shape detectors (#39); Instruction-file leakage (#52, instr-leak-output); Data in a rendered image URL (#71, egress-rendered-image); Deceptive link in output (#75, out-link-deceptive); Insecure code the agent writes (#61, code-* detectors) | content policy on output (secrets, instruction leakage, rendered-image exfiltration, deceptive links, insecure code); structure is not validated |
| D-5 | Data Lineage | Not covered |  |  | data provenance through the pipeline is not tracked |
| S-1 | Resource Allowlist | Partial | #25, #63, #64 | MCP server allow-list (policy.mcpAllow); Model-endpoint allow-list (#63); Egress rules (binary, host, port, method, path); Entitlement envelope (#64); Declared workload profiles | MCP servers, model endpoints, hosts and paths written in a call; resources reached at runtime are not seen, and the MCP proxy and gateway do not judge egress rules |
| S-2 | Action Boundaries | Covered | #64 | Entitlement envelope (#64); Per-tool argument rules (policy.mcpToolRules); Declared workload profiles |  |
| S-3 | Rate Limiting | Partial | #38 | Runaway-loop circuit breaker (#38); HTTP MCP gateway per-client cool-down | per-session call rate and call budget, off by default; the gateway's cool-down counts refusals |
| S-4 | Transaction Limits | Not covered |  |  | the impact of a single action is not bounded |
| S-5 | Blast Radius Containment | Partial | #59, #66 | Session risk: taint, sequences, slow exfiltration (#59); Sub-agent delegation gate (#66); Desktop host agent isolation (macOS Seatbelt) | a session risk score across calls, the parent's envelope on sub-agents, and opt-in host isolation; cumulative impact is not measured |
| R-1 | Circuit Breaker | Partial | #38 | Runaway-loop circuit breaker (#38) | halts runaway loops (the same call or cycle with unchanged results) in deny mode; failure counts alone do not trip it |
| R-2 | Kill Switch | Not covered |  |  | no manual termination control |
| R-3 | Session Revocation | Not covered |  |  | agent sessions cannot be invalidated |
| R-4 | State Rollback | Not covered |  |  | agent actions are not undone |
| R-5 | Graceful Degradation | Partial | #59, #64 | Session risk: taint, sequences, slow exfiltration (#59); Intent alignment: risky call vs the stated task (#64) | session risk and intent alignment can move calls from allow to ask a person when signals fire; opt-in |

Rejected credits:

| Id | Credit considered | Why it was rejected |
|---|---|---|
| I-1 | Verdict provenance (policy id, reason code) | the actor and session hashes identify a device, user and session for correlation; they are not an identity issued to an agent instance |
| I-2 | Placeholder credentials (model proxy, MCP gateway) | binds a secret to a route, not an identity to a credential |
| B-5 | Verdict provenance (policy id, reason code) | reason codes and moorai-explain explain MoorAI's own verdict, not the agent's decision |
| D-5 | #59, Session risk: taint, sequences, slow exfiltration (#59) | session taint is a time window flag on the session, not provenance tracked through the pipeline |
| S-4 | High-impact actions default to human approval | approval gates a class of action, not its magnitude |
| R-2 | Kill verdict terminates the agent session | the kill sentinel fires automatically on a kill verdict; there is no manual switch |
