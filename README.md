<div align="center">

# MoorAI

### On-device guardrails for AI coding agents. Nothing leaves the machine.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-ff4d6d.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-e4e4ef.svg)](#install)
[![Build: Windows](https://github.com/gitayg/moorai/actions/workflows/release-windows.yml/badge.svg)](https://github.com/gitayg/moorai/actions)

**MoorAI reviews what your developers send to AI coding agents — and what those agents read, run, and reply — right on the device, before anything is exposed.** Secrets, PII, and source code never leave the machine to be checked. Your security team sees content-free signals, never the prompts.

Let your engineers use AI freely. Keep your data in-house.

</div>

---

## The problem

Your developers use Claude Code, Cursor, and Copilot. Those agents don't just read what's typed — they **read files into context** (a stray `.env`), **call MCP tools** with whatever arguments they were given, and **reply** with whatever the model generates. Prompt review alone misses most of it, and every cloud DLP tool solves it by **sending your prompts to their servers to inspect**.

That's the exact trade MoorAI refuses.

## What it does

- **Context interception** — blocks a secret or PII being *read into the agent's context* (e.g. an agent slurping a `.env`), not just typed in a prompt. Via the agent's PreToolUse hooks, on-device.
- **Agency Enforcement** — bounds what an agent is *allowed to do*: inspects `mcp__*` tool-call arguments for secrets/policy violations and blocks them, and enforces an approved-MCP-server allow-list at call time — with a **discovered → approved/denied approval-gating lifecycle** in the console. The direct control for **OWASP LLM06: Excessive Agency**.
- **AI output review** — reviews what the agent says *back*, not just what's typed. On-device output screening flags **secrets, PII, and insecure code the agent generates** (SQL injection, XSS, command injection, `eval`/dynamic exec, weak crypto, unsafe deserialization) and masks secret spans on the `-p` path — emitting only a content-free verdict, never the reply. An intra-file **taint-lite** check (dependency-free source→sink proximity) raises a high-confidence *confirmed tainted-flow* signal when untrusted input actually reaches one of those sinks, so the console can prioritize real flows over hardcoded-literal matches.
- **Battle-tested secrets engine** — ~14 provider families (GitHub, AWS, Stripe, Slack, GCP, OpenAI/Anthropic, DB connection strings, …) plus Shannon-entropy scoring with an allowlist (UUIDs, git SHAs, base64) so it doesn't false-positive on the things that aren't secrets.
- **Model-endpoint allow-listing** — bounds *which LLM endpoints* an agent may talk to. A base-URL override (`ANTHROPIC_BASE_URL=…`) or a direct call to a non-approved provider is flagged/blocked at the endpoint — the exfil-via-rogue-endpoint defense, host-level and content-free (loopback / local models always allowed).
- **Transit-override detection (#67)** — the allow-list above asks *where* the agent is sending; this asks *what the traffic passes through on the way*. Setting `HTTPS_PROXY` plus a CA override (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, …) on an agent leaves the destination untouched — so the endpoint allow-list still passes it — while every request transits an interceptor that reads the prompt, the generated code and the API key in cleartext. Measured, not theorised: with those two variables set, a real Claude Code session decrypted at the proxy with the client reporting the TLS as **authorized**, because the injected CA makes the forged chain legitimately trusted. It needs no privileges. MoorAI reports any proxy or CA override and denies an unsanctioned proxy when `policy.transitAllow` is set — proxy **host** and variable **name** only, never the CA path or its contents. Report-first by default, because a corporate egress proxy is legitimate; loopback is deliberately *not* auto-approved, since a loopback proxy is what an on-device interceptor looks like.
- **Slopsquatting firewall** — an offline typosquat / hallucinated-package classifier (Damerau-Levenshtein against a curated popular-package list + a known-bad set) gates `npm/pip/cargo install` of near-miss names (`reqeusts`, `lodahs`) and documented hallucinations — the #1 AI-supply-chain threat, checked entirely on-device (name only).
- **MCP hardening** — an approval-gating lifecycle for MCP servers, **rug-pull detection** (a server whose config changes after approval is knocked back to pending), and an **invisible-payload scanner** (Unicode tag-block / ANSI escapes / bidi-override / variation-selector smuggling) that catches instructions hidden from human review.
- **Skill Analysis** — an inventory + *intent* view of the whole **skill surface** an agent auto-loads, not just its rules file: `SKILL.md` and `.claude/skills/**`, subagent definitions (`.claude/agents/*.md`), slash commands (`.claude/commands/**`), MCP server configs (`.mcp.json`, `~/.claude.json`, `managed-mcp.json`, `claude_desktop_config.json`), the settings files that can carry **hooks** (`.claude/settings.json`, `settings.local.json`, `managed-settings.json`), plugin manifests and their hook/monitor declarations, path-scoped rules and memory files, plus the other vendors' equivalents (`.cursorrules`, `.windsurfrules`, `.clinerules`, copilot-instructions). Every file gets its **kind**, a set of **intent category labels** — *hidden-instructions*, *instruction-override*, *external-network-egress*, *security-control-or-privilege-change*, *references-credentials*, *invisible-characters*, … — and a **drift fingerprint** per file. The labels are renames of findings the existing detection engine already produced; **no text, matched span, or excerpt is ever attached**, so a poisoned skill can be triaged without reading it off the device.
- **Per-agent destination map** — the observed counterpart to your allow-lists: for each agent/tool, *which external destinations it actually reached*. **Hosts** (never a URL path or query string — they are not captured in the first place) and **MCP server names**, with call counts, first/last-seen, and the allow/ask/deny verdict each call actually got. Kept in an on-device ledger; the console gets one content-free alert the first time an agent touches a new destination, over the existing alert path. View it with `moorai-destinations`.
- **Agent entitlement envelope** — declare each agent's authorized tools / path-prefixes / MCP servers; an action outside the envelope is flagged as **entitlement drift** and alerted or blocked — least-privilege for coding agents, content-free.
- **Local secret-egress detection** — fingerprints your local secret values (`.env`, cloud creds) on-device as keyed one-way hashes and blocks an outbound command or tool-call that carries one verbatim — catching a real secret leaving even when it isn't in a recognizable token shape. Only the hash + a verdict leave.
- **Insecure-defaults screening** — flags misconfigurations agents habitually emit (SSRF, path traversal, XXE, JWT `alg=none`, TLS-verify-off, wildcard CORS, `debug=True`, insecure randomness for tokens, hardcoded creds, world-writable perms, open redirect) — on top of the SQLi/XSS/RCE/deserialization coverage.
- **Sub-agent / A2A oversight** — records agent-to-agent delegation (sub-agent spawns), scans the delegated prompt for injection, and applies the parent's entitlement envelope to the child so a delegated action can't slip past the parent's controls.
- **Jailbreak & injection detection** — high-precision detectors for direct jailbreaks (DAN lineage, developer/god-mode, named personas, chat-template control-token injection) scoped so normal dev prompts don't trip them, with opportunistic local-model escalation on ambiguity.
- **Coach · alert · block · justify · kill** — per policy, per tenant, per device. Nudge, warn, hard-block, require a signed justification, or **kill the session** — terminate the running agent (not just deny the one call) on a critical finding, in both the `-p` guard and the interactive host.
- **Coach-as-literacy (EU AI Act Art. 4)** — each time MoorAI coaches a developer at the point of use (the *why* + *what-to-do*, mapped to OWASP LLM Top 10 / MITRE ATLAS), it records a **content-free "literacy touchpoint"** (topic + actor hash, never content). The console rolls these into a coverage view — demonstrable evidence of "measures taken" for a training program, not a substitute for one.
- **Context-aware severity** — the same pattern is scored higher by *where* it was caught: a secret read into an agent's context or shipped as an MCP argument outranks one typed into a still-editable prompt.
- **On-device exposure ledger** — a content-free local log of which credential/secret *classes* reached which agent, so an incident-response rotation is targeted, not a blanket burn. Plus a human-override *intent* log — the signal that separates legitimate agentic use from an attack. View both with `moorai-ledger`; nothing leaves the machine.
- **On-device, content-free** — everything is checked locally. The console receives a category, a risk level, and a **keyed** one-way hash (HMAC-SHA-256 under your tenant's enrollment token) — **never** the prompt, the file, or the matched span. The key matters: an *unkeyed* digest of a phone number or an SSN is enumerable, so it is not one-way in practice. A device with no enrollment token emits an explicit non-correlatable marker instead of a weaker hash.
- **Opportunistic on-device model escalation** — when a regex scan is ambiguous and your policy enables it, a *local* model (Ollama on the loopback interface) gives a second opinion. The text goes only to `127.0.0.1`, never off the machine; a failure never changes the decision. Off by default.
- **You control the evidence** — nothing trains anyone's model, and on-device signal logs are pruned on your schedule (`MOORAI_RETENTION_DAYS`, default 90; `0` = keep forever). Content-free by construction, not by promise.

## Why you can trust the "nothing leaves" claim

Because you can read the code. The agent is **AGPL-3.0 and open source** — the whole detection and reporting path is right here. Cloud DLP tools ask you to take "we don't store your prompts" on faith. MoorAI's telemetry is content-free *by construction*, and the construction is auditable.

**Governance without surveillance.**

## Install

**macOS** — download the signed, notarized `.dmg` from [Releases](https://github.com/gitayg/moorai/releases).
**Windows** — download the signed `-setup.exe` from [Releases](https://github.com/gitayg/moorai/releases) (built in the open by CI).

Community edition: runs standalone, local policy control, no account required.

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
  and never see the signup form.

### One-line install (CLI guard + Claude Code hooks)

```bash
curl -fsSL https://raw.githubusercontent.com/gitayg/moorai/main/scripts/install.sh | sh
```

Clones to `~/.moorai`, installs dependencies, and registers the on-device PreToolUse hooks. Needs `git` and Node 18+; content-free, no account. Set `MOORAI_NOHOOK=1` to skip hook registration, or `MOORAI_HOME` to change the location.

### Try the CLI guard in 30 seconds

```bash
npm run guard -- "here is my key sk-ant-api03-... please debug the charge"
# ✗ blocked by policy — nothing sent to claude -p (#39 secret)
```

### Wire the context-interception hooks into Claude Code

```bash
node cli/moorai-hook.mjs install     # registers PreToolUse hooks in ~/.claude/settings.json
node cli/moorai-hook.mjs uninstall   # removes only MoorAI's entries
```

Now a `Read` of a `.env`, a secret in an MCP tool-call argument, or a call to an
unapproved MCP server is blocked before it reaches the agent — content-free,
fails open (governance, not a sandbox).

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
npx moorai-shadow --strict                    # find unsanctioned AI (models · MCP servers · editor extensions) vs your allow-list
npx moorai-compliance --framework eu-ai-act   # evidence pack mapped to EU AI Act / NIST AI RMF / ISO 42001 controls
npx moorai-compliance --format stix           # export the same findings as a STIX 2.1 bundle for SIEM/TIP interchange
npx moorai-verify-chain                       # tamper-evidence check — detect a deleted, reordered, or edited evidence-log record
npx moorai-honeytokens register               # register a content-free canary (only its one-way hash is stored)
npx moorai-attest                             # export governed records as an in-toto / SLSA provenance attestation (SSCS interchange)
npx moorai-aibom --format cyclonedx           # export the AI Bill of Materials as a CycloneDX 1.6 SBOM (also --format spdx)
```

- **`moorai-trace`** reconstructs the on-device action chain — `time · actor · tool · decision · risk · destination · args-hash` — from the content-free logs, so you can answer *"what did this agent do?"* after an incident without ever surfacing a prompt or file.
- **`moorai-shadow`** layers a sanctioned/unsanctioned check on top of the AIBOM inventory (allow-list in `~/.moorai/config.json` `sanctioned`, or `MOORAI_SANCTIONED`); `--strict` exits non-zero for CI/posture gates.
- **`moorai-compliance`** maps the device's existing content-free signals to framework controls and marks each **covered / partial / not-covered honestly** — the evidence layer a cost-pressured SOC can actually keep. `--format stix` emits the findings as a STIX 2.1 bundle (custom `x-moorai-finding` objects + hash-keyed indicators) for threat-intel interchange.
- **`moorai-verify-chain`** walks each on-device evidence log and verifies its prev-hash chain — a deleted, reordered, or in-place-edited record breaks the chain and is reported. Every log line and every emitted OTel span is chain-stamped (`cli/record-chain.mjs`), so the record hash proves each record and the chain proves the *sequence* (immutable once streamed to your SIEM).
- **`moorai-honeytokens`** registers content-free canaries — a decoy value nobody should ever touch; only its one-way hash is stored, and a later hit is a high-signal alert with zero content at rest.
- **`moorai-attest`** emits the governed record chain as an **in-toto attestation / SLSA provenance predicate**, built only from the content-free fields (tool · category · risk · decision · stage · tenant + the one-way hashes + chain seq/prev/chash) — so an agent's action evidence plugs into the software-supply-chain attestation ecosystem without carrying any content. The AIBOM also exports as a standard **CycloneDX 1.6** or **SPDX 2.3** SBOM (`moorai-aibom --format cyclonedx|spdx`).
- **Obfuscation-resistant detection.** A bounded, DoS/ReDoS-capped decode/normalize pre-pass re-runs the detectors over decoded and reversed variants, so **encoded/obfuscated** payloads (base64/hex/rot13/caesar ciphers, reversed text, composed transforms) that defeat plain-text scanning are still caught — measured against the HackAgent red-team taxonomy (`npm run redteam-eval`): detection coverage rose 35% → 61%, and `npm run validate-blocking` shows every malicious *tool call* still denied at the hook even after a jailbreak. Semantic/multi-turn attacks (persuasion, tree-of-attacks) route to the optional on-device model-escalation, not a brittle regex.

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

## Coverage

| | |
|---|---|
| **Agents** | Claude Code (full hook enforcement) · Codex / Copilot CLI (detection-only — no equivalent deny hook) |
| **Surfaces** | prompts · AI outputs · files read into context · MCP tool calls · pasted images (on-device OCR) · RAG/index payloads · the agent's auto-loaded skill surface (skills, subagents, commands, MCP configs, hook-bearing settings) |
| **Platforms** | macOS · Windows · Linux (on-device OCR is a second-class tier — see below) |
| **Detects** | secrets · PII / PHI · source-code leakage · prompt injection · destructive commands · second-order/hidden-instruction injection · skill-surface poisoning & drift |

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

> The Windows engine is runtime-verified on a real Windows 11 host — `Windows.Media.Ocr` read back
> 8/8 sensitive strings (incl. an AWS key and an SSN) off a clean render. The Linux/Tesseract tier is
> validated end-to-end but **second-class**: accuracy on dense secret strings is below the macOS/Windows
> OS engines, so treat it as opportunistic, not parity.

## How it works

A small Rust (Tauri) host wraps the agent's terminal; a local webview runs the detection engine. Prompts, file reads, tool calls, and outputs are checked against a 60+ threat matrix + content rules + org-defined detector packs — entirely on the device. A separate, proprietary **management console** adds a multi-tenant dashboard, SSO, fleet policy, and content-free compliance exports (AIBOM, EU AI Act records, board AI-readiness report, SIEM streaming). Open-core: this agent is AGPL; the console is commercial.

## Learn more

- **Website & comparisons** — [glick.run/moorai](https://glick.run/moorai.html)
- **How it stacks up** — vs [Lakera](https://glick.run/moorai-vs-lakera.html) · [Prompt Security](https://glick.run/moorai-vs-prompt-security.html) · [BigID](https://glick.run/moorai-vs-bigid.html) · [Harmonic](https://glick.run/moorai-vs-harmonic.html) · [Zenity](https://glick.run/moorai-vs-zenity.html) · [Netskope](https://glick.run/moorai-vs-netskope.html)

## License

The MoorAI community agent is licensed under [AGPL-3.0](LICENSE). The management server is a separate, proprietary product.
