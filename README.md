<div align="center">

# MoorAI

### On-device guardrails for AI coding agents. Nothing leaves the machine.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-ff4d6d.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-e4e4ef.svg)](#install)
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
- **AI output review** — reviews what the agent says *back*, not just what's typed. On-device output screening flags **secrets, PII, and insecure code the agent generates** (SQL injection, XSS, command injection, `eval`/dynamic exec, weak crypto, unsafe deserialization) and masks secret spans on the `-p` path — emitting only a content-free verdict, never the reply.
- **Battle-tested secrets engine** — ~14 provider families (GitHub, AWS, Stripe, Slack, GCP, OpenAI/Anthropic, DB connection strings, …) plus Shannon-entropy scoring with an allowlist (UUIDs, git SHAs, base64) so it doesn't false-positive on the things that aren't secrets.
- **Model-endpoint allow-listing** — bounds *which LLM endpoints* an agent may talk to. A base-URL override (`ANTHROPIC_BASE_URL=…`) or a direct call to a non-approved provider is flagged/blocked at the endpoint — the exfil-via-rogue-endpoint defense, host-level and content-free (loopback / local models always allowed).
- **Slopsquatting firewall** — an offline typosquat / hallucinated-package classifier (Damerau-Levenshtein against a curated popular-package list + a known-bad set) gates `npm/pip/cargo install` of near-miss names (`reqeusts`, `lodahs`) and documented hallucinations — the #1 AI-supply-chain threat, checked entirely on-device (name only).
- **MCP hardening** — an approval-gating lifecycle for MCP servers, **rug-pull detection** (a server whose config changes after approval is knocked back to pending), and an **invisible-payload scanner** (Unicode tag-block / ANSI escapes / bidi-override / variation-selector smuggling) that catches instructions hidden from human review.
- **Agent entitlement envelope** — declare each agent's authorized tools / path-prefixes / MCP servers; an action outside the envelope is flagged as **entitlement drift** and alerted or blocked — least-privilege for coding agents, content-free.
- **Local secret-egress detection** — fingerprints your local secret values (`.env`, cloud creds) on-device as one-way hashes and blocks an outbound command or tool-call that carries one verbatim — catching a real secret leaving even when it isn't in a recognizable token shape. Only the hash + a verdict leave.
- **Insecure-defaults screening** — flags misconfigurations agents habitually emit (SSRF, path traversal, XXE, JWT `alg=none`, TLS-verify-off, wildcard CORS, `debug=True`, insecure randomness for tokens, hardcoded creds, world-writable perms, open redirect) — on top of the SQLi/XSS/RCE/deserialization coverage.
- **Sub-agent / A2A oversight** — records agent-to-agent delegation (sub-agent spawns), scans the delegated prompt for injection, and applies the parent's entitlement envelope to the child so a delegated action can't slip past the parent's controls.
- **Jailbreak & injection detection** — high-precision detectors for direct jailbreaks (DAN lineage, developer/god-mode, named personas, chat-template control-token injection) scoped so normal dev prompts don't trip them, with opportunistic local-model escalation on ambiguity.
- **Coach · alert · block · justify · kill** — per policy, per tenant, per device. Nudge, warn, hard-block, require a signed justification, or **kill the session** — terminate the running agent (not just deny the one call) on a critical finding, in both the `-p` guard and the interactive host.
- **Coach-as-literacy (EU AI Act Art. 4)** — each time MoorAI coaches a developer at the point of use (the *why* + *what-to-do*, mapped to OWASP LLM Top 10 / MITRE ATLAS), it records a **content-free "literacy touchpoint"** (topic + actor hash, never content). The console rolls these into a coverage view — demonstrable evidence of "measures taken" for a training program, not a substitute for one.
- **Context-aware severity** — the same pattern is scored higher by *where* it was caught: a secret read into an agent's context or shipped as an MCP argument outranks one typed into a still-editable prompt.
- **On-device exposure ledger** — a content-free local log of which credential/secret *classes* reached which agent, so an incident-response rotation is targeted, not a blanket burn. Plus a human-override *intent* log — the signal that separates legitimate agentic use from an attack. View both with `moorai-ledger`; nothing leaves the machine.
- **On-device, content-free** — everything is checked locally. The console receives a category, a risk level, and a one-way hash — **never** the prompt, the file, or the matched span.
- **Opportunistic on-device model escalation** — when a regex scan is ambiguous and your policy enables it, a *local* model (Ollama on the loopback interface) gives a second opinion. The text goes only to `127.0.0.1`, never off the machine; a failure never changes the decision. Off by default.
- **You control the evidence** — nothing trains anyone's model, and on-device signal logs are pruned on your schedule (`MOORAI_RETENTION_DAYS`, default 90; `0` = keep forever). Content-free by construction, not by promise.

## Why you can trust the "nothing leaves" claim

Because you can read the code. The agent is **AGPL-3.0 and open source** — the whole detection and reporting path is right here. Cloud DLP tools ask you to take "we don't store your prompts" on faith. MoorAI's telemetry is content-free *by construction*, and the construction is auditable.

**Governance without surveillance.**

## Install

**macOS** — download the signed, notarized `.dmg` from [Releases](https://github.com/gitayg/moorai/releases).
**Windows** — download the signed `-setup.exe` from [Releases](https://github.com/gitayg/moorai/releases) (built in the open by CI).

Community edition: runs standalone, local policy control, no account required.

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

### Review what was exposed — on-device, no server

```bash
npx moorai-ledger              # which credential classes reached which agent (for targeted rotation)
npx moorai-ledger --intent     # human overrides — who chose to proceed past a finding
npx moorai-ledger --format md  # Markdown report
```

Content-free by construction: category, risk, stage, device, and a one-way hash — never a secret value.

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

## Coverage

| | |
|---|---|
| **Agents** | Claude Code (full hook enforcement) · Codex / Copilot CLI (detection-only — no equivalent deny hook) |
| **Surfaces** | prompts · AI outputs · files read into context · MCP tool calls · pasted images (OCR) · RAG/index payloads |
| **Platforms** | macOS · Windows |
| **Detects** | secrets · PII / PHI · source-code leakage · prompt injection · destructive commands · second-order/hidden-instruction injection |

## How it works

A small Rust (Tauri) host wraps the agent's terminal; a local webview runs the detection engine. Prompts, file reads, tool calls, and outputs are checked against a 60+ threat matrix + content rules + org-defined detector packs — entirely on the device. A separate, proprietary **management console** adds a multi-tenant dashboard, SSO, fleet policy, and content-free compliance exports (AIBOM, EU AI Act records, board AI-readiness report, SIEM streaming). Open-core: this agent is AGPL; the console is commercial.

## Learn more

- **Website & comparisons** — [glick.run/moorai](https://glick.run/moorai.html)
- **How it stacks up** — vs [Lakera](https://glick.run/moorai-vs-lakera.html) · [Prompt Security](https://glick.run/moorai-vs-prompt-security.html) · [BigID](https://glick.run/moorai-vs-bigid.html) · [Harmonic](https://glick.run/moorai-vs-harmonic.html) · [Zenity](https://glick.run/moorai-vs-zenity.html) · [Netskope](https://glick.run/moorai-vs-netskope.html)

## License

The MoorAI community agent is licensed under [AGPL-3.0](LICENSE). The management server is a separate, proprietary product.
