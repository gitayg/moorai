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
- **Agency Enforcement** — bounds what an agent is *allowed to do*: inspects `mcp__*` tool-call arguments for secrets/policy violations and blocks them, and enforces an approved-MCP-server allow-list at call time. The direct control for **OWASP LLM06: Excessive Agency**.
- **AI output review** — reviews what the agent says *back*, not just what's typed. Masks secret spans the model echoes on the `-p` path.
- **Battle-tested secrets engine** — ~14 provider families (GitHub, AWS, Stripe, Slack, GCP, OpenAI/Anthropic, DB connection strings, …) plus Shannon-entropy scoring with an allowlist (UUIDs, git SHAs, base64) so it doesn't false-positive on the things that aren't secrets.
- **Coach · alert · block · justify** — per policy, per tenant, per device. Nudge, warn, hard-block, or require a signed justification.
- **Context-aware severity** — the same pattern is scored higher by *where* it was caught: a secret read into an agent's context or shipped as an MCP argument outranks one typed into a still-editable prompt.
- **On-device exposure ledger** — a content-free local log of which credential/secret *classes* reached which agent, so an incident-response rotation is targeted, not a blanket burn. Plus a human-override *intent* log — the signal that separates legitimate agentic use from an attack. View both with `moorai-ledger`; nothing leaves the machine.
- **On-device, content-free** — everything is checked locally. The console receives a category, a risk level, and a one-way hash — **never** the prompt, the file, or the matched span.

## Why you can trust the "nothing leaves" claim

Because you can read the code. The agent is **AGPL-3.0 and open source** — the whole detection and reporting path is right here. Cloud DLP tools ask you to take "we don't store your prompts" on faith. MoorAI's telemetry is content-free *by construction*, and the construction is auditable.

**Governance without surveillance.**

## Install

**macOS** — download the signed, notarized `.dmg` from [Releases](https://github.com/gitayg/moorai/releases).
**Windows** — download the signed `-setup.exe` from [Releases](https://github.com/gitayg/moorai/releases) (built in the open by CI).

Community edition: runs standalone, local policy control, no account required.

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

## Coverage

| | |
|---|---|
| **Agents** | Claude Code (full hook enforcement) · Codex / Copilot CLI (detection-only — no equivalent deny hook) |
| **Surfaces** | prompts · AI outputs · files read into context · MCP tool calls · pasted images (OCR) · RAG/index payloads |
| **Platforms** | macOS · Windows |
| **Detects** | secrets · PII / PHI · source-code leakage · prompt injection · destructive commands · second-order/hidden-instruction injection |

## How it works

A small Rust (Tauri) host wraps the agent's terminal; a local webview runs the detection engine. Prompts, file reads, tool calls, and outputs are checked against a 40+ threat matrix + content rules + org-defined detector packs — entirely on the device. A separate, proprietary **management console** adds a multi-tenant dashboard, SSO, fleet policy, and content-free compliance exports (AIBOM, EU AI Act records, board AI-readiness report, SIEM streaming). Open-core: this agent is AGPL; the console is commercial.

## Learn more

- **Website & comparisons** — [glick.run/moorai](https://glick.run/moorai.html)
- **How it stacks up** — vs [Lakera](https://glick.run/moorai-vs-lakera.html) · [Prompt Security](https://glick.run/moorai-vs-prompt-security.html) · [BigID](https://glick.run/moorai-vs-bigid.html) · [Harmonic](https://glick.run/moorai-vs-harmonic.html) · [Zenity](https://glick.run/moorai-vs-zenity.html) · [Netskope](https://glick.run/moorai-vs-netskope.html)

## License

The MoorAI community agent is licensed under [AGPL-3.0](LICENSE). The management server is a separate, proprietary product.
