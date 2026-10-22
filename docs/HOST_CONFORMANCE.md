# Live conformance tier

MoorAI ships hook adapters for six agent hosts, an MCP stdio guard, an MCP HTTP gateway and a model proxy.
Unit and adapter tests prove each piece against recorded or documented shapes. The live conformance tier
proves them against the real software: the installed host binary, a real MCP client, a real local model
server. Each run writes one signed, content-free report per target and version into
[`docs/conformance/`](conformance/).

```bash
npm run test:live                                   # both tiers, reports into docs/conformance/
node scripts/host-conformance.mjs                   # plan only: what would run here, nothing started
node scripts/host-conformance.mjs --live            # agent hosts and MCP clients
node scripts/server-conformance.mjs --live          # model proxy and MCP gateway
node scripts/host-conformance.mjs --verify docs/conformance/claude-code-2.1.295.json [--pub <base64 key>]
```

The tier is opt-in. `npm test` runs its plumbing against stand-ins (a stand-in Claude Code that follows the
documented hook contract, and an in-test model server), never a real host or model.

## What a run proves, and how

**Agent hosts** (`scripts/host-conformance.mjs`). Each case is one headless turn of the real host binary in a
throwaway HOME, with MoorAI's hook installed by MoorAI's own installer and the device enrolled to a loopback
stand-in console that serves a signed policy. The model is a scripted Anthropic Messages endpoint on
loopback: the host runs its real hook pipeline, its real permission layer and its real tools, and only the
model's turns are scripted. No model provider is called and no API key is read. On macOS the host runs
under `sandbox-exec`, which denies outbound connections other than localhost and writes to the real
`~/.claude.json`, `~/.claude` and `~/.cursor`.

| Case | What the scripted model asks for | Passes when |
|---|---|---|
| `shell-allow` | Bash `echo` | MoorAI allows it, the command runs, its output reaches the model |
| `shell-deny` | Bash reverse shell to `127.0.0.1:9` (a closed local port) | the host returns MoorAI's refusal as an error result, the command never runs, a Blocked alert reaches the console |
| `prompt-block` | (none: the prompt carries a fake AWS key) | with `promptScan: "all"` and `promptScanAction: "block"`, the prompt never reaches the model and a Blocked alert is sent |
| `mcp-allow` | the `echo` tool of an MCP server behind MoorAI's stdio guard | the call is forwarded, the server receives it, the echo comes back |
| `mcp-deny` | the same tool with an argument the policy's `mcpToolRules` deny | the host gets MoorAI's refusal, the server never receives the call, a Blocked alert is sent |

A person's own typed prompt is not scanned by default (`cli/prompt-scan.mjs`); `prompt-block` uses the
opt-in a pipeline or server-mode policy would set.

**Cursor.** A `cursor-agent` turn needs a Cursor account (login or `CURSOR_API_KEY`), and its local-model
flag (`--base-url`) is refused by the installed build ("agent-cli-local" is a separate build). The tier
uses no account, so the agent-turn case is a skip with reason `auth-required`, and both probes are
recorded as booleans. The MCP client side needs no account: `cursor-agent mcp enable` and
`mcp list-tools` complete the MCP handshake through MoorAI's stdio guard, and MoorAI records the tool list
it relayed. The hook events and version fields the adapter relies on are checked in the installed bundle.

**Desktop MCP clients** (Claude Desktop, VS Code, the Cursor desktop app) are GUI apps with no headless
mode. The tier records whether each is installed and at which version, and never launches one: a GUI run
would use the person's real profile and account.

**AI Servers** (`scripts/server-conformance.mjs`). A real `moorai-model-proxy` in `--mode enforce` sits in
front of a real Ollama. An upstream recorder between them tells each case whether a refused request
reached the model and whether the model really produced a tool call. The policy blocks threat #39
(credentials) and the `delete_project_files` function.

| Path through the proxy | Ollama endpoint | Cases |
|---|---|---|
| `/openai/chat/completions` | OpenAI-compatible `/v1/chat/completions` | allow (JSON), allow (SSE), credential refused before the model, tool call withheld (JSON), tool call withheld (SSE) |
| `/anthropic/v1/messages` | Anthropic-compatible `/v1/messages` | allow, credential refused, tool call withheld |
| `/ollama/api/chat` | native `/api/chat` | allow, credential refused, tool call withheld |
| `/openai/responses` | `/v1/responses` | credential: forwarded unparsed, recorded as `gap` (the proxy does not parse the Responses API) |

A withhold case whose model made no tool call is `inconclusive`, never a pass. Each credential case uses
its own fake key, because the proxy reports a repeated identical item once.

The MCP gateway case runs the official MCP TypeScript SDK on both ends: the SDK client over Streamable
HTTP, through a real `moorai-mcp-gateway` process, to an SDK server with one `echo` tool. A benign call is
forwarded; a call the policy denies comes back as MoorAI's refusal, the SDK server never receives it, and
the console gets a Blocked alert.

## The report

Type `moorai.host-conformance/v1` or `moorai.server-conformance/v1`, built by
[`cli/conformance-report.mjs`](../cli/conformance-report.mjs). It carries the target, its version, the
model kind (`scripted`, `ollama`, `none`) and model name, and per case: expected and observed outcome,
status, named boolean checks, the alert's category, risk level, decision and reason code, and latency.
It never carries a prompt, command, tool argument, path, host output or model output: every field passes
an allowlist, and verification refuses a report that carries anything the allowlist would drop.

Statuses: `pass`; `fail`; `skip` (a case that could not run, with the target's reason); `inconclusive`
(the real model did not do what the case needs); `gap` (a documented limit, observed). A target that did
not run says why: `not-installed`, `auth-required`, `separate-build-required`, `no-headless-mode`,
`sdk-not-installed`, `image-not-present`, `model-unavailable`, `no-live-tier`.

Signature: ed25519 over the SHA-256 of the canonical JSON (sorted keys) without the `signature` field.
Pass `--key <path>` (or set `MOORAI_CONFORMANCE_KEY`) for a stable key whose public half can be pinned
with `--verify … --pub`; without one, an ephemeral key signs the run and the report says
`signature.ephemeral: true`, which proves integrity only.

## Recorded run (2026-10-21, macOS arm64, agent 1.27.0)

| Target | Version | Result |
|---|---|---|
| Claude Code | 2.1.295 | ran, sandboxed: `shell-allow`, `shell-deny`, `prompt-block`, `mcp-allow`, `mcp-deny` all pass |
| Cursor (`cursor-agent`) | 2026.05.27-fe9a6e2 | MCP handshake through the stdio guard pass, bundle markers pass; agent turn skip (`auth-required`) |
| Codex CLI, Copilot CLI, Gemini CLI, Factory Droid | | not installed |
| Claude Desktop | 2.37337.1 | installed, not run (`no-headless-mode`) |
| VS Code, Cursor desktop app | | not installed |
| Model proxy with Ollama | Ollama 0.40.3, `llama3.2:latest` | 11 pass (every allow, refuse and withhold case on all three APIs, the real model made each tool call); Responses API `gap` |
| MCP gateway with the MCP TypeScript SDK | 1.32.1 | benign forwarded pass, denied refused pass |
| Official provider SDKs (OpenAI, Anthropic, Google Gen AI, Ollama; Node and Python) | | not installed (`sdk-not-installed`) |
| Server image, linux/amd64 | | not present (`image-not-present`; only arm64 builds are local) |

The signed reports for this run are in [`docs/conformance/`](conformance/).

## Not proven by this tier

- An agent turn in Cursor, Codex, Copilot CLI, Gemini CLI or Factory Droid: Cursor needs an account, the
  other four are not installed where the tier ran, and the tier uses no vendor key.
- Claude Desktop, VS Code and the Cursor desktop app as MCP clients: never launched.
- A real paid model: Claude Code's turns are scripted; the proxy's model is a local Ollama model. The
  official OpenAI, Anthropic and Google SDKs were not installed, so the proxy has not run under them; the
  cases send each API's documented request shape over HTTP.
- A real remote MCP server: the gateway case uses an SDK server on loopback.
- The linux/amd64 image, Windows and Linux hosts.
- A nightly schedule: the tier runs where the hosts and Ollama are installed; it is not wired into CI.
