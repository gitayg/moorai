# MoorAI MCP Guard

Claude Desktop has **no PreToolUse hooks** — that is a Claude Code CLI feature. But Claude Desktop *does*
launch MCP servers from `claude_desktop_config.json`. So MoorAI guards it the only place it can: by
inserting a tiny **stdio proxy between the host and each MCP server**. Every MCP tool-call passes through
the proxy, which runs the **exact same `mcpGateway()`** the Claude Code hook uses.

The guard itself was always host-agnostic — it speaks nothing but newline-delimited JSON-RPC over stdio,
and every MCP host launches a stdio server the same way. Only the *installer* was Claude-Desktop-specific;
it now writes Claude Desktop, project `.mcp.json`, Cursor and VS Code / Copilot (`HOSTS` in
[`install.mjs`](install.mjs)). **Codex is not covered:** its config is TOML and the installer writes JSON.

This covers the host's **MCP tool-calls — its highest-risk agentic surface** (the actions an agent takes:
file writes, shell, network, database, API calls). Reviewing the host's *prompt text* is a separate,
future mechanism and is out of scope here.

**Stated plainly: MCP is not the whole action surface.** Of the 12 malicious actions in the coverage
measurement below, only **4 natively traverse MCP** — the rest reach the machine through a host's own
built-in tools, where the Claude Code PreToolUse hook, not this proxy, is the control.

## What it does

The proxy is spawned by Claude Desktop in place of the real MCP server. It spawns the real server as a
child and pumps stdio both ways (newline-delimited JSON-RPC 2.0):

```
MCP host  ⇄  moorai-mcp-guard  ⇄  real MCP server
```

### agent → server: the tool CALL

- Every JSON-RPC message with `method === "tools/call"` is gated through `mcpGateway()`
  (from `cli/hook-core.mjs`), in this order, short-circuiting on the first deny:
  1. **server allow-list** (#3) — is this MCP server allowed at all?
  2. **per-tool argument rules** (#18) — deny/allow regexes for this tool's arguments.
  3. **argument content scan** (#2) — the shared MoorAI detectors over the serialized arguments.
- **Block** → the call is **not** forwarded; the proxy returns a JSON-RPC *result* to the host that
  is an MCP tool error (`isError: true`, using the request's `id`), so the model sees a clean refusal
  instead of a hang. The real server never receives the call.
- **Allow / coach** → forwarded unchanged. The host has no interactive banner, so a "coach"
  (justify) verdict is treated as **allow + record**.

### server → agent: the tool LISTING and the tool RESULT

This direction used to be observe-nothing, then observe-only. Both halves are now scanned, and one of
them can block.

- **`tools/list` responses** are copied to a bounded scanner at the **`tool`** stage
  ([`tool-scan.mjs`](tool-scan.mjs), with the cross-call shadowing / capability-expansion half in
  [`tool-baseline.mjs`](tool-baseline.mjs)), so tool descriptions and input schemas reach
  `mcp-tool-poisoning` (#60) and `mcp-hidden-canary` (#50). **Report-first, and never a mutation:** the
  listing is forwarded byte-identical, always. "Block" here could only mean deleting a tool from the
  agent's list — a lie about what the server offers. A blocking policy instead **quarantines** the tool,
  and the already-existing `tools/call` gate refuses calls to it. Observation at list time, enforcement
  at call time.
- **`tools/call` results** — the content the agent actually ingests — are scanned at the **`file`** stage
  and *can* be blocked. Before this, a child server returning a secret reached the agent verbatim with
  zero alerts. A result that resolves to `deny` is replaced by an MCP tool error (`isError: true`, same
  JSON-RPC `id`); anything else is forwarded unchanged. Default is still report-first — the built-in
  default resolves #39 to `notify` and forwards — so only an explicit `deny` blocks.
- **Everything else** — `initialize`, notifications, and all other responses — passes through
  **verbatim and transparently**.

**Limits of blocking a result, stated plainly.** The tool has already run by the time its result exists,
so blocking prevents the *agent* from reading the content; it does not undo whatever the tool did.

**Bounds that keep fail-open true across parse-then-forward:** a **750 ms** per-message deadline
(`CAPS.resultDeadlineMs`), an exactly-once write latch, and a **64 KB** cap on the composed scan text
(`CAPS.maxResultBytes`). A JSON-RPC line **over 1 MB** (`CAPS.maxLineBytes`) is forwarded entirely
unscanned rather than buffered.

It is the **same gateway, engine, detectors, and policy** as the Claude Code PreToolUse hook: it reuses
`buildEngine` + `mcpGateway` + `loadVerifiedPolicy` from `cli/hook-core.mjs`, so both entrypoints share
one implementation rather than a copy.

The policy is **signature-verified before it is trusted**. `loadVerifiedPolicy` checks the console's
ed25519 envelope against the machine-wide anchor (`/etc/moorai/policy.pub`, `%ProgramData%\MoorAI\policy.pub`,
or an MDM-injected key) or a TOFU pin established from a verified fetch. An unsigned, tampered, or
wrong-tenant `~/.moorai/hook-policy.json` is treated as **no policy at all** — the proxy falls back to the
last verified policy, then to the offline default per the posture ratchet — and emits a content-free
tamper alert. Writing `{}` into the cache therefore cannot disarm the gate. Because the proxy is a
long-lived process, verification re-runs on every lazy refresh, not once at startup.

## Content-free by construction

Only **category / risk / one-way hash / server / tool / decision** ever leave the device — the same
content-free contract as the hook. **Tool-call content is never emitted.** Each call produces one
content-free audit line in the local ledger (`~/.moorai/action-audit.jsonl`) and a content-free alert to
the console `/api/alerts`, using the config/token resolved by `cli/config.mjs`.

## Governance, not a sandbox — fail OPEN

On **any** error (unreadable/absent policy, engine build failure, an unparseable line, a network timeout)
the message is **forwarded unchanged**. The guard never blocks work because of its own failure.

## Install

```bash
# Preview what would change (no writes):
node mcp-proxy/install.mjs --dry-run

# Wrap every stdio MCP server in Claude Desktop's config (backs the file up first):
node mcp-proxy/install.mjs

# One other host, or every known host that actually has a config on this machine:
node mcp-proxy/install.mjs --host cursor
node mcp-proxy/install.mjs --all

# See which servers are currently guarded:
node mcp-proxy/install.mjs status

# Restore the originals:
node mcp-proxy/install.mjs uninstall
```

Known hosts (`--host <id>`): `claude-desktop`, `mcp-json` (the project-scoped `.mcp.json` in the CWD),
`cursor`, `vscode` (VS Code / Copilot — its server map is keyed `servers`, not `mcpServers`, which is why
the host table carries a `key`). **Codex has no entry:** its config is TOML and the installer writes JSON.
`--config <path>` targets an exact file, which is the supported route for profile/workspace variants
rather than growing the table into a guessing game.

The installer:

- reads the target host's config — with no flags that is `claude_desktop_config.json`
  (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`,
  Windows: `%APPDATA%\Claude\claude_desktop_config.json`), so an existing invocation is unchanged;
- **backs the file up** (`…​.moorai-backup-<timestamp>`) before any write;
- rewrites each entry in that host's server map that has a `command` so it launches through the guard,
  **preserving the original command/args** as the wrapped target
  (`node <guard> --server <name> -- <orig-cmd> <args…>`);
- is **idempotent** — a re-wrap of an already-wrapped entry is a no-op;
- leaves transport-only entries (e.g. `{ "url": … }` SSE/HTTP servers, which have no `command`) untouched;
- `uninstall` reconstructs each original from the wrapped args (no sidecar keys are added to your config).

**Restart the host** after installing or uninstalling.

## Run the guard directly

```bash
node mcp-proxy/moorai-mcp-guard.mjs [--server <label>] -- <real-server-cmd> [args…]
```

`--server <label>` is the MCP server name used for the gateway (allow-list, audit, alerts). It defaults to
the basename of the real command; the installer passes the configured server key.

## Verify

No real MCP host needed:

```bash
node mcp-proxy/moorai-mcp-guard.mjs --check   # (use: node --check on each .mjs)
node mcp-proxy/test-proxy.mjs
```

`test-proxy.mjs` spawns the guard wrapping `test-fake-mcp-server.mjs` (a tiny newline-JSON-RPC server that
answers `initialize` / `tools/list` and echoes `tools/call`) and asserts: benign calls are forwarded and
echoed; a policy-denied call is blocked (the real server never receives it — checked against its
received-log — and the host gets an error result with the matching id); and `initialize`/`tools/list`
pass through untouched. It also validates the `install.mjs` rewrite against a fixture
(wrap → idempotent re-wrap → uninstall restores the original).

## Measured coverage

`measure-mcp-coverage.mjs` drives malicious and benign actions through the proxy rather than reasoning
about it. Condition B (the guard in front of the server, enforcing policy):

| | result |
|---|---|
| malicious actions refused | **12 / 12** — 8 by the argument scan, **2 by the result scan** |
| benign actions forwarded | **4 / 4** |
| of those 12 actions, how many natively traverse MCP at all | **4** |

The last row is the honest bound on this surface: MCP is one wire. The other eight actions reach the
machine through a host's own built-in tools, where the Claude Code PreToolUse hook is the control and this
proxy sees nothing.

## Files

| File | Purpose |
|------|---------|
| `moorai-mcp-guard.mjs`     | The stdio proxy / gateway. |
| `tool-scan.mjs`            | Caps, and the composition of the scan text for a `tools/list` entry and a `tools/call` result. |
| `tool-baseline.mjs`        | Cross-call tool baseline — shadowing / capability-expansion drift. |
| `install.mjs`              | Wrap / uninstall / status a host's MCP config, per the `HOSTS` table (pure transforms exported for tests). |
| `test-proxy.mjs`           | Self-verification (proxy behavior + install rewrite). |
| `test-fake-mcp-server.mjs` | Tiny fake MCP server used by the test. |
| `measure-mcp-coverage.mjs` | Drives malicious/benign actions through the proxy to produce the coverage table above. |
