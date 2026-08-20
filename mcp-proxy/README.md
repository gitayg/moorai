# MoorAI MCP Guard for Claude Desktop

Claude Desktop has **no PreToolUse hooks** — that is a Claude Code CLI feature. But Claude Desktop *does*
launch MCP servers from `claude_desktop_config.json`. So MoorAI guards Claude Desktop the only place it
can: by inserting a tiny **stdio proxy between Claude Desktop and each MCP server**. Every MCP tool-call
passes through the proxy, which runs the **exact same `mcpGateway()`** the Claude Code hook uses.

This covers Claude Desktop's **MCP tool-calls — its highest-risk agentic surface** (the actions an agent
takes: file writes, shell, network, database, API calls). Reviewing Claude Desktop's *prompt text* is a
separate, future mechanism and is out of scope here.

## What it does

The proxy is spawned by Claude Desktop in place of the real MCP server. It spawns the real server as a
child and pumps stdio both ways (newline-delimited JSON-RPC 2.0):

```
Claude Desktop  ⇄  moorai-mcp-guard  ⇄  real MCP server
```

- Every JSON-RPC message with `method === "tools/call"` is gated through `mcpGateway()`
  (from `cli/hook-core.mjs`), in this order, short-circuiting on the first deny:
  1. **server allow-list** (#3) — is this MCP server allowed at all?
  2. **per-tool argument rules** (#18) — deny/allow regexes for this tool's arguments.
  3. **argument content scan** (#2) — the shared MoorAI detectors over the serialized arguments.
- **Block** → the call is **not** forwarded; the proxy returns a JSON-RPC *result* to Claude Desktop that
  is an MCP tool error (`isError: true`, using the request's `id`), so the model sees a clean refusal
  instead of a hang. The real server never receives the call.
- **Allow / coach** → forwarded unchanged. Claude Desktop has no interactive banner, so a "coach"
  (justify) verdict is treated as **allow + record**.
- **Everything else** — `initialize`, `tools/list`, notifications, and all responses — passes through
  **verbatim and transparently**.

It is the **same gateway, engine, detectors, and policy** as the Claude Code PreToolUse hook: it reuses
`buildEngine` + `mcpGateway` from `cli/hook-core.mjs` and the same policy cache
(`~/.curaiq/hook-policy.json`), fetched/served identically.

## Content-free by construction

Only **category / risk / one-way hash / server / tool / decision** ever leave the device — the same
content-free contract as the hook. **Tool-call content is never emitted.** Each call produces one
content-free audit line in the local ledger (`~/.curaiq/action-audit.jsonl`) and a content-free alert to
the console `/api/alerts`, using the config/token resolved by `cli/config.mjs`.

## Governance, not a sandbox — fail OPEN

On **any** error (unreadable/absent policy, engine build failure, an unparseable line, a network timeout)
the message is **forwarded unchanged**. The guard never blocks work because of its own failure.

## Install

```bash
# Preview what would change (no writes):
node mcp-proxy/install.mjs --dry-run

# Wrap every stdio MCP server in claude_desktop_config.json (backs the file up first):
node mcp-proxy/install.mjs

# See which servers are currently guarded:
node mcp-proxy/install.mjs status

# Restore the originals:
node mcp-proxy/install.mjs uninstall
```

The installer:

- reads `claude_desktop_config.json`
  (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`,
  Windows: `%APPDATA%\Claude\claude_desktop_config.json` — override with `--config <path>`);
- **backs the file up** (`…​.moorai-backup-<timestamp>`) before any write;
- rewrites each `mcpServers[*]` entry that has a `command` so it launches through the guard, **preserving
  the original command/args** as the wrapped target (`node <guard> --server <name> -- <orig-cmd> <args…>`);
- is **idempotent** — a re-wrap of an already-wrapped entry is a no-op;
- leaves transport-only entries (e.g. `{ "url": … }` SSE/HTTP servers, which have no `command`) untouched;
- `uninstall` reconstructs each original from the wrapped args (no sidecar keys are added to your config).

**Restart Claude Desktop** after installing or uninstalling.

## Run the guard directly

```bash
node mcp-proxy/moorai-mcp-guard.mjs [--server <label>] -- <real-server-cmd> [args…]
```

`--server <label>` is the MCP server name used for the gateway (allow-list, audit, alerts). It defaults to
the basename of the real command; the installer passes the configured server key.

## Verify

No real Claude Desktop needed:

```bash
node mcp-proxy/moorai-mcp-guard.mjs --check   # (use: node --check on each .mjs)
node mcp-proxy/test-proxy.mjs
```

`test-proxy.mjs` spawns the guard wrapping `test-fake-mcp-server.mjs` (a tiny newline-JSON-RPC server that
answers `initialize` / `tools/list` and echoes `tools/call`) and asserts: benign calls are forwarded and
echoed; a policy-denied call is blocked (the real server never receives it — checked against its
received-log — and Claude Desktop gets an error result with the matching id); and `initialize`/`tools/list`
pass through untouched. It also validates the `install.mjs` rewrite against a fixture
(wrap → idempotent re-wrap → uninstall restores the original).

## Files

| File | Purpose |
|------|---------|
| `moorai-mcp-guard.mjs`     | The stdio proxy / gateway. |
| `install.mjs`              | Wrap / uninstall / status the Claude Desktop config (pure transforms exported for tests). |
| `test-proxy.mjs`           | Self-verification (proxy behavior + install rewrite). |
| `test-fake-mcp-server.mjs` | Tiny fake MCP server used by the test. |
