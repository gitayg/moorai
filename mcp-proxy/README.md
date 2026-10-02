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
  (from `cli/hook-core.mjs`), in this order, steps 1–3 short-circuiting on the first deny:
  1. **server allow-list** (#3) — is this MCP server allowed at all?
  2. **per-tool argument rules** (#18) — deny/allow regexes for this tool's arguments.
  3. **argument content scan** (#2) — the shared MoorAI detectors over the serialized arguments.
  4. **files the arguments name** — unless step 1 or 2 refused the call, every local file an argument
     names (absolute, `~`, `file://`, or relative to the proxy's cwd and then to the client's MCP roots,
     kept from its `roots/list` answer, at most 16) gets what the Claude Code hook gives a file a `Bash`
     command reads: its content at the `file` stage, its metadata (#72) and its location against the
     credential list (#55). Same helper as the hook's `mcp__*` branch
     ([`../cli/mcp-file-args.mjs`](../cli/mcp-file-args.mjs)). A relative path is left alone when the call
     names a remote `owner` / `repo` / `repository` / `project_id` / `bucket` and the tool's name does
     not send. Only regular files are read (a symlink to a regular file is judged by its target; never
     `/dev`, `/proc`, `/sys`, FIFOs, sockets or UNC paths); at most 12 files, 256 KB each, 1 MB and 1 s per
     call, and anything past a cap is skipped silently. A file verdict that outranks the gateway's
     refuses the call with category `MCP: blocked file argument`; each file's findings are reported at
     stage `file`. Not tested against a live MCP server or on Windows.
- **Block** → the call is **not** forwarded; the proxy returns a JSON-RPC *result* to the host that
  is an MCP tool error (`isError: true`, using the request's `id`), so the model sees a clean refusal
  instead of a hang. The real server never receives the call.
- **Allow / coach** → forwarded unchanged. The host has no interactive banner, so a "coach"
  (justify) verdict is treated as **allow + record**.
- **Mask** → not applied here. The proxy never rewrites a call or a result, so a threat an org set to
  `mask` resolves to `policy.maskFallback` (`notify` / `justify` / `block`), else to the action it would
  have without the mask entry. The Claude Code hook is the surface that masks.

### server → agent: the tool LISTING and the tool RESULT

This direction used to be observe-nothing, then observe-only. Both halves are now scanned, and one of
them can block.

- **`tools/list` responses** are copied to a bounded scanner at the **`tool`** stage
  ([`tool-scan.mjs`](tool-scan.mjs), with the cross-call shadowing / capability-expansion half in
  [`tool-baseline.mjs`](tool-baseline.mjs)), so tool descriptions and input schemas reach
  `mcp-tool-poisoning` (#60), `mcp-hidden-canary` (#50) and `mcp-tool-cred-path` (#60: a description that
  tells the model to read a credential file such as `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`,
  `.netrc`, a browser cookie store or a keychain, and pass its contents into a call; silent when the text
  only names the file, negates the read, or describes what the server itself does). **Report-first, and never a mutation:** the
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

### first sight: the server's REPUTATION

The launch command the proxy wraps is scored once, at startup, and cached per server identity + version
in `~/.moorai/mcp-reputation.json` (`cli/mcp-reputation.mjs`, scoring in `data/mcp-reputation.js`). A
score starts at 100; each signal subtracts its weight; bands are good ≥ 80, fair ≥ 60, poor ≥ 35, bad.
Signals, all offline unless the policy opts in:

- the package name against the known-malicious / popular-library list and the popular MCP server list
  (`data/popular-mcp-servers.js`, from the SkillTriage catalogue seed) — `pkg-known-malicious`,
  `pkg-typosquat`, `mcp-typosquat`; an unpinned `npx -y pkg` — `unpinned-version`;
- the copy npx already installed under `~/.npm/_npx`, read with the package heuristics and scoped engine
  scan SkillTriage runs — `pkg-install-script-remote`, `pkg-remote-code`, …;
- the server's own `tools/list` — `tool-poisoning` (#60, including `mcp-tool-cred-path`),
  `tool-hidden-content` (#50), `tool-metadata`;
- opt-in `mcpReputation.lookup: "registry"` — MoorAI's `analyzePackage` on the exact registry artifact
  (only the public name and version reach the public registry): `new-package`, `name-not-published`;
  and, in parallel, the **repository link** below;
- opt-in `mcpReputation.feed: true` — SkillTriage's published verdicts, downloaded whole with a bare GET
  and matched on the device (`catalogue-do-not-install`, `catalogue-review`, …), so the request names no
  server.

Report-only by default: a content-free alert (`MCP: server reputation`, band, score, category codes —
never a package name, path, argument or env var) on first sight or a version change when the band is
below good. `mcpReputation.blockBelow: <n>` refuses `tools/call` to a server scoring below `n` on an
enforcing device; unenrolled, it coaches instead. `mcpReputation.enabled: false` turns it off. The same
score appears in `moorai-aibom` (`reputation` per MCP server) and `moorai-shadow`. The Claude Code hook
scores offline and reuses a registry result the proxy already cached.

**The repository link** (part of the opt-in registry lookup; [`../cli/mcp-repo-link.mjs`](../cli/mcp-repo-link.mjs),
pure half in [`../data/repo-link.js`](../data/repo-link.js)). Does the package link to a real repository that
is actually its own?

1. **Registry provenance first**, when the publisher produced it: npm `dist.attestations` (the SLSA
   predicate's workflow repository) or PyPI Trusted Publishing (`attestation_bundles[].publisher.repository`),
   compared with the repository the package declares. The registry checked the link at publish time.
2. **Otherwise the repository's own manifest**, read raw from github.com or gitlab.com at the declared
   directory or the root (`package.json` `name`; `pyproject.toml`, `setup.cfg`, `setup.py`), must name the
   same package. A monorepo root is searched at up to 6 candidate folders; not finding the package there
   is unverified, never a mismatch.

| Reason code | Weight | Meaning |
|---|--:|---|
| `repo-mismatch` | 30 | provenance, or the repository's own manifest, names a different package |
| `repo-unreachable` | 15 | the host says the declared repository is not publicly there (deleted, private, placeholder) |
| `repo-missing` | 5 | no repository declared, or it cannot be parsed |

Timeouts, 5xx, 429, a host it cannot read and a dynamic name are evidence only, never a signal: unknown is
not bad. Bounds: 4 s per request, 10 s in total, at most 12 requests, redirects followed by hand (at most
two) and only within the registries, github.com and gitlab.com. Only the public package name and version
go to the registry and the public owner / repo / directory the registry published go to the code host; no
local path, argument, environment value or identifying header.

Measured on 325 popular servers: provenance 128, verified 80, none declared 98, unverified 7,
unreachable 8, mismatch 2 (one of them a false positive after a rename, `blender-mcp`).

**Limits.** Sigstore signatures on provenance are read, not re-verified. The manifest is read at `HEAD`,
so a package renamed after publishing reads as a mismatch. Repositories on bitbucket.org and codeberg.org
are not verified.

## Content-free by construction

Only **category / risk / one-way hash / server / tool / decision** ever leave the device — the same
content-free contract as the hook. **Tool-call content is never emitted.** Each call produces one
content-free audit line in the local ledger (`~/.moorai/action-audit.jsonl`) and a content-free alert to
the console `/api/alerts`, using the config/token resolved by `cli/config.mjs`.

### Usage counts for the proxy-vs-hook cross-check

Every `tools/call` is also counted, content-free, in `~/.moorai/mcp-usage.json` (0600) per UTC day,
path `"proxy"`, host and server label (`cli/mcp-usage-beat.mjs`). Once a day is over it is posted once to
`POST /api/mcp-usage` with the install token: `{ user, device, platform, actor, day, path, host,
servers: [{ label, calls }] }` — at most 64 servers, labels at most 64 characters, no tool names and no
arguments. The Claude Code hook counts its `mcp__*` calls the same way under path `"hook"`, so the console
can show a server that one path saw and the other did not. The post runs off the stdio path (at start-up
and every 30 minutes, on an unref'd timer); a failed post is retried after ten minutes; an unenrolled
device posts nothing. The host comes from the `--host` stamp the installer writes (below); an entry
wrapped before the stamp existed reports `"unknown"` until the installer is re-run.

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
  (`node <guard> --server <name> --host <id> -- <orig-cmd> <args…>`);
- stamps **which host** the server belongs to (`--host`, for the usage cross-check): `claude-desktop`,
  `claude-code` for `.mcp.json`, `cursor`, `vscode`. A bare `--config <path>` writes no stamp;
- is **idempotent** — a re-wrap of an already-wrapped entry is a no-op, except that an entry wrapped
  before the host stamp existed gains it;
- leaves transport-only entries (e.g. `{ "url": … }` SSE/HTTP servers, which have no `command`) untouched;
- `uninstall` reconstructs each original from the wrapped args (no sidecar keys are added to your config).

**Restart the host** after installing or uninstalling.

## Run the guard directly

```bash
node mcp-proxy/moorai-mcp-guard.mjs [--server <label>] [--host <id>] -- <real-server-cmd> [args…]
```

`--server <label>` is the MCP server name used for the gateway (allow-list, audit, alerts). It defaults to
the basename of the real command; the installer passes the configured server key. `--host <id>` names the
MCP host for the usage counts (`claude-desktop`, `vscode`, `cursor`, `claude-code`, …); anything else, or
nothing, is `unknown`.

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

The usage counts have their own tests: `test/mcp-usage-beat.test.mjs` (tally, once a day, retry, the exact
post shape) and `test/mcp-usage-proxy.test.mjs` (the installer's host stamp driven through the real guard
to a stand-in console).

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
