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
  5. **vector-store writes** — when the tool writes documents into a vector store or memory (below),
     its arguments are scanned at the `index` stage too. Report-first; refused only under
     `policy.indexScanAction: "block"`.
- **Block** → the call is **not** forwarded; the proxy returns a JSON-RPC *result* to the host that
  is an MCP tool error (`isError: true`, using the request's `id`), so the model sees a clean refusal
  instead of a hang. The real server never receives the call.
- **Allow / coach** → forwarded unchanged. The host has no interactive banner, so a "coach"
  (justify) verdict is treated as **allow + record**.
- **Mask** → not applied here. The proxy never rewrites a call or a result, so a threat an org set to
  `mask` resolves to `policy.maskFallback` (`notify` / `justify` / `block`), else to the action it would
  have without the mask entry. The Claude Code hook is the surface that masks.

### agent → server: VECTOR-STORE WRITES (the index stage)

A document an agent writes into a vector store or a memory server is read back later into some other
context, with no tool call and nobody typing it. So a `tools/call` that writes documents gets the engine's
`index` stage (`DetectionEngine.scanForIndex`: the prompt detectors plus untrusted directives,
agent-addressed text, hidden canaries, tool poisoning and AI-only cloaking) over every string value of its
arguments, through [`../cli/index-tools.mjs`](../cli/index-tools.mjs) — the same module the HTTP gateway
uses, and the same decision as `scanBeforeEmbed` in `@moorai/agent-sdk` and `POST /v1/index-scan`.

A tool is a vector-store write when:
- `policy.indexTools` names it (`"add_documents"`, or `"<server>/<tool>"` for one server), always; or
- unless `policy.indexToolHeuristic: false`, it is one of the write tools of the servers below, by exact
  name (case-insensitive) and whatever the server is labelled; or
- unless `policy.indexToolHeuristic: false`, its name has a write verb (`add`, `upsert`, `insert`,
  `index`, `store`, `ingest`, `embed`, `save`, `remember`) and no read or delete verb (`get`, `list`,
  `query`, `search`, `delete`, …), plus one of: a store noun in the name (`documents`, `memory`,
  `memories`, `vectors`, `embeddings`, `chunks`, `passages`, `knowledge`), a vector-store hint in the
  tool or server name (`chroma`, `qdrant`, `pinecone`, `weaviate`, `milvus`, `mem0`, `openmemory`,
  `lancedb`, `pgvector`, `vector`, `memory`, `rag`, …), or a non-empty `documents` / `texts` / `chunks` /
  `passages` / `memories` array argument.

So `chroma_add_documents`, `qdrant-store`, `upsert` on a server labelled `pinecone`, `add_memory` and
`store_memory` match; `insert` on a server labelled `postgres`, `query_documents`, `get_index_stats` and
an index-creating call (`create-index-for-model`, `create_vector_index_hash`) do not. `update` and
`create` are not write verbs to the heuristic (`update_collection`, `create_document` on a docs server);
the real update and create writes are named below.

**Verified servers.** Tool names read from each server's source on 2026-10-07. Chroma (chroma-mcp 0.2.6) and Qdrant (mcp-server-qdrant 0.8.1) were also run live behind the proxy, and Qdrant behind the gateway (`test/index-real-vector-mcp.test.mjs`, opt-in): a poisoned document was refused and never stored; the others were not run. Every
write tool listed matches under its own label and under a neutral one; every other tool of these servers
(their read, search, delete and admin tools) matches under neither (`test/index-tools-mcp.test.mjs`).

| Server (repo @ commit) | Write tools recognised | Argument carrying the text |
|---|---|---|
| Chroma (`chroma-core/chroma-mcp` @ `98ff675`) | `chroma_add_documents`, `chroma_update_documents` | `documents` (string array) |
| Qdrant (`qdrant/mcp-server-qdrant` @ `c56ae5a`) | `qdrant-store` | `information` (string) |
| Pinecone (`pinecone-io/pinecone-mcp` @ `a15d4b9`) | `upsert-records` | `records[]`, in the field the index's `fieldMap` names |
| Weaviate (`weaviate/mcp-server-weaviate` @ `4db6a8f`, now deprecated; built into `weaviate/weaviate` @ `519a9ba`) | `weaviate-insert-one`, `weaviate-objects-upsert` | `properties`; `objects[].properties` |
| mem0 (`mem0ai/mem0-mcp` @ `624024d`, archived for the hosted server) | `add_memory`, `update_memory` | `text`, `messages` |
| OpenMemory (`mem0ai/mem0` @ `13c7f84`, removed from the repo since) | `add_memories` | `text` |
| Milvus (`zilliztech/mcp-server-milvus` @ `6a2bff9`) | `milvus_insert_data` | `data` (row objects) |
| OpenSearch (`opensearch-project/opensearch-mcp-server-py` @ `cd287e8`) | `SaveMemoryTool`, `AddAgenticMemoriesTool`, `UpdateAgenticMemoryTool`, `CreateAgenticMemorySessionTool`; `GenericOpenSearchApiTool` only for `POST` / `PUT` / `PATCH` to `_doc`, `_create`, `_update` or `_bulk` | `memory`; `messages[].content[].text`, `memory`, `summary`; `body` |
| Redis (`redis/mcp-redis` @ `e89cff9`) | `set_vector_in_hash` | `vector` (numbers only) |
| LanceDB (`lancedb/lancedb-mcp-server` @ `91a064e`) | `ingest_docs` | `docs` |
| MCP reference `memory` (`modelcontextprotocol/servers` @ `5abed86`) | `create_entities`, `create_relations`, `add_observations` | `entities[].observations[]`; `relations[]`; `observations[].contents[]` |
| Elasticsearch (`elastic/mcp-server-elasticsearch` @ `9e64b84`, deprecated) | none: every tool is read-only | |

Every string value of a matched call's arguments is scanned, so the argument name only matters to the
heuristic. Redis's plain key-value writes (`hset`, `json_set`, `set`, …) are not treated as index writes:
name them in `indexTools` when that Redis backs a vector index. Findings are reported at stage `index` (one per threat the argument scan did not already
report). `policy.indexScanAction: "block"` refuses the call before the server sees it
(`MCP: blocked vector-store write`) when a finding is an instruction-carrying threat or one whose action
is block / kill; the default `"report"` forwards it. An unenrolled device coaches. **Not covered:** a
store tool whose name and arguments match nothing (name it in `indexTools`), documents a store ingests
on its own, and an agent that embeds through an in-process library instead of MCP. Not tested against a
running Chroma, Qdrant, Pinecone, Weaviate, mem0, Milvus, OpenSearch, Redis, LanceDB or memory server: the
names above come from their source, and the end-to-end tests use the fake server
(`test/index-tools-mcp.test.mjs`).

### server → agent: the tool LISTING and the tool RESULT

This direction used to be observe-nothing, then observe-only. Both halves are now scanned, and one of
them can block.

- **`tools/list` responses** are copied to a bounded scanner at the **`tool`** stage
  ([`tool-scan.mjs`](tool-scan.mjs), with the cross-call shadowing / capability-expansion half in
  [`tool-baseline.mjs`](tool-baseline.mjs)), so tool descriptions and input schemas reach
  `mcp-tool-poisoning` (#60), `mcp-hidden-canary` (#50) and `mcp-tool-cred-path` (#60: a description that
  tells the model to read a credential file such as `~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`,
  `.netrc`, a browser cookie store or a keychain, and pass its contents into a call; silent when the text
  only names the file, negates the read, or describes what the server itself does). **Report-first:** the
  listing is forwarded byte-identical. A blocking policy for a content finding **quarantines** the tool,
  and the already-existing `tools/call` gate refuses calls to it. The one exception is the opt-in
  `mcpToolDrift: "block"` (below): a tool that changed since approval is left out of the listing.
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

### Tool drift: block until re-approved (`mcpToolDrift`)

Tool descriptions and schemas can change after a server was approved, and a changed description is
where a quiet prompt injection lands. [`tool-baseline.mjs`](tool-baseline.mjs) has always noticed:
description drift (Medium, High if the schema changed too), schema drift (High) and a tool name taken
over by a second server (shadowing, High). In the default mode that is all it does: it alerts and
re-baselines at once, so the change is accepted after one alert. The policy key `mcpToolDrift` makes
that a gate:

| `mcpToolDrift` | What happens to a drifted tool |
|---|---|
| `"alert"` (default; also any value other than `"block"`) | Today's behaviour, unchanged: the listing is forwarded byte-identical, an alert is raised, the baseline moves to the new value. A tool added later and a removed tool raise nothing. |
| `"block"` | The tool is **quarantined**: it is left out of the `tools/list` the client receives, and a `tools/call` to it is refused with the usual refusal shape (an MCP tool result with `isError: true`). The baseline does **not** move. |

In block mode, four things quarantine a tool: a changed description, a changed schema, a tool **added**
to a server that already has a baseline, and **shadowing**. A **removed** tool only alerts (`MCP: tool
removed after approval`, Medium, `decision: "notify"`); there is nothing to quarantine. The alerts keep
their categories and add `decision: "quarantine"` and `reasonCode: "MCP_TOOL_DRIFT"`
([`../cli/provenance.mjs`](../cli/provenance.mjs)). The new categories are `MCP: tool added after
approval`, `MCP: tool removed after approval`, and, for a refused call, `MCP: quarantined tool (changed
since approval)` and `MCP: tool not in a checked listing`. A listing in which nothing is quarantined is
still forwarded with its original bytes.

**What the tool is compared with.** When an admin approves the server in the console, the console pins
that server's tool fingerprints as the **approved baseline**: content-free hashes in the `toolIdentity`
shape (`{ key, srv, desc, schema }`, each `fp2:` + 16 hex of an unkeyed SHA-256). The baseline reaches
the device inside the **signed policy** it already fetches (`GET /api/policy`), as
`mcpToolBaselines[<server label>] = { version, tools: [...] }`. A server with an approved baseline is
judged against it; a server without one is judged against the device's own first-seen baseline
(`~/.moorai/mcp-tool-baseline.json`). Against an approved baseline, any tool not in it is "added" (or
"shadow" when another approved server, or the local baseline, gives the name to a different server).

**Where the console gets the fingerprints.** In block mode the proxy posts the fingerprints of every
complete listing (not a page of a paginated one) to `POST /api/mcp/tools` (install token, `{ server,
tools, actor }`), once per distinct set per process. `actor` is the device's content-free actor hash, the
one every alert carries: the install token is per tenant, so it is how the console tells one device's
report from another's. Nothing else: no tool name, description or schema. The console keeps the reports
per reporting device. Approving the server pins the set every current reporter agrees on (or the set the
admin names by digest) at the next version; while devices disagree, an approval pins nothing.
A later report that differs shows "tools changed since approval — awaiting re-approval"; re-approving
accepts the new fingerprints. So the order of operations for an org is: set `mcpToolDrift` to `block`,
let devices report, then approve (or re-approve) the server to pin its tools.

**Re-approval releases the tool without a re-list.** A quarantined tool is re-judged on every call
against the policy in force at that moment (refreshed every 60 s), so the first call after the new policy
arrives goes through. A released tool is recorded in the local baseline.

**A stale policy cannot unblock.** Each approved baseline carries a per-server `version` that the
console increments on every approval. The device keeps the highest version it has accepted for each
server (`~/.moorai/mcp-tool-approved.json`; the server label is stored as a fingerprint) and ignores an
approved baseline below it. This sits under the policy envelope's own rollback refusal (`policySig.iat`
against the pin's high-water mark), not in place of it: the version file is in the agent's write scope,
so deleting it removes this second layer and leaves the first.

**Which way each failure goes.**

| Situation | Result |
|---|---|
| No verified policy (unenrolled, console never reached, unverifiable cache, the fail-closed offline default) | alert mode (open): the default policy does not set `mcpToolDrift` |
| A coach device (unenrolled or unmanaged) | alert mode (open); coach never blocks |
| Policy says `block`, console unreachable | the cached or last-known-good policy still says `block`, and its approved baselines still apply |
| No approved baseline for this server | the local first-seen baseline; the first listing of a server new to the device is accepted (open) |
| Approved baseline malformed (a non-integer version, a non-`fp2` hash, more than 2,048 tools) | ignored; the local baseline decides |
| Approved baseline older than the version this device already accepted | ignored; the local baseline decides (a stale cache cannot unblock) |
| Local baseline file missing, corrupt or unwritable | treated as empty: the next listing is a first sighting and is accepted (open). It does not matter for a server with an approved baseline |
| A `tools/list` arrives before this process has loaded any policy | held up to 2 s for the policy only when the device's cached or last-known-good policy says `block` (an unverified hint, used for nothing else); otherwise, or after the wait, forwarded unfiltered and judged when the policy arrives. Calls are enforced either way (list open, call closed). A device in alert mode never waits |
| A `tools/list` line over 1 MB (`CAPS.maxLineBytes`), or one that is not JSON | never parsed, so not filtered; every call is refused as `MCP: tool not in a checked listing` (closed) until a listing is judged again — including tools an earlier listing passed: an unjudged listing clears every verdict for that server. (An over-cap or unparseable line while a `tools/list` is outstanding counts as that listing.) |
| A `tools/list` whose `result` key is spelled with a `\u` escape (`"\u0072esult"`) | parsed and judged like any other (any line with a `\u` escape is parsed) |
| A call to a tool that was never in a listing | refused (closed) |
| The policy switches from `alert` to `block` during a session | tools listed under `alert` are judged on their first call, against the approved baseline if there is one; a tool that passes keeps working without a re-list |
| The judgement throws | the listing is forwarded unfiltered; every verdict for that server is cleared, so calls are refused (closed) until a listing is judged again |
| The fingerprint post to the console fails | nothing changes on the device; the console has nothing new to pin until the next report |
| A paginated listing | each page is judged; a removal is not reported and fingerprints are not posted, so a paginated server cannot be pinned and stays on the local baseline. On a server's first sighting every page of that first listing is a first sighting (a page-2 tool is not "added after" page 1); a page over 1 MB clears the server's verdicts as above |

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

**Shutdown.** The guard ends its child the way an MCP client ends a stdio server. On stdin EOF it closes
the child's stdin; a child still running 2 s later gets SIGTERM, and SIGKILL 2 s after that. SIGTERM,
SIGINT and SIGHUP to the guard are forwarded to the child at once, with the same SIGKILL fallback. The
guard exits when the child does, after every response already read from the child has been written out;
its exit code is the child's (0 when the guard ended it after EOF). Some real servers never exit on stdin
EOF (chroma-mcp 0.2.6, measured), and before this they were left running with ppid 1. On Windows
`child.kill()` terminates only the direct child, so a server launched through a wrapper (`cmd /c npx …`)
can still leave its grandchild running there.

## Verify

`test-proxy.mjs` needs no MCP host:

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

### With real MCP clients (measured 2026-10-06, macOS, Node 22.22.0)

```bash
node scripts/mcp-client-matrix.mjs            # every installed client × the guard and the HTTP gateway; no model call
MOORAI_LIVE_MCP=1 node --test --import ./test/hermetic-env.mjs test/mcp-live-client.test.mjs   # the same, as 17 opt-in tests
node scripts/mcp-live-toolcall.mjs            # live tier: prints the plan; --run spends 3 `claude -p` turns
```

`scripts/mcp-client-matrix.mjs` runs each installed client against the guard, which wraps
`test-fake-mcp-server.mjs`. The clients are Claude Code 2.1.284 (`claude mcp list`), cursor-agent
2026.05.27-fe9a6e2 (`cursor-agent mcp list-tools`), the official TypeScript SDK 1.32.1 `Client` over
`StdioClientTransport`, and the MCP Inspector 2.9.0 CLI. No model is called. A small tap
([`test/live/tee-server.mjs`](test/live/tee-server.mjs)) records what the guard forwarded. Measured:

- every client's own `initialize` (its `clientInfo`), `notifications/initialized` and `tools/list` reached
  the server through the guard, and the client received the tool list. Claude Code prints
  "✔ Connected" only when `tools/list` succeeded (a failing `tools/list` prints
  "! Connected · tools fetch failed"); cursor-agent, the SDK and the Inspector print the tool names.
- the guard recorded the `tools/list` it relayed: an entry for `echo` in `~/.moorai/mcp-tool-baseline.json`,
  under the route's server label.
- the SDK and the Inspector each make two `tools/call`s. A benign one is forwarded and echoed. One whose
  argument matches the policy's deny rule comes back as `MoorAI blocked this MCP tool call: …`, and the
  server never receives it. Both calls are counted in `~/.moorai/mcp-usage.json` and appear in
  `action-audit.jsonl` as `allow` and `deny`; the console receives a `Blocked` alert.
- in a live Claude Code run (`claude -p`, Haiku, `--mcp-config … --strict-mcp-config`), the model called
  `mcp__moorai-stdio__echo`. A benign call was forwarded and recorded as `allow`. A call with a denied
  argument reached the model as an error result carrying MoorAI's refusal, the server never received it,
  and it was recorded as `deny` with a `Blocked` alert.

Each client in the matrix runs with a throwaway HOME and project, without its credentials. On macOS it
runs under `sandbox-exec`, which denies writes to `~/.claude.json`, `~/.claude` and `~/.cursor` and denies
all non-localhost egress. `MOORAI_LIVE_BREAK=bypass|dead|toolscan|no-refusal|no-policy|list-error` makes
the run fail; this is the check that the assertions can fail. A wrapped command cannot be given to the
Inspector on its command line, because it splits its target at the first `--`; use its `--config` session
file instead, as the matrix does.

Not tested: Claude Desktop, VS Code, Cursor's desktop app, Windows, Linux, and the `install.mjs` rewrite
applied to a real host config. The proxy refuses nothing at handshake time (`initialize` and `tools/list`
always pass), so a client can see a proxy refusal only on a `tools/call`; and only the call stage was
exercised with real clients, not a result-stage block.

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
| `tool-drift.mjs`           | `mcpToolDrift: "block"`: approved-baseline precedence, quarantine verdicts, the version mark, the fingerprint report. Shared with the HTTP gateway. |
| `install.mjs`              | Wrap / uninstall / status a host's MCP config, per the `HOSTS` table (pure transforms exported for tests). |
| `test-proxy.mjs`           | Self-verification (proxy behavior + install rewrite). |
| `test-fake-mcp-server.mjs` | Tiny fake MCP server used by the test. |
| `test/live/tee-server.mjs` | Tap in front of the fake server that records what the guard forwarded, for the real-client runs. |
| `measure-mcp-coverage.mjs` | Drives malicious/benign actions through the proxy to produce the coverage table above. |
