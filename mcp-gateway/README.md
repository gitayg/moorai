# MoorAI MCP Gateway (remote MCP servers)

[`../mcp-proxy/`](../mcp-proxy/README.md) guards MCP servers a host launches as **local stdio
processes**. A **remote** MCP server is reached over HTTP instead, so there is no process to wrap. The
gateway is a small reverse proxy on the same machine: the MCP client is pointed at
`http://127.0.0.1:8848/<route>` instead of the remote URL, and the gateway forwards to the remote server
after applying the stdio proxy's checks.

```
MCP client  ⇄  moorai-mcp-gateway (127.0.0.1)  ⇄  https://remote.example/mcp
```

One gateway serves several remote servers; each route maps a local path to one upstream URL, and the
route's name is the MCP server label used for the allow-list, the audit line and the alerts.

## Transport it implements against

Read from the MCP specification on 2026-10-01. The current revision is **2026-07-28**; its Streamable
HTTP binding says:

- "The server **MUST** provide a single HTTP endpoint path … that supports POST." Every client message
  is its own POST, and for a request "the server **MUST** return either `Content-Type: application/json`
  (a single JSON object) or `Content-Type: text/event-stream` (an SSE response stream)".
- On an SSE response the server "**MAY** send JSON-RPC *notifications* … before the final response",
  and "The final JSON-RPC *response* **SHOULD** terminate the stream."
- Revision 2026-07-28 removed "the GET stream endpoint" and "protocol-level sessions"; resumable streams
  via `Last-Event-ID` "are not supported".
- Request metadata is mirrored into headers (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`,
  `Mcp-Param-*`), and "Servers that process the request body **MUST** reject requests where the values
  specified in the headers do not match the corresponding values in the request body", with HTTP 400
  and JSON-RPC error `-32020` (`HeaderMismatch`).
- Security: "Servers **MUST** validate the `Origin` header on all incoming connections to prevent DNS
  rebinding attacks", and "When running locally, servers **SHOULD** bind only to localhost (127.0.0.1)".

Revisions **2025-03-26 through 2025-11-25** use the same transport in a different shape, and clients and
servers on those revisions are common: a server "**MAY** assign a session ID at initialization time, by
including it in an `MCP-Session-Id` header", which clients "**MUST** include … on all of their
subsequent HTTP requests"; clients "**SHOULD** send an HTTP DELETE to the MCP endpoint with the
`MCP-Session-Id` header" to end it; a client "**MAY** issue an HTTP GET to the MCP endpoint" to open a
server-initiated SSE stream.

Authorization (2026-07-28): the client "**MUST** use the Authorization request header field", which
"**MUST** be included in every HTTP request from client to server", and "Access tokens **MUST NOT** be
included in the URI query string".

The gateway handles **both eras** by being transparent to them: every end-to-end request header goes
upstream as sent (`Authorization`, `Mcp-Session-Id`, `MCP-Protocol-Version`, `Mcp-*`, `Last-Event-ID`),
every response header comes back (`Mcp-Session-Id`, `WWW-Authenticate`), and GET / DELETE / any other
method are forwarded. Only POST bodies are gated and only responses are scanned.

## What it checks

Same engine, detectors, policy and alert shapes as the stdio proxy; the call order is the proxy's.

| Direction | Message | Check | Outcome |
|---|---|---|---|
| client → server | every POST body | **staged JSON-RPC / MCP validation** (below) | refused with `SCHEMA_INVALID` (`--schema enforce`, the default) |
| | any request | client in a **cool-down** (below; off by default) | refused with `CLIENT_COOLDOWN` |
| | `tools/call` | tool quarantined at list time (policy blocked its metadata) | refused |
| | | `mcpToolDrift: "block"`: the tool changed, was added, or shadows another server's tool since the approved baseline; or it was never in a listing the gateway checked | refused, `MCP_TOOL_DRIFT`; released when the console re-approves |
| | | server reputation below `mcpReputation.blockBelow` (identity: the upstream URL) | refused on an enforcing device |
| | | **declared workload profile** (`workloadProfiles`, below) | report or block per profile; `PROFILE_DRIFT` |
| | | `mcpGateway`: server allow-list (#3) → per-tool argument rules (#18) → argument content scan (#2) | per policy |
| | | **local secret egress (#65)** — a value from this machine's `.env*` (gateway cwd), `~/.aws/credentials`, `~/.npmrc`, `~/.netrc`, `.git-credentials` appearing verbatim in the arguments. The hook's check; the stdio proxy does not run it | per policy; the default resolves #65 to block |
| | | **files the arguments name** — only with `--local-files` (or `"localFiles": true` on a route) | per policy |
| | | **vector-store write** — a tool in `policy.indexTools`, or matched by the name / argument heuristic ([`../cli/index-tools.mjs`](../cli/index-tools.mjs)): its arguments are scanned at the `index` stage | reported at stage `index`; refused (`MCP: blocked vector-store write`) only under `policy.indexScanAction: "block"` |
| | `Mcp-Name` / `Mcp-Method` header ≠ body | header–body consistency | HTTP 400, `-32020` |
| server → client | `tools/list` result | tool stage: #60 poisoning (incl. credential-path descriptions), #50; drift against the shared tool baseline (rug-pull, capability expansion, shadowing) | alert; a blocking policy quarantines the tool. Never altered, except under `mcpToolDrift: "block"`, where a quarantined tool is left out of the list (JSON body or SSE event) |
| | any other result (JSON or each SSE event) | result scan at stage `file` | alert; replaced by a tool error when policy resolves to block |
| | any response | staged validation | reported; an invalid **`tools/call` result** is replaced by a tool error (`--schema enforce`); a listing is never altered |
| | a JSON response / one SSE event over `--max-response-bytes` (4 MiB) | size cap | refused with `RESPONSE_TOO_LARGE` |

**File arguments are opt-in** because a remote server never reads the gateway's disk: a path in the
arguments names a file on the *client's* machine only when the gateway runs there too. Relative paths
resolve against the gateway's cwd, then the route's `roots`, then the `file://` roots the client sent
in a (legacy) `roots/list` answer.

**Vector-store writes** (`add_documents`, `upsert`, `store_memory`, … on a Chroma, Qdrant, Pinecone,
Weaviate or mem0 server) are content headed for a retrieval index, so their arguments get the engine's
`index` stage on top of the argument scan, through the module the stdio proxy uses. The write tools of
these servers are recognised by name, whatever the route is labelled (verified against their source on
2026-10-07, not against running servers):

| Server | Write tools |
|---|---|
| Chroma | `chroma_add_documents`, `chroma_update_documents` |
| Qdrant | `qdrant-store` |
| Pinecone | `upsert-records` |
| Weaviate | `weaviate-insert-one`, `weaviate-objects-upsert` |
| mem0 / OpenMemory | `add_memory`, `update_memory` / `add_memories` |
| Milvus | `milvus_insert_data` |
| OpenSearch | `SaveMemoryTool`, `AddAgenticMemoriesTool`, `UpdateAgenticMemoryTool`, `CreateAgenticMemorySessionTool`, and `GenericOpenSearchApiTool` for a document write |
| Redis | `set_vector_in_hash` |
| LanceDB | `ingest_docs` |
| MCP reference `memory` | `create_entities`, `create_relations`, `add_observations` |

Sources (repo and commit per server), the argument that carries the text, the name heuristic for other
servers, the report-first rule and what is not covered: "Vector-store writes" in
[`../mcp-proxy/README.md`](../mcp-proxy/README.md). The route label counts as the server name for the
vector-store hint (`--route /qdrant=…` makes a bare `upsert` a write).

**A refused call** gets HTTP 200 with the proxy's shape — a JSON-RPC response with the request's `id` and
`result: { content: [{ type: "text", text: "MoorAI blocked this MCP tool call: …" }], isError: true }` —
not a JSON-RPC `error`, which clients treat as a transport failure. The remote server never receives the
call. A refused **result** is the same shape ("…blocked this MCP tool result…"); in an SSE stream the
replacement event keeps the original's `id:` line, and the notifications before it pass unchanged.

A (2025-03-26) **batch** with one refused call is refused whole, every request in it answered with a
tool error; forwarding part of a batch would answer some ids and not others.

**Tool drift, block until re-approved.** The policy key `mcpToolDrift: "block"` works here exactly as
in the stdio proxy, through the same module ([`../mcp-proxy/tool-drift.mjs`](../mcp-proxy/tool-drift.mjs)),
one tracker per route: the approved baseline from the signed policy (`mcpToolBaselines[<route server
label>]`) or else the first-seen baseline, quarantine on description / schema drift, an added tool and
shadowing (across routes of one gateway too), an alert only for a removed tool, the baseline held until
re-approval, the per-server version mark, the fingerprint report to `POST /api/mcp/tools`, and the same
failure directions. See "Tool drift: block until re-approved" in
[`../mcp-proxy/README.md`](../mcp-proxy/README.md). One gateway-specific line: a JSON response between
1 MB and the response cap (or an SSE event over 1 MB) is forwarded unscanned, so its tools are not
filtered, and when the request was a `tools/list` every verdict for that route is cleared: calls are
refused as not checked until a listing is judged again, including tools an earlier listing passed. The
same clearing happens for every other `tools/list` answer the gateway forwards unjudged: a content type
it does not scan, a content-coding it cannot decode, an unparseable body or SSE event, and a listing
whose scan threw. A `tools/list` answer in `gzip`, `deflate` or `br` (the gateway asks upstream for
`identity`; a server can ignore that) is decoded, judged like any other, and sent to the client decoded;
the response cap counts decoded bytes. A response with no request ids (a GET stream, a resumed stream,
the answer to a POST of only notifications or responses) can carry the answer to any earlier
`tools/list`, so it is treated the same way: decoded when it is `gzip`/`deflate`/`br`, each SSE event
scanned and any listing in it judged. When such a response goes out unscanned anyway (a content-coding
the gateway cannot decode, a content type it does not scan, an unparseable `message` event, an event too
large to scan), the route's verdicts are cleared once its first byte is forwarded. The MCP SDK client
reads any 2xx GET body as SSE whatever its Content-Type, which is why a content type the gateway does not
scan counts. An empty body (a `405` to the GET, a `202`) and a non-`message` event with unparseable data
(a keep-alive `ping`) leave the verdicts alone, because the client reads no listing from them. With no
response cap (`--max-response-bytes 0`) an SSE event over 1 MB streams through unframed; that also
clears the verdicts. The response to any other POST can carry the answer to a `tools/list` that is still
outstanding (a hostile server holds it open and answers it inside a compressed or oversized `tools/call`
result), so the gateway tracks, per route, every `tools/list` it forwarded until a message answering
that id is judged ([`pending-lists.mjs`](pending-lists.mjs): at most 1,024, each for at most 5 minutes,
oldest dropped first). An entry that expires or is evicted unanswered clears the route's verdicts: the
gateway can no longer see that listing's answer. While any is outstanding, a compressed JSON or SSE
response is decoded and judged like a listing answer, and every unscanned path clears the verdicts. A
response that started passing through unscanned clears them once a byte of it goes out while one is
outstanding. When none is outstanding, other compressed responses (to a POST whose requests include no
`tools/list`) are still forwarded unscanned, verdicts untouched.

Every message with a `result.tools` array is judged as a listing, whatever its id and whatever the POST
carried. Ids are matched the way the MCP SDK client matches them, `Number(id)` (so `"1"`, `"1.0"`, `1.0`
and `"01"` all answer request `1`; an id that is not a finite number is matched as its string). A message
answers an outstanding `tools/list`, and takes its entry, only when the SDK would dispatch it as that
answer: a response read by the client (the body of a POST that carried a request, or a GET stream), a
single `message` event or a JSON body whose every message parses (the SDK refuses a JSON body with one bad
message whole), with no `method`, exactly `jsonrpc`/`id` plus one of `result`/`error`, an integer
`error.code` and string `error.message` for an error, and a `tools` array for a result. Any other listing
(a late duplicate for an id already answered, which the SDK drops because it keeps the first answer; a
malformed message; an id no outstanding `tools/list` carried, such as an unsolicited listing on a GET
stream) is judged **tighten-only**: a drifted tool in it is quarantined and left out, but it never clears a
verdict, never moves the baseline, and is never taken for the server's complete listing (no removed-tool
alert, no fingerprint report). A clean answer that is not attributable, such as a listing on a resumed
stream (where the SDK rewrites the id to the replayed request's), therefore leaves tools it did not
already vouch for refused until the client lists again, and the outstanding entry it did not take expires
and clears the verdicts. A
`tools/list` whose request carried a `cursor` is a page: it is judged, but a missing tool is not
reported as removed, and on a server's first sighting every page of that listing is a first sighting.

## Usage reporting (CONTRACT C4)

Every `tools/call` that reaches the gate (blocked by policy or not, the way the stdio proxy and the hook
count; a message refused as invalid or during a cool-down never reaches it) is
counted per server label (the route's) **and per tool name** (`params.name`, names only: 1-128 chars of
`[A-Za-z0-9_.:/-]`, anything else is not stored) in `~/.moorai/mcp-usage.json`. It uses the same tally the
hook and proxy use (`cli/mcp-usage-beat.mjs`). A **completed** UTC day is posted once to the console's
`POST /api/mcp-usage` with `path: "gateway"`, `host: "gateway"` and the hook's identity (server mode:
user `service`, device `svc:<serviceId>`):

```json
{ "user": "service", "device": "svc:ci-bot", "platform": "linux", "actor": "h2:…",
  "day": "2026-10-05", "path": "gateway", "host": "gateway",
  "servers": [{ "label": "github", "calls": 4,
                "tools": [{ "name": "create_issue", "calls": 3 }, { "name": "search_code", "calls": 1 }] }] }
```

At most 64 tools per server go in a post (the busiest first, ties broken by name), with
`"toolsTruncated": true` when more were seen. At most 256 are kept per server and day. Days are flushed at
start-up and every 30 minutes, off the request path. An unenrolled gateway counts locally and posts
nothing. Arguments and results never reach the tally or the post.

## Hardening (CONTRACT C5)

### Staged message validation (`--schema enforce|report|off`, default `enforce`)

Every POST body, and every response (JSON or SSE event), goes through these stages. The first failure is
the finding, reported as `SCHEMA_INVALID` with `schemaStage` and `schemaPath`. The path is built from the
schema's own field names and array indices, never from a key or value the peer sent:

| Stage | What is checked | Source |
|---|---|---|
| `json` | strict UTF-8 that parses as JSON; no BOM; no repeated key (anywhere); in an envelope or its `params`, no keys that differ only in case, and no key that differs only in case from a field the gateway reads (`Arguments`, `PARAMS`); nested no deeper than 64 objects / arrays combined (refused in every `--schema` mode) | MCP 2025-06-18 transports: "JSON-RPC messages **MUST** be UTF-8 encoded" |
| `jsonrpc` | an object; `jsonrpc` exactly `"2.0"`; `method` a string; a batch is non-empty | jsonrpc.org/specification: "MUST be exactly "2.0"" |
| `structure` | request id a string or integer, never null; no id on a `notifications/*`; `params` an object; a response has exactly one of `result` / `error`; error code an integer | MCP basic (2025-06-18, 2026-07-28): "Requests **MUST** include a string or integer ID", "the ID **MUST NOT** be `null`", "A response **MUST NOT** set both" |
| `method` | a known request method (either era plus the tasks extension); with `--allow-method`, one on the list | none (gateway policy) |
| `protocolVersion` | `initialize.protocolVersion`, `MCP-Protocol-Version` and the 2026-07-28 `_meta["io.modelcontextprotocol/protocolVersion"]` are `YYYY-MM-DD`; header and `_meta` agree | transports: "If the server receives a request with an invalid or unsupported `MCP-Protocol-Version`, it **MUST** respond with `400 Bad Request`" |
| `schema` | `initialize` params / result, `tools/list` params / result, `tools/call` params / result | MCP lifecycle and tools pages |

Why refuse instead of forward: the gateway gates the body as **it** parses it. A body the upstream parses
differently (invalid UTF-8, a BOM, a trailing comma, a non-object `params`) could otherwise carry a call
past the gate. The checks are lenient where the two eras differ, so valid traffic from both passes.
Nothing is required that one era lacks (`resultType`, or `content` on an MRTR `input_required` result). An
unknown but well-formed protocol version is accepted. `inputSchema` may be an object or a boolean
(2026-07-28 allows "any JSON Schema 2020-12"). An unknown request method is forwarded and reported unless
`--allow-method` is given, because revisions and extensions add methods (`server/discover`,
`subscriptions/listen`, `tasks/*`).

Refusals:

- A `tools/call` with an id gets the gateway's refusal shape (an isError tool result, HTTP 200).
- Any other request with an id gets a JSON-RPC error, `-32700` / `-32600` / `-32601` / `-32602` by stage
  (HTTP 200).
- A body with no usable id (unparseable, a notification, a response) gets HTTP 400 with an id-less error,
  as the transport says for input the server "cannot accept".
- A bad `MCP-Protocol-Version` gets HTTP 400. A header that disagrees with `_meta` gets HTTP 400 / `-32020`.
- A batch with one invalid message is refused whole.

On the server side, only an invalid `tools/call` result is replaced, because a malformed result could
carry text past the result scan (which reads the shape the spec defines). Everything else is reported and
forwarded. Validation applies on an unenrolled device too, as the header-mismatch and 16 MB checks always
have.

### Response size cap (`--max-response-bytes`, default 4 MiB; `0` = off)

A JSON response body, or one SSE event, larger than the cap is not relayed. The request is answered with a
tool error (`tools/call`) or a JSON-RPC `-32603` error, the upstream connection is dropped, and
`RESPONSE_TOO_LARGE` carries `limitBytes`. On an SSE stream for one request, the replacement event keeps
the dropped event's `id:` and the stream ends. On a stream with no single request (a GET stream, a batch)
the event is dropped and the stream goes on. 4 MiB is four times what the result scan reads (1 MB), so
responses between 1 MB and the cap are still forwarded unscanned, as before. SSE event size is counted in
UTF-8 bytes per complete line; an unterminated line is bounded by its length in characters.

### Per-client cool-down (`--cooldown-refusals N`, `--cooldown-window S`, `--cooldown-seconds M`)

After N refusals of one client (policy block, invalid message, profile block) within S seconds (default
60), every JSON-RPC request that client POSTs is refused for M seconds (default 120); notifications,
GET streams and DELETE still pass. `CLIENT_COOLDOWN` carries
`cooldownSeconds` and is posted once per cool-down. Refusals during a cool-down do not extend it, and are
not counted under any key: a client in a cool-down cannot fill the bounded tables (4,096 entries each, the
oldest dropped) with fresh credentials until its own entry is dropped. Tested in process at full scale
(4,097 fresh credentials x 2 refusals through `cooldown.noteRefusal`, the function the gateway calls for
every refusal) and end to end with a small flood (`test/mcp-gateway-review2.test.mjs`); the full
8,192-request flood against a gateway process runs only with `MOORAI_GATEWAY_FLOOD=1`.

It is **off by default**. A client is the route plus a one-way hash of its `Authorization` header when it
sends one (the credential it presents upstream), otherwise the TCP peer address. Because the gateway refuses
before the upstream ever checks that credential, a client could send a new junk `Authorization` on each refused
call; so each distinct refused credential is also counted once against its peer address, and `refusals`
distinct refused credentials from one address cool the whole address down. On the default loopback bind every local client shares 127.0.0.1, so one misbehaving or
prompt-injected agent would cool down every agent on the machine. Turn it on where clients carry their own
`Authorization`, or on a remote bind. The key stays in memory and nothing about it is reported.

### Declared workload profiles

`workloadProfiles` (`cli/workload-profile.mjs`) are evaluated for every `tools/call`, with the tool named
`mcp__<route server label>__<params.name>`. That is exactly the hook's name for the same call, so one
profile (`"tools": ["mcp__github__*"]`, `"mcpServers": ["github"]`) means the same on both surfaces. The
trust rules are the hook's: profiles come only from the verified console policy and the root-owned
machine-wide config (`/etc/moorai/config.json`), never from `~/.moorai/config.json`, a repository file or
an environment variable. `match.serviceId` is server mode's workload name; `match.repo` is the remote of
the gateway's cwd. A `"report"` profile forwards and posts `PROFILE_DRIFT`; `"block"` refuses with the
tool-error shape; an unenrolled device is coached (forwarded, stderr note). Drift kinds here are `tool`
and `mcpServer`. The hook's `host` kind (read from MCP arguments) is not evaluated at the gateway.

### Cost

Measured, not reasoned: 800 sequential clean `tools/call`s through a gateway against the in-process fake
upstream (enrolled, signed policy, engine on; no `workloadProfiles` in it), three runs each, one laptop.
p50 latency added by the gateway: before this work 5.49 / 4.92 / 4.63 ms (median 4.92); with usage
counting, validation, the size cap, the cool-down bookkeeping and the profile check 4.66 / 4.97 / 5.23 ms
(median 4.97). The difference is inside the run-to-run noise. Not measured: a policy with many profiles,
or large bodies.

## Policy semantics: fail-open, report-first (the proxy's)

- **Fail-open** on the gateway's own failure: no engine (no policy and no posture), a thrown check, a
  result scan past `CAPS.resultDeadlineMs` (750 ms), a compressed upstream response other than a
  `tools/list` answer, a response with no request ids, or any response while a `tools/list` is
  outstanding, in `gzip`/`deflate`/`br` (decoded and scanned), a JSON response or
  SSE event between `CAPS.maxLineBytes` (1 MB) and the size cap → forwarded unchanged and unscanned. An
  unparseable client body is refused (`SCHEMA_INVALID`, stage `json`) unless `--schema report|off`. A device whose durable posture is fail-closed gets `OFFLINE_DEFAULT_POLICY` when no policy
  verifies, exactly as in the proxy.
- **Only an explicit deny refuses**, and only on an enforcing device. Unenrolled → coach: forwarded, with
  a note on the gateway's stderr (the operator's log). "ask" (justify) forwards, because no banner exists
  — except in **server mode** (`cli/server-mode.mjs`), where the hook's headless rule settles it: deny,
  unless the system file or the org policy says `allow-with-report`. Server mode also enforces without a
  token and reports under the workload identity, as the hook does.
- The tool listing is report-first and byte-identical, always.
- Not fail-open: a request body over 16 MB is refused (413) rather than forwarded unscanned, because
  forwarding it would let an agent pad its arguments past the scan. So is a batch of more than 64
  messages (413, `-32600`, in every `--schema` mode): its calls are gated one after another without
  yielding to other clients (~3.7 ms each, measured), and a 5,000-call batch held the gateway for 23 s.
  So is a client message nested deeper than 64 objects / arrays combined (`SCHEMA_INVALID`, stage `json`,
  path `$`, in every `--schema` mode, before any scan): the gate serialises the arguments with
  `JSON.stringify`, which throws on deep nesting, and a failing check forwards, so arguments nested
  100,000 levels deep reached the upstream unscanned. Other internal errors still forward.

## Network posture

- Binds **127.0.0.1** by default. Any other address needs `--allow-remote` **and** a gateway token
  (`MOORAI_GATEWAY_TOKEN`, or `--token-file`; never argv), at least 16 characters; otherwise it exits 2
  before listening. Clients then send it in `X-MoorAI-Gateway-Token`, which is stripped before the
  upstream. A token can be set on loopback too.
- On a loopback bind, a request whose `Host` is not a loopback name is refused (403), and so is any
  browser `Origin` that is not loopback or listed with `--allow-origin` — the spec's DNS-rebinding rule.
- `Authorization` is passed through unchanged and never logged; the gateway mints, swaps or stores no
  token. Plain `http://` to a non-loopback upstream is refused unless `--allow-insecure-upstream`, so a
  bearer token does not cross a network in clear because a gateway was put in front of it.
- Upstream URLs are printed as origin + path only — never a query string or userinfo.
- `Accept-Encoding: identity` is sent upstream so the body can be scanned.
- Content-free: alerts go to the console's `/api/alerts` with `tool: "gateway:<tool>"` and
  `mcpServer: "<route label>"`; one audit line per call goes to the local ledger. No argument, result,
  header or URL leaves.

## Run

```bash
# one remote server
node mcp-gateway/moorai-mcp-gateway.mjs --route /github=https://api.githubcopilot.com/mcp/

# several, from a file
node mcp-gateway/moorai-mcp-gateway.mjs --config gateway.json
```

```json
{
  "port": 8848,
  "routes": {
    "/github": { "url": "https://api.githubcopilot.com/mcp/", "server": "github" },
    "/files":  { "url": "https://files.example.com/mcp", "localFiles": true, "roots": ["/Users/me/project"] }
  }
}
```

Then point the client at the route, keeping the headers it sent before, e.g. Claude Code:

```bash
claude mcp add --transport http github http://127.0.0.1:8848/github --header "Authorization: Bearer $GITHUB_PAT"
```

`--help` lists every flag.

## Tests

```bash
node --test --import ./test/hermetic-env.mjs test/mcp-gateway*.test.mjs test/mcp-usage-tools.test.mjs
node --test --import ./test/hermetic-env.mjs test/index-tools-mcp.test.mjs    # vector-store writes, proxy and gateway
```

A real gateway process, a fake remote server in the test process ([`test/fake-upstream.mjs`](test/fake-upstream.mjs),
JSON and SSE modes, SSE written in 5- and 7-byte slices) and a fake console serving a signed policy.

With real MCP clients (opt-in; they must be installed, and no model is called):

```bash
node scripts/mcp-client-matrix.mjs            # every installed client × the stdio guard and this gateway
MOORAI_LIVE_MCP=1 node --test --import ./test/hermetic-env.mjs test/mcp-live-client.test.mjs   # the same, as 17 tests
node scripts/mcp-live-toolcall.mjs            # live tier: prints the plan; --run spends 3 `claude -p` turns
```

The client drivers are in [`test/live/live-clients.mjs`](test/live/live-clients.mjs) and
[`test/live/sdk-client.mjs`](test/live/sdk-client.mjs). Each client runs with a throwaway HOME and project
(under `sandbox-exec` on macOS, localhost egress only); `MOORAI_LIVE_BREAK=bypass|dead|toolscan|no-refusal|no-policy|list-error`
must turn the run red.

## Limits

- **OAuth discovery through the gateway is untested.** A client that runs the authorization flow reads
  the upstream's `WWW-Authenticate` / protected-resource metadata, whose `resource` is the upstream URL,
  not the gateway's; a client that checks the two match may refuse. A static `Authorization` header in
  the client's config works (tested with the fake upstream only).
- The 2026-07-28 `subscriptions/listen` stream and MRTR `InputRequiredResult` pass through and are scanned
  like any other response; neither was exercised against a server that implements them.
- Run against a real remote MCP server (an AppCrane MCP endpoint over Streamable HTTP: initialize, tools/list with 62 tools and a read-only tools/call passed through intact; a malformed message and an over-cap response were refused), with a scripted client; that server issued no session id.
- Run with real MCP client applications against the fake upstream (measured 2026-10-06, macOS). The
  clients are Claude Code 2.1.284 (`claude mcp list`, HTTP transport), cursor-agent (`mcp list-tools`),
  the TypeScript SDK 1.32.1 `Client` over `StreamableHTTPClientTransport`, and the MCP Inspector 2.9.0
  CLI. Each client's own `initialize`, `notifications/initialized`, GET stream and `tools/list` reached the
  upstream through the gateway, and each carried the upstream's `Mcp-Session-Id` and
  `MCP-Protocol-Version` on its later requests. The gateway recorded the relayed `tools/list` in its
  tool-stage baseline.
- With `--allow-method initialize`, the gateway refuses `tools/list` with JSON-RPC -32601, and every client
  shows the refusal: cursor-agent, the SDK and the Inspector print `MoorAI refused this MCP message: …`;
  Claude Code prints `! Connected · tools fetch failed — MoorAI [redacted] this MCP message: …`, because it
  masks the word "refused". The upstream never receives `tools/list`, and the console receives a
  `SCHEMA_INVALID` / `method` / `deny` alert.
- `tools/call` through the gateway: the SDK and the Inspector each made one benign call and one
  policy-denied call. The benign call was forwarded and echoed; the denied one came back as
  `MoorAI blocked this MCP tool call`, and the upstream never received it. Both were counted (path
  `gateway`), and the ledger has `allow` and `deny`. In one live Claude Code run (`claude -p`, Haiku), the
  model's call to `mcp__moorai-http__echo` was forwarded, echoed and recorded `allow`.
- Claude Code 2.1.284 opens with a `server/discover` probe (2026-07-28 era), which the gateway forwards.
  The fake upstream does not answer it as a modern server would, so Claude Code falls back to
  `initialize` (2025 era).
- Still not tested: OAuth discovery through the gateway; a real client and a real remote server in the
  same run, so no session id issued by a real remote server behind a real client; a completed 2026-07-28
  session with a real client; a live model call through the gateway with a policy-denied argument (the
  deny case was run live only through the stdio proxy); a result-stage block seen by a real client;
  Claude Desktop, VS Code and Cursor's desktop app; Windows and Linux.
- Blocking a result cannot undo what the remote tool already did; it keeps the content out of the agent.
- **Parser differentials.** The gateway forwards the client's bytes, not a re-serialisation, so it refuses
  (`SCHEMA_INVALID`, stage `json`, path `$`) a client body that repeats a key in any object, or repeats one
  up to case in a message envelope or its `params`. `JSON.parse` keeps the last of two equal keys; a
  first-wins parser or Go's case-insensitive `encoding/json` would read another. In those two objects a
  key that only differs in case from a field the gateway reads (`jsonrpc`, `id`, `method`, `params`,
  `result`, `error`; `name`, `arguments`, `uri`, `cursor`, `_meta`, `protocolVersion`, `capabilities`,
  `clientInfo`) is refused even alone: to `JSON.parse` a lone `Arguments` is no field, so the gate would
  scan no arguments, while Go's `encoding/json` (measured, go1.26) reads it, `argument\u017f` too, as the
  arguments. Other envelope and `params` fields are not compared. Keys inside `arguments` may differ in
  case; a per-tool argument allow-rule (#18) that names one key can still be satisfied by `path` while a
  case-insensitive tool decoder reads `PATH`. Under `--schema report|off`, a body that fails the json stage is still forwarded,
  and is gated as a lenient decoder reads it (BOM dropped, invalid UTF-8 replaced, the last of repeated
  keys, no case-variant field), so a first-wins or case-insensitive upstream can run what the gate did not
  read. Nesting past 64 levels is refused in these modes too, on the strict reading and the lenient one. A body no UTF-8 decoder can read, for example UTF-16 that Python's `json.loads(bytes)` detects
  on its own, is forwarded ungated in those modes. Every message of a batch must agree with
  `Mcp-Method` / `Mcp-Name` when they are sent. `Mcp-Param-*` headers are not compared with the body, and
  a body on a GET or DELETE is forwarded ungated (the TypeScript SDK 1.32.1 server reads neither).
- **Responses are scanned as the client reads them.** A JSON body that fails strict UTF-8 (a BOM, an
  invalid byte) is reported and scanned as `fetch().json()` decodes it. An SSE event is scanned whatever
  its `event:` type, every message of an array event too. A U+2028 inside a data line and a BOM before
  the first line no longer hide an event from the scan. A UTF-16 response body is not scanned. Of
  repeated or case-variant response keys, the scan reads what `JSON.parse` keeps.
- **Cool-down keys.** No `Authorization` value on a refused call is ever checked upstream, so a client
  that builds its own requests can send a new one every time. Each distinct value is therefore also counted
  once at the TCP peer. N distinct refused credentials from one address within the window cool the whole
  address down, including the clients without `Authorization` there. N refusals of one credential still
  cool only that credential. So one client at an address, with no credential the upstream would accept,
  can cool down every client at that address, credentialed ones included; behind a proxy or NAT that is
  every client. `X-Forwarded-For` and `Mcp-Session-Id` are never part of the key. The tables hold 4,096
  entries each: a client with that many addresses (an IPv6 prefix) can still push other clients' live
  cool-downs out.
  `Mcp-Method` / `Mcp-Name` header-mismatch refusals count as refusals.

## Files

| File | Purpose |
|---|---|
| `moorai-mcp-gateway.mjs` | CLI entry: config, listen, warm the policy, start each route's reputation. |
| `config.mjs` | Flags / JSON config → validated routes; the bind and upstream-scheme rules. |
| `server.mjs` | HTTP reverse proxy: Host / Origin / token checks, header handling, JSON and SSE responses. |
| `guard.mjs` | Per-route gate: call checks, tool-list observation, result scan. |
| `sse.mjs` | Incremental SSE framing that keeps each event's original text. |
| `pending-lists.mjs` | Per-route table of forwarded `tools/list` requests not yet answered, keyed as the SDK matches ids (bounded, with a TTL; an entry dropped unanswered clears the verdicts). |
| `policy.mjs` | Verified policy + engine + coach/enforce, as the proxy loads them. |
| `report.mjs` | Content-free alerts and ledger lines (`gateway:<tool>`). |
| `validate.mjs` | Staged JSON-RPC / MCP validation (C5 `SCHEMA_INVALID`). |
| `cooldown.mjs` | Per-client cool-down (C5 `CLIENT_COOLDOWN`). |
| `profile.mjs` | Declared workload profiles at the gateway (C5 `PROFILE_DRIFT`). |
| `usage.mjs` | Per-server / per-tool usage counts and the completed-day post (C4). |
| `test/fake-upstream.mjs` | Fake remote MCP server for the tests. |
| `test/harness.mjs` | Fake console (alerts and usage posts), throwaway HOME, gateway process, for the newer tests. |
| `test/live/live-clients.mjs` | Real MCP client drivers (Claude Code, cursor-agent, SDK, Inspector), sandbox and judges for the opt-in real-client runs. |
| `test/live/sdk-client.mjs` | The TypeScript SDK client those runs spawn. |
