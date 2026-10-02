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
| client → server | `tools/call` | tool quarantined at list time (policy blocked its metadata) | refused |
| | | server reputation below `mcpReputation.blockBelow` (identity: the upstream URL) | refused on an enforcing device |
| | | `mcpGateway`: server allow-list (#3) → per-tool argument rules (#18) → argument content scan (#2) | per policy |
| | | **local secret egress (#65)** — a value from this machine's `.env*` (gateway cwd), `~/.aws/credentials`, `~/.npmrc`, `~/.netrc`, `.git-credentials` appearing verbatim in the arguments. The hook's check; the stdio proxy does not run it | per policy; the default resolves #65 to block |
| | | **files the arguments name** — only with `--local-files` (or `"localFiles": true` on a route) | per policy |
| | `Mcp-Name` / `Mcp-Method` header ≠ body | header–body consistency | HTTP 400, `-32020` |
| server → client | `tools/list` result | tool stage: #60 poisoning (incl. credential-path descriptions), #50; drift against the shared tool baseline (rug-pull, capability expansion, shadowing) | **never altered**; alert; a blocking policy quarantines the tool |
| | any other result (JSON or each SSE event) | result scan at stage `file` | alert; replaced by a tool error when policy resolves to block |

**File arguments are opt-in** because a remote server never reads the gateway's disk: a path in the
arguments names a file on the *client's* machine only when the gateway runs there too. Relative paths
resolve against the gateway's cwd, then the route's `roots`, then the `file://` roots the client sent
in a (legacy) `roots/list` answer.

**A refused call** gets HTTP 200 with the proxy's shape — a JSON-RPC response with the request's `id` and
`result: { content: [{ type: "text", text: "MoorAI blocked this MCP tool call: …" }], isError: true }` —
not a JSON-RPC `error`, which clients treat as a transport failure. The remote server never receives the
call. A refused **result** is the same shape ("…blocked this MCP tool result…"); in an SSE stream the
replacement event keeps the original's `id:` line, and the notifications before it pass unchanged.

A (2025-03-26) **batch** with one refused call is refused whole, every request in it answered with a
tool error; forwarding part of a batch would answer some ids and not others.

## Policy semantics: fail-open, report-first (the proxy's)

- **Fail-open** on the gateway's own failure: no engine (no policy and no posture), a thrown check, a
  result scan past `CAPS.resultDeadlineMs` (750 ms), an unparseable body, a compressed upstream response,
  a JSON response over `CAPS.maxLineBytes` (1 MB) or an SSE event over 1 MB → forwarded unchanged and
  unscanned. A device whose durable posture is fail-closed gets `OFFLINE_DEFAULT_POLICY` when no policy
  verifies, exactly as in the proxy.
- **Only an explicit deny refuses**, and only on an enforcing device. Unenrolled → coach: forwarded, with
  a note on the gateway's stderr (the operator's log). "ask" (justify) forwards, because no banner exists
  — except in **server mode** (`cli/server-mode.mjs`), where the hook's headless rule settles it: deny,
  unless the system file or the org policy says `allow-with-report`. Server mode also enforces without a
  token and reports under the workload identity, as the hook does.
- The tool listing is report-first and byte-identical, always.
- Not fail-open: a request body over 16 MB is refused (413) rather than forwarded unscanned, because
  forwarding it would let an agent pad its arguments past the scan.

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
node --test --import ./test/hermetic-env.mjs test/mcp-gateway.test.mjs test/mcp-gateway-sse.test.mjs
```

A real gateway process, a fake remote server in the test process ([`test/fake-upstream.mjs`](test/fake-upstream.mjs),
JSON and SSE modes, SSE written in 5- and 7-byte slices) and a fake console serving a signed policy.

## Limits

- **OAuth discovery through the gateway is untested.** A client that runs the authorization flow reads
  the upstream's `WWW-Authenticate` / protected-resource metadata, whose `resource` is the upstream URL,
  not the gateway's; a client that checks the two match may refuse. A static `Authorization` header in
  the client's config works (tested with the fake upstream only).
- The 2026-07-28 `subscriptions/listen` stream and MRTR `InputRequiredResult` pass through and are scanned
  like any other response; neither was exercised against a server that implements them.
- Not tested against a real remote MCP server or a real MCP client, nor on Windows.
- Blocking a result cannot undo what the remote tool already did; it keeps the content out of the agent.

## Files

| File | Purpose |
|---|---|
| `moorai-mcp-gateway.mjs` | CLI entry: config, listen, warm the policy, start each route's reputation. |
| `config.mjs` | Flags / JSON config → validated routes; the bind and upstream-scheme rules. |
| `server.mjs` | HTTP reverse proxy: Host / Origin / token checks, header handling, JSON and SSE responses. |
| `guard.mjs` | Per-route gate: call checks, tool-list observation, result scan. |
| `sse.mjs` | Incremental SSE framing that keeps each event's original text. |
| `policy.mjs` | Verified policy + engine + coach/enforce, as the proxy loads them. |
| `report.mjs` | Content-free alerts and ledger lines (`gateway:<tool>`). |
| `test/fake-upstream.mjs` | Fake remote MCP server for the tests. |
