# MoorAI model proxy

`moorai-model-proxy` is a loopback HTTP proxy that sits between an agent's model SDK and the model
provider. The agent points its SDK's base URL at the proxy. The proxy forwards each call to the real
provider and runs MoorAI's engine on what goes out and what comes back. It uses the same runtime as
`moorai-serve` (`packages/agent-sdk/src/runtime.mjs`), so verdicts are the sidecar's, under the same
server-mode rules.

```
agent SDK ──http──▶ 127.0.0.1:8791/anthropic/v1/messages ──https──▶ api.anthropic.com/v1/messages
          ──http──▶ 127.0.0.1:8791/openai/chat/completions ──https──▶ api.openai.com/v1/chat/completions
```

```bash
moorai-model-proxy                       # report-only, default routes
ANTHROPIC_BASE_URL=http://127.0.0.1:8791/anthropic  your-agent
OPENAI_BASE_URL=http://127.0.0.1:8791/openai        your-agent
```

The client's own API key goes upstream untouched. That covers `x-api-key`, `Authorization`,
`anthropic-version`, `anthropic-beta` and `OpenAI-Organization`. The proxy never reads, stores, logs or
reports them.

## Provider APIs it parses

These are the documented shapes the code is built against (read 2026-10-06):

- **Anthropic Messages**, `POST …/messages` ([messages](https://platform.claude.com/docs/en/api/messages),
  [streaming](https://platform.claude.com/docs/en/build-with-claude/streaming),
  [errors](https://platform.claude.com/docs/en/api/errors)).
  - Event flow: `message_start`, then for each block `content_block_start` → `content_block_delta`… →
    `content_block_stop`, then `message_delta`, then `message_stop`, with "any number of `ping` events".
  - A `tool_use` input arrives as `input_json_delta` "*partial JSON strings*". The docs say to "parse the
    JSON once you receive a `content_block_stop` event".
  - Errors look like `{"type":"error","error":{"type","message"}}`. Mid-stream, an error is
    `event: error` with the same body.
- **OpenAI Chat Completions**, `POST …/chat/completions`, from the official OpenAPI description
  (github.com/openai/openai-openapi). platform.openai.com refuses non-browser fetches.
  - Streaming is "data-only server-sent events … terminated by a `data: [DONE]` message".
  - Tool calls arrive as `delta.tool_calls[]` `{index, id, type, function: {name, arguments}}`, with
    `arguments` in fragments. A choice ends at its `finish_reason`.
  - Errors look like `{error: {message, type, param, code}}`.

Any other path or method (`/v1/models`, `count_tokens`, embeddings, the OpenAI Responses API, Bedrock,
Vertex) is **forwarded unparsed and unchecked**.

## What it checks

Each direction is checked as follows.

**Requests (agent → model).** The proxy scans each new piece of content. Prompt and system text is
scanned at stage `prompt` (for example, secrets leaving in prompts). A tool result or document the agent
feeds back (Anthropic `tool_result` or text `document`, OpenAI `role: "tool"`) is scanned at stage
`output` with `inbound: true`, the Agent SDK's PostToolUse scan. That is where indirect injection shows
up.

- **Repeats are scanned once.** Conversations are re-sent every turn, so each item is scanned once. A
  bounded LRU, keyed by a per-process HMAC, maps each item to its verdict.
- **Not scanned:** assistant turns, images, base64 PDFs, and the `tools` definitions.

**Responses (model → agent).** Each tool call the model asks for is decided like `/v1/tool-call`. The
proxy maps the tool name to the hook's vocabulary:

| Model's tool | Decided as |
|---|---|
| `Bash`, `Read`, `Write`, `Edit`, `WebFetch`, `Task`, `mcp__*` … | as named |
| Anthropic `bash`, any shell-named function with `command`/`cmd` | `Bash` (`PowerShell` for pwsh names) |
| Anthropic `str_replace_based_edit_tool` | `view`→`Read`, `create`→`Write`, `str_replace`/`insert`→`Edit` |
| read/write-named function with a `path` | `Read` / `Write` |
| fetch/web-named function with a `url` | `WebFetch` |
| anything else | argument text content-scanned at stage `prompt` |
| arguments that are not a JSON object (for example, invalid JSON) | content-scanned; **refused in enforce mode** |

Server-side tool blocks (`server_tool_use`, `mcp_tool_use`) are not checked: they run at the provider,
not in the agent. File contents are read from the proxy's own filesystem, resolved against `--cwd`. If
the proxy does not share the agent's filesystem, only path names are checked.

## Report vs enforce

**`--mode report` (default)** changes nothing in the traffic:

- Bytes are forwarded as received, and streaming is fully pass-through.
- Checks run after the response has been sent, so they never sit between the provider and the agent.
- An alert whose configured outcome would block is stamped `enforcement: LIMITED`.
- An "ask" is reported as configured.

**`--mode enforce`** refuses. It applies server mode's headless rule: an ask with no approver becomes a
deny, unless the system file or the org policy says `allow-with-report`.

- **Denied request:** HTTP 403 in the provider's error shape. The provider never receives the request.
  - Anthropic: `permission_error`.
  - OpenAI: `code: "moorai_policy_denied"`.
  - Neither SDK retries a 403.
- **Denied tool call in a non-streaming response:** the whole response is refused with the same 403.
  Why refuse rather than cut the tool call out:
  - Removing a `tool_use` means rewriting `stop_reason` and the turn the agent stores. It would still run
    any sibling calls from the same, now-suspect, turn.
  - A refusal is a typed error that both SDKs already raise. Nothing from that turn runs.
- **Streaming:** events are released as they arrive. When a tool call starts, its events are held until
  it is complete, then decided:
  - Anthropic: held from `content_block_start` (`tool_use`) to its `content_block_stop`.
  - OpenAI: held from the first `tool_calls` delta until every choice that started a tool call has sent
    its `finish_reason`.
  - Allowed: the held events are released byte-identical.
  - Denied: the stream ends with the provider's error event. Anthropic gets `event: error` with a
    `permission_error` body. OpenAI gets a `data:` chunk with `error`, which openai-node turns into an
    `APIError`.
  - Text sent before the tool call has already reached the agent.
  - An upstream that ends inside a held tool call: the stream ends with the error event, and the unfinished
    tool call is never released.
  - **Limit (Anthropic):** holding is per content block. If a turn has an allowed tool call followed by a
    denied one, the allowed call's block has already been released when the denied one ends the stream.
    The turn never completes (no `message_delta` / `message_stop`), and both SDKs raise the error, but a
    client that runs each `tool_use` block as soon as it closes, before the message ends, runs the allowed
    call. OpenAI holds every call of a choice until its `finish_reason`, so neither is released there.
- **Tool-call arguments that are not a JSON object** (for example, invalid JSON) are refused in enforce
  mode, streaming or not: the tool decision (hook branch, workload profile) cannot be made on them, and an
  SDK may still parse them leniently and run the call. Report mode content-scans and forwards them.
- **The provider dropping the connection** before its response ends:
  - Non-streaming: HTTP 502 in the provider's error shape (Anthropic `api_error`, OpenAI `server_error`)
    with `x-should-retry: false`. Both SDKs obey that header before their own rule of retrying 408, 409,
    429 and any status of 500 or more.
  - Streaming: no status can be sent any more, so the stream ends with the same 502-class error event
    ("the upstream closed inside a tool call; it was not released" when a call was held). The SDKs raise
    a mid-stream error event as an `APIError` and do not retry it.
  - The evaluation budget running out is the only case answered as retryable (Anthropic 529
    `overloaded_error`, OpenAI 503).
- **Content the proxy did not fully evaluate** is refused in enforce mode and reported as
  `UNEVALUATED_SIZE_CAP` in report mode. That covers:
  - more than `--max-scan-items` new items in one request;
  - an item longer than `--max-scan-chars`;
  - tool-call arguments over the 1 MB hold cap;
  - content-scanned tool-call arguments (a function with no hook branch, or arguments that are not valid
    JSON) longer than `--max-scan-chars`;
  - a compressed response;
  - an SSE event over 1 MB.

  Scanning the overflow in chunks instead would not be bounded: about 100 ms of blocked event loop per
  512 K characters (measured), or about 6 s for a 32 MB body.

## Network posture and limits

These follow moorai-serve and the MCP gateway:

- **Loopback by default.** Any other bind needs `--allow-remote` and a token of at least 16 characters
  (`--token-file` or `MOORAI_MODEL_PROXY_TOKEN`). Clients send it as `X-MoorAI-Proxy-Token`, and the proxy
  strips it before the upstream. It cannot be `Authorization`, because that header belongs to the
  provider.
- **DNS rebinding.** On a loopback bind, a non-loopback `Host` gets 421. A browser `Origin` that is not
  loopback, and not listed with `--allow-origin`, gets 403.
- **TLS.** The agent talks plain `http://127.0.0.1` to the proxy, and the proxy talks HTTPS to the
  provider. Plain `http://` to a non-loopback upstream is refused unless `--allow-insecure-upstream`. The
  proxy does not intercept TLS, so an SDK pinned to `https://api.anthropic.com` bypasses it.
- **`Accept-Encoding: identity`** is sent upstream so responses can be parsed.
- **Memory is bounded:**
  - request body cap `--max-body`: 32 MiB, Anthropic's documented limit; 413 over it;
  - non-streaming inspection cap `--max-response`: 32 MiB;
  - in-flight buffering budget `--max-inflight`: 256 MiB; over it, a retryable 529 or 503;
  - one pending SSE event: 1 MiB;
  - dedup cache: 4096 entries.

  The single event loop scans about 2 KB in 10 ms, which caps report-mode throughput, not latency.
- **Alerts are content-free.** They use surface `model-proxy` and `tool: "model-proxy:<kind or tool>"`,
  with existing reason codes (`DETECTOR_MATCH`, `UNEVALUATED_SIZE_CAP`, `HEADLESS_ASK` …). No text,
  argument, header or URL is included. The `--log` line is method, path without query, status and time.

## Tests

```bash
node --test --import ./test/hermetic-env.mjs test/model-proxy.test.mjs test/model-proxy-enforce.test.mjs
```

The tests run the real CLI against a fake provider (`model-proxy/test/fake-provider.mjs`, SSE written in
5-byte slices) and a fake console. No real provider or key is used.
