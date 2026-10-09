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
reports them. The exception is `--credentials`: the agent then holds a placeholder instead of the key, and
the proxy swaps the real key in (see [Placeholder credentials](#placeholder-credentials)).

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

### Exact coverage of tool-call judging

| Traffic | Tool calls judged |
|---|---|
| Anthropic Messages `POST …/messages`, JSON and SSE | yes: client `tool_use` blocks |
| OpenAI Chat Completions `POST …/chat/completions`, JSON and SSE | yes: `tool_calls`, deprecated `function_call` |
| a local OpenAI-compatible server (Ollama, LM Studio, llama.cpp server, vLLM) at its `…/v1/chat/completions`, routed with `--route /local=http://127.0.0.1:<port>/v1` | yes, the Chat Completions parser; tested against a fake only (see [Local models](#local-models)) |
| OpenAI Responses API (`/responses`), Assistants, Realtime | **no** — forwarded unparsed |
| Amazon Bedrock (`InvokeModel`, `Converse`, its event-stream framing), Google Vertex AI / Gemini | **no** — forwarded unparsed |
| Ollama's native `/api/chat` and `/api/generate` (NDJSON) | **no** — forwarded unparsed; use its `/v1` endpoint |
| Anthropic `server_tool_use` / `mcp_tool_use` | **no** — they run at the provider, not in the agent |
| anything the agent sends to a provider **without** going through this proxy (an SDK pinned to the provider URL, a direct HTTPS call, a second key) | **no** |

**This covers only traffic forced through the proxy.** Pointing `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at
it is a convention the agent can ignore. Make it the only way out with egress control (the agent's
network allows the proxy and nothing else), or the judging is advisory, like `moorai-serve`.

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

The mapping is the Python client's ([clients/python](../clients/python/README.md)) for shell, read, write
and fetch tools, and the decision is the same function `moorai-serve`'s `/v1/tool-call` calls
(`runtime.toolCall`). One difference, on purpose: the Python client tells a framework to send "anything
else" as `mcp__<app>__<tool>`; the proxy content-scans it instead. Here the proxy, not the framework, would
be naming a non-MCP function as an MCP tool, and a policy's MCP allow-list or `mcpFloor` would then deny
every unknown function. Passed to `runtime.toolCall` under its own name, an unknown function is not evaluated
at all (`evaluated: false`), so the generic path is the content scan.
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
- **Denied tool call in a non-streaming response:** with `--denied-tool-call refuse` (the default), the
  whole response is refused with the same 403. `--denied-tool-call replace` delivers the turn without its
  tool calls instead (see `--denied-tool-call replace` below). Why the default refuses rather than cut the tool
  call out:
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
- **`--denied-tool-call replace`** (enforce only). The denied call never reaches the agent, and neither does
  any other client tool call of the same turn. They are replaced by one text block, and the response stays
  a valid, complete turn for the SDK:
  - Anthropic: every `tool_use` block of the message is removed and one `text` block takes the first one's
    place: "MoorAI model-proxy withheld this turn's tool call; nothing was run — tool call Bash: denied via
    Bash — #57 Add-ons & Tools — …". `stop_reason` `tool_use` becomes `end_turn`. Streaming: the events
    before the first `tool_use` block are released as they arrive. From that block's `content_block_start`
    to the `message_delta`, the whole rest of the turn is held, then decided together. Allowed: released
    byte-identical. Denied: one `content_block_start` / `text_delta` / `content_block_stop` at that block's
    index, the `message_delta` with `stop_reason: "end_turn"` (usage kept), and `message_stop`. Block
    indexes stay contiguous, so no `tool_use` id is left without its block. Text the model wrote **after**
    a tool call in the same turn is dropped with it.
  - OpenAI: `tool_calls` and `function_call` are removed from every choice. The refusal becomes the
    message's `content` (after any text the model wrote), and `finish_reason` `tool_calls` /
    `function_call` becomes `stop`. Streaming: the held chunks are re-sent without their tool-call deltas
    (a chunk left empty is dropped), the text goes into the delta of the chunk that carries the
    `finish_reason`, and a choice that never sent one gets a final chunk with the text and `stop`. Usage
    chunks and `[DONE]` follow as sent.
  - The refusal names the tool and the engine's reasons, never the arguments. Non-streaming responses
    carry `x-moorai-model-proxy: replaced`.
  - Holding the rest of the turn closes the Anthropic per-block limit above: an allowed call before a
    denied one in the same turn is withheld too. The hold is capped at 1 MiB (`maxEvent`). Past it, the
    turn's calls are decided as over the cap, which is a deny.
  - An upstream that ends inside the held turn still ends in the provider's error event, as in refuse mode.
  - The agent then sees a turn that ended in text: its loop stops there, as it would for any answer.
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
  - an SSE event over 1 MB;
  - a 2xx response on a parsed path that is neither `text/event-stream` nor a JSON object (for example, a
    local server that labels its stream `application/json`). Enforce answers 502 with
    `x-should-retry: false` rather than forward tool calls it could not read.

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

## Placeholder credentials

With `--credentials <file>` (or `MOORAI_MODEL_PROXY_CREDENTIALS`), the agent never holds the real key. It
holds a placeholder such as `moorai-ph:anthropic-prod`. The proxy, running as another user or in its own
container, swaps in the real key only when the request goes to the route the placeholder is bound to. The
same mechanism is in the MCP gateway; the code is [`credentials.mjs`](credentials.mjs) and
[`credential-mask.mjs`](credential-mask.mjs).

```json
{
  "bindings": {
    "moorai-ph:anthropic-prod": { "secret": { "env": "ANTHROPIC_API_KEY" }, "route": "/anthropic",
                                  "upstream": "https://api.anthropic.com", "header": "x-api-key" },
    "moorai-ph:openai-prod":    { "secret": { "file": "/run/secrets/openai" }, "route": "/openai",
                                  "upstream": "https://api.openai.com/v1", "header": "authorization", "scheme": "Bearer" }
  }
}
```

```bash
moorai-model-proxy --credentials /etc/moorai/model-proxy-credentials.json     # proxy side, holds the keys
ANTHROPIC_BASE_URL=http://127.0.0.1:8791/anthropic ANTHROPIC_API_KEY=moorai-ph:anthropic-prod  your-agent
OPENAI_BASE_URL=http://127.0.0.1:8791/openai       OPENAI_API_KEY=moorai-ph:openai-prod        your-agent
```

**Bindings file.** Each key is a placeholder name, `moorai-ph:` plus up to 64 of `A-Z a-z 0-9 . _ -`.

- `secret` is where the key is read, at startup: `{ "env": NAME }` (the proxy's environment) or
  `{ "file": PATH }` (for example, a Kubernetes secret mount; surrounding whitespace is trimmed).
- A literal value (`"secret": "sk-…"` or `{ "value": … }`) is refused. The bindings file would then be a
  second copy of the key, and this is the file that ends up in config management and gets printed when
  debugging. A secret file of its own, mode 0600, does the same job.
- `route` must be one of the proxy's routes. `upstream` must equal that route's upstream exactly (origin
  and path, trailing slash ignored).
- `header` is the header the key goes in. It cannot be one the proxy strips or owns: hop-by-hop headers,
  `Host`, `Content-Length`, `Accept-Encoding`, `X-MoorAI-Proxy-Token`.
- `scheme` (optional), for example `Bearer`: the header is then `<scheme> <key>`.

**The proxy refuses to start** (exit 2) when:

- the bindings file or a secret file is group- or world-writable;
- on POSIX, either file is owned by a user other than the proxy's own or root;
- a binding is malformed or has an unknown key;
- an env var is unset;
- a secret is shorter than 8 or longer than 4096 characters, has a control or non-ASCII character, or is
  itself a placeholder.

Every error names the binding, the env var or the path, never the value. Windows is not checked: its mode
bits come from the read-only attribute, not the ACL.

**Requests.** A header carries a placeholder when its value contains `moorai-ph:` (any letter case).
Refusals happen before the body is read, in the provider's error shape. They are content-free: neither the
placeholder name nor any value is echoed.

| The request | Result |
|---|---|
| `[scheme ]placeholder` in its bound header, on its bound route and upstream | the whole header value is replaced by `[scheme ]key`; forwarded |
| a bound placeholder on another route, even one to the same host | 403 |
| a placeholder in a header it is not bound to | 403 |
| an unknown placeholder, extra text around it, or the wrong scheme | 401 |
| `moorai-ph:` (or `moorai-ph%3A`) in the query string | 400 |
| a credential header sent twice in any letter case (`Authorization` and `authorization`) | 400 |
| a raw key in `Authorization`, `x-api-key`, `api-key`, `x-goog-api-key` or a bound header | forwarded unchanged, one content-free alert per route; **401** with `--require-placeholders` |
| no credential at all | forwarded |

The duplicate rule is enforced on raw headers, the only place it can be seen. Node keeps the first
`Authorization` and silently drops the rest, and joins two `x-api-key` values with `, `. The rule covers
the four header names above, every bound header, and any header that carries a placeholder. The swap is
applied after the hop-by-hop strip, so a swapped value is never dropped.

**Responses.** Every upstream response is masked for every bound secret, on every route, whether or not
this request was swapped:

- A verbatim copy of a secret in a header, the status line or the body becomes `*` of the same length,
  so `Content-Length` stays right.
- The body is masked across chunk boundaries. At the end of a chunk, only a tail that is a prefix of a
  secret is held back, so an SSE event ending in `\n\n` is not delayed.
- A gzip, deflate or br body is decoded first, and `Content-Encoding` is dropped. Any other content coding
  is answered 502: it cannot be checked for an echo.
- The proxy follows no redirect. A `Location` is masked like any other header.

**Alerts.** A raw key is reported once per route as `Model proxy: raw credential sent where placeholders
are configured` (`notify`), or `… refused (placeholders required)` (`deny`). The tool is
`model-proxy:credential:<route>`. No header name, value or hash is included.

**What this does not protect. These limits are exact:**

- **Only keys used through this proxy (and the MCP gateway).** A key the agent can use on any other path
  is not protected. That includes a direct HTTPS call, an SDK pinned to the provider URL, or another tool
  holding its own key. Pair this with egress control.
- **A key the agent can read itself is not protected.** That includes a `.env` file, its own environment,
  a config file, or this proxy's secret file or environment. If the proxy runs as the agent's user, the
  agent can read `/proc/<pid>/environ` or the secret file, and placeholders give no isolation at all. Run
  the proxy as another user or in another container, with secret sources the agent cannot read.
- **The agent can still use the placeholder through the proxy.** Whatever the key allows on its bound
  route, the agent can do. The placeholder only stops the key itself from leaving. Policy (`--mode
  enforce`) decides what requests go through; nothing here limits cost or rate.
- **Masking only catches a verbatim echo.** A secret that is split across SSE events, JSON-escaped,
  encoded, or echoed in part (an `sk-…abcd` hint) passes. The bound upstream is trusted with the key by
  definition. A model never receives the request headers, so it has no key to echo.
- **The masking hold-back is a timing signal.** The tail of a chunk that matches a secret's prefix is held
  until the next chunk. An observer who controls chunking could, in principle, time it. Not measured.
- **No constant-time compare is needed, because none is made.** A placeholder is resolved by a map lookup
  on its name, which is not derived from a secret. Client input is never compared with a secret. Masking
  searches upstream response bytes.
- **Secrets are read once, at startup.** Rotating one means restarting the proxy.
- **A placeholder in a request body** (a prompt) is neither swapped nor refused: it is not a credential
  there.

## Local models

An OpenAI-compatible local server works with a route to its loopback URL. Plain `http://` is allowed
without `--allow-insecure-upstream` because the upstream is loopback (`127.0.0.1`, `localhost`, `[::1]`).
`--route` replaces the default routes, so list every route you need:

```bash
moorai-model-proxy --mode enforce --denied-tool-call replace \
  --route /openai=https://api.openai.com/v1 --route /ollama=http://127.0.0.1:11434/v1
OPENAI_BASE_URL=http://127.0.0.1:8791/ollama  your-agent        # Ollama's OpenAI-compatible endpoint
```

The same applies to LM Studio (`http://127.0.0.1:1234/v1`), llama.cpp server (`http://127.0.0.1:8080/v1`)
and vLLM (`http://127.0.0.1:8000/v1`). These ports are the projects' documented defaults, not tested here.

Tested against a fake local server only: no auth header, the request path under `/v1`, and a whole tool call
(id, name, all its arguments, `finish_reason`) in one chunk as well as a call fragmented across chunks. Not
tested against a real Ollama, LM Studio, llama.cpp or vLLM build. Their native APIs (Ollama `/api/chat`)
are not parsed. From reading the code, not from a test: a server that streams several tool-call deltas
with no `index` gets them merged into one call, whose arguments then fail to parse, which enforce mode denies
rather than misreads.

## Skip alert

`moorai-serve`'s `/v1/tool-call` only judges a call if the framework asks. The proxy sees every call the
model returns. With `--unchecked-window-ms <ms>` (off by default), it alerts on a tool call it forwarded that
no framework check matched within that window.

```bash
moorai-model-proxy --unchecked-window-ms 30000                          # sidecar 1
moorai-serve --model-proxy-url http://127.0.0.1:8791                    # sidecar 2, same pod
# the framework passes the model's call id with each check:
#   POST /v1/tool-call {"tool": "Bash", "input": {...}, "toolCallId": "toolu_…"}
#   Python: moorai.tool_call("Bash", {...}, tool_call_id=call["id"])
```

- **The proxy records** an HMAC of each tool call id it forwards, under a random per-process key, never the
  id itself. Enforce mode records a call once it is allowed. A withheld call never reached the agent and is
  not recorded. Report mode records every call.
- **`moorai-serve` passes** the `toolCallId` of each check it answered to the proxy over loopback:
  `POST /moorai/v1/tool-call-checked {"toolCallIds": [...]}`, batched (up to 256 per request, 4096 waiting,
  one request in flight, 1.5 s timeout), with `X-MoorAI-Proxy-Token` from `--model-proxy-token-file` or
  `MOORAI_MODEL_PROXY_TOKEN` when the proxy has a token. The endpoint exists only while the skip alert is on,
  takes only `application/json`, and answers how many ids it took, never whether one was known.
- **Why a loopback call, not a shared file.** Sidecars in one pod share the network namespace, so loopback
  needs no extra volume, no shared HMAC key and no file permissions across containers. The proxy keeps all
  the state, and `moorai-serve` only forwards ids it was given. Shared files would have to hold a common key
  (or plain ids) on a volume that both containers, and possibly the agent's, can write.
- **The alert** is `Model proxy: tool call forwarded with no framework check`, decision `notify`,
  `OBSERVATION_ONLY`, `tool: "model-proxy:<the tool name the model used>"`, with `count` and `windowMs`.
  There is one alert per tool name per sweep, at most 32 names per sweep, and the rest are folded into
  `other`. No id, argument or hash of either is sent.
- **A check may arrive first.** In report mode, the bytes reach the agent before the proxy has parsed them,
  so a check can arrive before the record. It is kept for one window and matched when the record lands.
- **Bounded.** At most `--unchecked-max` entries (default 8192), pending records and early checks together.
  At capacity the oldest entry is dropped. A dropped record is counted in one `Model proxy:
  unchecked-tool-call tracking at capacity` alert (`UNEVALUATED`) per sweep and is never reported as
  unchecked. The sweep runs every quarter window (at least 50 ms, at most 5 s).
- **What it does not prove.** It detects a framework that forgot to check, not one that lies. Anything on
  loopback that holds the proxy token can mark an id as checked: the agent can, by calling `/v1/tool-call`
  with the id and harmless arguments. The proxy's own verdict, in enforce mode, is what stands between the
  model and the tool. A lost batch (`moorai-serve` restarted, proxy busy) costs a false alert, never a
  verdict. Both processes keep their state in memory, so a restart forgets it.

## Tests

```bash
node --test --import ./test/hermetic-env.mjs test/model-proxy.test.mjs test/model-proxy-enforce.test.mjs test/model-proxy-credentials.test.mjs \
  test/model-proxy-toolcall.test.mjs test/model-proxy-toolcall-local.test.mjs test/serve-unchecked.test.mjs
```

Latency the judging adds, measured on an M-series Mac, node, no console, built-in rules:

- One decision (`checker.checkToolCalls`, one call, n=300): p50 1.3 ms for an allowed `Bash ls -la`, 3.1 ms
  for a denied `curl … | sh`, and 1.5–1.6 ms for `Read`, `run_shell`→`Bash` and a content-scanned unknown
  function. p95 is at most 4.5 ms.
- End to end, a streamed turn with one allowed tool call, enforce/replace minus report mode, paired, n=150:
  p50 1.5 ms (Anthropic and OpenAI), p95 2.0 ms. This is the hold plus the decision. Report mode adds
  nothing to the stream; its check runs after the response has been sent.

The tests run the real CLI against a fake provider (`model-proxy/test/fake-provider.mjs`, SSE written in
5-byte slices) and a fake console. No real provider or key is used.
