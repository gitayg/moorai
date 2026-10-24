# MoorAI model proxy

`moorai-model-proxy` is a loopback HTTP proxy that sits between an agent's model SDK and the model
provider. The agent points its SDK's base URL at the proxy. The proxy forwards each call to the real
provider and runs MoorAI's engine on what goes out and what comes back. It uses the same runtime as
`moorai-serve` (`packages/agent-sdk/src/runtime.mjs`), so verdicts are the sidecar's, under the same
server-mode rules.

```
agent SDK ──http──▶ 127.0.0.1:8791/anthropic/v1/messages ──https──▶ api.anthropic.com/v1/messages
          ──http──▶ 127.0.0.1:8791/openai/chat/completions ──https──▶ api.openai.com/v1/chat/completions
          ──http──▶ 127.0.0.1:8791/gemini/v1beta/models/<m>:generateContent ──https──▶ generativelanguage.googleapis.com/…
          ──http──▶ 127.0.0.1:8791/ollama/api/chat ──http──▶ 127.0.0.1:11434/api/chat   (Ollama, loopback)
```

```bash
moorai-model-proxy                       # report-only, default routes
ANTHROPIC_BASE_URL=http://127.0.0.1:8791/anthropic  your-agent
OPENAI_BASE_URL=http://127.0.0.1:8791/openai        your-agent
GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8791/gemini your-agent   # read by the Google Gen AI SDKs (JS and Python)
OLLAMA_HOST=http://127.0.0.1:8791/ollama            your-agent   # read by ollama-python; ollama-js: new Ollama({ host })
```

The default routes are:

| Route | Upstream | Client base URL |
|---|---|---|
| `/anthropic` | `https://api.anthropic.com` | `ANTHROPIC_BASE_URL=http://127.0.0.1:8791/anthropic` |
| `/openai` | `https://api.openai.com/v1` | `OPENAI_BASE_URL=http://127.0.0.1:8791/openai` |
| `/gemini` | `https://generativelanguage.googleapis.com` | `GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8791/gemini`, or the SDK's `httpOptions.baseUrl` (JS) / `http_options.base_url` (Python) |
| `/ollama` | `http://127.0.0.1:11434` (Ollama's documented default address), **loopback bind only** | `OLLAMA_HOST=http://127.0.0.1:8791/ollama` (ollama-python reads it; both official clients keep the path), or ollama-js `new Ollama({ host })` |

**Why `/ollama` is a default, and only on a loopback bind.** Ollama is the common local model server and
its default address is fixed (`127.0.0.1:11434`), so the default makes `OLLAMA_HOST=…/ollama` work with no
flags, as `/gemini` does for the Gemini SDKs. Plain `http://` is fine: the upstream is loopback. Ollama's
API has no authentication, though, and every path the proxy does not parse is forwarded, model management
included (`/api/pull`, `/api/delete`, `/api/create`, `/api/push`). On a non-loopback bind (`--allow-remote`)
the default would hand those to every token holder, so it is dropped there; an explicit
`--route /ollama=http://127.0.0.1:11434` keeps it. Ollama on another port or host is a `--route`.

A Gemini client keeps its own API version in the path: with base URL `http://127.0.0.1:8791/gemini` it calls
`/gemini/v1beta/models/<model>:generateContent`, which goes upstream as
`https://generativelanguage.googleapis.com/v1beta/models/<model>:generateContent`, query string unchanged.
`--route` replaces all the defaults, so a command line with any `--route` lists every route it needs.

The Gemini parser is chosen by the request path (`…/models/<model>:generateContent`), not by the route, so
any route whose upstream speaks that method is parsed: the Gemini API, a Vertex AI regional or global
endpoint (`--route /vertex=https://us-central1-aiplatform.googleapis.com`, then the SDK's `httpOptions.baseUrl`
or `GOOGLE_VERTEX_BASE_URL`), or a gateway in front of either.

The client's own API key goes upstream untouched. That covers `x-api-key`, `Authorization`,
`anthropic-version`, `anthropic-beta`, `OpenAI-Organization` and `x-goog-api-key`. The proxy never reads, stores, logs or
reports them. The exception is `--credentials`: the agent then holds a placeholder instead of the key, and
the proxy swaps the real key in (see [Placeholder credentials](#placeholder-credentials)). The other
exception is `traceparent` and `tracestate`, which carry this hop's trace (see [Trace context](#trace-context)).

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
- **Google Gemini `generateContent` / `streamGenerateContent`**, `POST …/{models|tunedModels|endpoints}/<id>:generateContent`
  and `…:streamGenerateContent` ([API reference](https://ai.google.dev/api/generate-content),
  [function calling](https://ai.google.dev/gemini-api/docs/generate-content/function-calling), Vertex AI
  [`streamGenerateContent`](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/projects.locations.publishers.models/streamGenerateContent),
  read 2026-10-09). Code: [`gemini.mjs`](gemini.mjs), [`gemini-replace.mjs`](gemini-replace.mjs).
  - Request: `contents[]` of `Content` `{role, parts[]}`, role "*Must be either 'user' or 'model'*", and
    `systemInstruction`. A `Part` is a union of `text`, `inlineData`, `functionCall`, `functionResponse`,
    `fileData`, `executableCode`, `codeExecutionResult`, `toolCall` and `toolResponse`. Both camelCase and
    snake_case field names are read (proto-JSON accepts both; the Python SDK sends snake_case).
  - Response: `GenerateContentResponse` `{candidates[], promptFeedback, usageMetadata, modelVersion,
    responseId}`; a client tool call is a `functionCall` part `{id, name, args}`, args "*in JSON object
    format*". "*Gemini 3 now always returns a unique `id` with every `functionCall`*." `toolCall` is "*A
    predicted server-side `ToolCall` … The client is NOT expected to execute this*": not decided, like
    `executableCode`, which the provider runs.
  - Stream: "*the response body contains a stream of `GenerateContentResponse` instances*". The Google Gen
    AI SDKs always add `alt=sse` (js-genai `src/_api_client.ts`), so each instance is one `data:` event.
    Without `alt=sse` the body is one JSON array. There is no terminator event: the candidate's last chunk
    carries its `finishReason`, and the connection closes.
  - Vertex AI only, opt-in (`streamFunctionCallArguments`): a call's arguments arrive as `partialArgs`
    pieces with `willContinue`. The field "*is not supported in Gemini API*" (Gen AI SDK type docs), and no
    rule for assembling the pieces is documented.
  - Errors: `{error: {code, message, status}}` (google.rpc `Status`). Mid-stream there is no documented
    error event. The Python SDK reads a bare JSON object "*line by line*" and raises `APIError` on one that
    starts `{"error":`; the JS SDK raises `ApiError` on a read chunk that parses as an object with `error`
    (`code` 400–599), and raises "*Incomplete JSON segment at the end*" on a stream that ends mid-segment.
  - Contradiction, noted: ai.google.dev's [API errors](https://ai.google.dev/gemini-api/docs/api-errors)
    page documents `{error: {code: "<snake_case>", message}}` and SSE `error` events. That page is about the
    Interactions API. Both SDKs read a numeric `code` on `generateContent`, so the proxy sends that.

- **Ollama native API**, `POST …/api/chat` and `POST …/api/generate`, on any route
  ([docs/api.md](https://github.com/ollama/ollama/blob/main/docs/api.md),
  [streaming](https://github.com/ollama/ollama/blob/main/docs/api/streaming.mdx),
  [errors](https://github.com/ollama/ollama/blob/main/docs/api/errors.mdx), read 2026-10-12; and Ollama
  0.15.6 measured on loopback). Code: [`ollama.mjs`](ollama.mjs), [`ollama-replace.mjs`](ollama-replace.mjs),
  [`ndjson.mjs`](ndjson.mjs).
  - Request, `/api/chat`: `messages[]` with `role` "*either `system`, `user`, `assistant`, or `tool`*" and
    `content`; a `tool` message (with `tool_name`) is a tool's result fed back. `tools` is the definitions.
    `/api/generate`: `prompt`, `suffix`, `system` and `template`; it has no `tools`.
  - Response, `/api/chat`: `message.tool_calls[]` `{function: {name, arguments}}`, where `arguments` is a
    JSON **object** (`{"city": "Tokyo"}` in every documented example), not a string. Ollama 0.15.6 also
    sends `id` and `function.index` (measured), and the id is read when present. A string `arguments` is
    parsed as JSON; anything else is unparsed arguments (refused in enforce mode). `/api/generate`:
    `response`, the generated text.
  - Stream: "*Certain API endpoints stream responses by default … newline-delimited JSON format (i.e. the
    `application/x-ndjson` content type)*"; `/api/chat` and `/api/generate` do, and `"stream": false`
    returns one `application/json` object. The last object has `done: true`. A streamed tool call arrives
    whole, arguments included, in a `done: false` line (docs example "*Chat request (Streaming with
    tools)*", and measured).
  - Errors: `{"error": "<message>"}` with the HTTP status. "*If an error occurs mid-stream, the error will
    be returned as an object in the `application/x-ndjson` format with an `error` property*". Both official
    clients raise on such a line (ollama-python `_client.py`: `if err := part.get('error'): raise
    ResponseError(err)`; ollama-js `src/utils.ts`: `if ('error' in message) throw new Error(message.error)`).

- **OpenAI Responses API** `POST …/responses` ([`openai-responses.mjs`](openai-responses.mjs), from the
  official SDK's types, openai-node `src/resources/responses/responses.ts`): request `instructions`, `input`
  (a string, or items: messages of role user / system / developer with `input_text` parts;
  `function_call_output`, `custom_tool_call_output`, `local_shell_call_output` ("A JSON string of the
  output"), `shell_call_output` (its `stdout` / `stderr`) and `apply_patch_call_output` fed back) are
  scanned; the model's own earlier items are not, and `computer_call_output` is a screenshot, not text.
  Response `output[]` items `function_call` ("A JSON string of the arguments to pass to the function"),
  `custom_tool_call` (free-text `input`) and `mcp_approval_request` (named `mcp__<server_label>__<name>`)
  are decided, and so are the built-in tools the client runs: `local_shell_call` ("A tool call to run a
  command on the local shell"; `action.command` is an argv list, `action.env` its environment) as `Bash`
  with the env assignments and the argv joined by spaces; `shell_call` (`action.commands`, decided whatever
  its `environment`) as `Bash` with the commands joined by newlines; `apply_patch_call` (`operation` with
  `path` and `diff`) as `Write` for `create_file` (content: the diff) and `delete_file` (empty content) and
  as `Edit` for `update_file` (new_string: the diff); `computer_call` (`action` / `actions`) under the name
  `computer`, its action JSON content-scanned (no hook tool reads clicks and keys, so a workload profile's
  tool list does not restrict it). A shell call without a list of command strings, or a patch operation
  other than those three, is kept raw and refused in enforce mode. Stream: `event: <type>` SSE; a call
  appears in `response.output_item.added` / `.done`, `response.function_call_arguments.delta` / `.done`,
  `response.custom_tool_call_input.delta` / `.done`, `response.shell_call_command.added` / `.delta` /
  `.done` (`output_index`, `command_index`; the commands are rebuilt from these and decided too) and the
  terminal `response.completed` /
  `.incomplete` / `.failed`. Every reading is decided; a denied call ends the stream with an `error` event
  (ResponseErrorEvent: `{ type: "error", code, message, param, sequence_number }`).
- **OpenAI embeddings** `POST …/embeddings` ([`openai-embeddings.mjs`](openai-embeddings.mjs)): string inputs
  ("Input text to embed, encoded as a string or array of tokens") are scanned as prompt content; token ids
  are not.

Any other path or method (`/v1/models`, `count_tokens`, `GET …/responses/{id}`, Bedrock,
Gemini's Interactions API, `countTokens`, `embedContent`, batch, cached contents, Ollama's `/api/tags`,
`/api/show`, `/api/embed`, `/api/pull` and the rest of its model management) is **forwarded unparsed and
unchecked**.

### Exact coverage of tool-call judging

| Traffic | Tool calls judged |
|---|---|
| Anthropic Messages `POST …/messages`, JSON and SSE | yes: client `tool_use` blocks |
| OpenAI Chat Completions `POST …/chat/completions`, JSON and SSE | yes: `tool_calls`, deprecated `function_call` |
| a local OpenAI-compatible server (Ollama, LM Studio, llama.cpp server, vLLM) at its `…/v1/chat/completions`, routed with `--route /local=http://127.0.0.1:<port>/v1` | yes, the Chat Completions parser; tested against a fake only (see [Local models](#local-models)) |
| OpenAI Responses API `POST …/responses`, JSON and SSE | yes: `function_call`, `custom_tool_call`, `mcp_approval_request`, and the client-run `local_shell_call`, `shell_call` (as `Bash`), `apply_patch_call` (as `Write` / `Edit`) and `computer_call` (content-scanned); tested against a fake provider and with the official OpenAI Node SDK 4.104.0 against that fake (allowed stream intact; denied call raised `PermissionDeniedError` / `APIError`); the client-run built-in tools against the fake provider only |
| OpenAI Responses API server-run items (`mcp_call`, `web_search_call`, `code_interpreter_call`), `GET …/responses/{id}` (background mode), Assistants, Realtime | **no** — they run at the provider, or are not parsed |
| OpenAI embeddings `POST …/embeddings` | no tool calls exist; string inputs are scanned |
| Gemini API `POST …/models/<m>:generateContent` and `:streamGenerateContent`, JSON, JSON array (no `alt=sse`) and SSE (`alt=sse`) | yes: `functionCall` parts; tested against a fake upstream only |
| Vertex AI `…/publishers/google/models/<m>:generateContent` / `:streamGenerateContent` (and tuned `…/endpoints/<id>:…`) | yes, the same parser: the documented request fields and response type are the Gemini API's; tested against a fake upstream only |
| Vertex AI streamed `partialArgs` (`streamFunctionCallArguments`) | judged as unparsed arguments: content-scanned, **refused in enforce mode** |
| Gemini `toolCall` / `executableCode` parts | **no** — they run at the provider, not in the agent |
| Gemini Interactions API (`/v1beta/interactions`), Live API (WebSocket `BidiGenerateContent`), batch, `cachedContents`, `countTokens`, `embedContent`; Vertex partner models (`:rawPredict`, `:streamRawPredict`) | **no** — not parsed |
| Gemini's OpenAI-compatible endpoint (`…/v1beta/openai/chat/completions`) | by path, the Chat Completions parser; not tested |
| `alt=proto` / protobuf bodies on a Gemini path | a response is refused in enforce mode (not JSON or SSE) and reported unevaluated in report mode; a protobuf **request** is forwarded unscanned |
| Amazon Bedrock (`InvokeModel`, `Converse`, its event-stream framing) | **no** — forwarded unparsed |
| Ollama's native `POST …/api/chat`, JSON (`"stream": false`) and NDJSON (the default) | yes: `message.tool_calls`; tested against a fake upstream and live against Ollama 0.15.6 with `mistral-nemo` |
| Ollama's native `POST …/api/generate` | no tool calls exist; `prompt` / `system` / `suffix` / `template` are scanned like any prompt, and the generated `response` text is scanned by every detector **report-only** (alerted, never withheld) besides the [reply text scan](#reply-text-scanning) |
| Anthropic `server_tool_use` / `mcp_tool_use` | **no** — they run at the provider, not in the agent |
| anything the agent sends to a provider **without** going through this proxy (an SDK pinned to the provider URL, a direct HTTPS call, a second key) | **no** |

**This covers only traffic forced through the proxy.** Pointing `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at
it is a convention the agent can ignore. Make it the only way out with egress control (the agent's
network allows the proxy and nothing else), or the judging is advisory, like `moorai-serve`.

## What it checks

Each direction is checked as follows.

**Requests (agent → model).** The proxy scans each new piece of content. Prompt and system text is
scanned at stage `prompt` (for example, secrets leaving in prompts). A tool result or document the agent
feeds back (Anthropic `tool_result` or text `document`, OpenAI `role: "tool"`, Ollama `role: "tool"`, Gemini
`functionResponse`, whose `response` object's string values are scanned joined by newlines) is scanned at stage
`output` with `inbound: true`, the Agent SDK's PostToolUse scan. That is where indirect injection shows
up.

- **Operator context.** Text the application itself puts in front of the model — Anthropic `system`, OpenAI
  `system` and `developer` messages, Gemini `systemInstruction`, Ollama `system` messages and the
  `/api/generate` `system` field — is judged like any other request content by default. A client controls
  its own system role, so a card number, an email address or a secret moved into the system prompt is
  blocked or asked about per policy, exactly as in a user turn.
  - **Opt-in, signed policy or admin binding only:** `"operatorContext": { "privacy": "report" }` (the only
    value besides the default `"enforce"`) makes PII-class findings in operator context report-only: threats
    1, 9, 15, 18, 27, 36 and 44 (card numbers, IBANs, email addresses, phone and national ids, IP markers,
    health data). They are reported at stage `context` (`decision: "notify"`, the threat's own risk level,
    never `Blocked`; `enforcement: LIMITED` when the policy's action for it is block or justify) and do not
    refuse the request. It is read from the root-owned admin binding (`operatorContext` in
    `/etc/moorai/config.json`, which wins, either value) or from a console-signed policy this device
    verified. A `--policy-file`, createProxy's `policy` option, the built-in baseline and the offline default
    never turn it on; the proxy warns once on stderr when one asks for it.
  - **Never exempt, even when opted in:** secrets — #39 (API keys, tokens, private keys, JWTs, connection
    strings) and #65 (a local secret value, credential-shaped egress) — and every finding that is not data:
    a prompt injection (#3), a reverse shell (#54), system-prompt extraction (#51), rendered-output
    exfiltration (#71), #1's clipboard-to-sink command, a content rule. These are decided at stage `prompt`
    exactly as in a user turn, because a system prompt assembled from untrusted parts (a retrieved
    document, a ticket, a filled template) can carry one.
  The user's turn, a tool result and the model's output are never operator context: the same card number in
  a user turn is refused under a blocking policy, even when the identical text was opted-in operator context
  earlier. `/api/generate` `template` and `prompt` are not operator context: the proxy cannot tell which part
  of one string the operator wrote. Code: [`context.mjs`](context.mjs).
- **Repeats are scanned once.** Conversations are re-sent every turn, so each item is scanned once. A
  bounded LRU, keyed by a per-process HMAC, maps each item to its verdict; opted-in operator context has
  keys of its own, so one system prompt is scanned and reported once per process and policy.
- **Not scanned:** assistant (Gemini `model`) turns, images, base64 PDFs, and the `tools` definitions.
  Gemini: `inlineData`, `fileData` URIs, `thought` parts, a `cachedContent` reference (its content was
  uploaded earlier, unparsed), and a request body that is not JSON. Ollama: `images`, `thinking`, `format`,
  `options`, and `context` (the deprecated token array of `/api/generate`).

**Responses (model → agent).** Each tool call the model asks for is decided like `/v1/tool-call`. The
proxy maps the tool name to the hook's vocabulary:

| Model's tool | Decided as |
|---|---|
| `Bash`, `Read`, `Write`, `Edit`, `WebFetch`, `Task`, `mcp__*` … | as named |
| Anthropic `bash`, any shell-named function with `command`/`cmd` | `Bash` (`PowerShell` for pwsh names) |
| Anthropic `str_replace_based_edit_tool` | `view`→`Read`, `create`→`Write`, `str_replace`/`insert`→`Edit` |
| read/write-named function with a `path` | `Read` / `Write` |
| fetch/web-named function with a `url` | `WebFetch` |
| any of the above, with its arguments wrapped once more (`{"function": "<name>", "arguments": {...}}`) | as above, after unwrapping (see [Function names and wrapped arguments](#function-names-and-wrapped-arguments)) |
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

**Model text.** The text of every reply is scanned for secrets, personal data, card numbers and the
system prompt (see [Reply text scanning](#reply-text-scanning)); each tool call is also judged against the
person's task (see [Intent alignment](#intent-alignment)). In addition, Ollama `/api/generate`
has no structured tool calls, so its generated `response` text is scanned by every detector at stage `output`, report-only, in
every mode. It is filed as a PostToolUse observation (`tool: "model-proxy:completion"`), so a deny-level
finding is stamped `enforcement: LIMITED`, and it is never withheld, streaming or not: holding a whole
generation to scan it would end streaming for `/api/generate` in enforce mode, and stage `output` flags
ordinary generated code (a sample key, a shell one-liner). Past `--max-scan-chars` only the prefix is
scanned and the rest is reported unevaluated; a streamed generation is accumulated up to 1 MiB, a budget it
shares with any held tool-call turn of the same response (text past it is not kept and is reported
unevaluated).

### Function names and wrapped arguments

**`policy.functionToolActions`** denies, or requires approval for, a tool call by the exact name of the
function the model called. It is for function-calling clients behind the proxy whose tools are not MCP
tools (`mcpToolRules` matches only `mcp__<server>__<tool>`, and a function with no hook branch is otherwise
only content-scanned). Code: [`function-rules.mjs`](function-rules.mjs), applied in
[`check.mjs`](check.mjs) `checkOne`.

```json
{ "functionToolActions": { "delete_project_files": "block", "send_*": "ask", "notify_team": "alert" } }
```

- **Actions** are `tagActions`' vocabulary: `block` denies the call. `ask` requires approval: in enforce mode
  server mode's headless rule settles it (no approver → deny, unless the system file or the org policy says
  `headlessAsk: "allow-with-report"`), and report mode reports it as configured. `alert` reports and
  changes nothing. `allow` is accepted and does nothing: nothing here loosens a verdict.
- **Matching** is on the name as a lenient client would still resolve it (`function-rules.mjs foldName`),
  on both the key and the name the model sent: Unicode NFKC (full-width letters become ASCII), control and
  zero-width characters removed, surrounding whitespace trimmed, a leading `functions.`, `function.`,
  `tools.` or `default_api.` removed, case folded, and `-` read as `_`. So `Delete_Project_Files`,
  `delete-project-files`, `functions.delete_project_files` and `delete_project_files` with a zero-width
  space all match the key `delete_project_files`; `delete_project_files2` does not, and neither does a name
  spelled with a look-alike letter from another script (Cyrillic `е`), which no client resolves to the Latin
  name. A key ending in `*` matches every name with that prefix (the egress-rule path style: `*` only at the
  end, never alone). When several keys match, the strictest action wins. A key that is not 1–128 of
  `A-Z a-z 0-9 _ . : -` (plus the trailing `*`) is ignored, with one stderr warning per loaded policy; a value
  outside the vocabulary is ignored. A wildcard whose prefix folds to nothing — a namespace alone, `tools.*`,
  `functions.*`, `default_api.*` — fails closed: it matches every function, with one stderr warning per loaded
  policy (`moorai-model-proxy: functionToolActions key "tools.*" matches every function: …`), because ignoring
  it would leave the namespace the admin meant to restrict unchecked. A key
  `tools*` (no dot) is valid and matches `tools.delete_all` and `toolsmith`.
- **Folding only adds matches.** Every key and every name is matched in three forms: as written, case and
  `-` folded without removing a namespace prefix, and fully folded; the strictest action over every form
  that matches wins (`function-rules.mjs formsOf`). Without the raw forms the full fold removed matches: the
  key `tools*` did not match the name `tools.delete_all`, which folds to `delete_all`. `allow` is never a
  match, so no form of a name can loosen another rule's action.
- **Inner names.** A name in a name key (`function`, `name`, `tool`, `tool_name`) anywhere in the arguments
  is matched too, at the top level or inside a wrapper, whether the arguments beside it are an object, a JSON
  string, other fields, or absent: `{"name": "delete_project_files", "arguments": {…}}`,
  `{"name": "delete_project_files", "arguments": "{…}"}`, `{"name": "delete_project_files"}` and
  `{"tool_name": "delete_project_files", "confirm": true}` sent to a dispatcher function are all matched,
  because the dispatcher could run that function. (Until v1.13.5 only the first form was matched.) A name key
  that happens to equal a blocked function's name in an ordinary call (`create_user {"name": …}`) is
  matched too; nothing else about such a call changes.
- **Order.** The rule runs on the name before the arguments are read. A `block` (or a settled `ask`) denies
  the call outright; otherwise the arguments are decided as before, and the stricter verdict wins. It
  applies to every function name the model calls through the proxy, `mcp__*` and mapped names (`Bash`,
  `run_shell`) included, on every parsed API.
- **Content-free.** One alert per call: `Model proxy: function denied by name (functionToolActions)`
  (`Blocked`, `deny`), `… requires approval by name …` (`High`, `ask`, plus the `HEADLESS_ASK` alert when
  enforce settles it), or `… reported by name …` (`Medium`, `notify`). `tool: "model-proxy:<function>"`, the
  name the model already sent; never an argument. The refusal reads `tool call delete_project_files:
  function delete_project_files blocked by policy (functionToolActions)`.
- **Source.** The policy the runtime loaded: the verified console policy, `--policy-file`, or code
  options. Never a request header, the request body or the model's output. The model proxy reads it; the
  hook, `@moorai/agent-sdk` and `moorai-serve` do not (their tool names are already the hook's vocabulary).
- **Alert reason code.** No reason code exists for this rule, so the alerts carry the derived
  `OBSERVATION_ONLY`, as the capability-tag alerts do; the category names the rule.

### Business-impact functions

A function with no hook branch is classed by its **name** into an impact class
([`business-tools.mjs`](business-tools.mjs)), so a business tool that the content scan has nothing to say about
(`issue_refund {"order_id": "A-1009"}`) is still reported:

| Class | Matches (words of the name) |
|---|---|
| `money` | a money action (`refund`, `payout`, `reimburse`, `disburse`, `withdraw`, `chargeback`); a money verb first (`charge`, `pay`, `wire`, `debit`, `credit`, `remit`); or a money verb beside a money object — `apply`/`add`/`redeem`/`issue`/`transfer`/`set`/`update`/`adjust` … with `coupon`, `discount`, `promo`, `voucher`, `payment`, `funds`, `money`, `price`, `pricing`, `credit`, `balance`, `wallet` … |
| `bulk-data` | `export`, `dump`, `exfiltrate`; `all`/`any`/`every`/`bulk`/`entire`/`mass` beside `customer(s)`, `user(s)`, `client(s)`, `contact(s)`, `account(s)`, `member(s)`, `employee(s)`, `patient(s)`, `email(s)`, `pii`, `data`, `record(s)`, `database`, `table(s)`; `download`/`copy`/`extract`/`scrape`/`backup` with a quantifier (`download_all`); `everything`, `everyone` |
| `identity` | `impersonate`, `sudo`, `login_as`; a grant verb with `role`, `permission`, `privilege`, `admin`, `superuser`, `scope`, `acl`, `owner`; a reset verb with `password`, `mfa`, `2fa`, `otp`, `totp`, `passcode`, `credential(s)`, `recovery`; a delete / disable / suspend / close / ban / lock verb with `account`, `user`, `member`, `profile`, `identity`, `login` |
| `destructive` | `delete`, `purge`, `wipe`, `destroy`, `truncate`, `erase`, `shred`, `nuke`, `obliterate`; `drop` with `table`, `database`, `db`, `collection`, `schema`, `index`, `bucket`, `keyspace` |
| `delegation` | `handoff`, `hand_off`, `fanout`, `fan_out`, `delegate`, `spawn`; `transfer_to_<agent>`; a call / invoke / run / dispatch / launch / start / create / assign / route / forward / send / ask / consult verb with `agent`, `subagent`, `worker`, `crew`, `swarm` |

- **Words.** The name is normalized as `functionToolActions` normalizes it (NFKC, invisible characters and a
  `functions.` / `tools.` / `default_api.` prefix removed), camelCase is split, and the result is cut into
  lower-case words at every other character, so `IssueRefund`, `issue-refund` and `functions.issue_refund`
  are all `money`. Matching is on whole words: `get_coupon_list` is not `apply_coupon`, `undelete_item` and
  `get_deleted_items` are not `destructive`, `dropdown_options` is not a `drop`.
- **Lookups are not classed.** A name whose first word is a read verb (`get`, `list`, `read`, `view`,
  `search`, `find`, `lookup`, `query`, `check`, `validate`, `verify`, `is`, `has`, `can`, `fetch`,
  `retrieve` …) or whose last word is a read noun (`status`, `policy`, `history`, `info`, `details`, `list`,
  `lookup`, `summary`, `count`, `eligibility`, `preview`, `quote`, `estimate`, `options`) is a lookup:
  `get_refund_status`, `validate_coupon`, `check_permission`, `refund_policy`. `bulk-data` is the exception
  to the read verb, because reading everything is its impact (`get_all_users`, `fetch_all_customer_records`);
  a read-noun ending still excludes it (`get_export_status`). A name can be in more than one class
  (`delete_account` is `identity` and `destructive`).
- **Action.** Built in: `alert` for every class — reported, never refused, in every mode. A signed policy
  sets a class's action:

  ```json
  { "businessToolActions": { "money": "block", "bulk-data": "ask", "identity": "ask", "destructive": "alert", "delegation": "allow" } }
  ```

  The vocabulary is `functionToolActions`': `block`, `ask` (settled by the headless rule in enforce mode),
  `alert`, `allow` (the class is not reported). A missing class or a value outside the vocabulary keeps
  `alert`. A name in several classes takes the strictest of their actions.
- **The most specific rule wins.** A `functionToolActions` key that names the function itself — an exact
  name or a wildcard with a real prefix (`issue_*`) — decides the call and its class is not applied, `allow`
  included: `{"functionToolActions": {"apply_coupon": "allow"}}` beside `"money": "block"` lets
  `apply_coupon` through. A namespace-only wildcard (`tools.*`) is not specific: it and the class combine,
  the stricter winning, so a `tools.*: alert` never loosens `money: block`. Among `functionToolActions` keys
  the strictest still wins, as above.
- **Content-free.** One alert per call: `Model proxy: business-impact function reported (<class>)` (`Medium`,
  `notify`), `… denied (<class>)` (`Blocked`, `deny`) or `… requires approval (<class>)` (`High`, `ask`),
  with `businessClass` and `functionName` (the folded name) beside `tool: "model-proxy:<function>"`; never an
  argument. Report mode files a denied or asked class with `enforcement: LIMITED`, as every other rule. The
  refusal reads `tool call issue_refund: function issue_refund blocked by policy (businessToolActions: money)`.
- **Order.** As `functionToolActions`: on the name the model sent and every inner name, before the arguments
  are read; a `block` (or settled `ask`) denies the call, otherwise the arguments are decided as before.

**Wrapped arguments.** Some small models (reported for nemotron-mini) wrap a call's real arguments once more,
as `{"function": "<name>", "arguments": {...}}` or with `parameters`, `args` or `input`. A wrapped
`{"command": …}` would miss the shell branch and only be content-scanned. `check.mjs unwrapArgs` removes the
wrapper before mapping, conservatively:

- only when the call does **not** map as sent (a call that already maps is mapped on its top-level
  fields; a wrapper beside them is still decided as another reading, see
  [Parser differentials](#parser-differentials));
- only when exactly one key is a wrapper (`arguments`, `parameters`, `args`, `input`) and its value is a JSON
  object;
- only when every other key is a name key (`function`, `name`, `tool`, `tool_name`) whose value equals the
  tool's own name.

So a tool whose real schema has an `arguments` field beside any other field, a wrapper beside a different
name, or a wrapper holding a string or an array is left as sent. Up to 4 levels are unwrapped. Unwrapping
changes only how the call is decided: the bytes the agent receives are always the provider's. A call that
still maps to nothing after unwrapping is content-scanned as before, on its arguments as sent.

Unwrapping picks the reading this checker maps; it is not the only one a client can take. Every other
reading is decided too (next section), so a harmless top-level `command` no longer hides a wrapped one.

### Parser differentials

The checker and the client that runs a tool call must agree on which function runs with which arguments.
**The principle: the proxy decides ONE canonical reading of each tool call.** Every reading a client could
take is decided (`check.mjs readings`) and the strictest verdict wins. Where the text or the call has no one
reading — the JSON is not strict, or two readings differ in a field the decision is made on — enforce mode
refuses it, replace mode withholds the turn's tool calls (replace is enforce: the same checker, the same
refusals), and report mode forwards it as sent and reports it as `UNEVALUATED_BAD_INPUT` (category
`Model proxy: content not evaluated (no one reading)`, one alert per kind and process, content-free).

**Strict JSON** (`json-strict.mjs`), for every tool call's argument string (OpenAI, Anthropic streaming,
Ollama string arguments) and for every response body, SSE event's data and NDJSON line on a parsed path
(which covers the argument objects inside Anthropic, Gemini and Ollama responses). Refused in enforce and
replace mode, reported in report mode (`tool-call-arguments`, or `response-<condition>` below):

| Condition | Why a client could read it differently |
|---|---|
| `not-json`: anything `JSON.parse` rejects — `NaN`, `Infinity`, comments, trailing commas, single quotes | a lenient client still reads it: Python's `json` (the OpenAI and Anthropic Python SDKs' stream parser) accepts `NaN` and `Infinity`. An SSE event that is not strict JSON used to be forwarded unread, and a tool call inside it was never checked. Only an empty data field and `[DONE]` are exempt |
| `duplicate-key`: an object repeats a key (after unescaping: `"\u0063ommand"` is `"command"`) | `JSON.parse` keeps the last value, simdjson's `find_field` the first, serde / Gson maps / .NET dictionaries throw |
| `key-collision`: two keys of one object differ only in case, after a NUL, or by an unpaired surrogate (compared cut at NUL, unpaired surrogates as U+FFFD, `toUpperCase().toLowerCase()`) | Go's `encoding/json` binds `{"command": "ls -la", "Command": "rm -rf ~"}` to one struct field and the last key wins (measured with Go: `command="rm -rf ~"`), as does case-insensitive .NET binding; Go turns unpaired surrogates into U+FFFD, merging `"x\ud800"` and `"x\udc00"`; C-string parsers stop at a NUL |
| `lone-surrogate`: a string with an unpaired UTF-16 surrogate | `JSON.parse` and Python keep it, Go replaces it with U+FFFD, serde rejects it |
| `too-deep`: nesting past 128 levels | serde_json's own default recursion limit is 128; the checker and a client could stop at different depths |
| `unsafe-number`: an integer literal beyond ±(2^53 − 1), or a number that overflows to ±Infinity, **in a field that groups, orders or counts tool calls** — OpenAI `choices[].index` and `choices[].delta.tool_calls[].index` (or `message.tool_calls[].index`), an Anthropic stream event's content-block `index`, Ollama `message.tool_calls[].function.index`, Gemini `candidates[].index` (`json-strict.mjs STRUCTURAL`; body and event scans only) | a double parser and an integer parser read different values: two stream tool calls with `index` 2^53 and 2^53 + 1 are one call to `JSON.parse` (their arguments merged) and two to Python. **Anywhere else** — an argument value such as `{"user_id": 1234567890123456789}`, in an argument string or an argument object — such a number is not refused and not reported: no decision reads a number (every decision field is a string), the call is decided normally and its bytes are released as sent. Its source digits (`large`) go with the response's tool calls to the content scan, which `JSON.stringify` alone would show rounded (`9007199254741055` → `…056`, which fails the card check digit) |
| `invalid-utf8` (bytes as received) | Node reads U+FFFD; another decoder may refuse, or decode differently |

`json-strict.mjs` is its own RFC 8259 recognizer (linear, iterative, no recursion at any depth); it does not
trust `JSON.parse` to have validated the text, and it agrees with `JSON.parse` on what is valid JSON and on
what every string and key decodes to (`\u0000`, `\/`, surrogate pairs and halves, every escape, `-0`):
`test/model-proxy-json-strict-fuzz.test.mjs` checks the two against each other on 6,000 generated inputs
from a fixed seed. Cost, measured on an M-series Mac: about 140 MB/s (28 ms for a 5.2 MB body, against 7 ms
for `JSON.parse`); a body at the 32 MB `--max-response` cap blocks about 0.25 s. A number with a fraction or
an exponent that every double parser reads alike (`1.5`, `1e3`) is not refused. The source digits of at most 256
large numbers per response are kept for the content scan; each is scanned on its own line, so a digit-run
pattern never joins two of them, and every content-scanned call of the response gets all of them (a number
from another call of the same response can therefore add a finding, never remove one).

**Readings.** Each of these is a reading; two readings whose decision fields differ (`check.mjs
decisionKey`: `command` for Bash / PowerShell / Shell, `file_path` for Read, `file_path` + `content` for
Write, `file_path` + `new_string` for Edit, `url` for WebFetch, `prompt` for Task / Agent) make the call
ambiguous, refused in enforce and replace mode and reported as `tool-call-ambiguous` in report mode. A
reading with no decision field (a hook tool's wrapper object with no `command`) does not count. An MCP
tool's readings are all decided but never make a call ambiguous: its input goes to its server whole.

| What could differ | What the proxy does |
|---|---|
| A wrapper object (`arguments`, `parameters`, `args`, `input`) beside top-level fields, `{"command": "ls", "arguments": {"command": "rm -rf ~"}}`: this checker mapped the top level and never read the wrapper; a client that unwraps runs the inner one | every object under a wrapper key, up to 4 levels, is a reading; two readings that map to different hook calls are refused in enforce mode |
| A hook tool name with wrapped arguments, `Bash {"function": "Bash", "arguments": {"command": …}}`: the whole object went to the hook, which found no `command` | the unwrapped command is decided as Bash too |
| A hook tool name with an alias field, `Bash {"cmd": …}`: a client whose `Bash` function declares `cmd` runs it, and the hook, reading only `command`, had nothing to decide | the alias is read under the hook's key (`cmd` → `command`, `path` / `filename` / `file` → `file_path`, `contents` / `text` / `file_text` → `content`) when the hook's key is empty; `Bash {"command": "ls", "cmd": …}` with different values is two readings, refused as ambiguous |
| Alias fields that disagree: `command` / `cmd`, `file_path` / `path` / `filename` / `file`, `content` / `contents` / `text` / `file_text`, `new_str` / `insert_text`. This checker took the first; a function declared with the other runs that one | each alias is a reading; two that map to different hook calls are refused as ambiguous; aliases with the same value are one reading. An alias is present when it has a non-empty string (or an array with one): `{"command": [], "cmd": …}` maps on `cmd` |
| A name key, `{"tool": "bash", "args": {…}}` or `{"tool": "bash", "args": "{…}"}` sent to a dispatcher | the inner name is a reading (mapped to the hook and matched by `functionToolActions`); a wrapper holding a JSON object as a string is a wrapped object too, and one that is not strict JSON makes the call ambiguous |
| A function name another client resolves differently (case, `-`/`_`, `functions.` prefix, padding, zero-width or full-width characters) | `functionToolActions` matches every form of the name (above); the hook mapping decides the call under the name as sent, its normalized form and a hook tool's own name, and two of those with different decision fields are ambiguous |
| An argument string that is not strict JSON (table above), `{"command": "ls", "Command": "rm -rf ~"}` | kept raw: content-scanned and refused in enforce mode ("tool call arguments have keys that differ only in case …"), on OpenAI, Anthropic and Ollama string arguments, streaming and not |
| A response that is not strict JSON (a second `message`, `choices` or `candidates`; `Choices` beside `choices`; an event with `NaN`) | not forwarded in enforce mode (see Report vs enforce) |

Bounds: at most 16 wrapper objects and 16 alias combinations per object are examined; past that the call is
refused as ambiguous in enforce mode. Not covered: a client that resolves look-alike letters from other
scripts (no mainstream client does; not tested), Unicode case folds beyond `toUpperCase().toLowerCase()`
(Go's fold orbits for `ſ` and the Kelvin sign are covered), and a number field that a decision reads (none
does: every decision field is a string).

## Intent alignment

Each tool call the model returns is also judged against the task the **person** gave in this session: does
it fit what they asked for? It is the hook's intent alignment (`data/intent-alignment.js`, lexical: "did
the person ever name this destination, file or service"), run per session in the proxy's memory by
`data/intent-server.mjs`. Code: [`intent.mjs`](intent.mjs), [`user-turns.mjs`](user-turns.mjs), and the
judging point in [`check.mjs`](check.mjs). It covers every API with tool calls (Anthropic, OpenAI Chat
Completions and Responses, Gemini, Ollama `/api/chat`), streaming and not.

**The session.** The first of, per request:

1. `X-MoorAI-Session-Id: <id>` (at most 256 characters): the application names its session. It is
   addressed to the proxy and is not sent upstream.
2. `X-Claude-Code-Session-Id` (Claude Code's own session id; forwarded as sent).
3. The trace-id of a valid incoming W3C `traceparent` (see [Trace context](#trace-context)): one agent run
   under one trace is one task.
4. The conversation: a keyed hash of its first user turn. Every request re-sends the whole conversation, so
   its first turn names it on every turn.
5. None of these (no header, no trace, no user turn): one session, `none`, in which nothing is ever
   captured.

A request body the proxy cannot parse (a gzip-encoded request, a leading byte-order mark) has no turns: its
session is the header's or the trace's, else `none`, nothing is captured from it, and its tool calls are
still judged (in a session with no task, as `task-unknown`).

The explicit headers win over the trace because one trace can wrap several conversations (a workflow trace
around many agent runs), which would merge their tasks and make more calls look aligned. An application
that runs many conversations under one trace, or two conversations that start with the same words, should
send `X-MoorAI-Session-Id`.

**The task.** From each request's real user turns: the first turn (the task) and the latest turn. Never a
system prompt or developer message, never a tool result, function response or document fed back to the
model, never the model's own turns, and never an agent harness's own blocks (below):

| API | A user turn is |
|---|---|
| Anthropic | a `user` message's string or `text` blocks; a `user` message that carries any `tool_result` block is the agent returning results, and its text blocks are not counted |
| OpenAI Chat Completions | a `user` message (string or text parts) |
| OpenAI Responses | `input` as a string, or its `message` items with `role: "user"` (`input_text` / `text` parts) |
| Gemini | a `contents[]` entry with `role: "user"` (or none) and no `functionResponse` part; `thought` parts are not counted |
| Ollama | `/api/chat` `user` messages; `/api/generate` `prompt` |

**Harness blocks are stripped first.** An agent harness writes text of its own into the user role. In
Claude Code 2.1.295 (measured in its bundle) CLAUDE.md, memory and the session context reach the model as a
user-role text block `<system-reminder>\nAs you answer the user's questions, you can use the following
context: … Contents of <path> …</system-reminder>`; background workers' results arrive as user-role
`<task-notification>` blocks; a `!` command's output is `<bash-stdout>` / `<bash-stderr>`; a local slash
command's output is `<local-command-stdout>` / `<local-command-stderr>`; hook output is
`<user-prompt-submit-hook>`; the IDE's selection and open file are `<ide_selection>` / `<ide_opened_file>`;
an MCP resource is `<mcp-resource server="…" uri="…">`. A tag may carry attributes of any length.
Each of those blocks is removed before any feature is taken
(`user-turns.mjs stripTurn`), so a host, a path or a label word ("delete", "token", "post") that appears
only there never counts — a cloned repository's CLAUDE.md naming a host does not put it in scope, and the
credentials, destructive and mcp-write labels are not switched on by a CLAUDE.md that happens to use those
words. One left-to-right scan per text over every harness tag, with a stack: the first block ends at its
own matching close and blocks nest. Kept: the text before the first harness tag, and — only when that block
closes cleanly and no further harness tag follows in the same text — the text after it. Fail closed: an
unclosed block, a tag with no closing `>`, a close with no open block, or a close that does not match the
innermost open block (interleaved tags), keeps only the text before the first harness tag and drops the rest
of the turn (every later text part); any further
harness tag after the first block (a second block of any tag, or a stray close) keeps only the text before
the first harness tag of that text — so a quoted file carrying `</system-reminder> words <system-reminder>`
cannot expose `words`. The cost is that a person's words after a harness block, in a text where another
harness tag follows, are dropped, which can only make a call look less aligned. Linear. `<bash-input>` (the
command the person typed) is kept.

**Only requests that declare tools, and only once the provider accepts them.** A request with no `tools`
(nor OpenAI Chat's legacy `functions`) is a side request — Claude Code's WebFetch summariser, whose user turn
is the fetched page; compaction; a title — and adds nothing to the task. The turns of a request that does
are captured when the provider's **2xx** response begins, before any tool call in it is judged; a request
the provider rejects adds nothing.

**Whose "user" turn.** In an agent-to-agent call — a sub-agent started by Claude Code's Task / Agent tool,
or any framework's delegated agent — the sub-agent's first user turn is the prompt the **parent model**
wrote, and this proxy cannot tell it from a person's. Its calls are then judged against model-written text,
so a parent steered by an injection can widen a sub-agent's scope; the same holds for a custom slash
command's expanded body (a file in the repository). Where the task must be the person's by construction,
name the session with `X-MoorAI-Session-Id` and set its task over the explicit channel — moorai-serve's
`POST /v1/task`, or the Agent SDK's prompt capture — instead of relying on the turns this proxy sees.

**Compaction.** When Claude Code compacts a conversation, the model-written summary of the earlier turns
becomes the first user turn, opening "This session is being continued from a previous conversation that ran
out of context." (2.1.295's bundle). It repeats whatever those turns quoted, so a turn that opens with that
sentence is never captured. Another harness's own summary wording is not recognised and counts as a
person's turn.

**First turn once.** A session's first captured request adds its first and latest user turns. After that,
each request adds only its latest user turn: the first turn of a re-sent conversation is the client's to
rewrite, or a compaction summary, so it is never learned again. The proxy remembers which sessions it
captured (keyed hashes, at most 1,024, 24 hours); a session the store evicted while the proxy still
remembers it is restored from its latest turn only, which can only make a call look less aligned. The store keeps per session only keyed hashes of the turn's features (hosts,
paths, known service names, three labels), at most 1,024 sessions, 512 features each, 24 hours; a turn's
text is in memory for the call only.

**Task unknown.** For a risky call in a session with no live captured task — no real user turn was ever
seen in it (a request that carries only tool results, or the `none` session), or the store evicted or
expired it — the store answers class `task-unknown`, and the proxy handles it like any misaligned call: an
alert, and in `--mode enforce` the ask or the block. **So `intentAlignment: "block"` refuses a risky call in
a session without a captured user turn**, and `"ask"` makes it a headless ask (a deny by default). A call
the store does not class as risky is never judged, task or not.

**Owner.** The store accepts an owner principal per session, so one caller cannot evict another's
sessions. The proxy passes none: every client of one proxy holds the same token, so it has no per-client
principal to give. All of a proxy's clients share one session space, and `X-MoorAI-Session-Id` is the
client's to choose: a client that names another client's session id adds its own turns to that session's
task. Run one proxy per tenant where that matters.

**Judging.** At the point the proxy decides tool calls, after its own verdict on the call and not when that
verdict is a deny, for a call that maps to a hook tool (`Bash`, `PowerShell`, `Read`, `mcp__*` …; the
table under [What it checks](#what-it-checks)). Every reading of the call that maps is judged, each with the
findings of its own decision — the as-sent mapping, `Bash {"cmd": …}` read with `cmd` as its command, the
tool a dispatcher names inside its arguments (`invoke {"tool_name": "Bash", "args": {…}}`), the other
readings under [Parser differentials](#parser-differentials) — and the strictest verdict wins (deny over
ask). The store's lexical rules decide which calls are judged at all: an upload to a host (egress, a
`curl` / `wget` destination given as a bare argument included), an upload to MoorAI's own loopback
endpoints or any other loopback service, whatever the port (moorai-control), a credential read, a destructive command, an MCP write. The policy's
`intentAlignment`:

| `intentAlignment` | `--mode report` | `--mode enforce` |
|---|---|---|
| `"off"` | nothing captured or judged | same |
| `"report"` (default) | one alert | one alert |
| `"ask"` | one alert, `enforcement: LIMITED` | the call is an ask, settled by server mode's headless rule as a `functionToolActions` ask is: a deny (the proxy's refusal) unless `--headless-ask allow-with-report` (`--headless-ask pass-through` is refused at startup: the proxy has no approver, so an unsettled ask would be forwarded) |
| `"block"` | one alert, `enforcement: LIMITED` | the call is denied: the proxy's refusal, or the replacement text with `--denied-tool-call replace` |

**The alert** is the hook's: `category: "Action outside the stated task"`, `reasonCode: "INTENT_MISMATCH"`,
`threatId: 64`, `riskLevel: "Medium"`, `stage: "behavior"`, `tool: "model-proxy:<name>"`, `decision`
(notify / ask / deny, the configured outcome), `intent: {class, mode}` with class `egress`, `credentials`,
`destructive`, `mcp-write`, `moorai-control` or `task-unknown`, and `contentHash`, the tenant-keyed hash of the class and the store's keyed
target hash. One alert per target per session; a refused call is refused every time. No prompt, path,
host or argument is in it.

**The key.** One HMAC key per process for the store and the conversation hash. `--intent-key-file <path>`
reads 64 hex characters from a file owned by root and not group- or world-writable (on Windows, a
protected file), so several proxy replicas hash alike; otherwise, or when that file is not usable (said
once on stderr), 32 random bytes at start. It never leaves the process. A restart with a random key forgets
every session, which costs little here: the next request re-sends the conversation and its first turn is
captured again (the intermediate turns, and which targets already alerted, are what is forgotten; a
conversation's first request after a restart is judged on its first and latest turns only).

**moorai-control: loopback uploads are always judged.** Every upload or egress to a host on this machine —
by URL (any scheme), bare `host:port`, `nc`, `socat` or a UNC copy — is class `moorai-control` and is never
aligned, whatever the task names and **whatever the port**: readable or not, one of MoorAI's own listeners
(moorai-serve 8790, the model proxy 8791, the MCP gateway 8848: an agent writing its own task with
`POST /v1/task`, or driving the control that judges it) or any other local service (a database on
`localhost:5432`, a dev server on `:3000`). The port is only the target's detail (`loopback:<port>`, leading
zeros dropped; `loopback` when it cannot be read); the decision never depends on parsing it. So in `ask` or
`block` every loopback upload by an agent is asked or refused; a GET (no upload) is not judged, and a copy
onto WSL's file share (`\\wsl.localhost\…`) is not a loopback service. The host is normalised before it is
classed, not matched by spelling: `localhost` / `*.localhost`, 127.0.0.0/8 and 0 in any inet_aton spelling
(`127.1`, `2130706433`, `0x7f.1`, `0177.0.0.1`, `0`), `::1`, `::`, IPv4-mapped and -compatible IPv6
(`[::ffff:127.0.0.1]`, `[::ffff:7f00:1]`), a trailing dot, any case. When the same command also uploads to a
remote host, it is still judged moorai-control (the strictest) with the remote sites among its targets, so
each remote destination raises its own alert.

**Bare curl / wget destinations.** Every curl / wget argument that is not a flag or a flag's value is a
destination (`--url VALUE` and `--url=VALUE` too; any scheme; a query or fragment after the host is ignored).
A destination whose host is shell text the proxy cannot resolve — `$VAR`, `$(…)`, backticks, a glob, a
brace, a backslash — or whose authority it cannot read at all (an underscore in the host, a port of more than
16 digits), is the site `unknown`, which no task can name (every site a task yields has a dot), so such an
upload is never aligned. A loopback host is recognised before the rest of the authority is read, so an
unreadable port on it is still moorai-control. Any upload form whose destination cannot be read at all (scp,
rsync or sftp to a dotless ssh alias, `Invoke-RestMethod -Uri $u`, nc or socat to a variable, `curl -K cfg`)
is egress to the site `unknown` too, and so is every host past the first 64 in one command; only a copy onto
WSL's own file share (`\\wsl.localhost\…`) and nothing else is not judged.

**Limits.**
- Lexical, as in the hook: an upload to a host the person named is aligned even when it is exfiltration to
  that host, and a task pasted from an untrusted source puts its hosts in scope.
- The person's turn is told from a harness's only by the blocks listed above; a sub-agent's prompt is
  model-written and judged as the task (see **Whose "user" turn**). A compaction summary is recognised
  only by Claude Code's opening sentence (see **Compaction**).
- A call the proxy cannot map to a hook tool (an unknown function, content-scanned instead) is not judged.
- If `data/intent-server.mjs` cannot start, the proxy runs without intent alignment and says so once on
  stderr.

## Reply text scanning

The text of the model's reply, what reaches the person or the application, is scanned for leaks, on every
API the proxy parses, streaming and not. Code: [`response-scan.mjs`](response-scan.mjs) (detection),
[`text-codecs.mjs`](text-codecs.mjs) (where the text is, per API), [`text-guard.mjs`](text-guard.mjs)
(holding and rewriting), [`text-report.mjs`](text-report.mjs) (alert and refusal).

| Class | Threat | What finds it |
|---|---|---|
| `secret` | #39 | the engine's output-stage secret detectors (`secret-*`, `dlp-jwt`, `dlp-private-key` …) |
| `payment-card` | #1 | `dlp-payment-card` (Luhn-checked), `pci-cvv` |
| `personal-data` | #15 | `dlp-email`, `dlp-phone`, `dlp-national-id`, `pii-passport` |
| `system-prompt` | #52 | the reply reproduces a run of at least 24 consecutive words of this request's system prompt |

The first three are the detection engine the proxy already judges outbound content with (the runtime's
policy-built engine, detector packs included), restricted to those threats' detectors that declare the
`output` stage. A threat the policy sets `"disabled"` is not looked for.

**System-prompt echo.** The request's system text (Anthropic `system`, OpenAI `system` / `developer`
messages, Responses `instructions`, Gemini `systemInstruction`, Ollama `system`) is lower-cased and split
into words (runs of letters and digits). Each run of 8 consecutive words is HMAC-SHA256'd with a random
per-process key and its first 48 bits kept, at most 8,192 shingles (words past that are not compared),
cached for the 16 most recent system prompts. A system prompt under 24 words is not tracked. The reply's
words go through the same 8-word window as they arrive; 17 consecutive matching shingles (a 24-word run) is
an echo. The system prompt and the reply are never stored or logged, only these hashes, in memory. Cost: one
HMAC per word (an 8,192-word system prompt took 25 ms to hash, once per process while cached). A run of
shared words is not proof of copying (a stock phrase the prompt quotes), and a paraphrase, a translation or
a re-tokenized copy is not found.

**Modes.** The policy's `responseScan`:

| `responseScan` | `--mode report` | `--mode enforce` |
|---|---|---|
| `"report"` (default) | one alert per finding; the reply is forwarded byte-identical | same |
| `"mask"` | alert, `enforcement: LIMITED`; nothing changed | the match is replaced by `[REDACTED:#<threat>]` (`[REDACTED:system-prompt]` for an echo) in what the client receives; `reasonCode: "MASK_APPLIED"` |
| `"block"` | alert, `enforcement: LIMITED`; nothing changed | non-streaming: HTTP 403 in the provider's error shape (`x-moorai-model-proxy: refused`); streaming: the provider's error event ends the stream (the same shapes as a denied tool call); `riskLevel: "Blocked"` |

A masked non-streaming body is re-serialized (`x-moorai-model-proxy: masked`); one with no finding goes out
byte-identical. In a stream, an event whose text changed is re-serialized — the `event:` line kept, the
same JSON keys in the same order, one `data:` line (one line for NDJSON) — and every other event goes out
byte-identical. Report-mode scanning runs after the bytes are written (a non-streaming body after the
response ends), so it never sits between the provider and the client.

**Streaming: the rolling window.** Each text channel (an Anthropic content block, an OpenAI choice, a
Responses content part, a Gemini candidate, an Ollama reply) is scanned over its last 256 characters
already passed on plus the text not yet passed on, so a match split across events, or across network
chunks, is found whole.
- **report:** nothing is held; the channel is scanned every 4,096 characters and at its end. Memory per
  channel: 256 + 4,096 characters plus one event's text.
- **mask / block:** the last **256 characters** of each channel are held back and released as more text
  arrives, and at the channel's end (its `content_block_stop`, `finish_reason`, `.output_text.done`,
  `finishReason`, `done` line, or the end of the stream). A streamed reply's text therefore reaches the
  client up to 256 characters (about 64 tokens) behind the provider; tool-call events are not delayed
  beyond their own hold. Memory per channel: 256 + 256 characters plus one event's text, and at most one
  event's data (up to 16 KiB) kept as the template for a flush event. Measured (Apple M5 Max, node 22, a
  100 KB reply in 4-character pieces, built-in detectors): 0.2 µs per piece in report mode, 18 µs per
  piece in mask / block mode, 20 µs with a tracked system prompt.
- A match of at most 256 characters is found before any of it is passed on. A longer one (a PEM body, a
  long JWT) can be found only after its start was passed on: the rest is still masked, or the stream
  stopped, and the alert says `sent: "partial"`. **Text already sent on a stream cannot be recalled.**
  Where the reply may carry long secrets, prefer `mask` (the remainder is still replaced) over relying on
  `block`.
- When a channel ends at an event that has no text of its own, the held text goes out in one flush event
  just before it, in the API's own delta shape (Anthropic `content_block_delta`, an OpenAI chunk, a
  Responses `response.output_text.delta` repeating the last delta's `sequence_number`, a Gemini chunk, an
  Ollama line). OpenAI Responses repeats the complete text in `.output_text.done`, `.content_part.*`,
  `.output_item.*` and the terminal response: each copy is scanned and masked whole.
  The repeated number cannot be made fresh without renumbering every later event the provider already
  numbered. The OpenAI Node SDK reads `sequence_number` only to skip events at or below a resume point
  (openai 4.104.0 `lib/responses/ResponseStream.js`: `starting_after == null || event.sequence_number >
  starting_after`), and a resumed stream (`GET …/responses/{id}?stream=true`) is not a parsed path here, so
  a flush is not skipped by it; a client that requires strictly increasing numbers would see one repeat.
- A re-serialized event or body keeps every number's source text (`json-lossless.mjs`): an integer past
  2^53 in a function call's arguments beside the masked text (a Gemini chunk, an Ollama line) is written as
  the provider sent it. String escapes and whitespace may differ from the provider's bytes; the values do
  not. (The text change is not spliced into the original bytes.)
- **report:** the kept tail is exactly the last 256 characters, so a match with spaces in it (a card or phone
  number) across a 4,096-character batch boundary is found whole.
- At most 64 channels per response. Past that, `mask` / `block` fail closed: the event that would open a
  65th channel is refused before any of its text is taken — reported unevaluated, and under a closed fail
  mode the stream is stopped (under `open`, that event goes out unscanned) — so no channel's text is ever
  released inside another's. Report mode scans text past the cap in one shared channel.

**The alert:** `category` "Model proxy: secret or credential in the model's reply" (or payment-card data,
personal data; "Model proxy: system prompt reproduced in the model's reply"), `threatId`, `riskLevel` (the
threat's, `Blocked` in block mode), `stage: "output"`, `tool: "model-proxy:response-text"`, `decision`
(`deny` for a configured block, else `notify`), `responseScan: {class, mode, applied, sent}`, and
`contentHash`: for a secret, the tenant-keyed hash of the matched text (for an echo, of the run's first
keyed shingle), so the console can correlate it; **for a payment card (#1) or personal data (#15), an HMAC
under a key random to this proxy process** (`proc:` and 16 hex), because those values come from small
spaces (a card is 10^16 candidates less the Luhn check, a phone number 10^10) and the tenant-keyed hash
could be enumerated back to the value by anyone holding the install token. The same card seen twice by one
proxy process hashes alike; the console, another proxy or a restart cannot link or reverse it. Never the
text, the match, the system prompt or a position. One alert per class and hash per response, at most 32.

**Token log-probabilities.** In `mask` and `block` (enforce) the token log-probabilities a client can ask
for are removed from every event and body, since they repeat the reply text token by token, held or masked
text included: OpenAI Chat `choices[].logprobs` → `null`; Responses `logprobs` on text deltas, `.done`
events and `output_text` parts → `[]`; Gemini `candidates[].logprobsResult` removed (`avgLogprobs` kept);
Ollama `logprobs` removed. A client that asked for log-probabilities gets none while `responseScan` is
`mask` or `block`; in report mode nothing is changed.

**Not scanned:** reasoning returned beside the answer (Anthropic `thinking`, Gemini `thought` parts, Ollama
`thinking`, Responses reasoning items), refusal fields, token log-probabilities in report mode (removed in
mask / block, above), Anthropic `citations[].cited_text`, Gemini `executableCode` / `codeExecutionResult`
parts, OpenAI `audio.transcript`, images and audio, and embeddings. A scan error is reported
unevaluated; in mask / block mode under a closed fail mode the response is refused (502) or the stream
stopped. Ollama `/api/generate` text is in addition still scanned report-only by every detector at stage
`output` (see **Model text** above), so a finding there can raise both alerts.

## Cloud file scanning

Policy `fileScan` (`cli/file-scan-policy.mjs`) has the proxy check every inline file, document or image part of
a parsed request with a cloud file-scanning provider before the request goes upstream. Two providers behind one
interface (`lookup(sha256)`, `upload(bytes)`, `poll(id)`): **OPSWAT MetaDefender Cloud** (`cli/file-scan-metadefender.mjs`,
API v4) and **VirusTotal** (`cli/file-scan-virustotal.mjs`, API v3). The scanner, cache, rate limit, decision and
alert are `cli/file-scan.mjs`; finding the parts is `model-proxy/file-parts.mjs`.

| Field | Values | Default |
|---|---|---|
| `provider` | `"metadefender"`, `"virustotal"` (anything else turns scanning off) | `"metadefender"` |
| `mode` | `"off"`, `"hash"`, `"upload"` | `"off"` |
| `onMalicious` | `"block"`, `"report"` | `"block"` |
| `onUnknown` | `"allow"`, `"ask"`, `"block"` | `"allow"` |
| `maxBytes` | largest file uploaded, 1 to 681574400 | 33554432 |
| `timeoutMs` | the whole scan of one request's files, 100 to 120000 | 10000 |
| `iocHash` | `true` adds a malicious file's raw SHA-256 to its alert | `false` |
| `privateScan` | MetaDefender: `true` sends `samplesharing: 0` on upload | `false` |
| `region` | MetaDefender regional endpoint by name: `us-west`, `eu-central`, `ca-central`, `ap-southeast`, `ap-northeast`, `ap-south`, `il-central` (never a URL) | OPSWAT's nearest (`api.metadefender.com`) |
| `ratePerMinute` | provider requests per minute from this process, 1 to 10000 | 4 (VirusTotal), 60 (MetaDefender) |
| `minEngines` | a clean verdict counts only from at least this many engines (VirusTotal: harmless + undetected + malicious + suspicious; MetaDefender: `total_avs`); fewer is unknown (`few-engines`), 1 to 1000 | 3 |

**Parts read.** Every turn, any role (a conversation re-sends its earlier files; the cache answers those):

| API | Parts |
|---|---|
| Anthropic Messages | `image` and `document` blocks with `source.type: "base64"`, also inside a `tool_result`'s content |
| OpenAI Chat Completions | `image_url` with a `data:` URL, `file` with `file_data` (a `data:` URL), `input_audio` (`data`); any role, a `tool` message's content included |
| OpenAI Responses | `input_image` (`image_url` `data:` URL) and `input_file` (`file_data`), in a message or a `function_call_output`; a `computer_call_output` screenshot (`output.image_url`) |
| Anthropic Message Batches (`POST …/messages/batches`) | every `requests[].params` read as a Messages request |
| Gemini `POST …/cachedContents` | read as a Gemini request (`contents`, `systemInstruction`) |
| Gemini | `inlineData` in `contents[].parts[]`, `systemInstruction.parts[]` and every nested `functionResponse.parts[]` |
| Ollama | `images[]` in `/api/chat` messages and `/api/generate` |

**Files the scan cannot read, and what happens to them** (all with `fileScan` on; `mode: "off"` changes nothing):

| What | Handling |
|---|---|
| A file sent by reference: a URL (`image_url` / `file_url` `https://…`, an Anthropic `url` source, Gemini `fileData.fileUri`) or a provider file id (OpenAI `file_id`, Anthropic `source.type: "file"`) | not fetched; an alert (`why: "reference"`, keyed hash of the reference, never the reference) and `onUnknown` decides |
| A `file_data` / `image_url` value that is neither a `data:` URL nor a URL (raw base64, a non-string), base64 that is not strict, a part nested past 16 levels | unscannable: an error, so the fail mode decides (open: `onUnknown`) |
| A body on a parsed path with a `Content-Encoding` other than identity, or that is not a JSON object (a BOM, protobuf) | refused in enforce mode or under a closed fail mode; otherwise forwarded with an `UNEVALUATED_BAD_INPUT` alert (`model-proxy:file-scan-body`) |
| Upload endpoints: Anthropic and OpenAI `…/files`, OpenAI `…/uploads` and `…/uploads/{id}/parts`, Gemini `/upload/…` media uploads, Gemini `:batchGenerateContent` | not read; refused in enforce mode or under a closed fail mode, otherwise alerted (`model-proxy:file-scan-endpoint`) and forwarded. A file uploaded there and later used by id is a reference (above) |
| Any other path the proxy does not parse, with a POST / PUT / PATCH body that is not plain JSON (multipart, binary, a content coding, unparseable) | refused in enforce mode or under a closed fail mode, otherwise alerted (`model-proxy:file-scan-unparsed`) and forwarded |
| Any other path the proxy does not parse, with a JSON body (OpenAI Batch input by file id, vector-store and Assistants file attachments by id) | not scanned |

**Paths.** With `fileScan` on, the request path is normalised before it is matched and forwarded: percent-encoded
unreserved characters are decoded, dot segments resolved, duplicate slashes collapsed and a trailing slash removed;
the normalised path is what goes upstream. Matching also reads `%2F` / `%5C` as `/` and ignores case, so
`/v1//files`, `/v1/files/`, `/V1/Files` and `/v1%2Ffiles` are all the Files API, and `/v1//messages/` is parsed and
scanned as `/v1/messages`. Anthropic `…/messages/count_tokens` is scanned like a Messages request.

An Anthropic `document` whose source is text is scanned as text, as before. At most 32 parts per request are
scanned; the rest count as not scanned (the fail mode decides). The request body is the same whether `stream` is set or not, so the
scan runs before forwarding either way.

**What is scanned is what is sent.** Three rules keep the bytes scanned and the bytes the provider reads the same:
- *Dual spellings.* Gemini's API is proto3 JSON, whose parsers take both `inlineData` and `inline_data` (likewise
  `mimeType` / `mime_type`, `functionResponse` / `function_response`, `systemInstruction` / `system_instruction`).
  Both are scanned; when both are present with different content the request is ambiguous: refused in enforce mode
  or under a closed fail mode, otherwise forwarded with a content-free `UNEVALUATED_BAD_INPUT` alert.
- *Strict base64.* A blob must be the standard alphabet (Gemini also the URL-safe one, which proto3 JSON accepts;
  never both in one value), padding only at the end, a length that is a multiple of 4 once whitespace is removed,
  and must re-encode to the same text. One that fails is **unscannable**: never clean, never looked up, decided as
  an error (closed fail mode refuses; open applies `onUnknown`). A Gemini blob sent unpadded is valid to Gemini but
  unscannable here.
- *Duplicate keys.* With file scanning on, a request body that repeats a JSON key, or has keys that differ only in
  case (Go's `encoding/json`, which Ollama uses, folds case), is a parser differential: a reader that keeps the first
  occurrence could see a file the last-wins parse never did. It is refused (403, the provider's error shape) in
  enforce mode or under a closed fail mode; otherwise it is forwarded re-serialised with a content-free
  `UNEVALUATED_BAD_INPUT` alert.
- *Re-serialised body.* With file scanning on, every parsed request body is forwarded as the parsed object
  re-serialised (lossless numbers, `json-lossless.mjs`), file or not, so the value scanned is the only one sent.
  With `mode: "off"` the body is forwarded byte for byte, as before.
- *Depth.* Nested parts are read 16 levels deep (`tool_result` in `tool_result`, `functionResponse.parts`); a part
  past that is recorded unscannable, not skipped.

**What leaves the server.**

| Mode | MetaDefender Cloud | VirusTotal |
|---|---|---|
| `off` | nothing | nothing |
| `hash` | `GET /v4/hash/{sha256}` with the `apikey` header: the SHA-256 only | `GET /api/v3/files/{sha256}` with `x-apikey`: the SHA-256 only. VirusTotal documents that a queried indicator is added to its dataset |
| `upload` | as `hash`, then for a hash the provider did not know and no larger than `maxBytes`: the file's bytes, `POST /v4/file` (a `filename` header), polled with `GET /v4/file/{data_id}`. By default OPSWAT may share the scan results with the security community; `privateScan: true` sends `samplesharing: 0` (a paid-licence feature: "All files scanned in private mode are not stored or shared") | as `hash`, then the file's bytes, multipart `POST /api/v3/files` (past 32 MB through the one-time `GET /files/upload_url`, accepted only on VirusTotal's own origin), polled with `GET /api/v3/analyses/{id}`. **Not private:** "Scanning reports produced by VirusTotal are shared with the public VirusTotal community" and "the contents of submitted files or pages may also be shared with premium VirusTotal customers" |

The proxy never sends a provider the request's text, headers, model, or the client's own credentials.

**Verdicts and decisions.**

| Provider answer | Verdict |
|---|---|
| MetaDefender `scan_all_result_i` 1 (Infected), 8 (Skipped Infected), 27 / 28 (sandbox likely malicious / malicious); VirusTotal `last_analysis_stats.malicious` > 0 | malicious |
| MetaDefender 0 (No Threats Found), 7 (Skipped Clean); VirusTotal no malicious or suspicious and at least one harmless or undetected | clean |
| HTTP 404 (MetaDefender "The hash was not found", VirusTotal `NotFoundError`); suspicious only (MetaDefender 2, 18, 26; VirusTotal `suspicious` > 0); any other result code (failed, encrypted, archive limits, unsupported, empty); no engine verdict yet; over `maxBytes` in upload mode | unknown |
| 429, MetaDefender 253 ("Not Scanned. Rate Limit Exceeded"), 401 / 403, any other error, the deadline, no key, past the 32-part cap, unscannable base64 | error |

`onMalicious: "block"` refuses the request in `--mode enforce` (403, `x-moorai-model-proxy: refused`, the
provider's name, the detection count and its threat name in the message); `"report"` forwards it with an alert.
`onUnknown: "block"` refuses an unknown file; `"ask"` settles as a headless ask (deny unless the admin binding or
policy says `headlessAsk: "allow-with-report"`). An error follows `failMode.modelProxy` (cli/fail-mode.mjs; the
proxy's own fallback is closed in enforce, open in report): closed refuses with a content-free `FAIL_CLOSED` alert
(`Fail-closed: file not scanned`); open treats the file as unknown. In report mode nothing is refused and the scan
runs after the response, except under a closed fail mode, where the scan runs first and a file it could not scan
is refused.

**Keys.** Only from the root-owned admin binding (`/etc/moorai/config.json` `"fileScanKeys": {"metadefender": "…",
"virustotal": "…"}`), then a key file per provider (`--file-scan-key-file metadefender=<path>`, first line, read only
when root-owned and not group- or world-writable), then the environment (`MOORAI_METADEFENDER_API_KEY`,
`MOORAI_VIRUSTOTAL_API_KEY`). A key in the policy is ignored. A key is sent only in the provider's header to the
provider's base URL (fetch with `redirect: "error"`); it is never in an error, a log line, an alert or a refusal.

**Cache, rate limit, deadline.** Verdicts are cached per process by provider, mode and SHA-256 (malicious and clean
1 h, unknown 5 min, errors never; LRU of 4096); concurrent scans of one file share one query. Every lookup, upload
and poll takes a token from the provider's per-minute bucket (`ratePerMinute`); a request with no token waits only
if a token comes before the deadline and fewer than 32 requests wait, otherwise it is a rate-limit error at once.
A provider 429 pauses that provider until its `X-RateLimit-Reset-In` / `Retry-After` (else 60 s). `timeoutMs`
bounds the whole scan, waits and polls included. Documented limits: VirusTotal's public API, 4 requests per minute
and 500 a day, not for commercial use; MetaDefender's throttling, 9 requests per hour on a free key, 75 / 150 / 500+
per minute on standard / professional / enterprise licences (uploads and bulk lookups), daily limits per key.

**Alerts.** One per file, verdict and decision per proxy process: `tool: "model-proxy:file-scan"`, stage `prompt`,
`fileScan: { provider, verdict, mode, detections?, engines?, threat?, mimeClass, sizeBucket, uploaded, why? }`,
`contentHash` the keyed hash of the SHA-256. A malicious file is threat #17 ("Dangerous links, files, or scripts",
the catalogue's only threat about a dangerous file; ATLAS AML.T0011 User Execution) with `REASON` `FILE_SCAN`; an
unknown or unscanned file is threat 0. The raw SHA-256 is added only for a malicious file with `iocHash: true`. A
clean file raises nothing.

**Not built.** Deep CDR (MetaDefender's sanitisation, `GET /v4/file/converted/{dataId}`) is not used. Files sent by
reference are not fetched (they are alerted and `onUnknown` decides). Upload endpoints are refused or alerted, not
scanned. Scan-before-embed for files (`/v1/index-scan`) is not wired.

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
  - Gemini: `{error: {code: 403, message, status: "PERMISSION_DENIED"}}`.
  - Ollama: `{"error": "<message>"}`, its only error shape; both official clients raise it as `ResponseError`
    / `Error` with the message.
  - No SDK retries a 403. The Google Gen AI SDKs retry nothing unless `httpOptions.retryOptions` is set
    (then 408, 429, 500, 502, 503 and 504), and they do not read `x-should-retry`.
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
  - Gemini (`alt=sse`): held from the first event with a `functionCall` part until every candidate that
    started a call has sent its `finishReason`. A Gemini call arrives whole in one event, so this holds the
    rest of the turn: an allowed call in an earlier event than a denied one is withheld with it. The JSON
    array sent without `alt=sse` is held whole, like a non-streaming body, so it is not progressive in
    enforce mode.
  - Ollama (NDJSON, `/api/chat`): lines are released as they arrive until the first line with
    `message.tool_calls`; from there every line is held until the `done: true` line, then the turn's calls
    are decided together. Ollama sends a call whole, so, as on Gemini, an allowed call in an earlier line
    than a denied one is withheld with it. A line that is not JSON is refused wherever it is (a lenient
    parser, Python's `json.loads` reading `NaN` for one, could find a tool call this one cannot), and so is
    an upstream `{"error"}` line inside a held turn. Every line of the held turn counts against the 1 MiB
    hold cap, blank lines and the `done` line included; past it the turn is refused as over the cap. Each
    turn is decided on its own calls (see [Ollama, exact limits](#ollama-exact-limits)).
  - Allowed: the held events are released byte-identical.
  - Denied: the stream ends with the provider's error event. Anthropic gets `event: error` with a
    `permission_error` body. OpenAI gets a `data:` chunk with `error`, which openai-node turns into an
    `APIError`. Gemini gets a bare `{"error":{"code":403,…,"status":"PERMISSION_DENIED"}}` line (no
    `data:`), which both Gen AI SDKs raise (see the Gemini errors bullet above); braces are kept out of its
    message because the Python SDK finds the object's end by counting them. Ollama gets a
    `{"error":"…"}` line, which both official clients raise.
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
  - Gemini: every `functionCall` part of the turn is removed and one `text` part takes the first one's
    place in each candidate that had calls. `finishReason` stays `STOP` (the reason a function-call turn
    already carries), becomes `STOP` in place of `UNEXPECTED_TOOL_CALL`, `TOO_MANY_TOOL_CALLS`,
    `MALFORMED_FUNCTION_CALL` or `FINISH_REASON_UNSPECIFIED`, and is set to `STOP` on a non-streaming
    candidate that had none. Streaming: the held events are re-sent without their `functionCall` parts (an
    event left with nothing in it is dropped; a candidate left with no part loses its `content`), the text in
    the first call's place, then `usageMetadata` as sent. The JSON array without `alt=sse` is rewritten the
    same way. The call's `thoughtSignature` goes with it: the replacement text part carries none.
  - Ollama: `message.tool_calls` is removed and the refusal is appended to `message.content` (after any text
    the model wrote); `done_reason` stays as sent (`stop`, which Ollama already sends for a tool-call turn).
    Streaming: the held lines are re-sent without `tool_calls` (a line left with no content and no
    `thinking` is dropped), and the text goes into the `done: true` line, whose statistics are kept.
  - The refusal names the tool and the engine's reasons, never the arguments. Non-streaming responses
    carry `x-moorai-model-proxy: replaced`.
  - Holding the rest of the turn closes the Anthropic per-block limit above: an allowed call before a
    denied one in the same turn is withheld too. The hold is capped at 1 MiB (`maxEvent`). Past it, the
    turn's calls are decided as over the cap, which is a deny. On Ollama every line counts, blank ones
    included, and past the cap nothing more of the turn is kept, only counted, until its `done` line.
  - An upstream that ends inside the held turn still ends in the provider's error event, as in refuse mode.
  - The agent then sees a turn that ended in text: its loop stops there, as it would for any answer.
- **Tool-call arguments that are not a JSON object** (for example, invalid JSON) are refused in enforce
  mode, streaming or not: the tool decision (hook branch, workload profile) cannot be made on them, and an
  SDK may still parse them leniently and run the call. Report mode content-scans and forwards them. An
  argument string that repeats a key is treated the same way (see
  [Parser differentials](#parser-differentials)).
- **A response that is not strict JSON** (anywhere in a JSON body, an SSE event's data or an NDJSON line:
  a repeated key, keys that differ only in case, `NaN`, a tool-call index past 2^53, invalid UTF-8 … — the table in
  [Parser differentials](#parser-differentials)) is not forwarded in enforce mode: 502 with
  `x-should-retry: false`, or the error event mid-stream ("the response repeats a JSON key …", "… has JSON
  keys that differ only in case …"), and an `UNEVALUATED_BAD_INPUT` report (`response-<condition>`). A second
  `message` or `choices` key would hide a tool call from this parser (it keeps the last value) from a client
  that keeps the first. Report mode forwards it as sent and reports it the same way.
- **The provider dropping the connection** before its response ends:
  - Non-streaming: HTTP 502 in the provider's error shape (Anthropic `api_error`, OpenAI `server_error`)
    with `x-should-retry: false`. Both SDKs obey that header before their own rule of retrying 408, 409,
    429 and any status of 500 or more.
  - Streaming: no status can be sent any more, so the stream ends with the same 502-class error event
    ("the upstream closed inside a tool call; it was not released" when a call was held). The SDKs raise
    a mid-stream error event as an `APIError` and do not retry it.
  - The evaluation budget running out is the only case answered as retryable (Anthropic 529
    `overloaded_error`, OpenAI and Gemini 503, Gemini status `UNAVAILABLE`).
  - Gemini: the Gen AI SDKs ignore `x-should-retry`. With `retryOptions` set they retry a 502; without it
    they retry nothing.
- **Content the proxy cannot judge follows the fail mode.** `cli/fail-mode.mjs resolveFailMode(policy,
  "modelProxy", { admin, fallback })` decides it: the root-owned admin binding (`failMode` in
  `/etc/moorai/config.json`, the machine directory on Windows) first, then the signed policy's
  `failMode.modelProxy`, then `failMode.default`, then the proxy's own behaviour — `closed` in enforce mode,
  `open` in report mode. The cases:
  - more than `--max-scan-items` new items in one request;
  - an item longer than `--max-scan-chars`;
  - tool-call arguments over the 1 MB hold cap;
  - content-scanned tool-call arguments (a function with no hook branch, or arguments that are not valid
    JSON) longer than `--max-scan-chars`;
  - an engine error or the evaluation budget (`--timeout-ms`) running out, on either side.

  `closed` refuses: a request with the 403 refusal (`not evaluated: over the 524288-character scan cap`, `not
  evaluated: more than 256 new items`), a response's tool call the same way, and an engine error or timeout
  with the retryable 529 / 503. In report mode `closed` refuses only what can be known before forwarding —
  a request item past a cap — because report mode scans after the response has been sent. `open` forwards:
  enforce mode scans the capped prefix (a finding there still refuses), releases arguments past the cap, and
  forwards past an engine error or timeout. Every case is reported unevaluated, whatever the mode:
  `UNEVALUATED_SIZE_CAP` for a cap, `UNEVALUATED_HOOK_ERROR` (`Model proxy: content not evaluated (evaluation
  failed)`) for an error or timeout released under `open`.
- **Content the proxy cannot read is refused in enforce mode** and reported as `UNEVALUATED_SIZE_CAP` in
  report mode, whatever the fail mode, because a tool call could hide in it:
  - a compressed response;
  - an SSE event or an NDJSON line over 1 MB;
  - a 2xx response on a parsed path that is neither `text/event-stream` (or, on an Ollama path,
    `application/x-ndjson`) nor a JSON object (for example, a local server that labels its stream
    `application/json`). Enforce answers 502 with
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
- **Upstream timeouts.** `--connect-timeout <ms>` (default 10000, at least 100): a new upstream connection
  must be usable within it, meaning TCP connected and, on an `https` route, the TLS handshake done. Past it
  the request gets 504 (Anthropic `api_error`, OpenAI `server_error`, Gemini `DEADLINE_EXCEEDED`) with the
  message `the upstream provider did not accept a connection within <n> ms`: no host, URL, query or key. A
  reused keep-alive connection skips the timer, and it is cleared once the connection is ready, so a slow
  first byte or a long stream is governed only by `--upstream-timeout-ms` (idle, default 600000). Any other
  connection failure (refused, NXDOMAIN) is the 502 `the upstream provider could not be reached`, as
  before. Measured against a dropped address (192.0.2.1, macOS): 502 after 75.0 s before, 504 after 10.0 s
  with the default and 2.0 s with `--connect-timeout 2000`.
- **Memory is bounded:**
  - request body cap `--max-body`: 32 MiB, Anthropic's documented limit; 413 over it;
  - non-streaming inspection cap `--max-response`: 32 MiB;
  - in-flight buffering budget `--max-inflight`: 256 MiB; over it, a retryable 529 or 503;
  - one pending SSE event or NDJSON line: 1 MiB (`maxEvent`, not a flag); an NDJSON line counts its `\n` and is
    held to the cap even when it arrives whole in one chunk;
  - a held tool-call turn: 1 MiB (the same `maxEvent`), see below for Ollama;
  - dedup cache: 4096 entries.

  <a id="ollama-exact-limits"></a>**Ollama, exact limits** (`ndjson.mjs`, `ollama.mjs`,
  `ollama-replace.mjs`; `test/model-proxy-ollama-bounds.test.mjs`). Per response, with the default
  `maxEvent` of 1048576 bytes:
  - **Held turn + kept text ≤ 1048576.** Every line of a held turn counts, blank (whitespace-only) lines and
    the `done` line included, in every mode, and so does the `/api/generate` text kept for the report-only
    scan. Refuse mode: past the cap the turn is refused at once and its lines are freed. Replace mode: past
    the cap the held lines and calls are freed, the rest of the turn is only counted, and the `done` line
    carries the over-cap refusal. Report mode keeps no lines; past the cap the turn is reported as over the
    cap (`UNEVALUATED_SIZE_CAP`).
  - **Tool calls:** at most 128 per turn, and only from lines inside the cap, so the calls kept are bounded
    by the held bytes. Past either limit the turn is decided as over the cap, never as an empty list. Each
    turn (a stream that sends lines after a `done` line) gets its own collector.
  - **One line ≤ 1048576 bytes**, its `\n` included; the splitter copies a partial line into one buffer
    that grows by doubling, so memory is at most the cap and a line sent a byte at a time costs linear CPU
    (measured: 1 MiB in 1-byte chunks, 25 s before, 45 ms after).
  - **Non-streaming** (`"stream": false`): `--max-response` (32 MiB) and `--max-inflight`, as every API.
  - **Request**: `--max-body` (32 MiB), at most `--max-scan-items` new items and `--max-scan-chars`
    characters per item; `images` (base64) are not scanned or copied.
  - Measured before this cap (v1.13.3, unit drive of the stream machines): 64 MiB of blank lines inside a
    held turn were all retained in refuse and replace mode; 128 tool-call lines of ~1 MB were all retained
    (122 MiB) in report and replace mode, and across 128 turns in refuse and report mode. After: at most the
    cap.

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
| a raw key in the `key` query parameter (`?key=<API key>`, the Gemini API's query-string auth) | the same as a raw key in a header: forwarded unchanged, one content-free alert per route; **401** with `--require-placeholders`. The key is never logged (the `--log` line drops the query) or reported |
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

## Decoy AI keys

A decoy is an AI provider key that was never issued, planted where real keys live
([`cli/decoy-keys.mjs`](../cli/decoy-keys.mjs)). Nothing legitimate ever sends one, so a request that
carries a decoy is a stolen key being used. The proxy checks every request before forwarding it: every
header value (`Authorization`, `x-api-key`, `x-goog-api-key` and any other header a client may put a key
in), the query string (Gemini's `?key=`) and the request body. On a match it:

- refuses the request with 403 (`x-moorai-model-proxy: refused`, `x-should-retry: false`) and forwards
  nothing. This happens in report and enforce mode alike, because a decoy authenticates nowhere and
  refusing it loses nothing;
- raises one Critical alert, `reasonCode` `DECOY_KEY_USED`, category "Decoy AI key used", with `decoyId`
  and `where: "model-proxy:request"`. The token, the header it was in and any hash of either never leave.

The decoy registry is read at the first request and re-read at most once a minute, so a decoy placed after
the proxy started is matched without a restart. The check is a substring search for each decoy: 0.07 ms per
request for 10 decoys against a 256 KiB body (M-series Mac, n=200). A decoy that a client re-encodes
(base64, split across fields) is not matched. The response is not checked: a decoy reaches the proxy only
when a client sends it.

## Local models

An OpenAI-compatible local server works with a route to its loopback URL. Plain `http://` is allowed
without `--allow-insecure-upstream` because the upstream is loopback (`127.0.0.1`, `localhost`, `[::1]`).
`--route` replaces the default routes, so list every route you need:

```bash
moorai-model-proxy --mode enforce --denied-tool-call replace \
  --route /openai=https://api.openai.com/v1 --route /local=http://127.0.0.1:11434/v1
OPENAI_BASE_URL=http://127.0.0.1:8791/local  your-agent         # Ollama's OpenAI-compatible endpoint
```

The same applies to LM Studio (`http://127.0.0.1:1234/v1`), llama.cpp server (`http://127.0.0.1:8080/v1`)
and vLLM (`http://127.0.0.1:8000/v1`). These ports are the projects' documented defaults, not tested here.

Tested against a fake local server only: no auth header, the request path under `/v1`, and a whole tool call
(id, name, all its arguments, `finish_reason`) in one chunk as well as a call fragmented across chunks.
Run live against Ollama 0.40.3 on `/v1` with `llama3.2:latest` (`scripts/server-conformance.mjs`,
[docs/HOST_CONFORMANCE.md](../docs/HOST_CONFORMANCE.md)): JSON and SSE answers forwarded, a credential
refused before the model, and the model's real tool call to a policy-blocked function withheld, in JSON and
in SSE; the same on Ollama's Anthropic-compatible `/v1/messages` and native `/api/chat`. Not tested
against LM Studio, llama.cpp or vLLM. From reading the code, not from a test: a server that streams several tool-call deltas
with no `index` gets them merged into one call, whose arguments then fail to parse, which enforce mode denies
rather than misreads.

**Ollama's native API** (`/api/chat`, `/api/generate`) is parsed on the default `/ollama` route, or on any
route, by path (see [Provider APIs it parses](#provider-apis-it-parses)). Measured live against Ollama
0.15.6 on 127.0.0.1:11434 with `mistral-nemo`, `--mode enforce`, the default `/ollama` route and
`functionToolActions: {"delete_project_files": "block"}`: an allowed `get_weather` call was released
(JSON 200, and the NDJSON tool-call and `done` lines), `delete_project_files` was refused (JSON 403
`{"error":"MoorAI model-proxy refused this response — tool call delete_project_files: function
delete_project_files blocked by policy (functionToolActions)"}`, and NDJSON ended in that `{"error"}` line),
and a content-free alert reached a local stub console. The wrapped-argument shape was not reproduced live
(nemotron-mini was not installed), and replace mode, `/api/generate` and the real ollama-python /
ollama-js packages were tested against the fake upstream and a copy of their read rule only.

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

## Trace context

Every request the proxy forwards, on every route and provider, carries a W3C Trace Context
([www.w3.org/TR/trace-context](https://www.w3.org/TR/trace-context/)) for its hop, so the provider side, an
APM and the console can join the agent's action, this model call and what follows from it.

- **`traceparent`** is set to a new span of:
  - the incoming trace, when the request carries a valid `traceparent` (its trace-id kept, its parent-id
    becoming the span's parent, its sampled flag kept). A version above `00` is read by the `00` layout;
  - else the agent session's trace, when the request names its session in `X-Claude-Code-Session-Id`.
    Claude Code sends that header on every model request, with the same id its hooks receive as
    `session_id` (measured on Claude Code 2.1.295). The trace-id is `traceIdFor` (`cli/trace-context.mjs`): a
    keyed hash under the install token, the same id the hook derives for that session, never the id itself;
  - else a new trace, sent sampled.
- **`tracestate`** gets the entry `moorai=a:model-proxy` first. Any earlier `moorai` entry is removed. The
  other entries keep their order, up to 32 in total. If adding `moorai` makes 33, one entry is dropped: an
  entry over 128 characters if there is one, otherwise the last. A client `tracestate` that is not a valid W3C
  list (a member outside the key/value grammar, or more than 32 members) is not sent on. When a key repeats,
  only its first entry is kept.
- **An invalid or missing `traceparent`** starts a new trace, and the client's `tracestate` is not sent on.
  W3C: a `tracestate` with no valid `traceparent` "MUST be discarded". Those two header values are the only
  ones the client sent that do not reach the provider as sent. `X-Claude-Code-Session-Id` goes on unchanged.
- **Every alert of the request** (its report-only checks, which run after the response, included) carries
  `traceId`, `spanId` (the span sent upstream), `parentSpanId` (the incoming span, when there was one),
  `provider` (`anthropic`, `openai`, `google`, `ollama` by the API the request speaks, else by its default
  route, else `other`) and `model`: the request's model string (the body's `model`, or the Gemini path's
  `models/<model>`), sent only if it is at most 64 characters of `[A-Za-z0-9._:/@-]`. An alert outside a
  request (the skip alert's sweep) carries none. No header value is ever logged or reported.
- **Providers accept it.** A recipient "SHOULD ignore unrecognized header" fields (RFC 9110 §5.1). With fake keys, the
  Anthropic, OpenAI and Gemini APIs answered the same status with and without `traceparent` / `tracestate`
  (401, 401, 400). A real Ollama `/api/chat` through the proxy answered 200.
- **Cost**, measured (M-series Mac, node 22, n=100k): about 2 µs per request, or 4 µs when the trace-id is
  derived from the session id.

## Allow trail

With the allow trail on (`actionTrail: "allowed"`, read only from the console-signed policy the device
verified; a `--policy-file` or options policy never turns it on), the proxy queues one record per model
request it forwards, so the console sees which agent used which model, and how often, and not only the
requests that raised an alert. It uses the hook's allow trail (`cli/action-trail.mjs`): the same record
builder, the same queue in `~/.moorai` with one `seq` shared with the hook's records, and the same flush to
`POST /api/actions`. The flush runs in the proxy's process, when enqueue says one is due, on the queue's age
rule (checked every 30 s), and at shutdown.

- **A record** carries tool `model-proxy:<provider>`, `provider`, `model` (validated as on alerts),
  decision `allow`, basis `default`, the signed policy's `iat`, `agentName` (`claude-code` when the request
  names a Claude Code session, else `model-proxy`), MoorAI's version, the device identity alerts carry, and
  `traceId` / `spanId` / `parentSpanId`. Never content, a header value, a session id or a hash of one.
- **Which requests.** A model request on a parsed path (Messages, Chat Completions, generateContent, Ollama
  chat / generate) that was forwarded. A request the proxy refused is an alert, not a trail record. An
  unparsed path (`GET /v1/models`, say) is not recorded.
- **Off** with the trail off, with an unverified policy, or on an unenrolled device: nothing is queued.
- **Cost**, measured: 160 µs per forwarded request with the trail on (the locked append to the queue file),
  nothing with it off.

## Tests

```bash
node --test --import ./test/hermetic-env.mjs test/trace-proxy.test.mjs test/trace-proxy-trail.test.mjs
node --test --import ./test/hermetic-env.mjs test/model-proxy.test.mjs test/model-proxy-enforce.test.mjs test/model-proxy-credentials.test.mjs \
  test/model-proxy-toolcall.test.mjs test/model-proxy-toolcall-local.test.mjs test/model-proxy-gemini.test.mjs test/serve-unchecked.test.mjs \
  test/model-proxy-connect-timeout.test.mjs test/model-proxy-ollama.test.mjs test/model-proxy-function-rules.test.mjs \
  test/model-proxy-differentials.test.mjs test/model-proxy-canonical.test.mjs test/model-proxy-json-strict-fuzz.test.mjs \
  test/proxy-context-system.test.mjs test/proxy-business-tools.test.mjs test/proxy-fail-mode.test.mjs test/decoy-use.test.mjs test/decoy-use-real.test.mjs \
  test/model-proxy-intent.test.mjs test/model-proxy-response-scan.test.mjs
node --test --import ./test/hermetic-env.mjs test/file-scan-providers.test.mjs test/file-scan-core.test.mjs \
  test/file-scan-proxy.test.mjs test/file-scan-parts.test.mjs test/file-scan-serve.test.mjs
```

**Cloud file scanning.** `test/file-scan-*.test.mjs` run against fake MetaDefender Cloud and VirusTotal servers
that answer in each provider's documented shapes (`test/file-scan-fakes.mjs`); no real API is called and no real
key exists. Covered: response parsing for both providers, hash hit (blocked), clean (forwarded), unknown under
each `onUnknown`, upload then poll to a verdict, a timeout and a 429 under each fail mode, the bounded rate-limit
queue, the cache, that hash mode sends only `GET` by hash, that the key is in no log line, alert or error, every
adapter's file part streaming and not, dual spellings, nested `functionResponse.parts`, strict base64 and the
re-serialised body.

**Intent alignment and reply text, exact coverage.** `test/model-proxy-intent.test.mjs` and
`test/model-proxy-response-scan.test.mjs` run the proxy in process against the fake upstreams, for
Anthropic, OpenAI Chat Completions and Responses, Gemini and Ollama (`/api/chat`, and `/api/generate` for
reply text), streaming and not. Intent: a misaligned upload alerts (report) and is refused (`block`) or
headless-asked (`ask`); an aligned one is delivered; a tool result, the text sent with it and the system
prompt are never captured as the task; the session precedence and the header strip. The intent store there
is a test double that honours `data/intent-server.mjs`'s contract (`model-proxy/test/fake-intent.mjs`); one
test runs the real module, and `test/servers-intent-e2e.test.mjs` runs the proxy CLI on it end to end
(host named in the user turn delivered, another host alerted or refused, a tool-result-only request
task-unknown). Reply text: a secret, an email address, a
card number and a system-prompt echo, each split across 7-character deltas and 5-byte network chunks, are
each found; report forwards byte-identical, mask replaces the match (every repeated Responses copy too),
block refuses with nothing of the match sent. Not tested: real providers and SDKs reading a masked or
flushed event and a model that interleaves text across several Responses content parts or Gemini candidates.

**Security-review hardening (v1.33.0), exact coverage.** `test/model-proxy-intent-review.test.mjs` (real
`data/intent-server.mjs` store unless a test needs to see what was captured): a CLAUDE.md-style
`<system-reminder>` naming a host does not align an upload to it (enforce + block refuses it; the same host
in the person's words is delivered), in its own block, in the prompt's block, as string content and with a
forged early close; every listed harness tag is stripped and an unclosed one runs to the end; label words
only inside a reminder align none of credentials / destructive / mcp-write; a tool-less request captures
nothing; `Bash {"cmd": …}` and `invoke {tool_name, args}` are refused as misaligned; a 4xx response captures
nothing; gzip and BOM bodies are judged task-unknown; an upload to 127.0.0.1:8790 / localhost:8791 is
refused as moorai-control even when the task names it; `--headless-ask pass-through` is refused.
`test/intent-alignment-control.test.mjs`: the MoorAI ports equal the code's defaults, every form of a
loopback control upload, never aligned, other loopback ports and GETs not risky, bare curl / wget hosts and
flag values, and a 60,000-character command bounded. `test/model-proxy-reply-scan-review.test.mjs`: a card's
and personal data's contentHash is none of the install-token-keyed hashes of the value's forms (enrolled
runtime), stable within a process, different across two; mask removes log-probabilities on OpenAI Chat
(both), Responses (both), Gemini (both) and Ollama (chat stream, generate body), and block lets not even the
secret's first 7 characters out through them on the four streams; a 65th channel throws in mask / block and
held text is released at the end; through the proxy a 66-choice masked stream is stopped; report mode finds
a spaced card across the batch boundary; a masked Gemini chunk and a masked Ollama body keep
`12345678901234567890` as sent. Commit-review follow-ups (the `R1`–`R4` tests in the same files): a command
posting to 127.0.0.1:8790 and uploading to a remote host keeps the remote site as a target; a query straight
after a bare host, `--url=`, any scheme, and unresolvable shell text (site `unknown`, never aligned); sixteen
loopback spellings on a MoorAI port, with public and other-port controls and a bounded-time check;
interleaved, nested, re-balanced and unclosed harness blocks, and a linear-time check; `R5` an interleaved or
unclosed block, or a second block, followed by an upload host keeps only the text before the first tag (and
the proxy refuses the upload); `R6` leading-zero MoorAI ports by URL, bare, `nc` and `socat`, a padded other
port, and unreadable authorities as `unknown`; `R7` every loopback upload judged whatever the port (a
20-digit zero-padded 8790, `localhost:5432`, `:3000`, an unreadable port, `nc` with a padded or non-numeric
port, `socat`, `wget` to `0x7f.1`), the port only in the detail, a GET and the WSL share not judged. Each
fix was mutated back and its test seen failing.

Latency the judging adds, measured on an M-series Mac, node, no console, built-in rules:

- One decision (`checker.checkToolCalls`, one call, n=300): p50 1.3 ms for an allowed `Bash ls -la`, 3.1 ms
  for a denied `curl … | sh`, and 1.5–1.6 ms for `Read`, `run_shell`→`Bash` and a content-scanned unknown
  function. p95 is at most 4.5 ms.
- End to end, a streamed turn with one allowed tool call, enforce/replace minus report mode, paired, n=150:
  p50 1.5 ms (Anthropic and OpenAI), p95 2.0 ms. This is the hold plus the decision. Report mode adds
  nothing to the stream; its check runs after the response has been sent.

The tests run the real CLI against a fake provider (`model-proxy/test/fake-provider.mjs`, SSE written in
5-byte slices) and a fake console. No real provider or key is used.

**Connect timeout.** `test/model-proxy-connect-timeout.test.mjs` routes `https://127.0.0.1:<port>` to a
local listener that accepts TCP and never sends a byte, so the TLS handshake never completes: with
`--connect-timeout 500` the request gets 504 in under 3 s with no address or key in the body. A
non-routable address is not used in the test, because whether its SYN is dropped or refused depends on the
host's network. A slow response (1.2 s to headers) and a stream lasting longer than the timeout both
arrive whole. A dropped SYN itself was measured by hand only (above).

**Gemini, exact limits.** `test/model-proxy-gemini.test.mjs` runs against a fake Gemini upstream
(`model-proxy/test/fake-gemini.mjs`) built from the documented shapes, and reads the result with a copy of
the JS SDK's stream-splitting rule. Not tested: a real Gemini API or Vertex AI endpoint, the real
`@google/genai` or `google-genai` packages, Vertex `partialArgs` from a real model (no documented example
exists; the fixture is the field descriptions), the latency the hold adds on Gemini, and the 503 evaluation
timeout on a Gemini path. A placeholder is swapped only in a header (a binding with
`"header": "x-goog-api-key"`). A placeholder in the `?key=` query string is refused 400 and never swapped,
because the swap would write the real key into a URL. Tested (`test/model-proxy-credentials.test.mjs`): a
**raw** key in `?key=` (the Gemini API's documented query-string auth) is a raw credential, alerted once per
route and refused 401 with `--require-placeholders`, and the key appears in no alert, log line or refusal.

**The default `/gemini` route.** `test/model-proxy-gemini-default.test.mjs` runs the real CLI with no
`--route` and a test-only preload (`model-proxy/test/redirect-upstream.mjs`) that sends its https requests
for `generativelanguage.googleapis.com` to the fake Gemini upstream and refuses every other https request.
It checks that `/gemini/v1beta/models/<m>:generateContent` (and `:streamGenerateContent?alt=sse`) is built
as `https://generativelanguage.googleapis.com/v1beta/models/<m>:…` with `x-goog-api-key` untouched, that the
Gemini parser refuses a denied `functionCall` on that route, that a `moorai-ph:` placeholder bound to
`/gemini` is swapped into `x-goog-api-key` there and refused on `/openai`, and that a raw `?key=` on
`/gemini` is alerted and, with `--require-placeholders`, refused 401. The TLS connection to Google itself
is not exercised.
