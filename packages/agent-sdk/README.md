# @moorai/agent-sdk

MoorAI in process: the MoorAI hook's engine and policy decisions without a process per call. One runtime
(configuration, workload identity, policy, engine, content-free reporter) is built once and reused. The
same runtime backs the `moorai-serve` sidecar, so both answer alike.

```js
import { moorAIHooks, scanBeforeEmbed, guardEmbed, createMoorAI } from "@moorai/agent-sdk";
```

## Claude Agent SDK hooks

```js
import { query } from "@anthropic-ai/claude-agent-sdk";
for await (const m of query({ prompt, options: { hooks: moorAIHooks({ serviceId: "invoice-agent" }) } })) …
```

`PreToolUse` returns the hook's decision and reason; prompts and tool results are observed by default
(`prompts: "enforce"`, `toolResults: "advise"` to act on them). Options are documented at the top of
[`src/index.mjs`](src/index.mjs).

### Intent alignment

`UserPromptSubmit` also records the task: the prompt passed to `query()` and every later user turn (a
machine-injected `source` such as `system` is skipped). The runtime keeps only HMACs of the sites, paths,
service names and labels the task mentions, per `session_id`, in memory under a random per-process key
([`data/intent-server.mjs`](../../data/intent-server.mjs)); the prompt is never stored. A `PreToolUse` call
that is already risky (an upload, a #43 destructive command, a #55 credential read, an MCP write) and
aimed at something the task never named is judged under `policy.intentAlignment`:

| Mode | Effect |
|---|---|
| `"report"` (default) | one content-free alert per session and target (#64, `Action outside the stated task`); the decision is unchanged |
| `"ask"` | an allow becomes an ask, which the headless rule settles (deny by default; `headlessAsk: "pass-through"` hands it to your `canUseTool`) |
| `"block"` | deny, with a fixed reason per class ("an upload to a host your request never mentioned") |
| `"off"` | nothing is captured or judged |

A call the branch already denied is not judged again, and a session with no task is never judged.
`createMoorAI()` exposes the same step as `captureTask(session, prompt)` plus `toolCall({ ..., session })`,
whose verdict carries `intent: {class, mode}` when it fires. Limits: it is lexical, asking whether the user
named the destination, file or service, not whether the action serves the task; a request pasted from an
untrusted source puts its hosts in scope; the store is per process, so a restart forgets the task. A
session the store held and lost (evicted past `intentStore.maxSessions`, default 1024, or idle past 24 h)
fails closed: a risky call on it is judged as class `task-unknown`, which `"block"` denies, `"ask"` asks
and `"report"` alerts on.

## Scan content before it is embedded

For an application that runs its own RAG or memory ingestion. A poisoned chunk in a retrieval index is
read back into a later user's context with no tool call; these helpers scan each chunk at the engine's
`index` stage first (`DetectionEngine.scanForIndex`, via the repository's `cli/index-scan.mjs`).

```js
const report = await scanBeforeEmbed(chunks, { source: "kb/handbook" });
// { action: "report" | "block", policyId,
//   results: [{ index, verdict: "allow" | "flag" | "hold" | "deny", threatIds, categories, reasons, findings, claims? }],
//   allowed: [0, …], flagged: [2], held: [], denied: [] }

// Who wrote the chunks (v1.20.0): a business-value claim from an untrusted or unknown author is #21.
await scanBeforeEmbed(reviews, { source: { name: "kb/reviews", trust: "untrusted", kind: "customer" } });

const addDocs = guardEmbed((docs) => vectorStore.addDocuments(docs), {
  source: "kb/handbook",
  onReport: (r) => r.denied.length && log.warn("dropped chunks", r.denied),
});
await addDocs(docs);
```

- **Chunks** are strings or objects; for an object every string value is scanned (a LangChain
  `Document`'s `pageContent` and `metadata`). Up to 256 KB of each chunk is scanned, 4,096 chunks per call.
- **Verdicts.** `allow` — no finding. `flag` — reported and kept. `deny` — only when the policy says
  `indexScanAction: "block"` and a finding is an instruction-carrying threat (#2, #3, #21, #22, #25, #40,
  #50, #51, #60, #68, #70, #72, #74) or a threat whose configured action is block or kill. The default is
  `"report"`: nothing is dropped. `findings` are content-free (`threatId`, `category`, `riskLevel`,
  `stage: "index"`, `detectorId`).
- **Provenance.** `source` is a string label or `{ name?, trust?: "trusted" | "untrusted" | "unknown",
  kind? }`. When the author is untrusted or unknown, a price or discount, a policy change, account or
  payment details, or an authority claim ("confirmed by management") raises #21 (`kb-untrusted-claim`;
  `claims` lists the kinds). `policy.indexProvenance.untrustedClaims`: `"report"` (default, `flag`), `"ask"`
  (`hold`: listed in `held`, and `guardEmbed` does not embed it), `"block"` (`deny`) or `"off"`. A trusted
  author, or a call that states no trust, is not checked.
- **`guardEmbed(embedFn, opts)`** returns `async (chunks, ...rest) => embedFn(kept, ...rest)`. Denied
  (and held) chunks are removed from the array `embedFn` receives; the report's indexes refer to the original array,
  so drop the matching ids in `onReport`. When every chunk is denied, `embedFn` is not called and the
  wrapper resolves to `[]`. Wrap the step that takes documents (`addDocuments`, an embeddings call whose
  output you store), not a layer whose caller expects one vector per input. `guarded.flush()` drains the
  alerts before shutdown.
- **Runtime.** Pass `runtime: await createMoorAI({...})` to share one runtime; or pass `createMoorAI`
  options (`policy`, `policyFile`, `console`, `serviceId`, …) to build one; with neither, one runtime from
  the environment is built on first use and reused. `guardEmbed` builds its runtime once per wrapper.
- **Reporting.** One content-free alert per finding to the console when one is configured: stage
  `index`, tool `index:embed`, a keyed hash of the matched span, `indexSource` as a keyed hash of
  `source` (never the source itself). No chunk text leaves, in alerts or in the returned report.
- **Fail-open.** An internal error returns every chunk as `allow` with `failOpen: true` (and calls
  `onError`); `failClosed: true` rethrows instead.

Over HTTP, the same verdicts come from `moorai-serve`: `POST /v1/index-scan` with `{ "chunks": [...],
"source": "…" }`.

**Not covered:** content your application embeds without calling one of these, and documents a vector
store ingests on its own. MoorAI ships no vector store or embedding writer.

## Packing

`npm pack` vendors the engine into `moorai/` (`scripts/vendor.mjs`, run by `prepack`); inside the MoorAI
repository the package uses the live tree.
