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

## Scan content before it is embedded

For an application that runs its own RAG or memory ingestion. A poisoned chunk in a retrieval index is
read back into a later user's context with no tool call; these helpers scan each chunk at the engine's
`index` stage first (`DetectionEngine.scanForIndex`, via the repository's `cli/index-scan.mjs`).

```js
const report = await scanBeforeEmbed(chunks, { source: "kb/handbook" });
// { action: "report" | "block", policyId,
//   results: [{ index, verdict: "allow" | "flag" | "deny", threatIds, categories, reasons, findings }],
//   allowed: [0, …], flagged: [2], denied: [] }

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
- **`guardEmbed(embedFn, opts)`** returns `async (chunks, ...rest) => embedFn(kept, ...rest)`. Denied
  chunks are removed from the array `embedFn` receives; the report's indexes refer to the original array,
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
