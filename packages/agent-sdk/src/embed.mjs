// Scan content before it is embedded, for applications that run their own RAG / memory ingestion.
//
//   import { scanBeforeEmbed, guardEmbed } from "@moorai/agent-sdk";
//   const report = await scanBeforeEmbed(chunks, { source: "kb/handbook" });
//   const addDocs = guardEmbed((docs) => vectorStore.addDocuments(docs), { source: "kb/handbook" });
//   await addDocs(docs);                    // denied chunks never reach vectorStore.addDocuments
//
// The same runtime and policy as createMoorAI (./runtime.mjs scanForIndex, cli/index-scan.mjs): the
// engine's index stage, policy.indexScanAction ("report" default, "block"), content-free alerts to the
// console when one is configured. Report-first: with no policy that says "block", nothing is dropped.
// Fail-open: an internal error keeps every chunk (verdict "allow", `failOpen: true`) unless failClosed.
import { createMoorAI } from "./runtime.mjs";

let shared = null;
// options: a createMoorAI() instance (or its promise) as `runtime`; else createMoorAI options (policy,
// policyFile, console, serviceId, …) build one for this caller; with neither, one process-wide runtime
// from the environment is built on first use and reused.
function runtimeFor(opts) {
  const { runtime, source, onError, onReport, failClosed, ...rest } = opts;
  if (runtime) return Promise.resolve(runtime);
  if (Object.keys(rest).length) return createMoorAI(rest);
  return (shared ||= createMoorAI({}).catch((err) => { shared = null; throw err; }));
}

function failOpenReport(n, err) {
  const idx = Array.from({ length: n }, (_, i) => i);
  return { action: "report", policyId: null, failOpen: true, error: String(err && err.message || err), results: idx.map((i) => ({ index: i, verdict: "allow", threatIds: [], categories: [], reasons: [], findings: [] })), allowed: idx, flagged: [], denied: [] };
}

// chunks: an array of strings or objects (a LangChain Document { pageContent, metadata }, a { text } or
// { content } record — every string value is scanned, metadata included). Resolves to
//   { action: "report" | "block", policyId,
//     results: [{ index, verdict: "allow" | "flag" | "deny", threatIds, categories, reasons, findings }],
//     allowed: [index…], flagged: [index…], denied: [index…] }
// findings are content-free ({ threatId, category, riskLevel, stage: "index", detectorId }).
export async function scanBeforeEmbed(chunks, opts = {}) {
  const list = Array.isArray(chunks) ? chunks : [chunks];
  try {
    const rt = await runtimeFor(opts);
    return await rt.scanForIndex(list, { source: opts.source });
  } catch (err) {
    try { if (opts.onError) opts.onError(err); } catch { /* the caller's handler */ }
    if (opts.failClosed) throw err;
    return failOpenReport(list.length, err);
  }
}

// guardEmbed(embedFn, opts) → async (chunks, ...rest) => embedFn(kept, ...rest)
// Scans the chunks first; a denied chunk (policy "block" only) is dropped from the array embedFn
// receives, and the report — indexes relative to the ORIGINAL array — goes to opts.onReport, so a
// caller that keeps ids alongside its chunks can drop the same entries. When every chunk is denied,
// embedFn is not called and the wrapper resolves to []. A non-array first argument is one chunk, passed
// through as it was when it is kept. Use it on the step that takes documents (vectorStore.addDocuments,
// an embeddings call whose output you store) rather than on a lower layer whose caller expects one
// vector per input.
export function guardEmbed(embedFn, opts = {}) {
  if (typeof embedFn !== "function") throw new TypeError("guardEmbed needs a function");
  // One runtime per wrapper, built on the first call and reused; a failed build is retried next call.
  let rt = null;
  const runtime = () => (rt ||= runtimeFor(opts).catch((err) => { rt = null; throw err; }));
  async function guarded(chunks, ...rest) {
    const single = !Array.isArray(chunks);
    const list = single ? [chunks] : chunks;
    const report = await scanBeforeEmbed(list, { ...opts, runtime: { scanForIndex: async (c, o) => (await runtime()).scanForIndex(c, o) } });
    try { if (opts.onReport) opts.onReport(report); } catch { /* the caller's handler */ }
    if (!report.denied.length) return embedFn(chunks, ...rest);
    const drop = new Set(report.denied);
    const kept = list.filter((_, i) => !drop.has(i));
    if (!kept.length) return [];
    return embedFn(single ? kept[0] : kept, ...rest);
  }
  // Drain the content-free alerts before shutdown (they are fire-and-forget, as the hooks' are).
  guarded.flush = async () => (opts.runtime ? (await opts.runtime).flush() : rt ? (await rt).flush() : undefined);
  return guarded;
}
