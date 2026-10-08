// The "index" stage as an integration point: content an application is about to EMBED into a vector
// store or retrieval index, scanned before it is embedded. Shared by every surface that offers it —
// @moorai/agent-sdk scanBeforeEmbed / guardEmbed (packages/agent-sdk/src/embed.mjs), moorai-serve's
// POST /v1/index-scan (cli/moorai-serve.mjs), and the vector-store write tools the MCP stdio proxy and
// the HTTP gateway recognise (cli/index-tools.mjs) — so all of them reach the same verdict on the same
// chunk.
//
// WHY THE STAGE. A poisoned chunk is retrieved later, into some other user's context, with no tool call
// and no user typing it (RAG / memory poisoning, threats #21 #22 #40). The engine's index stage is the
// prompt detectors plus the ingested-content ones that declare "index" (inj-untrusted-directive,
// ingest-agent-directed, mcp-tool-poisoning, mcp-hidden-canary, cloak-ai-audience, …: data/detectors.js).
// Every verdict here goes through DetectionEngine.scanForIndex, the engine's documented choke-point.
//
// REPORT-FIRST. policy.indexScanAction:
//   "report" (default)  every finding is reported (content-free) and the chunk is kept: verdict "flag".
//   "block"             a chunk is denied (verdict "deny": dropped by guardEmbed, refused at an MCP
//                       vector-store write) when a finding is one that carries instructions
//                       (cli/prompt-scan.mjs INSTRUCTION_THREATS) or one whose resolved action is block /
//                       kill — the same rule policy.promptScanAction "block" uses. A secret or PII in a
//                       chunk is reported, not blocked, unless the org policy blocks that threat.
// The policy's per-threat actions alone never drop a chunk: a default install's built-in "justify" for
// a deploy runbook (#49) must not keep that runbook out of an index. "disabled" still silences a threat.
//
// Pure apart from the engine: no I/O, no reporting. The caller reports, content-free.
import { decideText, threatActionFor } from "./hook-core.mjs";
import { promptBlockers } from "./prompt-scan.mjs";

export const INDEX_CHUNK_CAP = 262144;   // characters of one chunk that are scanned (256 KB)
export const INDEX_MAX_CHUNKS = 4096;    // chunks one call may submit
const WALK_NODES = 4096;
const WALK_DEPTH = 8;

export function indexScanAction(policy) {
  return policy && policy.indexScanAction === "block" ? "block" : "report";
}

// The text of one chunk: a string as it is; an object (a LangChain Document { pageContent, metadata },
// a { text } / { content } record, an MCP tool's arguments) as every string value in it, one per line —
// metadata is stored next to the vector and comes back with it, so it is scanned too. Bounded by node
// count, depth and the character cap; never JSON.stringify, which would escape newlines and quotes and
// hide line-anchored patterns.
export function chunkText(value, cap = INDEX_CHUNK_CAP) {
  if (typeof value === "string") return value.length > cap ? value.slice(0, cap) : value;
  if (!value || typeof value !== "object") return "";
  const out = [];
  let size = 0, nodes = WALK_NODES;
  (function walk(v, depth) {
    if (size >= cap || nodes-- <= 0 || depth > WALK_DEPTH || v == null) return;
    if (typeof v === "string") { if (v) { out.push(v); size += v.length + 1; } return; }
    if (typeof v !== "object") return;
    for (const x of Array.isArray(v) ? v : Object.values(v)) { if (size >= cap) return; walk(x, depth + 1); }
  })(value, 0);
  const t = out.join("\n");
  return t.length > cap ? t.slice(0, cap) : t;
}

// An engine whose scan() is scanForIndex, so decideText — the hook's own policy resolution (disabled,
// calibrated risk, content policy) — runs over the index choke-point rather than a look-alike.
function viaIndex(engine) {
  return Object.create(engine, { scan: { value: (text) => engine.scanForIndex(text) } });
}

const reasonOf = (f) => (f.threatId > 0 ? `#${f.threatId} ${f.category}` : f.category);

// One chunk → { verdict: "allow" | "flag" | "deny", action, findings, blockers, reasons }.
// findings carry the matched span (`match`) for the caller's keyed hash; strip it before it leaves.
export function decideIndexChunk(engine, policy, value) {
  const text = chunkText(value);
  const action = indexScanAction(policy);
  const d = decideText(viaIndex(engine), policy, text, "index");
  const findings = d.findings.map((f) => ({ ...f, stage: "index" }));
  const blockers = action === "block" ? promptBlockers(findings, (id) => threatActionFor(policy, id)) : [];
  const verdict = blockers.length ? "deny" : findings.length ? "flag" : "allow";
  const reasons = [...new Set((blockers.length ? blockers : findings).map(reasonOf))];
  return { verdict, action, findings, blockers, reasons };
}
