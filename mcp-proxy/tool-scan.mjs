// Tool-metadata scanning for the Claude Desktop MCP proxy — the "tool" stage, which until now had NO
// shipped caller at all.
//
// THE GAP THIS CLOSES, stated as it was measured, not as it was assumed:
//
//     grep -rn 'decideText([^)]*"tool"' cli/      ->  zero hits
//
// data/detectors.js ships two detectors scoped to ["tool","file","index"] — `mcp-tool-poisoning`
// (#60) and `mcp-hidden-canary` (#50) — and NOTHING in the product ever fed them a tool description
// or an input schema. moorai-mcp-guard.mjs gated `tools/call` ARGUMENTS and piped `tools/list`
// responses through verbatim (its own header said so). So every poisoned description, dangerous
// schema default, shadowed tool name and delayed rug-pull in test/redteam/vector3-supply-chain.json
// was detectable by the rules and unreachable by the product.
//
// This module is PURE: text composition, caps, and content-free identity. It performs no I/O, holds
// no state, and never decides anything. The proxy owns the wiring; tool-baseline.mjs owns the
// cross-call memory. Splitting it out is what makes the caps and the composition testable without a
// child process.
//
// COMPOSITION, and why it is not `JSON.stringify(tool)`. The corpus feeds the engine the tool's raw
// JSON, so JSON.stringify looks like the parity-preserving choice. It is not: JSON.stringify escapes
// every control character, and `\x1b` -> `` silently defeats mcp-hidden-canary's ANSI pattern
// (/\x1b[\[\]P^_]/). We therefore emit the RAW string values, one per line, so an escape sequence,
// a bidi override or a zero-width run reaches the detector as the byte it actually is.
//
// Content-free: this module returns text to be scanned IN-PROCESS and fingerprints to be compared
// IN-PROCESS. Nothing here is shaped for egress; the proxy hashes before anything leaves.

import { fileFingerprint } from "../cli/content-hash.mjs";

// ---- CAPS. A hostile server is a server: it may advertise 10,000 tools, or one tool with a 5 MB
// description, precisely to make the guard the thing that hangs the agent. Every bound below is a
// hard stop, and exceeding one degrades to LESS SCANNING, never to a dropped or delayed message. ----
export const CAPS = {
  maxLineBytes: 1048576, // 1 MB — a JSON-RPC line larger than this is forwarded but never parsed for observation
  maxTools: 128,         // tools inspected per tools/list response; the rest are forwarded unscanned
  maxToolBytes: 16384,   // composed scan text per tool (16 KB), truncated at a character boundary
  maxFieldBytes: 4096,   // any single string value contributes at most this much
  maxSchemaNodes: 256,   // schema nodes visited per tool
  maxSchemaDepth: 8,     // schema recursion depth
  scanBudgetMs: 250,     // wall-clock budget for one tools/list response; checked BETWEEN tools

  // ---- the RESULT stage. A tool result is the OTHER thing a server sends, and it is bigger and far
  // more frequent than a tool listing: a file read, a DB dump, a log tail. Every bound below exists
  // because the proxy must never be the reason a result was slow, and because "load the whole thing
  // into memory to scan it" is exactly what a hostile server would like us to do. ----
  maxResultBytes: 65536, // composed scan text per tools/call result (64 KB). ~4 ms of engine time at
                         // the "file" stage, measured; beyond it the result is scanned only up to
                         // here — LESS scanning, never a delayed or dropped message.
  maxResultNodes: 512,   // JSON nodes visited while harvesting result text
  maxResultDepth: 8,     // recursion depth of that harvest

  // ---- the two bounds that changed when the result stage became able to BLOCK. ----
  //
  // maxQueuedObs was written for an off-path observer that could safely DROP a backlogged line. The
  // result stage is no longer off-path — its queue IS the transport, and dropping a line there would
  // lose a message. So the cap moved to the one queue where dropping is still safe: the tools/list
  // observation, which remains forward-first and structurally unable to block.
  maxQueuedObs: 64,      // tools/list observations that may be in flight; over this, a LISTING is
                         // skipped unscanned rather than queued without bound. Never a result.

  // resultDeadlineMs is the wall-clock wall that makes parse-then-forward safe. Every result-stage
  // decision races this timer, and losing the race forwards the ORIGINAL bytes. It bounds the ASYNC
  // hazards (a policy refresh, a starved microtask queue, any await a later change adds). It cannot
  // bound a synchronous regex pass — V8 cannot interrupt one — which is what maxResultBytes is for:
  // measured on this repo, decideText over 64 KB at stage "file" costs 3.8-4.2 ms warm.
  resultDeadlineMs: 750,

  // An overload valve, NOT a kill switch. The previous shape of this budget was cumulative for the
  // life of the process, which meant ~1250 ordinary results permanently blinded the stage — and a
  // hostile server could buy that blindness deliberately with cheap traffic before sending the
  // payload. It is now a SLIDING WINDOW: at most resultBudgetMs of scanning per resultWindowMs
  // (~8% of one core). Exceed it and the stage skips results until the window rolls, then resumes.
  resultBudgetMs: 5000,
  resultWindowMs: 60000
};

// A JSON-RPC response carrying a tool list. Matched structurally (result.tools is an array of objects
// with string names) rather than only by request id, so a schema refresh or a server that pushes a
// list outside the request/response pair is still observed.
export function toolsOfResponse(msg) {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
  const r = msg.result;
  if (!r || typeof r !== "object" || Array.isArray(r)) return null;
  const t = r.tools;
  if (!Array.isArray(t)) return null;
  const tools = t.filter((x) => x && typeof x === "object" && !Array.isArray(x) && typeof x.name === "string");
  return tools.length ? tools : null;
}

// A JSON-RPC RESPONSE carrying tool RESULT content — the content the agent INGESTS, which the proxy
// never looked at. Matched structurally, like toolsOfResponse, and deliberately NOT by pairing a
// request id: an id map is state that has to be bounded, and a result that arrives without its
// request still deserves to be scanned. The four rejections below are the whole contract:
//
//   result.tools present  -> a tools/list; the tool stage owns it, and double-scanning it would
//                            double every tool-poisoning alert.
//   msg.method present    -> a server->client REQUEST or notification (sampling/createMessage,
//                            notifications/message). Not a result, whatever else it carries.
//   msg.error present     -> a JSON-RPC error; there is no result content to ingest.
//   non-object result     -> nothing to walk.
//
// Note what this deliberately DOES accept: any method's result, not just tools/call. `resources/read`
// ({contents:[{text}]}) and `prompts/get` ({messages:[{content:{text}}]}) are the same ingestion event
// wearing a different shape, and the harvester below is shape-agnostic, so they come along free.
export function resultOfResponse(msg) {
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
  if (msg.method != null) return null;
  if (msg.error != null) return null;
  const r = msg.result;
  if (!r || typeof r !== "object" || Array.isArray(r)) return null;
  if (Array.isArray(r.tools)) return null;
  return r;
}

// Base64 payloads. `data` (image / audio content blocks) and `blob` (binary resource contents) are
// megabytes of base64 that no text detector can read; harvesting them would spend the entire byte
// budget on noise and buffer the exact thing the caps exist to avoid. Skipped by key, and declared
// as uncovered rather than quietly dropped.
const BINARY_KEYS = new Set(["data", "blob"]);

// Harvest the model-visible STRINGS out of a result, bounded three ways at once (nodes, depth, total
// bytes). Every string value is taken, not only `content[].text`: `structuredContent` values, a
// resource `uri`, an error string in a tool's own payload are all things the model reads, and keying
// on one field name would make the harvester wrong the moment a server used a different shape.
function walkResult(node, depth, out, budget) {
  if (budget.nodes <= 0 || budget.bytes <= 0 || depth > CAPS.maxResultDepth || node == null) return;
  if (Array.isArray(node)) {
    for (const item of node) { if (budget.nodes <= 0 || budget.bytes <= 0) return; walkResult(item, depth + 1, out, budget); }
    return;
  }
  if (typeof node !== "object") return;
  budget.nodes--;
  for (const k of Object.keys(node)) {
    if (budget.nodes <= 0 || budget.bytes <= 0) return;
    const v = node[k];
    if (typeof v === "string") {
      if (BINARY_KEYS.has(k) || !v) continue;
      const take = v.length > budget.bytes ? v.slice(0, budget.bytes) : v;
      budget.bytes -= take.length;
      out.push(take);
    } else if (v && typeof v === "object") walkResult(v, depth + 1, out, budget);
  }
}

// The text the engine sees for one result, at stage "file". One value per line for the same reason
// toolScanText does it: detector patterns use [^.\n]{0,N} spans, so a match must not be stitched
// together across two unrelated fields.
// The cap is on the COMPOSED text, so the join's own separators have to be inside it: budgeting only
// the harvested values let a result of N fields exceed maxResultBytes by N-1 newlines (measured: 65537
// bytes against a 65536 cap on a single-field result, because the trailing budget slice was taken
// before the join). The final clip is what actually holds the contract; the walk budget is what stops
// us from BUILDING megabytes in order to throw them away.
export function resultScanText(result) {
  if (!result || typeof result !== "object") return "";
  const out = [];
  walkResult(result, 0, out, { nodes: CAPS.maxResultNodes, bytes: CAPS.maxResultBytes });
  return clip(out.join("\n"), CAPS.maxResultBytes);
}

function clip(s, n) { const v = String(s); return v.length > n ? v.slice(0, n) : v; }

function safeJson(v) {
  try { return JSON.stringify(v); } catch { return ""; }
}

// Walk a JSON Schema and collect the model-visible strings plus the structural facts that carry risk
// (defaults and enums — where a "delete everything" default hides behind a benign description).
// Bounded by node count and depth; both are counters, not recursion guards, so a cyclic object cannot
// spin here either.
function walkSchema(node, name, depth, out, budget) {
  if (budget.nodes <= 0 || depth > CAPS.maxSchemaDepth || node == null) return;
  if (Array.isArray(node)) {
    for (const item of node) { if (budget.nodes <= 0) return; walkSchema(item, name, depth + 1, out, budget); }
    return;
  }
  if (typeof node !== "object") return;
  budget.nodes--;

  for (const k of ["description", "title", "$comment"]) {
    if (typeof node[k] === "string" && node[k]) out.push(clip(node[k], CAPS.maxFieldBytes));
  }
  if (Object.prototype.hasOwnProperty.call(node, "default")) out.push(clip(`${name} default ${safeJson(node.default)}`, CAPS.maxFieldBytes));
  if (Array.isArray(node.enum)) out.push(clip(`${name} enum ${safeJson(node.enum)}`, CAPS.maxFieldBytes));

  const props = node.properties;
  if (props && typeof props === "object" && !Array.isArray(props)) {
    const keys = Object.keys(props);
    if (keys.length) out.push(clip(`properties ${keys.join(" ")}`, CAPS.maxFieldBytes));
    for (const k of keys) { if (budget.nodes <= 0) return; walkSchema(props[k], k, depth + 1, out, budget); }
  }
  for (const k of ["items", "additionalProperties", "anyOf", "oneOf", "allOf", "$defs", "definitions", "patternProperties"]) {
    const child = node[k];
    if (child && typeof child === "object") {
      if (Array.isArray(child)) walkSchema(child, name, depth + 1, out, budget);
      else if (k === "$defs" || k === "definitions" || k === "patternProperties") {
        for (const dk of Object.keys(child)) { if (budget.nodes <= 0) return; walkSchema(child[dk], dk, depth + 1, out, budget); }
      } else walkSchema(child, name, depth + 1, out, budget);
    }
  }
}

// The text the engine sees for one tool, at stage "tool". One value per line: detector patterns use
// [^.\n]{0,N} spans, so keeping each field on its own line stops a match from being stitched together
// across two unrelated fields (a false-positive source) while leaving every field intact internally.
export function toolScanText(tool) {
  if (!tool || typeof tool !== "object") return "";
  const out = [];
  for (const k of ["name", "title", "version", "server", "description"]) {
    if (typeof tool[k] === "string" && tool[k]) out.push(clip(tool[k], CAPS.maxFieldBytes));
  }
  const budget = { nodes: CAPS.maxSchemaNodes };
  for (const k of ["inputSchema", "outputSchema", "parameters", "annotations"]) {
    if (tool[k] && typeof tool[k] === "object") walkSchema(tool[k], k, 0, out, budget);
  }
  return clip(out.join("\n"), CAPS.maxToolBytes);
}

// Content-free identity for the cross-call baseline. fileFingerprint (unkeyed SHA-256, 16 hex chars)
// and NOT contentHash: contentHash is HMAC-keyed off the enrollment token and returns one constant
// sentinel on an UNENROLLED device, which would make every description hash identically and silently
// stop drift from ever firing. That failure mode is documented at cli/content-hash.mjs's
// fileFingerprint — this is exactly the case it exists for.
export function toolIdentity(tool, server) {
  const schema = safeJson({
    input: tool.inputSchema ?? null,
    output: tool.outputSchema ?? null,
    parameters: tool.parameters ?? null,
    annotations: tool.annotations ?? null
  });
  return {
    key: fileFingerprint("mcp-tool:" + String(tool.name)),
    srv: fileFingerprint("mcp-server:" + String(server || "")),
    desc: fileFingerprint(String(tool.description ?? "")),
    schema: fileFingerprint(schema)
  };
}
