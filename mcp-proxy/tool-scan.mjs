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
  scanBudgetMs: 250      // wall-clock budget for one tools/list response; checked BETWEEN tools
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
