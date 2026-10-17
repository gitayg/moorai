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
// PROVENANCE. Who wrote a chunk, when the caller says: `source` is a string (a label, as before) or
// { name?, trust?: "trusted" | "untrusted" | "unknown", kind?: "customer" | "ticket" | "web" | "staff" | … }.
// A chunk from an "untrusted" or "unknown" author that makes a business-value claim (data/business-claims.js:
// a price or discount, a policy change, account or payment details, an authority vouching for it) raises #21
// as detector kb-untrusted-claim, with the claim kinds, under policy.indexProvenance.untrustedClaims:
//   "report" (default)  reported, the chunk kept (verdict "flag")
//   "ask"               held for review (verdict "hold": guardEmbed does not embed it; an MCP vector-store
//                       write becomes an "ask")
//   "block"             refused (verdict "deny"), whatever indexScanAction says
//   "off"               not checked
// A trusted author's claim passes, and a caller that states no trust (a string source, or none) is not
// checked at all: a genuine catalog is full of prices, and only the author tells a forged update from a
// real one. The claim finding never counts as an instruction for indexScanAction "block".
//
// Pure apart from the engine: no I/O, no reporting. The caller reports, content-free.
import { decideText, decideThreat, threatActionFor } from "./hook-core.mjs";
import { promptBlockers } from "./prompt-scan.mjs";
import { businessClaims } from "../data/business-claims.js";

export const INDEX_CHUNK_CAP = 262144;   // characters of one chunk that are scanned (256 KB)
export const INDEX_MAX_CHUNKS = 4096;    // chunks one call may submit
const WALK_NODES = 4096;
const WALK_DEPTH = 8;

export function indexScanAction(policy) {
  return policy && policy.indexScanAction === "block" ? "block" : "report";
}

export const TRUST_LEVELS = Object.freeze(["trusted", "untrusted", "unknown"]);
export const UNTRUSTED_CLAIM_MODES = Object.freeze(["off", "report", "ask", "block"]);
export const CLAIM_DETECTOR = "kb-untrusted-claim";
const KIND = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const SOURCE_KEYS = new Set(["name", "id", "trust", "kind"]);

export function untrustedClaimsMode(policy) {
  const p = policy && policy.indexProvenance;
  const m = p && typeof p === "object" ? p.untrustedClaims : undefined;
  return UNTRUSTED_CLAIM_MODES.includes(m) ? m : "report";
}

// `source` as the caller passed it → { name, trust, kind }. A string is a label with no trust stated (the
// pre-provenance shape). An object's trust outside TRUST_LEVELS is "unknown": the caller did try to state
// one, and an unrecognised value must not read as trusted.
export function indexSource(source) {
  if (typeof source === "string") return { name: source || null, trust: null, kind: null };
  if (!source || typeof source !== "object" || Array.isArray(source)) return { name: null, trust: null, kind: null };
  const name = typeof source.name === "string" && source.name ? source.name : typeof source.id === "string" && source.id ? source.id : null;
  const trust = source.trust == null ? null : TRUST_LEVELS.includes(source.trust) ? source.trust : "unknown";
  const kind = typeof source.kind === "string" && KIND.test(source.kind.toLowerCase()) ? source.kind.toLowerCase() : null;
  return { name, trust, kind };
}

// For a surface that must refuse a malformed request (moorai-serve): "" when `source` is acceptable.
export function indexSourceProblem(source) {
  if (source == null) return "";
  if (typeof source === "string") return source.length > 1024 ? "source must be a string of at most 1024 characters" : "";
  if (typeof source !== "object" || Array.isArray(source)) return "source must be a string or an object { name?, trust?, kind? }";
  for (const k of Object.keys(source)) if (!SOURCE_KEYS.has(k)) return `source.${k.slice(0, 32)} is not a source field (name, id, trust, kind)`;
  for (const k of ["name", "id"]) if (source[k] != null && (typeof source[k] !== "string" || source[k].length > 1024)) return `source.${k} must be a string of at most 1024 characters`;
  if (source.trust != null && !TRUST_LEVELS.includes(source.trust)) return `source.trust must be one of ${TRUST_LEVELS.join(", ")}`;
  if (source.kind != null && (typeof source.kind !== "string" || !KIND.test(source.kind.toLowerCase()))) return "source.kind must be a short word (letters, digits, - and _; at most 32)";
  return "";
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

// The two #21 fact findings name what they saw, so an app can route them apart from an instruction.
const DETAIL = {
  [CLAIM_DETECTOR]: (f) => `business-value claim from ${f.sourceTrust === "untrusted" ? "an untrusted source" : "a source of unknown trust"}`,
  "kb-fact-conflict": () => "conflicting facts in retrieved context"
};
const reasonOf = (f) => (f.threatId > 0 ? `#${f.threatId} ${f.category}${DETAIL[f.detectorId] ? ` (${DETAIL[f.detectorId](f)})` : ""}` : f.category);

// One chunk → { verdict: "allow" | "flag" | "hold" | "deny", action, findings, blockers, reasons, claims }.
// opts.source: the caller's source (indexSource). findings carry the matched span (`match`) for the
// caller's keyed hash; strip it before it leaves.
export function decideIndexChunk(engine, policy, value, opts = {}) {
  const text = chunkText(value);
  const action = indexScanAction(policy);
  const d = decideText(viaIndex(engine), policy, text, "index");
  const findings = d.findings.map((f) => ({ ...f, stage: "index" }));
  const blockers = action === "block" ? promptBlockers(findings, (id) => threatActionFor(policy, id)) : [];
  const src = indexSource(opts.source);
  const mode = untrustedClaimsMode(policy);
  let claims = [], claim = null;
  if (mode !== "off" && (src.trust === "untrusted" || src.trust === "unknown")) {
    claims = businessClaims(text, { detectorIds: findings.map((f) => f.detectorId) });
    // decideThreat resolves #21 through the policy like any finding: "disabled" silences it.
    const t = claims.length ? decideThreat(policy, 21, CLAIM_DETECTOR, "index") : null;
    if (t && t.findings.length) {
      claim = { ...t.findings[0], stage: "index", claims, sourceTrust: src.trust, ...(src.kind ? { sourceKind: src.kind } : {}) };
      findings.push(claim);
      if (mode === "block" || (action === "block" && ["block", "kill"].includes(threatActionFor(policy, 21)))) blockers.push(claim);
    }
  }
  const verdict = blockers.length ? "deny" : claim && mode === "ask" ? "hold" : findings.length ? "flag" : "allow";
  const reasons = [...new Set((blockers.length ? blockers : verdict === "hold" ? [claim] : findings).map(reasonOf))];
  return { verdict, action, findings, blockers, reasons, claims: claim ? claims : [] };
}
