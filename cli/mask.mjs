// The "mask" enforcement action: replace a sensitive span with a content-free placeholder and let the
// call proceed, instead of blocking it.
//
// WHERE IT CAN RUN is decided by the host, not by this file. Claude Code (code.claude.com/docs/en/hooks)
// gives a hook exactly two payload-rewriting powers, and mask uses only those:
//   * PreToolUse  `updatedInput`      — "Modifies the tool's input parameters before execution. Replaces
//                                        the entire input object, so include unchanged fields alongside
//                                        modified ones."
//   * PostToolUse `updatedToolOutput` — "Replaces the tool's output with the provided value before it is
//                                        sent to Claude. The value must match the tool's output shape."
// Both are whole-object replacements validated against the tool's schema, so the rewrite here never
// changes a key, a type or a container: it walks the value and rewrites STRING LEAVES only.
//
// WHAT IS MASKABLE. Only the data-tier threats (data/data-tiers.js: pii, secret, regulated — not
// "source"), because only those name a span whose removal leaves the call meaningful. An injection or a
// destructive command has no span to hide; an org that sets "mask" on one gets that threat's fallback
// (cli/hook-core.mjs threatActionFor). Within those threats, only SPAN detectors are applied: the two
// clipboard detectors carry a data-tier id but match a behaviour (`pbpaste | curl`), not data.
//
// THE PLACEHOLDER IS CONTENT-FREE: `[MOORAI:<tier>:<8 letters>]`. The letters are the first 8 hex digits
// of the device's KEYED content hash of the span (cli/content-hash.mjs), mapped 0-f → a-p so the tag can
// never look like a phone number, a card fragment or a hex key to the very detectors that verify it. No
// character of the span survives, and without the enrollment key the tag cannot be tested against a guess.
//
// VERIFY, DON'T ASSUME. A detector's match can come from the engine's normalisation pass (a secret inside
// base64) or from its score promotion, and neither is a span of the raw text. The caller therefore
// re-scans the masked text and treats ANY surviving finding of a masked threat as a failed mask — which
// falls back to the configured action rather than letting a half-masked payload through as "masked".
import { TIER_OF } from "../data/data-tiers.js";
import { safeRegex } from "../src/safe-regex.js";

export const MASKABLE_TIERS = new Set(["pii", "secret", "regulated"]);
export function isMaskable(threatId) { return MASKABLE_TIERS.has(TIER_OF[threatId]); }

// Behaviour detectors that carry a data-tier threat id. Masking their match would rewrite a command verb.
const NOT_A_SPAN = new Set(["clipboard-read", "clipboard-to-sink"]);

// Bounds on the walk. A rewrite must return the WHOLE value, so unlike the scan (which may clip) an
// over-budget value aborts the mask entirely and the caller falls back. 256 KB of strings keeps the
// regex pass in the low milliseconds; the scan window the detectors saw is 64 KB (mcp-proxy CAPS).
export const MASK_CAPS = { maxBytes: 262144, maxNodes: 4096, maxDepth: 16 };

const LETTERS = "abcdefghijklmnop";
export function placeholder(threatId, span, hash) {
  const hex = String(hash(span) || "").replace(/^h2:/, "").replace(/[^0-9a-f]/g, "");
  const tag = hex ? hex.slice(0, 8).split("").map((c) => LETTERS[parseInt(c, 16)]).join("") : "nokey";
  return `[MOORAI:${TIER_OF[threatId] || "data"}:${tag}]`;
}

function spanDetectors(engine, stage, ids) {
  const want = engine._wantStages(stage);
  return engine.detectors.filter((d) => ids.has(d.threatId) && d.mode !== "coach" && !NOT_A_SPAN.has(d.detectorId) && engine._inStage(d, want));
}

// Every occurrence every span detector of a masked threat accepts, merged, replaced right to left.
function maskString(s, dets, ctx, hash) {
  const spans = [];
  for (const d of dets) {
    for (const p of d.patterns || []) {
      const g = safeRegex(p.source, p.flags.includes("g") ? p.flags : p.flags + "g");
      if (!g) continue;
      let m;
      while ((m = g.exec(s)) !== null) {
        if (!m[0]) { g.lastIndex++; continue; }
        if (!d.refine || d.refine(m[0], s, ctx)) spans.push([m.index, m.index + m[0].length, d.threatId]);
      }
    }
  }
  if (!spans.length) return { text: s, count: 0 };
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged = [];
  for (const sp of spans) {
    const last = merged[merged.length - 1];
    if (last && sp[0] < last[1]) last[1] = Math.max(last[1], sp[1]);
    else merged.push([...sp]);
  }
  let out = s;
  for (let i = merged.length - 1; i >= 0; i--) {
    const [a, b, id] = merged[i];
    out = out.slice(0, a) + placeholder(id, s.slice(a, b), hash) + out.slice(b);
  }
  return { text: out, count: merged.length };
}

// Rewrite the string leaves of `value` (a string, an array or a plain object). Returns
// { value, count, complete }; complete=false means the budget ran out and NOTHING may be emitted.
// `only` optionally names the top-level keys to rewrite (the write family's content fields); every
// other key is copied through untouched.
export function maskValue(engine, value, { stage, ids, ctx, hash, only } = {}) {
  const set = ids instanceof Set ? ids : new Set(ids || []);
  const dets = spanDetectors(engine, stage, set);
  const budget = { bytes: MASK_CAPS.maxBytes, nodes: MASK_CAPS.maxNodes, ok: true };
  let count = 0;
  const walk = (v, depth) => {
    if (!budget.ok) return v;
    if (typeof v === "string") {
      budget.bytes -= v.length;
      if (budget.bytes < 0) { budget.ok = false; return v; }
      const r = maskString(v, dets, ctx, hash);
      count += r.count;
      return r.text;
    }
    if (v === null || typeof v !== "object") return v;
    if (--budget.nodes < 0 || depth > MASK_CAPS.maxDepth) { budget.ok = false; return v; }
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    const o = {};
    for (const k of Object.keys(v)) o[k] = walk(v[k], depth + 1);
    return o;
  };
  let out;
  if (only && value && typeof value === "object" && !Array.isArray(value)) {
    out = { ...value };
    for (const k of only) if (k in value) out[k] = walk(value[k], 1);
  } else out = walk(value, 0);
  return { value: out, count, complete: budget.ok && dets.length > 0 };
}

// The note given to the model (additionalContext) and the user (systemMessage). Content-free: counts and
// threat ids only. It tells the model the tag is not the value, so it does not try to reconstruct it.
export function maskNote(where, count, ids) {
  const list = [...ids].map((id) => `#${id}`).join(", ");
  return `MoorAI: masked ${count} sensitive span${count === 1 ? "" : "s"} (${list}) in ${where}. Each [MOORAI:…] tag stands in for a value that was withheld by policy; it is not the value and cannot be turned back into it — do not try to recover or guess it.`;
}
