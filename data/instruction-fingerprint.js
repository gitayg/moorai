// Content-free fingerprints of the protected instruction files (CLAUDE.md, AGENTS.md, rules files) and
// the test "does this text reproduce a substantial part of one of them". Browser-safe (no node:
// imports); the file discovery, key and on-disk cache live in cli/instruction-fingerprints.mjs.
//
// A FINGERPRINT is a bounded set of 40-bit HMAC-SHA-256 values (data/keyed-hash.js) of the file's
// normalized 7-word shingles. No text is kept: not the shingles, not the file, not a line of it.
//   * normalized: NFKC, lower-cased, markdown/punctuation dropped, JSON and %-escapes undone, so a
//     payload that carries the file inside a JSON string or a URL still lines up word for word.
//   * distinctive only: a shingle with fewer than 3 non-stopword tokens is skipped, and the BOILERPLATE
//     lines tool templates put in thousands of repos (the /init header, "use TypeScript"-grade generics)
//     are cut out before shingling. Two repos sharing template lines therefore share nothing here.
//   * bounded: at most MAX_KEPT hashes per file, chosen as the bottom-k (smallest) values. Bottom-k is a
//     consistent sample, so "matched / kept" stays an unbiased estimate of the reproduced fraction of a
//     file of any size, and the stored set can never exceed MAX_KEPT * files.
//
// A HIT needs BOTH a floor on reproduced volume and a meaningful share of one file, or a large absolute
// volume (a long file reproduced in part). A quoted line or two is below the floor by construction.

import { makeKeyedHash } from "./keyed-hash.js";

export const SHINGLE = 7;
export const MAX_KEPT = 2048;
export const MIN_TEXT_CHARS = 160;
export const MAX_TEXT_CHARS = 262144;
// Tuned on test/instruction-leak.test.mjs's hand-made positives and hard negatives — see the report.
export const THRESHOLDS = { absLo: 40, frac: 0.3, absHi: 200 };

const STOP = new Set(("a an and are as at be been but by can could did do does done for from had has have " +
  "he her here his how i if in into is it its just me more most my no not of on once only or other our " +
  "out over own same she should so some such than that the their them then there these they this those " +
  "through to too under until up very was we were what when where which while who whom why will with " +
  "would you your yours all any both each few again against about above after before below between " +
  "during off further also always never use using make sure must don t s").split(" "));

// Lines tool templates stamp into many repos. Their shingles are excluded from every fingerprint, so a
// reply that repeats them matches nothing. Plain text here is fine: it is public template text, and it
// is used only to BUILD an exclusion set in memory — nothing derived from it is written anywhere.
const BOILERPLATE = [
  "This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.",
  "This file provides guidance to Codex when working with code in this repository.",
  "This file provides guidance to Gemini CLI when working with code in this repository.",
  "These instructions are for AI assistants working in this project.",
  "Always use TypeScript for new code and follow the existing code style.",
  "Run the tests before committing and make sure the build passes.",
  "Use conventional commits for commit messages.",
  "Do not commit secrets, API keys or credentials to the repository.",
  "Prefer small, focused functions and descriptive variable names.",
  "Write unit tests for new features and bug fixes."
];

// JSON / shell escapes and %-encoding are undone first so text inside a JSON string, a URL query or an
// echo -e argument tokenizes the same way as the file itself.
function unescape(text) {
  let t = text;
  if (/\\[nrtu"\\/]/.test(t)) t = t.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/\\[nrt]/g, " ").replace(/\\(["\\/])/g, "$1");
  if (/%[0-9a-fA-F]{2}/.test(t)) t = t.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => { try { return decodeURIComponent(m); } catch { return " "; } }).replace(/\+/g, " ");
  return t;
}

export function tokenize(text) {
  const t = unescape(String(text)).normalize("NFKC").toLowerCase();
  return t.match(/[\p{L}\p{N}]+/gu) || [];
}

// Boilerplate token runs, removed before shingling. Removing (rather than skipping the lines' own
// shingles) matters: two template lines in a row form shingles that span BOTH, which no per-line
// exclusion catches, and a template line followed by real content must not glue onto it either.
const BOILER_SEQS = BOILERPLATE.map((l) => tokenize(l));
function stripBoilerplate(tok) {
  const cut = new Uint8Array(tok.length);
  for (const b of BOILER_SEQS) {
    for (let i = 0; i + b.length <= tok.length; i++) {
      if (tok[i] !== b[0]) continue;
      let j = 1;
      while (j < b.length && tok[i + j] === b[j]) j++;
      if (j === b.length) cut.fill(1, i, i + b.length);
    }
  }
  return cut;
}

// Distinct distinctive shingles of `text`, as strings. In memory only. A shingle never spans a removed
// boilerplate run.
export function shingles(text, k = SHINGLE) {
  const tok = tokenize(text);
  const cut = stripBoilerplate(tok);
  const out = new Set();
  let run = 0;
  for (let i = 0; i < tok.length; i++) {
    run = cut[i] ? 0 : run + 1;
    if (run < k) continue;
    const s = i - k + 1;
    let content = 0;
    for (let j = s; j <= i; j++) if (!STOP.has(tok[j]) && tok[j].length > 1) content++;
    if (content < 3) continue;
    out.add(tok.slice(s, i + 1).join(" "));
  }
  return out;
}

// Build one file's fingerprint. `hash` is makeKeyedHash(key). Returns only numbers.
export function fingerprintText(text, hash, { maxKept = MAX_KEPT } = {}) {
  const hs = [];
  for (const s of shingles(text)) hs.push(hash(s));
  const uniq = [...new Set(hs)].sort((a, b) => a - b);
  const kept = uniq.slice(0, maxKept);
  return { n: uniq.length, max: uniq.length > maxKept ? kept[kept.length - 1] : null, h: kept };
}

// ---------------------------------------------------------------------------------------------------
// Encoded payload variants the scorer reads itself (the engine's decode pass does not hand ctx to
// refine, so it cannot be relied on): base64 / base64url blobs of 64+ chars, bounded.
// ---------------------------------------------------------------------------------------------------
const B64 = /[A-Za-z0-9+/_-]{64,}={0,2}/g;
const DEC = new TextDecoder("utf-8", { fatal: false });
function decodedVariants(text) {
  const out = [];
  let budget = 131072;
  for (const m of text.matchAll(B64)) {
    if (out.length >= 8 || budget <= 0) break;
    const s = m[0].slice(0, budget).replace(/-/g, "+").replace(/_/g, "/");
    try {
      const bin = atob(s.replace(/=+$/, "").padEnd(Math.ceil(s.replace(/=+$/, "").length / 4) * 4, "="));
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      const dec = DEC.decode(bytes);
      // Only keep decodes that are mostly text; random base64 decodes to control-byte soup.
      const printable = (dec.match(/[\p{L}\p{N}\s.,:;'"()\-#*`]/gu) || []).length;
      if (printable / Math.max(1, dec.length) > 0.85) { out.push(dec); budget -= s.length; }
    } catch { /* not base64 */ }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------
// The runtime set: { hash, sources:[{kind, n, max, set:Set<number>}] }. Registered by the host (the
// hook) or lazily through a loader, so nothing is read or hashed until a scan actually needs it.
// ---------------------------------------------------------------------------------------------------
let REG = null;
let LOADER = null;

export function makeFingerprintSet(key, sources) {
  const hash = makeKeyedHash(key);
  return { hash, sources: sources.filter((s) => s && Array.isArray(s.h) && s.h.length).map((s) => ({ kind: s.kind || "", n: s.n || s.h.length, max: s.max ?? null, set: new Set(s.h) })) };
}

export function setInstructionFingerprints(fp) { REG = fp || null; LOADER = null; }
export function setInstructionFingerprintLoader(fn) { REG = null; LOADER = typeof fn === "function" ? fn : null; }
export function getInstructionFingerprints() {
  if (!REG && LOADER) { const l = LOADER; LOADER = null; try { REG = l() || null; } catch { REG = null; } }
  return REG;
}

// Per-file overlap of `text` with the registered fingerprints. Content-free result.
export function instructionOverlap(text, fp = getInstructionFingerprints()) {
  if (!fp || !fp.sources.length || typeof text !== "string") return [];
  const body = text.length > MAX_TEXT_CHARS ? text.slice(0, MAX_TEXT_CHARS) : text;
  const all = new Set();
  for (const v of [body, ...decodedVariants(body)]) for (const s of shingles(v)) all.add(s);
  const hs = new Set();
  for (const s of all) hs.add(fp.hash(s));
  const out = [];
  for (const src of fp.sources) {
    let m = 0;
    for (const h of hs) if (src.set.has(h)) m++;
    if (!m) continue;
    const frac = m / src.set.size;
    out.push({ kind: src.kind, matched: m, kept: src.set.size, frac, est: Math.round(frac * src.n) });
  }
  return out;
}

export function overlapIsLeak(o, th = THRESHOLDS) {
  return o.est >= th.absHi || (o.est >= th.absLo && o.frac >= th.frac);
}

// The detector predicate. ctx comes from the hook (decideText opts.ctx):
//   ctx.inbound     — content the agent RECEIVED (a fetched page): not a leak by the agent. Silent.
//   ctx.targetPath  — a Write/Edit target; writing INTO a rules file (editing CLAUDE.md, mirroring it
//                     into AGENTS.md) naturally reproduces it. Silent.
export function instructionLeakHit(text, ctx, isRulesPath) {
  if (typeof text !== "string" || text.length < MIN_TEXT_CHARS) return false;
  if (ctx && ctx.inbound) return false;
  if (ctx && ctx.targetPath && isRulesPath && isRulesPath(ctx.targetPath)) return false;
  const fp = getInstructionFingerprints();
  if (!fp) return false;
  return instructionOverlap(text, fp).some((o) => overlapIsLeak(o));
}
