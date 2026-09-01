// Tamper-evident record chain for MoorAI's on-device evidence logs and OTel record stream.
//
// Borrowed from AgentDFIR's hash-chained collection / chain-of-custody log: every record commits to
// the previous one, so deleting, reordering, or inserting a record anywhere in the sequence breaks
// the chain and is detectable — the gap/reorder property record_hash alone could not give.
//
// TWO HASHES, TWO JOBS — do not conflate them:
//   * rhash: a per-record fingerprint. On the OTel stream it is the tenant-KEYED HMAC over the
//     record's content-free fields (cli/otel.mjs canonicalRecord) — it proves AUTHENTICITY, since a
//     SIEM reader without the tenant key cannot forge a record that verifies. On the on-device logs
//     it is recordRhash() below, a plain digest of the stored content-free fields, so verifyChain can
//     also confirm no field was altered in place.
//   * chash: a keyless SHA-256 CHAIN link, sha256(prev_chash | seq | rhash). Proves CONTINUITY —
//     ANYONE, with no key, can verify that no record was dropped, reordered, or inserted, PROVIDED
//     the head has been anchored somewhere the on-device attacker cannot rewrite. Emitting seq+chash
//     into the OTel/SIEM stream is that anchor: the collector already holds the earlier heads, so a
//     later local rewrite is caught by comparison. Keyed/local authenticity per record, keyless
//     continuity across records — complementary, not redundant.
//
// FAIL-OPEN: nothing here may block an enforcement decision or a log write. The head advance is
// best-effort and lock-free; under concurrent short-lived hook processes a rare fork (two records
// sharing a seq/prev) is possible and is surfaced by verifyChain as an anomaly rather than silently
// corrupting the stream — strictly better than dropping a record or serialising the hot path.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";

const sha256hex = (s) => createHash("sha256").update(String(s ?? ""), "utf8").digest("hex");
const chainHash = (prev, seq, rhash) => sha256hex(`${prev}|${seq}|${rhash}`);

// The chain fields a record carries — excluded when fingerprinting the record's own content.
const CHAIN_FIELDS = ["seq", "prev", "chash", "rhash"];

// A stable, content-free fingerprint of a log record's own fields (chain metadata excluded), with
// keys sorted so re-serialisation is deterministic. Lets verifyChain detect an in-place field edit.
export function recordRhash(obj) {
  const src = obj && typeof obj === "object" ? obj : {};
  const keys = Object.keys(src).filter((k) => !CHAIN_FIELDS.includes(k)).sort();
  return sha256hex(JSON.stringify(keys.map((k) => [k, src[k]]))).slice(0, 32);
}

// Distinct genesis per (log, tenant) so an empty chain from one stream can never be replayed as
// another's, and the very first record still commits to a fixed, recomputable anchor.
export function genesis(logKey, tenant) {
  return "g:" + sha256hex(`moorai/chain/${logKey}/${tenant ?? ""}`).slice(0, 24);
}

function headPath(dir, logKey) { return join(dir, `.chain-${logKey}.head.json`); }

function readHead(dir, logKey, tenant) {
  try {
    const h = JSON.parse(readFileSync(headPath(dir, logKey), "utf8"));
    if (h && Number.isInteger(h.seq) && typeof h.chash === "string") return h;
  } catch { /* no head yet → genesis */ }
  return { seq: 0, chash: genesis(logKey, tenant) };
}

function writeHead(dir, logKey, head) {
  try { mkdirSync(dir, { recursive: true }); writeFileSync(headPath(dir, logKey), JSON.stringify(head)); } catch { /* best-effort */ }
}

// Advance `logKey`'s chain by one and return the stamp { seq, prev, chash } to attach to the record.
// `rhash` is the record's fingerprint (keyed authenticity hash on the OTel stream, recordRhash on the
// on-device logs; may be empty on an unenrolled device — the continuity chain still holds). `dir` is
// injectable for tests; production callers take the default STATE_DIR. Never throws.
export function nextLink(logKey, rhash, { tenant, dir = STATE_DIR } = {}) {
  try {
    const head = readHead(dir, logKey, tenant);
    const seq = head.seq + 1;
    const prev = head.chash;
    const chash = chainHash(prev, seq, rhash || "");
    writeHead(dir, logKey, { seq, chash });
    return { seq, prev, chash };
  } catch {
    const g = genesis(logKey, tenant);
    return { seq: 0, prev: g, chash: chainHash(g, 0, rhash || "") };
  }
}

// Verify a sequence of records in file order. Each must carry { seq, prev, chash } (and rhash, folded
// into the recompute). Reports every discontinuity: a chash that does not recompute (record altered),
// a prev that does not match the previous record's chash (reorder / insertion), a seq that is not
// exactly previous+1 (gap = deletion, or duplicate/fork), and — when `rhashOf` is supplied — a stored
// rhash that does not match a fresh fingerprint of the record's content (in-place field edit).
// Pass { logKey, tenant } to additionally require the first record to commit to genesis (a full-stream
// check); omit it to check internal continuity only, which tolerates age/count retention pruning of
// the head. Pure and content-free — reads only chain metadata and (via rhashOf) the record's own
// content-free fields.
export function verifyChain(records, { logKey, tenant, rhashOf } = {}) {
  const breaks = [];
  const anchored = logKey != null;
  let prevChash = anchored ? genesis(logKey, tenant) : null;
  let prevSeq = null;
  for (let idx = 0; idx < records.length; idx++) {
    const r = records[idx] || {};
    if (typeof r.chash !== "string" || typeof r.prev !== "string" || !Number.isInteger(r.seq)) {
      breaks.push({ index: idx, seq: r.seq ?? null, reason: "unchained" });
      prevChash = null; prevSeq = null; // an unchained row breaks linkage for the next check
      continue;
    }
    if (rhashOf && typeof r.rhash === "string" && rhashOf(r) !== r.rhash) breaks.push({ index: idx, seq: r.seq, reason: "content_altered" });
    if (chainHash(r.prev, r.seq, r.rhash || "") !== r.chash) breaks.push({ index: idx, seq: r.seq, reason: "chash_mismatch" });
    if (prevSeq === null) {
      if (anchored && r.prev !== prevChash) breaks.push({ index: idx, seq: r.seq, reason: "genesis_mismatch" });
    } else {
      if (r.prev !== prevChash) breaks.push({ index: idx, seq: r.seq, reason: "prev_mismatch" });
      if (r.seq !== prevSeq + 1) breaks.push({ index: idx, seq: r.seq, reason: r.seq <= prevSeq ? "seq_nonmonotonic" : "seq_gap" });
    }
    prevChash = r.chash; prevSeq = r.seq;
  }
  return { ok: breaks.length === 0, count: records.length, breaks };
}
