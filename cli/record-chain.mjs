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

// The chain metadata lives under a single `chain` key on each record, namespaced so its fields
// (seq/prev/chash/rhash) can never collide with a domain field of the same name — notably `seq`, which
// data/agent-detections.js reads as a per-agent STEP counter and which the chain's global per-log
// sequence must not masquerade as. Excluded when fingerprinting the record's own content.
const CHAIN_KEY = "chain";

// A stable, content-free fingerprint of a log record's own fields (chain metadata excluded), with
// keys sorted so re-serialisation is deterministic. Lets verifyChain detect an in-place field edit.
export function recordRhash(obj) {
  const src = obj && typeof obj === "object" ? obj : {};
  const keys = Object.keys(src).filter((k) => k !== CHAIN_KEY).sort();
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

// Stamp an on-device log record with its chain metadata under the namespaced `chain` key:
// { seq, prev, chash, rhash }. rhash is a fresh content fingerprint of the record (chain excluded);
// the chain link is taken over that rhash. This is what cli/signals.mjs append() writes. `dir` is
// injectable for tests. Never throws — on failure returns the record with a genesis-linked stamp.
export function stampRecord(logKey, obj, { tenant, dir = STATE_DIR } = {}) {
  const rhash = recordRhash(obj);
  const link = nextLink(logKey, rhash, { tenant, dir });
  return { ...obj, [CHAIN_KEY]: { seq: link.seq, prev: link.prev, chash: link.chash, rhash } };
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

// Verify a sequence of stamped records in file order. Each must carry a `chain` sub-object
// { seq, prev, chash, rhash }. Reports every discontinuity: a stored rhash that does not match a fresh
// fingerprint of the record's content (in-place field edit → content_altered), a chash that does not
// recompute (chash_mismatch), a prev that does not match the previous record's chash (reorder /
// insertion → prev_mismatch), and a seq that is not exactly previous+1 (gap = deletion, or
// duplicate/fork → seq_gap / seq_nonmonotonic). Pass { logKey, tenant } to additionally require the
// first record to commit to genesis (a full-stream check); omit it to check internal continuity only,
// which tolerates age/count retention pruning of the head. Pure and content-free — reads only the chain
// metadata and (to recompute rhash) the record's own content-free fields.
export function verifyChain(records, { logKey, tenant } = {}) {
  const breaks = [];
  const anchored = logKey != null;
  let prevChash = anchored ? genesis(logKey, tenant) : null;
  let prevSeq = null;
  for (let idx = 0; idx < records.length; idx++) {
    const r = records[idx] || {};
    const c = r[CHAIN_KEY];
    if (!c || typeof c.chash !== "string" || typeof c.prev !== "string" || !Number.isInteger(c.seq)) {
      breaks.push({ index: idx, seq: c && c.seq != null ? c.seq : null, reason: "unchained" });
      prevChash = null; prevSeq = null; // an unchained row breaks linkage for the next check
      continue;
    }
    if (typeof c.rhash === "string" && recordRhash(r) !== c.rhash) breaks.push({ index: idx, seq: c.seq, reason: "content_altered" });
    if (chainHash(c.prev, c.seq, c.rhash || "") !== c.chash) breaks.push({ index: idx, seq: c.seq, reason: "chash_mismatch" });
    if (prevSeq === null) {
      if (anchored && c.prev !== prevChash) breaks.push({ index: idx, seq: c.seq, reason: "genesis_mismatch" });
    } else {
      if (c.prev !== prevChash) breaks.push({ index: idx, seq: c.seq, reason: "prev_mismatch" });
      if (c.seq !== prevSeq + 1) breaks.push({ index: idx, seq: c.seq, reason: c.seq <= prevSeq ? "seq_nonmonotonic" : "seq_gap" });
    }
    prevChash = c.chash; prevSeq = c.seq;
  }
  return { ok: breaks.length === 0, count: records.length, breaks };
}
