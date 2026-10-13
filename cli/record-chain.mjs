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
// lock-free here; under concurrent short-lived hook processes a rare fork (two records sharing a
// seq/prev) is possible and is surfaced by verifyChain as an anomaly rather than silently corrupting
// the stream — strictly better than dropping a record or serialising the hot path. The alert chain
// takes its own lock around the advance (cli/alert-seq.mjs).
//
// THE HEAD IS THE ONLY MEMORY OF THE LAST NUMBER, so a number is handed out only once it is on disk.
// The head is replaced atomically (temp file, fsync, rename, keeping the old file's mode and owner),
// after a copy of the same new head (.prev) is replaced the same way. If either write fails the link
// carries no number (seq 0, linked to genesis), never the number of the head that was not saved. A head
// that exists but does not parse or cannot be read is replaced by its copy, which is never behind it; with
// no good copy either, every link carries no number until the files are repaired. The chain never quietly
// restarts at 1: on the alert chain a reused number is what the console records as a counter reset.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync, fsyncSync, fchmodSync, fchownSync, renameSync, unlinkSync, statSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";

const sha256hex = (s) => createHash("sha256").update(String(s ?? ""), "utf8").digest("hex");
const chainHash = (prev, seq, rhash) => sha256hex(`${prev}|${seq}|${rhash}`);

// The chain metadata lives under a single `chain` key on each record, namespaced so its fields
// (seq/prev/chash/rhash) can never collide with a domain field of the same name — notably `seq`, which
// data/agent-detections.js reads as a per-agent STEP counter and which the chain's global per-log
// sequence must not masquerade as. Excluded when fingerprinting the record's own content.
const CHAIN_KEY = "chain";

// Pure, add-only accessor: return a record's chain sub-object ({ seq, prev, chash, rhash }) or null.
// Single-sources the CHAIN_KEY so callers (e.g. the attestation builder) never hardcode "chain".
export function chainOf(obj) {
  const c = obj && typeof obj === "object" ? obj[CHAIN_KEY] : null;
  return c && typeof c === "object" ? c : null;
}

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
const COPY = ".prev";
// The alert chain's number is sent to the console, which reads a number it already holds as a counter
// reset (cli/alert-seq.mjs ALERT_CHAIN). Its head is fsynced before the rename (the directory is not; see
// writeHead), so a crash never repeats a number. An fsync costs milliseconds (F_FULLFSYNC on macOS), so the
// local log chains, written on every hook event, are replaced atomically but not fsynced: a crash leaves
// their head whole, a power loss can at worst leave it behind, which verifyChain reports as a fork.
const DURABLE = new Set(["alerts"]);
const ABSENT = Symbol("absent");

// The parsed head at `path`, ABSENT when there is no file, or null when one exists but cannot be used.
function loadHead(path) {
  let raw;
  try { raw = readFileSync(path, "utf8"); } catch (e) { return e && e.code === "ENOENT" ? ABSENT : null; }
  try {
    const h = JSON.parse(raw);
    if (h && Number.isSafeInteger(h.seq) && h.seq >= 0 && typeof h.chash === "string") return h;
  } catch { /* torn or not JSON */ }
  return null;
}

// The head to advance from, or null when a head exists and neither it nor its copy can be used.
function readHead(dir, logKey, tenant) {
  const p = headPath(dir, logKey);
  const head = loadHead(p);
  if (head && head !== ABSENT) return head;
  const copy = loadHead(p + COPY);
  if (copy && copy !== ABSENT) return copy;
  return head === ABSENT && copy === ABSENT ? { seq: 0, chash: genesis(logKey, tenant) } : null;
}

// Atomically replaces `path` with `data`, fsynced first when `sync`. `like` is the stat of the file being
// replaced, whose mode and owner the new file keeps. Throws if any step fails, leaving `path` as it was
// and no temp file.
function replaceFile(path, data, like, sync) {
  const tmp = join(dirname(path), `.${process.pid}.tmp${basename(path)}`);
  try {
    try { unlinkSync(tmp); } catch { /* none left by a crashed process with this pid */ }
    writeFileSync(tmp, data, { flag: "wx" });
    const fd = openSync(tmp, "r+");
    try {
      if (like && process.platform !== "win32") {
        fchmodSync(fd, like.mode & 0o777);
        if (process.getuid() === 0) fchownSync(fd, like.uid, like.gid);
      }
      if (sync) fsyncSync(fd);
    } finally { closeSync(fd); }
    renameSync(tmp, path);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* not created */ }
    throw e;
  }
}

// Saves the copy, then the head, both holding `head`: the copy is never behind the head (across a power
// loss only the head is guaranteed). Throws on failure.
function writeHead(dir, logKey, head) {
  mkdirSync(dir, { recursive: true });
  const p = headPath(dir, logKey);
  let like = null;
  try { like = statSync(p); } catch { /* first head: default mode */ }
  const data = JSON.stringify(head);
  const sync = DURABLE.has(logKey);
  replaceFile(p + COPY, data, like, false);
  replaceFile(p, data, like, sync);
  // The directory is not fsynced: that second fsync (~4 ms on macOS) doubled the time the alert lock is
  // held and left 8.5% of alerts unnumbered in bursts. A power cut can lose the last rename, so after one
  // the last number may be handed out once more (the console reads it as a counter reset); a process crash
  // cannot, because the file content is fsynced before the rename.
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
// injectable for tests; production callers take the default STATE_DIR. Never throws. When the head
// cannot be read or the advance cannot be saved, the stamp carries no number: seq 0, linked to genesis,
// with `unnumbered` saying which ("head-unreadable" or "head-unsaved").
export function nextLink(logKey, rhash, { tenant, dir = STATE_DIR } = {}) {
  let unnumbered = "head-unreadable";
  try {
    const head = readHead(dir, logKey, tenant);
    if (head) {
      const seq = head.seq + 1;
      const prev = head.chash;
      const chash = chainHash(prev, seq, rhash || "");
      unnumbered = "head-unsaved";
      writeHead(dir, logKey, { seq, chash });
      return { seq, prev, chash };
    }
  } catch { /* reported below */ }
  const g = genesis(logKey, tenant);
  return { seq: 0, prev: g, chash: chainHash(g, 0, rhash || ""), unnumbered };
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
