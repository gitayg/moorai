// The alert outbox: bounded, content-free store-and-forward for the alerts the hook hands to the console.
//
// An alert the hook could not deliver on its own invocation goes here: one it deferred because the console
// gave that invocation no HTTP answer (via "deferred"), and one whose direct POST got no answer, a 5xx, a 429,
// a 401 or a 403 (via "direct-failed"; a 400 is deterministic and never retried). A detached worker
// (`moorai-hook.mjs alertpost`) sends the queue in batches (POST /api/alerts/batch, falling back to single
// POSTs on a console without the route, or one whose 2xx carries no per-entry results) and removes an entry only when the console acknowledges it: stored,
// duplicate, or rejected. Nothing here runs on the hook's decision path: the hook appends after its decision
// is written and spawns the worker; it never waits on the network for the outbox.
//
// BOUNDS. MAX_ENTRIES entries, MAX_BYTES on disk, MAX_ENTRY_BYTES per entry, MAX_AGE_MS old. A full outbox
// drops its oldest entries down to TRIM_TO of each bound; an entry older than MAX_AGE_MS is dropped before
// each batch; an entry over MAX_ENTRY_BYTES is never queued; a line that does not parse is removed. Every
// one is counted (dropped.full / aged / oversize / rejected, cumulative, never decreasing) and the seqs of
// the numbered ones go into droppedRanges, so a gap the console sees can be explained. The worker reports
// new drops to the console as one alert ("Alert outbox: entries dropped before delivery").
//
// CONTENT-FREE ON DISK. The capture-tier fields (CAPTURE_FIELDS: what data/capture-tiers.js adds above
// content-free) are removed before an entry is written. The entry then records captureStripped and rhash
// = recordRhash of the alert as stamped (minus seq and chainHead), so the console can still check the
// alert's chain link without the stripped fields.
//
// TRUST. The outbox sits in ~/.moorai, which the governed agent can write: it can delete or edit a queued
// entry. Numbered alerts keep the seq they were given, so a deleted entry reads at the console as a seq gap,
// the same evidence level as cli/alert-seq.mjs. What the agent CANNOT do is delay delivery through the hook's
// console back-off file: this module never reads it (cli/console-backoff.mjs: "Alerts: the file has no
// say"). Its own retryAt and lease are honoured only when they are no further ahead than this module ever
// writes, so a planted value cannot age the queue out.
import { readFileSync, writeFileSync, appendFileSync, statSync, mkdirSync, renameSync, readdirSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { STATE_DIR } from "./state-dirs.mjs";
import { withFileLock } from "./alert-seq.mjs";
import { recordRhash } from "./record-chain.mjs";
import { backoffDelay, BACKOFF_CAP_MS } from "./console-backoff.mjs";

export const OUTBOX_FILE = "alert-outbox.jsonl", OUTBOX_STATE_FILE = "alert-outbox-state.json", OUTBOX_LOCK_FILE = ".alert-outbox.lock";
export const MAX_ENTRIES = 5000, MAX_BYTES = 4 * 1024 * 1024, MAX_ENTRY_BYTES = 16 * 1024, MAX_AGE_MS = 30 * 86400000, TRIM_TO = 0.9;
export const BATCH_MAX = 64, BATCH_BYTES = 256 * 1024, FLUSH_LEASE_MS = 60000, POST_TIMEOUT_MS = 10000, SINGLE_MODE_TTL_MS = 86400000;
export const CAPTURE_FIELDS = Object.freeze(["matchText", "filePath", "cmdShape", "argText"]);
export const MAX_DROPPED_RANGES = 8;
const MAX_BATCHES_PER_RUN = Math.ceil(MAX_ENTRIES / BATCH_MAX) + 1;
const LOCK_WAIT_MS = 200;
const DROP_KINDS = ["full", "aged", "rejected", "oversize"];
const VIAS = ["deferred", "direct-failed"];

const paths = (dir) => ({ queue: join(dir, OUTBOX_FILE), state: join(dir, OUTBOX_STATE_FILE), lock: join(dir, OUTBOX_LOCK_FILE) });
const nonNeg = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
const seqOf = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);
const keyOf = (e) => (e.seq !== null ? `s:${e.seq}` : `o:${e.oid}`);
// What an entry says, apart from where it sits in the chain: two entries with one seq are the same alert only
// when this matches. A different alert on a queued seq (a reset counter, a planted entry) is kept, not dropped.
const sameOf = (e) => { const { seq, chainHead, ...rest } = e.alert || {}; return recordRhash(rest); };
const hourIso = (ms) => (ms > 0 ? new Date(Math.floor(ms / 3600000) * 3600000).toISOString() : null);

function withLock(dir, fn) {
  try { mkdirSync(dir, { recursive: true }); } catch { /* the lock fails too */ }
  const r = withFileLock(paths(dir).lock, fn, { waitMs: LOCK_WAIT_MS, mode: 0o600 });
  return r.held ? r.value : undefined;
}

function counts(o) {
  const out = {};
  for (const k of DROP_KINDS) out[k] = nonNeg(o && o[k]);
  return out;
}
function ranges(v) {
  if (!Array.isArray(v)) return [];
  return v.filter((r) => Array.isArray(r) && r.length === 2 && seqOf(r[0]) && seqOf(r[1]) && r[0] <= r[1]).slice(-MAX_DROPPED_RANGES).map((r) => [r[0], r[1]]);
}
export function readOutboxState(dir = STATE_DIR) {
  let s = {};
  try { s = JSON.parse(readFileSync(paths(dir).state, "utf8")) || {}; } catch { /* fresh */ }
  return {
    count: nonNeg(s.count), bytes: nonNeg(s.bytes), oldest: nonNeg(s.oldest), maxSeq: nonNeg(s.maxSeq),
    lease: nonNeg(s.lease), retryAt: nonNeg(s.retryAt), rejects: nonNeg(s.rejects), freshAt: nonNeg(s.freshAt), pickAt: nonNeg(s.pickAt),
    lastDeliveredSeq: nonNeg(s.lastDeliveredSeq), lastDeliveredAt: nonNeg(s.lastDeliveredAt),
    dropped: counts(s.dropped), droppedRanges: ranges(s.droppedRanges), reported: counts(s.reported), seqCollisions: nonNeg(s.seqCollisions),
    mode: s.mode === "single" ? "single" : "batch", modeAt: nonNeg(s.modeAt)
  };
}
function writeState(dir, st) {
  try { writeFileSync(paths(dir).state, JSON.stringify(st), { mode: 0o600 }); } catch { /* the next call recounts from the file */ }
}

// Merges seqs into the dropped ranges, keeping the MAX_DROPPED_RANGES newest (by seq). Ranges are never
// widened over seqs that were not dropped; an old range that falls off is still counted in dropped.*.
function addRanges(st, seqs) {
  const all = [...st.droppedRanges];
  for (const s of seqs) if (seqOf(s)) all.push([s, s]);
  all.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of all) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  st.droppedRanges = merged.slice(-MAX_DROPPED_RANGES);
}
function drop(st, kind, entries, extra = 0) {
  st.dropped[kind] += entries.length + extra;
  addRanges(st, entries.map((e) => e.seq));
}

function readQueue(dir) {
  let raw = "";
  try { raw = readFileSync(paths(dir).queue, "utf8"); } catch { return { entries: [], bad: 0 }; }
  const entries = [];
  let bad = 0;
  for (const l of raw.split("\n")) {
    if (!l) continue;
    try {
      const e = JSON.parse(l);
      if (e && typeof e === "object" && e.v === 1 && typeof e.oid === "string" && e.alert && typeof e.alert === "object" && !Array.isArray(e.alert)) {
        e.seq = seqOf(e.seq); e.queuedAt = nonNeg(e.queuedAt); e.attempts = nonNeg(e.attempts);
        entries.push(e);
      } else bad++;
    } catch { bad++; }
  }
  return { entries, bad };
}
const lineOf = (e) => JSON.stringify(e) + "\n";
function writeQueue(dir, entries) {
  const { queue } = paths(dir);
  const body = entries.map(lineOf).join("");
  const tmp = `${queue}.${process.pid}.tmp`;
  writeFileSync(tmp, body, { mode: 0o600 });
  renameSync(tmp, queue);
  return Buffer.byteLength(body);
}
const queueSize = (dir) => { try { return statSync(paths(dir).queue).size; } catch { return 0; } };
function settle(st, entries, bytes) {
  st.count = entries.length;
  st.bytes = bytes;
  st.oldest = entries.reduce((m, e) => (m === 0 || (e.queuedAt && e.queuedAt < m) ? e.queuedAt : m), 0);
  st.maxSeq = Math.max(st.maxSeq, ...entries.map((e) => e.seq || 0));
}
// The file is the truth: when its size is not what the state says (deleted, edited, a torn write), the
// counts are taken from the file again and malformed lines are removed and counted.
function resync(dir, st) {
  const size = queueSize(dir);
  if (size === st.bytes) return null;
  const q = readQueue(dir);
  if (q.bad) { st.dropped.full += q.bad; settle(st, q.entries, writeQueue(dir, q.entries)); }
  else settle(st, q.entries, size);
  return q;
}
const leaseHeld = (st, now) => st.lease > 0 && st.lease <= now && now - st.lease < FLUSH_LEASE_MS;
const retryWaits = (st, now) => st.retryAt > now && st.retryAt - now <= BACKOFF_CAP_MS;

// One entry for `alert` as stamped. → the entry, or null when it is still over MAX_ENTRY_BYTES after the
// capture fields are stripped.
export function outboxEntry(alert, { via, now = Date.now(), oid } = {}) {
  if (!alert || typeof alert !== "object" || Array.isArray(alert)) return null;
  const copy = { ...alert };
  delete copy.delivery;
  let stripped = false;
  for (const k of CAPTURE_FIELDS) if (k in copy) { delete copy[k]; stripped = true; }
  const e = {
    v: 1,
    oid: typeof oid === "string" && /^[0-9a-f]{32}$/.test(oid) ? oid : randomBytes(16).toString("hex"),
    seq: seqOf(alert.seq),
    queuedAt: now,
    via: VIAS.includes(via) ? via : "deferred",
    attempts: 0,
    lastAttemptAt: 0,
    captureStripped: stripped
  };
  if (stripped) {
    const { seq, chainHead, delivery, ...orig } = alert;
    e.rhash = recordRhash(orig);
  }
  e.alert = copy;
  return Buffer.byteLength(lineOf(e)) > MAX_ENTRY_BYTES ? null : e;
}

// Queues alerts (already stamped). `oids` (optional, same order): a fixed oid per alert, so a re-import
// dedups. → { queued, duplicates, trimmed, oversize, flushDue: false }. Never throws.
export function enqueueAlerts(alerts, { via, dir = STATE_DIR, now = Date.now(), oids } = {}) {
  const out = { queued: 0, duplicates: 0, trimmed: 0, oversize: 0, flushDue: false };
  try {
    const list = Array.isArray(alerts) ? alerts : [];
    if (!list.length) return out;
    withLock(dir, () => {
      const st = readOutboxState(dir);
      let q = resync(dir, st);
      const entries = [];
      for (let i = 0; i < list.length; i++) {
        const e = outboxEntry(list[i], { via, now, oid: Array.isArray(oids) ? oids[i] : undefined });
        if (!e) { out.oversize++; st.dropped.oversize++; addRanges(st, [seqOf(list[i] && list[i].seq)]); continue; }
        entries.push(e);
      }
      // Dedup by seq (oid when unnumbered). A seq above every seq this outbox has held cannot be queued, and
      // a random oid is fresh, so the file is only read when one could be.
      const needRead = entries.some((e) => (e.seq !== null && e.seq <= st.maxSeq) || (Array.isArray(oids) && e.seq === null));
      const have = new Map();
      const hold = (e) => { const k = keyOf(e); if (!have.has(k)) have.set(k, new Set()); have.get(k).add(sameOf(e)); };
      if (needRead) { q = q || readQueue(dir); for (const e of q.entries) hold(e); }
      const fresh = [];
      for (const e of entries) {
        const seen = have.get(keyOf(e));
        if (seen && seen.has(sameOf(e))) { out.duplicates++; continue; }
        if (seen && e.seq !== null) st.seqCollisions++;
        hold(e);
        fresh.push(e);
      }
      if (!fresh.length) { writeState(dir, st); return; }
      st.freshAt = Math.max(st.freshAt, now); // an entry never attempted: the next claim may send it at once
      const add = fresh.map(lineOf).join("");
      const len = Buffer.byteLength(add);
      if (st.count + fresh.length > MAX_ENTRIES || st.bytes + len > MAX_BYTES) {
        const all = readQueue(dir);
        if (all.bad) st.dropped.full += all.bad;
        const pool = [...all.entries, ...fresh];
        const keepN = Math.floor(MAX_ENTRIES * TRIM_TO), keepB = Math.floor(MAX_BYTES * TRIM_TO);
        let i = Math.max(0, pool.length - keepN);
        let bytes = pool.slice(i).reduce((n, e) => n + Buffer.byteLength(lineOf(e)), 0);
        while (i < pool.length - 1 && bytes > keepB) bytes -= Buffer.byteLength(lineOf(pool[i++]));
        const gone = pool.slice(0, i), kept = pool.slice(i);
        drop(st, "full", gone);
        out.trimmed = gone.length + all.bad;
        out.queued = fresh.filter((e) => kept.includes(e)).length;
        settle(st, kept, writeQueue(dir, kept));
      } else {
        // st matches the file here (resync above), so the running totals stay exact.
        appendFileSync(paths(dir).queue, add, { mode: 0o600 });
        if (!st.count) st.oldest = now;
        st.count += fresh.length;
        st.bytes += len;
        st.maxSeq = Math.max(st.maxSeq, ...fresh.map((e) => e.seq || 0));
        out.queued = fresh.length;
      }
      writeState(dir, st);
    });
  } catch { /* the local audit log still holds every finding */ }
  return out;
}

// Takes the flush lease when something is queued, no worker holds it, and either the retry time (when it is
// one this module could have written) has passed or an entry was queued after the last batch was picked: an
// alert's first attempt never waits for the back-off of earlier ones; only a retry does. force: ignore the
// retry time and clear it. → true: spawn the worker.
export function claimOutboxFlush({ dir = STATE_DIR, now = Date.now(), force = false } = {}) {
  try {
    return withLock(dir, () => {
      const st = readOutboxState(dir);
      resync(dir, st);
      if (!st.count || leaseHeld(st, now)) return false;
      if (!force && retryWaits(st, now) && !(st.freshAt > st.pickAt)) return false;
      if (force) st.retryAt = 0;
      st.lease = now;
      writeState(dir, st);
      return true;
    }) === true;
  } catch { return false; }
}

const sortForSend = (entries) => [
  ...entries.filter((e) => e.seq !== null).sort((a, b) => a.seq - b.seq),
  ...entries.filter((e) => e.seq === null).sort((a, b) => a.queuedAt - b.queuedAt)
];
// The queued entries in send order (ascending seq, then unnumbered by queuedAt), read without the lock and
// without changing anything: the device bundle copies, it never removes.
export function readOutboxEntries(dir = STATE_DIR) {
  return sortForSend(readQueue(dir).entries);
}
function wireAlert(e) {
  return { ...e.alert, delivery: { v: 1, via: "outbox", oid: e.oid, attempt: e.attempts + 1, queuedAt: new Date(e.queuedAt || 0).toISOString(), captureStripped: e.captureStripped === true, ...(e.captureStripped === true && typeof e.rhash === "string" ? { rhash: e.rhash } : {}) } };
}

async function postJson(fetchImpl, url, token, body) {
  try {
    const r = await fetchImpl(url, { method: "POST", headers: { "Content-Type": "application/json", "X-Install-Token": token }, body: JSON.stringify(body), signal: AbortSignal.timeout(POST_TIMEOUT_MS) });
    let json = null;
    try { json = await r.json(); } catch { json = null; }
    return { status: r.status, json };
  } catch { return { status: 0, json: null }; }
}

// The console's per-entry answers for one batch → Map(oid -> "stored" | "duplicate" | "rejected"). A result
// counts only when its index names an entry of this batch and it names that entry's oid or seq; anything
// else is ignored, so a console cannot acknowledge an entry it was not sent.
function readResults(batch, json) {
  const out = new Map();
  const results = json && Array.isArray(json.results) ? json.results : [];
  for (const r of results) {
    if (!r || typeof r !== "object" || !Number.isSafeInteger(r.i) || r.i < 0 || r.i >= batch.length) continue;
    const e = batch[r.i];
    const byOid = typeof r.oid === "string" && r.oid === e.oid;
    const bySeq = e.seq !== null && Number.isSafeInteger(r.seq) && r.seq === e.seq;
    if (!byOid && !bySeq) continue;
    if ((r.oid !== undefined && r.oid !== null && r.oid !== e.oid) || (r.seq !== undefined && r.seq !== null && r.seq !== e.seq)) continue;
    if (r.status === "stored" || r.status === "duplicate" || r.status === "rejected") out.set(e.oid, r.status);
  }
  return out;
}

// The detached worker's body. Sends the outbox until nothing eligible is left. Inside the retry window (a
// batch failed less than backoffDelay(rejects) ago), and after a batch of this run fails, only entries never
// attempted are sent: a retry waits for its back-off, a first attempt does not. A batch the console does
// not take, or takes only in part, keeps what is left (attempts + 1) for the retry. Never reads the hook's
// back-off file. The lease is released in the same locked step that finds nothing left to send, so an
// entry queued after that step is claimed by the call that queued it.
export async function flushAlertOutbox({ config, dir = STATE_DIR, fetchImpl = globalThis.fetch, now = () => Date.now() } = {}) {
  const out = { posted: 0, duplicates: 0, rejected: 0, batches: 0, mode: "batch", status: "empty", httpStatus: 0, droppedAged: 0 };
  const token = config && typeof config.installToken === "string" ? config.installToken.trim() : "";
  let failed = false, released = false;
  try {
    if (!token || !config.serverUrl) { out.status = "unenrolled"; return out; }
    const base = String(config.serverUrl).replace(/\/+$/, "");
    let freshOnly = retryWaits(readOutboxState(dir), now());
    for (let b = 0; b < MAX_BATCHES_PER_RUN; b++) {
      const t = now();
      const picked = withLock(dir, () => {
        const st = readOutboxState(dir);
        const q = readQueue(dir);
        const cutoff = t - MAX_AGE_MS;
        const aged = q.entries.filter((e) => e.queuedAt < cutoff);
        const kept = q.entries.filter((e) => !(e.queuedAt < cutoff));
        if (aged.length || q.bad) {
          drop(st, "aged", aged);
          st.dropped.full += q.bad;
          settle(st, kept, writeQueue(dir, kept));
          out.droppedAged += aged.length;
        }
        const batch = [];
        let bytes = 0;
        for (const e of sortForSend(kept)) {
          if (freshOnly && e.attempts > 0) continue;
          const len = Buffer.byteLength(JSON.stringify(wireAlert(e)));
          if (batch.length && (batch.length >= BATCH_MAX || bytes + len > BATCH_BYTES)) break;
          batch.push(e); bytes += len;
        }
        if (batch.length) { st.lease = t; st.pickAt = t; } // still running: keep the lease ours
        else { st.lease = 0; released = true; }
        writeState(dir, st);
        return { batch, single: st.mode === "single" && t - st.modeAt < SINGLE_MODE_TTL_MS };
      });
      if (!picked) { if (!out.posted && !failed) out.status = "locked"; break; }
      const { batch } = picked;
      if (!batch.length) { if (!out.posted && !out.rejected && !out.duplicates && !failed) out.status = "empty"; break; }
      const acks = new Map();
      let status = 0, single = picked.single;
      if (!single) {
        const r = await postJson(fetchImpl, `${base}/api/alerts/batch`, token, { v: 1, alerts: batch.map(wireAlert) });
        status = r.status;
        // 404 / 405: a console before the batch route. A 2xx that carries no results array is not a batch
        // acknowledgement either (a console or proxy answering every POST alike): post one at a time.
        if (status === 404 || status === 405) single = true;
        else if (status >= 200 && status < 300) {
          if (r.json && typeof r.json === "object" && Array.isArray(r.json.results)) for (const [k, v] of readResults(batch, r.json)) acks.set(k, v);
          else single = true;
        }
      }
      if (single) {
        out.mode = "single";
        for (const e of batch) {
          const r = await postJson(fetchImpl, `${base}/api/alerts`, token, wireAlert(e));
          status = r.status;
          const ok = status >= 200 && status < 300;
          if (ok) acks.set(e.oid, r.json && r.json.duplicate === true ? "duplicate" : "stored");
          else if (status === 400) acks.set(e.oid, "rejected");
          else break;
        }
      }
      out.httpStatus = status;
      const done = batch.filter((e) => acks.has(e.oid));
      const all = done.length === batch.length;
      withLock(dir, () => {
        const st = readOutboxState(dir);
        if (single && !(st.mode === "single" && now() - st.modeAt < SINGLE_MODE_TTL_MS)) { st.mode = "single"; st.modeAt = now(); }
        const q = readQueue(dir);
        const remove = new Set(done.map((e) => e.oid));
        const sentLeft = new Set(batch.filter((e) => !remove.has(e.oid)).map((e) => e.oid));
        const kept = [];
        for (const e of q.entries) {
          if (remove.has(e.oid)) continue;
          if (sentLeft.has(e.oid)) { e.attempts += 1; e.lastAttemptAt = now(); }
          kept.push(e);
        }
        st.dropped.full += q.bad;
        const rejected = done.filter((e) => acks.get(e.oid) === "rejected");
        drop(st, "rejected", rejected);
        const delivered = done.filter((e) => acks.get(e.oid) !== "rejected");
        if (delivered.length) {
          st.lastDeliveredSeq = Math.max(st.lastDeliveredSeq, ...delivered.map((e) => e.seq || 0));
          st.lastDeliveredAt = now();
        }
        if (all) { st.rejects = 0; st.retryAt = 0; }
        else { st.rejects = Math.min(32, st.rejects + 1); st.retryAt = now() + backoffDelay(st.rejects); }
        settle(st, kept, writeQueue(dir, kept));
        writeState(dir, st);
      });
      for (const e of done) {
        const a = acks.get(e.oid);
        if (a === "stored") out.posted++;
        else if (a === "duplicate") out.duplicates++;
        else out.rejected++;
      }
      if (done.length) out.batches++;
      if (!all) { failed = true; freshOnly = true; out.status = done.length ? "posted" : status ? "rejected" : "unreachable"; continue; }
      if (!failed) { out.status = "posted"; freshOnly = false; } // the console took a whole batch: retries may go now
    }
  } catch { out.status = "error"; }
  finally {
    // Not after the step above released it: a call may already have claimed the lease again since.
    if (!released) { try { withLock(dir, () => { const st = readOutboxState(dir); st.lease = 0; writeState(dir, st); }); } catch { /* the lease runs out */ } }
  }
  return out;
}

// The alertOutbox object of the posture heartbeat (POST /api/agent-posture). Content-free counts; the two
// times are rounded down to the hour, like posture lastActive.
export function outboxPosture({ dir = STATE_DIR, now = Date.now() } = {}) {
  let st = readOutboxState(dir);
  try { withLock(dir, () => { const s = readOutboxState(dir); if (resync(dir, s)) writeState(dir, s); st = s; }); } catch { /* the state as read */ }
  const near = st.count >= Math.floor(MAX_ENTRIES * TRIM_TO) || st.bytes >= Math.floor(MAX_BYTES * TRIM_TO);
  const state = !st.count ? "empty" : near ? "full" : st.rejects > 0 ? "retrying" : "pending";
  return { v: 1, state, pending: st.count, bytes: st.bytes, oldestQueuedAt: st.count ? hourIso(st.oldest) : null, lastDeliveredSeq: st.lastDeliveredSeq || null, lastDeliveredAt: hourIso(st.lastDeliveredAt), dropped: { ...st.dropped }, droppedRanges: st.droppedRanges.map((r) => [...r]) };
}

// New drops since the last report, and marks them reported. → null, or { full, aged, rejected, oversize,
// ranges } (deltas, plus the current dropped ranges).
export function takeDropReport({ dir = STATE_DIR } = {}) {
  try {
    return withLock(dir, () => {
      const st = readOutboxState(dir);
      const d = {};
      let any = false;
      for (const k of DROP_KINDS) { d[k] = Math.max(0, st.dropped[k] - st.reported[k]); if (d[k]) any = true; }
      if (!any) return null;
      st.reported = { ...st.dropped };
      writeState(dir, st);
      return { ...d, ranges: st.droppedRanges.map((r) => [...r]) };
    }) ?? null;
  } catch { return null; }
}

// Job files a hook before 1.27.0 wrote for its alertpost worker (`alertpost-*.json`, { alerts }), moved
// into the outbox and removed. The oid is derived from the file name and index, so a file read twice (a
// crash between the enqueue and the unlink) dedups. → { imported, files }.
export function importLegacyJobs({ dir = STATE_DIR, prefix = "alertpost-", now = Date.now() } = {}) {
  const out = { imported: 0, files: 0 };
  let names = [];
  try { names = readdirSync(dir).filter((f) => f.startsWith(prefix) && f.endsWith(".json")); } catch { return out; }
  for (const f of names) {
    const p = join(dir, f);
    let alerts = [];
    try { const j = JSON.parse(readFileSync(p, "utf8")); if (Array.isArray(j && j.alerts)) alerts = j.alerts.filter((a) => a && typeof a === "object" && !Array.isArray(a)); } catch { alerts = []; }
    const oids = alerts.map((_, i) => createHash("sha256").update(`${f}|${i}`).digest("hex").slice(0, 32));
    const r = alerts.length ? enqueueAlerts(alerts, { via: "deferred", dir, now, oids }) : { queued: 0 };
    out.imported += r.queued;
    out.files++;
    try { unlinkSync(p); } catch { /* removed elsewhere */ }
  }
  return out;
}
