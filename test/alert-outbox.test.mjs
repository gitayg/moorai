// The alert outbox (cli/alert-outbox.mjs): bounded, content-free store-and-forward for console alerts.
//
//   node --test --import ./test/hermetic-env.mjs test/alert-outbox.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, existsSync, readdirSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OUTBOX_FILE, OUTBOX_STATE_FILE, MAX_ENTRIES, MAX_BYTES, MAX_ENTRY_BYTES, MAX_AGE_MS, TRIM_TO, BATCH_MAX, CAPTURE_FIELDS,
  outboxEntry, enqueueAlerts, claimOutboxFlush, readOutboxState, flushAlertOutbox, outboxPosture, takeDropReport, importLegacyJobs
} from "../cli/alert-outbox.mjs";
import { CAPTURE_FIELDS as TIER_FIELDS } from "../data/capture-tiers.js";
import { recordRhash } from "../cli/record-chain.mjs";
import { CONSOLE_BACKOFF, BACKOFF_BASE_MS } from "../cli/console-backoff.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const fresh = () => mkdtempSync(join(tmpdir(), "moorai-outbox-"));
const CONFIG = { serverUrl: "http://console.invalid", installToken: "tok-outbox", tenant: "acme" };
const alert = (seq, extra = {}) => ({ threatId: 2, category: "Indirect prompt injection", riskLevel: "Blocked", stage: "file", tool: "Bash", ts: "2026-10-21T09:14:07.123Z", contentHash: "h2:abc", user: "u", device: "d", ...(seq ? { seq, chainHead: "a".repeat(64) } : {}), ...extra });
const lines = (dir) => { try { return readFileSync(join(dir, OUTBOX_FILE), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };

// A fake fetch: `answer(url, body)` returns { status, json } (or throws for "no answer"). Records every call.
function fakeFetch(answer) {
  const calls = [];
  const f = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push({ url, body, headers: opts.headers });
    const a = await answer(url, body, calls.length);
    if (a === "drop") throw new TypeError("fetch failed");
    return { ok: a.status >= 200 && a.status < 300, status: a.status, json: async () => a.json, text: async () => JSON.stringify(a.json ?? null) };
  };
  f.calls = calls;
  return f;
}
const ackAll = (status = "stored") => (url, body) => ({ status: 200, json: { v: 1, results: body.alerts.map((a, i) => ({ i, seq: a.seq ?? null, oid: a.delivery.oid, status, id: 1000 + i })) } });

test("CAPTURE_FIELDS: every capture-tier field above content-free except the tool name", () => {
  const all = [...new Set(Object.values(TIER_FIELDS).flat())].filter((k) => k !== "toolName").sort();
  assert.deepEqual([...CAPTURE_FIELDS].sort(), all);
  assert.equal(MAX_ENTRIES, 5000);
  assert.equal(MAX_BYTES, 4 * 1024 * 1024);
  assert.equal(MAX_ENTRY_BYTES, 16 * 1024);
  assert.equal(MAX_AGE_MS, 30 * 86400000);
});

test("outboxEntry: capture fields stripped, rhash = recordRhash of the original minus seq and chainHead", () => {
  const a = alert(7, { matchText: "AKIA-SECRET", filePath: "/home/u/.aws/credentials", cmdShape: "cat [1 args]", argText: "x", toolName: "Bash" });
  const e = outboxEntry(a, { via: "deferred", now: 1000 });
  for (const k of CAPTURE_FIELDS) assert.equal(k in e.alert, false, k);
  assert.equal(e.alert.toolName, "Bash");
  assert.equal(e.captureStripped, true);
  const { seq, chainHead, ...orig } = a;
  assert.equal(e.rhash, recordRhash(orig));
  assert.equal(e.seq, 7);
  assert.equal(e.via, "deferred");
  assert.match(e.oid, /^[0-9a-f]{32}$/);
  assert.ok(!JSON.stringify(e).includes("AKIA-SECRET") && !JSON.stringify(e).includes(".aws"));
  const plain = outboxEntry(alert(8), { via: "direct-failed" });
  assert.equal(plain.captureStripped, false);
  assert.equal("rhash" in plain, false);
  assert.equal(outboxEntry(alert(0), {}).seq, null);
  assert.equal(outboxEntry(alert(9, { pad: "x".repeat(MAX_ENTRY_BYTES) }), {}), null);
});

test("flush: a 500 keeps both and backs off about a minute; a batch ack removes both", async () => {
  const dir = fresh();
  try {
    const t = Date.now();
    enqueueAlerts([alert(1), alert(2)], { via: "deferred", dir, now: t });
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: fakeFetch(() => ({ status: 500 })), now: () => t });
    assert.equal(r.status, "rejected");
    assert.equal(r.httpStatus, 500);
    assert.equal(lines(dir).length, 2);
    const st = readOutboxState(dir);
    assert.equal(st.retryAt, t + BACKOFF_BASE_MS);
    assert.equal(lines(dir)[0].attempts, 1);
    // Inside the retry window an attempted entry is not re-sent.
    const early = fakeFetch(ackAll());
    assert.equal((await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: early, now: () => t + 1000 })).status, "empty");
    assert.equal(early.calls.length, 0);
    const f = fakeFetch(ackAll());
    const ok = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f, now: () => t + BACKOFF_BASE_MS + 1 });
    assert.equal(ok.status, "posted");
    assert.equal(ok.posted, 2);
    assert.equal(lines(dir).length, 0);
    assert.equal(readOutboxState(dir).retryAt, 0);
    assert.equal(readOutboxState(dir).lastDeliveredSeq, 2);
    const sent = f.calls[0];
    assert.match(sent.url, /\/api\/alerts\/batch$/);
    assert.equal(sent.headers["X-Install-Token"], "tok-outbox");
    assert.deepEqual(sent.body.alerts.map((a) => a.seq), [1, 2]);
    assert.equal(sent.body.alerts[0].delivery.via, "outbox");
    assert.equal(sent.body.alerts[0].delivery.attempt, 2);
    assert.match(sent.body.alerts[0].delivery.queuedAt, /^\d{4}-\d\d-\d\dT/);
  } finally { rmTree(dir); }
});

test("flush: no answer at all keeps the entries and reads unreachable", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1)], { via: "deferred", dir });
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: fakeFetch(() => "drop") });
    assert.equal(r.status, "unreachable");
    assert.equal(lines(dir).length, 1);
  } finally { rmTree(dir); }
});

test("flush: partial results remove only the acked entry; rejected leaves, counted with its seq range", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1), alert(2), alert(3)], { via: "deferred", dir });
    const f = fakeFetch((url, body) => ({ status: 200, json: { v: 1, results: [
      { i: 0, seq: 1, oid: body.alerts[0].delivery.oid, status: "duplicate", id: 5 },
      { i: 2, seq: 3, oid: body.alerts[2].delivery.oid, status: "rejected", error: "threatId required" }
    ] } }));
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f });
    assert.equal(r.duplicates, 1);
    assert.equal(r.rejected, 1);
    assert.deepEqual(lines(dir).map((e) => e.seq), [2]);
    const st = readOutboxState(dir);
    assert.equal(st.dropped.rejected, 1);
    assert.deepEqual(st.droppedRanges, [[3, 3]]);
  } finally { rmTree(dir); }
});

test("flush: an ack naming a seq or oid that was not sent removes nothing", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1), alert(2)], { via: "deferred", dir });
    const f = fakeFetch(() => ({ status: 200, json: { v: 1, results: [
      { i: 0, seq: 999, oid: "f".repeat(32), status: "stored" },
      { i: 1, seq: 1, status: "stored" },
      { i: 7, seq: 2, status: "stored" }
    ] } }));
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f });
    assert.equal(f.calls.length, 1);
    assert.deepEqual(lines(dir).map((e) => e.seq), [1, 2]);
    // A result naming neither, or naming the right seq with another entry's oid, removes nothing either
    // (sent after the retry window, so the entries really go out again).
    const g = fakeFetch((url, body) => ({ status: 200, json: { v: 1, results: [
      { i: 0, status: "stored" },
      { i: 1, seq: 2, oid: body.alerts[0].delivery.oid, status: "stored" }
    ] } }));
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: g, now: () => Date.now() + 10 * 60000 });
    assert.equal(g.calls.length, 1);
    assert.deepEqual(lines(dir).map((e) => e.seq), [1, 2]);
  } finally { rmTree(dir); }
});

test("flush: 404 on the batch route falls back to single POSTs and remembers it for 24 h", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1), alert(2), alert(3)], { via: "deferred", dir });
    const f = fakeFetch((url, body) => url.endsWith("/batch") ? { status: 404 } : body.seq === 2 ? { status: 400, json: { ok: false, error: "bad" } } : { status: 201, json: { ok: true, id: 1 } });
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f });
    assert.equal(r.mode, "single");
    assert.equal(lines(dir).length, 0);
    assert.equal(readOutboxState(dir).dropped.rejected, 1);
    assert.equal(f.calls.filter((c) => c.url.endsWith("/api/alerts")).length, 3);
    enqueueAlerts([alert(4)], { via: "deferred", dir });
    const g = fakeFetch(() => ({ status: 201, json: { ok: true } }));
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: g });
    assert.equal(g.calls.length, 1);
    assert.ok(g.calls[0].url.endsWith("/api/alerts"), "the batch route is not probed again within 24 h");
    // A 401 / 5xx on the single route keeps the entry.
    enqueueAlerts([alert(5)], { via: "deferred", dir });
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: fakeFetch(() => ({ status: 401 })) });
    assert.deepEqual(lines(dir).map((e) => e.seq), [5]);
  } finally { rmTree(dir); }
});

test("flush: a 2xx without a results array is not an acknowledgement; the worker posts one at a time", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1), alert(2)], { via: "deferred", dir });
    const f = fakeFetch((url) => (url.endsWith("/batch") ? { status: 200, json: {} } : { status: 201, json: { ok: true } }));
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f });
    assert.equal(r.mode, "single");
    assert.equal(r.posted, 2);
    assert.equal(lines(dir).length, 0);
    assert.deepEqual(f.calls.map((c) => c.url.replace(/^.*\/api/, "/api")), ["/api/alerts/batch", "/api/alerts", "/api/alerts"]);
  } finally { rmTree(dir); }
});

test("dedup: the same seq twice is one entry; unnumbered entries dedup by oid", () => {
  const dir = fresh();
  try {
    const a = enqueueAlerts([alert(5)], { via: "deferred", dir });
    const b = enqueueAlerts([alert(5)], { via: "direct-failed", dir });
    assert.equal(a.queued, 1);
    assert.equal(b.queued, 0);
    assert.equal(b.duplicates, 1);
    const e1 = outboxEntry(alert(0), { via: "deferred", oid: "1".repeat(32) });
    const e2 = outboxEntry(alert(0), { via: "deferred", oid: "1".repeat(32) });
    assert.equal(enqueueAlerts([e1.alert], { via: "deferred", dir, oids: [e1.oid] }).queued, 1);
    assert.equal(enqueueAlerts([e2.alert], { via: "deferred", dir, oids: [e2.oid] }).duplicates, 1);
    assert.equal(enqueueAlerts([alert(0)], { via: "deferred", dir }).queued, 1, "a fresh unnumbered alert gets its own oid");
    assert.equal(lines(dir).length, 3);
  } finally { rmTree(dir); }
});

test("full: MAX_ENTRIES + 1 trims the oldest, counts them in dropped.full with their seqs, keeps the newest", () => {
  const dir = fresh();
  try {
    const batch = Array.from({ length: MAX_ENTRIES }, (_, i) => alert(i + 1));
    enqueueAlerts(batch, { via: "deferred", dir });
    assert.equal(lines(dir).length, MAX_ENTRIES);
    const r = enqueueAlerts([alert(MAX_ENTRIES + 1)], { via: "deferred", dir });
    const kept = lines(dir);
    const keepN = Math.floor(MAX_ENTRIES * TRIM_TO);
    assert.ok(r.trimmed >= MAX_ENTRIES - keepN, `trimmed ${r.trimmed}`);
    assert.equal(kept[kept.length - 1].seq, MAX_ENTRIES + 1, "the newest is kept");
    assert.equal(kept[0].seq, r.trimmed + 1, "the oldest went");
    const st = readOutboxState(dir);
    assert.equal(st.dropped.full, r.trimmed);
    assert.deepEqual(st.droppedRanges, [[1, r.trimmed]]);
    assert.equal(st.count, kept.length);
  } finally { rmTree(dir); }
});

test("bytes bound: a 4 MiB outbox trims by size too", () => {
  const dir = fresh();
  try {
    const big = (s) => alert(s, { pad: "p".repeat(12000) });
    const n = Math.ceil(MAX_BYTES / 12200) + 5;
    for (let i = 1; i <= n; i += 50) enqueueAlerts(Array.from({ length: Math.min(50, n - i + 1) }, (_, k) => big(i + k)), { via: "deferred", dir });
    const st = readOutboxState(dir);
    assert.ok(st.bytes <= MAX_BYTES, `${st.bytes}`);
    assert.ok(st.dropped.full > 0);
    assert.equal(lines(dir).at(-1).seq, n);
  } finally { rmTree(dir); }
});

test("age, oversize and malformed lines are counted, never silent", async () => {
  const dir = fresh();
  try {
    const t = 2_000_000_000_000;
    enqueueAlerts([alert(1)], { via: "deferred", dir, now: t - MAX_AGE_MS - 1000 });
    enqueueAlerts([alert(2)], { via: "deferred", dir, now: t - MAX_AGE_MS + 60000 });
    const over = enqueueAlerts([alert(3, { pad: "z".repeat(MAX_ENTRY_BYTES) })], { via: "deferred", dir, now: t });
    assert.equal(over.oversize, 1);
    appendFileSync(join(dir, OUTBOX_FILE), "{torn\n");
    const f = fakeFetch(ackAll());
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f, now: () => t });
    assert.equal(r.droppedAged, 1);
    assert.deepEqual(f.calls[0].body.alerts.map((a) => a.seq), [2], "the aged entry is not sent; the one just inside the window is");
    const st = readOutboxState(dir);
    assert.equal(st.dropped.aged, 1);
    assert.equal(st.dropped.oversize, 1);
    assert.equal(st.dropped.full, 1, "the malformed line");
    assert.deepEqual(st.droppedRanges, [[1, 1], [3, 3]]);
  } finally { rmTree(dir); }
});

test("an outbox deleted from outside resyncs the counts", () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1), alert(2)], { via: "deferred", dir });
    assert.equal(readOutboxState(dir).count, 2);
    rmSync(join(dir, OUTBOX_FILE));
    assert.equal(outboxPosture({ dir }).pending, 0);
    assert.equal(claimOutboxFlush({ dir }), false, "nothing to flush");
    enqueueAlerts([alert(3)], { via: "deferred", dir });
    assert.equal(readOutboxState(dir).count, 1);
  } finally { rmTree(dir); }
});

test("lease: single-flight; a retryAt within the cap waits, one a day ahead is ignored", () => {
  const dir = fresh();
  try {
    const t = 2_000_000_000_000;
    enqueueAlerts([alert(1)], { via: "deferred", dir, now: t });
    assert.equal(claimOutboxFlush({ dir, now: t }), true);
    assert.equal(claimOutboxFlush({ dir, now: t + 10 }), false, "lease held");
    const st = JSON.parse(readFileSync(join(dir, OUTBOX_STATE_FILE), "utf8"));
    writeFileSync(join(dir, OUTBOX_STATE_FILE), JSON.stringify({ ...st, lease: 0, retryAt: t + 120000, pickAt: t + 1 }));
    assert.equal(claimOutboxFlush({ dir, now: t + 2 }), false, "retry within the cap waits");
    enqueueAlerts([alert(2)], { via: "deferred", dir, now: t + 3 });
    assert.equal(claimOutboxFlush({ dir, now: t + 4 }), true, "an entry queued after the last pick is sent at once");
    writeFileSync(join(dir, OUTBOX_STATE_FILE), JSON.stringify({ ...readOutboxState(dir), lease: 0, retryAt: t + 120000, pickAt: t + 5 }));
    assert.equal(claimOutboxFlush({ dir, now: t, force: true }), true, "force ignores the retry time");
    // Every entry already attempted (pickAt after the last enqueue), so only the retry time can hold a claim.
    writeFileSync(join(dir, OUTBOX_STATE_FILE), JSON.stringify({ ...readOutboxState(dir), lease: 0, retryAt: t + 86400000, pickAt: t + 5 }));
    assert.equal(claimOutboxFlush({ dir, now: t + 6 }), true, "a retryAt a day ahead was not written by this module");
    writeFileSync(join(dir, OUTBOX_STATE_FILE), JSON.stringify({ ...readOutboxState(dir), lease: t + 86400000, retryAt: 0 }));
    assert.equal(claimOutboxFlush({ dir, now: t + 6 }), true, "a lease in the future is not one this module wrote");
  } finally { rmTree(dir); }
});

test("a first attempt never waits for an earlier entry's back-off; the retry does", async () => {
  const dir = fresh();
  try {
    const t = Date.now();
    enqueueAlerts([alert(1)], { via: "deferred", dir, now: t });
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: fakeFetch(() => ({ status: 503 })), now: () => t });
    assert.ok(readOutboxState(dir).retryAt > t);
    enqueueAlerts([alert(2)], { via: "deferred", dir, now: t + 10 });
    assert.equal(claimOutboxFlush({ dir, now: t + 20 }), true);
    const f = fakeFetch(ackAll());
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f, now: () => t + 20 });
    assert.deepEqual(f.calls.map((c) => c.body.alerts.map((a) => a.seq)), [[2], [1]], "the fresh entry first; once the console took it, the retry");
    assert.equal(r.posted, 2);
    assert.deepEqual(lines(dir).map((e) => e.seq), []);
    assert.equal(readOutboxState(dir).lease, 0, "the lease is released");
    // Within one run, after a failed batch, entries queued meanwhile still get their first attempt.
    enqueueAlerts([alert(3)], { via: "deferred", dir, now: t + 30 });
    let n = 0;
    const g = fakeFetch((url, body) => { n++; if (n === 1) enqueueAlerts([alert(4)], { via: "deferred", dir, now: t + 31 }); return { status: 503 }; });
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: g, now: () => t + 40 });
    assert.deepEqual(g.calls.map((c) => c.body.alerts.map((a) => a.seq)), [[3], [4]]);
  } finally { rmTree(dir); }
});

test("a planted hook-console-backoff.json (failedAt = now) does not stop delivery", async () => {
  const dir = fresh();
  try {
    mkdirSync(join(CONSOLE_BACKOFF, ".."), { recursive: true });
    writeFileSync(CONSOLE_BACKOFF, JSON.stringify({ failedAt: Date.now(), failures: 32 }));
    enqueueAlerts([alert(1)], { via: "deferred", dir });
    assert.equal(claimOutboxFlush({ dir }), true);
    const f = fakeFetch(ackAll());
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f });
    assert.equal(r.status, "posted");
    assert.equal(f.calls.length, 1);
    assert.equal(lines(dir).length, 0);
  } finally { rmTree(dir); rmSync(CONSOLE_BACKOFF, { force: true }); }
});

test("order: ascending seq, unnumbered by queuedAt after them; batches of at most BATCH_MAX", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(9), alert(0, { k: "u1" })], { via: "deferred", dir, now: 1000 });
    enqueueAlerts([alert(3), alert(0, { k: "u2" })], { via: "deferred", dir, now: 2000 });
    enqueueAlerts(Array.from({ length: BATCH_MAX + 3 }, (_, i) => alert(100 + i)), { via: "deferred", dir, now: 3000 });
    const f = fakeFetch(ackAll());
    const r = await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: f, now: () => 4000 });
    assert.equal(r.batches, 2);
    assert.equal(f.calls[0].body.alerts.length, BATCH_MAX);
    const order = f.calls.flatMap((c) => c.body.alerts.map((a) => a.seq ?? a.k));
    assert.deepEqual(order.slice(0, 3), [3, 9, 100]);
    assert.deepEqual(order.slice(-2), ["u1", "u2"]);
  } finally { rmTree(dir); }
});

test("drop report: deltas since the last report, then null; counters never go down", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1)], { via: "deferred", dir });
    await flushAlertOutbox({ config: CONFIG, dir, fetchImpl: fakeFetch((url, body) => ({ status: 200, json: { results: [{ i: 0, seq: 1, oid: body.alerts[0].delivery.oid, status: "rejected" }] } })) });
    const r = takeDropReport({ dir });
    assert.deepEqual({ ...r, ranges: r.ranges }, { full: 0, aged: 0, rejected: 1, oversize: 0, ranges: [[1, 1]] });
    assert.equal(takeDropReport({ dir }), null);
    const before = readOutboxState(dir).dropped.rejected;
    enqueueAlerts([alert(2, { pad: "q".repeat(MAX_ENTRY_BYTES) })], { via: "deferred", dir });
    assert.equal(takeDropReport({ dir }).oversize, 1);
    assert.equal(readOutboxState(dir).dropped.rejected, before);
  } finally { rmTree(dir); }
});

test("posture: content-free heartbeat object, times rounded down to the hour", () => {
  const dir = fresh();
  try {
    assert.equal(outboxPosture({ dir }).state, "empty");
    const t = Date.parse("2026-10-21T09:47:13.000Z");
    enqueueAlerts([alert(1)], { via: "deferred", dir, now: t });
    const p = outboxPosture({ dir, now: t });
    assert.equal(p.v, 1);
    assert.equal(p.state, "pending");
    assert.equal(p.pending, 1);
    assert.equal(p.oldestQueuedAt, "2026-10-21T09:00:00.000Z");
    assert.deepEqual(p.dropped, { full: 0, aged: 0, rejected: 0, oversize: 0 });
    assert.deepEqual(Object.keys(p).sort(), ["bytes", "dropped", "droppedRanges", "lastDeliveredAt", "lastDeliveredSeq", "oldestQueuedAt", "pending", "state", "v"]);
  } finally { rmTree(dir); }
});

test("legacy alertpost-*.json job files are imported once, then removed", () => {
  const dir = fresh();
  try {
    writeFileSync(join(dir, "alertpost-123-abc.json"), JSON.stringify({ alerts: [alert(41, { matchText: "secret" }), alert(42)] }));
    writeFileSync(join(dir, "alertpost-bad.json"), "{nope");
    const r = importLegacyJobs({ dir });
    assert.equal(r.imported, 2);
    assert.equal(readdirSync(dir).filter((f) => f.startsWith("alertpost-")).length, 0);
    assert.deepEqual(lines(dir).map((e) => e.seq), [41, 42]);
    assert.ok(!readFileSync(join(dir, OUTBOX_FILE), "utf8").includes("secret"));
    assert.equal(importLegacyJobs({ dir }).imported, 0);
  } finally { rmTree(dir); }
});

test("unenrolled: nothing is sent", async () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(1)], { via: "deferred", dir });
    const f = fakeFetch(ackAll());
    assert.equal((await flushAlertOutbox({ config: { serverUrl: "http://x" }, dir, fetchImpl: f })).status, "unenrolled");
    assert.equal(f.calls.length, 0);
    assert.equal(existsSync(join(dir, OUTBOX_FILE)), true);
  } finally { rmTree(dir); }
});

test("enqueue: a DIFFERENT alert reusing a queued seq (counter reset, planted entry) is kept, never dropped as a duplicate; the same alert again still is", () => {
  const dir = fresh();
  try {
    enqueueAlerts([alert(7)], { via: "deferred", dir });
    // Same seq, different alert: the seq counter was reset, or an entry with that seq was planted in the outbox.
    const r = enqueueAlerts([alert(7, { threatId: 54, category: "Secret / credential exposure", ts: "2026-10-21T09:20:00.000Z" })], { via: "deferred", dir });
    assert.equal(r.duplicates, 0, "a colliding seq with different content is not a duplicate");
    assert.equal(r.queued, 1);
    assert.deepEqual(lines(dir).map((e) => [e.seq, e.alert.threatId]), [[7, 2], [7, 54]]);
    assert.equal(readOutboxState(dir).seqCollisions, 1, "the collision is counted locally; the console sees two alerts on one seq and raises its counter-reset finding");
    // The very same alert queued again is still a duplicate.
    assert.equal(enqueueAlerts([alert(7)], { via: "deferred", dir }).duplicates, 1);
    assert.equal(lines(dir).length, 2);
  } finally { rmTree(dir); }
});
