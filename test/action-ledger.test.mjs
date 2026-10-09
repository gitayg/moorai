// The action-audit ledger (cli/signals.mjs recordAction / readActions): the write path is append-only
// and compacts (1000-row cap + age prune) only now and then, by temp file + rename. These tests pin the
// guarantees that design has to keep, each as a reader sees them:
//   * the cap and the age prune hold after many writes, and the file on disk stays bounded;
//   * several processes writing at once neither corrupt the file nor lose rows;
//   * a crash in the middle of a compaction, or a torn last line, leaves a log every reader can read;
//   * the cost of a write does not grow with the ledger (the gateway calls recordAction for every
//     refused request on its one event loop; at the cap the old rewrite-every-write path cost ~7 ms,
//     ~39 ms under load, per refusal).
//
//   node --test --import ./test/hermetic-env.mjs test/action-ledger.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, statSync, truncateSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import os from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { rmTree } from "./fs-cleanup.mjs";
import { scalingRatio } from "./timing.mjs";
import { recordAction, readActions } from "../cli/signals.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SIGNALS = pathToFileURL(join(ROOT, "cli", "signals.mjs")).href;
const TRACE = join(ROOT, "cli", "moorai-trace.mjs");
const CAP = 1000;

// A gateway-refusal-shaped row (what recordAction is called with on every refused request).
const row = (i, extra = {}) => ({ threatId: 0, category: "Invalid request", riskLevel: "Blocked", stage: "mcp", tool: "gateway:-", decision: "deny", mcpServer: "remote", ts: new Date().toISOString(), contentHash: "h2:0123456789abcdef0123", user: "u", device: "d", tenant: "t", actor: "a1b2c3d4", n: i, ...extra });
const seedLine = (i, ts = new Date().toISOString()) => JSON.stringify({ ...row(i), ts, chain: { seq: i + 1, prev: "p".repeat(64), chash: "c".repeat(64), rhash: "r".repeat(32) } });

const rawLines = (file) => (existsSync(file) ? readFileSync(file, "utf8").split("\n").filter((l) => l.trim()) : []);
const allParse = (lines) => lines.every((l) => { try { JSON.parse(l); return true; } catch { return false; } });

// In-process ledger: hermetic-env gave this file its own HOME, so signals.mjs resolved ~/.moorai there.
const DIR = join(os.homedir(), ".moorai");
const LIVE = join(DIR, "action-audit.jsonl");
const reset = () => { rmSync(DIR, { recursive: true, force: true }); mkdirSync(DIR, { recursive: true }); };

function freshHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-ledger-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  return { home, env, live: join(home, ".moorai", "action-audit.jsonl") };
}
// Run `body` (module source with `s` = signals.mjs) in a child process under `env`.
const childSrc = (body) => `const s = await import(${JSON.stringify(SIGNALS)});\n${body}`;
function runChild(env, body, extraArgs = []) {
  return spawnSync(process.execPath, [...extraArgs, "--input-type=module", "-e", childSrc(body)], { env, encoding: "utf8", timeout: 60000 });
}

test("ledger: after many writes readers see exactly the newest 1000 rows, and the file stays bounded", () => {
  reset();
  const N = 2600;
  let maxLines = 0;
  for (let i = 0; i < N; i++) {
    recordAction(row(i));
    if (i % 50 === 0) maxLines = Math.max(maxLines, rawLines(LIVE).length);
  }
  const rows = readActions();
  assert.equal(rows.length, CAP);
  assert.deepEqual(rows.map((r) => r.n), Array.from({ length: CAP }, (_, k) => N - CAP + k), "readers must see the newest 1000, in order");
  // Between compactions the file may overshoot the cap; the overshoot must stay bounded (~25 %).
  assert.ok(maxLines <= CAP * 1.3, `the on-disk ledger grew to ${maxLines} rows`);
  assert.ok(allParse(rawLines(LIVE)));
});

test("ledger: rows past the retention age leave the log on the next write, as readers see it", () => {
  const { home, env, live } = freshHome();
  try {
    // ~2.6 s retention: 5 rows, wait past it, 1 more row. Only the last may remain, on disk too.
    const r = runChild({ ...env, MOORAI_RETENTION_DAYS: "0.00003" }, `
      for (let i = 0; i < 5; i++) s.recordAction({ n: i, ts: new Date().toISOString() });
      const a = s.readActions().length;
      await new Promise((ok) => setTimeout(ok, 3000));
      s.recordAction({ n: 5, ts: new Date().toISOString() });
      process.stdout.write(JSON.stringify({ a, b: s.readActions().map((x) => x.n) }));`);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.a, 5);
    assert.deepEqual(out.b, [5], "expired rows survived the next write");
    assert.equal(rawLines(live).length, 1, "expired rows are still on disk");
  } finally { rmTree(home); }
});

test("ledger: concurrent writers in several processes do not corrupt the file or lose rows", async () => {
  const { home, env, live } = freshHome();
  try {
    const W = 4, PER = 250; // 1000 rows in all: exactly the cap, so every row must survive
    const start = Date.now() + 1500;
    const body = (w) => `
      while (Date.now() < ${start}) {}
      for (let i = 0; i < ${PER}; i++) s.recordAction({ w: ${w}, i, ts: new Date().toISOString(), pad: "x".repeat(300) });`;
    const codes = await Promise.all(Array.from({ length: W }, (_, w) => new Promise((ok) => {
      const c = spawn(process.execPath, ["--input-type=module", "-e", childSrc(body(w))], { env, stdio: ["ignore", "ignore", "inherit"] });
      c.on("exit", ok);
    })));
    assert.deepEqual(codes, Array(W).fill(0));
    const lines = rawLines(live);
    assert.ok(allParse(lines), "a line in the ledger is corrupt");
    const rows = lines.map((l) => JSON.parse(l));
    const seen = new Set(rows.map((r) => `${r.w}:${r.i}`));
    assert.equal(seen.size, rows.length, "a row was duplicated");
    const lost = W * PER - seen.size;
    assert.equal(lost, 0, `${lost} of ${W * PER} rows were lost`);
  } finally { rmTree(home); }
});

// Preload for a child: SIGKILL the process half-way through the compaction's rewrite of the log, i.e.
// after writing half of the rows to whichever file the rewrite goes to (the log itself, or a temp file
// beside it). Appends (flag "a") and small writes are let through. It drops a marker file first, so the
// test can tell the crash point was reached on Windows too, where SIGKILL is TerminateProcess with exit
// code 1 and no signal is reported.
const CRASH_PRELOAD = `
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const { openSync, writeSync, writeFileSync } = fs;
const target = (p) => typeof p === "string" && /action-audit\\.jsonl(\\.tmp-\\d+)?$/.test(p);
const die = () => { writeFileSync.call(fs, process.env.CRASH_MARK, "crashed"); process.kill(process.pid, "SIGKILL"); };
const rewrites = new Set();
fs.openSync = function (p, flags, ...rest) { const fd = openSync.call(fs, p, flags, ...rest); if (target(p) && flags === "w") rewrites.add(fd); return fd; };
fs.writeSync = function (fd, buf, ...rest) {
  if (rewrites.has(fd) && buf && buf.length > 4096) { writeSync.call(fs, fd, buf.subarray(0, buf.length >> 1)); die(); }
  return writeSync.call(fs, fd, buf, ...rest);
};
fs.writeFileSync = function (p, data, opts) {
  const flag = (opts && typeof opts === "object" && opts.flag) || "w";
  if (target(p) && flag === "w" && data && data.length > 4096) { writeFileSync.call(fs, p, data.slice(0, data.length >> 1)); die(); }
  return writeFileSync.call(fs, p, data, opts);
};
syncBuiltinESMExports();
`;

test("ledger: a crash in the middle of a compaction leaves a log every reader can read", () => {
  const { home, env, live } = freshHome();
  try {
    const preload = join(home, "crash-preload.mjs");
    writeFileSync(preload, CRASH_PRELOAD);
    writeFileSync(live, Array.from({ length: CAP }, (_, i) => seedLine(i)).join("\n") + "\n");
    // This write takes the ledger past the cap, so it compacts, and the preload kills it mid-rewrite.
    const mark = join(home, "crash-mark");
    const r = runChild({ ...env, CRASH_MARK: mark }, `s.recordAction(${JSON.stringify(row(CAP))});`, ["--import", pathToFileURL(preload).href]);
    assert.ok(existsSync(mark), `the crash point was not reached (status ${r.status}, signal ${r.signal}): ${r.stderr}`);
    if (process.platform === "win32") assert.deepEqual([r.status, r.signal], [1, null], r.stderr);
    else assert.equal(r.signal, "SIGKILL", `status ${r.status}: ${r.stderr}`);
    const lines = rawLines(live);
    assert.ok(allParse(lines), "the crash left a torn line in the log");
    const read = runChild(env, `process.stdout.write(JSON.stringify(s.readActions().map((x) => x.n)));`);
    const ns = JSON.parse(read.stdout);
    assert.equal(ns.length, CAP, `readers see ${ns.length} rows after the crash`);
    assert.equal(ns[ns.length - 1], CAP, "the row written before the crash is gone");

    // The dead compactor left its lock (and maybe a temp file). Writes go on; once the lock is stale the
    // next write compacts back to the cap and clears what the crash left behind.
    assert.equal(runChild(env, `s.recordAction(${JSON.stringify(row(CAP + 1))});`).status, 0);
    const lock = live + ".lock";
    if (existsSync(lock)) utimesSync(lock, new Date(Date.now() - 120000), new Date(Date.now() - 120000));
    assert.equal(runChild(env, `s.recordAction(${JSON.stringify(row(CAP + 2))});`).status, 0);
    const after = rawLines(live);
    assert.ok(allParse(after));
    assert.equal(after.length, CAP, "the next compaction did not bring the log back to the cap");
    assert.equal(JSON.parse(after.at(-1)).n, CAP + 2);
    const left = readdirSync(join(home, ".moorai")).filter((n) => /\.tmp-|\.lock$/.test(n));
    assert.deepEqual(left, [], "the crash's temp file or lock was left behind");
  } finally { rmTree(home); }
});

// A compaction reads the log, closes it and only then renames the compacted copy over it: Windows refuses
// a rename over a file that is open, even by the compactor itself (EPERM, MEASURED on Node 24, so up to
// v1.9.0 the log was never trimmed there). A row appended past the point the compactor read would be lost
// with the old file, so its writer waits for the compaction to end and writes it again if the log was
// replaced and the new log does not hold it. These tests play the compaction by hand around a real
// writer: the lock file names the compactor (pid.start.random), and the rename replaces the log with
// what the compactor read.
const COMPACTED = (n) => Array.from({ length: n }, (_, i) => seedLine(i)).join("\n") + "\n";
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
async function untilTrue(fn, ms = 20000) {
  const end = Date.now() + ms;
  while (!fn()) { if (Date.now() > end) throw new Error("timed out"); await sleep(10); }
}
async function renameRetry(from, to) {
  for (let i = 0; ; i++) {
    try { return renameSync(from, to); } catch (e) { if (e.code !== "EPERM" || i > 200) throw e; await sleep(10); }
  }
}
function lateWriter(env) {
  const t0 = Date.now();
  const c = spawn(process.execPath, ["--input-type=module", "-e", childSrc(`s.recordAction(${JSON.stringify(row(500, { late: true }))});`)], { env, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  c.stderr.on("data", (d) => (stderr += d));
  return new Promise((ok) => c.on("exit", (code) => ok({ code, ms: Date.now() - t0, stderr })));
}
const lates = (live) => rawLines(live).filter((l) => l.includes('"late":true')).length;
// A compaction in flight, held by this (live) process, with ten rows read: the state a writer sees
// between the compactor's read and its rename.
function compactionInFlight(live, pid = process.pid) {
  writeFileSync(live, COMPACTED(10));
  writeFileSync(live + ".lock", `${pid}.${Date.now()}.test`);
  return statSync(live).size; // what the compactor has read
}
// The compactor's rename. `upTo` is how much of the old log it read and carried over.
async function finishCompaction(live, upTo) {
  writeFileSync(live + ".tmp-test", readFileSync(live).subarray(0, upTo));
  await renameRetry(live + ".tmp-test", live);
  rmSync(live + ".lock");
}

test("ledger: a row appended past what a compaction read is written again once the compaction renames", async () => {
  const { home, env, live } = freshHome();
  try {
    const read = compactionInFlight(live);
    const done = lateWriter(env);
    await untilTrue(() => lates(live) === 1); // the row is in the old log, past what the compactor read
    await finishCompaction(live, read);
    const r = await done;
    assert.equal(r.code, 0, r.stderr);
    assert.equal(lates(live), 1, "the row appended during the compaction was lost with the old log");
    assert.ok(allParse(rawLines(live)));
  } finally { rmTree(home); }
});

test("ledger: a row the compaction carried over is not written twice", async () => {
  const { home, env, live } = freshHome();
  try {
    compactionInFlight(live);
    const done = lateWriter(env);
    await untilTrue(() => lates(live) === 1);
    await finishCompaction(live, statSync(live).size); // this compactor read the row too
    const r = await done;
    assert.equal(r.code, 0, r.stderr);
    assert.equal(lates(live), 1, "the row was written twice");
  } finally { rmTree(home); }
});

test("ledger: when the compaction fails instead, the row stays where it landed, once", async () => {
  const { home, env, live } = freshHome();
  try {
    compactionInFlight(live);
    const done = lateWriter(env);
    await untilTrue(() => lates(live) === 1);
    rmSync(live + ".lock"); // the compactor gave up: no rename, no marker
    const r = await done;
    assert.equal(r.code, 0, r.stderr);
    assert.equal(lates(live), 1, "the row was written twice");
    assert.ok(allParse(rawLines(live)), "a failed compaction left a line that is not a row");
  } finally { rmTree(home); }
});

test("ledger: a lock left by a compactor that died does not hold a writer", async () => {
  const { home, env, live } = freshHome();
  try {
    const dead = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
    compactionInFlight(live, Number(dead.stdout));
    const r = await lateWriter(env);
    assert.equal(r.code, 0, r.stderr);
    assert.ok(r.ms < 4000, `the writer waited ${r.ms} ms on the lock of a dead compactor`);
    assert.equal(lates(live), 1);
  } finally { rmTree(home); }
});

test("ledger: a torn last line costs that line only, not the whole log", () => {
  const { home, env, live } = freshHome();
  try {
    // A crash mid-append leaves a fragment with no newline; the next append lands on the same line.
    writeFileSync(live, Array.from({ length: 10 }, (_, i) => seedLine(i)).join("\n") + "\n" + seedLine(10).slice(0, 40));
    const r = runChild(env, `const before = s.readActions().map((x) => x.n);
      s.recordAction(${JSON.stringify(row(11))});
      process.stdout.write(JSON.stringify({ before, after: s.readActions().map((x) => x.n) }));`);
    assert.equal(r.status, 0, r.stderr);
    const { before, after } = JSON.parse(r.stdout);
    const ten = Array.from({ length: 10 }, (_, i) => i);
    assert.deepEqual(before, ten, `readers of the torn log lost the intact rows: ${r.stdout}`);
    assert.deepEqual(after.slice(0, 10), ten, `after the next write readers lost the intact rows: ${r.stdout}`);
    assert.ok(rawLines(live).length >= 10, "the intact rows were wiped from disk");
  } finally { rmTree(home); }
});

test("ledger: moorai-trace keeps the newest 1000 rows when the file overshoots the cap between compactions", () => {
  const { home, env, live } = freshHome();
  try {
    const t0 = Date.now() - 3600000;
    writeFileSync(live, Array.from({ length: 1200 }, (_, i) => seedLine(i, new Date(t0 + i * 1000).toISOString())).join("\n") + "\n");
    const r = spawnSync(process.execPath, [TRACE, "--json", "--limit", "5000"], { env, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const steps = JSON.parse(r.stdout);
    assert.equal(steps.length, CAP, `trace returned ${steps.length} rows from a 1200-row file`);
  } finally { rmTree(home); }
});

test("ledger: the cost of a write does not grow with the ledger (empty vs at the cap)", (t) => {
  reset();
  const META = LIVE + ".compact";
  // Two ledgers, swapped into place by rename (O(1)) around each timed write. The small one is emptied
  // after every write so it stays small; the large one starts at the cap and is left to grow and compact,
  // so its side carries the amortised compaction cost. Each side does the same renames and one truncate.
  const side = (name, lines) => {
    const s = { file: join(DIR, `${name}.jsonl`), meta: join(DIR, `${name}.compact`), scratch: join(DIR, `${name}.scratch`) };
    writeFileSync(s.file, lines.length ? lines.join("\n") + "\n" : "");
    writeFileSync(s.scratch, "");
    return s;
  };
  const small = side("small", []);
  const large = side("large", Array.from({ length: CAP }, (_, i) => seedLine(i)));
  let i = 0;
  const inodes = new Set();
  const write = (s, empty) => () => {
    renameSync(s.file, LIVE); if (existsSync(s.meta)) renameSync(s.meta, META);
    recordAction(row(i++));
    const ino = statSync(LIVE).ino; if (!empty) inodes.add(ino); // a compaction renames a new file in
    renameSync(LIVE, s.file); if (existsSync(META)) renameSync(META, s.meta);
    truncateSync(empty ? s.file : s.scratch, 0);
  };
  // minMs is sized so one sample is several hundred writes: every sample of the large side then spans at
  // least one compaction (one per ~250 rows at this row size), so the best-of cannot pick around it.
  // minReps holds that where a write costs more CPU: on a loaded Windows runner minMs alone left 63 reps.
  const r = scalingRatio(write(small, true), write(large, false), 3, 1000, 500);
  t.diagnostic(`at-cap / empty write cost: ${r.ratio.toFixed(2)}x (${r.small.toFixed(3)} ms vs ${r.large.toFixed(3)} ms CPU, ${r.reps} reps)`);
  assert.ok(r.ratio < 1.5, `a write at the cap costs ${r.ratio.toFixed(2)}x a write to an empty ledger (${r.small.toFixed(3)} ms vs ${r.large.toFixed(3)} ms CPU, ${r.reps} reps)`);
  assert.ok(inodes.size > 3, `the large ledger compacted ${inodes.size - 1} times; the samples did not include the amortised compaction`);
});
