// Per-device alert sequence and record-chain head (trust-anchor design, phase 1D).
//
// Every alert the hook hands to the console (posted now, or queued for the detached worker) carries
//   seq        an integer that goes up by exactly one per alert on this device (user scope), and
//   chainHead  the head of a hash chain over those alerts (cli/record-chain.mjs: sha256(prev|seq|rhash),
//              rhash = recordRhash of the alert as stamped, before seq and chainHead are added).
// The console keeps the last seq and head per device, so a gap (an alert that never arrived) or a
// regression (the counter rewound) is visible there.
//
// WHAT THIS CATCHES, AND WHAT IT DOES NOT. The counter and the head live in ~/.moorai, which the agent
// can write. An agent that deletes a queued alert job (~/.moorai/alertpost-*.json) leaves a seq gap the
// console sees. An agent that also rewinds the counter and the head before the next alert goes out leaves
// a regression or a fork, which the console also sees, unless it rewinds them to exactly the last value the
// console received and suppresses everything after. So this is evidence against naive deletion only. The
// guarantee needs state the agent cannot write: the privileged helper (design phase 2/3).
//
// Concurrency: Claude Code runs PreToolUse hooks for parallel tool calls in parallel processes, and two
// unlocked read-increment-write cycles would hand out the same seq, which the console records as a
// counter reset. The advance only ever runs while holding an exclusive lock file (open "wx", holding the
// holder's pid) for the few file operations it takes. A lock is broken only when its holder is gone: older
// than LOCK_STALE_MS with its pid no longer running, or older than LOCK_DEAD_MS whatever it holds (a
// reused pid, or a lock planted by hand). An alert whose stamper cannot get the lock within LOCK_WAIT_MS
// is sent without seq and chainHead: it is never held back, and never given a number another alert holds.
// Never throws.
import { openSync, closeSync, unlinkSync, lstatSync, fstatSync, mkdirSync, readFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { nextLink, recordRhash } from "./record-chain.mjs";

export const ALERT_CHAIN = "alerts";
const LOCK_WAIT_MS = 200;
const LOCK_STALE_MS = 5000;
const LOCK_DEAD_MS = 60000;
const SLEEP = new Int32Array(new SharedArrayBuffer(4));
const nap = (ms) => { try { Atomics.wait(SLEEP, 0, 0, ms); } catch { /* best-effort */ } };
const sameFile = (a, b) => a.ino === b.ino && a.dev === b.dev;

// A lock with no pid yet (its holder is between open and write) counts as held.
function holderAlive(lock) {
  let pid;
  try { pid = Number.parseInt(readFileSync(lock, "utf8"), 10); } catch { return false; }
  if (!Number.isSafeInteger(pid) || pid <= 0) return true;
  try { process.kill(pid, 0); return true; } catch (e) { return !!e && e.code === "EPERM"; }
}

function breakIfAbandoned(lock) {
  try {
    const st = lstatSync(lock);
    const age = Date.now() - st.mtimeMs;
    if (age <= LOCK_STALE_MS || (age <= LOCK_DEAD_MS && holderAlive(lock))) return;
    const now = lstatSync(lock);
    if (sameFile(now, st) && now.mtimeMs === st.mtimeMs) unlinkSync(lock);
  } catch { /* gone already, or not removable: wait it out */ }
}

function acquire(lock) {
  const until = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lock, "wx");
      try { writeSync(fd, String(process.pid)); } catch { /* an empty lock still holds */ }
      return fd;
    } catch (e) {
      if (!e || e.code !== "EEXIST") return null;
    }
    breakIfAbandoned(lock);
    if (Date.now() >= until) return null;
    nap(2);
  }
}

// Runs fn() holding the lock and returns its result, or returns null without running it.
function withLock(dir, fn) {
  const lock = join(dir, `.chain-${ALERT_CHAIN}.lock`);
  try { mkdirSync(dir, { recursive: true }); } catch { /* the open below reports it */ }
  const fd = acquire(lock);
  if (fd === null) return null;
  try { return fn(); } finally {
    let mine = false;
    try { mine = sameFile(fstatSync(fd), lstatSync(lock)); } catch { /* gone */ }
    try { closeSync(fd); } catch { /* closed */ }
    if (mine) { try { unlinkSync(lock); } catch { /* gone */ } }
  }
}

// Stamps `alert` in place with { seq, chainHead } and returns it. `dir` is injectable for tests.
export function stampAlertSeq(alert, { tenant, dir = STATE_DIR } = {}) {
  if (!alert || typeof alert !== "object") return alert;
  try {
    const rhash = recordRhash(alert);
    const link = withLock(dir, () => nextLink(ALERT_CHAIN, rhash, { tenant, dir }));
    if (link && Number.isInteger(link.seq) && link.seq > 0) { alert.seq = link.seq; alert.chainHead = link.chash; }
  } catch { /* evidence, never delivery */ }
  return alert;
}
