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
// unlocked read-increment-write cycles would hand out the same seq. The advance holds an exclusive lock
// file (open "wx") for the few file operations it takes; a lock older than LOCK_STALE_MS is a crashed
// holder and is broken. If the lock cannot be had within LOCK_WAIT_MS the alert is still stamped (an
// alert is never held back for this), which can at worst produce one duplicate seq. Never throws.
import { openSync, closeSync, unlinkSync, statSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { nextLink, recordRhash } from "./record-chain.mjs";

export const ALERT_CHAIN = "alerts";
const LOCK_WAIT_MS = 200;
const LOCK_STALE_MS = 5000;
const SLEEP = new Int32Array(new SharedArrayBuffer(4));
const nap = (ms) => { try { Atomics.wait(SLEEP, 0, 0, ms); } catch { /* best-effort */ } };

function withLock(dir, fn) {
  const lock = join(dir, `.chain-${ALERT_CHAIN}.lock`);
  let fd = null;
  const until = Date.now() + LOCK_WAIT_MS;
  try { mkdirSync(dir, { recursive: true }); } catch { /* the advance below fails open */ }
  while (fd === null) {
    try { fd = openSync(lock, "wx"); break; } catch (e) {
      if (!e || e.code !== "EEXIST") break;
      try { if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) { unlinkSync(lock); continue; } } catch { continue; }
      if (Date.now() >= until) break;
      nap(2);
    }
  }
  try { return fn(); } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* closed */ } try { unlinkSync(lock); } catch { /* gone */ } }
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
