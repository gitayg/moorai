// Console back-off: after the hook's policy fetch gets NO HTTP response from the console (timeout,
// refused, DNS failure), later invocations usually skip the network for a bounded window instead of paying
// the 1.5s fetch timeout on every tool call. Policy resolution is unchanged: cache, then last-known-good,
// then the offline default, exactly as after a failed fetch.
//
// The state file sits next to the policy cache (~/.moorai), at the same trust level: the governed agent
// can write it, and nothing on the device can tell a file a hook wrote after a real failure from one the
// agent planted. So the file is only ever allowed to DELAY work, never to cancel it:
//   - Policy fetch: a malformed file or a failure time in the FUTURE is ignored, the window is measured from
//     the recorded failure time and capped at BACKOFF_CAP_MS, and even inside the window one call in
//     FORCED_FETCH_ONE_IN fetches anyway (backoffSkipsFetch). The draw comes from this process's own
//     crypto RNG, so a file rewritten before every call still leaves the policy refreshed every eighth call
//     on average, and a console that answers clears the file on that call.
//   - Alerts: the file has no say. A call that got no HTTP answer of its own (it skipped the fetch, or its
//     fetch failed) hands its alert posts to a detached worker instead of waiting on them
//     (cli/moorai-hook.mjs deferAlerts), so the decision path stays fast and every alert is still sent.
// Any HTTP response at all resets the window.
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import { randomInt } from "node:crypto";
import { statePath } from "./state-dirs.mjs";

export const CONSOLE_BACKOFF = statePath("hook-console-backoff.json");
export const BACKOFF_BASE_MS = 60000;
export const BACKOFF_CAP_MS = 300000;
export const FORCED_FETCH_ONE_IN = 8;

export function backoffDelay(failures) {
  const n = Math.max(1, Math.min(32, failures | 0));
  return Math.min(BACKOFF_BASE_MS * 2 ** (n - 1), BACKOFF_CAP_MS);
}

// { active, failures } — failures is the count to carry forward into the next failure.
export function readConsoleBackoff(now = Date.now(), path = CONSOLE_BACKOFF) {
  let s;
  try { s = JSON.parse(readFileSync(path, "utf8")); } catch { return { active: false, failures: 0 }; }
  const at = s && s.failedAt, failures = s && s.failures;
  if (!Number.isFinite(at) || !Number.isInteger(failures) || failures < 1 || at > now) return { active: false, failures: 0 };
  return { active: now - at < backoffDelay(failures), failures };
}

// → true when this call may skip the policy fetch: the window is active and this call did not draw the
// forced fetch. `draw` returns an integer in [0, FORCED_FETCH_ONE_IN); 0 means fetch.
export function backoffSkipsFetch(backoff, draw = () => randomInt(FORCED_FETCH_ONE_IN)) {
  return !!(backoff && backoff.active) && draw() !== 0;
}

export function recordConsoleFailure(prevFailures, now = Date.now(), path = CONSOLE_BACKOFF) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ failedAt: now, failures: Math.min(32, (prevFailures | 0) + 1) }));
  } catch { /* best-effort: without it the next call simply retries */ }
}

export function clearConsoleBackoff(path = CONSOLE_BACKOFF) {
  try { rmSync(path, { force: true }); } catch { /* best-effort */ }
}
