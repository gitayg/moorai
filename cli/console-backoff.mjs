// Console back-off: after the hook's policy fetch gets NO HTTP response from the console (timeout,
// refused, DNS failure), later invocations skip the network for a bounded window instead of paying the
// 1.5s fetch timeout (and the alert-post timeout) on every tool call. Policy resolution is unchanged:
// cache, then last-known-good, then the offline default, exactly as after a failed fetch.
//
// The state file sits next to the policy cache (~/.moorai), at the same trust level: the governed agent
// can write it. So it is read defensively: a malformed file or a failure time in the FUTURE is ignored
// (no back-off), and the window is measured from the recorded failure time and capped at BACKOFF_CAP_MS,
// so one write can suppress fetches for at most five minutes. Any HTTP response at all resets it.
//
// `unreachable` records whether a TCP connection to the console could be opened at all (tcpProbe, run
// beside the fetch). Only then are alert posts skipped too: a console that accepts the connection but is
// slow to answer still receives a post the hook gives up waiting on, so those posts keep being sent.
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import { statePath } from "./state-dirs.mjs";

export const CONSOLE_BACKOFF = statePath("hook-console-backoff.json");
export const BACKOFF_BASE_MS = 60000;
export const BACKOFF_CAP_MS = 300000;

export function backoffDelay(failures) {
  const n = Math.max(1, Math.min(32, failures | 0));
  return Math.min(BACKOFF_BASE_MS * 2 ** (n - 1), BACKOFF_CAP_MS);
}

// { active, failures, unreachable } — failures is the count to carry forward into the next failure.
export function readConsoleBackoff(now = Date.now(), path = CONSOLE_BACKOFF) {
  let s;
  try { s = JSON.parse(readFileSync(path, "utf8")); } catch { return { active: false, failures: 0, unreachable: false }; }
  const at = s && s.failedAt, failures = s && s.failures;
  if (!Number.isFinite(at) || !Number.isInteger(failures) || failures < 1 || at > now) return { active: false, failures: 0, unreachable: false };
  return { active: now - at < backoffDelay(failures), failures, unreachable: s.unreachable === true };
}

export function recordConsoleFailure(prevFailures, unreachable, now = Date.now(), path = CONSOLE_BACKOFF) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ failedAt: now, failures: Math.min(32, (prevFailures | 0) + 1), unreachable: unreachable === true }));
  } catch { /* best-effort: without it the next call simply retries */ }
}

// → a promise of true when a TCP connection to the server URL's host and port opens within timeoutMs.
// cancel() settles it at once, so a probe the caller no longer needs never holds the process open.
export function tcpProbe(serverUrl, timeoutMs) {
  let u;
  try { u = new URL(serverUrl); } catch { return Object.assign(Promise.resolve(false), { cancel() {} }); }
  const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  let finish;
  const p = new Promise((resolve) => {
    let done = false;
    const s = net.connect({ host, port });
    finish = (ok) => { if (done) return; done = true; clearTimeout(t); s.destroy(); resolve(ok); };
    const t = setTimeout(() => finish(false), timeoutMs);
    s.once("connect", () => finish(true));
    s.once("error", () => finish(false));
  });
  return Object.assign(p, { cancel: () => finish(false) });
}

export function clearConsoleBackoff(path = CONSOLE_BACKOFF) {
  try { rmSync(path, { force: true }); } catch { /* best-effort */ }
}
