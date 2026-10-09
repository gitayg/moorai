// The skip alert: a tool call the proxy forwarded to the agent that no framework check matched.
//
// moorai-serve's /v1/tool-call is advisory — it only runs if the framework calls it. With
// --unchecked-window-ms set, the proxy remembers each tool call id it forwarded, as an HMAC under a random
// per-process key (never the id itself), and moorai-serve, given --model-proxy-url, tells the proxy which
// ids it was asked to check (POST /moorai/v1/tool-call-checked, loopback; checked-notify.mjs). A forwarded
// id with no matching check inside the window is reported, content-free (report.mjs uncheckedReporter).
//
// BOUNDED. At most `max` entries (forwarded ids awaiting a check, and checks that arrived before their id
// was recorded — in report mode the bytes reach the agent before the proxy has parsed them). Every entry
// has the same window, so the map is in deadline order: the sweep stops at the first entry not yet due.
// At capacity the oldest entry is dropped; a dropped forwarded id is counted, never reported as unchecked.
import { createHmac, randomBytes } from "node:crypto";

export const DEFAULT_MAX = 8192;
export const MAX_ID = 256;

export function createUncheckedTracker({ windowMs, max = DEFAULT_MAX, onUnchecked, now = () => Date.now() }) {
  const key = randomBytes(32);
  const keyOf = (id) => createHmac("sha256", key).update(id, "utf8").digest("base64");
  const entries = new Map();
  const stats = { forwarded: 0, checked: 0, matched: 0, unchecked: 0, evicted: 0 };
  let evictedPending = 0;
  function put(k, e) {
    if (entries.size >= max) {
      const [oldest, o] = entries.entries().next().value;
      entries.delete(oldest);
      stats.evicted++;
      if (!o.checked) evictedPending++;
    }
    entries.set(k, e);
  }
  function forwarded(id, label) {
    if (typeof id !== "string" || !id || id.length > MAX_ID) return;
    stats.forwarded++;
    const k = keyOf(id), e = entries.get(k);
    if (e && e.checked) { entries.delete(k); stats.matched++; return; }
    if (e) entries.delete(k);
    put(k, { deadline: now() + windowMs, label: String(label || ""), checked: false });
  }
  function checked(id) {
    if (typeof id !== "string" || !id || id.length > MAX_ID) return;
    stats.checked++;
    const k = keyOf(id), e = entries.get(k);
    if (e && !e.checked) { entries.delete(k); stats.matched++; return; }
    if (!e) put(k, { deadline: now() + windowMs, checked: true });
  }
  function sweep() {
    const t = now(), due = new Map();
    for (const [k, e] of entries) {
      if (e.deadline > t) break;
      entries.delete(k);
      if (!e.checked) { stats.unchecked++; due.set(e.label, (due.get(e.label) || 0) + 1); }
    }
    const ev = evictedPending; evictedPending = 0;
    if (due.size || ev) onUnchecked(due, ev);
  }
  const timer = setInterval(sweep, Math.max(50, Math.min(Math.floor(windowMs / 4), 5000)));
  timer.unref();
  return { forwarded, checked, sweep, stop: () => clearInterval(timer), stats: () => ({ ...stats, pending: entries.size }) };
}
