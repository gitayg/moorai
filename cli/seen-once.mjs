// "Report this once": true when `key` was recorded less than `ttl` ms ago, otherwise records it now and
// returns false. ttl = Infinity means once for as long as the record is kept. Records older than 7 days
// are dropped and at most 400 are kept, so a key can come back after a week. A key with no record is
// never "seen": the old inline version read a missing key as recorded at time 0, and 0 is less than
// Infinity ago, so a once-only alert (a local exception granted or ignored) never posted.
// read() returns the stored object (or null); write(obj) stores it. Any error counts as seen, so a
// broken state file costs a report, never a flood of them.
export const SEEN_KEEP_MS = 7 * 86400000;
export const SEEN_MAX = 400;

export function seenOnce(key, ttl = Infinity, { read, write, now = Date.now() }) {
  try {
    const st = read() || {};
    const last = Number(st[key]);
    if (Number.isFinite(last) && last > 0 && now - last < ttl) return true;
    const out = Object.fromEntries(Object.entries(st).filter(([, v]) => now - Number(v) < SEEN_KEEP_MS).slice(-SEEN_MAX));
    out[key] = now;
    write(out);
    return false;
  } catch { return true; }
}
