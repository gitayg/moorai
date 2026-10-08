// Per-client cool-down (CONTRACT C5, CLIENT_COOLDOWN): after `refusals` refusals within `windowSeconds`,
// the client's requests are refused for `seconds`. Off unless configured (see config.mjs for why).
//
// What a "client" is, decided by the caller (server.mjs clientKey): the route plus a one-way hash of the
// request's Authorization header when it carries one (the credential the agent presents upstream: one
// per agent or user), else the TCP peer address. A credential on a refused call is never checked by the
// upstream, so a client crafting its own requests could rotate it; each distinct one is therefore also
// counted once at the peer address (refusedOnce), which cools the whole address down. On a loopback
// bind every local client shares 127.0.0.1, which is why the cool-down is off by default. Keys stay in
// this process's memory; nothing about them is reported.
//
// Pure apart from the injectable clock. Bounded: at most MAX_KEYS clients are tracked (oldest dropped).
export const MAX_KEYS = 4096;

export function createCooldown({ refusals = 0, windowSeconds = 60, seconds = 0, now = Date.now } = {}) {
  const enabled = refusals > 0 && seconds > 0 && windowSeconds > 0;
  const hits = new Map();   // key → [refusal times]
  const until = new Map();  // key → cool-down end (ms)
  const touch = (map, k, v) => { map.delete(k); map.set(k, v); if (map.size > MAX_KEYS) map.delete(map.keys().next().value); };

  // Seconds left in this client's cool-down, 0 when none.
  function remaining(key) {
    if (!enabled) return 0;
    const u = until.get(key);
    if (!u) return 0;
    const left = u - now();
    if (left <= 0) { until.delete(key); return 0; }
    return Math.ceil(left / 1000);
  }

  // One refusal by the gateway. → true when it starts a cool-down. Refusals during a cool-down do not
  // extend it, so a client that keeps calling is let back in on time.
  function refused(key) {
    if (!enabled || remaining(key)) return false;
    const t = now();
    const recent = (hits.get(key) || []).filter((x) => t - x < windowSeconds * 1000);
    recent.push(t);
    if (recent.length >= refusals) {
      hits.delete(key);
      touch(until, key, t + seconds * 1000);
      return true;
    }
    touch(hits, key, recent);
    return false;
  }

  // One refusal under `key`, counted once per distinct `sub` within the window. The caller keys a peer
  // address with the credential as `sub`: a client that presents a new Authorization value with every
  // refused call (nothing upstream ever checks one the gateway refuses) still adds up at its peer, while N
  // refusals of ONE credential only cool down that credential. → true when it starts a cool-down.
  const seen = new Map();   // key + sub → when it was last counted
  function refusedOnce(key, sub) {
    if (!enabled) return false;
    const t = now();
    const k = `${key}\u0000${sub}`;
    const at = seen.get(k);
    if (at !== undefined && t - at < windowSeconds * 1000) return false;
    touch(seen, k, t);
    return refused(key);
  }

  // One refusal the gateway made for client `ck` ({ key, peer, cred }, server.mjs clientKey): counted at
  // its key, and once per credential at its peer. → true when it starts a cool-down. A refusal made while
  // the key or the peer is already cooling down is not counted again, at any key: counting it let a
  // cooled-down client fill the bounded tables with fresh credentials until its own entry was evicted.
  function noteRefusal(ck) {
    if (remaining(ck.key) || remaining(ck.peer)) return false;
    const started = refused(ck.key);
    return Boolean(ck.cred && refusedOnce(ck.peer, ck.cred)) || started;
  }

  return { enabled, remaining, refused, refusedOnce, noteRefusal, seconds };
}
