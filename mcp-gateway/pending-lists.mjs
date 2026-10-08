// The tools/list requests a route forwarded upstream whose answer the gateway has not yet judged. The
// MCP SDK client dispatches every message by its id, whatever response carries it, so while one is
// outstanding ANY response on the route can carry its answer (server.mjs onUpstream decodes and scans,
// or clears the drift verdicts). An entry goes when a well-formed message answering its id is judged
// (take), after PENDING_LIST_TTL_MS, or, oldest first, when more than PENDING_LIST_MAX are outstanding.
// An entry that expires or is evicted unanswered calls onDrop: the gateway can no longer see that
// listing's answer, so server.mjs clears the route's drift verdicts (fail closed).
export const PENDING_LIST_MAX = 1024;
export const PENDING_LIST_TTL_MS = 5 * 60 * 1000;

// An id as the MCP SDK client matches it: Number(response.id) against its own numeric request ids
// (shared/protocol.js _onresponse), so "1", "1.0", 1.0 and "01" are all id 1. An id that is not a finite
// number never matches an SDK request; it is kept as its string.
export function idKey(id) {
  const n = Number(id);
  return Number.isFinite(n) ? n : String(id);
}

export function createPendingLists({ max = PENDING_LIST_MAX, ttlMs = PENDING_LIST_TTL_MS, now = Date.now, onDrop = () => {} } = {}) {
  const entries = new Map(); // seq → { k, exp, paged }, oldest first
  const byId = new Map();    // idKey(id) → Set of seq, oldest first
  let seq = 0;
  const del = (s) => {
    const e = entries.get(s);
    entries.delete(s);
    const set = byId.get(e.k);
    set.delete(s);
    if (!set.size) byId.delete(e.k);
    return e;
  };
  function prune() {
    const t = now();
    let dropped = 0;
    for (const [s, e] of entries) {
      if (e.exp > t && entries.size <= max) break;
      del(s);
      dropped++;
    }
    if (dropped) { try { onDrop(dropped); } catch { /* governance, not a sandbox */ } }
  }
  return {
    add(id, { paged = false } = {}) {
      const k = idKey(id);
      const s = ++seq;
      entries.set(s, { k, exp: now() + ttlMs, paged });
      if (!byId.has(k)) byId.set(k, new Set());
      byId.get(k).add(s);
      prune();
    },
    // the oldest outstanding listing with this id is answered → its { paged }, or null when none was
    take(id) {
      prune();
      const set = byId.get(idKey(id));
      if (!set) return null;
      return { paged: del(set.values().next().value).paged };
    },
    get(id) {
      prune();
      const set = byId.get(idKey(id));
      return set ? { paged: entries.get(set.values().next().value).paged } : null;
    },
    sweep() { prune(); },
    any() { prune(); return entries.size > 0; },
    get size() { prune(); return entries.size; }
  };
}
