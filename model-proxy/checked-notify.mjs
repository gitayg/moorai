// moorai-serve's side of the skip alert (unchecked.mjs): each toolCallId a /v1/tool-call request carried
// is passed to the model proxy, batched, over loopback: POST <proxy>/moorai/v1/tool-call-checked
// {"toolCallIds": [...]}, with the proxy's token in X-MoorAI-Proxy-Token when it has one.
//
// Fire-and-forget and BOUNDED: at most MAX_QUEUE ids waiting, MAX_BATCH per request, one request in flight,
// a 1500 ms timeout (the reporter's). A dropped or failed batch costs a false "unchecked" alert at the
// proxy, never a verdict: the check itself has already been answered.
export const PATH = "/moorai/v1/tool-call-checked";
export const MAX_BATCH = 256;
export const MAX_QUEUE = 4096;
const FLUSH_MS = 20;

export function createCheckedNotifier({ url, token = "", fetchImpl = globalThis.fetch }) {
  const target = new URL(PATH, url.replace(/\/+$/, "") + "/").href;
  const queue = [];
  const stats = { queued: 0, sent: 0, dropped: 0, failed: 0 };
  let timer = null, inflight = null;
  async function flush() {
    timer = null;
    if (inflight) return inflight;
    while (queue.length) {
      const ids = queue.splice(0, MAX_BATCH);
      inflight = fetchImpl(target, {
        method: "POST",
        headers: { "content-type": "application/json", ...(token ? { "x-moorai-proxy-token": token } : {}) },
        body: JSON.stringify({ toolCallIds: ids }),
        signal: AbortSignal.timeout(1500)
      }).then((r) => { if (r.ok) stats.sent += ids.length; else stats.failed += ids.length; }, () => { stats.failed += ids.length; });
      await inflight;
      inflight = null;
    }
  }
  function note(id) {
    if (queue.length >= MAX_QUEUE) { stats.dropped++; return; }
    queue.push(id);
    stats.queued++;
    if (!timer && !inflight) { timer = setTimeout(flush, FLUSH_MS); timer.unref(); }
  }
  async function close() { if (timer) clearTimeout(timer); await flush(); }
  return { note, close, stats: () => ({ ...stats, waiting: queue.length }) };
}
