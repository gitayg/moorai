// Content-free reporting to the MoorAI console, from a long-lived process.
//
// The shell hook posts each alert with a 1500 ms timeout and drains them before it exits; a library in an
// SDK service has no exit per call, so posts are fire-and-forget with the same timeout, a bounded queue
// (an unreachable console must not grow memory without limit), and flush() for shutdown. Nothing is sent
// without an install token — the hook's own rule (data/enforcement.js isEnrolled): no enrollment, no
// console.
//
// WHAT LEAVES: threat id, category, risk level, stage, tool name, a keyed hash, the workload identity and
// provenance — never the text, the matched span, a path or an argument, whatever capture tier the policy
// names: this surface sends no capture extras at all.
import { hookCore, provenance } from "./core.mjs";

const { isEnrolled } = hookCore;
const { stampAlert } = provenance;
export const MAX_PENDING = 256;
export const POST_TIMEOUT_MS = 1500;

export function createReporter({ config, identity, fetchImpl = globalThis.fetch, onDrop } = {}) {
  const pending = new Set();
  let dropped = 0, sent = 0;
  const enrolled = isEnrolled(config);
  function post(alert, { prov = {} } = {}) {
    const a = { ...alert, ...identity, ts: new Date().toISOString() };
    stampAlert(a, { ...prov, coach: false, event: prov.event || "PreToolUse" });
    if (!enrolled) return null;
    if (pending.size >= MAX_PENDING) { dropped++; if (onDrop) onDrop(a); return null; }
    const p = fetchImpl(`${config.serverUrl}/api/alerts`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(config.installToken ? { "X-Install-Token": config.installToken } : {}) },
      body: JSON.stringify(a),
      signal: AbortSignal.timeout(POST_TIMEOUT_MS)
    }).then(() => { sent++; }, () => {}).finally(() => pending.delete(p));
    pending.add(p);
    return p;
  }
  async function flush() { while (pending.size) await Promise.allSettled([...pending]); }
  return { post, flush, enrolled, stats: () => ({ pending: pending.size, dropped, sent }) };
}
