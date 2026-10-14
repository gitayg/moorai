// The allow trail (cli/action-trail.mjs, policy key `actionTrail: "allowed"`) for the model proxy: one
// content-free record per model request the proxy forwarded, so the console's runtime AIBOM sees which
// agent used which model, and how often, and not only the requests that raised an alert.
//
// ON only when the policy is the console-signed policy this device verified (context.mjs VERIFIED_SOURCES:
// a --policy-file or options policy never turns it on, whatever it says), actionTrailMode() reads
// "allowed", and the device is enrolled. Otherwise nothing is queued.
//
// THE RECORD is cli/action-trail.mjs buildActionRecord's and nothing else (its seq from the shared queue,
// under the shared lock, so the hook's records and these are one sequence): event "ModelRequest", tool
// "model-proxy:<provider>", decision "allow", basis "default", the signed policy's iat, agentName
// ("claude-code" when the request names a Claude Code session, else "model-proxy"), MoorAI's version, the
// identity alerts carry, the request's traceId / spanId / parentSpanId, `provider` and `model` (the
// request's model string; the builder validates both and leaves out a value off its enum or shape). Never
// content, a header value, a session id or a hash of either.
//
// DELIVERY is the allow trail's own queue and flush (POST /api/actions), run in this process: a flush when
// enqueue says one is due, a claim every FLUSH_AT_AGE_MS (the age rule needs a call to look at the queue),
// and a forced one at close. One flush in flight.
import { actionTrailMode, buildActionRecord, enqueueActionRecord, claimFlush, flushActionTrail, FLUSH_AT_AGE_MS } from "../cli/action-trail.mjs";
import { VERIFIED_SOURCES } from "./context.mjs";
import { traceFields } from "./trace-w3c.mjs";

// rt: the proxy's runtime. config: { serverUrl, installToken } for the flush. appVersion: MoorAI's version.
export function createTrail(rt, { config, appVersion }) {
  let flushing = null;
  const flush = () => (flushing ||= flushActionTrail({ config }).catch(() => {}).finally(() => { flushing = null; }));
  const on = (s) => rt.config.enrolled && VERIFIED_SOURCES.has(s.source) && actionTrailMode(s.policy) === "allowed";
  const timer = setInterval(() => { if (claimFlush()) flush(); }, FLUSH_AT_AGE_MS);
  timer.unref();
  return {
    // One forwarded model request. s: the runtime's policy state; r: { trace, provider, model }.
    record(s, r, agentName) {
      if (!on(s)) return;
      const rec = buildActionRecord({ event: "ModelRequest", tool: `model-proxy:${r.provider}`, basis: "default", policyIat: s.policy.policySig.iat, ...rt.identity, agentName, appVersion, ...traceFields(r.trace), provider: r.provider, model: r.model });
      if (enqueueActionRecord(rec).flushDue) flush();
    },
    async close() {
      clearInterval(timer);
      if (claimFlush({ force: true })) await flush();
      else if (flushing) await flushing;
    }
  };
}
