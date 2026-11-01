// Egress rules (cli/egress-rules.mjs) on the gateway's OWN upstream connection: the route's remote MCP
// server is a destination like any other, judged at the network layer exactly as egress-proxy/judge.mjs
// judges a connection (binary unknown, so an allow rule that sets `binary` never matches; host, port,
// method and path known, because the gateway is the TLS client). Two checks:
//   1. judgeUpstream(): before the request is sent, on the route URL's host name (or IP literal). A block
//      refuses the request before the gate runs, so the gate's block-mode re-list never reaches it either.
//   2. egressLookup(): the socket's DNS lookup. With a cidr rule in force, every address the lookup returns
//      is judged beside the name (egress-proxy/judge.mjs judgeAddresses) and the connection is refused when
//      any is blocked. The socket connects to an address that was judged, so a second DNS answer cannot
//      redirect it. A reused keep-alive socket was judged when it connected.
// The trust sources are the gateway's: the verified console policy (state.POLICY), the root-owned
// machine-wide config, and server mode's workload name for a profile's match.serviceId. Coach on an
// unenrolled device: a block is reported and forwarded. Never throws to the caller; an error while judging
// refuses the connection (a network boundary fails closed, as the egress proxy does).
import dns from "node:dns";
import { judgeConnection, judgeAddresses, hasCidrRules, networkTarget } from "../egress-proxy/judge.mjs";
import { egressAlerts, egressReason } from "../cli/egress-rules.mjs";

export const EGRESS_CODE = "MOORAI_EGRESS";

// The route URL plus the request's method → a network target.
export function upstreamTarget(url, method) {
  const scheme = url.protocol.replace(/:$/, "");
  const port = url.port ? Number(url.port) : scheme === "https" ? 443 : 80;
  return networkTarget({ scheme, host: url.hostname.toLowerCase().replace(/\.$/, ""), port, method: String(method || "").toUpperCase() || null, path: url.pathname || "/" });
}

const alertsOf = (target, v, coach) => egressAlerts([{ target, action: v.action, ref: v.ref, ...(v.ruleId ? { ruleId: v.ruleId } : {}) }], { coach, profileId: v.profileId }).map((a) => ({ ...a, egressLayer: "network" }));

// → { block: null | reason, alerts }
export function judgeUpstream(target, st) {
  const v = judgeConnection(target, st);
  if (v.error) return { block: "the egress rules could not be evaluated", alerts: [] };
  const alerts = v.action === "allow" ? [] : alertsOf(target, v, !!st.coach);
  const block = v.action === "block" && !st.coach ? egressReason({ target, action: v.action, ref: v.ref, ...(v.ruleId ? { ruleId: v.ruleId } : {}) }) : null;
  return { block, alerts };
}

// A dns.lookup-compatible function for http.request's `lookup` option. onAlert(alert) reports.
export function egressLookup(target, st, onAlert = () => {}, lookup = dns.lookup) {
  return function egressCheckedLookup(hostname, options, cb) {
    if (typeof options === "function") { cb = options; options = {}; }
    const opts = typeof options === "number" ? { family: options } : { ...(options || {}) };
    lookup(hostname, { ...opts, all: true }, (err, addrs) => {
      if (err) return cb(err);
      const list = Array.isArray(addrs) ? addrs : [];
      if (!list.length) return cb(Object.assign(new Error(`${hostname} could not be resolved`), { code: "ENOTFOUND" }));
      if (hasCidrRules(st)) {
        const v = judgeAddresses(target, list.map((a) => String(a.address)), st);
        if (v.error) return cb(Object.assign(new Error("the egress rules could not be evaluated"), { code: EGRESS_CODE }));
        if (v.action !== "allow") for (const a of alertsOf(target, v, !!st.coach)) onAlert(a);
        if (v.action === "block" && !st.coach) return cb(Object.assign(new Error(egressReason({ target, action: v.action, ref: v.ref, ...(v.ruleId ? { ruleId: v.ruleId } : {}) })), { code: EGRESS_CODE }));
      }
      if (opts.all) return cb(null, list);
      cb(null, list[0].address, list[0].family);
    });
  };
}
