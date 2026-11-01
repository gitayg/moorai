// The model proxy's check of X-MoorAI-Agent-Identity (../cli/agent-session-identity.mjs), against this device's key
// and the verified policy's agentIdentity settings and revokedAgentSessions list. The header is addressed to the
// proxy and never forwarded (./server.mjs HOP). In --mode enforce a revoked session is refused 403 and, under
// agentIdentity.mode "require", a request without a verified identity 401; in --mode report (the default) nothing
// is refused and the alert is stamped enforcement LIMITED, as a budget block is. The identity rides on every alert
// the request raises (./report.mjs REQUEST). Each distinct verdict is posted once per process.
import { judgeIdentity, identityAlert, devicePublicKey, IDENTITY_HEADER } from "../cli/agent-session-identity.mjs";
import { ENFORCEMENT } from "../cli/provenance.mjs";

export { IDENTITY_HEADER };

export function createIdentityGate(rt, { enforce }) {
  const seen = new Set();
  // current: the request's REQUEST store. → { status, message } to refuse with, or null.
  return async function gate(req, current) {
    const s = await rt.ready();
    const v = judgeIdentity(req.headers[IDENTITY_HEADER], { policy: s.policy, publicKey: devicePublicKey() });
    if (v.record) current.agentSession = v.record;
    const refuse = v.refuse && enforce ? v.refuse : null;
    const k = `${v.record && v.record.status}|${(v.record && v.record.id) || ""}|${refuse ? 1 : 0}`;
    if (v.alert && !seen.has(k) && seen.size < 1024) {
      seen.add(k);
      try {
        rt.reporter.post({ ...identityAlert(v.record, { refused: !!refuse, surfacePrefix: "model-proxy" }), ...(v.refuse && !refuse ? { enforcement: ENFORCEMENT.LIMITED } : {}) },
          { prov: { policyId: s.policyId, policySource: s.source, event: "ModelRequest" } });
      } catch { /* report-only */ }
    }
    return refuse;
  };
}
