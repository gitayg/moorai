// The gateway's check of X-MoorAI-Agent-Identity (../cli/agent-session-identity.mjs): verified against this
// device's key and the verified policy's agentIdentity settings and revokedAgentSessions list. The header is
// addressed to the gateway and never forwarded (./config.mjs HOP). A revoked session is refused 403 and, in
// require mode, a request without a verified identity 401 (Claude Code re-runs an MCP server's headersHelper and
// retries once on a 401 or 403, so an expired token is replaced on the next call). An unenrolled, unmanaged
// gateway (coach) reports and never refuses. Each distinct verdict is posted once per process (seenOnce).
import { judgeIdentity, identityAlert, devicePublicKey, IDENTITY_HEADER } from "../cli/agent-session-identity.mjs";
import { state as policyState, ensurePolicy } from "./policy.mjs";
import { post, seenOnce, setAgentSession, IDENTITY, CONFIG } from "./report.mjs";
import { localOwner } from "../cli/owner-verify.mjs";

export { IDENTITY_HEADER };

// → { refuse: { status, message } | null } for one request, after recording the identity on the request's alerts.
export async function gateIdentity(req, server) {
  try { await ensurePolicy(); } catch { /* no policy: report mode, no revocations */ }
  const v = judgeIdentity(req.headers[IDENTITY_HEADER], { policy: policyState.POLICY, publicKey: devicePublicKey(), owner: localOwner(CONFIG.tenant) });
  if (v.record) setAgentSession(v.record);
  const refuse = v.refuse && !policyState.COACH ? v.refuse : null;
  if (v.alert && seenOnce(`identity|${server}|${v.record.status}|${v.record.id || ""}|${(v.record.owner && v.record.owner.status) || ""}|${refuse ? 1 : 0}`)) {
    post({ ...identityAlert(v.record, { refused: !!refuse, surfacePrefix: "gateway" }), mcpServer: server, ts: new Date().toISOString(), ...IDENTITY });
  }
  return { refuse };
}
