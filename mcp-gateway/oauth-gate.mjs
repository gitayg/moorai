// The gateway's OAuth checks, wired to the verified policy and content-free reporting: the bearer token on
// each request (./oauth-token.mjs), the `scope` an upstream challenge asks for, and the authorization
// servers named in the protected-resource metadata the gateway serves (./oauth-as-check.mjs).
// A block is a refusal only when the gateway enforces (not coach on an unenrolled device, the shared rule);
// in coach it is reported with decision "coach" and forwarded. Alerts carry the route's server label, the
// check, the decision and, for a scope finding, a count. No token, claim, scope name, URL or hash of any.
import { state, ensurePolicy } from "./policy.mjs";
import { post, seenOnce, recordLedger, coachNote, IDENTITY } from "./report.mjs";
import { oauthPolicy, judgeToken, createReuseTracker, excessScopes } from "./oauth-token.mjs";
import { checkAuthServers } from "./oauth-as-check.mjs";
import { PRM_PREFIX } from "./oauth-discovery.mjs";
import { REASON } from "../cli/provenance.mjs";

export const OAUTH_REASON = REASON.MCP_OAUTH;
const CATEGORY = {
  audience: "MCP gateway: OAuth token for another resource",
  issuer: "MCP gateway: OAuth token from another issuer",
  scope: "MCP gateway: OAuth token scope outside the allow-list",
  reuse: "MCP gateway: bearer token reused across servers",
  "challenge-scope": "MCP gateway: OAuth scope challenge outside the allow-list",
  "auth-server": "MCP gateway: OAuth authorization server metadata failed",
  malformed: "MCP gateway: Authorization header without exactly one Bearer token"
};
const RISK = { audience: "High", issuer: "High", scope: "Medium", reuse: "Medium", "challenge-scope": "Medium", "auth-server": "High", malformed: "Medium" };

export function alertOAuth(server, check, decision, extra = {}) {
  const blocked = decision === "deny";
  const a = { threatId: 0, category: CATEGORY[check], riskLevel: blocked ? "Blocked" : RISK[check], stage: "mcp", tool: "gateway:mcp", decision, reasonCode: OAUTH_REASON, oauthCheck: check, ...extra, mcpServer: server, ts: new Date().toISOString(), contentHash: `oauth:${check}:${server}`, ...IDENTITY };
  if (seenOnce(`oauth|${server}|${check}|${decision}|${extra.authServerChecks ? extra.authServerChecks.join(",") : ""}`)) post(a);
  recordLedger(a);
}

const policyNow = async () => { try { await ensurePolicy(); } catch { /* no policy: the defaults */ } return oauthPolicy(state.POLICY); };
const quote = (v) => `"${String(v).replace(/(["\\])/g, "\\$1")}"`;
// The Authorization value as the gateway judges it: Node keeps only the first of two Authorization headers
// (req.headers; the rest stay in rawHeaders), so a second one is joined in and makes the value malformed.
function authorizationOf(req) {
  const raw = [];
  const rh = req.rawHeaders || [];
  for (let i = 0; i + 1 < rh.length; i += 2) if (String(rh[i]).toLowerCase() === "authorization") raw.push(rh[i + 1]);
  return raw.length > 1 ? raw.join(", ") : req.headers.authorization;
}

// discovery: ./oauth-discovery.mjs createDiscovery's result (its known() is the upstream's last metadata).
export function createOAuthGate({ discovery } = {}) {
  const reuse = createReuseTracker();
  const asCache = new WeakMap();
  return {
    // → null (forward) | { status, message, headers } (refuse). Called before the body is read.
    async request(req, route) {
      const auth = authorizationOf(req);
      if (typeof auth !== "string" || !auth) return null;
      const pol = await policyNow();
      const doc = discovery && discovery.known ? discovery.known(route) : null;
      const j = judgeToken(auth, { route, pol, gatewayHost: req.headers.host, authorizationServers: doc ? doc.authorization_servers : null, reuse });
      if (!j.findings.length && !j.tokens.length) return null;
      let refuse = null;
      for (const f of j.findings) {
        const enforce = f.action === "block" && !state.COACH;
        const decision = f.action === "block" ? (enforce ? "deny" : "coach") : "allow";
        alertOAuth(route.server, f.check, decision, f.excess ? { excessScopes: f.excess } : {});
        if (decision === "coach") coachNote(`a request to MCP server ${route.server}`, CATEGORY[f.check]);
        if (enforce && !refuse) refuse = f;
      }
      if (!refuse) { for (const t of j.tokens) reuse.note(t, j.origin); return null; }
      const prm = `http://${req.headers.host}${PRM_PREFIX}${route.path}`;
      if (refuse.check === "malformed") {
        const bad = "the Authorization header does not carry exactly one Bearer token";
        return { status: 400, message: bad, headers: { "WWW-Authenticate": `Bearer resource_metadata=${quote(prm)}, error="invalid_request", error_description=${quote(bad)}` } };
      }
      if (refuse.check === "scope") return { status: 403, message: "the token's scopes go beyond what policy allows for this MCP server" };
      const why = refuse.check === "issuer" ? "the token was not issued by this MCP server's authorization server" : refuse.check === "reuse" ? "this token was already sent to another MCP server" : "the token was not issued for this MCP server";
      return { status: 401, message: why, headers: { "WWW-Authenticate": `Bearer resource_metadata=${quote(prm)}, error="invalid_token", error_description=${quote(why)}` } };
    },
    // An upstream 401 / 403 challenge's `scope` (a step-up request) against the allow-list: reported only.
    async challenge(route, scope) {
      if (typeof scope !== "string" || !scope) return;
      const pol = await policyNow();
      const allow = pol.scopes[route.server];
      if (!allow || pol.scope === "off") return;
      const extra = excessScopes(scope.split(/\s+/).filter(Boolean).slice(0, 256), allow);
      if (extra.length) alertOAuth(route.server, "challenge-scope", "allow", { excessScopes: extra.length });
    },
    // The upstream's protected-resource metadata, before the gateway serves it → null | { status, body }.
    async discoveryCheck(route, doc, fetchJson) {
      const pol = await policyNow();
      if (pol.authServer === "off") return null;
      // One check per metadata document, shared by concurrent requests: the endpoint is unauthenticated.
      let pending = asCache.get(doc);
      if (!pending) { pending = checkAuthServers(doc.authorization_servers, fetchJson).catch(() => []); asCache.set(doc, pending); }
      const failed = await pending;
      if (!failed.length) return null;
      const checks = [...new Set(failed.flatMap((f) => f.failures))].sort();
      const enforce = pol.authServer === "block" && !state.COACH;
      const decision = pol.authServer === "block" ? (enforce ? "deny" : "coach") : "allow";
      alertOAuth(route.server, "auth-server", decision, { authServerChecks: checks });
      if (decision === "coach") coachNote(`discovery for MCP server ${route.server}`, `${CATEGORY["auth-server"]} (${checks.join(", ")})`);
      return enforce ? { status: 502, body: { error: `an authorization server of this route failed MoorAI's metadata checks (${checks.join(", ")})` } } : null;
    }
  };
}
