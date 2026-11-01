// Agent session identity (docs/proposals/agent-identity.md §12): a signed, short-lived token that names one agent
// session on this device, minted with the device's ed25519 key (data/agency-sign.mjs, the key the console pins on
// first use), carried on the agent's requests to the MCP gateway and the model proxy in X-MoorAI-Agent-Identity,
// verified there against this device's public key, checked against the signed policy's revocation list, and
// recorded on alerts as `agentSession: { id, status, agentName }`.
//
// TOKEN. mai1.<base64url(JSON claims)>.<base64url(ed25519 signature over "mai1." + claims part)>
//   claims: { v: 1, sid: "asi-" + 16 hex, agent, kid, sat, iat, exp, jti }
//   sid  the session id: random, fixed for the session; every token minted for the session repeats it
//   kid  the first 16 hex of sha256 over the device key's SPKI DER: a token signed by another device is "foreign"
//   sat  session start, iat / exp issue and expiry (seconds since the epoch), jti 16 random hex
//   own  optional: "own-" + 16 hex, the owner id of the person bound to this device key by `moorai-identity login`
//        (cli/owner-assertion.mjs); verifiers check it against the console-signed owner assertion on the device
// No user, email, hostname, path, prompt or tool name is in a token.
//
// WHAT IT PROVES. The token was minted by a process that could read this OS user's device key, for a session
// that started at `sat`, and has not expired or been revoked. Any process of the same OS user can read that key
// and mint a token for any session id, so a token attributes a request to a session and lets an administrator
// end that session; it does not authenticate the agent process against other processes of the same user.
import { createHash, createPrivateKey, createPublicKey, verify as edVerify, randomBytes } from "node:crypto";
import { readState } from "./state-dirs.mjs";
import { agentNameOf } from "./agent-names.mjs";
import { OWNER_ID_RE, ownerStatus } from "./owner-assertion.mjs";

export const IDENTITY_HEADER = "x-moorai-agent-identity";
export const SESSION_ID_RE = /^asi-[0-9a-f]{16}$/;
export const MODES = Object.freeze(["off", "report", "require"]);
export const STATUSES = Object.freeze(["verified", "expired", "revoked", "invalid", "foreign", "absent"]);
export const REASON_CODE = "AGENT_IDENTITY";
// The rule the identity alert reports under: #94 Agent request without a valid session identity.
export const IDENTITY_THREAT_ID = 94;
// Token lifetime for a helper that can re-mint (an MCP headersHelper); the session's own end caps every token.
export const TOKEN_TTL_SEC = 900;
export const SESSION_MAX_SEC = 43200;
// Policy bounds: agentIdentity.maxTokenSeconds (60..86400, default 86400) and maxSessionSeconds (300..604800,
// default 86400). A token or session longer than the policy allows is refused as invalid / expired.
export const POLICY_TOKEN_MAX = { min: 60, max: 86400, dflt: 86400 };
export const POLICY_SESSION_MAX = { min: 300, max: 604800, dflt: 86400 };
export const REVOKED_MAX = 5000;
const SKEW_SEC = 60;
const PREFIX = "mai1";
const TOKEN_RE = /^mai1\.([A-Za-z0-9_-]{16,1024})\.([A-Za-z0-9_-]{86})$/;
const HEX16 = /^[0-9a-f]{16}$/;

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const isInt = (n) => Number.isSafeInteger(n) && n >= 0;

export const newSessionId = () => `asi-${randomBytes(8).toString("hex")}`;
export function keyIdOf(pubB64) {
  return createHash("sha256").update(Buffer.from(String(pubB64 || ""), "base64")).digest("hex").slice(0, 16);
}
export const agentLabel = (v) => agentNameOf(v) || "unknown";

// signer: { sign(bytes) → Buffer, publicKey: base64 SPKI DER } (data/agency-sign.mjs deviceReceiptSigner).
// → the token string. exp is the earlier of iat + ttlSec and sat + sessionMaxSec.
export function mintToken({ sid, agentName, sat, ttlSec = TOKEN_TTL_SEC, sessionMaxSec = SESSION_MAX_SEC, now = Date.now(), signer, ownerId = null }) {
  if (!SESSION_ID_RE.test(String(sid || ""))) throw new Error("session id must be asi- followed by 16 hex characters");
  if (!signer || typeof signer.sign !== "function" || !signer.publicKey) throw new Error("no device key to sign with");
  const iat = Math.floor(now / 1000);
  const start = isInt(sat) ? Math.min(sat, iat) : iat;
  const exp = Math.min(iat + Math.max(1, Math.floor(ttlSec)), start + Math.max(1, Math.floor(sessionMaxSec)));
  if (exp <= iat) throw new Error("the session has ended");
  const claims = { v: 1, sid, agent: agentLabel(agentName), kid: keyIdOf(signer.publicKey), sat: start, iat, exp, jti: randomBytes(8).toString("hex"), ...(OWNER_ID_RE.test(String(ownerId || "")) ? { own: ownerId } : {}) };
  const body = `${PREFIX}.${b64u(JSON.stringify(claims))}`;
  return `${body}.${b64u(signer.sign(Buffer.from(body)))}`;
}

function claimsOf(part) {
  let c;
  try { c = JSON.parse(Buffer.from(part, "base64url").toString("utf8")); } catch { return null; }
  if (!c || typeof c !== "object" || Array.isArray(c) || c.v !== 1) return null;
  if (!SESSION_ID_RE.test(c.sid) || !HEX16.test(c.kid) || !HEX16.test(c.jti) || typeof c.agent !== "string") return null;
  if (!isInt(c.sat) || !isInt(c.iat) || !isInt(c.exp) || c.sat > c.iat || c.exp <= c.iat) return null;
  if (c.own !== undefined && !OWNER_ID_RE.test(c.own)) return null;
  return c;
}

// → { status, sid?, agentName?, exp?, own? }. sid, agentName and own only once the signature has verified.
export function verifyToken(token, { publicKey, now = Date.now(), maxTokenSec = POLICY_TOKEN_MAX.dflt, maxSessionSec = POLICY_SESSION_MAX.dflt } = {}) {
  const m = typeof token === "string" ? TOKEN_RE.exec(token) : null;
  if (!m) return { status: "invalid" };
  const c = claimsOf(m[1]);
  if (!c) return { status: "invalid" };
  if (!publicKey) return { status: "invalid" };
  if (c.kid !== keyIdOf(publicKey)) return { status: "foreign" };
  let ok = false;
  try { ok = edVerify(null, Buffer.from(`${PREFIX}.${m[1]}`), createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" }), Buffer.from(m[2], "base64url")); } catch { ok = false; }
  if (!ok) return { status: "invalid" };
  const nowSec = Math.floor(now / 1000);
  if (c.iat > nowSec + SKEW_SEC || c.exp - c.iat > maxTokenSec) return { status: "invalid" };
  const who = { sid: c.sid, agentName: agentLabel(c.agent), exp: c.exp, ...(c.own ? { own: c.own } : {}) };
  if (nowSec >= c.exp || nowSec - c.sat > maxSessionSec) return { status: "expired", ...who };
  return { status: "verified", ...who };
}

const bounded = (v, b) => (Number.isSafeInteger(v) && v >= b.min && v <= b.max ? v : b.dflt);
// The signed policy's settings: agentIdentity { mode, maxTokenSeconds, maxSessionSeconds, requireOwner } and the
// console's revokedAgentSessions list. No policy, or no agentIdentity key: report mode. Anything malformed is ignored.
// requireOwner (true only) applies under mode "require": a verified identity whose owner is not verified is refused too.
export function identityConfig(policy) {
  const ai = policy && typeof policy.agentIdentity === "object" && policy.agentIdentity && !Array.isArray(policy.agentIdentity) ? policy.agentIdentity : {};
  const list = policy && Array.isArray(policy.revokedAgentSessions) ? policy.revokedAgentSessions : [];
  return {
    mode: MODES.includes(ai.mode) ? ai.mode : "report",
    maxTokenSec: bounded(ai.maxTokenSeconds, POLICY_TOKEN_MAX),
    maxSessionSec: bounded(ai.maxSessionSeconds, POLICY_SESSION_MAX),
    requireOwner: ai.requireOwner === true,
    revoked: new Set(list.filter((s) => typeof s === "string" && SESSION_ID_RE.test(s)).slice(0, REVOKED_MAX))
  };
}

const REFUSE_TEXT = {
  revoked: "MoorAI: this agent session was revoked by an administrator",
  absent: "MoorAI: this endpoint requires an agent identity (X-MoorAI-Agent-Identity); start the agent with moorai-identity run",
  expired: "MoorAI: the agent identity has expired; mint a new one (moorai-identity headers)",
  invalid: "MoorAI: the agent identity did not verify",
  foreign: "MoorAI: the agent identity was minted on another device",
  owner: "MoorAI: this endpoint requires an agent session of a signed-in owner (moorai-identity login, then a new session)"
};

// One request's identity verdict. raw: the header value (a string, undefined, or an array when repeated). owner: this
// device's owner as cli/owner-assertion.mjs deviceOwner reads it.
// → { record, refuse, alert }:
//   record  { id?, status, agentName?, owner?: { id, status } } for the request's alerts, or null (no header, or mode
//           off). owner only when the token carries an `own` claim.
//   refuse  { status: 401 | 403, message } or null. A revoked session is refused in report and require mode;
//           in require mode anything but a verified identity is refused too.
//   alert   true when the verdict is worth an alert (anything but verified)
export function judgeIdentity(raw, { policy, publicKey, owner = null, now = Date.now() } = {}) {
  const cfg = identityConfig(policy);
  if (cfg.mode === "off") return { record: null, refuse: null, alert: false };
  const require = cfg.mode === "require";
  if (raw === undefined || raw === null || raw === "") {
    return require ? { record: { status: "absent" }, refuse: { status: 401, message: REFUSE_TEXT.absent }, alert: true } : { record: null, refuse: null, alert: false };
  }
  const v = Array.isArray(raw) ? { status: "invalid" } : verifyToken(String(raw).trim(), { publicKey, now, maxTokenSec: cfg.maxTokenSec, maxSessionSec: cfg.maxSessionSec });
  const status = v.sid && cfg.revoked.has(v.sid) ? "revoked" : v.status;
  const record = { status, ...(v.sid ? { id: v.sid, agentName: v.agentName } : {}), ...(v.own ? { owner: { id: v.own, status: ownerStatus(v.own, owner, policy) } } : {}) };
  if (status === "verified") {
    const os = record.owner ? record.owner.status : null;
    if (require && cfg.requireOwner && os !== "verified") return { record: record.owner ? record : { ...record, owner: { status: "absent" } }, refuse: { status: 401, message: REFUSE_TEXT.owner }, alert: true };
    return { record, refuse: null, alert: !!os && os !== "verified" };
  }
  const refuse = status === "revoked" ? { status: 403, message: REFUSE_TEXT.revoked } : require ? { status: 401, message: REFUSE_TEXT[status] || REFUSE_TEXT.invalid } : null;
  return { record, refuse, alert: true };
}

// The content-free alert for a verdict that is not "verified". surfacePrefix: "gateway" or "model-proxy".
// A verified identity whose owner claim did not verify is reported as "Agent owner: <status>".
export function identityAlert(record, { refused, surfacePrefix }) {
  const status = STATUSES.includes(record && record.status) ? record.status : "invalid";
  const os = status === "verified" && record.owner ? OWNER_ALERT_STATUSES.find((x) => x === record.owner.status) || "unverified" : null;
  const what = os ? `owner: ${os}` : `identity: ${status}`;
  return {
    threatId: IDENTITY_THREAT_ID, category: `Agent ${what}`, riskLevel: refused ? "Blocked" : "Medium", stage: "identity",
    tool: `${surfacePrefix}:identity`, decision: refused ? "deny" : "allow", reasonCode: REASON_CODE,
    contentHash: `agent-${what.replace(": ", ":")}`, agentSession: record
  };
}
const OWNER_ALERT_STATUSES = ["unverified", "mismatch", "revoked", "absent"];

// This device's public key (base64 SPKI DER) from the private key the hook created, or null when the device has
// none yet. Never creates a key: a verifier with no key has nothing a token could have been signed with. A miss
// is retried after 30 s, so a key the hook writes later is picked up by a long-lived gateway or proxy.
let pubCache = null, missAt = 0;
export function devicePublicKey({ read = readState, now = Date.now() } = {}) {
  if (pubCache) return pubCache;
  if (missAt && now - missAt < 30000) return null;
  try {
    const pem = read("agency-ed25519.key");
    if (pem) { pubCache = createPublicKey(createPrivateKey(pem)).export({ type: "spki", format: "der" }).toString("base64"); return pubCache; }
  } catch { /* unreadable: treated as none */ }
  missAt = now;
  return null;
}

// What the console is told when a session starts (POST /api/agent-sessions/register): content-free, signed with
// the device key so the console can check it against the key it pinned for this device.
export const registrationCanonical = (r) => `moorai-agent-session-v1|${r.sid}|${r.agentName}|${r.sat}|${r.sessionExp}|${r.kid}`;
export function registrationRecord({ sid, agentName, satSec, sessionExpSec, signer }) {
  const r = { v: 1, sid, agentName: agentLabel(agentName), sat: new Date(satSec * 1000).toISOString(), sessionExp: new Date(sessionExpSec * 1000).toISOString(), kid: keyIdOf(signer.publicKey) };
  return { ...r, pub: signer.publicKey, alg: "ed25519", sig: signer.sign(Buffer.from(registrationCanonical(r))).toString("base64") };
}
