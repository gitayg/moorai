// The device owner assertion (docs/proposals/agent-identity.md §12.6): after `moorai-identity login` the console binds the
// person who signed in at the company identity provider to this device key, and answers with an assertion signed by
// the tenant's POLICY key, kept in ~/.moorai/agent-owner.json. `moorai-identity` puts its owner id into session tokens
// (claim `own`); the MCP gateway and the model proxy check that claim against this file, verified with the same anchor or
// pin that verifies the policy (cli/hook-core.mjs policyTrustKeys), and record { id, status } on alerts.
//
// ASSERTION. moo1.<base64url(JSON claims)>.<base64url(ed25519 signature over "moorai-owner-v1|<tenant>|moo1.<claims>")>
//   claims: { v: 1, oid: "own-" + 16 hex, aid: 16 hex, kid, iat, exp }. Server side: console server/owner-bindings.js.
//
// OWNER STATUS of a token's `own` claim:
//   verified    this file's assertion verifies, names this device key and the same owner, is not expired and its aid
//               is not in the policy's revokedOwnerAssertions
//   revoked     as verified, but the console unbound it (or a later sign-in on this key replaced it)
//   mismatch    the assertion verifies but names another owner than the token claims
//   unverified  no file, no trusted key (an unpinned device), a bad signature, another key or tenant, or expired
// Any process of the device's OS user can read the file and the device key, so a verified owner says the person signed
// in on this device user's key; it does not say which process made the request.
import { verify as edVerify } from "node:crypto";
import { writeFileSync, unlinkSync, mkdirSync, renameSync } from "node:fs";
import { dirname } from "node:path";
import { readState, statePath } from "./state-dirs.mjs";

export const OWNER_FILE = "agent-owner.json";
export const OWNER_ID_RE = /^own-[0-9a-f]{16}$/;
export const OWNER_STATUSES = Object.freeze(["verified", "unverified", "mismatch", "revoked"]);
export const REVOKED_OWNER_MAX = 5000;
const ASSERT_RE = /^moo1\.([A-Za-z0-9_-]{16,1024})\.([A-Za-z0-9_-]{86})$/;
const HEX16 = /^[0-9a-f]{16}$/;
const isInt = (n) => Number.isSafeInteger(n) && n >= 0;

export const assertionCanonical = (tenant, body) => `moorai-owner-v1|${tenant}|${body}`;

// → the claims of a well-formed assertion (signature NOT checked), or null.
export function parseAssertion(a) {
  const m = typeof a === "string" ? ASSERT_RE.exec(a) : null;
  if (!m) return null;
  let c;
  try { c = JSON.parse(Buffer.from(m[1], "base64url").toString("utf8")); } catch { return null; }
  if (!c || typeof c !== "object" || Array.isArray(c) || c.v !== 1) return null;
  if (!OWNER_ID_RE.test(c.oid) || !HEX16.test(c.aid) || !HEX16.test(c.kid) || !isInt(c.iat) || !isInt(c.exp) || c.exp <= c.iat) return null;
  return c;
}

// keys: ed25519 public KeyObjects (policyTrustKeys). → { status: "ok" | "untrusted" | "foreign" | "expired" | "invalid", claims? }.
export function verifyAssertion(a, { keys = [], tenant = "", kid = "", now = Date.now() } = {}) {
  const c = parseAssertion(a);
  if (!c) return { status: "invalid" };
  if (!keys.length) return { status: "untrusted" };
  const [body, sig] = [a.slice(0, a.lastIndexOf(".")), Buffer.from(a.slice(a.lastIndexOf(".") + 1), "base64url")];
  const msg = Buffer.from(assertionCanonical(tenant, body));
  if (!keys.some((k) => { try { return edVerify(null, msg, k, sig); } catch { return false; } })) return { status: "untrusted" };
  if (c.kid !== kid) return { status: "foreign" };
  if (Math.floor(now / 1000) >= c.exp) return { status: "expired", claims: c };
  return { status: "ok", claims: c };
}

// The local file: { v: 1, assertion, email?, name?, issuer?, boundAt, expiresAt }. email / name are for `whoami` only.
export function readOwnerFile(read = readState) {
  try { const j = JSON.parse(read(OWNER_FILE) || ""); return j && typeof j === "object" && typeof j.assertion === "string" ? j : null; } catch { return null; }
}
export function writeOwnerFile(rec, path = statePath(OWNER_FILE)) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify({ v: 1, ...rec })}\n`, { mode: 0o600 });
  renameSync(tmp, path);
  return path;
}
export function removeOwnerFile(path = statePath(OWNER_FILE)) {
  try { unlinkSync(path); return true; } catch { return false; }
}

// The owner id to put into a new token: the file's assertion when it names this key and has not expired. The signature
// is not checked here (the verifiers check it); an assertion for another key is never used.
export function ownerClaimFor(kid, { now = Date.now(), read = readState } = {}) {
  const f = readOwnerFile(read);
  const c = f && parseAssertion(f.assertion);
  return c && c.kid === kid && Math.floor(now / 1000) < c.exp ? c.oid : null;
}

// The verifiers' view of this device's owner, cached for 30 s: → { status, oid?, aid? }.
let cache = null;
export function deviceOwner({ keys = [], tenant = "", kid = "", now = Date.now(), read = readState } = {}) {
  if (cache && now - cache.at < 30000 && cache.kid === kid && cache.tenant === tenant && cache.nkeys === keys.length) return cache.v;
  const f = readOwnerFile(read);
  const r = f ? verifyAssertion(f.assertion, { keys, tenant, kid, now }) : { status: "none" };
  const v = r.claims ? { status: r.status, oid: r.claims.oid, aid: r.claims.aid } : { status: r.status };
  cache = { at: now, kid, tenant, nkeys: keys.length, v };
  return v;
}
export const resetDeviceOwnerCache = () => { cache = null; };

// A token's `own` claim judged against the device owner and the policy's revokedOwnerAssertions. → status.
export function ownerStatus(claim, owner, policy) {
  if (!owner || owner.status !== "ok") return "unverified";
  if (owner.oid !== claim) return "mismatch";
  const revoked = policy && Array.isArray(policy.revokedOwnerAssertions) ? policy.revokedOwnerAssertions.slice(0, REVOKED_OWNER_MAX) : [];
  return revoked.includes(owner.aid) ? "revoked" : "verified";
}
