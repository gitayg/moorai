// What the gateway can tell about the bearer token a client sends on a route, before it is forwarded.
// Quoted from the MCP 2026-07-28 revision (basic/authorization):
//   "MCP servers MUST NOT accept or transit any other tokens." (Token Handling)
//   "The MCP server MUST NOT pass through the token it received from the MCP client." (Security
//   Considerations, Access Token Privilege Restriction)
//   "MCP clients MUST implement and use the `resource` parameter as defined in RFC 8707 ... This ensures
//   that access tokens are bound to their intended resources and cannot be misused across different
//   services."
// The gateway holds no key for any token, so it reads a JWT access token's claims (RFC 9068: aud, iss,
// scope) WITHOUT verifying its signature. That can only make the gateway stricter: a token it refuses is
// never forwarded, and a token it forwards still has to pass the upstream's own validation, so a forged
// claim gains nothing. An opaque token (no readable claims) gets no audience, issuer or scope verdict.
//
// Checks, each under the signed policy key `mcpOAuth` (oauthPolicy below):
//   audience  a JWT with an http(s) URI among its `aud` values and no value that is this route's upstream (same origin,
//             and the aud path a segment prefix of the upstream path), the gateway route the client uses
//             (the resource the gateway's protected-resource metadata names), or an audience the admin lists
//             for the route's server. Default "report"; under "block" refused 401 with a Bearer challenge that
//             points the client at the route's metadata, so it can obtain a token for this resource.
//   issuer    a JWT whose `iss` is not among the authorization servers the upstream's protected-resource
//             metadata lists (known only once the gateway has read that metadata). Default "report".
//   scope     (`scopeAction`) a JWT whose `scope` / `scp` holds a scope outside the admin's allow-list for the route's
//             server (`scopes: { <server>: [..] }`; no list, no check). Default "report".
//   reuse     (`tokenReuse`) the same bearer value (an opaque token, or a JWT whose `aud` values are not all http(s) URIs) sent on two routes
//             whose upstreams are different origins. The value is kept in memory only, as a sha256 prefix.
//             Default "report".
//   malformed an Authorization value that names the Bearer scheme but is not exactly one token (two tokens, trailing
//             text, a comma, a second Authorization header). The gateway cannot tell which token the upstream will
//             use, so it follows the audience action (default "report"; under "block" refused 400 invalid_request,
//             RFC 6750 3.1), and every token-shaped part of it still gets the checks above.
// Content-free: no token, claim value, scope name, audience or hash of any of them leaves the process.
import { createHash } from "node:crypto";
import { isLoopbackHost } from "./config.mjs";

export const MODES = ["block", "report", "off"];
const DEFAULTS = { audience: "report", issuer: "report", scope: "report", reuse: "report", authServer: "off" };
const REUSE_MAX = 4096;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const mode = (v, d) => (MODES.includes(v) ? v : d);
const strList = (v) => (Array.isArray(v) ? v.filter((s) => typeof s === "string" && s).slice(0, 256) : []);
function perServer(v) {
  const out = {};
  if (isObj(v)) for (const [k, list] of Object.entries(v)) if (Array.isArray(list)) out[k] = strList(list);
  return out;
}

// policy.mcpOAuth → { audience, issuer, scope, reuse, authServer, audiences, scopes }. Only the verified
// policy reaches this (./policy.mjs state.POLICY); nothing user-writable is read.
export function oauthPolicy(policy) {
  const p = policy && isObj(policy.mcpOAuth) ? policy.mcpOAuth : {};
  return {
    audience: mode(p.audience, DEFAULTS.audience),
    issuer: mode(p.issuer, DEFAULTS.issuer),
    scope: mode(p.scopeAction, DEFAULTS.scope),
    reuse: mode(p.tokenReuse, DEFAULTS.reuse),
    authServer: mode(p.authServer, DEFAULTS.authServer),
    audiences: perServer(p.audiences),
    scopes: Object.hasOwn(p, "scopes") ? perServer(p.scopes) : {}
  };
}

// The token of an `Authorization: Bearer <token>` value, or null.
export function bearerOf(value) {
  if (typeof value !== "string") return null;
  const m = /^\s*Bearer\s+([^\s,]+)\s*$/i.exec(value);
  return m ? m[1] : null;
}

// A value that names the Bearer scheme (first, or after a comma as in a joined second header).
export const namesBearer = (value) => typeof value === "string" && /(?:^|,)\s*Bearer(?=[\s,]|$)/i.test(value);
// The token-shaped parts of a value bearerOf cannot read, bounded.
export function bearerParts(value) {
  return String(value).split(/[\s,]+/).filter((p) => p && p.toLowerCase() !== "bearer").slice(0, 8);
}

function b64urlJson(s) {
  try {
    const v = JSON.parse(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return isObj(v) ? v : null;
  } catch { return null; }
}

// A JWS compact token's payload claims, or null (opaque, JWE, malformed). Never verified: see the header.
export function jwtClaims(token) {
  if (typeof token !== "string" || token.length > 16384) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts.every((p) => /^[A-Za-z0-9_-]*$/.test(p))) return null;
  const head = b64urlJson(parts[0]);
  if (!head || typeof head.alg !== "string") return null;
  return b64urlJson(parts[1]);
}

// The URL parser drops tab and newline anywhere and leading C0 controls and spaces, so this shape test passes
// every string it could read as http(s), without the cost of a throw on the rest.
const httpShaped = (s) => /^[\x00-\x20]*https?:/i.test(String(s).replace(/[\t\n\r]/g, ""));
function parseUri(s) {
  if (!httpShaped(s)) return null;
  try {
    const u = new URL(String(s));
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return { origin: `${u.protocol}//${u.host.toLowerCase()}`, host: u.hostname.toLowerCase(), port: u.port || (u.protocol === "https:" ? "443" : "80"), path: u.pathname.replace(/\/+$/, "") };
  } catch { return null; }
}
// `aud` path covers `want` path: equal, empty (origin-wide), or a whole-segment prefix.
const pathCovers = (aud, want) => !aud || aud === want || want.startsWith(`${aud}/`);

// One `aud` value against the route, parsed once per token by routeOf.
function audMatches(aud, { up, g, routePath, extra }) {
  const a = parseUri(aud);
  if (!a) return null;
  if (up && a.origin === up.origin && pathCovers(a.path, up.path)) return true;
  if (g && pathCovers(a.path, routePath)) {
    if (a.host === g.host && a.port === g.port) return true;
    if (isLoopbackHost(a.host) && isLoopbackHost(g.host) && a.port === g.port) return true;
  }
  for (const e of extra) if (e.origin === a.origin && pathCovers(e.path, a.path)) return true;
  return false;
}
// gatewayHost: the request's Host header (the client's name for the gateway).
const routeOf = ({ upstream, gatewayHost, routePath, extra }) => ({ up: parseUri(upstream), g: gatewayHost ? parseUri(`http://${gatewayHost}`) : null, routePath: routePath.replace(/\/+$/, ""), extra: (extra || []).map(parseUri).filter(Boolean) });

// Every `aud` value; the token's own length cap (jwtClaims) bounds the list.
const audValues = (claims) => (!claims || claims.aud == null ? [] : Array.isArray(claims.aud) ? claims.aud : [claims.aud]);

// → "match" | "mismatch" | "unknown". Mismatch when no value fits and at least one is an http(s) URI: a value
// that is not a URI (a client id, a GUID) cannot vouch for this route. Unknown only when no value is a URI.
export function audienceVerdict(claims, ctx) {
  const auds = audValues(claims);
  const route = auds.length ? routeOf(ctx) : null;
  const r = auds.map((a) => (typeof a === "string" ? audMatches(a, route) : null));
  if (r.includes(true)) return "match";
  return r.includes(false) ? "mismatch" : "unknown";
}
// Whether every `aud` value is an http(s) URI. The reuse check covers every other token.
const audAllUris = (claims) => { const a = audValues(claims); return a.length > 0 && a.every((v) => typeof v === "string" && parseUri(v) !== null); };

const canon = (s) => { const u = parseUri(s); return u ? `${u.origin}${u.path}` : null; };

// → "match" | "mismatch" | "unknown". authorizationServers: from the upstream's protected-resource metadata.
export function issuerVerdict(claims, authorizationServers) {
  if (!claims || typeof claims.iss !== "string" || !Array.isArray(authorizationServers) || !authorizationServers.length) return "unknown";
  const iss = canon(claims.iss);
  if (!iss) return "unknown";
  return authorizationServers.some((a) => canon(a) === iss) ? "match" : "mismatch";
}

// The token's scopes (RFC 9068 `scope`, space-separated; or `scp`, a list or a string), or null.
export function tokenScopes(claims) {
  if (!claims) return null;
  const v = claims.scope != null ? claims.scope : claims.scp;
  if (typeof v === "string") return v.split(/\s+/).filter(Boolean).slice(0, 256);
  if (Array.isArray(v)) return v.filter((s) => typeof s === "string" && s).slice(0, 256);
  return null;
}

// Scopes not in the allow-list (a challenge's `scope` parameter is checked the same way).
export function excessScopes(scopes, allow) {
  const ok = new Set(allow);
  return [...new Set(scopes)].filter((s) => !ok.has(s));
}

// Bearer values seen per upstream origin, in memory, keyed by a sha256 prefix; bounded (oldest dropped).
export function createReuseTracker(max = REUSE_MAX) {
  const seen = new Map();
  const key = (token) => createHash("sha256").update(String(token)).digest("hex").slice(0, 32);
  return {
    // → true when this value was already sent on a route whose upstream is another origin.
    elsewhere(token, origin) {
      const s = seen.get(key(token));
      return !!s && [...s].some((o) => o !== origin);
    },
    note(token, origin) {
      const k = key(token);
      let s = seen.get(k);
      if (!s) {
        if (seen.size >= max) seen.delete(seen.keys().next().value);
        seen.set(k, (s = new Set()));
      }
      if (s.size < 16) s.add(origin);
    },
    size: () => seen.size
  };
}

// Every finding for one request's Authorization value → { findings: [{ check, action, excess? }], tokens, origin }.
// action is the policy mode ("block" | "report"); checks set to "off" produce nothing. tokens: the bearer
// values judged (one, or the parts of a malformed value), for the reuse tracker.
// ctx: { route, gatewayHost, pol (oauthPolicy), authorizationServers (or null), reuse (tracker) }
export function judgeToken(authorization, ctx) {
  const one = bearerOf(authorization);
  const malformed = !one && namesBearer(authorization);
  if (!one && !malformed) return { findings: [], tokens: [] };
  const { route, pol } = ctx;
  const origin = parseUri(route.url).origin;
  const tokens = (one ? [one] : bearerParts(authorization)).filter((t) => !t.startsWith("moorai-ph:"));
  const found = new Map();
  if (malformed && pol.audience !== "off") found.set("malformed", { check: "malformed", action: pol.audience });
  for (const token of tokens) for (const f of tokenFindings(token, ctx, origin)) if (!found.has(f.check)) found.set(f.check, f);
  return { findings: [...found.values()], tokens, origin };
}

function tokenFindings(token, ctx, origin) {
  const { route, pol } = ctx;
  const claims = jwtClaims(token);
  const findings = [];
  const aud = audienceVerdict(claims, { upstream: route.url, gatewayHost: ctx.gatewayHost, routePath: route.path, extra: pol.audiences[route.server] });
  if (aud === "mismatch" && pol.audience !== "off") findings.push({ check: "audience", action: pol.audience });
  if (pol.issuer !== "off" && issuerVerdict(claims, ctx.authorizationServers) === "mismatch") findings.push({ check: "issuer", action: pol.issuer });
  const allow = pol.scopes[route.server];
  if (allow && pol.scope !== "off") {
    const sc = tokenScopes(claims);
    const extra = sc ? excessScopes(sc, allow) : [];
    if (extra.length) findings.push({ check: "scope", action: pol.scope, excess: extra.length });
  }
  if (!audAllUris(claims) && pol.reuse !== "off" && ctx.reuse && ctx.reuse.elsewhere(token, origin)) findings.push({ check: "reuse", action: pol.reuse });
  return findings;
}
