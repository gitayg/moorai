// OAuth 2.0 Protected Resource Metadata (RFC 9728) through the gateway, so an MCP client can run the
// 2026-07-28 authorization flow against a route. Quoted from the revision (basic/authorization):
//   "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)"; discovery is the
//   WWW-Authenticate `resource_metadata` of a 401, or the well-known URI "At the path of the server's MCP
//   endpoint: https://example.com/public/mcp could host metadata at
//   https://example.com/.well-known/oauth-protected-resource/public/mcp" or "At the root"; the client's
//   RFC 8707 `resource` "MUST use the canonical URI of the MCP server".
// And RFC 9728 3.3: "The resource value returned MUST be identical to the protected resource's resource
// identifier value into which the well-known URI path suffix was inserted ... If these values are not
// identical, the data contained in the response MUST NOT be used."
//
// A client knows the gateway route (http://127.0.0.1:8848/<route>) as the MCP server, so the upstream's own
// metadata (resource = the upstream URL) fails that check. The gateway therefore:
//   1. rewrites the `resource_metadata` of an upstream 401 / 403 Bearer challenge to its own well-known URL
//      for the route (adding one when the challenge has none), keeping every other parameter (scope, error);
//   2. serves GET /.well-known/oauth-protected-resource/<route> (and the root form when it has exactly one
//      route): the upstream's metadata, checked against the upstream URL as RFC 9728 3.3 requires, with
//      `resource` set to the gateway route. authorization_servers, scopes_supported and the rest are the
//      upstream's.
// The upstream metadata is read only from the route's own origin: the URL from its challenge when it is on
// that origin, else the path-inserted then the root well-known URI. A challenge that names another origin is
// never fetched. The gateway never runs the authorization flow, never sees a token outside the
// Authorization header it forwards, and stores none.
//
// What this does not change: the token the client obtains is requested for the gateway route as its
// RFC 8707 resource. An upstream that validates the audience strictly ("MCP servers MUST validate that
// access tokens were issued specifically for them as the intended audience") refuses it unless its
// authorization server issues tokens for that resource.
import http from "node:http";
import https from "node:https";

export const PRM_PREFIX = "/.well-known/oauth-protected-resource";
const MAX_BYTES = 65536;
const CACHE_MS = 300000;
const TIMEOUT_MS = 5000;

// The canonical form of a resource URI: lower-case scheme and host, no fragment or query, no trailing slash
// (except the bare origin).
export function canonicalResource(u) {
  try {
    const x = new URL(String(u));
    const path = x.pathname.replace(/\/+$/, "");
    return `${x.protocol.toLowerCase()}//${x.host.toLowerCase()}${path}`;
  } catch { return null; }
}

// The route a well-known request names, or null. `routes` is a list of { path }.
export function prmRoute(pathname, routes) {
  if (pathname === PRM_PREFIX) return routes.length === 1 ? routes[0] : null;
  if (!pathname.startsWith(`${PRM_PREFIX}/`)) return null;
  const rest = pathname.slice(PRM_PREFIX.length);
  return routes.find((r) => r.path === rest) || null;
}

// Parameters of one Bearer challenge → { params: [[k, v]], ok } (a quoted-string or token per RFC 9110).
function parseChallenge(value) {
  const s = String(value || "").trim();
  const m = /^Bearer(?:\s+(.*))?$/is.exec(s);
  if (!m) return null;
  const params = [];
  const re = /\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]*))\s*,?/gy;
  const body = m[1] || "";
  let x;
  while (re.lastIndex < body.length && (x = re.exec(body))) params.push([x[1], x[2] !== undefined ? x[2].replace(/\\(.)/g, "$1") : x[3]]);
  if (re.lastIndex < body.length && body.slice(re.lastIndex).trim()) return null;
  return params;
}
const quote = (v) => `"${String(v).replace(/(["\\])/g, "\\$1")}"`;

// An upstream WWW-Authenticate value → { value (rewritten), upstreamMetadata (a URL or null) }. A value that
// is not a single Bearer challenge comes back unchanged.
export function rewriteChallenge(value, gatewayMetadataUrl) {
  if (Array.isArray(value)) return { value, upstreamMetadata: null };
  const params = parseChallenge(value);
  if (!params) return { value, upstreamMetadata: null };
  const i = params.findIndex(([k]) => k.toLowerCase() === "resource_metadata");
  const upstreamMetadata = i >= 0 ? params[i][1] : null;
  const rest = params.filter(([k]) => k.toLowerCase() !== "resource_metadata");
  return { value: `Bearer ${[["resource_metadata", gatewayMetadataUrl], ...rest].map(([k, v]) => `${k}=${quote(v)}`).join(", ")}`, upstreamMetadata };
}

function sameOrigin(a, b) { try { return new URL(a).origin === new URL(b).origin; } catch { return false; } }

// The URLs the upstream's metadata is read from, in order, all on the route's origin.
export function metadataCandidates(routeUrl, remembered) {
  const u = new URL(routeUrl);
  const path = u.pathname.replace(/\/+$/, "");
  const out = [];
  if (remembered && sameOrigin(remembered, routeUrl)) out.push(remembered);
  if (path) out.push(`${u.origin}${PRM_PREFIX}${path}`);
  out.push(`${u.origin}${PRM_PREFIX}`);
  return [...new Set(out)];
}

// One GET → parsed JSON object | null. opts: { agent, lookup } (the egress-checked lookup).
export function getJson(url, { agent, lookup } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(null); }
    const lib = u.protocol === "https:" ? https : u.protocol === "http:" ? http : null;
    if (!lib) return resolve(null);
    const req = lib.request(u, { method: "GET", headers: { accept: "application/json", "accept-encoding": "identity" }, ...(agent ? { agent } : {}), ...(lookup ? { lookup } : {}), timeout: TIMEOUT_MS }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      const chunks = []; let n = 0;
      res.on("data", (c) => { n += c.length; if (n > MAX_BYTES) { req.destroy(); return resolve(null); } chunks.push(c); });
      res.on("end", () => { try { const v = JSON.parse(Buffer.concat(chunks).toString("utf8")); resolve(v && typeof v === "object" && !Array.isArray(v) ? v : null); } catch { resolve(null); } });
      res.on("error", () => resolve(null));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
    req.end();
  });
}

const isHttpsOrLoopback = (s) => { try { const u = new URL(s); return u.protocol === "https:" || (u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)); } catch { return false; } };

// Per-route state: the upstream's metadata URL learned from a challenge, and a short cache.
export function createDiscovery({ fetchJson = getJson } = {}) {
  const state = new Map();
  const of = (route) => { let s = state.get(route.path); if (!s) state.set(route.path, (s = { remembered: null, doc: null, at: 0 })); return s; };
  return {
    // Called with each upstream 401 / 403: remembers the upstream's metadata URL and returns the header to send.
    challenge(route, value, gatewayMetadataUrl) {
      const r = rewriteChallenge(value, gatewayMetadataUrl);
      if (r.upstreamMetadata && sameOrigin(r.upstreamMetadata, route.url)) of(route).remembered = r.upstreamMetadata;
      return r.value;
    },
    // → { status, body } for GET /.well-known/oauth-protected-resource/<route>. resourceUrl: the gateway route.
    async metadata(route, resourceUrl, opts = {}) {
      const s = of(route);
      const want = canonicalResource(route.url);
      let doc = s.doc && Date.now() - s.at < CACHE_MS ? s.doc : null;
      let mismatch = false;
      if (!doc) {
        for (const url of metadataCandidates(route.url, s.remembered)) {
          const d = await fetchJson(url, opts);
          if (!d) continue;
          if (typeof d.resource !== "string" || canonicalResource(d.resource) !== want) { mismatch = true; continue; }
          if (!Array.isArray(d.authorization_servers) || !d.authorization_servers.length || !d.authorization_servers.every((a) => typeof a === "string" && isHttpsOrLoopback(a))) { mismatch = true; continue; }
          doc = d;
          break;
        }
        if (doc) { s.doc = doc; s.at = Date.now(); }
      }
      if (!doc) return mismatch ? { status: 502, body: { error: "the upstream's protected resource metadata does not describe this route's upstream" } } : { status: 404, body: { error: "the upstream publishes no protected resource metadata" } };
      return { status: 200, body: { ...doc, resource: resourceUrl } };
    }
  };
}
