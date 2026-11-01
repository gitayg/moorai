// Authorization-server metadata checks at discovery, under signed policy `mcpOAuth.authServer`
// ("report" | "block"; absent or "off": nothing is fetched). A client that discovers a route through the
// gateway learns its authorization servers only from the protected-resource metadata the gateway serves
// (./oauth-discovery.mjs), so the gateway can refuse to point it at one that fails what the MCP 2026-07-28
// revision requires of the client (basic/authorization):
//   issuer    "the `issuer` value in the document MUST be identical to the issuer identifier used to
//             construct the well-known URL. If they differ, the client MUST NOT use the metadata."
//   https     "All authorization server endpoints MUST be served over HTTPS." (loopback http is accepted,
//             as ./oauth-discovery.mjs accepts a loopback authorization server)
//   pkce      "If `code_challenge_methods_supported` is absent, the authorization server does not support
//             PKCE and MCP clients MUST refuse to proceed." and "MCP clients MUST use the `S256` code
//             challenge method": a document without S256 in that list fails.
// The documents are read in the order the revision gives (RFC 8414 path insertion, then OpenID Connect
// Discovery path insertion and path appending), through the route's egress checks, at most 4 servers; a
// document naming more fails the check ("too-many-servers") rather than being served with the rest unchecked.
// The upstream chooses these URLs, so each fetch also passes an address check (RFC 9728 7.7: "Clients SHOULD
// take appropriate precautions against SSRF attacks, such as blocking requests to internal IP address
// ranges"): https only, and every address the name resolves to (or the IP literal) must be public
// (egress-proxy/address.mjs addressClass). Loopback, over http or https, is allowed only when the route's own
// upstream is on loopback; private, link-local, unique-local and cloud metadata addresses never are. A new
// connection is opened for each fetch, so a pooled socket is never reused unchecked. A fetch the address check
// refuses is never made, and fails the check ("address"): the client would be sent to that address itself.
// An authorization server whose metadata cannot be read gets no verdict: the gateway may not be able to
// reach what the client can. What never passes through the gateway, and so is not checked here: the
// authorization request (redirect_uri, state, the PKCE challenge actually sent), the token request and
// client registration. The client contacts the authorization server directly.
import { addressClass, isMetadataAddress, isLocalAddress, ipOf } from "../egress-proxy/address.mjs";
import { isLoopbackHost } from "./config.mjs";

export const MAX_SERVERS = 4;
export const AS_ADDRESS_CODE = "MOORAI_AS_ADDRESS";
// What fetchJson returns for a URL the address check refused (by asUrlOk, or by asLookup's onRefuse).
export const AS_REFUSED = Symbol("authorization server address refused");

// Whether the route's upstream URL names this host (a loopback name or address).
export function upstreamIsLoopback(routeUrl) {
  try { const h = new URL(routeUrl).hostname; const ip = ipOf(h); return ip ? isLocalAddress(ip) : isLoopbackHost(h); } catch { return false; }
}
// One address an authorization-server fetch may connect to.
export function asAddressOk(ip, loopbackOk) {
  if (isMetadataAddress(ip)) return false;
  const c = addressClass(ip);
  return c === "public" || (c === "special" && loopbackOk && isLocalAddress(ip));
}
// An authorization-server metadata URL the gateway may fetch, before any lookup: https (http only to a loopback
// host when loopbackOk), and an IP literal host must pass asAddressOk (a literal is never looked up).
export function asUrlOk(url, loopbackOk) {
  let u;
  try { u = new URL(String(url)); } catch { return false; }
  const ip = ipOf(u.hostname);
  if (u.protocol === "http:") { if (!loopbackOk || !(ip ? isLocalAddress(ip) : isLoopbackHost(u.hostname))) return false; }
  else if (u.protocol !== "https:") return false;
  return !ip || asAddressOk(ip, loopbackOk);
}
// A dns.lookup-compatible wrapper that refuses the connection when any resolved address fails asAddressOk
// (and then calls onRefuse).
export function asLookup(lookup, loopbackOk, onRefuse) {
  return function asCheckedLookup(hostname, options, cb) {
    if (typeof options === "function") { cb = options; options = {}; }
    const opts = typeof options === "number" ? { family: options } : { ...(options || {}) };
    lookup(hostname, { ...opts, all: true }, (err, addrs) => {
      if (err) return cb(err);
      const list = Array.isArray(addrs) ? addrs : [];
      if (!list.length || list.some((a) => !asAddressOk(String(a.address), loopbackOk))) { if (onRefuse) onRefuse(); return cb(Object.assign(new Error("an authorization server address is not public"), { code: AS_ADDRESS_CODE })); }
      if (opts.all) return cb(null, list);
      cb(null, list[0].address, list[0].family);
    });
  };
}

// The metadata URLs for one issuer identifier, in the revision's order.
export function asMetadataCandidates(issuer) {
  let u;
  try { u = new URL(String(issuer)); } catch { return []; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return [];
  const path = u.pathname.replace(/\/+$/, "");
  if (!path) return [`${u.origin}/.well-known/oauth-authorization-server`, `${u.origin}/.well-known/openid-configuration`];
  return [`${u.origin}/.well-known/oauth-authorization-server${path}`, `${u.origin}/.well-known/openid-configuration${path}`, `${u.origin}${path}/.well-known/openid-configuration`];
}

const isHttpsOrLoopback = (s) => { try { const u = new URL(s); return u.protocol === "https:" || (u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname)); } catch { return false; } };
const ENDPOINTS = ["authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint", "introspection_endpoint", "pushed_authorization_request_endpoint"];

// One metadata document against the issuer it was read for → the failed checks ([] = passes).
export function asDocFailures(issuer, doc) {
  const out = [];
  if (typeof doc.issuer !== "string" || doc.issuer !== String(issuer)) out.push("issuer");
  if (!isHttpsOrLoopback(String(issuer)) || ENDPOINTS.some((k) => doc[k] != null && (typeof doc[k] !== "string" || !isHttpsOrLoopback(doc[k])))) out.push("https");
  const m = doc.code_challenge_methods_supported;
  if (!Array.isArray(m) || !m.includes("S256")) out.push("pkce");
  return out;
}

// authorizationServers → [{ index, failures }] for each server whose metadata was read and failed, or whose
// address was refused ("address"). A list of more than MAX_SERVERS fails as a whole ("too-many-servers"), with
// nothing fetched: the servers past the cap would otherwise be served unchecked.
// fetchJson(url) → object | null (cannot be read) | AS_REFUSED.
export async function checkAuthServers(authorizationServers, fetchJson) {
  const out = [];
  if (Array.isArray(authorizationServers) && authorizationServers.length > MAX_SERVERS) return [{ index: MAX_SERVERS, failures: ["too-many-servers"] }];
  const list = Array.isArray(authorizationServers) ? authorizationServers : [];
  for (let i = 0; i < list.length; i++) {
    for (const url of asMetadataCandidates(list[i])) {
      const doc = await fetchJson(url);
      if (doc === AS_REFUSED) { out.push({ index: i, failures: ["address"] }); break; }
      if (!doc) continue;
      const failures = asDocFailures(list[i], doc);
      if (failures.length) out.push({ index: i, failures });
      break;
    }
  }
  return out;
}
