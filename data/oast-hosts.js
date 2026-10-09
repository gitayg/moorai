// Public out-of-band (OAST) and request-capture services: hosts whose whole purpose is to record whatever
// reaches them so someone else can read it later. A coding agent sending data to one is the last hop of
// an exfiltration (the published trigger-backdoor study's script posted `.env` to one); a plain lookup or
// GET is the "did my payload run?" ping that precedes it.
//
// Curated, small, and each entry checked against the vendor's own public documentation (2026-10-08).
// Entries that could not be verified there were dropped: bare `requestbin.*` hosts (the vendor's current
// RequestBin page does not name a capture domain; Pipedream's endpoint domain is listed instead) and
// canarytokens.org (documented as the site that issues tokens, not as a callback domain).
//
// `sub`: the vendor's capture endpoints are subdomains (a token per user); `apex`: the bare host itself
// receives captures (webhook.site puts the token in the path).
export const OAST_HOSTS = [
  // interactsh (ProjectDiscovery). "Default servers: oast.pro, oast.live, oast.site, oast.online,
  // oast.fun, oast.me"; the hosted web client "uses interact.sh as the default server".
  // https://docs.projectdiscovery.io/tools/interactsh/running , https://github.com/projectdiscovery/interactsh
  { domain: "oast.pro", sub: true, apex: false, vendor: "interactsh" },
  { domain: "oast.live", sub: true, apex: false, vendor: "interactsh" },
  { domain: "oast.site", sub: true, apex: false, vendor: "interactsh" },
  { domain: "oast.online", sub: true, apex: false, vendor: "interactsh" },
  { domain: "oast.fun", sub: true, apex: false, vendor: "interactsh" },
  { domain: "oast.me", sub: true, apex: false, vendor: "interactsh" },
  { domain: "interact.sh", sub: true, apex: false, vendor: "interactsh" },
  // Burp Collaborator (PortSwigger): "Currently, the domains in use are *.burpcollaborator.net or
  // *.oastify.com." https://portswigger.net/burp/documentation/desktop/settings/project/collaborator
  { domain: "burpcollaborator.net", sub: true, apex: false, vendor: "burp-collaborator" },
  { domain: "oastify.com", sub: true, apex: false, vendor: "burp-collaborator" },
  // Webhook.site: a "free, unique, random URL … Everything that's sent to these addresses are shown
  // instantly"; endpoint format https://webhook.site/{unique-id}. https://docs.webhook.site/
  { domain: "webhook.site", sub: true, apex: true, vendor: "webhook.site" },
  // Pipedream (RequestBin's operator): HTTP endpoints are created on *.m.pipedream.net.
  // https://pipedream.com/docs/workflows/triggers
  { domain: "m.pipedream.net", sub: true, apex: false, vendor: "pipedream" },
  // Request Catcher: "All requests sent to any path on the subdomain are forwarded to your browser in
  // real time." https://requestcatcher.com/
  { domain: "requestcatcher.com", sub: true, apex: false, vendor: "requestcatcher" },
  // Beeceptor: the endpoint is a subdomain, e.g. my-api.free.beeceptor.com.
  // https://beeceptor.com/docs/create-endpoint/
  { domain: "free.beeceptor.com", sub: true, apex: false, vendor: "beeceptor" },
  // Canarytokens (Thinkst): a DNS token is a hostname such as pz21qtyfsidipvrsuzs9n2udi.canarytokens.com.
  // https://docs.canarytokens.org/guide/dns-token.html
  { domain: "canarytokens.com", sub: true, apex: false, vendor: "canarytokens" }
];

// The entry a host belongs to, or null. `host` is a lowercased hostname with no port.
export function oastHost(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h || h.length > 253) return null;
  for (const e of OAST_HOSTS) {
    if (h === e.domain) { if (e.apex) return e; continue; }
    if (e.sub && h.endsWith("." + e.domain)) return e;
  }
  return null;
}

// Cheap prefilter for the detectors: does the text name any listed domain at all?
export const OAST_MENTION = new RegExp(`(?:${OAST_HOSTS.map((e) => e.domain.replace(/\./g, "\\.")).join("|")})(?![A-Za-z0-9-])`, "i");
