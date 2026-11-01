// Cloud Instance Metadata API (ATT&CK T1552.005): a command the agent runs that reaches a cloud or
// container metadata endpoint — the address a machine serves its own role credentials on. A coding agent
// has no routine reason to curl 169.254.169.254; an injected or compromised one does it to take over the
// machine's cloud identity. The egress proxy already refuses these (egress-proxy/address.mjs), but only
// where it is deployed; this detector flags the command itself on the hook, proxy and gateway surfaces.
//
// Credited on threat #55 (credential access) as T1552.005. The host set and the obfuscated-spelling
// reader are data/metadata-hosts.js, shared with the egress proxy and pinned to it by
// test/cloud-metadata.test.mjs. Content-free: refine runs once, the reported match is one character.
import { metadataHost } from "./metadata-hosts.js";

const ONCE = /^[\s\S]/;
// A cheap gate: a metadata address, in dotted, IPv6, decimal, hex or octal spelling, appears somewhere.
// The full decision is metadataHost() on each extracted host — the prefilter only avoids the scan on
// ordinary text.
const PREFILTER = /169[.-]254[.-]|a9fea9fe|nip\.io|sslip\.io|xip\.io|traefik\.me|rbndr\.us|1u\.ms|metadata\.google\.internal|100\.100\.100\.200|168\.63\.129\.16|fd00:ec2|fd20:ce|0x[0-9a-f]{6,}|\b0{0,2}251\.|\d{9,}/i;
const HOSTISH = /(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^\s"'`;|&<>()@/]{0,64}@)?(\[[0-9a-fA-F:.]+\]|[0-9a-zA-Z._-]+)(?::\d{1,5})?/gi;
const MAX = 20_000;
// Wildcard-DNS and rebinding services answer a name with the address written into it
// (`169.254.169.254.nip.io`, `169-254-169-254.sslip.io`, `a9fea9fe.nip.io`, `7f000001.a9fea9fe.rbndr.us`), so
// such a name reaches the metadata endpoint while no metadata address appears as a host. Only names under
// these services are decoded; any other name is judged as written.
const WILDCARD_DNS = /\.(?:nip\.io|sslip\.io|xip\.io|traefik\.me|rbndr\.us|1u\.ms)\.?$/i;
const EMBED_QUAD = /(?:^|[.-])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})(?=[.-])/g;
const EMBED_HEX = /(?:^|[.-])([0-9a-f]{8})(?=[.-])/gi;
export function wildcardMetadataHost(host) {
  const h = String(host || "");
  if (h.length > 255 || !WILDCARD_DNS.test(h)) return false;
  for (const re of [EMBED_QUAD, EMBED_HEX]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(h)) !== null) {
      const ip = m.length > 2 ? m.slice(1, 5).join(".") : [0, 2, 4, 6].map((i) => parseInt(m[1].slice(i, i + 2), 16)).join(".");
      if (metadataHost(ip)) return true;
      re.lastIndex = m.index + 1;
    }
  }
  return false;
}

export function cloudMetadataHit(text) {
  if (typeof text !== "string" || !text || text.length > MAX) return false;
  if (!PREFILTER.test(text)) return false;
  HOSTISH.lastIndex = 0;
  let m, n = 0;
  while ((m = HOSTISH.exec(text)) !== null && n++ < 512) {
    if (m[1] && (metadataHost(m[1]) || wildcardMetadataHost(m[1]))) return true;
    if (m.index === HOSTISH.lastIndex) HOSTISH.lastIndex++;
  }
  return false;
}

export const CLOUD_METADATA_DETECTORS = [
  {
    detectorId: "cloud-metadata-access",
    threatId: 55,
    stages: ["prompt", "output"],
    mode: "warn",
    hint: "Reaches a cloud instance-metadata or container-credential endpoint (169.254.169.254, metadata.google.internal, 169.254.170.2) — harvests the machine's cloud identity.",
    patterns: [ONCE],
    refine: (_m, text) => cloudMetadataHit(text)
  }
];
