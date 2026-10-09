// Destination hosts and addresses at the network layer: which host spellings the egress proxy accepts, and
// which resolved addresses it refuses to connect to unless a rule names the destination.
//
// HOST FORM. A destination is a host name a rule could name (cli/egress-rules.mjs RULE_HOST_RE: lower-case
// letters, digits, hyphens and dots, after WHATWG normalisation, so IDN is punycode) or an IP literal.
// Anything else (an underscore, an empty label, a name the URL parser refuses) is refused: a rule could
// never have allowed it. Numeric IPv4 spellings (`2130706433`, `0x7f.1`, `127.1`) are what WHATWG makes of
// them, 127.0.0.1, so they are IP literals like any other.
//
// ADDRESS CLASSES. Refused unless a rule with an exact host names the destination (server.mjs): loopback,
// RFC 1918 private, carrier-grade NAT, link-local (cloud metadata at 169.254.169.254 included), unique-local
// IPv6, the benchmark and IETF protocol ranges, the Azure WireServer, IPv6 forms that embed an IPv4 address
// in one of those (::ffff:0:0/96, NAT64 64:ff9b::/96 and 64:ff9b:1::/48, 2002::/16), and the rest of
// 64:ff9b::/32. Never connected to at all: the unspecified address (0.0.0.0 reaches the local host on
// Linux), multicast, broadcast and reserved 240/4. Cloud metadata addresses
// (isMetadataAddress) need a rule naming the IP literal itself.
import net from "node:net";

const NAME_RE = /^(?=.{1,253}$)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})*$/;

function blockList(ranges) {
  const b = new net.BlockList();
  for (const [a, p, t] of ranges) b.addSubnet(a, p, t);
  return b;
}

const SPECIAL = blockList([
  ["10.0.0.0", 8, "ipv4"], ["100.64.0.0", 10, "ipv4"], ["127.0.0.0", 8, "ipv4"], ["169.254.0.0", 16, "ipv4"],
  ["172.16.0.0", 12, "ipv4"], ["192.0.0.0", 24, "ipv4"], ["192.0.2.0", 24, "ipv4"], ["192.168.0.0", 16, "ipv4"],
  ["198.18.0.0", 15, "ipv4"], ["198.51.100.0", 24, "ipv4"], ["203.0.113.0", 24, "ipv4"], ["168.63.129.16", 32, "ipv4"],
  ["::1", 128, "ipv6"], ["fc00::", 7, "ipv6"], ["fe80::", 10, "ipv6"], ["100::", 64, "ipv6"], ["2001:db8::", 32, "ipv6"]
]);
const NEVER = blockList([
  ["0.0.0.0", 8, "ipv4"], ["224.0.0.0", 4, "ipv4"], ["240.0.0.0", 4, "ipv4"],
  ["::", 128, "ipv6"], ["ff00::", 8, "ipv6"]
]);

// The NAT64 block: RFC 6052's well-known prefix 64:ff9b::/96 and RFC 8215's local-use 64:ff9b:1::/48 sit in
// it; neither RFC assigns the rest. An address in it that is not read as one of those two is "special".
const NAT64 = blockList([["64:ff9b::", 32, "ipv6"]]);

// The IPv4 address an IPv6 address carries in a translation prefix, or null. NAT64 (64:ff9b::/96, RFC 6052
// section 2.1; 64:ff9b:1::/48, RFC 8215) is read from the last 32 bits, the /96 layout of RFC
// 6052 section 2.2: RFC 8215 lets an operator use any RFC 6052 layout inside the /48, and its examples are
// /96 sub-prefixes. A translator configured with the /48, /56 or /64 layout embeds the address elsewhere.
function embeddedV4(ip6) {
  const words = expand6(ip6);
  if (!words) return null;
  const v4 = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  if (words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff) return v4(words[6], words[7]);
  if (words[0] === 0x64 && words[1] === 0xff9b && words.slice(2, 6).every((w) => w === 0)) return v4(words[6], words[7]);
  if (words[0] === 0x64 && words[1] === 0xff9b && words[2] === 1) return v4(words[6], words[7]);
  if (words[0] === 0x2002) return v4(words[1], words[2]);
  return null;
}
function expand6(s) {
  let str = String(s).toLowerCase();
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(str);
  if (tail) {
    const o = tail[1].split(".").map(Number);
    str = `${str.slice(0, -tail[1].length)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = str.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const words = [...head, ...Array(Math.max(0, fill)).fill("0"), ...rest].map((w) => parseInt(w, 16));
  return words.length === 8 && words.every((w) => Number.isInteger(w) && w >= 0 && w <= 0xffff) ? words : null;
}

// "public" | "special" (refused unless a rule names the destination) | "never" (never connected to).
export function addressClass(ip) {
  const fam = net.isIP(ip);
  if (!fam) return "never";
  const type = fam === 4 ? "ipv4" : "ipv6";
  if (NEVER.check(ip, type)) return "never";
  if (SPECIAL.check(ip, type)) return "special";
  if (fam === 6) {
    const v4 = embeddedV4(ip);
    if (v4) return addressClass(v4) === "public" ? "public" : NEVER.check(v4, "ipv4") ? "never" : "special";
    if (NAT64.check(ip, "ipv6")) return "special";
  }
  return "public";
}

// Cloud instance-metadata and credential endpoints: AWS / GCP / Azure / OCI (169.254.169.254, AWS IPv6
// fd00:ec2::254), ECS task metadata (169.254.170.2), EKS Pod Identity (169.254.170.23, fd00:ec2::23),
// Alibaba Cloud (100.100.100.200) and the Azure WireServer, 168.63.129.16: "a virtual public IP address
// that facilitates communication channels to Azure platform resources", the VM agent's WireServer (80/tcp,
// 32526/tcp), DHCP, DNS and load-balancer probes, "used in all regions and all national clouds"
// (learn.microsoft.com/azure/virtual-network/what-is-ip-address-168-63-129-16). Microsoft reserves
// 168.63.129.16/32 only (learn.microsoft.com/azure/networking/design-guide/ip-planning, "Avoid prohibited
// ranges"); the rest of 168.63.129.0/24 is not documented as special, so it stays public here. Each is
// "special" too; on top of that only a rule naming the exact IP literal reaches one (never a name that
// resolves to it).
const METADATA = blockList([
  ["169.254.169.254", 32, "ipv4"], ["169.254.170.2", 32, "ipv4"], ["169.254.170.23", 32, "ipv4"], ["100.100.100.200", 32, "ipv4"],
  ["168.63.129.16", 32, "ipv4"],
  ["fd00:ec2::254", 128, "ipv6"], ["fd00:ec2::23", 128, "ipv6"]
]);
const LOOPBACK = blockList([["127.0.0.0", 8, "ipv4"], ["::1", 128, "ipv6"]]);

function inList(list, ip) {
  const fam = net.isIP(ip);
  if (!fam) return false;
  if (list.check(ip, fam === 4 ? "ipv4" : "ipv6")) return true;
  const v4 = fam === 6 ? embeddedV4(ip) : null;
  return !!v4 && list.check(v4, "ipv4");
}

export function isMetadataAddress(ip) { return inList(METADATA, String(ip)); }

// Loopback, or one of `local` (this host's interface addresses, the proxy's bound address), in any IPv6
// form that embeds the IPv4 address.
export function isLocalAddress(ip, local = []) {
  const s = String(ip);
  if (inList(LOOPBACK, s)) return true;
  const b = new net.BlockList();
  for (const a of local) {
    const bare = String(a).replace(/%.*$/, "");
    const fam = net.isIP(bare);
    if (fam) b.addAddress(bare, fam === 4 ? "ipv4" : "ipv6");
  }
  return inList(b, s);
}

// The bare address of an IP-literal host (`[::1]` → `::1`), or "" when the host is a name.
export function ipOf(host) {
  const h = String(host || "");
  const bare = h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
  return net.isIP(bare) ? bare : "";
}

// A host as WHATWG normalises it (lower case, punycode, numeric IPv4 spellings to dotted, no trailing dot),
// or null when it is not a form a rule could name. IPv6 comes back bracketed, as rules spell it.
export function normalizeHost(raw) {
  const s = String(raw || "");
  if (!s || s.length > 255 || /[\s@/\\?#%]/.test(s)) return null;
  let h;
  try { h = new URL(`http://${s}/`).hostname; } catch { return null; }
  h = h.toLowerCase().replace(/\.$/, "");
  if (!h) return null;
  if (h.startsWith("[")) return net.isIP(h.slice(1, -1)) === 6 ? h : null;
  if (net.isIP(h) === 4) return h;
  return NAME_RE.test(h) ? h : null;
}
