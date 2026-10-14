// Cloud instance-metadata and container-credential endpoints: the addresses a cloud machine or container
// serves its own role credentials on. A coding agent has no routine reason to contact one; an injected or
// compromised one does it to take over the machine's cloud identity (ATT&CK T1552.005).
//
// Each entry checked against the vendor's own documentation (2026-10-08). The addresses are the ones
// egress-proxy/address.mjs refuses as METADATA, which connects where this one only detects; that module
// imports node:net and this one must stay browser-safe, so the embedded-IPv4 reading is repeated here and
// test/cloud-metadata.test.mjs pins the two to the same verdicts.
//
// Hosts are stored as the WHATWG URL parser serialises them (lower case, IPv6 bracketed and compressed),
// so a lookup is one normalisation and one Map read.
export const METADATA_HOSTS = [
  // AWS EC2 IMDS: "http://169.254.169.254/latest/meta-data/" and, over IPv6, "[fd00:ec2::254]"; IMDSv2
  // takes a token from PUT /latest/api/token first.
  // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
  // Azure IMDS answers on the same IPv4 address (/metadata/…, header `Metadata: true`).
  // https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
  // GCP's metadata server answers on it too. https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
  { host: "169.254.169.254", vendor: "aws-imds, azure-imds, gcp-metadata" },
  { host: "[fd00:ec2::254]", vendor: "aws-imds" },
  // GCP: "metadata.google.internal", and over IPv6 "fd20:ce::254" (/computeMetadata/v1, header
  // `Metadata-Flavor: Google`). https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
  { host: "metadata.google.internal", vendor: "gcp-metadata" },
  { host: "[fd20:ce::254]", vendor: "gcp-metadata" },
  // Azure WireServer: 168.63.129.16, the VM agent's channel to the platform (80/tcp, 32526/tcp).
  // https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
  { host: "168.63.129.16", vendor: "azure-wireserver" },
  // Alibaba Cloud ECS: "http://100.100.100.200/latest/meta-data/".
  // https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata
  { host: "100.100.100.200", vendor: "alibaba-metadata" },
  // ECS task credentials: 169.254.170.2 + AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.
  // https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
  { host: "169.254.170.2", vendor: "ecs-task-credentials" },
  // EKS Pod Identity agent: 169.254.170.23 and [fd00:ec2::23], /v1/credentials.
  // https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html
  { host: "169.254.170.23", vendor: "eks-pod-identity" },
  { host: "[fd00:ec2::23]", vendor: "eks-pod-identity" }
];

const BY_HOST = new Map(METADATA_HOSTS.map((e) => [e.host, e]));

// The host as WHATWG serialises it: numeric IPv4 spellings (2852039166, 0xa9fea9fe, 0251.0376.0251.0376,
// 169.254.43518) to dotted decimal, percent-encoding and full-width forms decoded, IPv6 compressed.
function whatwgHost(h) {
  try { return new URL(`http://${h}/`).hostname; } catch { return null; }
}

// The IPv4 address an IPv6 address carries, read the way egress-proxy/address.mjs embeddedV4 reads it:
// IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96 and 64:ff9b:1::/48 (last 32 bits), 6to4 2002::/16.
function embeddedV4(ip6) {
  const halves = String(ip6).toLowerCase().split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const w = [...head, ...Array(Math.max(0, fill)).fill("0"), ...rest].map((x) => parseInt(x, 16));
  if (w.length !== 8 || !w.every((x) => Number.isInteger(x) && x >= 0 && x <= 0xffff)) return null;
  const v4 = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  if (w.slice(0, 5).every((x) => x === 0) && w[5] === 0xffff) return v4(w[6], w[7]);
  if (w[0] === 0x64 && w[1] === 0xff9b && w.slice(2, 6).every((x) => x === 0)) return v4(w[6], w[7]);
  if (w[0] === 0x64 && w[1] === 0xff9b && w[2] === 1) return v4(w[6], w[7]);
  if (w[0] === 0x2002) return v4(w[1], w[2]);
  return null;
}

const BARE_V6 = /^[0-9a-f]*:[0-9a-f]*:[0-9a-f:.]*$/i;

// The entry a destination host belongs to, or null. `raw` is a host as a command names it: no scheme,
// path or port (data/net-exec.js hostOf), an IPv6 address bracketed or bare. A shell substitution ends
// what can be known of it (`169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` is 169.254.170.2).
export function metadataHost(raw) {
  let s = String(raw || "").trim();
  const sub = s.search(/[$`]/);
  if (sub >= 0) s = s.slice(0, sub);
  if (!s || s.length > 255) return null;
  if (!s.startsWith("[") && BARE_V6.test(s)) s = `[${s}]`;
  const h = whatwgHost(s);
  if (!h) return null;
  const name = h.replace(/\.$/, "");
  const hit = BY_HOST.get(name);
  if (hit) return hit;
  if (name.startsWith("[")) {
    const v4 = embeddedV4(name.slice(1, -1));
    if (v4) return BY_HOST.get(v4) || null;
  }
  return null;
}
