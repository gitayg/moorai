// The open, signed MCP server and skill catalogue: the pure half (format, signed bytes, validation).
// cli/mcp-catalogue.mjs signs, verifies, caches and maps entries onto MCP reputation signals;
// scripts/mcp-catalogue-build.mjs builds and signs a catalogue from data/mcp-catalogue/source.json.
//
// Wording: a verdict says what MoorAI's scan FOUND ("no-findings", "review", ...), never that a server
// is safe. "not-scanned" means the name is catalogued but no MoorAI scan stands behind that version.
//
// Shape (every field below is inside the signature except `sig`):
//   { catalogue: "moorai-mcp-catalogue", v: 1, seq, issuedAt, expiresAt?, publisher,
//     entries: [ { kind, ecosystem, name, status, source, repository?, license?, registryName?,
//                  advisories?, reputation?, versions: [ { version, verdict, reasons?, sha256?,
//                  treeSha256?, scannedAt?, engine? } ] } ],
//     sig: { v: 1, alg: "ed25519", keyId, sig } }
import { createHash } from "node:crypto";

export const CATALOGUE_FORMAT = "moorai-mcp-catalogue";
export const CATALOGUE_VERSION = 1;
export const CATALOGUE_SIG_VERSION = 1;
export const CATALOGUE_KINDS = ["mcp-server", "skill"];
export const CATALOGUE_ECOSYSTEMS = ["npm", "pypi", "docker", "remote", "skill"];
export const CATALOGUE_STATUSES = ["listed", "do-not-install"];
export const CATALOGUE_VERDICTS = ["no-findings", "caution", "review", "do-not-install", "not-scanned"];
export const CATALOGUE_SOURCES = ["official-registry", "reference-servers", "vendor", "community", "advisory"];

// Key-sorted serialization, byte-identical to cli/hook-core.mjs canonicalJson (kept here so this file
// needs nothing beyond node:crypto).
export function canonicalJson(v) {
  if (v === undefined) return "null";
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}

// sha256 over everything except the signature envelope.
export function catalogueDigest(cat) {
  const { sig, ...b } = cat || {};
  return createHash("sha256").update(canonicalJson(b)).digest("hex");
}

// The exact bytes signed. No catalogue or publisher key is published yet; once one is, changing these
// bytes breaks every signature already issued, so the format is pinned by a test.
export function catalogueCanonical(s) {
  return `moorai-mcp-catalogue|v${s.v}|${s.seq}|${s.issuedAt}|${s.digest}`;
}

const HEX64 = /^[0-9a-f]{64}$/;
const isStr = (x, max = 214) => typeof x === "string" && x.length > 0 && x.length <= max;

export function validateEntry(e) {
  const err = [];
  if (!e || typeof e !== "object" || Array.isArray(e)) return ["entry is not an object"];
  if (!CATALOGUE_KINDS.includes(e.kind)) err.push(`kind ${JSON.stringify(e.kind)}`);
  if (!CATALOGUE_ECOSYSTEMS.includes(e.ecosystem)) err.push(`ecosystem ${JSON.stringify(e.ecosystem)}`);
  if (e.kind === "skill" && e.ecosystem !== "skill") err.push("a skill uses ecosystem skill");
  if (!isStr(e.name)) err.push("name");
  if (!CATALOGUE_STATUSES.includes(e.status)) err.push(`status ${JSON.stringify(e.status)}`);
  if (!CATALOGUE_SOURCES.includes(e.source)) err.push(`source ${JSON.stringify(e.source)}`);
  if (!Array.isArray(e.versions)) err.push("versions");
  else {
    const seen = new Set();
    for (const v of e.versions) {
      if (!v || typeof v !== "object" || !isStr(v.version, 128)) { err.push("version"); continue; }
      if (seen.has(v.version)) err.push(`duplicate version ${v.version}`);
      seen.add(v.version);
      if (!CATALOGUE_VERDICTS.includes(v.verdict)) err.push(`verdict ${JSON.stringify(v.verdict)}`);
      if (v.sha256 != null && !HEX64.test(v.sha256)) err.push("sha256");
      if (v.treeSha256 != null && !HEX64.test(v.treeSha256)) err.push("treeSha256");
      if (v.reasons != null && !(Array.isArray(v.reasons) && v.reasons.every((r) => isStr(r, 64)))) err.push("reasons");
    }
  }
  if (e.advisories != null && !(Array.isArray(e.advisories) && e.advisories.every((a) => isStr(a, 64)))) err.push("advisories");
  if (e.registryName != null && !/^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/.test(e.registryName)) err.push("registryName");
  return err.map((m) => `${e.ecosystem || "?"}:${e.name || "?"}: ${m}`);
}

export const entryKey = (e) => `${e.ecosystem}:${String(e.name).toLowerCase()}`;

export function validateCatalogue(c) {
  if (!c || typeof c !== "object" || c.catalogue !== CATALOGUE_FORMAT || c.v !== CATALOGUE_VERSION) return ["not a moorai-mcp-catalogue v1"];
  const err = [];
  if (!Number.isInteger(c.seq) || c.seq < 0) err.push("seq");
  if (!isStr(c.issuedAt, 40) || Number.isNaN(Date.parse(c.issuedAt))) err.push("issuedAt");
  if (c.expiresAt != null && Number.isNaN(Date.parse(c.expiresAt))) err.push("expiresAt");
  if (!Array.isArray(c.entries)) return [...err, "entries"];
  const keys = new Set();
  for (const e of c.entries) {
    err.push(...validateEntry(e));
    if (e && e.ecosystem && e.name) { const k = entryKey(e); if (keys.has(k)) err.push(`duplicate entry ${k}`); keys.add(k); }
  }
  return err;
}
