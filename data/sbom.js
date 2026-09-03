// Standard-SBOM serializers for the MoorAI AIBOM (cli/moorai-aibom.mjs). Emit the SAME content-free
// device inventory the AIBOM already holds — asset names, counts, versions, and risk/capability labels —
// as a valid CycloneDX 1.6 JSON BOM and a valid SPDX 2.3 JSON document, so a MoorAI AIBOM can flow into
// SBOM tooling / GRC pipelines over the two formats that ecosystem speaks.
//
// SACRED RULE — content-free: the AIBOM component is NEVER spread. Each serializer reads only the known,
// content-free component fields (type, name, provider, local, version, riskLevel, capabilities, editor,
// kind), so a stray field on a component can never reach an SBOM. No token value, prompt, or file
// content is ever present in the AIBOM, and none is introduced here.
//
// Deterministic: identical AIBOM -> byte-identical output (ids derived from the inventory, timestamp
// taken from the AIBOM's own generatedAt).

import { createHash } from "node:crypto";

export const CYCLONEDX_SPEC = "1.6";
export const SPDX_VERSION = "SPDX-2.3";

// Allowed CycloneDX 1.6 component types we map onto.
export const CYCLONEDX_TYPES = new Set([
  "application", "framework", "library", "container", "platform", "operating-system",
  "device", "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"
]);

const str = (v) => (v == null ? "" : String(v));

// A deterministic UUID (v5-shaped, SHA-1 based) over a content-free seed — lets serial numbers and
// namespaces be byte-stable without inventing randomness.
const NS = Buffer.from("6f8a1b2c3d4e5f60718293a4b5c6d7e8", "hex");
function detUuid(seed) {
  const h = createHash("sha1").update(NS).update(Buffer.from(str(seed), "utf8")).digest().subarray(0, 16);
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const s = h.toString("hex");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

function componentsOf(d) { return Array.isArray(d && d.components) ? d.components : []; }
function seedOf(d) { return componentsOf(d).map((c) => `${c.type}|${c.name}|${str(c.version)}`).join("\n"); }
function capList(caps) { return ["net", "fs", "cred"].filter((k) => caps && caps[k]); }

const CDX_TYPE = {
  model: "machine-learning-model",
  agent: "application",
  "mcp-server": "application",
  "editor-extension": "application",
  skill: "data"
};

function cdxProps(c) {
  const p = [];
  const add = (name, value) => { if (value !== "" && value != null) p.push({ name, value: str(value) }); };
  add("moorai:aibom:type", c.type);
  add("moorai:provider", c.provider);
  if (c.type === "model") add("moorai:local", c.local ? "true" : "false");
  add("moorai:editor", c.editor);
  add("moorai:kind", c.kind);
  add("moorai:transport", c.transport);
  add("moorai:riskLevel", c.riskLevel);
  const caps = capList(c.capabilities);
  if (caps.length) add("moorai:capabilities", caps.join(","));
  return p;
}

export function toCycloneDX(d = {}) {
  const comps = componentsOf(d);
  const timestamp = d.generatedAt || "1970-01-01T00:00:00.000Z";
  const version = str(d.version || d.specVersion || "");
  const components = comps.map((c, i) => {
    const type = CDX_TYPE[c.type] || "application";
    const out = { type, "bom-ref": `moorai-${c.type}-${i}`, name: str(c.name) };
    if (c.version) out.version = str(c.version);
    const props = cdxProps(c);
    if (props.length) out.properties = props;
    return out;
  });
  return {
    bomFormat: "CycloneDX",
    specVersion: CYCLONEDX_SPEC,
    serialNumber: `urn:uuid:${detUuid(seedOf(d))}`,
    version: 1,
    metadata: {
      timestamp,
      tools: { components: [{ type: "application", name: "MoorAI-AIBOM", version }] },
      component: { type: "device", "bom-ref": "moorai-device", name: str(d.device || "device") }
    },
    components
  };
}

function spdxComment(c) {
  const parts = [];
  if (c.type === "model" && c.local) parts.push("local model");
  if (c.riskLevel) parts.push(`risk=${c.riskLevel}`);
  const caps = capList(c.capabilities);
  if (caps.length) parts.push(`caps=${caps.join("|")}`);
  if (c.editor) parts.push(`editor=${c.editor}`);
  if (c.kind) parts.push(`kind=${c.kind}`);
  return parts.join("; ");
}

export function toSpdx(d = {}) {
  const comps = componentsOf(d);
  const created = d.generatedAt || "1970-01-01T00:00:00.000Z";
  const version = str(d.version || d.specVersion || "");
  const device = str(d.device || "device");
  const packages = comps.map((c, i) => {
    const pkg = {
      SPDXID: `SPDXRef-Package-${i}`,
      name: str(c.name),
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      supplier: c.provider ? `Organization: ${str(c.provider)}` : "NOASSERTION",
      primaryPackagePurpose: c.type === "model" ? "MACHINE_LEARNING_MODEL" : "APPLICATION"
    };
    if (c.version) pkg.versionInfo = str(c.version);
    const comment = spdxComment(c);
    if (comment) pkg.comment = comment;
    return pkg;
  });
  const relationships = packages.map((p) => ({
    spdxElementId: "SPDXRef-DOCUMENT",
    relatedSpdxElement: p.SPDXID,
    relationshipType: "DESCRIBES"
  }));
  return {
    spdxVersion: SPDX_VERSION,
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `MoorAI-AIBOM-${device}`,
    documentNamespace: `https://moorai.dev/spdx/${detUuid(seedOf(d))}`,
    creationInfo: {
      created,
      creators: [`Tool: MoorAI-AIBOM-${version}`, "Organization: MoorAI"]
    },
    packages,
    relationships
  };
}
