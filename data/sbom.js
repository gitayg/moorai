// Standard-SBOM serializers for the MoorAI AIBOM (cli/moorai-aibom.mjs). Emit the SAME content-free
// device inventory the AIBOM already holds — asset names, counts, versions, and risk/capability labels —
// as a valid CycloneDX 1.6 JSON BOM and a valid SPDX 2.3 JSON document, so a MoorAI AIBOM can flow into
// SBOM tooling / GRC pipelines over the two formats that ecosystem speaks.
//
// SACRED RULE — content-free: the AIBOM component is NEVER spread. Each serializer reads only the known,
// content-free component fields (type, name, provider, local, version, riskLevel, capabilities, editor,
// kind, the use fields usageStatus / lastUsed / calls30d and the declared governance fields of
// cli/aibom-declarations.mjs, each checked against its own shape), so a stray field on a component can
// never reach an SBOM. No token value, prompt, or file
// content is ever present in the AIBOM, and none is introduced here.
//
// Deterministic: identical AIBOM -> byte-identical output (ids derived from the inventory, timestamp
// taken from the AIBOM's own generatedAt).

import { createHash } from "node:crypto";
import { cleanDeclaration, validItemName, DECLARATION_STATUSES } from "../cli/aibom-declarations.mjs";

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

// Installed vs used (cli/aibom-usage.mjs). Only the known vocabulary, a YYYY-MM-DD date and a non-negative
// integer pass; anything else on those fields is dropped. → [[name, value]] in a fixed order.
const USAGE_STATUSES = new Set(["used", "never-seen", "not-observable"]);
function usageOf(c) {
  const out = [];
  if (USAGE_STATUSES.has(c.usageStatus)) out.push(["usageStatus", c.usageStatus]);
  if (typeof c.lastUsed === "string" && /^\d{4}-\d{2}-\d{2}$/.test(c.lastUsed)) out.push(["lastUsed", c.lastUsed]);
  if (Number.isInteger(c.calls30d) && c.calls30d >= 0) out.push(["calls30d", String(c.calls30d)]);
  return out;
}

// Declared governance (signed policy aibomDeclarations, cli/aibom-declarations.mjs), re-checked here:
// { status, key, fields } with only a known status, a valid item key and fields that pass the validator.
function declarationOf(c) {
  const status = DECLARATION_STATUSES.includes(c.declarationStatus) ? c.declarationStatus : null;
  if (!status) return null;
  const k = typeof c.declarationKey === "string" ? c.declarationKey : "";
  const sep = k.indexOf(":");
  const key = sep > 0 && validItemName(k.slice(0, sep), k.slice(sep + 1)) ? k : null;
  const fields = status === "declared" ? cleanDeclaration(c.declared).declaration || {} : {};
  return { status, key, fields };
}

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
  for (const [k, v] of usageOf(c)) add(`moorai:${k}`, v);
  const decl = declarationOf(c);
  if (decl) {
    add("moorai:declaration", decl.status);
    add("moorai:declaration:key", decl.key);
    // A model's purpose and intended users go in its model card (modelCard.considerations); the rest here.
    for (const f of ["owner", "purpose", "dataUse", "retention", "intendedUsers"])
      if (!(c.type === "model" && (f === "purpose" || f === "intendedUsers"))) add(`moorai:declaration:${f}`, decl.fields[f]);
  }
  return p;
}

// CycloneDX 1.6 modelCard.considerations: "users" (Who are the intended users of the model?) and
// "useCases" (What are the intended use cases of the model?), each an array of strings.
function cdxModelCard(c) {
  const decl = c.type === "model" ? declarationOf(c) : null;
  if (!decl) return null;
  const considerations = {};
  if (decl.fields.intendedUsers) considerations.users = [decl.fields.intendedUsers];
  if (decl.fields.purpose) considerations.useCases = [decl.fields.purpose];
  return Object.keys(considerations).length ? { considerations } : null;
}

const SUMMARY_COUNTS = ["declared", "undeclared", "notDeclarable", "declarationsDropped"];
function cdxMetadataProps(d) {
  const s = d && d.summary && typeof d.summary === "object" ? d.summary : {};
  const p = SUMMARY_COUNTS.filter((k) => Number.isInteger(s[k]) && s[k] >= 0).map((k) => ({ name: `moorai:declarations:${k}`, value: String(s[k]) }));
  if (p.length && ["device-policy", "file", "none"].includes(s.declarationsSource)) p.push({ name: "moorai:declarations:source", value: s.declarationsSource });
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
    const card = cdxModelCard(c);
    if (card) out.modelCard = card;
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
      component: { type: "device", "bom-ref": "moorai-device", name: str(d.device || "device") },
      ...(cdxMetadataProps(d).length ? { properties: cdxMetadataProps(d) } : {})
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
  for (const [k, v] of usageOf(c)) parts.push(`${k}=${v}`);
  const decl = declarationOf(c);
  if (decl) parts.push(`declaration=${decl.status}`);
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
