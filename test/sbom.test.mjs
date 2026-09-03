// SBOM serializer tests (data/sbom.js) + the moorai-aibom --format cyclonedx|spdx wiring. Pinned:
//   1. STRUCTURE — toCycloneDX yields a valid CycloneDX 1.6 JSON doc and toSpdx a valid SPDX 2.3 JSON
//      doc: required top-level fields, allowed component/package types, unique refs, resolvable
//      relationships.
//   2. CONTENT-FREE — the serializers read only the content-free AIBOM component fields; a stray field
//      planted on a component never reaches the SBOM.
//
//   node --test test/sbom.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { toCycloneDX, toSpdx, CYCLONEDX_TYPES } from "../data/sbom.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-aibom.mjs");
const SENTINEL = "SECRET-TOKEN-VALUE-sk-live-DO-NOT-LEAK";

const AIBOM = {
  bomFormat: "MoorAI-AIBOM", specVersion: "1.0", scope: "device", device: "testbox",
  generatedAt: "2026-01-01T00:00:00.000Z",
  summary: { providers: 1, models: 2, localModels: 1, agents: 1, mcpServers: 1, mcpHighRisk: 1, editorAiExtensions: 1, skills: 1, calls: 0, roughSpendUsd: null },
  components: [
    { type: "model", name: "claude-opus-4", provider: "Anthropic", local: false },
    { type: "model", name: "llama3.1", provider: "ollama", local: true },
    { type: "agent", name: "claude" },
    { type: "mcp-server", name: "github", riskLevel: "high", capabilities: { net: true, fs: false, cred: true }, transport: "stdio", secret: SENTINEL },
    { type: "editor-extension", name: "GitHub.copilot", editor: "vscode", version: "1.2.3" },
    { type: "skill", name: "docx", kind: "skill" }
  ]
};

const SPDXID_RE = /^SPDXRef-[0-9A-Za-z.-]+$/;

test("CycloneDX: valid 1.6 document shape", () => {
  const bom = toCycloneDX(AIBOM);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(typeof bom.version, "number");
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.ok(bom.metadata && bom.metadata.timestamp, "metadata.timestamp required");
  assert.ok(bom.metadata.tools, "metadata.tools required");
  assert.ok(Array.isArray(bom.components) && bom.components.length === AIBOM.components.length);
  const refs = new Set();
  for (const c of bom.components) {
    assert.ok(CYCLONEDX_TYPES.has(c.type), `component type ${c.type} must be a valid CycloneDX type`);
    assert.ok(c.name, "component needs a name");
    assert.ok(c["bom-ref"], "component needs a bom-ref");
    assert.ok(!refs.has(c["bom-ref"]), `bom-ref ${c["bom-ref"]} must be unique`);
    refs.add(c["bom-ref"]);
  }
});

test("CycloneDX: models map to machine-learning-model, versions preserved", () => {
  const bom = toCycloneDX(AIBOM);
  const models = bom.components.filter((c) => c.type === "machine-learning-model");
  assert.equal(models.length, 2);
  const ext = bom.components.find((c) => c.name === "GitHub.copilot");
  assert.equal(ext.version, "1.2.3");
});

test("SPDX: valid 2.3 JSON document shape", () => {
  const doc = toSpdx(AIBOM);
  assert.equal(doc.spdxVersion, "SPDX-2.3");
  assert.equal(doc.dataLicense, "CC0-1.0");
  assert.equal(doc.SPDXID, "SPDXRef-DOCUMENT");
  assert.ok(doc.name, "document name required");
  assert.ok(doc.documentNamespace, "documentNamespace required");
  assert.ok(doc.creationInfo && doc.creationInfo.created, "creationInfo.created required");
  assert.ok(Array.isArray(doc.creationInfo.creators) && doc.creationInfo.creators.some((c) => c.startsWith("Tool:")), "a Tool: creator required");
  assert.ok(Array.isArray(doc.packages) && doc.packages.length === AIBOM.components.length);
  const ids = new Set([doc.SPDXID]);
  for (const p of doc.packages) {
    assert.match(p.SPDXID, SPDXID_RE, `package SPDXID ${p.SPDXID}`);
    assert.ok(p.name, "package needs a name");
    assert.ok(p.downloadLocation, "package needs downloadLocation");
    assert.ok(!ids.has(p.SPDXID), `SPDXID ${p.SPDXID} must be unique`);
    ids.add(p.SPDXID);
  }
});

test("SPDX: DOCUMENT DESCRIBES every package and refs resolve", () => {
  const doc = toSpdx(AIBOM);
  const ids = new Set([doc.SPDXID, ...doc.packages.map((p) => p.SPDXID)]);
  assert.ok(Array.isArray(doc.relationships) && doc.relationships.length >= doc.packages.length);
  const described = doc.relationships.filter((r) => r.relationshipType === "DESCRIBES");
  assert.equal(described.length, doc.packages.length);
  for (const r of doc.relationships) {
    assert.ok(ids.has(r.spdxElementId), `spdxElementId ${r.spdxElementId} must resolve`);
    assert.ok(ids.has(r.relatedSpdxElement), `relatedSpdxElement ${r.relatedSpdxElement} must resolve`);
  }
});

test("CONTENT-FREE: a stray field on a component never reaches either SBOM", () => {
  const cdx = JSON.stringify(toCycloneDX(AIBOM));
  const spdx = JSON.stringify(toSpdx(AIBOM));
  assert.ok(!cdx.includes(SENTINEL), "CycloneDX leaked a stray field");
  assert.ok(!spdx.includes(SENTINEL), "SPDX leaked a stray field");
  // legitimate content-free inventory names are still present
  assert.ok(cdx.includes("claude-opus-4"));
  assert.ok(spdx.includes("claude-opus-4"));
});

test("DETERMINISTIC: identical AIBOM -> byte-identical SBOMs", () => {
  assert.equal(JSON.stringify(toCycloneDX(AIBOM)), JSON.stringify(toCycloneDX(AIBOM)));
  assert.equal(JSON.stringify(toSpdx(AIBOM)), JSON.stringify(toSpdx(AIBOM)));
});

test("CLI wiring: moorai-aibom --format cyclonedx emits valid CycloneDX JSON", () => {
  const out = execFileSync("node", [CLI, "--format", "cyclonedx"], { encoding: "utf8" });
  const bom = JSON.parse(out);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.ok(Array.isArray(bom.components));
});

test("CLI wiring: moorai-aibom --format spdx emits valid SPDX 2.3 JSON", () => {
  const out = execFileSync("node", [CLI, "--format", "spdx"], { encoding: "utf8" });
  const doc = JSON.parse(out);
  assert.equal(doc.spdxVersion, "SPDX-2.3");
  assert.equal(doc.SPDXID, "SPDXRef-DOCUMENT");
  assert.ok(Array.isArray(doc.packages));
});
