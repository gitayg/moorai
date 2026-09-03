#!/usr/bin/env node
// MoorAI — in-toto attestation export of the device's content-free governance records.
//
// Turns a governed record (or a whole tamper-evident chain of them) into a signed-attestation-ready
// in-toto Statement (https://in-toto.io/Statement/v1) carrying a SLSA-style provenance predicate
// (https://slsa.dev/provenance/v1). This is the interchange format supply-chain tooling already speaks
// (cosign / in-toto / SLSA verifiers), so a MoorAI device can hand its governance provenance to that
// tooling over the standard envelope — WITHOUT carrying any prompt, response, argument, or path
// content. Every field is governance metadata or a one-way hash: tool, category, risk, decision, stage,
// tenant, the content hash, and the chain link (seq/prev/chash/rhash).
//
// SACRED RULE — content-free: a record is NEVER spread. Every governed record passes through the strict
// allowlist sanitizeRecord() before any of its fields reach a subject or the predicate, so a stray
// content field on the row can never reach the Statement.
//
// The subject digest is the chain's chash when present — a genuine keyless SHA-256 over the record's
// content-free link fields (cli/record-chain.mjs), so it is a spec-valid in-toto sha256 DigestSet
// entry. With no chain link, the (one-way, tenant-keyed) content hash is carried under a MoorAI-namespaced
// digest algorithm instead. Deterministic: same records + version -> byte-stable Statement.
//
//   node cli/moorai-attest.mjs            # attest this device's on-device signals (stdout JSON)
//
// Also usable as a pure builder: buildAttestation(record | records, { version }).

import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { chainOf } from "./record-chain.mjs";

export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const PREDICATE_TYPE = "https://slsa.dev/provenance/v1";
export const BUILDER_ID = "https://moorai.dev/agent-governance";
export const BUILD_TYPE = "https://moorai.dev/agent-governance/v1";
const NO_KEY = "h2:nokey";

let VERSION = "unknown";
try { VERSION = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")).version; } catch { /* version is cosmetic */ }

const str = (v) => (v == null ? "" : String(v));

// One-way hashes are our own tokens (h2:… / h2:nokey / seeded test ids). Bound the length and restrict
// the charset before it lands in a digest value — closes any injection / ReDoS surface.
function safeHash(h) { return str(h).slice(0, 128).replace(/[^A-Za-z0-9:._-]/g, ""); }

const HEX64 = /^[0-9a-f]{64}$/;

// STRICT allowlist. The row is never spread — only these content-free fields are ever read, so a stray
// prompt/argument/path field on the record cannot reach the Statement. The chain link is pulled through
// the single-sourced accessor so this module never hardcodes the chain key.
export function sanitizeRecord(r = {}) {
  const c = chainOf(r) || {};
  return {
    tool: str(r.tool),
    category: str(r.category),
    risk: str(r.risk != null ? r.risk : r.riskLevel),
    decision: str(r.decision),
    stage: str(r.stage),
    tenant: str(r.tenant),
    contentHash: str(r.contentHash),
    seq: Number.isInteger(c.seq) ? c.seq : null,
    prev: str(c.prev),
    chash: str(c.chash),
    rhash: str(c.rhash)
  };
}

function subjectOf(r, idx) {
  const digest = {};
  if (HEX64.test(r.chash)) digest.sha256 = r.chash;
  const ch = safeHash(r.contentHash);
  if (ch && ch !== NO_KEY) digest["moorai-content-hash-v2"] = ch;
  const rh = safeHash(r.rhash);
  if (rh) digest["moorai-record-rhash"] = rh;
  if (Object.keys(digest).length === 0) digest["moorai-nokey"] = "nokey";
  return { name: `moorai:governed-record:${r.seq != null ? r.seq : idx}`, digest };
}

function annotations(r) {
  const a = {};
  const put = (k, v) => { if (v !== "" && v != null) a[k] = v; };
  put("moorai.tool", r.tool);
  put("moorai.category", r.category);
  put("moorai.risk", r.risk);
  put("moorai.decision", r.decision);
  put("moorai.stage", r.stage);
  put("moorai.tenant", r.tenant);
  if (r.seq != null) a["moorai.chain.seq"] = r.seq;
  put("moorai.chain.prev", r.prev);
  put("moorai.chain.chash", r.chash);
  return a;
}

// Pure builder: a governed record (or an array / chain of them) -> an in-toto Statement carrying a
// SLSA-style provenance predicate. Content-free by construction (sanitizeRecord). Deterministic given a
// fixed `version`; `now`, when supplied, stamps the run metadata (omitted otherwise to stay byte-stable).
export function buildAttestation(recordOrRecords, { version = VERSION, now } = {}) {
  const rows = (Array.isArray(recordOrRecords) ? recordOrRecords : [recordOrRecords])
    .filter((r) => r && typeof r === "object")
    .map(sanitizeRecord);
  const subject = rows.map(subjectOf);
  const byproducts = rows.map((r, i) => ({ name: subject[i].name, digest: subject[i].digest, annotations: annotations(r) }));

  const metadata = { invocationId: rows.length ? (rows[rows.length - 1].chash || subject[0].name) : "moorai:empty" };
  if (now != null) { const iso = new Date(now).toISOString(); metadata.startedOn = iso; metadata.finishedOn = iso; }

  return {
    _type: STATEMENT_TYPE,
    subject,
    predicateType: PREDICATE_TYPE,
    predicate: {
      buildDefinition: {
        buildType: BUILD_TYPE,
        externalParameters: {},
        internalParameters: { moorai: { version } },
        resolvedDependencies: []
      },
      runDetails: {
        builder: { id: BUILDER_ID, version: { moorai: version } },
        metadata,
        byproducts
      }
    }
  };
}

// ------------------------------------------------------------------------------------------------
// Evidence adapter. Flatten the compliance pack's content-free evidence into governed records — the
// SAME rows moorai-stix.mjs exports. Each row is read field-by-field (never spread).
// ------------------------------------------------------------------------------------------------
export function recordsFromEvidence(ev = {}) {
  const out = [];
  for (const r of ev.ledger || []) out.push({ tool: r.tool, category: r.category, riskLevel: r.riskLevel, decision: r.decision, stage: r.stage, tenant: r.tenant, contentHash: r.contentHash });
  for (const r of ev.actions || []) out.push({ tool: r.tool, category: r.category, riskLevel: r.riskLevel, decision: r.decision, stage: r.stage, tenant: r.tenant, contentHash: r.contentHash });
  for (const r of ev.intent || []) out.push({ tool: r.tool, category: Array.isArray(r.categories) ? r.categories.join(",") : "human-override", riskLevel: r.riskLevel, decision: "override", stage: r.stage, tenant: r.tenant, contentHash: r.justificationHash });
  for (const r of ev.destinations || []) out.push({ tool: r.tool, category: "destination", riskLevel: r.riskLevel, decision: r.decision, stage: r.kind, tenant: r.tenant, contentHash: r.contentHash });
  return out;
}

export function attestationFromEvidence(ev = {}, opts = {}) {
  return buildAttestation(recordsFromEvidence(ev), opts);
}

// ------------------------------------------------------------------------------------------------
// Standalone CLI — attest THIS device's on-device signals. Best-effort: on any read/build error it
// degrades to an empty (still-valid) Statement rather than throwing.
// ------------------------------------------------------------------------------------------------
async function main() {
  let ev = {};
  try {
    const s = await import("./signals.mjs");
    ev = { ledger: s.readLedger(), actions: s.readActions(), intent: s.readIntent(), destinations: s.readDestinations() };
  } catch { ev = {}; }
  let st;
  try { st = attestationFromEvidence(ev, { now: Date.now() }); } catch { st = buildAttestation([]); }
  process.stdout.write(JSON.stringify(st, null, 2) + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
