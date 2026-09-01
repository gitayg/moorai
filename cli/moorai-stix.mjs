#!/usr/bin/env node
// MoorAI — STIX 2.1 export of the device's content-free findings, for threat-intel interchange.
//
// Turns the SAME content-free rows the compliance/evidence pack already assembles (exposure-ledger,
// action-audit, agent-events, intent, destination observations) into a valid STIX 2.1 bundle so a
// MoorAI device can hand its governance signal to a TIP / SIEM / MISP over the standard interchange
// format — WITHOUT carrying any prompt, response, argument, or file-path content. Every object holds
// only metadata + one-way hashes: category, risk, decision, stage, tool, tenant, contentHash, ts.
//
// SACRED RULE — content-free: an exported object may only contain fields the source rows already
// guarantee to be content-free. The row is never spread; every finding is passed through a strict
// allowlist (sanitizeFinding) so a stray content field on a row can never reach a STIX object.
//
// Ids are deterministic (UUIDv5 over the finding's content-free canonical string) so re-exporting the
// same evidence yields a byte-stable bundle — safe to diff, dedup, and re-ingest.
//
//   node cli/moorai-stix.mjs            # bundle over this device's on-device signals (stdout JSON)
//
// Also consumed by `moorai-compliance --format stix`, which runs it over the same evidence the other
// compliance formats use.

import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

// A fixed MoorAI namespace for UUIDv5 id derivation. Stable across releases so ids stay reproducible.
export const NAMESPACE = "5f8d2c1a-3e4b-4a6c-8b7d-9e0f1a2b3c4d";
export const SPEC_VERSION = "2.1";
const EPOCH = "1970-01-01T00:00:00.000Z";

export function uuidv5(name, namespace = NAMESPACE) {
  const ns = Buffer.from(namespace.replace(/-/g, ""), "hex");
  const h = createHash("sha1").update(ns).update(Buffer.from(String(name), "utf8")).digest().subarray(0, 16);
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const s = h.toString("hex");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`;
}

const str = (v) => (v == null ? "" : String(v));

// Normalize a timestamp (epoch-ms number or ISO string) to a STIX UTC timestamp. Unparseable → EPOCH,
// which keeps the export deterministic without inventing a "now".
function isoTs(ts) {
  if (typeof ts === "number") { const d = new Date(ts); return Number.isNaN(d.getTime()) ? EPOCH : d.toISOString(); }
  const p = Date.parse(ts);
  return Number.isNaN(p) ? EPOCH : new Date(p).toISOString();
}

// One-way hashes are our own tokens (h2:… / h2:nokey / seeded test ids). Bound length and restrict the
// charset before it ever lands in a STIX pattern string — closes quote-injection and any ReDoS surface.
function safeHash(h) { return str(h).slice(0, 128).replace(/[^A-Za-z0-9:._-]/g, ""); }

const NO_KEY = "h2:nokey";

// STRICT allowlist. The row is never spread — only these content-free fields are ever read, so a stray
// prompt/argument/path field on the source row cannot reach the bundle. `source` is a constant tag the
// collector assigns, never a value from the row.
export function sanitizeFinding(f = {}) {
  return {
    source: str(f.source),
    category: str(f.category),
    risk: str(f.risk != null ? f.risk : f.riskLevel),
    decision: str(f.decision),
    stage: str(f.stage),
    tool: str(f.tool),
    tenant: str(f.tenant),
    contentHash: str(f.contentHash),
    ts: f.ts
  };
}

function canonical(f) {
  return [f.source, f.category, f.risk, f.decision, f.stage, f.tool, f.tenant, f.contentHash, isoTs(f.ts)].join("|");
}

function prop(obj, key, val) { if (val) obj[key] = val; }

function findingObject(f) {
  const iso = isoTs(f.ts);
  const o = { type: "x-moorai-finding", spec_version: SPEC_VERSION, id: `x-moorai-finding--${uuidv5(canonical(f))}`, created: iso, modified: iso };
  prop(o, "x_moorai_source", f.source);
  prop(o, "x_moorai_category", f.category);
  prop(o, "x_moorai_risk", f.risk);
  prop(o, "x_moorai_decision", f.decision);
  prop(o, "x_moorai_stage", f.stage);
  prop(o, "x_moorai_tool", f.tool);
  prop(o, "x_moorai_tenant", f.tenant);
  prop(o, "x_moorai_content_hash", f.contentHash);
  return o;
}

function indicatorObject(f) {
  const hash = safeHash(f.contentHash);
  if (!hash || f.contentHash === NO_KEY) return null;
  const iso = isoTs(f.ts);
  return {
    type: "indicator",
    spec_version: SPEC_VERSION,
    id: `indicator--${uuidv5(`indicator|${canonical(f)}`)}`,
    created: iso,
    modified: iso,
    name: `MoorAI ${f.category || f.source || "finding"}`.trim(),
    indicator_types: ["anomalous-activity"],
    pattern: `[x-moorai-finding:x_moorai_content_hash = '${hash}']`,
    pattern_type: "stix",
    valid_from: iso,
    x_moorai_content_hash: hash
  };
}

// Pure exporter: content-free findings -> STIX 2.1 bundle. `opts.now` sets the provenance note's
// timestamps (defaults to EPOCH so a bundle is deterministic when no clock is supplied).
export function buildStixBundle(findings = [], opts = {}) {
  const clean = (Array.isArray(findings) ? findings : []).map(sanitizeFinding);
  const objects = [];
  for (const f of clean) {
    objects.push(findingObject(f));
    const ind = indicatorObject(f);
    if (ind) objects.push(ind);
  }

  if (clean.length) {
    const bundleName = uuidv5(clean.map(canonical).join("\n"));
    const noteTs = opts.now ? isoTs(opts.now) : EPOCH;
    objects.push({
      type: "note",
      spec_version: SPEC_VERSION,
      id: `note--${uuidv5(`note|${bundleName}`)}`,
      created: noteTs,
      modified: noteTs,
      abstract: "MoorAI content-free finding export",
      content: "Content-free STIX 2.1 export. Objects carry only metadata and one-way hashes — never prompt, response, argument, or path content.",
      object_refs: objects.filter((o) => o.type === "x-moorai-finding").map((o) => o.id)
    });
  }

  return { type: "bundle", id: `bundle--${uuidv5(objects.map((o) => o.id).join("\n"))}`, objects };
}

// ------------------------------------------------------------------------------------------------
// Evidence adapters. Flatten the compliance pack's content-free evidence into strict findings. Each
// row is read field-by-field (never spread); agent-event `sig` is split into its tool + one-way hash
// halves with a bounded regex.
// ------------------------------------------------------------------------------------------------
const SIG = /^([^|]{0,160})\|(.{0,200})$/;

export function collectFindings(ev = {}) {
  const out = [];
  for (const r of ev.ledger || []) out.push({ source: "exposure-ledger", category: r.category, risk: r.riskLevel, decision: r.decision, stage: r.stage, tool: r.tool, tenant: r.tenant, contentHash: r.contentHash, ts: r.ts });
  for (const r of ev.actions || []) out.push({ source: "action-audit", category: r.category, risk: r.riskLevel, decision: r.decision, stage: r.stage, tool: r.tool, tenant: r.tenant, contentHash: r.contentHash, ts: r.ts });
  for (const r of ev.agentEvents || []) {
    const m = SIG.exec(str(r.sig));
    out.push({ source: "agent-events", category: "agent-behavior", risk: r.risk, decision: r.ok === false ? "deny" : "allow", stage: "", tool: m ? m[1] : "", tenant: r.tenant, contentHash: m ? m[2] : "", ts: r.ts });
  }
  for (const r of ev.intent || []) out.push({ source: "intent-log", category: "human-override", risk: r.riskLevel, decision: "override", stage: r.stage, tool: r.tool, tenant: r.tenant, contentHash: r.justificationHash, ts: r.ts });
  for (const r of ev.destinations || []) out.push({ source: "destinations", category: "destination", risk: r.riskLevel, decision: r.decision, stage: r.kind, tool: r.tool, tenant: r.tenant, contentHash: r.contentHash, ts: r.ts });
  return out;
}

export function stixFromEvidence(ev = {}, opts = {}) {
  return buildStixBundle(collectFindings(ev), opts);
}

// ------------------------------------------------------------------------------------------------
// Standalone CLI — bundle over THIS device's on-device signals. Best-effort: on any read/build error
// it degrades to an empty (still-valid) bundle rather than throwing.
// ------------------------------------------------------------------------------------------------
async function main() {
  let ev = {};
  try {
    const s = await import("./signals.mjs");
    ev = { ledger: s.readLedger(), actions: s.readActions(), agentEvents: s.readAgentEvents(), intent: s.readIntent(), destinations: s.readDestinations() };
  } catch { ev = {}; }
  let bundle;
  try { bundle = stixFromEvidence(ev, { now: Date.now() }); } catch { bundle = { type: "bundle", id: `bundle--${uuidv5("empty")}`, objects: [] }; }
  process.stdout.write(JSON.stringify(bundle, null, 2) + "\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
