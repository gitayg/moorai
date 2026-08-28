#!/usr/bin/env node
// MoorAI — compliance-evidence packs. Turns the device's EXISTING content-free signals (the exposure
// ledger, action-audit, intent log, agent-events, destination map) and its AIBOM inventory into an
// auditable, control-by-control crosswalk against three AI-governance frameworks:
//
//   EU AI Act (Regulation (EU) 2024/1689)   NIST AI RMF 1.0        ISO/IEC 42001:2023
//
// For each control it answers "show me the evidence" with a content-free metric MoorAI actually
// produces — a count, a retention window, an inventory size — and marks the control covered / partial /
// not-covered HONESTLY. A control is only mapped to a signal that really exists on the device; where
// MoorAI produces no evidence (e.g. training-data governance) the control is listed and marked
// not-covered rather than fabricated. Read-only, no network, fail-open.
//
//   node cli/moorai-compliance.mjs --framework eu-ai-act
//   node cli/moorai-compliance.mjs --framework nist-ai-rmf --json
//   node cli/moorai-compliance.mjs --framework iso-42001
//   node cli/moorai-compliance.mjs --framework all --json
//
// SACRED RULE — content-free: evidence is metadata, counts, retention windows, control-coverage
// booleans and one-way-hash-derived class labels only. Never a prompt, file content, output, or
// argument. This CLI reads only the fields those constraints already guarantee (category, riskLevel,
// stage, tool, ts, decision, counts) and emits counts + framework text.

import { execFileSync } from "node:child_process";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readLedger, readIntent, readActions, readDestinations, readAgentEvents } from "./signals.mjs";

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
const RETENTION_DAYS = Number(process.env.MOORAI_RETENTION_DAYS) || 90; // mirrors signals.mjs default

// ---------------------------------------------------------------------------------------------------
// Evidence sources. Each key names a REAL on-device signal (a ~/.moorai/*.jsonl log or the AIBOM
// inventory) and returns a content-free { metric, unit, detail }. metric drives coverage; detail is the
// human sentence. Nothing here reads a content field — those fields do not exist in these logs.
// ---------------------------------------------------------------------------------------------------
const EVIDENCE = {
  // EU AI Act Art. 4 — every finding surfaced to the developer (blocked, or shown "ask" with the
  // why + what-to-do) is a just-in-time AI-literacy touchpoint. The action-audit log holds those.
  literacy(ev) {
    const n = ev.actions.filter((a) => ["High", "Critical", "Blocked"].includes(a.riskLevel)).length;
    return { metric: n, unit: "touchpoints", detail: `${n} finding(s) surfaced to the developer as just-in-time AI-literacy touchpoints` };
  },
  // Automatic event logging over the system lifetime — the searchable action-audit timeline.
  records(ev) {
    const n = ev.actions.length;
    const span = spanDays(ev.actions);
    return { metric: n, unit: "records", detail: `${n} content-free action record(s) retained; retention window ${RETENTION_DAYS} day(s)` + (span != null ? `; observed span ${span} day(s)` : "") };
  },
  // Human oversight — a human overriding a finding and proceeding leaves one content-free intent line.
  oversight(ev) {
    const n = ev.intent.length;
    return { metric: n, unit: "overrides", detail: `${n} human-override intent record(s) (justification hashes only, never the text)` };
  },
  // Cybersecurity / incident detection — secret-class exposure events caught and recorded.
  exposure(ev) {
    const n = ev.ledger.length;
    const classes = new Set(ev.ledger.map((r) => r.category).filter(Boolean)).size;
    return { metric: n, unit: "exposures", detail: `${n} secret/credential-class exposure event(s) detected across ${classes} class(es)` };
  },
  // AI inventory — the AIBOM (models, agents, MCP servers, editor AI extensions).
  inventory(ev) {
    const s = ev.aibom?.summary || {};
    const n = ev.aibom?.components?.length || 0;
    return { metric: n, unit: "components", detail: `${n} AI component(s) inventoried: ${s.models || 0} model(s), ${s.agents || 0} agent CLI(s), ${s.mcpServers || 0} MCP server(s), ${s.editorAiExtensions || 0} AI extension(s)` };
  },
  // Third-party AI suppliers — the MCP servers in the AIBOM, with their capability risk.
  suppliers(ev) {
    const s = ev.aibom?.summary || {};
    const n = s.mcpServers || 0;
    return { metric: n, unit: "suppliers", detail: `${n} MCP server(s) inventoried as AI suppliers (${s.mcpHighRisk || 0} high-risk by capability scope)` };
  },
  // Operational / behavioral monitoring — the rolling autonomous-behavior event window.
  behavior(ev) {
    const n = ev.agentEvents.length;
    return { metric: n, unit: "events", detail: `${n} content-free agent-behavior event(s) monitored (tool, risk, trifecta legs — never any text)` };
  },
  // Deployment context / data-egress — the per-agent destination map + the hook's own verdicts.
  destinations(ev) {
    const names = new Set(ev.destinations.map((d) => d.name).filter(Boolean)).size;
    const denied = ev.destinations.filter((d) => d.decision === "deny").length;
    return { metric: ev.destinations.length, unit: "destinations", detail: `${ev.destinations.length} destination observation(s) across ${names} distinct host(s)/MCP server(s); ${denied} denied by policy` };
  },
  // Genuinely not observable on-device — MoorAI sees runtime signals, not the model's training pipeline.
  none() { return { metric: 0, unit: "", detail: "MoorAI observes runtime agent signals only — it produces no evidence for this control" }; }
};

// ---------------------------------------------------------------------------------------------------
// The crosswalk. Auditable and extensible: each control names its framework text and the ONE evidence
// signal that backs it. `support`:
//   full    — the signal directly attests this control
//   partial — MoorAI contributes evidence, but the control is broader than a device can attest
//   none    — MoorAI produces no evidence for this control (listed honestly, always not-covered)
// ---------------------------------------------------------------------------------------------------
const FRAMEWORKS = {
  "eu-ai-act": {
    name: "EU AI Act (Regulation (EU) 2024/1689)",
    controls: [
      { id: "Art. 4", title: "AI literacy", requirement: "Ensure a sufficient level of AI literacy among staff operating AI systems", signal: "literacy", support: "full" },
      { id: "Art. 12", title: "Record-keeping", requirement: "Automatic recording of events (logs) over the system's lifetime", signal: "records", support: "full" },
      { id: "Art. 14", title: "Human oversight", requirement: "Enable natural persons to oversee and intervene in AI operation", signal: "oversight", support: "full" },
      { id: "Art. 15", title: "Accuracy, robustness & cybersecurity", requirement: "Resilience against attempts to exploit vulnerabilities (incl. data leakage)", signal: "exposure", support: "partial" },
      { id: "Art. 26", title: "Deployer obligations", requirement: "Monitor operation and maintain an inventory of deployed AI systems", signal: "inventory", support: "partial" },
      { id: "Art. 72", title: "Post-market monitoring", requirement: "Collect and review data on AI system performance in operation", signal: "behavior", support: "partial" },
      { id: "Art. 10", title: "Data & data governance", requirement: "Quality and governance of training, validation and testing datasets", signal: "none", support: "none" }
    ]
  },
  "nist-ai-rmf": {
    name: "NIST AI RMF 1.0",
    controls: [
      { id: "GOVERN 1.6", title: "AI system inventory", requirement: "An inventory of AI systems is maintained and resourced", signal: "inventory", support: "partial" },
      { id: "MAP 4.1", title: "Deployment context & third parties", requirement: "Map third-party AI resources and the deployment/attack surface", signal: "suppliers", support: "partial" },
      { id: "MEASURE 2.7", title: "Security & resilience", requirement: "AI security and resilience are evaluated and documented", signal: "exposure", support: "full" },
      { id: "MEASURE 2.6", title: "Behavioral monitoring", requirement: "AI system is monitored for performance and unexpected behavior", signal: "behavior", support: "full" },
      { id: "MANAGE 4.1", title: "Risk treatment & oversight", requirement: "Post-deployment risk response, including human intervention, is applied", signal: "oversight", support: "full" },
      { id: "MANAGE 2.4", title: "Response record-keeping", requirement: "Mechanisms to document and track AI risks and responses", signal: "records", support: "partial" },
      { id: "MAP 1.1", title: "Impact on individuals", requirement: "Likely impacts on affected individuals and communities are assessed", signal: "none", support: "none" }
    ]
  },
  "iso-42001": {
    name: "ISO/IEC 42001:2023",
    controls: [
      { id: "A.6.2.2", title: "AI system requirements & inventory", requirement: "Document AI system resources and maintain their inventory", signal: "inventory", support: "partial" },
      { id: "A.6.2.8", title: "AI system event logging", requirement: "Record events during AI system operation", signal: "records", support: "full" },
      { id: "A.6.2.6", title: "AI system operation & monitoring", requirement: "Monitor AI systems while in operation", signal: "behavior", support: "full" },
      { id: "A.10.2", title: "Supplier / third-party management", requirement: "Manage AI-related third parties and their components", signal: "suppliers", support: "partial" },
      { id: "A.7.4", title: "Data provenance & egress", requirement: "Track where AI-processed data flows during operation", signal: "destinations", support: "partial" },
      { id: "A.9.2", title: "Incident detection", requirement: "Detect and record AI-related security incidents", signal: "exposure", support: "full" },
      { id: "A.5.4", title: "Human oversight", requirement: "Provide human oversight of the AI system", signal: "oversight", support: "full" },
      { id: "A.7.2", title: "Data quality for AI", requirement: "Ensure the quality of data used to build the AI system", signal: "none", support: "none" }
    ]
  }
};

const tsMs = (e) => { const t = e && e.ts; if (typeof t === "number") return t; const p = Date.parse(t); return Number.isNaN(p) ? null : p; };
function spanDays(rows) {
  const ms = rows.map(tsMs).filter((x) => x != null);
  if (ms.length < 2) return null;
  return Math.round((Math.max(...ms) - Math.min(...ms)) / 86400000);
}

// Consume the AIBOM CLI rather than duplicating its inventory logic. Read-only, fail-open: if it can't
// run, the inventory-backed controls simply read as not-covered instead of throwing.
function loadAibom() {
  try {
    const out = execFileSync(process.execPath, [join(SELF_DIR, "moorai-aibom.mjs")], { encoding: "utf8", env: process.env, timeout: 15000, maxBuffer: 16 * 1024 * 1024 });
    return JSON.parse(out);
  } catch { return null; }
}

function collectEvidence() {
  return {
    ledger: readLedger(),
    intent: readIntent(),
    actions: readActions(),
    destinations: readDestinations(),
    agentEvents: readAgentEvents(),
    aibom: loadAibom()
  };
}

function coverageFor(control, ev) {
  const e = EVIDENCE[control.signal](ev);
  const status = control.support === "none" ? "not-covered"
    : e.metric > 0 ? (control.support === "full" ? "covered" : "partial")
    : "not-covered";
  return { id: control.id, title: control.title, requirement: control.requirement, signal: control.signal, support: control.support, status, metric: e.metric, unit: e.unit, evidence: e.detail };
}

function buildPack(key, ev) {
  const fw = FRAMEWORKS[key];
  const controls = fw.controls.map((c) => coverageFor(c, ev));
  const summary = { total: controls.length, covered: 0, partial: 0, notCovered: 0 };
  for (const c of controls) summary[c.status === "covered" ? "covered" : c.status === "partial" ? "partial" : "notCovered"]++;
  return { framework: key, name: fw.name, summary, controls };
}

function build(frameworkArg) {
  const keys = frameworkArg === "all" ? Object.keys(FRAMEWORKS) : [frameworkArg];
  const ev = collectEvidence();
  return {
    tool: "MoorAI-Compliance", specVersion: "1.0", scope: "device", device: hostname(), generatedAt: new Date().toISOString(),
    frameworks: keys.map((k) => buildPack(k, ev))
  };
}

// ---- renderers ----
const GLYPH = { covered: "✓", partial: "~", "not-covered": "✗" };
const LABEL = { covered: "COVERED    ", partial: "PARTIAL    ", "not-covered": "NOT COVERED" };
function toHuman(d) {
  let out = `MoorAI — compliance-evidence pack   ·   device ${d.device}   ·   ${d.generatedAt}\n`
    + `Content-free evidence only: counts, retention windows, inventory sizes. No prompts, contents, or arguments.\n`;
  for (const fw of d.frameworks) {
    const s = fw.summary;
    out += `\n${"═".repeat(92)}\n${fw.name}\n`
      + `  ${s.covered}/${s.total} covered   ·   ${s.partial} partial   ·   ${s.notCovered} not covered\n${"═".repeat(92)}\n`;
    for (const c of fw.controls) {
      out += `\n  [${GLYPH[c.status]} ${LABEL[c.status]}]  ${c.id} — ${c.title}   (${c.support}-support)\n`
        + `      requirement: ${c.requirement}\n`
        + `      evidence:    ${c.evidence}\n`;
    }
  }
  return out + `\n${"─".repeat(92)}\nGenerated on-device by MoorAI. A defensible, content-free crosswalk to support GRC — not a certification.\n`;
}

const HELP = `MoorAI compliance — content-free evidence packs mapped to AI-governance frameworks.

Usage:
  moorai-compliance --framework <eu-ai-act|nist-ai-rmf|iso-42001|all> [--json]
  moorai-compliance --help

Maps the device's EXISTING content-free signals to framework controls and shows, per control,
the concrete metric MoorAI can attest — marking each covered / partial / not-covered honestly.

Evidence sources (all on-device; nothing leaves the machine):
  ~/.moorai/action-audit.jsonl        record-keeping + literacy touchpoints (EU Art. 12/4, ISO A.6.2.8)
  ~/.moorai/intent-log.jsonl          human-override intents (EU Art. 14, NIST MANAGE 4.1, ISO A.5.4)
  ~/.moorai/exposure-ledger.jsonl     secret-class exposure detection (EU Art. 15, NIST MEASURE 2.7)
  ~/.moorai/agent-events.jsonl        behavioral monitoring (EU Art. 72, NIST MEASURE 2.6, ISO A.6.2.6)
  ~/.moorai/destinations.jsonl        data-egress / deployment context (NIST MAP 4.1, ISO A.7.4)
  moorai-aibom (consumed)             AI inventory + MCP suppliers (EU Art. 26, NIST GOVERN 1.6, ISO A.6.2.2)

Controls MoorAI cannot attest (training-data governance, impact assessments) are listed and
marked NOT COVERED rather than fabricated. Read-only, no network, fail-open.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const framework = argv.includes("--framework") ? argv[argv.indexOf("--framework") + 1] : null;
if (!framework || !(framework === "all" || FRAMEWORKS[framework])) {
  process.stderr.write(`Choose a framework: --framework <eu-ai-act|nist-ai-rmf|iso-42001|all>\n\n${HELP}`);
  process.exit(2);
}

const pack = build(framework);
process.stdout.write(argv.includes("--json") ? JSON.stringify(pack, null, 2) + "\n" : toHuman(pack));
