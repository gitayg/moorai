// Per-file runner:  node --test test/crosswalks.test.mjs
//
// Three external frameworks are crosswalked to the rule base in data/crosswalks/, each in its own file:
// SAF-MCP (OpenSSF SIG), "Careful adoption of agentic AI services" (ASD's ACSC with CISA, NSA, the
// Canadian Centre for Cyber Security, NCSC-NZ and NCSC-UK) and the CSA Agentic Trust Framework. This file
// scores:
//
//   1. THE LISTS     — each crosswalk carries a copy of the framework's official list, pinned here, so an
//                      invented id or an edited title fails instead of reaching a report.
//   2. EVERY ID ONCE — every listed id has exactly one entry, and no entry names an id off the list.
//   3. THE CREDITS   — a status from the four, a non-empty limit on every partial, a reason on every gap,
//                      evidence on every credit, and only threat ids data/threats.json has.
//   4. THE EVIDENCE  — every component a credit cites exists, and its file contains the symbol named.
//   5. THE REJECTS   — a credit the review considered and rejected stays uncredited.
//   6. THE REPORT    — scripts/crosswalk-report.mjs prints the numbers the data holds, and
//                      docs/CROSSWALKS.md carries the same table.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadCrosswalks, loadComponents, report, summaryMarkdown, STATUSES, CROSSWALK_FILES } from "../scripts/crosswalk-report.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const THREAT_IDS = new Set(threats.map((t) => t.id));
const CWS = loadCrosswalks();
const COMPONENTS = loadComponents();
const byKey = Object.fromEntries(CWS.map((c) => [c.framework.key, c]));

// ---------------------------------------------------------------------------------------------
// 1. The official lists
// ---------------------------------------------------------------------------------------------
// Source: github.com/secure-agentic-framework/saf-mcp @ d3d4029 (2026-09-02), research/framework-model.yml,
// every technique with lifecycle_status: active, in file order. The README's generated catalog lists the
// same 78 ids ("Active techniques: 78", "Registered technique IDs: 86").
const SAF_ACTIVE = [
  ["SAF-T1001", "Tool Poisoning Attack"],
  ["SAF-T1002", "Supply Chain Compromise"],
  ["SAF-T1003", "Malicious MCP-Server Distribution"],
  ["SAF-T1005", "Exposed Endpoint Exploit"],
  ["SAF-T1004", "Server Impersonation / Name-Collision"],
  ["SAF-T1006", "User-Social-Engineering Install"],
  ["SAF-T1007", "OAuth Authorization Phishing"],
  ["SAF-T1207", "Hijack Update Mechanism"],
  ["SAF-T1008", "Cross-Server Tool Shadowing"],
  ["SAF-T1101", "Command Injection"],
  ["SAF-T1009", "Authorization Server Mix-up"],
  ["SAF-T1102", "Prompt Injection (Multiple Vectors)"],
  ["SAF-T1103", "Fake Tool Invocation (Function Spoofing)"],
  ["SAF-T1105", "Path Traversal via File Tool"],
  ["SAF-T1106", "Autonomous Loop Exploit"],
  ["SAF-T1111", "AI Agent CLI Weaponization"],
  ["SAF-T1110", "Multimodal Prompt Injection via Images/Audio"],
  ["SAF-T1201", "Post-Approval Tool Mutation"],
  ["SAF-T1202", "OAuth Token Persistence"],
  ["SAF-T1203", "Backdoored Server Binary"],
  ["SAF-T1204", "Context Memory Implant"],
  ["SAF-T1206", "Credential Implant in Config"],
  ["SAF-T1302", "Agentic Confused Deputy"],
  ["SAF-T1304", "Credential Relay Chain"],
  ["SAF-T1303", "Sandbox Escape via Server Exec"],
  ["SAF-T1305", "Host OS Priv-Esc (RCE)"],
  ["SAF-T1307", "Confused Deputy Attack"],
  ["SAF-T1308", "Token Scope Substitution"],
  ["SAF-T1406", "Metadata Manipulation"],
  ["SAF-T1401", "Line Jumping"],
  ["SAF-T1403", "Consent-Fatigue Exploit"],
  ["SAF-T1402", "Instruction Steganography"],
  ["SAF-T1404", "Response Tampering"],
  ["SAF-T1405", "Tool Obfuscation/Renaming"],
  ["SAF-T1408", "OAuth Protocol Downgrade"],
  ["SAF-T1407", "Server Proxy Masquerade"],
  ["SAF-T1503", "Env-Var Scraping"],
  ["SAF-T1501", "Full-Schema Poisoning (FSP)"],
  ["SAF-T1502", "File-Based Credential Harvest"],
  ["SAF-T1504", "Token Theft via API Response"],
  ["SAF-T1505", "In-Memory Secret Extraction"],
  ["SAF-T1507", "Authorization Code Interception"],
  ["SAF-T1506", "Infrastructure Token Theft"],
  ["SAF-T1601", "MCP Server Enumeration"],
  ["SAF-T1602", "Tool Enumeration"],
  ["SAF-T1603", "System Prompt Disclosure"],
  ["SAF-T1604", "Server Version Enumeration"],
  ["SAF-T1605", "Capability Mapping"],
  ["SAF-T1606", "Directory Listing via File Tool"],
  ["SAF-T1701", "Cross-Tool Contamination"],
  ["SAF-T1703", "Tool-Chaining Pivot"],
  ["SAF-T1704", "Compromised-Server Pivot"],
  ["SAF-T1706", "OAuth Token Pivot Replay"],
  ["SAF-T1112", "Sampling Request Abuse"],
  ["SAF-T1705", "Cross-Agent Instruction Injection"],
  ["SAF-T1801", "Automated Data Harvesting"],
  ["SAF-T1803", "Database Dump"],
  ["SAF-T1707", "CSRF Token Relay"],
  ["SAF-T1804", "API Data Harvest"],
  ["SAF-T1910", "Covert Channel Exfiltration"],
  ["SAF-T1911", "Parameter Exfiltration"],
  ["SAF-T1904", "Chat-Based Backchannel"],
  ["SAF-T1915", "Cross-Chain Laundering via Bridges/DEXs"],
  ["SAF-T2101", "Data Destruction"],
  ["SAF-T1903", "Malicious Server Control Channel"],
  ["SAF-T2102", "Service Disruption"],
  ["SAF-T2104", "Fraudulent Transactions"],
  ["SAF-T2105", "Disinformation Output"],
  ["SAF-T2103", "Code Sabotage"],
  ["SAF-T2106", "Context Memory Poisoning via Vector Store Contamination"],
  ["SAF-T3001", "RAG Backdoor Attack"],
  ["SAF-T2107", "AI Model Poisoning via MCP Tool Training Data Contamination"],
  ["SAF-T1901", "Outbound Webhook C2"],
  ["SAF-T1805", "Context Snapshot Capture"],
  ["SAF-T1802", "File Collection"],
  ["SAF-T1902", "Response-Borne Covert Channel"],
  ["SAF-T1913", "HTTP POST Exfil"],
  ["SAF-T1914", "Tool-to-Tool Exfil"]
];
const SAF_DEPRECATED = {
  "SAF-T1104": ["SAF-T1302"], "SAF-T1109": ["SAF-T1005", "SAF-T1101"], "SAF-T1205": ["SAF-T1201"], "SAF-T1301": ["SAF-T1008"],
  "SAF-T1306": ["SAF-T1009"], "SAF-T1309": ["SAF-T1102", "SAF-T1302"], "SAF-T1702": ["SAF-T1204"], "SAF-T1912": ["SAF-T1902"]
};

// Source: CONFORMANCE.md, github.com/massivescale-ai/agentic-trust-framework @ c494c6b (tag v0.9.1).
const ATF = [
  ["I-1", "Unique Identifier"], ["I-2", "Credential Binding"], ["I-3", "Ownership Chain"], ["I-4", "Purpose Declaration"], ["I-5", "Capability Manifest"],
  ["B-1", "Structured Logging"], ["B-2", "Action Attribution"], ["B-3", "Behavioral Baseline"], ["B-4", "Anomaly Detection"], ["B-5", "Explainability"],
  ["D-1", "Schema Validation"], ["D-2", "Injection Prevention"], ["D-3", "PII/PHI Protection"], ["D-4", "Output Validation"], ["D-5", "Data Lineage"],
  ["S-1", "Resource Allowlist"], ["S-2", "Action Boundaries"], ["S-3", "Rate Limiting"], ["S-4", "Transaction Limits"], ["S-5", "Blast Radius Containment"],
  ["R-1", "Circuit Breaker"], ["R-2", "Kill Switch"], ["R-3", "Session Revocation"], ["R-4", "State Rollback"], ["R-5", "Graceful Degradation"]
];

// Source: the PDF the guidance was published as (NCSC-NZ copy, SHA-256 d41bc59c…, 29 pages). It numbers
// nothing, so the ids are locators: the section counts below and a digest of every "id<TAB>text" line.
const CAAIS_SECTIONS = {
  "design/controlled-context": 2, "design/oversight-mechanisms": 3, "design/identity-management": 6, "design/defence-in-depth": 3,
  "develop/comprehensive-testing": 4, "develop/appropriate-evaluation": 5, "develop/input-management": 3, "develop/red-teaming": 4,
  "develop/resilience": 3, "develop/accountability": 4, "develop/third-party-components": 11,
  "deploy/threat-modelling": 5, "deploy/governance": 3, "deploy/progressive-deployment": 3, "deploy/secure-by-default": 3,
  "deploy/guardrails-and-constraints": 6, "deploy/isolation": 3,
  "operate/monitoring-and-auditing": 14, "operate/validate-outputs": 3, "operate/human-in-the-loop": 6,
  "operate/performance-monitoring": 4, "operate/privileges-and-authentication": 10,
  "future/threat-intelligence": 6, "future/agent-specific-evaluations": 4, "future/system-theoretic-analysis": 4,
  "appendix-a/design": 10, "appendix-a/development": 8
};
const CAAIS_DIGEST = "db330b3ef2a2e4c3a0064c36f974b088266339ebb39952a37365596c5c00e1c1";

test("CROSSWALK: the three files load, one per framework", () => {
  assert.deepEqual(CWS.map((c) => c.framework.key), ["saf-mcp", "careful-adoption-of-agentic-ai-services", "agentic-trust-framework"]);
  assert.equal(CROSSWALK_FILES.length, 3);
});

test("CROSSWALK: SAF-MCP's list is the 78 active techniques at the pinned commit", () => {
  const cw = byKey["saf-mcp"];
  assert.deepEqual(cw.catalog.map((c) => [c.id, c.title]), SAF_ACTIVE);
  assert.deepEqual(Object.fromEntries(cw.deprecated.map((d) => [d.id, d.replacedBy])), SAF_DEPRECATED);
  assert.equal(cw.framework.commit, "d3d40297c478d2680d315399b6aaf317e5aa15b8");
  assert.equal(cw.framework.source, "https://github.com/secure-agentic-framework/saf-mcp");
});

test("CROSSWALK: the agentic AI guidance list is the pinned 140 recommendations", () => {
  const cw = byKey["careful-adoption-of-agentic-ai-services"];
  const counts = {};
  for (const c of cw.catalog) {
    const sec = c.id.split("/").slice(0, 2).join("/");
    counts[sec] = (counts[sec] || 0) + 1;
    assert.match(c.id, new RegExp(`^${sec}/${counts[sec]}$`), `${c.id} is out of order`);
  }
  assert.deepEqual(counts, CAAIS_SECTIONS);
  const digest = createHash("sha256").update(cw.catalog.map((c) => `${c.id}\t${c.text}\n`).join("")).digest("hex");
  assert.equal(digest, CAAIS_DIGEST, "the recommendation text changed: re-read the PDF before re-pinning");
  assert.equal(cw.framework.source, "https://www.cyber.gov.au/publication/careful-adoption-of-agentic-ai-services");
  assert.equal(cw.framework.textSha256, "d41bc59cde8ddcc00bf69d09a3bef9f3c577225ba99f9d8aa61c2b76bc27b74d");
});

test("CROSSWALK: the Agentic Trust Framework list is the 25 core requirements", () => {
  const cw = byKey["agentic-trust-framework"];
  assert.deepEqual(cw.catalog.map((c) => [c.id, c.title]), ATF);
  assert.equal(cw.framework.commit, "c494c6b17100d1fa46cac8ae54386d9a04fa7afe");
});

// ---------------------------------------------------------------------------------------------
// 2. Every id once
// ---------------------------------------------------------------------------------------------
for (const cw of CWS) {
  test(`CROSSWALK: ${cw.framework.shortName} maps every listed id exactly once, and nothing else`, () => {
    const listed = cw.catalog.map((c) => c.id);
    assert.equal(new Set(listed).size, listed.length, "the list repeats an id");
    const seen = cw.entries.map((e) => e.id);
    const off = seen.filter((id) => !listed.includes(id));
    assert.deepEqual(off, [], `entries for ids not on the official list: ${off.join(", ")}`);
    const dup = seen.filter((id, i) => seen.indexOf(id) !== i);
    assert.deepEqual(dup, [], `ids mapped twice: ${dup.join(", ")}`);
    const missing = listed.filter((id) => !seen.includes(id));
    assert.deepEqual(missing, [], `listed ids with no entry: ${missing.join(", ")}`);
  });
}

// ---------------------------------------------------------------------------------------------
// 3. The credits
// ---------------------------------------------------------------------------------------------
for (const cw of CWS) {
  test(`CROSSWALK: ${cw.framework.shortName} — every partial states its limit and every gap its reason`, () => {
    const problems = [];
    for (const e of cw.entries) {
      if (!STATUSES.includes(e.status)) { problems.push(`${e.id}: unknown status ${e.status}`); continue; }
      const credit = e.status === "covered" || e.status === "partial";
      if (e.status === "partial" && !(typeof e.limit === "string" && e.limit.trim().length > 3)) problems.push(`${e.id}: partial with no limit`);
      if (e.status !== "partial" && e.limit !== undefined) problems.push(`${e.id}: a limit on a ${e.status} entry`);
      if (!credit && !(typeof e.reason === "string" && e.reason.trim().length > 3)) problems.push(`${e.id}: ${e.status} with no reason`);
      if (e.status === "not-applicable" && !["organisational", "agent-build"].includes(e.naKind)) problems.push(`${e.id}: not-applicable without naKind`);
      if (credit && !(Array.isArray(e.evidence) && e.evidence.length)) problems.push(`${e.id}: ${e.status} with no evidence`);
      if (!credit && (e.threats.length || e.evidence.length)) problems.push(`${e.id}: ${e.status} still carries threats or evidence`);
    }
    assert.deepEqual(problems, [], problems.join("\n"));
  });

  test(`CROSSWALK: ${cw.framework.shortName} — every threat id is a rule in data/threats.json`, () => {
    const problems = [];
    for (const e of cw.entries) {
      assert.ok(Array.isArray(e.threats), `${e.id}: threats must be an array`);
      if (new Set(e.threats).size !== e.threats.length) problems.push(`${e.id}: repeats a threat id`);
      for (const t of e.threats) if (!THREAT_IDS.has(t)) problems.push(`${e.id}: #${t} is not in data/threats.json`);
    }
    for (const r of cw.rejected || []) if (r.credit.threat !== undefined && !THREAT_IDS.has(r.credit.threat)) problems.push(`rejected ${r.id}: #${r.credit.threat} is not in data/threats.json`);
    assert.deepEqual(problems, [], problems.join("\n"));
  });
}

test("CROSSWALK: SAF-MCP marks nothing not applicable (each technique is a runtime attack)", () => {
  assert.deepEqual(byKey["saf-mcp"].entries.filter((e) => e.status === "not-applicable").map((e) => e.id), []);
});

// ---------------------------------------------------------------------------------------------
// 4. The evidence
// ---------------------------------------------------------------------------------------------
test("CROSSWALK: every cited component exists and its file contains the symbol named", () => {
  const cited = new Set(CWS.flatMap((cw) => [...cw.entries.flatMap((e) => e.evidence), ...(cw.rejected || []).map((r) => r.credit.component).filter(Boolean)]));
  const problems = [];
  for (const k of cited) {
    const c = COMPONENTS[k];
    if (!c) { problems.push(`${k}: not in data/crosswalks/components.json`); continue; }
    const p = join(ROOT, c.path);
    if (!existsSync(p)) { problems.push(`${k}: ${c.path} does not exist`); continue; }
    if (!readFileSync(p, "utf8").includes(c.symbol)) problems.push(`${k}: ${c.path} no longer contains ${JSON.stringify(c.symbol)}`);
  }
  assert.deepEqual(problems, [], problems.join("\n"));
});

// ---------------------------------------------------------------------------------------------
// 5. The rejects
// ---------------------------------------------------------------------------------------------
for (const cw of CWS) {
  test(`CROSSWALK: ${cw.framework.shortName} — credits the review rejected stay uncredited`, () => {
    const entries = new Map(cw.entries.map((e) => [e.id, e]));
    const problems = [];
    for (const r of cw.rejected || []) {
      const e = entries.get(r.id);
      if (!e) { problems.push(`rejected ${r.id}: not on the list`); continue; }
      if (!(typeof r.reason === "string" && r.reason.trim().length > 10)) problems.push(`rejected ${r.id}: no reason`);
      if (r.credit.threat === undefined && r.credit.component === undefined) problems.push(`rejected ${r.id}: names no credit`);
      if (r.credit.threat !== undefined && e.threats.includes(r.credit.threat)) problems.push(`${r.id} credits #${r.credit.threat}, which the review rejected`);
      if (r.credit.component !== undefined && e.evidence.includes(r.credit.component)) problems.push(`${r.id} cites ${r.credit.component}, which the review rejected`);
    }
    assert.deepEqual(problems, [], problems.join("\n"));
  });
}

// ---------------------------------------------------------------------------------------------
// 6. The report
// ---------------------------------------------------------------------------------------------
function recount(cw) {
  const n = (s) => cw.entries.filter((e) => e.status === s).length;
  return { covered: n("covered"), partial: n("partial"), "not-covered": n("not-covered"), "not-applicable": n("not-applicable"), total: cw.catalog.length };
}

test("CROSSWALK: the report's numbers are the data's", () => {
  const rows = report(CWS);
  for (const [i, cw] of CWS.entries()) {
    const want = recount(cw);
    const got = rows[i];
    for (const k of Object.keys(want)) assert.equal(got[k], want[k], `${cw.framework.shortName} ${k}: report says ${got[k]}, data says ${want[k]}`);
    assert.equal(got.covered + got.partial + got["not-covered"] + got["not-applicable"], got.total, `${cw.framework.shortName}: the statuses do not add up to the list`);
  }
});

test("CROSSWALK: the CLI prints the same numbers (--json)", () => {
  const out = JSON.parse(execFileSync(process.execPath, [join(ROOT, "scripts/crosswalk-report.mjs"), "--json"], { encoding: "utf8" }));
  assert.deepEqual(out.map((r) => [r.key, r.covered, r.partial, r["not-covered"], r["not-applicable"]]),
    CWS.map((cw) => { const c = recount(cw); return [cw.framework.key, c.covered, c.partial, c["not-covered"], c["not-applicable"]]; }));
});

test("CROSSWALK: docs/CROSSWALKS.md carries the current summary table", () => {
  const doc = readFileSync(join(ROOT, "docs/CROSSWALKS.md"), "utf8");
  assert.ok(doc.includes(summaryMarkdown(report(CWS))), "docs/CROSSWALKS.md is stale: regenerate it with node scripts/crosswalk-report.mjs --markdown");
});
