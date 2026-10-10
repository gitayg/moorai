// Per-file runner:  node --test test/owasp-frameworks.test.mjs
//
// The rule base carried two framework tags, `owasp` (LLM Top 10) and `atlas`. Buyers working from agentic
// red-team checklists ask for two more: the OWASP Top 10 for Agentic Applications (ASI01–ASI10) and the
// OWASP MCP Top 10 (MCP01–MCP10). Every rule now carries `owaspAgentic` and `owaspMcp`. This file scores:
//
//   1. THE LISTS  — the id → title tables in data/owasp-frameworks.js are the official ones, pinned here
//                   so an edit to a title or an invented id fails instead of reaching a buyer's report.
//   2. SHAPE      — both tags are arrays of unique ids from those lists, on every rule; a bounded credit
//                   names an id the rule credits and states a non-empty limit.
//   3. THE MAP    — every credit, full or bounded, is named with the mechanism that earns it, and the
//                   credits considered and rejected stay rejected.
//   4. COVERAGE   — the per-framework numbers the console crosswalk reports.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  OWASP_AGENTIC, OWASP_MCP, owaspAgenticIds, owaspMcpIds, owaspAgenticPartialNote, owaspMcpPartialNote
} from "../data/owasp-frameworks.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { meta, threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const byId = new Map(threats.map((t) => [t.id, t]));

const FW = [
  { key: "owaspAgentic", partialKey: "owaspAgenticPartial", list: OWASP_AGENTIC, ids: owaspAgenticIds, note: owaspAgenticPartialNote, re: /^ASI(0[1-9]|10)$/ },
  { key: "owaspMcp", partialKey: "owaspMcpPartial", list: OWASP_MCP, ids: owaspMcpIds, note: owaspMcpPartialNote, re: /^MCP(0[1-9]|10)$/ }
];

// ---------------------------------------------------------------------------------------------
// 1. The official lists
// ---------------------------------------------------------------------------------------------
test("OWASP-MAP: the Agentic Applications list is the official 2026 list", () => {
  // Source: OWASP Top 10 for Agentic Applications 2026, OWASP GenAI Security Project, December 2025.
  assert.deepEqual(OWASP_AGENTIC.items, {
    ASI01: "Agent Goal Hijack",
    ASI02: "Tool Misuse and Exploitation",
    ASI03: "Identity and Privilege Abuse",
    ASI04: "Agentic Supply Chain Vulnerabilities",
    ASI05: "Unexpected Code Execution (RCE)",
    ASI06: "Memory & Context Poisoning",
    ASI07: "Insecure Inter-Agent Communication",
    ASI08: "Cascading Failures",
    ASI09: "Human-Agent Trust Exploitation",
    ASI10: "Rogue Agents"
  });
  assert.equal(OWASP_AGENTIC.source, "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/");
});

test("OWASP-MAP: the MCP list is the official 2025 list, with MCP06's current title", () => {
  // Source: github.com/OWASP/www-project-mcp-top-10, index.md and the 2025/ item files.
  assert.deepEqual(OWASP_MCP.items, {
    MCP01: "Token Mismanagement & Secret Exposure",
    MCP02: "Privilege Escalation via Scope Creep",
    MCP03: "Tool Poisoning",
    MCP04: "Software Supply Chain Attacks & Dependency Tampering",
    MCP05: "Command Injection & Execution",
    MCP06: "Intent Flow Subversion",
    MCP07: "Insufficient Authentication & Authorization",
    MCP08: "Lack of Audit and Telemetry",
    MCP09: "Shadow MCP Servers",
    MCP10: "Context Injection & Over-Sharing"
  });
  assert.equal(OWASP_MCP.source, "https://github.com/OWASP/www-project-mcp-top-10");
});

// ---------------------------------------------------------------------------------------------
// 2. Shape
// ---------------------------------------------------------------------------------------------
test("OWASP-MAP: every rule carries both tags as arrays of unique ids from the official lists", () => {
  for (const t of threats) {
    for (const f of FW) {
      assert.ok(Array.isArray(t[f.key]), `#${t.id} ${f.key} must be an array (possibly empty), got ${typeof t[f.key]}`);
      const ids = f.ids(t);
      assert.equal(new Set(ids).size, ids.length, `#${t.id} repeats a ${f.key} id: ${ids.join(", ")}`);
      for (const id of ids) {
        assert.match(id, f.re, `#${t.id} malformed ${f.key} id ${id}`);
        assert.ok(f.list.items[id], `#${t.id} credits ${id}, which is not in the official ${f.list.name} list`);
      }
    }
  }
});

test("OWASP-MAP: a bounded credit is for an id the rule credits, and states a non-empty limit", () => {
  for (const t of threats) {
    for (const f of FW) {
      if (t[f.partialKey] === undefined) continue;
      const entries = Object.entries(t[f.partialKey]);
      assert.ok(entries.length > 0, `#${t.id} has an empty ${f.partialKey} — omit the field instead`);
      const ids = new Set(f.ids(t));
      for (const [id, limit] of entries) {
        assert.ok(ids.has(id), `#${t.id} marks ${id} partial but does not credit it`);
        assert.equal(typeof limit, "string", `#${t.id} ${id} partial limit must be a string`);
        assert.ok(limit.trim().length > 3, `#${t.id} ${id} partial limit is empty`);
      }
    }
  }
});

test("OWASP-MAP: the schema documents both tags", () => {
  for (const k of ["owaspAgentic", "owaspAgenticPartial", "owaspMcp", "owaspMcpPartial"]) {
    assert.ok((meta.schema?.[k] || "").length > 20, `meta.schema.${k} is missing`);
  }
});

// ---------------------------------------------------------------------------------------------
// 3. The map — every credit, named
// ---------------------------------------------------------------------------------------------
// [rule, id, bounded limit or null for a full credit, the mechanism that earns it]
const AGENTIC = [
  [2, "ASI01", "jailbreak and override phrasing typed into the prompt only", "eight prompt-stage detectors match guardrail-override and jailbreak families"],
  [3, "ASI01", null, "override phrasing in fetched pages, files and tool results (the file stage runs these detectors), plus session-window persona scaffolding"],
  [40, "ASI01", null, "inj-untrusted-directive and ingest-agent-directed fire on imperatives inside files, index content and tool output"],
  [50, "ASI01", "hidden-text channel only", "zero-width, bidi and rendering-hidden instructions in content"],
  [64, "ASI01", "lexical check that a risky call's targets were named in the task", "intent alignment flags a risky call whose targets the user never named"],
  [68, "ASI01", "prefilled assistant links only", "craftedAssistantLink decodes a ?q= / ?prompt= payload"],
  [70, "ASI01", "content addressed only to AI readers", "cloak-ai-audience matches a block addressed to the model that steers or contradicts the page"],
  [72, "ASI01", "file-metadata channel only", "directives in EXIF / XMP / ID3 / document properties"],
  [74, "ASI01", "self-replication directives only", "inj-self-replication matches content telling the model to reproduce the instruction"],
  [38, "ASI02", "runaway loops, call rate and session call budget only", "the circuit breaker (data/circuit-breaker.js) posts loop, rate and budget alerts under #38"],
  [43, "ASI02", "irreversible shell commands only", "destructive-command matches rm -rf, force-push, DROP, format run through the shell tool"],
  [47, "ASI02", "send-message tool families, gated on human approval", "action-external-comms gates email / SMS / webhook sends"],
  [49, "ASI02", "production deploy commands, gated on human approval", "action-prod-deploy gates terraform apply, kubectl to prod, npm publish"],
  [56, "ASI02", "irreversible tool and MCP operations only", "mcp-destructive-call matches drop / mass-delete / teardown through a tool"],
  [59, "ASI02", "outbound calls after untrusted content, and exfiltration sequences, within one session", "data/session-risk.js taint and sequence alerts post under #59"],
  [65, "ASI02", "known local secret values only", "the secret-value fingerprint is matched against outbound commands and MCP tool arguments"],
  [77, "ASI02", "model files and caches, one command", "model-artifact-collection matches weights or datasets staged into an upload"],
  [78, "ASI02", "listed collection hosts only", "oast-exfil matches data sent to a public request-capture host"],
  [46, "ASI03", "IAM, sudo and security-setting changes, gated on human approval", "action-security-config matches IAM grants, sudoers edits, firewall opening"],
  [48, "ASI03", "identity and credential creation, gated on human approval", "action-credential-create matches create-access-key, adduser, service-account creation"],
  [55, "ASI03", "local credential files and keychain only", "cred-file-access matches the agent reading the authentication material it runs with"],
  [66, "ASI03", "the parent's entitlement envelope applied to a delegated sub-agent", "the hook applies the parent's envelope to an Agent/Task delegation"],
  [25, "ASI04", "approved-connector allow-list only", "policy.mcpAllow refuses a call to a third-party server off the list"],
  [50, "ASI04", "hidden characters in MCP tool metadata only", "mcp-hidden-canary runs at the tool stage on tools/list"],
  [60, "ASI04", "MCP tool descriptors and auto-loaded agent config; no provenance check", "tool-stage descriptor scan and index-stage scan of auto-loaded config"],
  [54, "ASI05", "reverse-shell / remote-exec payloads only", "exec-reverse-shell"],
  [57, "ASI05", "remote scripts piped to a shell and installs from untrusted sources", "pkg-install-untrusted and fetch-then-exec"],
  [80, "ASI05", "a repository checkout run in the same command", "clone-then-run matches a clone or downloaded archive whose install or start scripts run in the same chain"],
  [61, "ASI05", "exploitable constructs in code the agent writes; nothing is executed", "eight code-* detectors: eval, shell=True, unsafe deserialisation"],
  [62, "ASI05", "package names in install commands only", "dep-typosquat classifies a hallucinated or typosquatted name before install"],
  [76, "ASI05", "load calls only", "model-unsafe-load matches pickle-based and trust_remote_code loads"],
  [21, "ASI06", "content scanned before it is embedded; the store is not read at retrieval", "rag-poisoning at the index stage"],
  [22, "ASI06", "instructions an agent writes into its own memory and instruction files", "memory-poisoning"],
  [68, "ASI06", "memory writes carried in a crafted assistant link only", "craftedAssistantLink requires the payload to ask for persistence"],
  [73, "ASI06", "local agent transcript files only", "agent-history-tamper matches a forged or rewritten transcript store"],
  [66, "ASI07", "sub-agent handoffs on one host, logged and scanned for injection; no message authentication", "handoff edges logged, delegated prompt scanned, orphan sub-agents flagged"],
  [75, "ASI09", "deceptive links in output only", "out-link-deceptive compares a link's shown address with its real host"],
  [64, "ASI10", "actions outside a declared envelope or a learned baseline, by name and path", "entitlement drift and learned first-seen drift post under #64"]
];

const MCP = [
  [39, "MCP01", "secret values in prompts and output; token lifetime and storage are not assessed", "twenty secret-shape detectors block or mask a live credential entering the model's context"],
  [55, "MCP01", "local credential files and keychain only", "cred-file-access and secret-file-upload"],
  [65, "MCP01", "known local secret values in egress, MCP tool arguments included", "secret-value fingerprint matched on egress"],
  [46, "MCP02", "IAM, sudo and security-setting changes, gated on human approval", "action-security-config"],
  [48, "MCP02", "identity and credential creation, gated on human approval", "action-credential-create"],
  [64, "MCP02", "actions checked against a declared envelope; granted scopes are not reviewed", "entitlement envelope comparison"],
  [50, "MCP03", "hidden characters in MCP tool metadata only", "mcp-hidden-canary at the tool stage"],
  [60, "MCP03", "description and schema text only", "mcp-tool-poisoning, mcp-tool-poisoning-i18n and mcp-tool-cred-path on tools/list"],
  [54, "MCP05", "reverse-shell / remote-exec payloads only", "exec-reverse-shell, which the MCP gateway runs on tools/call arguments"],
  [57, "MCP05", "remote scripts piped to a shell and installs from untrusted sources", "fetch-then-exec and pkg-install-untrusted"],
  [3, "MCP06", null, "override phrasing in MCP tool results and fetched content at the file stage"],
  [40, "MCP06", null, "imperatives in tool output, files and index content"],
  [50, "MCP06", "hidden-text channel only", "hidden-text detectors at the file / index / output stages"],
  [59, "MCP06", "outbound calls after injection-class content, within one session", "session-risk taint window"],
  [64, "MCP06", "lexical check that a risky call's targets were named in the task", "intent alignment"],
  [70, "MCP06", "content addressed only to AI readers", "cloak-ai-audience"],
  [72, "MCP06", "file-metadata channel only", "metadata directive scan"],
  [74, "MCP06", "self-replication directives only", "inj-self-replication"],
  [73, "MCP08", "tampering with local agent transcript files only", "agent-history-tamper protects the agent's own record of what it did"],
  [25, "MCP09", "calls to servers off the approved allow-list; no discovery of deployed servers", "policy.mcpAllow"]
];

for (const [label, f, table] of [["Agentic", FW[0], AGENTIC], ["MCP", FW[1], MCP]]) {
  test(`OWASP-MAP: every ${label} credit is present, with its bound`, () => {
    const problems = [];
    for (const [rule, id, limit] of table) {
      const t = byId.get(rule);
      if (!f.ids(t).includes(id)) { problems.push(`#${rule} is missing ${id}`); continue; }
      const note = f.note(t, id);
      if (note !== limit) problems.push(`#${rule} ${id} bound is ${JSON.stringify(note)}, expected ${JSON.stringify(limit)}`);
    }
    assert.deepEqual(problems, [], problems.join("\n"));
  });

  test(`OWASP-MAP: no ${label} credit exists that the table does not name`, () => {
    const named = new Set(table.map(([rule, id]) => `${rule}:${id}`));
    const extra = threats.flatMap((t) => f.ids(t).map((id) => `${t.id}:${id}`)).filter((k) => !named.has(k));
    assert.deepEqual(extra, [], `unreviewed credits: ${extra.join(", ")}`);
  });
}

test("OWASP-MAP: the credits the review rejected stay uncredited", () => {
  const REJECTED = [
    [7, "owaspMcp", "MCP09", "the AIBOM inventories MCP servers, but it raises no finding under #7"],
    [11, "owaspAgentic", "ASI09", "a human attacker's payment-change request, not an agent exploiting the user's trust"],
    [29, "owaspAgentic", "ASI09", "out-citation is coach-mode and fires on every citation marker"],
    [17, "owaspAgentic", "ASI05", "out-links fires on every URL in an output"],
    [32, "owaspAgentic", "ASI05", "out-code-exec fires on every code fence"],
    [24, "owaspAgentic", "ASI02", "coaching rule with no detection or enforcement behind it"],
    [63, "owaspAgentic", "ASI04", "decides the destination host of model traffic, not a component's provenance"],
    [67, "owaspAgentic", "ASI07", "not wired, and agent-to-provider transit is not inter-agent communication"],
    [79, "owaspAgentic", "ASI02", "a contact without a payload moves no data through a tool"],
    [74, "owaspAgentic", "ASI08", "OWASP files the initial defect under its own entry and ASI08 only for measured fan-out"],
    [38, "owaspAgentic", "ASI08", "one session's loop and call rate, not propagation across agents"],
    [1, "owaspMcp", "MCP10", "DLP keeps data out of the context; sharing between users or sessions is not observed"],
    [36, "owaspMcp", "MCP10", "coaching rule with no detection"],
    [57, "owaspAgentic", "ASI04", "the agent's project dependencies, not agent or MCP components"],
    [57, "owaspMcp", "MCP04", "the agent's project dependencies, not MCP components"],
    [62, "owaspMcp", "MCP04", "general-purpose package names; MCP server names are checked by the reputation layer, which posts under no rule"],
    [2, "owaspMcp", "MCP06", "MCP06 excludes a user's own direct injection by definition"],
    [61, "owaspMcp", "MCP05", "code written into the project, not a command the agent runs"],
    [43, "owaspMcp", "MCP05", "destructive, not injected"]
  ];
  const wrong = REJECTED.filter(([rule, key, id]) => (byId.get(rule)[key] || []).includes(id))
    .map(([rule, , id, why]) => `#${rule} credits ${id} — rejected because ${why}`);
  assert.deepEqual(wrong, [], wrong.join("\n"));
});

// ---------------------------------------------------------------------------------------------
// 4. Coverage — what the crosswalk reports
// ---------------------------------------------------------------------------------------------
function coverage(f) {
  const out = {};
  for (const id of Object.keys(f.list.items)) {
    const rules = threats.filter((t) => f.ids(t).includes(id));
    const full = rules.filter((t) => !f.note(t, id));
    out[id] = rules.length === 0 ? "uncovered" : full.length ? "covered" : "partial";
  }
  return out;
}

test("OWASP-MAP: Agentic coverage — 1 covered, 8 partial, ASI08 uncovered", () => {
  const c = coverage(FW[0]);
  assert.deepEqual(Object.keys(c).filter((k) => c[k] === "covered"), ["ASI01"]);
  assert.deepEqual(Object.keys(c).filter((k) => c[k] === "partial"), ["ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI09", "ASI10"]);
  assert.deepEqual(Object.keys(c).filter((k) => c[k] === "uncovered"), ["ASI08"]);
});

test("OWASP-MAP: MCP coverage — 1 covered, 6 partial, MCP04 / MCP07 / MCP10 uncovered", () => {
  const c = coverage(FW[1]);
  assert.deepEqual(Object.keys(c).filter((k) => c[k] === "covered"), ["MCP06"]);
  assert.deepEqual(Object.keys(c).filter((k) => c[k] === "partial"), ["MCP01", "MCP02", "MCP03", "MCP05", "MCP08", "MCP09"]);
  assert.deepEqual(Object.keys(c).filter((k) => c[k] === "uncovered"), ["MCP04", "MCP07", "MCP10"]);
});

test("OWASP-MAP: the readers normalise a missing or malformed tag to []", () => {
  assert.deepEqual(owaspAgenticIds({}), []);
  assert.deepEqual(owaspMcpIds(undefined), []);
  assert.deepEqual(owaspAgenticIds({ owaspAgentic: "ASI01" }), []);
  assert.equal(owaspMcpPartialNote({ owaspMcp: ["MCP01"] }, "MCP01"), null);
});
