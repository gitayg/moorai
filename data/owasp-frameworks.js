// The two OWASP agentic frameworks a rule can be crosswalked to, beside `owasp` (LLM Top 10) and `atlas`:
//
//   owaspAgentic  OWASP Top 10 for Agentic Applications, ASI01–ASI10 (version 2026, December 2025).
//   owaspMcp      OWASP MCP Top 10, MCP01–MCP10 (2025 list, project in beta).
//
// Both tags are always arrays, possibly empty: an empty array is a reviewed "no credit", not a missing
// field. `owaspAgenticPartial` / `owaspMcpPartial` mark a bounded credit the way `atlasPartial` does:
// the rule addresses the risk, but only over part of what the OWASP entry covers, and the short phrase
// says which part. Every partial key must also appear in the array.
//
// The id → title tables are the official lists, copied from the sources below on 2026-10-08. They are the
// only ids a rule may carry; test/owasp-frameworks.test.mjs pins both the tables and every credit.

export const OWASP_AGENTIC = {
  name: "OWASP Top 10 for Agentic Applications",
  version: "2026",
  published: "2025-12",
  source: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
  items: {
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
  }
};

// MCP06 is "Intent Flow Subversion" on the project home page (index.md) and in its 2025/ item file since
// commit c1804f3 (2026-01-12). The repository's tab_top10.md, last edited 2025-11-21, still carries the
// earlier title "Prompt Injection via Contextual Payloads"; the newer one is used here.
export const OWASP_MCP = {
  name: "OWASP MCP Top 10",
  version: "2025",
  status: "beta",
  source: "https://github.com/OWASP/www-project-mcp-top-10",
  items: {
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
  }
};

// "2026" / "2025, beta" — the edition as a report heading prints it.
export function frameworkEdition(fw) {
  return fw.status ? `${fw.version}, ${fw.status}` : fw.version;
}

export function owaspAgenticIds(threat) {
  return Array.isArray(threat?.owaspAgentic) ? threat.owaspAgentic.filter(Boolean) : [];
}

export function owaspMcpIds(threat) {
  return Array.isArray(threat?.owaspMcp) ? threat.owaspMcp.filter(Boolean) : [];
}

export function owaspAgenticPartialNote(threat, id) {
  return threat?.owaspAgenticPartial?.[id] || null;
}

export function owaspMcpPartialNote(threat, id) {
  return threat?.owaspMcpPartial?.[id] || null;
}
