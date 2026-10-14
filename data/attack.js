// The MITRE ATT&CK tag on a threat: `attack` is always an array of credits, `{ id, coverage, reason }`, and an
// empty array is a reviewed "no ATT&CK technique corresponds", with `attackNote` saying why.
//
//   coverage  full     a shipped mechanism addresses the technique as an AI agent MoorAI watches performs it
//             partial  a shipped mechanism addresses part of it; `reason` states the bound
//             none     the technique corresponds to the threat, but MoorAI ships no runtime mechanism for it
//
// Every credit is scoped to actions an AI agent takes through a surface MoorAI sees (hook, sidecar, MCP proxy
// or gateway, model proxy). Coverage is a mechanism claim, not a detection rate. Technique ids and names come
// from data/attack-v20-techniques.json, a slice of MITRE's own v20 STIX bundle; test/attack-v20.test.mjs
// checks every credited id against it.

export const ATTACK_V20 = {
  name: "MITRE ATT&CK Enterprise",
  version: "20.0",
  released: "2026-10-13",
  source: "https://attack.mitre.org/resources/updates/",
  stix: "https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.0"
};

export const COVERAGE_LEVELS = ["full", "partial", "none"];

// The v20 techniques an AI agent on an endpoint, server or AI runtime can perform or be aimed at: the
// denominator the benchmark reports ATT&CK coverage over. `lane` says who can see the technique:
//   agent     an action an AI agent takes that a MoorAI hook, proxy or gateway sees
//   edr       host activity outside any agent's tool calls (endpoint detection territory)
//   identity  sign-ins, tokens and accounts at an identity provider or SaaS tenant
//   email     mail, voice and messaging that reach a person, not an agent
//   pre       the adversary's own infrastructure, before anything touches the victim
export const ATTACK_SCOPE = {
  "T1698": "agent", "T1699": "agent", "T1700": "agent", "T1685.007": "agent", "T1608.007": "agent",
  "T1027.018": "agent", "T1195.001": "agent",
  "T1059.001": "agent", "T1059.004": "agent", "T1059.006": "agent", "T1059.013": "agent", "T1027.010": "agent",
  "T1105": "agent", "T1204.001": "agent", "T1204.002": "agent", "T1204.004": "agent", "T1204.005": "agent",
  "T1176.002": "agent", "T1677": "agent", "T1053.003": "agent", "T1543.001": "agent", "T1546.004": "agent",
  "T1552.001": "agent", "T1552.003": "agent", "T1552.004": "agent", "T1552.005": "agent", "T1552.008": "agent",
  "T1555.001": "agent", "T1555.003": "agent", "T1003.008": "agent", "T1528": "agent",
  "T1074.001": "agent", "T1560.001": "agent", "T1030": "agent", "T1016.001": "agent",
  "T1567": "agent", "T1567.001": "agent", "T1567.002": "agent", "T1567.003": "agent", "T1567.004": "agent",
  "T1048.003": "agent",
  "T1485": "agent", "T1561": "agent", "T1490": "agent",
  "T1070": "agent", "T1070.003": "agent", "T1690": "agent",
  "T1685": "agent", "T1686": "agent", "T1553.001": "agent", "T1553.004": "agent", "T1557": "agent",
  "T1098.001": "agent", "T1098.003": "agent", "T1098.004": "agent", "T1136.001": "agent", "T1136.003": "agent",
  "T1548.003": "agent",
  "T1176.001": "edr",
  "T1078.004": "identity", "T1697": "identity", "T1496.004": "identity",
  "T1566": "email", "T1566.004": "email", "T1684.001": "email", "T1657": "email",
  "T1682": "pre", "T1683.001": "pre", "T1683.002": "pre", "T1588.007": "pre", "T1696": "pre"
};

export function attackCredits(threat) {
  return Array.isArray(threat?.attack) ? threat.attack.filter((c) => c && c.id) : [];
}

export function attackIds(threat) {
  return attackCredits(threat).map((c) => c.id);
}

// The rule's overall level: none with no credit or only `none` credits, full when every credit is full,
// partial otherwise.
export function attackCoverage(threat) {
  const levels = attackCredits(threat).map((c) => c.coverage);
  if (!levels.some((l) => l === "full" || l === "partial")) return "none";
  return levels.every((l) => l === "full") ? "full" : "partial";
}

// "T1698 · T1685.007 (partial)" — the display form.
export function attackLabel(threat) {
  return attackCredits(threat).map((c) => (c.coverage === "full" ? c.id : `${c.id} (${c.coverage})`)).join(" · ");
}
