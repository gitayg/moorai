// A credential location in an MCP tool's description or input schema, in an instruction-shaped context
// (data/tool-credpaths.js holds the decision and the precision argument). Spread into DETECTORS.
//
// Threat: #60, the one mcp-tool-poisoning already reports on this stage — what is poisoned is the tool
// metadata, and the finding an admin acts on is "remove the server". The proxy feeds tool-stage #60
// findings into the server's reputation as `tool-poisoning` (cli/mcp-reputation.mjs toolCode), so this
// detector reaches the reputation signal with no extra wiring.
//
// "tool" stage only: rules files and fetched pages have their own #60 / #40 detectors, and #55
// cred-file-access already covers the agent actually reading the file. Not "inj*"-prefixed, so the
// engine's decode pass does not re-run it over normalized variants.
import { toolCredPathHit } from "./tool-credpaths.js";

// One anchored match per text: refine() runs once, and the reported `match` is one character — the path
// never reaches a finding.
const ONCE = /^[\s\S]/;

export const TOOL_CREDPATH_DETECTORS = [
  {
    detectorId: "mcp-tool-cred-path",
    threatId: 60,
    stages: ["tool"],
    mode: "warn",
    hint: "Tool description / schema tells the model to read a credential file (SSH key, cloud credentials, .env, browser or keychain store) and put it in a call (MCP tool poisoning).",
    patterns: [ONCE],
    refine: (_m, text) => toolCredPathHit(text)
  }
];
