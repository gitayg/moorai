// Detectors for agent output or outbound payloads that reproduce the protected instructions the agent
// runs under (CLAUDE.md, AGENTS.md, rules files) — system-instruction leakage (AML.T0056 on the output
// side). Spread into DETECTORS.
//
// Threat: #52 ("System-prompt or instruction leakage in output", LLM07 / AML.T0056) until a dedicated
// threat lands in data/threats.json. #52's built-in action is "notify", so all three REPORT by default.
//
// The two fingerprint detectors are silent until a host registers fingerprints
// (cli/instruction-fingerprints.mjs → data/instruction-fingerprint.js), so the browser extension, the
// desktop app, mcp-proxy and every benchmark scorer that loads DETECTORS see no change at all.
//
// Named instr-*, NOT sysprompt-*: the engine's decode pass re-runs sysprompt-* detectors over normalized
// variants WITHOUT ctx, which would bypass the rules-file-target exclusion (a leet/homoglyph variant of
// CLAUDE.md written back to CLAUDE.md). The fingerprint scorer decodes base64 itself, with ctx intact.
import { instructionLeakHit } from "./instruction-fingerprint.js";
import { isInstructionFilePath, rulesFileEgressHit, INSTRUCTION_NAME_PREFILTER } from "./instruction-files.js";

// One anchored match per text: refine() then runs once, not once per occurrence, and the reported
// `match` is at most one character — nothing of the rules file reaches an alert.
const ONCE = /^[\s\S]/;

export const INSTRUCTION_LEAK_DETECTORS = [
  {
    // Text the agent EMITS (Write/Edit content, generated output) that reproduces a substantial share of
    // a fingerprinted rules file. Silent for inbound content (ctx.inbound) and for writes whose target is
    // itself a rules file (ctx.targetPath).
    detectorId: "instr-leak-output",
    threatId: 52,
    stages: ["output"],
    mode: "warn",
    hint: "Output reproduces a substantial part of the agent's protected instruction file (CLAUDE.md / AGENTS.md / rules).",
    patterns: [ONCE],
    refine: (_m, text, ctx) => instructionLeakHit(text, ctx, isInstructionFilePath)
  },
  {
    // An OUTBOUND payload (Bash command, WebFetch url+prompt, MCP tool args, or a file an upload command
    // reads) that carries the rules file's text. Opt-in: fires only when the host marks the text as
    // leaving the device (ctx.egress === true). The "prompt" stage also carries Read/indexscan content —
    // i.e. the rules file itself — which must never be judged as its own leak.
    detectorId: "instr-leak-egress",
    threatId: 52,
    stages: ["prompt"],
    mode: "warn",
    hint: "An outbound request carries a substantial part of the agent's protected instruction file.",
    patterns: [ONCE],
    refine: (_m, text, ctx) => !!(ctx && ctx.egress === true) && instructionLeakHit(text, ctx, isInstructionFilePath)
  },
  {
    // Path-only: an upload whose data is a rules file — `curl -d "$(cat CLAUDE.md)" https://…`,
    // `curl -F f=@AGENTS.md`, `cat .cursorrules | base64 | curl --data-binary @- …`, `gh gist create
    // CLAUDE.md`. The shell expands the file after the hook runs, so this is the only view of it.
    detectorId: "instr-leak-upload-ref",
    threatId: 52,
    stages: ["prompt"],
    mode: "warn",
    hint: "An upload command sends the agent's protected instruction file (CLAUDE.md / AGENTS.md / rules) off the device.",
    patterns: [INSTRUCTION_NAME_PREFILTER],
    refine: (_m, text) => rulesFileEgressHit(text)
  }
];
