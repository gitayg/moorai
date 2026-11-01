// Hiding techniques in agent skill and instruction files (data/skill-hiding.js) as engine detectors, so
// threatActionFor, detector packs and the console's threat policy reach them like any other rule, and
// cli/skill-analysis.mjs can name them as intent labels without a second engine.
//
// STAGES. "file" and "index": a file the agent reads (the hook's Read branch, `moorai scan`, the MCP
// package scan) and the auto-loaded instruction files the hook's ingest worker screens at session start.
// Not "prompt" (the user's own words), not "output" (what the agent writes; memory writes are judged by
// memory-poisoning #22 and by the protected instruction-file surface, cli/oversight-surfaces.mjs).
//
// PATH SCOPE. ctx.readPath / ctx.targetPath, when the caller knows the file:
//   * padding and HTML comments are LAYOUT tells, and a fetched HTML page or a log carries commented-out
//     links and blank runs as a matter of course. They fire only when that path is on the skill
//     surface (data/skill-surface.js, which includes every SKILL.md). No path, no finding.
//   * concealment, reviewer text and memory persistence are PHRASING tells. They fire on a skill-surface
//     path, and on content whose path the caller does not know (an MCP tool result at the proxy, an
//     embedding pipeline): an order to hide an action from the user is an attack wherever it is read. A
//     known path that is not on the skill surface (a README, a source file the agent reads) is quiet.
//
// THREATS.
//   #40 Second-Order Prompt Injection — a malicious instruction stored in content a privileged agent reads
//       later, which is what a skill or instruction file is. Padding, HTML comments and concealment are
//       three ways of hiding such an instruction from the human who installs the file. Concealment maps
//       here rather than to #3 because the existing concealment payload (data/agent-directed.js, class
//       "conceal") already raises #40 for ingested content, and the intent label for #3 is
//       "instruction-override", which concealment is not.
//   #3  Indirect Prompt Injection — the instruction-override family (inj-ignore, inj-override-structural,
//       inj-multilingual all raise #3). Text telling a reviewer or scanner to override its flags is an
//       override aimed at a different reader.
//   #22 Memory Poisoning — the skill writes its own text into the agent's standing memory, the exact act
//       #22 names ("saving unapproved instructions into an AI tool's memory").
//
// ORDER. Appended after every other detector (data/detectors.js), so where another #40 detector also fires
// the engine keeps one of these (it keeps the last "warn" finding per threat) and the more specific
// intent label survives. Not "inj"-prefixed: the decoded-variant pass would re-run them over every rot13
// and reversed copy of a 256 KB file; the invisible-character views (data/text-views.js) do reach them.
import { isSkillSurface } from "./skill-surface.js";
import { paddedHiddenContent, hiddenHtmlInstruction, concealsFromUser, targetsReviewers, persistsToMemory } from "./skill-hiding.js";

// The file being judged: ctx.readPath (a file the agent reads: the hook's Read and Bash branches, `moorai
// scan`, the MCP package scan) or ctx.targetPath (the ingest worker's auto-loaded file). readPath is its
// own key because targetPath already means "a write target" to other refines (instr-leak-* goes silent on
// a rules-file target, which must not happen to an upload that reads CLAUDE.md).
const pathOf = (ctx) => {
  const p = ctx && (ctx.readPath || ctx.targetPath);
  return typeof p === "string" && p ? p : "";
};
const onSurface = (ctx) => { const p = pathOf(ctx); return Boolean(p) && isSkillSurface(p); };
const surfaceOrUnknown = (ctx) => { const p = pathOf(ctx); return !p || isSkillSurface(p); };
const STAGES = ["file", "index"];

export const SKILL_HIDING_DETECTORS = [
  {
    detectorId: "skill-padded-hidden-content",
    threatId: 40,
    stages: STAGES,
    mode: "warn",
    // Reads the blank-line layout the invisible-character views collapse, so it judges the original only.
    rawOnly: true,
    hint: "Skill / instruction file hides content below a long run of blank lines (padding that pushes a directive out of a reviewer's view).",
    patterns: [/^[\s\S]/],
    refine: (_m, text, ctx) => onSurface(ctx) && paddedHiddenContent(text)
  },
  {
    detectorId: "skill-hidden-html-instructions",
    threatId: 40,
    stages: STAGES,
    mode: "warn",
    hint: "Skill / instruction file hides a URL, a shell command, a beacon line or an order to the agent inside an HTML comment (invisible when the Markdown is rendered).",
    patterns: [/^[\s\S]/],
    refine: (_m, text, ctx) => onSurface(ctx) && hiddenHtmlInstruction(text)
  },
  {
    detectorId: "skill-conceals-from-user",
    threatId: 40,
    stages: STAGES,
    mode: "warn",
    hint: "Instruction tells the agent to keep its actions from the user (\"do not tell the user\", \"your human doesn't need to know\", \"silently … without asking\").",
    patterns: [/^[\s\S]/],
    refine: (_m, text, ctx) => surfaceOrUnknown(ctx) && concealsFromUser(text)
  },
  {
    detectorId: "skill-targets-reviewers",
    threatId: 3,
    stages: STAGES,
    mode: "warn",
    hint: "Text addressed to automated reviewers or scanners tells them to override their flags or claims the file is verified safe (instruction override aimed at the reviewer).",
    patterns: [/^[\s\S]/],
    refine: (_m, text, ctx) => surfaceOrUnknown(ctx) && targetsReviewers(text)
  },
  {
    detectorId: "skill-persists-to-memory",
    threatId: 22,
    stages: STAGES,
    mode: "warn",
    hint: "Instruction tells the agent to write this text into its standing memory or instruction file (MEMORY.md, SOUL.md, CLAUDE.md, AGENTS.md, .cursorrules), so it outlives the skill.",
    patterns: [/^[\s\S]/],
    refine: (_m, text, ctx) => surfaceOrUnknown(ctx) && persistsToMemory(text)
  }
];
