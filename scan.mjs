// Public library entry point for the MoorAI scan engine.
//
// This barrel is the STABLE import surface for consumers (e.g. `import { scanPath }
// from "moorai/scan"`). It re-exports only the public scan surface; internal files
// under cli/, src/, data/ may move freely as long as these names keep resolving here.

export {
  scanPath,
  scanFileText,
  VERDICTS,
  VERDICT_RANK,
  decisionToVerdict,
  worseVerdict,
  tierOf,
  jsonStrings,
} from "./cli/scan-core.mjs";

export { buildEngine, decideText } from "./cli/hook-core.mjs";

export { skillIntents } from "./cli/skill-analysis.mjs";

export { contentHash, NO_KEY } from "./cli/content-hash.mjs";

export { skillSurfaceKind, isSkillSurface } from "./data/skill-surface.js";
