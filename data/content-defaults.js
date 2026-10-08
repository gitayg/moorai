// The BUILT-IN content-policy default: which parental-control content categories (data/content-rules.js)
// run when an org's policy says nothing about them, and in which mode.
//
// THE DEFAULT. The NSFW categories run in "notify": every hit is reported to the console as a content
// finding and the person sees it (a coach card in the desktop app, the finding list in moorai-guard), but
// nothing is held — notify never raises a decision above allow (cli/hook-core.mjs decideText). An org
// changes it per category from the console; an explicit entry ALWAYS wins, so "disabled" turns a category
// off and "justify" / "block" are the only ways it can ever hold anything. A policy with no contentPolicy
// at all (an enrolled device whose org published nothing yet, the offline default) gets exactly this.
//
// NSFW here means the three categories that name not-safe-for-work material itself: sexual / explicit,
// graphic violence, profanity. The wellbeing and child-safety categories (self-harm, eating-disorder,
// drugs, hate, harassment, grooming) stay off by default: they are org decisions with their own escalation
// paths, not a workplace-content default.
//
// MEASURED COST (scripts/measure-content-defaults.mjs, after the content-rules precision pass): 0 of 1,393
// benign corpus rows, 0 of 149 benign fetched pages, 1 of 46 deliberately hard rows (crude workplace slang,
// which this category reports), and 10 of 110,537 real source and markdown files — mostly files that quote the
// keyword lists themselves. Before that pass: 1/1,393, 13/46 and 450/110,536. See docs/DETECTION_ENGINE.md.
export const NSFW_CONTENT_RULES = Object.freeze(["sexual", "violence", "profanity"]);
export const BUILTIN_CONTENT_ACTION = "notify";
export const BUILTIN_CONTENT_DEFAULTS = Object.freeze(Object.fromEntries(NSFW_CONTENT_RULES.map((id) => [id, BUILTIN_CONTENT_ACTION])));

// The content policy actually enforced: the built-in defaults under the org's explicit entries. A
// non-object contentPolicy (malformed) is treated as absent, never as "everything off".
export function effectiveContentPolicy(policy) {
  const cp = policy && policy.contentPolicy;
  return { ...BUILTIN_CONTENT_DEFAULTS, ...(cp && typeof cp === "object" && !Array.isArray(cp) ? cp : {}) };
}
