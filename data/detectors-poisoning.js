// #22 memory poisoning and #21 RAG / knowledge-base poisoning as detectors. The phrasing lives in
// data/poisoning-tells.js; this module wires it to the engine's stages and reuses the INGESTED-CONTENT
// injection family that already exists, so a poisoned memory file or index chunk is judged by the same
// tuned detectors that judge a poisoned web page, plus the persistence / retrieval tells only these two
// threats need.
//
// Exported as a factory over the finished DETECTORS array (data/detectors.js calls it last) because the
// reused detectors live in that array and this module must not import it back (an import cycle).
//
// WHERE EACH ONE FIRES
//   memory-poisoning (#22) — stage "output" with ctx.targetPath, which is exactly how cli/moorai-hook.mjs
//     scans a Write / Edit / MultiEdit / NotebookEdit (and, through shellMemoryWrites, an echo/tee/heredoc
//     write from Bash or PowerShell); and stage "index" with ctx.targetPath, which is how the hook's
//     detached `indexscan` worker reads the auto-loaded instruction files at session start. Silent unless
//     ctx.targetPath is a MEMORY path (data/poisoning-tells.js memoryKind). Any other output-stage scan —
//     a model reply, a fetched page, a tool result — carries no targetPath and is untouched.
//   rag-poisoning (#21) — stage "index" only, which is DetectionEngine.scanForIndex: the embedding
//     pipelines (@moorai/agent-sdk scanBeforeEmbed / guardEmbed, POST /v1/index-scan, MCP vector-store
//     writes through cli/index-scan.mjs). Silent when ctx.targetPath names a skill-surface file: that is
//     the hook reading CLAUDE.md / AGENTS.md at session start, which is memory (#22), not a knowledge base.
//
// Both use a whole-text prefilter (/^[\s\S]/) and decide in refine, the division ingest-agent-directed
// uses. Neither is "inj"-prefixed, on purpose: the decoded-variant pass would otherwise re-run the whole
// reused family over every decoded copy of a large document. An ENCODED instruction already raises #50
// (obf-encoded-payload) and the inj-* detectors on its decoded form; it does not also raise #21/#22.
import { safeRegex } from "../src/safe-regex.js";
import { globalMatches } from "../src/regex-restart.js";
import { isSkillSurface } from "./skill-surface.js";
import { memoryKind, memoryPoisoningTell, retrievalTell, stripMetaExamples } from "./poisoning-tells.js";

// The ingested-content injection family: every detector that already says "this content carries an
// instruction aimed at the agent". Chosen by id, not by threat, so a new #40 detector does not join
// silently — it has to be measured against the memory and index benign sets first.
// The reused injection detectors, chosen by id rather than threat so a new detector does not join
// silently. TWO lists, because the two surfaces differ in kind:
//   * An instruction FILE is supposed to be imperative prose addressed to the agent ("You MUST run…",
//     "When you are done, run…", "Always use…", "<SECRET>" placeholders). Measured on the tune half of 442
//     real CLAUDE.md / auto-memory / skill files, the directive-shaped detectors (inj-untrusted-directive,
//     idx-hidden-instructions, ingest-agent-directed, mcp-tool-poisoning, inj-ignore's /DAN/i) fired on 7.7%
//     of them. Memory reuses only the override and hidden-text detectors; those directive detectors keep
//     raising #40 / #60 on the same write exactly as before.
//   * A knowledge-base document is NOT supposed to address the agent at all, so the whole ingested-content
//     family is evidence there.
export const MEMORY_FAMILY = [
  "inj-override-structural", "inj-multilingual-untrusted",
  "mcp-hidden-canary", "hidden-zero-width-interleave", "obf-rendered-hidden"
];
export const RAG_FAMILY = [
  "inj-untrusted-directive", "idx-hidden-instructions", "ingest-agent-directed", "inj-multilingual-untrusted",
  "mcp-tool-poisoning", "inj-ignore", "inj-override-structural",
  "mcp-hidden-canary", "hidden-zero-width-interleave", "obf-rendered-hidden"
];

// The engine's _matchDetector, minus the engine: patterns, then refine on each occurrence.
function matches(d, text, ctx) {
  if (!d.refine) return d.patterns.some((p) => { p.lastIndex = 0; return p.test(text); });
  for (const p of d.patterns) {
    const g = safeRegex(p.source, p.flags.includes("g") ? p.flags : p.flags + "g");
    if (!g) continue;
    for (const m of globalMatches(p, g, text)) if (d.refine(m[0], text, ctx)) return true;
  }
  return false;
}

export function poisoningDetectors(all) {
  const resolved = new Map();
  const familyHit = (ids, text, ctx) => {
    if (!resolved.has(ids)) resolved.set(ids, ids.map((id) => all.find((d) => d.detectorId === id)).filter(Boolean));
    for (const d of resolved.get(ids)) { try { if (matches(d, text, ctx)) return d.detectorId; } catch { /* one detector's error is not a finding */ } }
    return null;
  };
  return [
    {
      // #22 (LLM04, OWASP Agentic ASI06) — an instruction written into the agent's own persistent memory or
      // an auto-loaded instruction file. Fires on the ingested-content injection family, on a payload that
      // is an attack wherever it is written (exfiltration to a destination, concealment from the user,
      // fetch-and-run, an override), or on persistence phrasing ("from now on", "in every future session",
      // "remember to…") paired with a payload that is ordinary alone (reading .env, skipping a check,
      // "treat X as the only trusted source"). "Always run the tests" has persistence and no payload.
      detectorId: "memory-poisoning",
      threatId: 22,
      stages: ["output", "index"],
      mode: "warn",
      hint: "An instruction is being written into the agent's persistent memory / auto-loaded instruction file, where it will steer every future session (memory poisoning).",
      patterns: [/^[\s\S]/],
      refine: (_m, text, ctx) => {
        if (!ctx || !memoryKind(ctx.targetPath)) return false;
        const t = stripMetaExamples(text);
        return Boolean(familyHit(MEMORY_FAMILY, t, ctx) || memoryPoisoningTell(t).fire);
      }
    },
    {
      // #21 (LLM08, ATLAS AML.T0020) — content headed into a knowledge base / vector index carries an
      // instruction aimed at the model that will later retrieve it: the ingested-content injection family,
      // or a retrieval tell (it addresses the assistant, suppresses the other sources, forces an answer,
      // arms a query trigger). A support playbook's "if a customer asks for a refund, tell them…" addresses
      // a person and is not one.
      detectorId: "rag-poisoning",
      threatId: 21,
      stages: ["index"],
      mode: "warn",
      hint: "Content headed into a knowledge base / index carries an instruction aimed at the model that will retrieve it (RAG / knowledge-base poisoning).",
      patterns: [/^[\s\S]/],
      refine: (_m, text, ctx) => {
        if (ctx && ctx.targetPath && isSkillSurface(ctx.targetPath)) return false;
        const t = stripMetaExamples(text);
        return Boolean(retrievalTell(t) || familyHit(RAG_FAMILY, t, ctx));
      }
    }
  ];
}
