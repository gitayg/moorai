// Phrasing tells for the two PERSISTENCE threats, and the path / shell plumbing that decides when they
// apply. Pure, dependency-light, size-capped, ReDoS-safe (every gap is bounded). They decide nothing and
// enforce nothing: data/detectors-poisoning.js turns them into findings for the engine.
//
//   #22 memory poisoning — the agent writes an instruction into its OWN persistent memory or an
//       auto-loaded instruction file, so it steers every future session. The question asked of the
//       written text is "would this be an attack if it ran at the start of every session?".
//   #21 RAG / knowledge-base poisoning — content headed into an index carries an instruction aimed at
//       whatever model later RETRIEVES it: it addresses the assistant, suppresses the other sources, or
//       arms a trigger. The question is "is this passage talking to the model that will read it?".
//
// What neither can see, stated so nobody reads more into a pass: factual poisoning with no instruction
// in it (PoisonedRAG's "Tim Cook became CEO of OpenAI" passage) carries no phrasing tell at all. The
// rag-misinfo-only family in test/redteam/poisoning-corpus.json exists to keep that miss on the record.
import { skillSurfaceKind } from "./skill-surface.js";

const MAX = 64_000;
const cap = (s) => (typeof s === "string" ? (s.length > MAX ? s.slice(0, MAX) : s) : "");

// ---- which paths are MEMORY ----
// The instruction-text subset of data/skill-surface.js: files whose prose is loaded into the model's
// context as standing instructions. The JSON/TOML config kinds (settings, MCP configs, hooks) are left
// out on purpose: what is dangerous there is a hook command or a server entry, which other detectors
// own, not a sentence.
const MEMORY_KINDS = new Set([
  "claude-memory", "CLAUDE.md", "CLAUDE.local.md", "claude-rule",
  "AGENTS.md", "AGENTS.override.md", "GEMINI.md",
  ".cursorrules", ".cursor/rules", ".windsurfrules", "windsurf-rule", "windsurf-global",
  ".clinerules", "cline-rule", "copilot-instructions", "copilot-path-instructions",
  "kiro-steering", "kiro-spec",
  "claude-skill", "claude-agent", "claude-command", "plugin-agent",
  "cursor-command", "windsurf-workflow", "cline-workflow", "copilot-prompt", "copilot-agent",
  "codex-prompt", "gemini-command", "opencode-command", "opencode-agent"
]);
export const MEMORY_SURFACE_KINDS = [...MEMORY_KINDS];
export function memoryKind(path) {
  const k = skillSurfaceKind(path);
  return k && MEMORY_KINDS.has(k) ? k : null;
}

// ---- shell writes into a memory path ----
// echo / printf / cat-heredoc with `>` or `>>`, `tee [-a]`, and PowerShell Add-Content / Set-Content /
// Out-File. Best-effort and bounded: the target is any redirect or tee operand; the written text is the
// quoted literals and heredoc bodies of the command (plus unquoted echo arguments), because the
// command's own syntax and any other file it names are not being written into memory.
// Not covered: interpreters writing the file themselves (python -c "open(...).write(...)"), and writes
// through a variable or command substitution whose value is not in the command text.
const unq = (t) => t.replace(/^(["'])([\s\S]*)\1$/, "$2");
const TARGETS = [
  /(?:^|[^<>&\d])>>?\|?\s{0,4}("[^"\n]{1,400}"|'[^'\n]{1,400}'|[^\s;&|<>()]{1,400})/g,
  /\btee\b(?:\s{1,4}-{1,2}[a-z-]{1,20}){0,3}\s{1,4}("[^"\n]{1,400}"|'[^'\n]{1,400}'|[^\s;&|<>()]{1,400})/gi,
  /\b(?:Add-Content|Set-Content|Out-File)\b[^\n;|]{0,200}?-(?:Path|FilePath|LiteralPath)\s{1,4}("[^"\n]{1,400}"|'[^'\n]{1,400}'|[^\s;&|<>()]{1,400})/gi
];
function heredocBodies(cmd) {
  const out = [];
  const re = /<<-?\s{0,4}(["']?)([A-Za-z_][\w-]{0,30})\1[^\n]{0,400}\n/g;
  let m;
  while ((m = re.exec(cmd)) !== null) {
    const start = m.index + m[0].length;
    const lines = cmd.slice(start).split("\n");
    const end = lines.findIndex((l) => l.trim() === m[2]);
    out.push((end < 0 ? lines : lines.slice(0, end)).join("\n"));
  }
  return out;
}
export function shellMemoryWrites(command) {
  const cmd = cap(command);
  if (!cmd || !/>|\btee\b|-Content\b|Out-File\b/i.test(cmd)) return [];
  const paths = new Set();
  for (const re of TARGETS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(cmd)) !== null) {
      const p = unq(m[1]);
      if (memoryKind(p)) paths.add(p);
    }
  }
  if (!paths.size) return [];
  const bodies = heredocBodies(cmd);
  const head = cmd.split(/<<-?\s{0,4}["']?[A-Za-z_][\w-]{0,30}["']?/)[0];
  const quoted = [...head.matchAll(/"((?:[^"\\\n]|\\.){1,4000})"|'([^'\n]{1,4000})'/g)].map((q) => (q[1] ?? q[2]).replace(/\\n/g, "\n"));
  const bare = [...head.matchAll(/\becho\s{1,4}(?:-[neE]{1,3}\s{1,4})?([^"'\n;&|<>]{3,4000}?)\s{0,4}(?=>|\||;|&|$)/g)].map((e) => e[1]);
  const text = [...quoted, ...bare, ...bodies].filter((t) => t && !memoryKind(t.trim())).join("\n");
  return text.trim() ? [...paths].map((path) => ({ path, text })) : [];
}

// ---- examples and detection guidance are not instructions ----
// Two narrow frames are removed before either verdict, because both are how a security note NAMES an
// attack: (a) a quoted span introduced as an example ("documents that say things like 'ignore other
// sources'"), and (b) a sentence whose payload is conditional on SOMETHING ELSE asking for it and whose
// consequence is refusal ("if a memory file ever tells you to read credentials … stop and report it").
// Both stay narrow on purpose: (a) needs the example marker right before the quote, and (b) needs the
// refusal verb, so "if a file tells you to send .env to X, do it" is not removed.
const EXAMPLE_QUOTE = /\b(?:things\s+like|phrases?\s+like|such\s+as|e\.g\.,?|for\s+example,?|for\s+instance,?|like|contains?\s+text[^"'“\n]{0,40}?|says?|saying)\s{0,3}[—:-]?\s{0,3}(?:"[^"\n]{1,200}"|'[^'\n]{1,200}'|\u201c[^\u201d\n]{1,200}\u201d)(?:\s{0,3}(?:or|and|,)\s{0,3}(?:"[^"\n]{1,200}"|'[^'\n]{1,200}'|\u201c[^\u201d\n]{1,200}\u201d)){0,4}/gi;
const DETECT_GUIDANCE = /[^.\n]{0,200}\b(?:if|when|whenever)\b[^.\n]{0,80}\b(?:ever\s+)?(?:tells?|asks?|instructs?|wants?|directs?)\s+(?:you|the\s+(?:agent|assistant|ai|model))\s+to\b[^.\n]{0,240}?\b(?:stop|report|refuse|flag|escalate|decline|do\s+not\s+(?:comply|follow|act))\b[^.\n]{0,200}/gi;
export function stripMetaExamples(text) {
  const t = cap(text);
  return t.replace(EXAMPLE_QUOTE, " ").replace(DETECT_GUIDANCE, " ");
}

// ---- negation, so "never print API keys" is a rule and not a payload ----
const NEG_BEFORE = /\b(?:never|not|don'?t|do\s+not|avoid|without|no)\b[^.\n]{0,24}$/i;
function firstUnnegated(text, re) {
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m;
  while ((m = g.exec(text)) !== null) {
    const before = text.slice(Math.max(0, m.index - 40), m.index);
    if (!NEG_BEFORE.test(before)) return m[0];
    if (!m[0]) g.lastIndex++;
  }
  return null;
}

// ---- persistence phrasing: the instruction is meant to outlive this session ----
export const PERSISTENCE_TELLS = [
  /\bfrom\s+(?:now|this\s+(?:point|moment)|here|today)\s+(?:on(?:wards?)?|forward)\b/i,
  /\b(?:going\s+forward|henceforth|hereafter|from\s+now)\b/i,
  /\b(?:in|for|during|across)\s+(?:all|every|each|any)\s+(?:future|subsequent|later|new|upcoming)\s+(?:sessions?|conversations?|chats?|tasks?|runs?|interactions?|repl(?:y|ies)|responses?)\b/i,
  /\b(?:in|for)\s+future\s+(?:sessions?|conversations?|chats?|interactions?)\b/i,
  /\bevery\s+future\s+(?:sessions?|conversations?|chats?|repl(?:y|ies)|responses?|interactions?)\b/i,
  /\b(?:at\s+the\s+(?:start|beginning|end)\s+of|after|before)\s+(?:every|each)\s+(?:session|conversation|chat|task|run)\b/i,
  /\bnext\s+time\s+(?:the\s+user|you|someone|anyone|they)\b/i,
  /\b(?:at|on)\s+(?:every\s+|each\s+)?session\s+start\b|^\s{0,4}[-*]?\s{0,2}session\s+start\s{0,2}:/im,
  /\b(?:remember|memori[sz]e|keep\s+in\s+mind)\s+(?:that|to|for)\b/i,
  /\b(?:standing|permanent|persistent)\s+(?:instruction|order|rule|directive|note)\b/i,
  /\bfor\s+the\s+rest\s+of\s+(?:this|the)\s+(?:project|session|repo|repository|conversation)\b/i,
  /\b(?:after|once|until)\s+\d{4}-\d{2}-\d{2}\b/i
];
export function persistenceTell(text) {
  const t = cap(text);
  for (const re of PERSISTENCE_TELLS) { const m = t.match(re); if (m) return m[0]; }
  return null;
}

// ---- payloads ----
// Tightened against real instruction files (CLAUDE.md, auto-memory notes, skills): those are dense
// technical notes full of URLs, e-mail addresses, "POST /upload", "curl … | sh" install lines and "tell
// the user to …", so a payload must name SENSITIVE data (not "files" or "the repo"), a concealment must
// hide something FROM a person (not tell them to do something), and fetch-and-run is only an attack in
// memory when the same text says it should persist.
const SENSITIVE = String.raw`(?:\.env\b|credentials?|secrets?|tokens?|api[\s_-]?keys?|passwords?|private\s+keys?|ssh\s+keys?|deploy[_\s]keys?|~\/\.ssh|id_rsa|id_ed25519|\.aws\b|cookies?|conversation(?:\s+history)?|chat\s+history|git\s+history|(?:full|entire|whole)\s+(?:conversation|repo(?:sitory)?|working\s+tree|codebase|history|chat)|contents\s+of|file\s+listing|source\s+code|card\s+numbers?|cvv|last\s+\w+\s+e-?mails|attendee\s+list)`;
const DEST = String.raw`(?:https?:\/\/|\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,63}\b|\bpastebin\b|\bngrok\b|\brequestbin\b|\bexternal\s+(?:server|endpoint|url|host|address)\b|\btelemetry\s+endpoint\b|\bsync\s+endpoint\b)`;
// Not a URL path segment ("POST /upload/<uid>", "api/send") and not an HTTP verb naming an endpoint.
const EXFIL_VERB = String.raw`(?<![\/\w.-])(?:send|forward|upload|transmit|exfiltrat\w*|leak|sync|copy|mirror|post|e-?mail|share|include|append)\b(?![\/.-]|\s{1,3}\/)`;
const PERSON = String.raw`(?:the\s+)?(?:user|developer|human|operator|reviewer|owner|anyone|admin|engineer|team)\b`;
const SENSITIVE_OBJ = String.raw`(?:keys?|credentials?|tokens?|secrets?|alerts?|warnings?|audit|logs?|\.env|ssh|passwords?|hooks?|guard|security|backdoor|data)`;
// STRONG: an attack wherever it is written into memory, with or without persistence phrasing.
const STRONG = {
  exfil: [
    new RegExp(`${EXFIL_VERB}[^\\n]{0,120}?${SENSITIVE}[^\\n]{0,120}?${DEST}`, "i"),
    /!\[[^\]\n]{0,80}\]\(\s{0,4}https?:\/\/[^)\s]{0,200}\?[^)\s]{0,200}(?:conversation|summary|history|question|e-?mail|secret|token|SUMMARY|QUESTION|USER)/i
  ],
  conceal: [
    new RegExp(String.raw`\b(?:do\s+not|don'?t|never|without)\s+(?:ever\s+)?(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|notify(?:ing)?|alert(?:ing)?|disclos(?:e|ing)|reveal(?:ing)?|report(?:ing)?|point(?:ing)?\s+(?:it|this|that)\s+out\s+to)\b[^.\n]{0,40}?\b${PERSON}(?!\s{1,3}(?:to|how|about\s+how)\b)`, "i"),
    /\b(?:do\s+not|don'?t|never)\s+(?:mention|disclose|reveal|report)\s+(?:that\s+you\b|this\s+(?:step|note|instruction|upload|change|rule)\b|the\s+(?:upload|step|deviation|pre-?approval|change)\b)/i,
    /\bkeep\s+(?:this|it)\s+(?:note\s+)?(?:to\s+yourself|secret|hidden|out\s+of\s+(?:the\s+)?(?:commit|summary|summaries|log|report|pr|pull\s+request|commit\s+messages?))\b/i,
    /\bkeep\s+this\s+out\s+of\b/i,
    /\b(?:secretly|covertly)\s+\w+/i,
    new RegExp(String.raw`\b(?:silently|quietly)\s+(?:send|upload|forward|exfiltrat\w*|dismiss|disable|copy|add|delete|push|remove)\b[^.\n]{0,60}?${SENSITIVE_OBJ}`, "i")
  ],
  override: [
    // The qualifier must sit right before the rules-noun, the precision rule inj-override-structural keeps:
    // "ignore the previous FORMATTING instructions" is a style note, not an override.
    /\b(?:ignore|disregard|forget|override|bypass)\s{1,3}(?:(?:the|all|any|of|your|my)\s{1,3}){0,2}(?:(?:previous|prior|earlier|above|system|operator'?s?|safety|developer|original|existing)\s{1,3}){1,3}(?:instructions?|rules?|guidelines?|prompts?|polic(?:y|ies)|restrictions?)\b(?!\s{1,3}(?:found\s+|contained\s+|embedded\s+|that\s+appear\s+|appearing\s+)?(?:in|inside|within|from)\b)/i
  ]
};
// CONDITIONAL: ordinary in a memory file on their own ("read DATABASE_URL from .env", an install line
// "curl … | sh"), an attack when the same text also says the instruction is meant to persist / fire on a
// later trigger.
const CONDITIONAL = {
  exfil: [
    new RegExp(`${EXFIL_VERB}[^\\n]{0,80}?\\b(?:its|their|the|all|every|any)?\\s{0,3}(?:contents?|files?|repo(?:sitory)?|code|listing|data|history)\\b[^\\n]{0,80}?(?:https?:\\/\\/|\\b[\\w.+-]{1,64}@[\\w-]{1,63}\\.[\\w.-]{2,63}\\b)`, "i")
  ],
  secret: [
    /\b(?:read|cat|open|print|include|paste|attach|copy|dump|output|show|display|log|place)\b[^.\n]{0,60}(?:\.env\b|~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|credentials\s+file|\.netrc|hosts\.yml|\.npmrc|private\s+keys?|deploy[_\s]key|api\s+keys?\s+and\s+tokens|api\s+keys?\s+in\s+full)/i
  ],
  exec: [
    /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,200}\|\s{0,4}(?:sudo\s+)?(?:ba|z|da)?sh\b/i,
    /\bdownload(?:ed)?\s+(?:and\s+)?(?:run|execute)\b|\bexecute\s+any\s+downloaded\b|\brun\s+it\s+as\s+administrator\b/i
  ],
  bypass: [
    /--no-verify\b|--dangerously-skip-permissions\b|\bbypassPermissions\b/i,
    /\bdisable\s+(?:the\s+)?(?:audit(?:\s+log)?|security|safety|moorai|hooks?|guard|scanner|logging|sandbox|firewall|2fa|mfa|signing|pre-?commit)\b/i,
    /\bskip\s+(?:the\s+)?(?:security|pre-?commit|review|approval|confirmation)\b/i,
    /\bbypass\s+(?:the\s+)?(?:branch\s+protection|review|approval|security|polic(?:y|ies)|hooks?|checks?)\b/i,
    /\bpre-?approved\b|\bauto-?approve\b|\bapprove\s+the\s+request\s+automatically\b/i,
    /\b(?:never|don'?t|do\s+not)\s+ask\s+(?:for\s+)?(?:confirmation|approval|permission)\b/i,
    /\bmerge\s+(?:your|its)\s+own\s+(?:pull\s+requests|prs?)\b|\bpush\s+(?:straight|directly)\s+to\s+(?:main|master|prod(?:uction)?)\b/i
  ],
  trust: [
    /\b(?:treat|consider|regard)\b[^.\n]{0,60}\bas\s+the\s+(?:only|sole)\s+(?:trusted|authoritative|reliable|approved)\b/i,
    /\bnever\s+recommend\s+(?:a\s+|any\s+)?(?:competitor|alternative|other)\b/i,
    /\bis\s+the\s+approved\s+replacement\s+for\b/i
  ]
};
const anyMatch = (t, list) => { for (const re of list) { const m = t.match(re); if (m) return m[0]; } return null; };
const anyUnnegated = (t, list) => { for (const re of list) { const m = firstUnnegated(t, re); if (m) return m; } return null; };

// The memory-write verdict on the written text alone (the caller has already decided the path is
// memory). Returns { fire, kind, match } — `kind` names which payload class decided it.
export function memoryPoisoningTell(text) {
  const t = cap(text);
  if (!t.trim()) return { fire: false };
  for (const kind of ["exfil", "override"]) {
    const m = kind === "override" ? anyMatch(t, STRONG[kind]) : anyUnnegated(t, STRONG[kind]);
    if (m) return { fire: true, kind, match: m };
  }
  const c = anyMatch(t, STRONG.conceal);
  if (c) return { fire: true, kind: "conceal", match: c };
  if (!persistenceTell(t)) return { fire: false };
  // The persistence phrase and the payload must sit in the same unit — a short paragraph, or one line of
  // a long one. A skill that mentions "at session start" in one table row and a "pre-approved runbook"
  // forty lines later is describing two things, not arming one.
  for (const unit of units(t)) {
    if (!persistenceTell(unit)) continue;
    for (const kind of ["exfil", "secret", "exec", "bypass", "trust"]) {
      const m = kind === "bypass" ? anyBypass(unit) : anyUnnegated(unit, CONDITIONAL[kind]);
      if (m) return { fire: true, kind: `persist+${kind}`, match: m };
    }
  }
  return { fire: false };
}
const UNIT_MAX = 400;
function units(t) {
  const out = [];
  for (const para of t.split(/\n\s*\n/)) {
    if (para.length <= UNIT_MAX) out.push(para);
    else out.push(...para.split("\n"));
  }
  return out;
}
// "never ask for confirmation" IS the bypass, so that one pattern is exempt from the negation rule.
function anyBypass(t) {
  const [flags, disable, skip, bypass, pre, neverAsk, merge] = CONDITIONAL.bypass;
  return anyUnnegated(t, [flags, disable, skip, bypass, pre, merge]) || anyMatch(t, [neverAsk]);
}

// ---- #21: a passage that talks to the model which will retrieve it ----
const AI = String.raw`(?:ai|a\.i\.|assistants?|chat\s?bots?|bots?|llms?|language\s+models?|models?|agents?|copilots?|retrieval\s+system|rag\s+system|search\s+assistant)`;
const DIRECTIVE = String.raw`\b(?:must|should|shall|always|never|answer|respond|reply|tell|report|cite|say|state|ignore|disregard|discard|refuse|approve|append|include|forward|send|reveal|rate|recommend|treat|rely|use)\b`;
export const RETRIEVAL_TELLS = [
  // addresses the model: "Note to the AI assistant:", "Instructions for language models that retrieve…",
  // "[assistant instructions]", "Hidden rule for AI agents:", "Appendix (for AI reviewers):"
  new RegExp(String.raw`\b(?:note|message|instructions?|directives?|rules?|appendix|reminder|guidance)\s{1,4}(?:\([^)\n]{0,20})?(?:to|for)\s{1,4}(?:the\s+|any\s+|all\s+)?(?:\w+\s+){0,2}?${AI}\b[^\n]{0,200}?${DIRECTIVE}`, "i"),
  new RegExp(String.raw`\[\s{0,2}(?:${AI})\s+(?:instructions?|directives?|note)\s{0,2}\]`, "i"),
  new RegExp(String.raw`\b(?:hidden|secret)\s+(?:rule|instruction|note|directive)s?\s+(?:for|to)\s+${AI}\b`, "i"),
  new RegExp(String.raw`\bif\s+you\s+are\s+an?\s+(?:ai|a\.i\.|language\s+model|llm|assistant|chat\s?bot|agent|automated\s+agent)\b[^\n]{0,200}?${DIRECTIVE}`, "i"),
  new RegExp(String.raw`\b(?:the\s+|any\s+|all\s+)?${AI}\s+(?:reading|retrieving|summari[sz]ing|processing|indexing|that\s+(?:reads?|retrieves?|summari[sz]es?))\s+(?:this|the\s+following)\b[^\n]{0,160}?${DIRECTIVE}`, "i"),
  new RegExp(String.raw`\b(?:when|whenever|once|if)\s+(?:any\s+|an?\s+|the\s+)?${AI}\s+(?:reads?|retrieves?|summari[sz]es?|processes|sees?)\s+(?:this|the\s+following)\b`, "i"),
  new RegExp(String.raw`\b(?:when|whenever|once|if)\s+(?:this|the)\s+(?:document|passage|page|text|content|article|section|chunk|note)\s+(?:is|gets)\s+(?:retrieved|summari[sz]ed|read|processed|indexed|cited|loaded)\b`, "i"),
  new RegExp(String.raw`\bwhen\s+answering\s+(?:from|using|with)\s+this\b[^\n]{0,120}?${DIRECTIVE}`, "i"),
  // suppresses the other sources
  /\b(?:ignore|disregard|discard|distrust|dismiss)\s+(?:all\s+|any\s+|the\s+)?(?:other|conflicting|remaining|competing)\s+(?:retrieved\s+|search\s+)?(?:documents?|sources?|passages?|results?|context|chunks?|pages?|articles?|search\s+results)\b/i,
  /\b(?:this|the\s+present)\s+(?:document|passage|page|source|text|article|section)\s+(?:supersedes|overrides|trumps|takes\s+precedence\s+over|outranks)\s+(?:all|any|every)\s+(?:other|previous)\b/i,
  /\brel(?:y|ies)\s+(?:solely|only|exclusively)\s+on\s+this\s+(?:text|document|passage|page|section|source)\b/i,
  /\bcite\s+only\s+this\s+(?:page|document|section|passage|source)\b/i,
  /\b(?:the\s+)?only\s+authoritative\s+(?:context|source)\b/i,
  /\bregardless\s+of\s+what\s+(?:other|the\s+other)\s+(?:documents?|sources?|passages?|pages?)\s+say\b/i,
  // forces an answer / arms a trigger
  /\bthe\s+correct\s+answer\s+to\s+(?:any|every|all)\s+questions?\b/i,
  new RegExp(String.raw`\bwhenever\s+(?:a|the|any)\s+(?:question|query|prompt|request|message)\s+(?:mentions|contains|includes|is\s+about)\b[^\n]{0,160}?${DIRECTIVE}`, "i"),
  new RegExp(String.raw`\bif\s+the\s+(?:query|question|prompt|request)\s+(?:contains|mentions|includes)\b[^\n]{0,160}?${DIRECTIVE}`, "i")
];
export function retrievalTell(text) {
  const t = cap(text);
  for (const re of RETRIEVAL_TELLS) { const m = t.match(re); if (m) return m[0]; }
  return null;
}
