// destructive-command (#43) on a turn of prose: a command that is discussed, not issued.
//
// Engine stage "prompt" carries two kinds of text: a command about to run (a Bash call, a model's tool-call
// arguments) and a turn of prose (a person's or a third party's message to a model). A prose turn executes
// nothing; whatever the model runs because of it comes back as a tool call and is judged as a command. So on
// text the caller marks as prose (ctx.prose, set only by the model proxy's user and system turns, the hook's
// scanned UserPromptSubmit and the agent SDK's prompt scan), #43 stands down when the turn only DISCUSSES the
// command: every #43 match sits in a sentence framed as a question, an explanation, a comparison or a
// warning, and no sentence anywhere in the turn asks for something to run. Every other caller, and prose
// that does not meet both conditions, keeps today's verdict. The frame is read per sentence, so a command on
// its own line or in a fenced block under a question is still a command.
//
// Pure, bounded and content-free: a boolean, nothing quoted. Longer prose than MAX is judged as today.

const MAX = 16000;

// Sentence ends: . ! ? followed by whitespace, or a line break. A dot inside a path or a flag (`./build`,
// `mkfs.ext4`) is not followed by whitespace and does not split.
const BOUNDARY = /[.!?](?=\s)|\n/g;

// Leading list marks, quotes and markdown a sentence may start with.
const LEAD = /^[\s>*#\-–—"'`(\[]*(?:\d{1,3}[.)]\s*)?/;

// Words that may precede the frame or the verb without changing what the sentence asks.
const FILLER = String.raw`(?:(?:so|and|but|ok|okay|hey|hi|please|pls|kindly|now|then|just|also|next|first|finally|afterwards|quickly)[\s,]{1,4}){0,3}`;

const VERBS = String.raw`(?:run|execute|exec|launch|invoke|type|paste|enter|issue|perform|apply|do|try|use|wipe|delete|remove|drop|erase|format|nuke|clean|clear|purge|force-push|push|reset|truncate|destroy)`;
// At the start of a sentence a SQL statement is the command itself, not an English imperative: `DROP TABLE x;
// — is that safe?` asks about it. Everywhere else ("can you drop table x") the verb counts.
const START_VERBS = String.raw`(?:run|execute|exec|launch|invoke|type|paste|enter|issue|perform|apply|do|try|use|wipe|delete(?!\s{1,4}from\b)|remove|drop(?!\s{1,4}(?:table|database|schema)\b)|erase|format|nuke|clean|clear|purge|force-push|push|reset|truncate(?!\s{1,4}table\b)|destroy)`;

// A sentence that asks about, explains or compares something.
const OPENER = new RegExp(String.raw`^${FILLER}(?:why|what|what's|whats|how|when|where|which|who|whether|is|are|was|were|isn't|does|did|doesn't|should|shouldn't|would|could|can|will|explain|describe|compare|contrast|define|summari[sz]e|clarify|tell me (?:about|what|why|how|whether|if)|help me understand|walk me through|i(?:'d| would) like to (?:understand|know)|i (?:want|need) to (?:understand|know)|i'm (?:curious|wondering)|i (?:wonder|was wondering)|difference between)\b`, "i");

// A question: ends in "?" and carries an interrogative word.
const QUESTION_END = /\?["'`)\s]*$/;
const QUESTION_WORD = /\b(?:why|what|how|when|where|which|whether|is|are|was|were|does|do|did|should|would|could|can|will)\b/i;

// A warning against running it.
const WARNING = /\b(?:never|don't|dont|do not|avoid|shouldn't|should not|must not|mustn't)\s{1,4}(?:ever\s{1,4})?(?:run|running|execute|executing|use|using|type|typing|issue|issuing)\b|^(?:warning|caution|careful|be careful)\b/i;

// A request for something to run, anywhere in the turn.
const RUN_REQUEST = [
  new RegExp(String.raw`^${FILLER}(?:go ahead(?: and)?\s{1,4})?${START_VERBS}\b`, "i"),
  new RegExp(String.raw`\b(?:can|could|would|will)\s{1,4}(?:you|u)\s{1,4}(?:please\s{1,4}|kindly\s{1,4}|just\s{1,4}|now\s{1,4}|also\s{1,4})?${VERBS}\b`, "i"),
  new RegExp(String.raw`\b(?:please|pls|kindly)\s{1,4}(?:[a-z]{1,12}\s{1,4})?${VERBS}\b`, "i"),
  new RegExp(String.raw`\b(?:you|u)\s{1,4}(?:should|must|need to|have to|can|may)\s{1,4}(?:now\s{1,4}|just\s{1,4}|also\s{1,4}|then\s{1,4})?(?:run|execute|type|paste|use)\b`, "i"),
  /\bgo ahead\b/i,
  /\b(?:run|execute|exec|type|paste|enter|do|try|issue)\s{1,4}(?:it|this|that|them|these|those|the (?:command|commands|query|script))\b/i
];

function sentences(text) {
  const out = [];
  let start = 0;
  BOUNDARY.lastIndex = 0;
  let m;
  while ((m = BOUNDARY.exec(text)) !== null) {
    const end = m.index + m[0].length;
    out.push([start, end]);
    start = end;
  }
  if (start < text.length) out.push([start, text.length]);
  return out;
}

const clean = (s) => s.replace(LEAD, "").trim();

function framedAsMention(s) {
  if (OPENER.test(s) || WARNING.test(s)) return true;
  return QUESTION_END.test(s) && QUESTION_WORD.test(s);
}

const globals = new WeakMap();
function globalOf(p) {
  let g = globals.get(p);
  if (!g) { g = new RegExp(p.source, p.flags.includes("g") ? p.flags : p.flags + "g"); globals.set(p, g); }
  return g;
}

// True when `text` only discusses the commands `patterns` match: at least one match, every match inside a
// mention-framed sentence, and no run request in any sentence.
export function mentionOnly(text, patterns) {
  if (typeof text !== "string" || !text || text.length > MAX) return false;
  const spans = sentences(text);
  const body = spans.map(([a, b]) => clean(text.slice(a, b)));
  if (body.some((s) => RUN_REQUEST.some((r) => r.test(s)))) return false;
  const framed = body.map(framedAsMention);
  let seen = 0;
  for (const p of patterns) {
    const g = globalOf(p);
    g.lastIndex = 0;
    let m;
    while ((m = g.exec(text)) !== null) {
      seen++;
      const i = spans.findIndex(([a, b]) => m.index >= a && m.index < b);
      if (i < 0 || !framed[i]) return false;
      if (!m[0]) g.lastIndex++;
    }
  }
  return seen > 0;
}

// detector gate: true keeps the finding. Only prose can stand down.
export function destructiveIssued(text, ctx, patterns) {
  return !(ctx && ctx.prose === true && mentionOnly(text, patterns));
}
