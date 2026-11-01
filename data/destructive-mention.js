// destructive-command (#43) on a turn of prose: a command that is discussed, not issued.
//
// Engine stage "prompt" carries two kinds of text: a command about to run (a Bash call, a model's tool-call
// arguments) and a turn of prose (a person's message to a model). A prose turn executes nothing; whatever
// the model runs because of it comes back as a tool call and is judged as a command. So on text the caller
// marks as prose (ctx.prose: the model proxy's user turns, the hook's UserPromptSubmit when the prompt is a
// person's, the agent SDK's prompt scan for a person's prompt) #43 stands down only on positive evidence
// that the turn DISCUSSES the command:
//   - every sentence of the turn is framed as a question, an explanation, a comparison or a warning;
//   - every sentence a match touches is one of those, judged both on the whole-text span (rescanning from
//     each match's start + 1, so an overlapping later match is not hidden) and on each sentence on its own;
//   - nothing in the turn asks for an action: no second-person ask ("could you …", "would you mind …",
//     "what happens if you run …"), no "for me" / "show me" / "let me", no first-person plan to run it, no
//     reference back to the command ("that way", "do it", "with it"), no imperative opening.
// Anything short of that, and every caller that does not mark prose, keeps today's verdict. Machine-injected
// and third-party text (an event-triggered prompt, a system turn, a tool result) is never marked prose.
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

// The only things "you" may be asked to do on a mention: explain. Any other "you" is an ask.
const EXPLAIN_AFTER_YOU = String.raw`(?:please\s{1,4}|just\s{1,4}|kindly\s{1,4}|briefly\s{1,4})?(?:explain|describe|tell me (?:about|what|why|how|whether|if)|clarify|compare|summari[sz]e|define|outline|walk me through|help me understand)\b`;

// A request for an action, anywhere in the turn.
const REQUEST = [
  new RegExp(String.raw`^${FILLER}(?:go ahead(?: and)?\s{1,4})?${START_VERBS}\b`, "i"),
  new RegExp(String.raw`\b(?:you|u|ya)\b(?!\s{1,4}${EXPLAIN_AFTER_YOU})`, "i"),
  new RegExp(String.raw`\b(?:please|pls|kindly)\s{1,4}(?:[a-z]{1,12}\s{1,4})?${VERBS}\b`, "i"),
  /\b(?:for me|show me|give me|let me|let's|lets|mind|help me(?!\s{1,4}understand\b)|demonstrate|demo)\b/i,
  /\bi(?:'m| am)?\s{1,4}(?:want|need|plan|intend|going|gonna|about|will|'ll|ll)\s{1,4}(?:to\s{1,4})?(?:run|execute|use|try|type|paste|do|apply|issue)\b/i,
  /\bi'll\s{1,4}(?:run|execute|use|try|type|paste|do|apply|issue)\b/i,
  /\bgo ahead\b/i,
  /\b(?:run|execute|exec|type|paste|enter|do|doing|try|use|issue)\s{1,4}(?:it|this|that|them|these|those|the (?:command|commands|query|script))\b/i,
  /\b(?:that way|this way|like that|like this|with it|with that|with this|on it|same way)\b/i
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

// Every whole-text match, rescanning from each match's start + 1: every sentence its span touches must be
// framed. Returns -1 for a violation, else the number of matches.
function spanCheck(text, spans, framed, patterns) {
  let seen = 0;
  for (const p of patterns) {
    const g = globalOf(p);
    g.lastIndex = 0;
    let m;
    while ((m = g.exec(text)) !== null) {
      seen++;
      const a = m.index, b = m.index + Math.max(m[0].length, 1);
      for (let i = 0; i < spans.length; i++) if (spans[i][0] < b && spans[i][1] > a && !framed[i]) return -1;
      g.lastIndex = m.index + 1;
    }
  }
  return seen;
}

// Each sentence on its own: a sentence any pattern matches must be framed.
function sliceCheck(text, spans, framed, patterns) {
  for (let i = 0; i < spans.length; i++) {
    if (framed[i]) continue;
    const slice = text.slice(spans[i][0], spans[i][1]);
    if (patterns.some((p) => { const g = globalOf(p); g.lastIndex = 0; return g.test(slice); })) return false;
  }
  return true;
}

// True when `text` only discusses the commands `patterns` match (see the header). Fails closed: false keeps
// the finding.
export function mentionOnly(text, patterns) {
  if (typeof text !== "string" || !text || text.length > MAX) return false;
  const spans = sentences(text);
  const body = spans.map(([a, b]) => clean(text.slice(a, b)));
  if (body.some((s) => REQUEST.some((r) => r.test(s)))) return false;
  const framed = body.map((s) => !s || framedAsMention(s));
  if (framed.some((f) => !f)) return false;
  if (!sliceCheck(text, spans, framed, patterns)) return false;
  return spanCheck(text, spans, framed, patterns) > 0;
}

// detector gate: true keeps the finding. Only prose can stand down.
export function destructiveIssued(text, ctx, patterns) {
  return !(ctx && ctx.prose === true && mentionOnly(text, patterns));
}
