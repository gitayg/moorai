// Model/agent text is DATA, never instructions — every input here is treated as hostile bytes to be
// neutralized before it is displayed or parsed.
//
// The on-device logs this CLI replays are written from agent/model output. A hostile agent can seed
// those rows with ANSI escapes (to rewrite the terminal, hide lines, or spoof a clean trace), with
// zero-width / bidi-control Unicode (to make a tool name read as another, or reverse a hash), or with
// a malformed / gigantic JSONL line (to crash or hang the parser). None of that is content — it is an
// anti-analysis payload riding on metadata. Everything below strips or bounds it and NEVER throws, so
// a poisoned line degrades to a visible gap instead of breaking the trace.
//
// ReDoS discipline: every regex over untrusted input is a single global character-class replace or a
// flat alternation of linear parts — no nested quantifiers, no catastrophic backtracking — and the
// display path length-caps its input BEFORE any regex runs.

// ANSI/CSI/OSC escape sequences. Flat alternation, each branch linear:
//   \x1b[ … final          CSI (colours, cursor moves): params are digits/;/:/?, one final byte
//   \x1b] … BEL|ST         OSC (window title, hyperlinks): body is anything up to the terminator
//   \x1b[@-_]              two-byte escapes (e.g. ESC c reset)
//   \x1b                   a lone, dangling escape
const ANSI_RE = /\x1b\[[0-9;:?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]|\x1b/g;

// Zero-width, invisible, bidi-control, and C0/C1 control chars (keeping only \n and \t). One flat
// character class → strictly linear. Covers U+00AD, U+180E, U+200B-200F, U+202A-202E, U+2060-2064,
// U+2066-2069, U+FEFF, plus C0 (except \t \n) and C1/DEL.
const INVISIBLE_RE = /[\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;

const DISPLAY_CAP = 2048;

export function stripAnsi(s) {
  return String(s == null ? "" : s).replace(ANSI_RE, "");
}

export function neutralizeInvisible(s) {
  return String(s == null ? "" : s).replace(INVISIBLE_RE, "");
}

export function sanitizeForDisplay(s) {
  try {
    let out = String(s == null ? "" : s);
    let truncated = false;
    if (out.length > DISPLAY_CAP) { out = out.slice(0, DISPLAY_CAP); truncated = true; }
    out = neutralizeInvisible(stripAnsi(out));
    return truncated ? out + "…[truncated]" : out;
  } catch {
    return "";
  }
}

export function boundedParseJsonl(text, opts = {}) {
  const maxBytes = opts.maxBytes ?? 8 * 1024 * 1024;
  const maxLines = opts.maxLines ?? 50000;
  const maxLineBytes = opts.maxLineBytes ?? 65536;
  const records = [];
  const gaps = [];
  let s = String(text == null ? "" : text);
  if (Buffer.byteLength(s, "utf8") > maxBytes) {
    s = s.slice(0, maxBytes);
    gaps.push({ type: "TRACE_GAP", reason: "input exceeded maxBytes", index: -1 });
  }
  const lines = s.split("\n");
  let kept = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    if (kept >= maxLines) { gaps.push({ type: "TRACE_GAP", reason: "exceeded maxLines", index: i }); break; }
    kept++;
    if (Buffer.byteLength(line, "utf8") > maxLineBytes) {
      gaps.push({ type: "TRACE_GAP", reason: "line exceeded maxLineBytes", index: i });
      continue;
    }
    try { records.push(JSON.parse(line)); }
    catch { gaps.push({ type: "TRACE_GAP", reason: "malformed JSON", index: i }); }
  }
  return { records, gaps };
}
