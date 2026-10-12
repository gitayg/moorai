// Strict JSON for what the model proxy decides on: a tool call's argument string, a response body, a stream
// event. The checker reads JSON with JSON.parse; the client that runs the call may use another parser. Where
// the two could read the same text as different values, the text has no one reading and is refused in enforce
// mode (reported in report mode). `strictProblem` names the first such condition, or null:
//
//   not-json        JSON.parse rejects it (NaN, Infinity, a comment, a trailing comma, single quotes …), and
//                   a lenient client (Python's json reads NaN and Infinity) may still read it
//   duplicate-key   an object repeats a key: JSON.parse keeps the last value, simdjson's find_field the
//                   first, serde / Gson maps / .NET dictionaries throw. Compared after unescaping
//                   ("\u0063ommand" is "command")
//   key-collision   two keys of an object that differ only in case, after a NUL, or by an unpaired surrogate:
//                   Go's encoding/json binds `{"command":"ls","Command":"rm -rf ~"}` to ONE field, the last
//                   key winning (measured: command = "rm -rf ~"), case-insensitive .NET binding does the
//                   same, Go turns every unpaired surrogate into U+FFFD, C-string parsers stop at a NUL
//   lone-surrogate  a string with an unpaired UTF-16 surrogate (\ud800 with no low half): JSON.parse and
//                   Python keep it, Go replaces it with U+FFFD, serde rejects it
//   too-deep        nesting past MAX_DEPTH (serde_json's own default limit is 128)
//   unsafe-number   an integer literal beyond ±(2^53 − 1), or a number that overflows to ±Infinity, in a field
//                   that decides which tool call a piece belongs to (STRUCTURAL: a stream's tool-call or
//                   content-block `index`, a choice or candidate `index`): a double parser and an integer
//                   parser read different values, so stream tool calls with indexes 2^53 and 2^53 + 1 are ONE
//                   call to JSON.parse and two to Python. Anywhere else (an argument value such as a numeric
//                   snowflake id) such a number is not a problem: no decision reads a number, and its source
//                   digits are returned in `large` so the content scan reads them as sent (check.mjs scanArgs)
//   invalid-utf8    (strictBytes only) bytes that are not UTF-8; Node reads U+FFFD, other decoders differ
//
// The scanner below is a full RFC 8259 recognizer of its own (it never trusts JSON.parse to have validated
// the text), linear in the length, iterative (no recursion, whatever the depth). It agrees with JSON.parse on
// what is valid JSON and on what every string and key decodes to: test/model-proxy-json-strict-fuzz.test.mjs
// checks both against each other on generated inputs.
export const MAX_DEPTH = 128;

export const PROBLEM_TEXT = Object.freeze({
  "not-json": "is not strict JSON (for example a non-finite number, a comment or a trailing comma)",
  "duplicate-key": "repeats a JSON key",
  "key-collision": "has JSON keys that differ only in case, a NUL or an unpaired surrogate",
  "lone-surrogate": "has a string with an unpaired surrogate",
  "too-deep": `nests deeper than ${MAX_DEPTH} levels`,
  "unsafe-number": "has a tool-call index beyond 2^53 or out of range",
  "invalid-utf8": "is not valid UTF-8"
});
const ARG_TEXT = Object.freeze({
  "duplicate-key": "repeat a key",
  "key-collision": "have keys that differ only in case, a NUL or an unpaired surrogate",
  "lone-surrogate": "have a string with an unpaired surrogate",
  "too-deep": `nest deeper than ${MAX_DEPTH} levels`
});
// The refusal reason for tool-call arguments with one of these problems ("not-json" keeps the checker's own
// "not a valid JSON object" reason).
export const argReason = (problem) => (ARG_TEXT[problem] ? `tool call arguments ${ARG_TEXT[problem]}, so a client may read a different value than the one checked` : undefined);
export const DUPLICATE_KEY_REASON = argReason("duplicate-key");

const LONE = /\p{Cs}/u; // with the u flag a surrogate pair is one code point; only an unpaired half matches
const SAFE = 9007199254740991;
// The paths (object keys joined with ".", an array element as "[]") whose number groups, orders or counts tool
// calls: OpenAI choices[].index and choices[].delta|message.tool_calls[].index; an Anthropic stream event's
// content-block `index` (at the root); Ollama message.tool_calls[].function.index; Gemini candidates[].index
// (a Gemini stream may be a JSON array of responses). Body and event scans only: an argument string has none.
export const STRUCTURAL = /^(?:\[\]\.?)?(?:index|choices\[\]\.index|choices\[\]\.(?:delta|message)\.tool_calls\[\]\.index|message\.tool_calls\[\]\.function\.index|candidates\[\]\.index)$/;
const MAX_LARGE = 256;
// The key two objects' keys collide on in a lenient client: cut at a NUL, unpaired surrogates as U+FFFD,
// then case-folded (toUpperCase first, so ſ → S → s and the Kelvin sign → k, as Go's fold orbit does).
const collisionKey = (k) => k.split("\0")[0].replace(/\p{Cs}/gu, "\uFFFD").toUpperCase().toLowerCase();
const isDigit = (c) => c >= 0x30 && c <= 0x39;
const isWs = (c) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
const HEX = (c) => (c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 55 : c >= 0x61 && c <= 0x66 ? c - 87 : -1);
const ESC = { 0x22: '"', 0x5c: "\\", 0x2f: "/", 0x62: "\b", 0x66: "\f", 0x6e: "\n", 0x72: "\r", 0x74: "\t" };

// { valid, problem, problems, value? }. `valid` is exactly whether JSON.parse accepts `text`; `problem` is the first
// condition above (always "not-json" when not valid), `problems` all of them. With `build` the value is constructed (repeated keys:
// last wins, as JSON.parse) so a test can compare it with JSON.parse's.
export function strictScan(text, { build = false, structural = null } = {}) {
  const s = String(text);
  const n = s.length;
  let i = 0, problem = null;
  const problems = new Set(), large = [];
  const flag = (p) => { problems.add(p); if (!problem) problem = p; };
  const fail = () => ({ valid: false, problem: "not-json", problems: new Set(["not-json"]), large: [] });
  const ws = () => { while (i < n && isWs(s.charCodeAt(i))) i++; };

  // A string at s[i] === '"': its decoded value, or null when it is not a valid JSON string.
  function str() {
    i++;
    let out = "", from = i;
    for (;;) {
      if (i >= n) return null;
      const c = s.charCodeAt(i);
      if (c === 0x22) { out += s.slice(from, i); i++; break; }
      if (c < 0x20) return null;
      if (c !== 0x5c) { i++; continue; }
      out += s.slice(from, i);
      const e = s.charCodeAt(i + 1);
      if (e === 0x75) {
        if (i + 6 > n) return null;
        let v = 0;
        for (let k = 2; k < 6; k++) { const h = HEX(s.charCodeAt(i + k)); if (h < 0) return null; v = v * 16 + h; }
        out += String.fromCharCode(v);
        i += 6;
      } else if (ESC[e] !== undefined) { out += ESC[e]; i += 2; }
      else return null;
      from = i;
    }
    if (LONE.test(out)) flag("lone-surrogate");
    return out;
  }

  // A number at s[i]: its value, or undefined when it is not a valid JSON number.
  function num() {
    const start = i;
    if (s.charCodeAt(i) === 0x2d) i++;
    if (i >= n || !isDigit(s.charCodeAt(i))) return undefined;
    if (s.charCodeAt(i) === 0x30) i++;
    else while (i < n && isDigit(s.charCodeAt(i))) i++;
    let integer = true;
    if (s.charCodeAt(i) === 0x2e) {
      integer = false; i++;
      if (i >= n || !isDigit(s.charCodeAt(i))) return undefined;
      while (i < n && isDigit(s.charCodeAt(i))) i++;
    }
    const e = s.charCodeAt(i);
    if (e === 0x65 || e === 0x45) {
      integer = false; i++;
      const sg = s.charCodeAt(i);
      if (sg === 0x2b || sg === 0x2d) i++;
      if (i >= n || !isDigit(s.charCodeAt(i))) return undefined;
      while (i < n && isDigit(s.charCodeAt(i))) i++;
    }
    const v = Number(s.slice(start, i));
    if (!Number.isFinite(v) || (integer && Math.abs(v) > SAFE)) {
      if (structural && structural.test(pathOf())) flag("unsafe-number");
      else if (large.length < MAX_LARGE) large.push(s.slice(start, i));
    }
    return v;
  }

  // Containers on an explicit stack: { obj, keys, folded, arr, key }.
  const stack = [];
  const pathOf = () => { let p = ""; for (const f of stack) p += f.isArr ? "[]" : `${p ? "." : ""}${f.key}`; return p; };
  let result;
  ws();
  for (;;) {
    // ---- a value ----
    if (i >= n) return fail();
    const c = s.charCodeAt(i);
    let v, open = false;
    if (c === 0x7b || c === 0x5b) {
      i++;
      if (stack.length + 1 > MAX_DEPTH) flag("too-deep");
      const frame = c === 0x7b ? { isArr: false, obj: build ? {} : null, keys: new Set(), folded: new Set(), key: null } : { isArr: true, arr: build ? [] : null };
      stack.push(frame);
      ws();
      const close = s.charCodeAt(i);
      if (c === 0x7b && close === 0x7d) { i++; stack.pop(); v = build ? frame.obj : undefined; }
      else if (c === 0x5b && close === 0x5d) { i++; stack.pop(); v = build ? frame.arr : undefined; }
      else open = true;
    } else if (c === 0x22) {
      v = str();
      if (v === null) return fail();
    } else if (c === 0x2d || isDigit(c)) {
      v = num();
      if (v === undefined) return fail();
    } else if (s.startsWith("true", i)) { v = true; i += 4; }
    else if (s.startsWith("false", i)) { v = false; i += 5; }
    else if (s.startsWith("null", i)) { v = null; i += 4; }
    else return fail();

    if (open) {
      const top = stack[stack.length - 1];
      if (!top.isArr) {
        // first key of a new object
        if (s.charCodeAt(i) !== 0x22) return fail();
        if (!readKey(top)) return fail();
      }
      ws();
      continue;
    }

    // ---- after a complete value: attach it, then a separator or a close ----
    for (;;) {
      const top = stack[stack.length - 1];
      if (!top) { result = v; ws(); return i === n ? { valid: true, problem, problems, large, ...(build ? { value: result } : {}) } : fail(); }
      if (build) {
        if (top.isArr) top.arr.push(v);
        else Object.defineProperty(top.obj, top.key, { value: v, writable: true, enumerable: true, configurable: true });
      }
      ws();
      const d = s.charCodeAt(i);
      if (d === 0x2c) {
        i++; ws();
        if (!top.isArr) { if (s.charCodeAt(i) !== 0x22 || !readKey(top)) return fail(); ws(); }
        break;
      }
      if ((top.isArr && d === 0x5d) || (!top.isArr && d === 0x7d)) {
        i++;
        stack.pop();
        v = build ? (top.isArr ? top.arr : top.obj) : undefined;
        continue;
      }
      return fail();
    }
  }

  // A key at s[i] === '"' and its colon; records repeats and collisions. False when not valid JSON.
  function readKey(top) {
    const k = str();
    if (k === null) return false;
    if (top.keys.has(k)) flag("duplicate-key");
    else {
      const f = collisionKey(k);
      if (top.folded.has(f)) flag("key-collision");
      top.folded.add(f);
      top.keys.add(k);
    }
    top.key = k;
    ws();
    if (s.charCodeAt(i) !== 0x3a) return false;
    i++;
    ws();
    return true;
  }
}

// The first problem of `text` (a string), or null.
export const strictProblem = (text, opts) => strictScan(text, opts).problem;

// Bytes as received (a body, an SSE event's data bytes, an NDJSON line): { problem, large } — the first
// problem or null (index fields are STRUCTURAL here), and the source digits of every other unsafe number.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export function strictBytes(buf, text) {
  try { UTF8.decode(buf); } catch { return { problem: "invalid-utf8", large: [] }; }
  const r = strictScan(text === undefined ? Buffer.from(buf).toString("utf8") : text, { structural: STRUCTURAL });
  return { problem: r.problem, large: r.large };
}

// Kept for callers that ask only about repeated keys (valid JSON assumed).
export const hasDuplicateKeys = (text) => strictScan(text).problems.has("duplicate-key");

// A tool call's argument string: { value, problem, ok, rawReason, large }. `value` is JSON.parse's (null when
// it fails); `ok` when it is a JSON object with no problem — the only arguments decided as parsed. Otherwise
// the caller keeps the text raw (content-scanned; refused in enforce mode) with `rawReason`. `large`: the
// source digits of numbers JSON.parse rounds (a numeric id past 2^53), which the call carries as `numbers`.
export function parseArgs(text) {
  let value = null;
  try { value = JSON.parse(text); } catch { return { value: null, problem: "not-json", ok: false, rawReason: undefined, large: [] }; }
  const r = strictScan(text);
  const ok = Boolean(value) && typeof value === "object" && !Array.isArray(value) && !r.problem;
  return { value, problem: r.problem, ok, rawReason: argReason(r.problem), large: r.large };
}
