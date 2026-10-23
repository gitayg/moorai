// Response text scanning: the text of the model's reply — what reaches the person or the application — read
// for leaks, in every API this proxy parses, streaming and not (text-codecs.mjs finds the text, text-guard.mjs
// rewrites events). Four kinds of finding:
//   secret          #39  the engine's output-stage secret detectors (data/detectors.js secret-*, dlp-jwt,
//                        dlp-private-key …)
//   payment-card    #1   dlp-payment-card (Luhn-checked), pci-cvv
//   personal-data   #15  dlp-email, dlp-phone, dlp-national-id, pii-passport
//   system-prompt   #52  the reply reproduces a run of at least ECHO_MIN_WORDS consecutive words of THIS
//                        request's system prompt (below)
// The first three are the detection engine the proxy already judges outbound content with (the runtime's
// policy-built engine, its detector packs included), restricted to those threats' detectors that declare the
// "output" stage; a threat the policy sets "disabled" is not looked for.
//
// SYSTEM-PROMPT ECHO, keyed shingles. The request's system text (every outbound item of kind "system") is
// lower-cased and split into words (runs of letters and digits); each run of ECHO_K = 8 consecutive words is
// HMAC-SHA256'd with a random per-process key and the first 48 bits kept, at most MAX_SHINGLES = 8192 of
// them (words past that are not compared). A system prompt shorter than ECHO_MIN_WORDS = 24 words is not
// tracked. The reply's words go through the same window as they arrive; ECHO_MIN_WORDS - ECHO_K + 1 = 17
// consecutive matching shingles (a 24-word run) is an echo. Only the hashes exist past the call: the system
// prompt and the reply are never stored or logged. Linear: one HMAC per word, an 8-word window. A run of
// shared words is not proof of copying (a stock phrase the prompt quotes), and a paraphrase, a translation or
// words split by punctuation into other tokens are not caught.
//
// THE ROLLING WINDOW (per text channel: an Anthropic block, an OpenAI choice, a Responses content part, a
// Gemini candidate, an Ollama reply). The detectors run over the channel's last TAIL = 256 characters already
// passed on plus the text not yet passed on, so a match split across chunks or events is found whole.
//   report   nothing is held: the text is scanned each BATCH = 4096 characters and at the channel's end. The
//            tail is exactly the last TAIL characters (not cut at a whitespace: a card or phone number with
//            spaces in it across a batch boundary keeps its start); a match that starts exactly at the cut and
//            ends inside the tail is a cut-off token's end and is not reported.
//            Memory per channel: TAIL + BATCH + one event's text.
//   mask /   the last HOLD = 256 characters of each channel are held back and released as more text arrives
//   block    (a stream's text reaches the client up to 256 characters behind the provider — about 64
//            tokens — and the held text is released at the channel's end). A match of at most HOLD
//            characters is therefore found before any of it is released. Memory per channel: TAIL + HOLD +
//            one event's text. A match longer than HOLD (a PEM body, a long JWT) can be found only after its
//            start was released: the rest is still masked (or the stream stopped), and the alert says
//            sent "partial". Text already released can never be recalled.
// A match is replaced by "[REDACTED:#<threat>]" ("[REDACTED:system-prompt]" for an echo); the length changes,
// and the event is re-serialized. At most MAX_CHANNELS = 64 channels per response. Past that, mask / block
// fail closed: admit() (and a push to a 65th channel) throws before anything is taken, and the caller reports
// it unevaluated and, under a closed fail mode, stops the stream — no channel's text is ever released inside
// another's. Report mode, which changes nothing, scans text past the cap in one shared channel.
import { createHmac, randomBytes } from "node:crypto";
import { globalMatches } from "../src/regex-restart.js";
import { threatActionFor } from "../cli/hook-core.mjs";

export const CLASSES = Object.freeze({ 39: "secret", 1: "payment-card", 15: "personal-data", 52: "system-prompt" });
const PRIORITY = [39, 1, 15, 52];
export const HOLD = 256;
export const TAIL = 256;
export const BATCH = 4096;
export const ECHO_K = 8;
export const ECHO_MIN_WORDS = 24;
export const MAX_SHINGLES = 8192;
export const MAX_CHANNELS = 64;
const MAX_WORD = 64;
const MAX_SEEN = 256;
const WORD = /[\p{L}\p{N}]+/gu;

// "report" (default) | "mask" | "block" (policy.responseScan). Unknown values are the default.
export function responseScanMode(policy) {
  const m = policy && policy.responseScan;
  return m === "mask" || m === "block" ? m : "report";
}

export const marker = (id) => (id === 52 ? "[REDACTED:system-prompt]" : `[REDACTED:#${id}]`);

// The engine's detectors for the response classes, compiled once per engine (a policy refresh builds a new one).
const compiled = new WeakMap();
export function responseDetectors(engine) {
  let list = compiled.get(engine);
  if (list) return list;
  list = [];
  for (const d of engine.detectors || []) {
    if (!CLASSES[d.threatId] || d.threatId === 52 || d.mode === "coach") continue;
    if (!(d.stages || [d.stage]).includes("output")) continue;
    const patterns = [];
    for (const p of d.patterns || []) { try { patterns.push({ p, g: new RegExp(p.source, p.flags.includes("g") ? p.flags : `${p.flags}g`) }); } catch { /* skipped */ } }
    list.push({ id: d.threatId, refine: d.refine, patterns });
  }
  compiled.set(engine, list);
  return list;
}

// [{ s, e, id }] in `text`, every match of every enabled detector (refine honoured, as the engine's redact).
export function findSpans(dets, text, enabled) {
  const out = [];
  for (const d of dets) {
    if (!enabled(d.id)) continue;
    for (const { p, g } of d.patterns) {
      for (const m of globalMatches(p, g, text)) {
        if (!m[0]) continue;
        if (d.refine && !d.refine(m[0], text)) continue;
        out.push({ s: m.index, e: m.index + m[0].length, id: d.id });
      }
    }
  }
  return out;
}

// Disjoint spans, sorted; overlapping ones joined under the highest-priority id.
export function mergeSpans(spans) {
  const sorted = [...spans].sort((a, b) => a.s - b.s || b.e - a.e);
  const out = [];
  for (const sp of sorted) {
    const last = out[out.length - 1];
    if (last && sp.s < last.e) { last.e = Math.max(last.e, sp.e); if (PRIORITY.indexOf(sp.id) < PRIORITY.indexOf(last.id)) last.id = sp.id; }
    else out.push({ ...sp });
  }
  return out;
}

// The system prompt's shingle set, or null when it is too short to track. Cached per (key, text) — the same
// system prompt is re-sent every turn — 16 entries.
const echoCache = new Map();
export function createEcho(systemText, key) {
  const text = String(systemText || "");
  if (!text.trim()) return null;
  const hk = (s) => createHmac("sha256", key).update(s, "utf8").digest();
  const id = hk(`system\0${text}`).toString("base64");
  if (echoCache.has(id)) { const v = echoCache.get(id); echoCache.delete(id); echoCache.set(id, v); return v; }
  const words = [];
  for (const m of text.toLowerCase().matchAll(WORD)) { if (m[0].length > MAX_WORD) continue; words.push(m[0]); if (words.length >= MAX_SHINGLES + ECHO_K - 1) break; }
  let v = null;
  if (words.length >= ECHO_MIN_WORDS) {
    const hash = (s) => hk(s).readUIntBE(0, 6);
    const set = new Set();
    for (let i = 0; i + ECHO_K <= words.length; i++) set.add(hash(words.slice(i, i + ECHO_K).join(" ")));
    v = { set, hash, need: ECHO_MIN_WORDS - ECHO_K + 1 };
  }
  echoCache.set(id, v);
  if (echoCache.size > 16) echoCache.delete(echoCache.keys().next().value);
  return v;
}

// One response's scanner. hold: true in mask / block mode (text is held back and masked), false in report
// mode. onFind({ id, match, sent }) is called once per new finding, synchronously; `match` is the matched text
// (or, for an echo, its first shingle's keyed hash), for the caller to hash and drop.
export function createScanner({ dets, policy, echo = null, hold = false, onFind }) {
  const enabled = (() => { const memo = new Map(); return (id) => { if (!memo.has(id)) memo.set(id, threatActionFor(policy, id) !== "disabled"); return memo.get(id); }; })();
  const channels = new Map();
  let overflowed = false;

  const tooMany = () => new Error(`response text: more than ${MAX_CHANNELS} text channels; not scanned`);
  function channel(key) {
    let ch = channels.get(key);
    if (ch) return ch;
    if (channels.size >= MAX_CHANNELS && !key.startsWith("\0whole")) {
      overflowed = true;
      if (hold) throw tooMany();
      key = "\0overflow"; ch = channels.get(key); if (ch) return ch;
    }
    ch = { buf: "", base: 0, rel: 0, spans: [], echoSpans: [], seen: new Set(), wpos: 0, ring: [], run: 0, runStart: -1, echoSpan: null, done: false };
    channels.set(key, ch);
    return ch;
  }
  const end = (ch) => ch.base + ch.buf.length;

  function found(ch, sp) {
    const k = `${sp.id}:${sp.s}`;
    if (ch.seen.has(k)) return;
    if (ch.seen.size >= MAX_SEEN) return;
    ch.seen.add(k);
    const sent = sp.s >= ch.rel ? "none" : sp.e <= ch.rel ? "all" : "partial";
    const match = sp.id === 52 ? `echo:${sp.first}` : ch.buf.slice(Math.max(0, sp.s - ch.base), sp.e - ch.base);
    try { onFind({ id: sp.id, match, sent }); } catch { /* reporting never breaks the stream */ }
  }

  function word(ch, w, s, e) {
    if (w.length > MAX_WORD) { ch.ring = []; ch.run = 0; ch.echoSpan = null; return; }
    ch.ring.push({ w, s });
    if (ch.ring.length > ECHO_K) ch.ring.shift();
    if (ch.ring.length < ECHO_K) return;
    const h = echo.hash(ch.ring.map((x) => x.w).join(" "));
    if (!echo.set.has(h)) { ch.run = 0; ch.echoSpan = null; return; }
    if (ch.run === 0) { ch.runStart = ch.ring[0].s; ch.runFirst = h; }
    ch.run++;
    if (ch.run < echo.need) return;
    if (ch.echoSpan) { ch.echoSpan.e = e; return; }
    ch.echoSpan = { s: ch.runStart, e, id: 52, first: ch.runFirst };
    ch.echoSpans.push(ch.echoSpan);
    found(ch, ch.echoSpan);
  }
  function words(ch, final) {
    if (!echo) return;
    if (ch.wpos < ch.base) { ch.wpos = ch.base; ch.ring = []; ch.run = 0; ch.echoSpan = null; }
    WORD.lastIndex = ch.wpos - ch.base;
    let m;
    while ((m = WORD.exec(ch.buf)) !== null) {
      const s = ch.base + m.index, e = s + m[0].length;
      if (e === end(ch) && !final) { ch.wpos = s; return; }
      word(ch, m[0].toLowerCase(), s, e);
    }
    ch.wpos = end(ch);
  }

  function scan(ch) {
    const spans = findSpans(dets, ch.buf, enabled).map((sp) => ({ s: sp.s + ch.base, e: sp.e + ch.base, id: sp.id }));
    // Report mode's tail can start inside a token; a match that starts exactly there and ends inside the tail is
    // that token's cut-off end, not a new finding (a real one there was found, at the same position, before).
    for (const sp of mergeSpans(spans)) if (hold || !(ch.base > 0 && sp.s === ch.base && sp.e <= ch.rel)) found(ch, sp);
    ch.spans = mergeSpans([...ch.spans.filter((sp) => sp.e > ch.rel), ...spans.filter((sp) => sp.e > ch.rel)]);
  }
  function masked(ch, from, to) {
    const all = mergeSpans([...ch.spans, ...ch.echoSpans]).filter((sp) => sp.e > from && sp.s < to);
    let out = "", at = from;
    for (const sp of all) {
      const s = Math.max(sp.s, from), e = Math.min(sp.e, to);
      out += ch.buf.slice(at - ch.base, s - ch.base) + marker(sp.id);
      at = e;
    }
    return out + ch.buf.slice(at - ch.base, to - ch.base);
  }
  function trim(ch) {
    let nb = Math.max(ch.base, ch.rel - TAIL);
    if (nb > ch.base) {
      // mask / block: start the kept tail after a whitespace, so a token cut in half does not look like a token
      // of its own (a match there would be masked in text already released). Report mode keeps the exact tail.
      const ws = hold ? ch.buf.slice(nb - ch.base, ch.rel - ch.base).search(/\s/) : -1;
      if (ws >= 0) nb += ws + 1;
      ch.buf = ch.buf.slice(nb - ch.base);
      ch.base = nb;
    }
    ch.spans = ch.spans.filter((sp) => sp.e > ch.rel);
    ch.echoSpans = ch.echoSpans.filter((sp) => sp.e > ch.rel || sp === ch.echoSpan);
  }

  // Text for channel `key`; final: the channel ends here. Returns the text to pass on now (mask / block: the
  // released part, masked; report: `text` itself).
  function push(key, text, final = false) {
    const ch = channel(key);
    // Text after a channel's end (report mode's shared overflow channel) reopens it, so finish() scans it.
    if (typeof text === "string" && text) { ch.buf += text; ch.done = false; }
    words(ch, final);
    if (!hold) {
      if (final || end(ch) - ch.rel >= BATCH) { scan(ch); ch.rel = end(ch); trim(ch); }
      if (final) ch.done = true;
      return text;
    }
    if (!final && end(ch) - ch.rel <= HOLD) return "";
    scan(ch);
    let cut = final ? end(ch) : end(ch) - HOLD;
    // A found span crossing the cut is released whole (it is masked); an echo run under way is held from its
    // start, up to 4 x HOLD characters, so the run is masked from its first word once it qualifies.
    for (const sp of mergeSpans([...ch.spans, ...ch.echoSpans])) if (sp.s < cut && sp.e > cut) cut = sp.e;
    if (!final && echo && ch.run > 0 && !ch.echoSpan && ch.runStart >= ch.rel && ch.runStart < cut && end(ch) - ch.runStart <= 4 * HOLD) cut = ch.runStart;
    cut = Math.max(cut, ch.rel);
    const out = masked(ch, ch.rel, cut);
    ch.rel = cut;
    trim(ch);
    if (final) ch.done = true;
    return out;
  }
  // A complete text (a body's text, a stream's `.done` text): scanned whole in windows, returned masked.
  let wholeN = 0;
  function whole(text) {
    const key = `\0whole${wholeN++}`;
    let out = "";
    for (let i = 0; i < text.length; i += BATCH) out += push(key, text.slice(i, i + BATCH), false);
    out += push(key, "", true);
    channels.delete(key);
    return hold ? out : text;
  }
  // Every channel not yet ended: its held text, released (masked). → [[key, text]]
  function finish() {
    const out = [];
    for (const [k, ch] of channels) if (!ch.done) { const t = push(k, "", true); if (t) out.push([k, t]); }
    return out;
  }
  // mask / block: throws when the channels in `keys` that are not open yet would take the response past
  // MAX_CHANNELS — before any text of the event is pushed.
  function admit(keys) {
    if (!hold) return;
    const fresh = new Set(keys.filter((k) => !channels.has(k)));
    if (channels.size + fresh.size > MAX_CHANNELS) { overflowed = true; throw tooMany(); }
  }
  // held: characters received and not yet passed on; retained: characters kept (tail + held).
  return { push, whole, finish, admit, get overflowed() { return overflowed; }, held: (key) => { const ch = channels.get(key); return ch ? end(ch) - ch.rel : 0; }, retained: (key) => { const ch = channels.get(key); return ch ? ch.buf.length : 0; } };
}
