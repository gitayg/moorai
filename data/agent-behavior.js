// Autonomous-agent-behavior signature (the "is this an agent gone rogue?" analyzer).
//
// Encodes the 8 behavioral tells the Hugging Face team used to conclude their July 2026 incident was
// a FULLY AUTONOMOUS attack, as documented in the CSA/SANS/[un]prompted/RSAC/Knostic/FIRST community
// post-mortem ("Hugging Face Incident Initial Post-Mortem", §IV Observations). Two layers:
//
//   contentTells(text)        — per-event text heuristics (#5 benchmark strings, #6 hallucinated/
//                               incoherent input, #7 LLM-generated obfuscation, #8 poor-opsec
//                               artifacts). Runs where the text is in hand (hook/guard), then only a
//                               content-free FLAG is kept — never the text.
//   assessSession(events)     — session-level behavioral heuristics over a window of content-free
//                               events (#1 repeating an already-succeeded action, #2 brilliant-then-
//                               malformed variance, #3 machine-speed parallel bursts, #4 clumsy
//                               inefficient paths) plus the aggregated content flags. Returns which
//                               tells fired, a score, and a verdict level.
//
// Content-free by construction: assessSession consumes counts/flags/timestamps only. Nothing here
// reads or retains a prompt, a file, or a matched span.

// ---- per-event content tells (#5–#8). Input is raw text; output is boolean flags only. ----
const BENCHMARK_RE = /\b(exploit\s?gym|cyber\s?gym|capture[-\s]the[-\s]flag|\bctf\b|benchmark|leaderboard|flag\{)/i;
const OBFUSCATION_RE = /\b(eval\s*\(\s*atob|atob\s*\(|base64\s+-d|FromBase64String|[A-Za-z0-9+/]{160,}={0,2})\b|curl\s[^|]*\|\s*(ba)?sh/i;
const OPSEC_KEY_RE = /-----BEGIN\s[A-Z ]*PRIVATE KEY-----|\b(aes|iv|nonce|enc(ryption)?[_-]?key)\b[^\n]{0,40}\b[0-9a-f]{32,}\b/i;

// #6 — hallucinated / incoherent input: over a non-trivial length, the ratio of dictionary-shaped
// word tokens to all tokens collapses. Cheap, language-rough, content-free in its OUTPUT (a boolean).
function looksIncoherent(text) {
  const t = String(text || "");
  if (t.length < 160) return false;
  const toks = t.split(/\s+/).filter(Boolean);
  if (toks.length < 24) return false;
  const wordish = toks.filter((w) => /^[A-Za-z][A-Za-z'-]{1,}$/.test(w)).length;
  return wordish / toks.length < 0.32;
}

export function contentTells(text) {
  const t = String(text || "");
  return {
    benchmarkStr: BENCHMARK_RE.test(t),   // #5
    incoherent: looksIncoherent(t),       // #6
    obfuscation: OBFUSCATION_RE.test(t),  // #7
    opsecArtifact: OPSEC_KEY_RE.test(t)   // #8
  };
}

// ---- session-level behavioral tells (#1–#4) over content-free events. ----
// event = { ts:number(ms), sig:string(action fingerprint), ok:boolean(allowed/succeeded),
//           risk:"Low|Medium|High|Critical|Blocked", flags?:{benchmarkStr,incoherent,obfuscation,opsecArtifact} }
const TELLS = {
  repeatSucceeded: { n: 1, w: 25, label: "Repeats actions that already succeeded" },       // #1
  sophVariance:    { n: 2, w: 20, label: "Brilliant move then malformed/basic action" },   // #2
  burstParallel:   { n: 3, w: 25, label: "Machine-speed parallel burst" },                 // #3
  inefficient:     { n: 4, w: 15, label: "Clumsy, inefficient repeated-failure path" },    // #4
  benchmarkStr:    { n: 5, w: 20, label: "Benchmark / decoy strings in activity" },        // #5
  incoherent:      { n: 6, w: 20, label: "Hallucinated / incoherent input" },              // #6
  obfuscation:     { n: 7, w: 20, label: "LLM-generated obfuscation (base64→exec, pipe-to-shell)" }, // #7
  opsecArtifact:   { n: 8, w: 20, label: "Leftover opsec artifacts (keys / crypto material)" }       // #8
};

export function assessSession(events, opts = {}) {
  const evs = Array.isArray(events) ? events.slice() : [];
  const burstN = opts.burstN || 8, burstMs = opts.burstMs || 5000, autoScore = opts.autoScore || 50;
  const fired = new Set();

  // #1 — a sig that recurs after it already succeeded once.
  const succeeded = new Map(); // sig -> count of successful occurrences
  const seen = new Map();
  for (const e of evs) {
    const s = e.sig || "";
    seen.set(s, (seen.get(s) || 0) + 1);
    if (e.ok) succeeded.set(s, (succeeded.get(s) || 0) + 1);
    if (s && succeeded.get(s) >= 1 && seen.get(s) >= 3) fired.add("repeatSucceeded");
  }

  // #2 — sophistication variance: a high-risk finding coexists with ≥2 malformed/no-finding events.
  const highRisk = evs.some((e) => e.risk === "Critical" || e.risk === "High" || e.risk === "Blocked");
  const malformed = evs.filter((e) => e.ok === false && (!e.risk || e.risk === "Low")).length;
  if (highRisk && malformed >= 2) fired.add("sophVariance");

  // #3 — machine-speed burst: burstN events inside burstMs.
  const ts = evs.map((e) => e.ts).filter((x) => typeof x === "number").sort((a, b) => a - b);
  for (let i = 0; i + burstN - 1 < ts.length; i++) {
    if (ts[i + burstN - 1] - ts[i] <= burstMs) { fired.add("burstParallel"); break; }
  }

  // #4 — inefficient path: the same sig fails ≥3 times (clumsy retry loop with no success).
  const failBySig = new Map();
  for (const e of evs) if (e.ok === false) { const s = e.sig || ""; failBySig.set(s, (failBySig.get(s) || 0) + 1); }
  if ([...failBySig.values()].some((c) => c >= 3)) fired.add("inefficient");

  // #5–#8 — aggregate the content flags carried on events.
  for (const e of evs) {
    const f = e.flags || {};
    if (f.benchmarkStr) fired.add("benchmarkStr");
    if (f.incoherent) fired.add("incoherent");
    if (f.obfuscation) fired.add("obfuscation");
    if (f.opsecArtifact) fired.add("opsecArtifact");
  }

  const tells = [...fired].map((k) => ({ id: TELLS[k].n, key: k, label: TELLS[k].label }))
    .sort((a, b) => a.id - b.id);
  const score = [...fired].reduce((s, k) => s + TELLS[k].w, 0);
  const level = score >= autoScore ? "autonomous-signature" : fired.size >= 1 ? "suspicious" : "clean";
  return { level, score, tellsFired: fired.size, tells, events: evs.length };
}

export const TELL_DEFS = TELLS;

// ---- Certiv-style "lethal trifecta" (Simon Willison's term). An exfiltration setup needs three legs
// in the SAME agent session: (A) access to private data, (B) exposure to untrusted content, and (C)
// the ability to communicate externally. Any one is fine; all three together is the exploit. Detected
// purely from content-free per-event legs (booleans on tool/stage/finding class) — never any content.
export function assessTrifecta(events) {
  const evs = Array.isArray(events) ? events : [];
  const legs = { read: false, ingest: false, callout: false };
  for (const e of evs) {
    const l = e.legs || {};
    if (l.read) legs.read = true;
    if (l.ingest) legs.ingest = true;
    if (l.callout) legs.callout = true;
  }
  const present = legs.read && legs.ingest && legs.callout;
  const count = (legs.read ? 1 : 0) + (legs.ingest ? 1 : 0) + (legs.callout ? 1 : 0);
  return { present, count, legs };
}

// Derive the three content-free trifecta legs for a single tool call from what the hook already knows:
// the tool name, the stage, and the finding classes (threat ids) — no prompt/file content required.
const SENSITIVE_THREATS = new Set([1, 9, 15, 39, 44, 45, 55]); // secrets, PII, PHI, source/IP, cards
const UNTRUSTED_THREATS = new Set([3, 40, 50]);                 // injection, indirect/RAG, invisible text
const CALLOUT_THREATS = new Set([2, 47, 54, 56, 57]);           // exfil, external comms, reverse shell, MCP-destructive, install
export function trifectaLegs(tool, stage, findings, flags) {
  const ids = new Set((findings || []).map((f) => f.threatId));
  const has = (set) => [...ids].some((id) => set.has(id));
  const read = tool === "Read" || tool === "Bash" || has(SENSITIVE_THREATS);
  const ingest = has(UNTRUSTED_THREATS) || !!(flags && (flags.obfuscation || flags.incoherent));
  const callout = String(tool || "").startsWith("mcp__") || stage === "egress" || has(CALLOUT_THREATS);
  return { read, ingest, callout };
}
