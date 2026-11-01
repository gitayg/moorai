// What an agent SENDS to an MCP tool (OWASP MCP10, Context Injection & Over-Sharing): the parts of the
// outbound-argument check that the serialized-JSON scan in mcpGateway (cli/hook-core.mjs) cannot see, and an
// over-sharing signal. Merged into mcpGateway's decision, so the Claude Code hook, the stdio MCP guard, the
// HTTP MCP gateway and @moorai/agent-sdk all run it. Additive only: a finding is added for a threat the
// JSON scan did not already raise, and a decision is only ever raised, never lowered.
//
//   1. The argument VALUES, unescaped. mcpGateway scans JSON.stringify(arguments), where a line break in a
//      value is the two characters "\n"; a detector that reads lines (a list of keys under an "API keys"
//      heading) or a word boundary at a line start does not fire there. The string values are joined with
//      real line breaks and scanned with the data-loss detectors (DLP_IDS: the threat ids of
//      data/data-tiers.js). Only when a value holds a character JSON escapes; otherwise the two views match.
//   2. Content an argument carries ENCODED: a data: URI, or a value of at least minEncoded characters of which
//      at least 95% (minAlphabet) are base64 / base64url characters. A value with other characters is
//      decoded the way a lenient decoder reads it: Node's Buffer.from(value, "base64") skips every character
//      outside both alphabets and stops at the first "=", and Python's base64.b64decode (validate=False)
//      also skips "-" and "_"; when the two differ, both readings are decoded. An "=" before the end of the
//      value is read the two ways other decoders read on past it: the runs between "=" joined (Python 3.14's
//      b64decode) and each run decoded on its own, the bytes one after another (GNU base64 -d); a value whose
//      readings hold under half the bytes its characters give is unevaluated (size). Decoded in memory within
//      OUTBOUND_CAPS, text is scanned with the same detectors at the "file" stage, and a ZIP
//      (.docx/.xlsx/.pptx), PDF or OLE file gets the labelPolicy "send" check (cli/sensitivity-labels.mjs
//      readSensitivityLabelsBytes; at most labelReads per call). Nothing decoded is written to disk. The body
//      of an Office or PDF file is not decompressed; only its label is read, and its raw bytes are scanned
//      only when they read as text, whatever file type its first bytes name. A value that is not decoded
//      whole (over decodedBytes, or past decodedTotal for the call) is UNEVALUATED, whatever its type (an
//      image too); the part of it the budget still allows is scanned as text, and under an active
//      labelPolicy a ZIP / PDF / OLE file has its label read in place (readSensitivityLabelsAt decodes only
//      the byte ranges the reader asks for, within LABEL_CAPS). A labelled file type in a value that needed
//      characters skipped, a label not read (past labelReads), or one that could not be read, is a label
//      unevaluated. Both are returned as d.unevaluated = { why: "size" | "label", values }: it never lowers
//      the decision, each surface applies its fail mode (cli/mcp-outbound-fail.mjs), and an unevaluated
//      label is refused when a labelPolicy rule blocks sending a labelled or rights-protected file.
//   3. The over-sharing signal (policy mcpOversharing): the arguments past a size, an encoded or
//      high-entropy blob, a whole file pasted into a value (a known binary file type, or a text value of
//      many lines), or a conversation pasted into a value (chat turns by role). Reported as a content-free
//      finding (OVERSHARE_CATEGORY): the signal names, byte and line counts, the turn count and a keyed hash
//      of the arguments; never a value. Default action "notify" (report); "justify" asks, "block" refuses.
//      A local filesystem write is exempt (its content stays on disk) when the caller passes `localWrite`
//      (cli/mcp-local-write.mjs: a write-shaped call to a server that is a local filesystem server by its
//      launch declaration, or listed in mcpOversharing.localWriteServers; the hook and the stdio guard pass
//      it, the HTTP gateway and the SDK do not). Only this signal is exempt: 1 and 2 run on every call.
//
// Secret VALUES from this machine (#65) are a separate check each surface runs beside mcpGateway, because
// each keeps its own session-read secret tracker (the stdio guard's is cli/mcp-secret-egress.mjs).
import { contentHash } from "./content-hash.mjs";
import { DATA_TIERS } from "../data/data-tiers.js";
import { decideSensitivityLabel, labelPolicy, readSensitivityLabelsAt, readSensitivityLabelsBytes, LABEL_THREAT } from "./sensitivity-labels.mjs";

export const DLP_IDS = Object.freeze([...new Set(Object.values(DATA_TIERS).flat())]);
export const OUTBOUND_CAPS = Object.freeze({
  depth: 32,                // nesting walked in the arguments
  leaves: 10_000,           // string values walked
  leafText: 2_097_152,      // characters of joined values scanned (view 1)
  minEncoded: 64,           // shortest value tried as base64
  minAlphabet: 0.95,        // share of base64 / base64url characters (padding included) a value needs without a data: prefix
  decodedBytes: 1_048_576,  // one decoded value; a larger one is not decoded
  decodedTotal: 4_194_304,  // decoded bytes per call (every reading of every value)
  labelReads: 8             // ZIP / PDF / OLE files whose label is read per call
});
// #92 Over-sharing to an MCP tool.
export const OVERSHARE_THREAT = 92;
export const OVERSHARE_CATEGORY = "MCP: over-sharing";
export const OVERSHARE_DEFAULTS = Object.freeze({ action: "notify", maxArgBytes: 65_536, maxEncodedBytes: 16_384, maxLines: 500, minTurns: 4, minEntropyBits: 5.5 });
const ACTIONS = ["off", "notify", "justify", "block"];
const RANK = { allow: 1, ask: 2, deny: 3 };
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// policy.mcpOversharing: false | { action?, maxArgBytes?, maxEncodedBytes?, maxLines?, minTurns?, minEntropyBits? }.
// Absent → the defaults (report). An invalid field keeps its default.
export function oversharingPolicy(policy) {
  const v = isObj(policy) ? policy.mcpOversharing : undefined;
  if (v === false) return { ...OVERSHARE_DEFAULTS, action: "off" };
  const out = { ...OVERSHARE_DEFAULTS };
  if (!isObj(v)) return out;
  if (ACTIONS.includes(v.action)) out.action = v.action;
  for (const k of ["maxArgBytes", "maxEncodedBytes", "maxLines", "minTurns"]) if (Number.isInteger(v[k]) && v[k] > 0) out[k] = v[k];
  if (typeof v.minEntropyBits === "number" && v.minEntropyBits > 0 && v.minEntropyBits <= 8) out.minEntropyBits = v.minEntropyBits;
  return out;
}

const ROLES = new Set(["user", "assistant", "system", "human", "ai", "model", "tool"]);
// String values and chat-message objects of the arguments, bounded.
function walk(value) {
  const leaves = [], roles = [];
  const stack = [[value, 0]];
  let seen = 0;
  while (stack.length && seen < OUTBOUND_CAPS.leaves) {
    const [v, depth] = stack.pop();
    if (typeof v === "string") { leaves.push(v); seen++; continue; }
    if (v === null || typeof v !== "object" || depth >= OUTBOUND_CAPS.depth) continue;
    if (!Array.isArray(v) && typeof v.role === "string" && ROLES.has(v.role.toLowerCase()) && ("content" in v || "text" in v || "parts" in v)) roles.push(v.role.toLowerCase());
    const kids = Array.isArray(v) ? v : Object.values(v);
    for (let i = kids.length - 1; i >= 0; i--) stack.push([kids[i], depth + 1]);
  }
  return { leaves, roles };
}

const DATA_URI = /^data:([\w.+-]+\/[\w.+-]+)?((?:;[\w.+-]+=[^;,]*)*);base64,/i;
const ALPHA = new Uint8Array(128);
for (const c of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-=") ALPHA[c.charCodeAt(0)] = 1;
const ALL_ALPHA = /^[A-Za-z0-9+/_=-]*$/;
const toPad = (t) => { const p = t.indexOf("="); return p < 0 ? t : t.slice(0, p); };
// → { readings, size, max, total, lenient, dataUri, mid, short } for a data: URI or a value that is (95% or
// more) base64 / base64url, else null. Nothing is decoded here. readings: the characters each lenient decoder
// decodes, the first Node's (both alphabets), then Python's b64decode when it differs (it skips "-" and "_");
// size: the bytes of the first reading, max: of the largest, total: of all of them. lenient: the value is not
// one clean alphabet with its padding at the end, so a decoder had to skip characters (whitespace aside:
// every decoder skips it). mid: an "=" before the end. Node and Python up to 3.12 stop there; Python 3.14's
// b64decode drops it and reads on (the runs joined), and GNU base64 -d decodes each run between "=" on its
// own and writes the bytes one after another ({ runs }); both are readings too. short: those readings hold
// under half the bytes the value's characters give (runs of one character carry none).
function encodedLeaf(s) {
  if (s.length < OUTBOUND_CAPS.minEncoded) return null;
  const m = DATA_URI.exec(s);
  const raw = m ? s.slice(m[0].length) : s;
  let space = 0, other = 0;
  if (!ALL_ALPHA.test(raw)) {
    const limit = m ? Infinity : raw.length * (1 - OUTBOUND_CAPS.minAlphabet);
    for (let i = 0; i < raw.length; i++) {
      const c = raw.charCodeAt(i);
      if (c < 128 && ALPHA[c]) continue;
      if (c === 32 || (c >= 9 && c <= 13)) space++; else other++;
      if (other + space > limit) return null;
    }
  }
  const body = space ? raw.replace(/\s+/g, "") : raw;
  if (body.length < OUTBOUND_CAPS.minEncoded) return null;
  // A value of letters only (an identifier, a word run) is not taken for base64 without a data: prefix.
  if (!m && !/[0-9+/_-]/.test(body)) return null;
  const pad = body.indexOf("="), url = /[-_]/.test(body);
  const mid = pad >= 0 && !/^={1,2}$/.test(body.slice(pad));
  const lenient = other > 0 || mid || (url && /[+/]/.test(body));
  const node = other ? body.replace(/[^A-Za-z0-9+/_=-]/g, "") : body;
  const readings = [toPad(node)];
  if (url) { const py = toPad(body.replace(/[^A-Za-z0-9+/=]/g, "")); if (py.length >= 4) readings.push(py); }
  let short = false;
  if (mid) {
    for (const t of url ? [node, body.replace(/[^A-Za-z0-9+/=]/g, "")] : [node]) {
      const runs = t.split(/=+/).filter((x) => x.length >= 2), joined = runs.join("");
      if (joined.length >= 2 && !readings.includes(joined)) readings.push(joined);
      if (runs.length > 1) readings.push({ runs });
      const chars = t.length - (t.match(/=/g) || []).length;
      if (chars >= OUTBOUND_CAPS.minEncoded && readingBytes({ runs }) < Math.floor(chars * 3 / 4) / 2) short = true;
    }
  }
  const sizes = readings.map(readingBytes);
  return { readings, size: sizes[0], max: Math.max(...sizes), total: sizes.reduce((n, b) => n + b, 0), lenient, dataUri: Boolean(m), mid, short };
}
const readingBytes = (r) => (typeof r === "string" ? Math.floor(r.length * 3 / 4) : r.runs.reduce((n, x) => n + Math.floor(x.length * 3 / 4), 0));
function decodeReading(r) {
  if (typeof r === "string") return Buffer.from(r, "base64");
  const b = Buffer.alloc(readingBytes(r));
  let off = 0;
  for (const x of r.runs) off += b.write(x, off, "base64");
  return b.subarray(0, off);
}
// Bytes [pos, pos + len) of a reading of either kind; the file types that start a run within its first `limit` bytes.
function readingAt(r, pos, len) {
  if (typeof r === "string") return decodeAt(r, pos, len);
  const parts = [];
  for (let k = 0, off = 0; k < r.runs.length && off < pos + len; k++) {
    const n = Math.floor(r.runs[k].length * 3 / 4);
    if (off + n > pos) { const a = Math.max(0, pos - off); parts.push(decodeAt(r.runs[k], a, Math.min(n, pos + len - off) - a)); }
    off += n;
  }
  return Buffer.concat(parts);
}
function runTypes(r, limit, buf) {
  const at = (off, k) => (buf ? buf.subarray(off, off + 8) : decodeAt(r.runs[k], 0, 8));
  const types = new Set([fileType(buf ? buf.subarray(0, 8) : readingAt(r, 0, 8))]);
  if (typeof r !== "string") for (let k = 0, off = 0; k < r.runs.length && off < limit; off += Math.floor(r.runs[k].length * 3 / 4), k++) types.add(fileType(at(off, k)));
  return types;
}
// Bytes [pos, pos + len) of a reading, decoding only the characters that hold them.
function decodeAt(t, pos, len) {
  const a = Math.floor(pos / 3) * 4, b = Math.ceil((pos + len) / 3) * 4;
  const buf = Buffer.from(t.slice(a, b), "base64");
  const off = pos - (a / 4) * 3;
  return buf.subarray(off, off + len);
}

const MAGIC = [
  ["zip", (b) => b.length >= 4 && b.readUInt32LE(0) === 0x04034b50],
  ["pdf", (b) => b.length >= 5 && b.toString("latin1", 0, 5) === "%PDF-"],
  ["ole", (b) => b.length >= 8 && b.readUInt32BE(0) === 0xd0cf11e0 && b.readUInt32BE(4) === 0xa1b11ae1],
  ["png", (b) => b.length >= 8 && b.readUInt32BE(0) === 0x89504e47],
  ["jpeg", (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff],
  ["gif", (b) => b.length >= 4 && b.toString("latin1", 0, 4) === "GIF8"],
  ["gzip", (b) => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b],
  ["elf", (b) => b.length >= 4 && b.readUInt32BE(0) === 0x7f454c46],
  ["macho", (b) => b.length >= 4 && [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(b.readUInt32BE(0))]
];
const fileType = (b) => { for (const [k, f] of MAGIC) if (f(b)) return k; return ""; };
const LABELLED = new Set(["zip", "pdf", "ole"]);
const EXT = { zip: ".docx", pdf: ".pdf", ole: ".doc" };

// Decoded bytes as text, or "" when they are not text (more than 2% control or invalid UTF-8 characters).
function asText(b) {
  const s = b.toString("utf8");
  const limit = s.length * 0.02;
  let bad = 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if ((c === 0xfffd || c === 0 || (c < 9) || (c > 13 && c < 32)) && ++bad > limit) return ""; }
  return s.length ? s : "";
}

function entropyBits(s) {
  const n = Math.min(s.length, 65_536);
  if (!n) return 0;
  const f = new Map();
  for (let i = 0; i < n; i++) { const c = s.charCodeAt(i); f.set(c, (f.get(c) || 0) + 1); }
  let h = 0;
  for (const k of f.values()) { const p = k / n; h -= p * Math.log2(p); }
  return h;
}

const TURN = /^[ \t>*_#-]*(user|assistant|human|ai|system|claude|chatgpt|model)\s*:/gim;
function textTurns(s) {
  const roles = [];
  for (const m of s.matchAll(TURN)) { roles.push(m[1].toLowerCase()); if (roles.length > 1000) break; }
  return roles;
}
const turnCount = (roles) => (new Set(roles).size >= 2 ? roles.length : 0);
const lineCount = (s) => { let n = 1; for (let i = s.indexOf("\n"); i >= 0 && n <= 1_000_000; i = s.indexOf("\n", i + 1)) n++; return n; };

// The engine with only the data-loss detectors (built-ins and org packs), so the extra scans below do not
// re-run every other rule and its decoded-variant pass (measured on a loaded machine, median of 7: a 2 KB
// multi-line value took 37 ms for this whole step through the whole engine, 5.6 ms with this one). Rebuilt
// when a policy refresh replaces the engine's detectors.
const DLP_ENGINES = new WeakMap();
export function dlpEngine(engine) {
  if (!engine || !Array.isArray(engine.detectors)) return engine;
  const c = DLP_ENGINES.get(engine);
  if (c && c.src === engine.detectors) return c.engine;
  const e = Object.create(engine);
  e.detectors = engine.detectors.filter((d) => DLP_IDS.includes(d.threatId));
  DLP_ENGINES.set(engine, { src: engine.detectors, engine: e });
  return e;
}

function merge(d, r) {
  if (!r || !r.findings.length) return;
  d.findings.push(...r.findings);
  d.reasons.push(...r.reasons);
  if (RANK[r.decision] > RANK[d.decision]) d.decision = r.decision;
  if (r.kill) { d.kill = true; d.killIds.push(...r.killIds); }
  for (const a of r.alternatives || []) if (!d.alternatives.includes(a)) d.alternatives.push(a);
}

// d: mcpGateway's content decision (decideText's shape), edited in place. decide: decideText (passed in,
// so this module does not import cli/hook-core.mjs). args: the serialized arguments mcpGateway scanned.
// localWrite (optional): (mcp__server__tool, parsed arguments) → true for a local filesystem write.
export function mergeOutbound(d, { engine, policy, tool, server, args, decide, localWrite }) {
  let parsed;
  try { parsed = typeof args === "string" ? JSON.parse(args) : args; } catch { return d; }
  if (parsed === null || typeof parsed !== "object") return d;
  const { leaves, roles } = walk(parsed);
  const have = () => new Set(d.findings.map((f) => f.threatId));
  const missing = () => { const h = have(); return DLP_IDS.filter((id) => !h.has(id)); };

  // 1 — the values with their line breaks.
  if (leaves.some((s) => /[\u0000-\u001f"\\]/.test(s))) {
    const only = missing();
    if (only.length) merge(d, decide(dlpEngine(engine), policy, leaves.join("\n").slice(0, OUTBOUND_CAPS.leafText), "prompt", { ctx: { egress: true }, only }));
  }

  // 2 — encoded content.
  const texts = [], blobs = [];
  const lp = labelPolicy(policy, () => {});
  const unread = { size: 0, label: 0, values: new Set() };
  const miss = (kind, i) => { unread[kind]++; unread.values.add(i); };
  let decodedTotal = 0, labelReads = 0, largestEncoded = 0, binaryType = "";
  const label = (i, type, hash, read) => {
    if (labelReads >= OUTBOUND_CAPS.labelReads) return miss("label", i);
    labelReads++;
    blobs.push({ i, type, hash, read });
  };
  leaves.forEach((s, i) => {
    const e = encodedLeaf(s);
    if (!e) return;
    if (!e.lenient || e.dataUri) largestEncoded = Math.max(largestEncoded, e.size);
    if (e.short) miss("size", i);
    if (e.max <= OUTBOUND_CAPS.decodedBytes && decodedTotal + e.total <= OUTBOUND_CAPS.decodedTotal) {
      e.readings.forEach((r, k) => {
        const bytes = decodeReading(r);
        decodedTotal += bytes.length;
        if (typeof r !== "string" && lp.active && [...runTypes(r, bytes.length, bytes)].some((x) => LABELLED.has(x))) miss("label", i);
        const type = fileType(bytes);
        if (k === 0) binaryType = binaryType || type;
        if (LABELLED.has(type) && lp.active) {
          if (e.lenient) miss("label", i);
          label(i, type, () => contentHash(bytes.toString("base64")), (name) => readSensitivityLabelsBytes(bytes, name));
        }
        const t = asText(bytes);
        if (t) texts.push(t);
      });
      return;
    }
    // Not decoded whole: unevaluated, whatever it is. The budget left is scanned; a label is read in place.
    miss("size", i);
    const r = e.readings[0];
    const at = (pos, len) => decodeAt(r, pos, len);
    const type = fileType(at(0, 8));
    binaryType = binaryType || type;
    if (LABELLED.has(type) && lp.active) {
      if (e.lenient) miss("label", i);
      label(i, type, () => contentHash(`${e.size}:${r.slice(0, 4096)}:${r.slice(-4096)}`), (name) => readSensitivityLabelsAt(at, e.size, name));
    }
    const scan = (o, room) => {
      if (room <= 0) return;
      const t = asText(readingAt(o, 0, room));
      decodedTotal += room;
      if (t) texts.push(t);
    };
    scan(r, Math.min(OUTBOUND_CAPS.decodedBytes, OUTBOUND_CAPS.decodedTotal - decodedTotal));
    if (e.mid) for (const o of e.readings.slice(1)) {
      const room = Math.min(OUTBOUND_CAPS.decodedBytes, OUTBOUND_CAPS.decodedTotal - decodedTotal, readingBytes(o));
      if (lp.active && [...runTypes(o, room)].some((x) => LABELLED.has(x))) miss("label", i);
      scan(o, room);
    }
  });
  if (texts.length) {
    const only = missing();
    if (only.length) merge(d, decide(dlpEngine(engine), policy, texts.join("\n"), "file", { only }));
  }
  for (const b of blobs) {
    const r = decideSensitivityLabel(engine, policy, `mcp-arg:${b.hash()}`, "send", { read: () => b.read(`arg${EXT[b.type]}`) });
    if (r.unevaluated) miss("label", b.i);
    merge(d, r);
  }
  if (unread.values.size) {
    d.unevaluated = { why: unread.label ? "label" : "size", values: unread.values.size };
    // A label that was not read may be one the policy blocks from being sent: refused, whatever the fail mode.
    if (unread.label && (lp.rules.some((r) => r.send === "block") || lp.protected.send === "block")) {
      merge(d, { decision: "deny", reasons: [`#${LABEL_THREAT} sensitivity label: an encoded file in the arguments could not be label-checked, and your organization blocks AI agents sending labelled files`], alternatives: [], kill: false, killIds: [],
        findings: [{ threatId: LABEL_THREAT, category: "Encoded file sent by an AI agent without a readable sensitivity label", riskLevel: "High", detectorId: "mcp-outbound-unevaluated", match: `unevaluated:label:${unread.label}` }] });
    }
  }

  // 3 — over-sharing.
  const op = oversharingPolicy(policy);
  if (op.action === "off") return d;
  const full = String(tool || "").startsWith("mcp__") ? String(tool) : `mcp__${server || ""}__${tool || ""}`;
  let local = false;
  try { local = typeof localWrite === "function" && localWrite(full, parsed) === true; } catch { local = false; }
  if (local) return d;
  const bytes = Buffer.byteLength(typeof args === "string" ? args : JSON.stringify(args));
  let largest = 0, lines = 0, turns = turnCount(roles), entropic = false;
  for (const s of leaves) {
    largest = Math.max(largest, s.length);
    if (s.length > 200) lines = Math.max(lines, lineCount(s));
    if (s.length > 200 && turns < op.minTurns) turns = Math.max(turns, turnCount(textTurns(s)));
    if (!entropic && s.length >= op.maxEncodedBytes && entropyBits(s) >= op.minEntropyBits) entropic = true;
  }
  const signals = [];
  if (bytes > op.maxArgBytes) signals.push("size");
  if (largestEncoded >= op.maxEncodedBytes || entropic) signals.push("encoded-blob");
  if (binaryType || lines >= op.maxLines) signals.push("file-paste");
  if (turns >= op.minTurns) signals.push("conversation");
  if (!signals.length) return d;
  const argsHash = contentHash(typeof args === "string" ? args : JSON.stringify(args));
  const oversharing = { signals, bytes, largestValueBytes: largest, lines, turns, ...(binaryType ? { fileType: binaryType } : {}), argsHash };
  const r = { decision: "allow", reasons: [], alternatives: [], kill: false, killIds: [], findings: [{ threatId: OVERSHARE_THREAT, category: OVERSHARE_CATEGORY, riskLevel: op.action === "block" ? "High" : "Medium", match: `overshare:${argsHash}`, detectorId: "mcp-oversharing", oversharing }] };
  if (op.action !== "notify") {
    r.decision = op.action === "block" ? "deny" : "ask";
    r.reasons.push(`MCP over-sharing: ${signals.join(", ")}${op.action === "justify" ? " (needs sign-off)" : ""}`);
    r.alternatives.push("Send only the part of the file or conversation the tool needs, or reference it instead of pasting it.");
  }
  merge(d, r);
  return d;
}

// The alert fields a reporter adds for an over-sharing finding (content-free; see the header).
export function oversharingAlertFields(f) {
  return f && f.oversharing ? { oversharing: f.oversharing } : {};
}
