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
//   2. Content an argument carries ENCODED: a data: URI or a base64 / base64url value. It is decoded in
//      memory (OUTBOUND_CAPS), and text is scanned with the same detectors at the "file" stage; a ZIP
//      (.docx/.xlsx/.pptx), PDF or OLE file gets the labelPolicy "send" check (cli/sensitivity-labels.mjs
//      readSensitivityLabelsBytes). Nothing decoded is written to disk. The body of an Office or PDF file is
//      not decompressed or scanned; only its label is read.
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
import { decideSensitivityLabel, readSensitivityLabelsBytes } from "./sensitivity-labels.mjs";

export const DLP_IDS = Object.freeze([...new Set(Object.values(DATA_TIERS).flat())]);
export const OUTBOUND_CAPS = Object.freeze({
  depth: 32,                // nesting walked in the arguments
  leaves: 10_000,           // string values walked
  leafText: 2_097_152,      // characters of joined values scanned (view 1)
  minEncoded: 64,           // shortest value tried as base64
  decodeLeaves: 8,          // encoded values decoded per call
  decodedBytes: 1_048_576,  // one decoded value; a larger one is not decoded
  decodedTotal: 4_194_304   // decoded bytes per call
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
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const B64URL = /^[A-Za-z0-9_-]+={0,2}$/;
// → { bytes, mime } for a value that is a data: URI or base64 / base64url, else null. Bounded before decoding.
function decodeLeaf(s) {
  if (s.length < OUTBOUND_CAPS.minEncoded) return null;
  let body = s, mime = "";
  const m = DATA_URI.exec(s);
  if (m) { body = s.slice(m[0].length); mime = (m[1] || "").toLowerCase(); }
  body = body.replace(/\s+/g, "");
  if (body.length < OUTBOUND_CAPS.minEncoded || Math.floor(body.length * 3 / 4) > OUTBOUND_CAPS.decodedBytes) return m ? { bytes: null, mime, size: Math.floor(body.length * 3 / 4) } : null;
  const std = B64.test(body), url = !std && B64URL.test(body);
  if (!std && !url) return null;
  if (!m && std && body.length % 4 !== 0) return null;
  // A value of letters only (an identifier, a word run) is not taken for base64 without a data: prefix.
  if (!m && !/[0-9+/_-]/.test(body)) return null;
  return { bytes: Buffer.from(body, url ? "base64url" : "base64"), mime, size: 0 };
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
  let bad = 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c === 0xfffd || c === 0 || (c < 9) || (c > 13 && c < 32)) bad++; }
  return s.length && bad / s.length <= 0.02 ? s : "";
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
function dlpEngine(engine) {
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
  let decodedTotal = 0, tries = 0, largestEncoded = 0, binaryType = "";
  for (const s of leaves) {
    if (tries >= OUTBOUND_CAPS.decodeLeaves) break;
    const e = decodeLeaf(s);
    if (!e) continue;
    tries++;
    if (!e.bytes) { largestEncoded = Math.max(largestEncoded, e.size); continue; }
    largestEncoded = Math.max(largestEncoded, e.bytes.length);
    if (decodedTotal + e.bytes.length > OUTBOUND_CAPS.decodedTotal) continue;
    decodedTotal += e.bytes.length;
    const type = fileType(e.bytes);
    if (type) { binaryType = binaryType || type; if (LABELLED.has(type)) blobs.push({ bytes: e.bytes, type }); continue; }
    const t = asText(e.bytes);
    if (t) texts.push(t);
  }
  if (texts.length) {
    const only = missing();
    if (only.length) merge(d, decide(dlpEngine(engine), policy, texts.join("\n"), "file", { only }));
  }
  for (const b of blobs) {
    const h = contentHash(b.bytes.toString("base64"));
    merge(d, decideSensitivityLabel(engine, policy, `mcp-arg:${h}`, "send", { read: () => readSensitivityLabelsBytes(b.bytes, `arg${EXT[b.type]}`) }));
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
