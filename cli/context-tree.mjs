// context.tree: a per-session Merkle tree of everything that entered an AI agent's context, content-free.
//
// Every prompt, file read, web page, MCP result, subagent handoff, tool output, skill and system text the
// agent took in becomes one LEAF: { stage, sourceKind, sourceHash, blobHash, blobHashKind, size, ts }.
// No path, URL, server name or byte of content is stored: the source is a tenant-keyed hash, the blob a hash.
// The tree's root at decision time goes on the alert or allow-trail record (contextRoot, contextSize), so an
// investigator can later prove which source carried an injected instruction (patient zero): hash the original
// blob, find the leaf whose blobHash matches, and check its inclusion proof against the recorded root.
//
// HASHING (RFC 6962 section 2.1, the Certificate Transparency Merkle tree):
//   leaf hash = SHA-256(0x00 || canonical JSON of the leaf)     canonical JSON = sorted keys, no whitespace
//   node hash = SHA-256(0x01 || left || right)
//   empty root = SHA-256("")
// The tree is split at the largest power of two below n, exactly as RFC 6962 MTH, so its roots and inclusion
// proofs are checked against the published CT known-answer vectors (test/context-tree-ct-vectors.json).
//
// BLOB HASH THRESHOLD: a blob of SHA256_MIN_BYTES (256) bytes or more is hashed with plain SHA-256
// (blobHashKind "sha256"), so anyone holding the original file or page can confirm it against the leaf
// without any key. A shorter blob is hashed with the tenant-keyed hash (blobHashKind "keyed", the same
// HMAC as contentHash, cli/content-hash.mjs). The reason: short text can be confirmed by guessing. "yes",
// a phone number or a one-line instruction is a small space, and a plain digest of it is an encoding anyone
// can reverse by enumeration. 256 bytes of real content is far past any enumeration. The cost of the plain
// hash is a stated limit: whoever holds a 256-byte-or-longer original can confirm it entered the context.
//
// PERSISTENCE: one append-only JSONL file per session, ~/.moorai/context-tree/<keyed session id>.jsonl
// (":" in the id is written as "-" in the file name), mode 0600 in a 0700 directory, holding leaves only;
// the root is recomputed on load. Each leaf is ONE write of one line.
// Next to it, <file>.frontier caches the compact range: the leaf count, the session file's byte length,
// and the hashes of the perfect subtrees named by the set bits of the count (at most log2(n) + 1). An
// append reads the frontier, writes its line, folds the new leaf hash into the frontier and replaces the
// frontier (temp + rename), all under the session lock, so it costs O(log n) hashes whatever the session's
// size. A frontier that is missing, unreadable or whose byte length is not the session file's (an append
// that could not get the lock, a hand edit, a torn write, an older writer) is rebuilt from the session
// file once, by that append. The frontier is a cache: the leaves stay the truth. A torn last line is ignored and
// reported on load, never rewritten; the next append terminates it with a newline so the fragment stays in
// the file as a reported, skipped line. A session holds at most MAX_LEAVES leaves: at the cap appends stop
// and say so; old leaves are never dropped. Session files older than RETENTION_DAYS are deleted by a sweep
// that runs when a session's first leaf is written.
//
// LIMITS: the tree is tamper-evident, not tamper-proof. The file lives where the agent can write, so an
// agent can rewrite its own history; that rewrite changes the root, which no longer matches the roots
// already on records. Tamper-proof needs roots signed by the privileged helper.
import { createHash } from "node:crypto";
import { openSync, closeSync, writeSync, readSync, readFileSync, writeFileSync, renameSync, fstatSync, lstatSync, unlinkSync, mkdirSync, chmodSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, posix as pathPosix, win32 as pathWin32 } from "node:path";
import { contentHash, hashWithKey, NO_KEY } from "./content-hash.mjs";
import { splitPath } from "./path-within.mjs";
import { withFileLock } from "./alert-seq.mjs";
import { readConsoleBackoff, backoffDelay, BACKOFF_BASE_MS, BACKOFF_CAP_MS } from "./console-backoff.mjs";

export const STAGES = Object.freeze(["prompt", "file", "web", "mcp", "subagent", "tool-output", "skill", "system"]);
export const SOURCE_KINDS = Object.freeze(["path", "url", "mcp", "skill", "name", "none"]);
export const DEFAULT_SOURCE_KIND = Object.freeze({ prompt: "none", file: "path", web: "url", mcp: "mcp", subagent: "name", "tool-output": "none", skill: "skill", system: "none" });
export const SHA256_MIN_BYTES = 256;
export const MAX_LEAVES = 50000;
export const RETENTION_DAYS = 30;
export const LEAF_FIELDS = Object.freeze(["stage", "sourceKind", "sourceHash", "blobHash", "blobHashKind", "size", "ts"]);

const sha256 = (...parts) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };
const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);
const KEYED_RE = /^h2:(?:[0-9a-f]{16}|nokey)$/;
const SHA_RE = /^[0-9a-f]{64}$/;

// ---- canonical source strings -------------------------------------------------------------------------

// The string the sourceHash is taken over. Only its keyed hash is ever stored.
//   path   a normalised absolute path under the platform's case rule (cli/path-within.mjs): "/"-separated,
//          resolved against cwd, NFC + lower case on macOS, lower case on Windows, byte-exact on Linux.
//   url    the URL with the fragment and any user:password dropped; scheme and host lower-cased, query kept.
//   mcp    "mcp:<server>/<tool>"; source is that string or { server, tool }.
//   skill  "skill:<canonical path>".
//   name   "name:<name>" (a subagent type, a tool name).
//   none   "" (prompt and system text have no external source); sourceHash is "".
export function canonicalSource(sourceKind, source, { cwd = process.cwd(), platform = process.platform } = {}) {
  switch (sourceKind) {
    case "path": return canonicalPath(source, cwd, platform);
    case "skill": return `skill:${canonicalPath(String(source ?? "").replace(/^skill:/, ""), cwd, platform)}`;
    case "url": return canonicalUrl(source);
    case "mcp": return canonicalMcp(source);
    case "name": { const n = String(source ?? "").trim(); if (!n) throw new TypeError("context-tree: empty name source"); return `name:${n}`; }
    case "none": return "";
    default: throw new TypeError(`context-tree: unknown sourceKind ${JSON.stringify(sourceKind)}`);
  }
}

function canonicalPath(p, cwd, platform) {
  const s = String(p ?? "");
  if (!s || s.includes("\0")) throw new TypeError("context-tree: empty or invalid path source");
  const abs = (platform === "win32" ? pathWin32 : pathPosix).resolve(String(cwd), s);
  const sp = splitPath(abs, platform);
  if (!sp) throw new TypeError("context-tree: path source cannot be normalised");
  return sp.head === "/" ? `/${sp.keys.join("/")}` : `${sp.head}/${sp.keys.join("/")}`;
}

function canonicalUrl(u) {
  let url;
  try { url = new URL(String(u ?? "").trim()); } catch { throw new TypeError("context-tree: url source does not parse"); }
  url.hash = "";
  url.username = "";
  url.password = "";
  return url.href;
}

function canonicalMcp(src) {
  let server, tool;
  if (src && typeof src === "object") ({ server, tool } = src);
  else {
    const m = /^mcp:([^/]+)\/(.+)$/.exec(String(src ?? "").trim());
    if (!m) throw new TypeError('context-tree: mcp source must be "mcp:<server>/<tool>" or { server, tool }');
    [, server, tool] = m;
  }
  server = String(server ?? "").trim(); tool = String(tool ?? "").trim();
  if (!server || !tool || server.includes("/")) throw new TypeError("context-tree: mcp source needs a server and a tool");
  return `mcp:${server}/${tool}`;
}

// ---- leaves --------------------------------------------------------------------------------------------

const keyed = (tenantKey, s) => (tenantKey === undefined ? contentHash(s) : hashWithKey(tenantKey, s));
const UTF8 = new TextDecoder("utf-8", { fatal: true });

// A short blob's keyed hash. Valid UTF-8 is hashed as its text, so it equals the contentHash the hook puts
// on alerts for the same text; other bytes are hashed as a tagged hex string.
function keyedBlob(buf, tenantKey) {
  let text;
  try { text = UTF8.decode(buf); } catch { text = `moorai/context-tree/bin:${buf.toString("hex")}`; }
  return keyed(tenantKey, text);
}

// leafOf({ stage, sourceKind, source, bytes, tenantKey, ts }) -> leaf. tenantKey is the raw key
// (deriveKey(installToken)); omitted, the device's enrolled key is used, as contentHash does. With no key
// at all the keyed fields are the NO_KEY sentinel "h2:nokey", never a reversible hash. `cwd` and
// `platform` are optional and only shape path canonicalisation.
export function leafOf({ stage, sourceKind, source, bytes, tenantKey, ts, cwd, platform } = {}) {
  if (!STAGES.includes(stage)) throw new TypeError(`context-tree: unknown stage ${JSON.stringify(stage)}`);
  const kind = sourceKind === undefined ? DEFAULT_SOURCE_KIND[stage] : sourceKind;
  const canon = canonicalSource(kind, source, { cwd, platform });
  const buf = Buffer.isBuffer(bytes) ? bytes : bytes instanceof Uint8Array ? Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength) : Buffer.from(String(bytes ?? ""), "utf8");
  const big = buf.length >= SHA256_MIN_BYTES;
  const when = ts === undefined ? new Date().toISOString() : typeof ts === "number" ? new Date(ts).toISOString() : String(ts);
  return {
    stage,
    sourceKind: kind,
    sourceHash: canon === "" ? "" : keyed(tenantKey, canon),
    blobHash: big ? sha256(buf).toString("hex") : keyedBlob(buf, tenantKey),
    blobHashKind: big ? "sha256" : "keyed",
    size: buf.length,
    ts: when,
  };
}

// A leaf is content-free by construction: every field is an enum, a hash, an integer or a timestamp.
export function isLeaf(l) {
  if (!l || typeof l !== "object" || Array.isArray(l)) return false;
  if (!STAGES.includes(l.stage) || !SOURCE_KINDS.includes(l.sourceKind)) return false;
  if (l.sourceKind === "none" ? l.sourceHash !== "" : !KEYED_RE.test(l.sourceHash)) return false;
  if (!Number.isSafeInteger(l.size) || l.size < 0) return false;
  if (l.blobHashKind === "sha256") { if (!SHA_RE.test(l.blobHash) || l.size < SHA256_MIN_BYTES) return false; }
  else if (l.blobHashKind === "keyed") { if (!KEYED_RE.test(l.blobHash) || l.size >= SHA256_MIN_BYTES) return false; }
  else return false;
  return typeof l.ts === "string" && l.ts.length > 0 && l.ts.length <= 64;
}

const pick = (leaf) => { const o = {}; for (const k of LEAF_FIELDS) o[k] = leaf[k]; return o; };

export function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
}

// RFC 6962 leaf hash of raw leaf data, and of a context leaf (its canonical JSON).
export const hashLeafData = (data) => sha256(LEAF_PREFIX, Buffer.from(data));
export const leafHash = (leaf) => hashLeafData(Buffer.from(canonicalJson(pick(leaf)), "utf8"));
const hashChildren = (l, r) => sha256(NODE_PREFIX, l, r);
const EMPTY_ROOT = sha256(Buffer.alloc(0));

// ---- the Merkle tree -----------------------------------------------------------------------------------

const largestPow2Below = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const toBuf = (h) => (Buffer.isBuffer(h) ? h : Buffer.from(String(h), "hex"));

export class ContextTree {
  constructor() {
    // levels[k][j] is the hash of the perfect subtree of 2^k leaves starting at leaf j*2^k. levels[0] holds
    // the leaf hashes. Appending fills it bottom-up: amortised O(1), at worst O(log n) hashes per leaf.
    this.levels = [[]];
    this.leaves = [];
  }

  size() { return this.levels[0].length; }

  // append(leaf) -> { index, root }
  append(leaf) {
    if (!isLeaf(leaf)) throw new TypeError("context-tree: not a content-free leaf");
    const index = this.appendHash(leafHash(leaf));
    this.leaves.push(pick(leaf));
    return { index, root: this.root() };
  }

  // Appends an already-computed RFC 6962 leaf hash; returns its index. The known-answer tests use it.
  appendHash(h) {
    const index = this.levels[0].length;
    let cur = toBuf(h);
    let k = 0;
    this.levels[0].push(cur);
    while (this.levels[k].length % 2 === 0) {
      const lv = this.levels[k];
      cur = hashChildren(lv[lv.length - 2], cur);
      k++;
      if (!this.levels[k]) this.levels[k] = [];
      this.levels[k].push(cur);
    }
    return index;
  }

  // The root is the fold, right to left, of the frontier: the perfect subtrees named by the set bits of n.
  // O(log n).
  rootBuf() {
    const n = this.size();
    if (n === 0) return EMPTY_ROOT;
    let acc = null;
    for (let k = 0; k < this.levels.length; k++) {
      if (!((n >> k) & 1)) continue;
      const h = this.levels[k][(n >> k) - 1];
      acc = acc === null ? h : hashChildren(h, acc);
    }
    return acc;
  }
  root() { return this.rootBuf().toString("hex"); }

  // MTH(D[start:end]) using the stored perfect subtrees. O(log n).
  subtree(start, end) {
    const len = end - start;
    if ((len & (len - 1)) === 0 && start % len === 0) {
      const k = Math.log2(len);
      return this.levels[k][start / len];
    }
    const k = largestPow2Below(len);
    return hashChildren(this.subtree(start, start + k), this.subtree(start + k, end));
  }

  // proof(index, size = size()) -> [hex...]: the RFC 6962 audit path PATH(m, D[0:size]), leaf to root.
  proof(index, size = this.size()) {
    if (!Number.isSafeInteger(size) || size < 1 || size > this.size()) throw new RangeError("context-tree: bad tree size");
    if (!Number.isSafeInteger(index) || index < 0 || index >= size) throw new RangeError("context-tree: bad leaf index");
    const out = [];
    const path = (m, start, end) => {
      const n = end - start;
      if (n === 1) return;
      const k = largestPow2Below(n);
      if (m < k) { path(m, start, start + k); out.push(this.subtree(start + k, end)); }
      else { path(m - k, start + k, end); out.push(this.subtree(start, start + k)); }
    };
    path(index, 0, size);
    return out.map((b) => b.toString("hex"));
  }

  // The root of the first `size` leaves (a root recorded earlier in the session).
  rootAt(size) {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.size()) throw new RangeError("context-tree: bad tree size");
    return (size === 0 ? EMPTY_ROOT : this.subtree(0, size)).toString("hex");
  }

  static verify(leaf, index, size, proof, root) {
    if (!isLeaf(leaf)) return false;
    return verifyLeafHash(leafHash(leaf), index, size, proof, root);
  }
}

// RFC 9162 section 2.1.3.2 inclusion verification over a leaf hash. Never throws.
export function verifyLeafHash(lh, index, size, proof, root) {
  try {
    if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
    if (!Array.isArray(proof)) return false;
    const want = toBuf(root);
    if (want.length !== 32) return false;
    let r = toBuf(lh);
    if (r.length !== 32) return false;
    let fn = BigInt(index), sn = BigInt(size - 1);
    for (const p of proof) {
      const ph = toBuf(p);
      if (ph.length !== 32 || sn === 0n) return false;
      if ((fn & 1n) === 1n || fn === sn) {
        r = hashChildren(ph, r);
        while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
      } else {
        r = hashChildren(r, ph);
      }
      fn >>= 1n; sn >>= 1n;
    }
    return sn === 0n && r.equals(want);
  } catch { return false; }
}

// ---- persistence ---------------------------------------------------------------------------------------

export const treeDir = (home = homedir()) => join(home, ".moorai", "context-tree");
const ID_RE = /^[A-Za-z0-9_:]{1,128}$/;

// The file a keyed session id is stored in. ":" becomes "-" (Windows file names cannot hold ":"); "-" is not
// allowed in an id, so the mapping is one-to-one. The NO_KEY sentinel is refused: it would merge every
// unenrolled session into one tree.
export function sessionFile(sessionId, { home = homedir() } = {}) {
  const id = String(sessionId ?? "");
  if (!ID_RE.test(id) || id === NO_KEY) throw new TypeError("context-tree: session id must be a keyed id ([A-Za-z0-9_:], not h2:nokey)");
  return join(treeDir(home), `${id.replace(/:/g, "-")}.jsonl`);
}
export const sessionIdOfFile = (name) => (name.endsWith(".jsonl") ? name.slice(0, -6).replace(/-/g, ":") : null);

function ensureDir(home) {
  const d = treeDir(home);
  mkdirSync(d, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") { try { chmodSync(d, 0o700); } catch { /* not ours to change */ } }
  return d;
}

// Parse a session file's text. -> { leaves, skipped: [{ line, offset, bytes }], tornTail }
// tornTail: the file does not end in a newline, so its last line is a torn write; it is skipped and listed.
// Any other line that is not a content-free leaf is skipped and listed too. Nothing is rewritten.
export function parseSession(text) {
  const { leaves, skipped, tornTail } = parseLines(text);
  return { leaves, skipped, tornTail };
}
// raws[i] is the exact line of leaves[i], already checked to be its canonical JSON, so a load hashes the line
// as it is instead of re-serialising the leaf.
function parseLines(text) {
  const leaves = [], raws = [], skipped = [];
  const tornTail = text.length > 0 && !text.endsWith("\n");
  let offset = 0, line = 0;
  for (const raw of text.split("\n")) {
    line++;
    const bytes = Buffer.byteLength(raw, "utf8");
    if (raw.length > 0) {
      let l = null;
      try { l = JSON.parse(raw); } catch { /* reported below */ }
      if (l && isLeaf(l) && canonicalJson(pick(l)) === raw) { leaves.push(pick(l)); raws.push(raw); }
      else skipped.push({ line, offset, bytes });
    }
    offset += bytes + 1;
  }
  return { leaves, raws, skipped, tornTail };
}

// loadSession(id) -> { tree, size, root, skipped, tornTail, capped, file }. A missing file is an empty tree.
export function loadSession(sessionId, { home = homedir(), maxLeaves = MAX_LEAVES } = {}) {
  const file = sessionFile(sessionId, { home });
  let text = "";
  try { text = readFileSync(file, "utf8"); } catch (e) { if (!e || e.code !== "ENOENT") throw e; }
  const { leaves, raws, skipped, tornTail } = parseLines(text);
  const tree = new ContextTree();
  for (let i = 0; i < leaves.length; i++) { tree.appendHash(hashLeafData(Buffer.from(raws[i], "utf8"))); tree.leaves.push(leaves[i]); }
  return { tree, size: tree.size(), root: tree.root(), skipped, tornTail, capped: tree.size() >= maxLeaves, file };
}

// ---- the append lock: cli/alert-seq.mjs withFileLock ----------------------------------------------------
// The hook runs one process per event and parallel tool calls run in parallel processes, so the
// read-frontier / append / write-frontier cycle that hands out an index runs under an exclusive per-session
// lock file, with the alert sequence's own discipline: a lock is broken only when its holder is gone. An
// append that cannot get the lock within lockWaitMs still writes its leaf (one O_APPEND write, so lines
// never interleave) and returns index null: the leaf is never dropped and never given an index another leaf
// holds. Its line leaves the frontier's byte length behind, so the next locked append rebuilds the frontier.

// One write of one line. A file whose last byte is not "\n" (a torn tail) gets the newline in the same
// write, so the fragment is closed off as its own skipped line rather than merged into this leaf.
function writeLine(file, line, needsNewline) {
  const fd = openSync(file, "a", 0o600);
  try {
    const buf = Buffer.from((needsNewline ? "\n" : "") + line + "\n", "utf8");
    const n = writeSync(fd, buf);
    if (n !== buf.length) throw new Error(`context-tree: short write (${n}/${buf.length})`);
    return n;
  } finally { closeSync(fd); }
}
function endsWithoutNewline(file) {
  let fd;
  try { fd = openSync(file, "r"); } catch { return false; }
  try {
    const { size } = fstatSync(fd);
    if (size === 0) return false;
    const b = Buffer.alloc(1);
    readSyncAt(fd, b, size - 1);
    return b[0] !== 0x0a;
  } finally { closeSync(fd); }
}
const readSyncAt = (fd, b, pos) => readSync(fd, b, 0, 1, pos);
// Whether `line` + "\n" sits at byte offset `at` of the file.
function landedAt(file, at, line) {
  const want = Buffer.from(line + "\n", "utf8");
  const got = Buffer.alloc(want.length);
  const fd = openSync(file, "r");
  try { return readSync(fd, got, 0, want.length, at) === want.length && got.equals(want); } finally { closeSync(fd); }
}

// ---- the frontier (compact range) ----------------------------------------------------------------------

export const frontierFile = (sessionId, opts) => `${sessionFile(sessionId, opts)}.frontier`;
const popcount = (n) => { let c = 0; while (n > 0) { c += n & 1; n = Math.floor(n / 2); } return c; };
const fileBytes = (file) => { try { return statSync(file).size; } catch (e) { if (e && e.code === "ENOENT") return -1; throw e; } };

// { size, bytes, hashes: [Buffer] } or null. hashes run left to right: the perfect subtrees named by the set
// bits of size, highest first.
export function readFrontier(sessionId, { home = homedir() } = {}) { return readFrontierAt(frontierFile(sessionId, { home })); }
function readFrontierAt(ffile) {
  try {
    const j = JSON.parse(readFileSync(ffile, "utf8"));
    if (!j || j.v !== 1 || !Number.isSafeInteger(j.size) || j.size < 0 || !Number.isSafeInteger(j.bytes) || j.bytes < 0 || !Array.isArray(j.hashes)) return null;
    if (j.hashes.length !== popcount(j.size) || !j.hashes.every((h) => typeof h === "string" && SHA_RE.test(h))) return null;
    return { size: j.size, bytes: j.bytes, hashes: j.hashes.map((h) => Buffer.from(h, "hex")) };
  } catch { return null; }
}
function writeFrontierAt(ffile, fr) {
  const tmp = `${ffile}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ v: 1, size: fr.size, bytes: fr.bytes, hashes: fr.hashes.map((h) => h.toString("hex")) }), { mode: 0o600 });
  renameSync(tmp, ffile);
}
// The frontier of an in-memory tree.
export function frontierOf(tree) {
  const n = tree.size(), hashes = [];
  for (let k = tree.levels.length - 1; k >= 0; k--) if (Math.floor(n / 2 ** k) % 2 === 1) hashes.push(tree.levels[k][Math.floor(n / 2 ** k) - 1]);
  return { size: n, hashes };
}
// Fold one leaf hash into a frontier of `size` leaves: each trailing set bit of size merges one subtree.
export function frontierPush(hashes, size, lh) {
  const out = hashes.slice();
  let cur = toBuf(lh), n = size;
  while (n % 2 === 1) { cur = hashChildren(out.pop(), cur); n = Math.floor(n / 2); }
  out.push(cur);
  return out;
}
// The root: the frontier folded right to left, as rootBuf does. O(log n).
export function frontierRoot(hashes) {
  if (!hashes.length) return EMPTY_ROOT.toString("hex");
  let acc = hashes[hashes.length - 1];
  for (let i = hashes.length - 2; i >= 0; i--) acc = hashChildren(hashes[i], acc);
  return acc.toString("hex");
}

// The frontier for the session file as it is now (bytes long), rebuilt from the file when the cached one is
// missing or stale. Call holding the session lock. -> { fr, healed, skipped, tornTail }
function currentFrontier(sessionId, home, maxLeaves, ffile, bytes) {
  const fr = readFrontierAt(ffile);
  if (fr && fr.bytes === bytes) return { fr, healed: false, skipped: [], tornTail: false };
  const s = loadSession(sessionId, { home, maxLeaves });
  return { fr: { ...frontierOf(s.tree), bytes }, healed: true, skipped: s.skipped, tornTail: s.tornTail };
}

// ---- console upload state (contextTree "console") -------------------------------------------------------
// <file>.upload: { sent, since, lease, retryAt, rejects }. sent = leaves 0..sent-1 the console took (2xx).
// The hook marks a session for upload in the same locked step as its append, and takes the flush lease when
// enough is pending (UPLOAD_AT_LEAVES, or the oldest unsent leaf is UPLOAD_AT_AGE_MS old, or force at
// session end); the detached worker (flushContextTree) posts. The schedule is the allow trail's.
export const uploadFile = (sessionId, opts) => `${sessionFile(sessionId, opts)}.upload`;
export const UPLOAD_AT_LEAVES = 50;
export const UPLOAD_AT_AGE_MS = 30000;
export const UPLOAD_BATCH = 500;
export const UPLOAD_LEASE_MS = 60000;
export const UPLOAD_TIMEOUT_MS = 10000;
const nonNeg = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
function readUploadAt(ufile) {
  let j = null;
  try { j = JSON.parse(readFileSync(ufile, "utf8")); } catch { return null; }
  j = j && typeof j === "object" ? j : {};
  return { sent: nonNeg(j.sent), since: nonNeg(j.since), lease: nonNeg(j.lease), retryAt: nonNeg(j.retryAt), rejects: nonNeg(j.rejects) };
}
export function readUpload(sessionId, { home = homedir() } = {}) { return readUploadAt(uploadFile(sessionId, { home })); }
function writeUploadAt(ufile, st) {
  const tmp = `${ufile}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
  renameSync(tmp, ufile);
}
// A lease or retry time ahead of now by more than this module ever writes is not one it wrote: ignored.
const leaseHeld = (st, now) => st.lease > 0 && st.lease <= now && now - st.lease < UPLOAD_LEASE_MS;
const retryWaits = (st, now) => st.retryAt > now && st.retryAt - now <= BACKOFF_CAP_MS;
// Updates the upload state for a session of `size` leaves; -> true when this call took the lease.
function markUploadAt(ufile, size, now, force) {
  const st = readUploadAt(ufile) || { sent: 0, since: 0, lease: 0, retryAt: 0, rejects: 0 };
  if (st.sent > size) st.sent = size;
  const pending = size - st.sent;
  if (pending > 0 && !st.since) st.since = now;
  let due = false;
  if (pending > 0 && !leaseHeld(st, now) && !retryWaits(st, now) && (force || pending >= UPLOAD_AT_LEAVES || now - st.since >= UPLOAD_AT_AGE_MS)) { st.lease = now; due = true; }
  writeUploadAt(ufile, st);
  return due;
}

// appendLeaf(sessionId, leaf) -> { index, root, size, capped, skipped, tornTail, healed, uploadDue, unlocked? }
//   index/root: the leaf's position and the tree root including it, to stamp on the record.
//   capped: true when the session already holds maxLeaves; nothing is written and index is null.
//   healed: the frontier was missing or stale and was rebuilt from the session file by this append.
//   unlocked: true when the lock was not obtained; the leaf IS written, index and root are null.
//   upload: true (contextTree "console") also marks the session for upload; uploadDue says this call took
//   the flush lease and should start the worker.
export function appendLeaf(sessionId, leaf, { home = homedir(), maxLeaves = MAX_LEAVES, lockWaitMs = 200, retentionDays = RETENTION_DAYS, now = Date.now(), upload = false } = {}) {
  if (!isLeaf(leaf)) throw new TypeError("context-tree: not a content-free leaf");
  const file = sessionFile(sessionId, { home });
  ensureDir(home);
  const line = canonicalJson(pick(leaf));
  const ffile = `${file}.frontier`;
  const r = withFileLock(`${file}.lock`, () => {
    let bytes = fileBytes(file);
    const fresh = bytes < 0;
    if (fresh) bytes = 0;
    const { fr, healed, skipped, tornTail } = currentFrontier(sessionId, home, maxLeaves, ffile, bytes);
    if (fr.size >= maxLeaves) {
      if (healed) { try { writeFrontierAt(ffile, fr); } catch { /* rebuilt again next time */ } }
      return { index: null, root: frontierRoot(fr.hashes), size: fr.size, capped: true, skipped, tornTail, healed, uploadDue: false };
    }
    const n = writeLine(file, line, tornTail);
    // An append that could not get the lock writes without it, so its line can land between this append's
    // stat and its write. Then this leaf is not where the frontier says: the index and root come from the
    // file, and the frontier is left stale for the next append to rebuild.
    if (!landedAt(file, bytes + (tornTail ? 1 : 0), line)) {
      const s = loadSession(sessionId, { home, maxLeaves: Infinity });
      let index = null;
      for (let i = s.tree.leaves.length - 1; i >= 0; i--) if (canonicalJson(s.tree.leaves[i]) === line) { index = i; break; }
      return { index, root: s.root, size: s.size, capped: false, skipped: s.skipped, tornTail: s.tornTail, healed: true, uploadDue: false };
    }
    const next = { size: fr.size + 1, bytes: bytes + n, hashes: frontierPush(fr.hashes, fr.size, hashLeafData(Buffer.from(line, "utf8"))) };
    try { writeFrontierAt(ffile, next); } catch { /* the leaf is written; the next append rebuilds the frontier */ }
    let uploadDue = false;
    if (upload) { try { uploadDue = markUploadAt(`${file}.upload`, next.size, now, false); } catch { /* retried on the next append */ } }
    if (fresh) { try { sweepRetention({ home, days: retentionDays, now }); } catch { /* opportunistic */ } }
    return { index: fr.size, root: frontierRoot(next.hashes), size: next.size, capped: false, skipped, tornTail, healed, uploadDue };
  }, { waitMs: lockWaitMs, mode: 0o600 });
  if (!r.held) {
    writeLine(file, line, endsWithoutNewline(file));
    return { index: null, root: null, size: null, capped: false, unlocked: true };
  }
  return r.value;
}

// The session's current { size, root } without appending: the frontier when it matches the session file,
// else rebuilt (and rewritten) under the lock; with the lock busy, recomputed from the file without writing.
// A session with no file is the empty tree.
export function sessionHead(sessionId, { home = homedir(), maxLeaves = MAX_LEAVES, lockWaitMs = 200 } = {}) {
  const file = sessionFile(sessionId, { home });
  const ffile = `${file}.frontier`;
  const bytes = fileBytes(file);
  if (bytes < 0) return { size: 0, root: EMPTY_ROOT.toString("hex") };
  const fr = readFrontierAt(ffile);
  if (fr && fr.bytes === bytes) return { size: fr.size, root: frontierRoot(fr.hashes) };
  const r = withFileLock(`${file}.lock`, () => {
    const b = Math.max(0, fileBytes(file));
    const c = currentFrontier(sessionId, home, maxLeaves, ffile, b);
    if (c.healed) { try { writeFrontierAt(ffile, c.fr); } catch { /* rebuilt again next time */ } }
    return { size: c.fr.size, root: frontierRoot(c.fr.hashes) };
  }, { waitMs: lockWaitMs, mode: 0o600 });
  if (r.held) return r.value;
  const s = loadSession(sessionId, { home, maxLeaves });
  return { size: s.size, root: s.root };
}

// Session end (or any caller that wants pending leaves sent now): takes the flush lease when anything is
// pending for a session marked for upload. -> true when the caller should start the worker.
export function claimUpload(sessionId, { home = homedir(), now = Date.now(), force = true, lockWaitMs = 200 } = {}) {
  try {
    const file = sessionFile(sessionId, { home });
    const ufile = `${file}.upload`;
    if (!readUploadAt(ufile)) return false;
    const r = withFileLock(`${file}.lock`, () => markUploadAt(ufile, sessionHead(sessionId, { home, lockWaitMs: 0 }).size, now, force), { waitMs: lockWaitMs, mode: 0o600 });
    return r.held && r.value === true;
  } catch { return false; }
}

// The detached worker's body (contextTree "console"): for every session marked for upload, posts the leaves
// the console has not taken, UPLOAD_BATCH at a time, to POST /api/context-tree { v:1, sessionHash, leaves:
// [{ index, ...leaf }] }. sent advances only on a 2xx. Any other answer, or none, keeps the leaves and sets
// retryAt on the allow trail's schedule (1, 2, 4 minutes, capped at 5) and stops the run. While the hook's
// console back-off is active nothing is sent. Content-free: leaves are hashes, enums, sizes and times.
// -> { posted, batches, sessions, status, httpStatus }
export async function flushContextTree({ config, home = homedir(), fetchImpl = globalThis.fetch, now = () => Date.now(), backoff = readConsoleBackoff, lockWaitMs = 200 } = {}) {
  const out = { posted: 0, batches: 0, sessions: 0, status: "empty", httpStatus: 0 };
  const token = config && typeof config.installToken === "string" ? config.installToken.trim() : "";
  if (!token || !config.serverUrl) { out.status = "unenrolled"; return out; }
  let names = [];
  try { names = readdirSync(treeDir(home)); } catch { return out; }
  const ids = names.filter((n) => n.endsWith(".jsonl.upload")).map((n) => sessionIdOfFile(n.slice(0, -7))).filter((id) => id && ID_RE.test(id) && id !== NO_KEY);
  const locked = (id, fn) => { const f = sessionFile(id, { home }); const r = withFileLock(`${f}.lock`, () => fn(`${f}.upload`), { waitMs: lockWaitMs, mode: 0o600 }); return r.held ? r.value : undefined; };
  const release = (id) => { try { locked(id, (uf) => { const st = readUploadAt(uf); if (st) { st.lease = 0; writeUploadAt(uf, st); } }); } catch { /* the lease runs out */ } };
  try {
    if (backoff().active) {
      out.status = "console-backoff";
      for (const id of ids) locked(id, (uf) => { const st = readUploadAt(uf); if (st) { st.retryAt = now() + BACKOFF_BASE_MS; st.lease = 0; writeUploadAt(uf, st); } });
      return out;
    }
    for (const id of ids) {
      out.sessions++;
      try {
        for (;;) {
          const batch = locked(id, (uf) => {
            const st = readUploadAt(uf);
            if (!st) return null;
            const s = loadSession(id, { home });
            if (st.sent >= s.size) return [];
            return s.tree.leaves.slice(st.sent, st.sent + UPLOAD_BATCH).map((l, i) => ({ index: st.sent + i, ...l }));
          });
          if (!batch || !batch.length) break;
          let status = 0;
          try {
            const res = await fetchImpl(`${config.serverUrl}/api/context-tree`, { method: "POST", headers: { "Content-Type": "application/json", "X-Install-Token": token }, body: JSON.stringify({ v: 1, sessionHash: id, leaves: batch }), signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS) });
            status = res.status;
          } catch { status = 0; }
          out.httpStatus = status;
          const ok = status >= 200 && status < 300;
          const end = batch[batch.length - 1].index + 1;
          locked(id, (uf) => {
            const st = readUploadAt(uf) || { sent: 0, since: 0, lease: 0, retryAt: 0, rejects: 0 };
            if (ok) { st.sent = Math.max(st.sent, end); st.rejects = 0; st.retryAt = 0; st.since = 0; }
            else { st.rejects = Math.min(32, st.rejects + 1); st.retryAt = now() + backoffDelay(st.rejects); }
            writeUploadAt(uf, st);
          });
          if (!ok) { out.status = status ? "rejected" : "unreachable"; return out; }
          out.posted += batch.length;
          out.batches++;
          out.status = "posted";
        }
      } finally { release(id); }
    }
  } catch { out.status = "error"; }
  return out;
}

// contextTree from the VERIFIED policy only: "off" | "local" | "console"; absent or any other value
// "local". "console" sends leaves off the device, so it needs a policy with a signature envelope, as the
// allow trail does; a console value in a body without one reads "local".
export const CONTEXT_TREE_MODES = Object.freeze(["off", "local", "console"]);
export function contextTreeMode(policy) {
  const v = policy && typeof policy === "object" && !Array.isArray(policy) ? policy.contextTree : undefined;
  if (v === "off") return "off";
  if (v !== "console") return "local";
  const s = policy.policySig;
  return s && typeof s === "object" && typeof s.sig === "string" && s.sig ? "console" : "local";
}

// Delete session files (and abandoned locks, frontiers and upload states) last modified more than `days` days
// ago. -> { deleted }
export function sweepRetention({ home = homedir(), days = RETENTION_DAYS, now = Date.now() } = {}) {
  const d = treeDir(home);
  const cutoff = now - days * 86400000;
  let names = [];
  try { names = readdirSync(d); } catch { return { deleted: 0 }; }
  let deleted = 0;
  for (const n of names) {
    if (!n.endsWith(".jsonl") && !n.endsWith(".jsonl.lock") && !n.endsWith(".jsonl.frontier") && !n.endsWith(".jsonl.upload")) continue;
    const p = join(d, n);
    try {
      const st = lstatSync(p);
      if (st.isFile() && st.mtimeMs < cutoff) { unlinkSync(p); deleted++; }
    } catch { /* gone or not ours */ }
  }
  return { deleted };
}

// Every session id with a file under the tree directory.
export function listSessions({ home = homedir() } = {}) {
  let names = [];
  try { names = readdirSync(treeDir(home)); } catch { return []; }
  return names.filter((n) => n.endsWith(".jsonl")).map(sessionIdOfFile).filter((id) => id && ID_RE.test(id)).sort();
}

// The blobHash a blob would get, for the patient-zero lookup.
export function blobHashOf(bytes, { tenantKey } = {}) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  return buf.length >= SHA256_MIN_BYTES
    ? { blobHash: sha256(buf).toString("hex"), blobHashKind: "sha256", size: buf.length }
    : { blobHash: keyedBlob(buf, tenantKey), blobHashKind: "keyed", size: buf.length };
}
