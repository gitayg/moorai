// Tier-2 (#65) — local secret-value egress detection ("Option C"). Reads local secret stores ON-DEVICE
// only, fingerprints each value as a one-way hash, and checks whether any value appears in an outbound
// flow (command / MCP arg / prompt) — verbatim, or in any encoded form cli/secret-forms.mjs lists (base64
// and base64url at every alignment, hex, percent-encoding, JSON escaping, reversed). The value itself is
// NEVER emitted — only the hash of the matched secret, the encoding and the source kind leave. This
// catches an agent shipping a real .env / cloud credential off the device even when the string isn't in
// a recognizable provider-token shape. Secrets the agent READ in the session join the same check through
// a tracker (cli/secret-taint.mjs), passed as `opts.tracker`.
import { readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { contentHash } from "./content-hash.mjs";
import { keyring, buildIndex, scanText } from "./secret-match.mjs";
import { recordOf, entriesOf } from "./secret-taint.mjs";

// Values too short or obviously non-secret (placeholders) are ignored to avoid false matches.
const PLACEHOLDER = /^(?:todo|tbd|changeme|placeholder|example|test|none|null|true|false|localhost|your[-_ ]?\w*|<[^>]*>|\$\{[^}]*\}|x{3,}|\*{3,}|\.{3,})$/i;
export function isSecretish(v) {
  if (!v || v.length < 8 || v.length > 512) return false;
  if (PLACEHOLDER.test(v)) return false;
  if (/^\d+$/.test(v)) return false;               // pure numbers (ports, timestamps)
  if (/^[a-z]+$/i.test(v) && v.length < 16) return false; // short plain words
  return /[^\w]|[A-Z].*[0-9]|[0-9].*[A-Z]|[-_./+=]/.test(v) || v.length >= 20; // some entropy / structure
}

export function parseEnv(text) {
  const out = [];
  for (const line of String(text).split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?[\w.-]+\s*=\s*(.+?)\s*$/);
    if (!m) continue;
    let v = m[1].trim().replace(/^["']|["']$/g, "");
    if (isSecretish(v)) out.push(v);
  }
  return out;
}

let _cache = null; // { dir, values: [{hash,value}] } — memoized per process, values stay in memory only
function loadLocalSecrets(cwd) {
  const dir = cwd || process.cwd();
  if (_cache && _cache.dir === dir) return _cache.values;
  const values = new Map(); // value -> hash (dedup)
  const add = (v) => { if (isSecretish(v) && !values.has(v)) values.set(v, contentHash(v)); };
  const readFileSafe = (p) => { try { const b = readFileSync(p); return b.includes(0) ? "" : b.subarray(0, 262144).toString("utf8"); } catch { return ""; } };
  // Project dotenv files
  try { for (const f of readdirSync(dir)) { if (f === ".env" || f.startsWith(".env.")) parseEnv(readFileSafe(join(dir, f))).forEach(add); } } catch { /* no dir access */ }
  // Well-known credential files (KEY=VALUE / INI-ish) — values only.
  for (const p of [join(homedir(), ".aws", "credentials"), join(homedir(), ".npmrc"), join(homedir(), ".netrc"), join(dir, ".git-credentials")]) {
    const t = readFileSafe(p);
    if (t) parseEnv(t.replace(/:/g, "=")).forEach(add); // tolerate `key: value`
  }
  const arr = [...values.entries()].map(([value, hash]) => ({ value, hash }));
  _cache = { dir, values: arr };
  return arr;
}

// The process's own keyring for store secrets when no tracker supplies one (values stay in memory).
let _procKr = null;
const procKr = () => (_procKr ||= keyring());
// Store records per keyring, built once per directory: the forms of every store value under that key,
// aligned with loadLocalSecrets (null where a value has no trackable form).
const _storeIx = new WeakMap(); // kr -> { dir, src, records }
function storeRecords(kr, cwd) {
  const values = loadLocalSecrets(cwd);
  const c = _storeIx.get(kr);
  if (c && c.src === values) return c.records;
  const records = values.map(({ value, hash }) => recordOf(kr, value, () => hash));
  _storeIx.set(kr, { src: values, records });
  return records;
}

// Every local or session-read secret present in `text`, content-free:
//   { matches: [{ hash, encoding, source: "store" | "session-read" }], truncated, exhausted }
// One match per secret: verbatim (whole text) first, else the first form the encoded scan meets.
// FAIL CLOSED: each of these adds a match with encoding "unverified", so #65's action applies —
//   source "scan-budget"   the scan's HMAC budget ran out (`exhausted`)
//   source "scan-cap"      text past the scan limits was not read (`truncated`: raw text over MAX_RAW, a
//                          decoded view over MAX_SCAN) while there was something to match
//   source "cap-overflow"  the tracker's session evicted or refused a secret it read, which is still live
// opts.tracker: { kr, entries(), overflowed?() } (cli/secret-taint.mjs).
export function egressMatches(text, cwd, opts = {}) {
  const t = String(text || "");
  const out = { matches: [], truncated: false, exhausted: false };
  if (!t) return out;
  const tracker = opts.tracker || null;
  const kr = tracker ? tracker.kr : procKr();
  const values = loadLocalSecrets(cwd);
  const records = storeRecords(kr, cwd);
  const done = new Set();
  values.forEach(({ value, hash }, i) => {
    if (!t.includes(value)) return;
    const sid = records[i] ? records[i].sid : `v${i}`;
    if (done.has(sid)) return;
    done.add(sid);
    out.matches.push({ hash, encoding: "raw", source: "store" });
  });
  if (tracker && typeof tracker.overflowed === "function" && tracker.overflowed()) out.matches.push({ hash: "overflow", encoding: "unverified", source: "cap-overflow" });
  const entries = [...entriesOf(records.filter(Boolean), "store"), ...(tracker ? tracker.entries() : [])];
  if (!entries.length) return out;
  const r = scanText(buildIndex(kr, entries), t);
  const bySid = new Map();
  for (const e of entries) if (!bySid.has(e.sid)) bySid.set(e.sid, e); // a store secret read again stays "store"
  for (const h of r.hits) {
    const e = bySid.get(h.sid);
    if (!e || done.has(h.sid)) continue;
    done.add(h.sid);
    out.matches.push({ hash: e.hash, encoding: h.enc, source: e.src });
  }
  out.truncated = r.truncated;
  if (r.exhausted) { out.exhausted = true; out.matches.push({ hash: "budget", encoding: "unverified", source: "scan-budget" }); }
  else if (r.truncated) out.matches.push({ hash: "truncated", encoding: "unverified", source: "scan-cap" });
  return out;
}

// Return the one-way hashes of any local secret VALUE that appears in `text`, verbatim or encoded.
// Content-free output: the caller emits only these hashes, never the value. Empty array = no local secret
// is leaking.
export function egressHits(text, cwd, opts) {
  return [...new Set(egressMatches(text, cwd, opts).matches.map((m) => m.hash))];
}

// What an unverified match (encoding "unverified": text past the scan limits, an exhausted HMAC budget, a
// session that lost tracked records or whose state could not be verified) does: "ask" (the default) holds the
// call for a person (a host with no prompt settles it by its existing rule), "block" applies #65's action,
// "report" only alerts. From the root-owned admin binding first, then the signed
// policy: `secretEgress.unverified`. A confirmed match always applies #65's action.
export const UNVERIFIED_LEVELS = Object.freeze(["ask", "block", "report"]);
export function unverifiedLevel(policy, admin) {
  for (const src of [admin, policy]) {
    const v = src && typeof src === "object" && src.secretEgress && typeof src.secretEgress === "object" ? src.secretEgress.unverified : undefined;
    if (UNVERIFIED_LEVELS.includes(v)) return v;
  }
  return "ask";
}
// The verdict for a set of matches: "deny" | "ask" | "report" (alert only) | null (no match).
// action: threatActionFor(policy, 65); level: unverifiedLevel(policy, admin).
export function secretEgressVerdict(matches, { action, level = "ask" }) {
  if (!matches || !matches.length) return null;
  const enforce = action === "block" || action === "kill";
  if (!enforce) return "report";
  if (matches.some((m) => m.encoding !== "unverified")) return "deny";
  return level === "ask" ? "ask" : level === "report" ? "report" : "deny";
}
