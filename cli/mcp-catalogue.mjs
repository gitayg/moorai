// The open, signed MCP server and skill catalogue: the on-device half. Sign (for the generator),
// verify, fetch, cache, and map a catalogue entry onto MCP reputation signals (cli/mcp-reputation.mjs).
// data/mcp-catalogue.js holds the format, the signed bytes and validation.
//
// TRUST. A catalogue is used only after its ed25519 signature verifies against a key the device got out
// of band: the signed policy's mcpCatalogue.publicKeys, MOORAI_CATALOGUE_PUBKEY (MDM), the root-owned
// /etc/moorai/catalogue.pub, or data/mcp-catalogue-keys.js (empty until the owner publishes a key). With
// no key at all a catalogue is NOT trusted (unlike a policy, which is "unanchored"): nothing breaks
// without it, so there is no compatibility reason to accept an unverifiable one. The cached copy lives in
// the user's writable state, so it is re-verified on every read, and nothing in that file decides freshness
// on its own: a fetch time in the future makes the copy stale, a catalogue past its signed expiresAt
// (mandatory) is refused outright, cached or fetched, so an old signed catalogue cannot be replayed
// forever, and a copy whose seq is below the highest seq this device accepted from that key (mcp-catalogue.seq.json) is
// refused. The mark sits in the same writable directory, so a local user who rewrites both files can
// still hold an older signed catalogue until the next refresh, at most 24 h.
//
// ONE DIRECTION. A catalogue only ever ADDS risk signals (do-not-install, review, caution). A
// "no-findings" verdict is evidence only and never raises a score, so deleting or withholding the
// catalogue can only return a device to its no-catalogue verdicts.
//
// NETWORK. Only when the policy names an https URL (mcpCatalogue.url): one bare GET for the whole file,
// no server name in it, at most once a day; MOORAI_OFFLINE=1 serves the cached copy and never fetches.
import { createHash, sign as cryptoSign, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync, readdirSync, lstatSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { parseTrustedKeys, publicKeyId } from "./hook-core.mjs";
import { STATE_DIR } from "./state-dirs.mjs";
import { isOffline } from "./mcp-package/endpoints.mjs";
import { signal } from "../data/mcp-reputation.js";
import { CATALOGUE_FORMAT, CATALOGUE_VERSION, CATALOGUE_SIG_VERSION, catalogueCanonical, catalogueDigest, validateCatalogue, entryKey } from "../data/mcp-catalogue.js";
import { BUILTIN_CATALOGUE_KEYS } from "../data/mcp-catalogue-keys.js";

export const CATALOGUE_FILE = "mcp-catalogue.json";
export const CATALOGUE_SEQ_FILE = "mcp-catalogue.seq.json";
export const DEFAULT_ANCHOR_FILE = "/etc/moorai/catalogue.pub";
const TTL_MS = 24 * 3600 * 1000;
const SKEW_MS = 5 * 60 * 1000;
const MAX_BYTES = 16 * 1024 * 1024;

// ---- sign / verify ------------------------------------------------------------------------------

function signedBytes(cat) {
  return Buffer.from(catalogueCanonical({ v: CATALOGUE_SIG_VERSION, seq: cat.seq, issuedAt: String(cat.issuedAt), digest: catalogueDigest(cat) }));
}

export function signCatalogue(body, privateKey) {
  const { sig: _drop, ...b } = body || {};
  const sig = cryptoSign(null, signedBytes(b), privateKey).toString("base64");
  return { ...b, sig: { v: CATALOGUE_SIG_VERSION, alg: "ed25519", keyId: publicKeyId(createPublicKey(privateKey)), sig } };
}

// → { trusted, status, keyId? }  status: ok | no-anchor | unsigned | malformed | untrusted | expired
export function verifyCatalogue(cat, { keys = [], now = Date.now() } = {}) {
  if (!cat || typeof cat !== "object" || Array.isArray(cat) || cat.catalogue !== CATALOGUE_FORMAT || cat.v !== CATALOGUE_VERSION) return { trusted: false, status: "malformed" };
  if (!keys.length) return { trusted: false, status: "no-anchor" };
  const s = cat.sig;
  if (!s || typeof s !== "object" || typeof s.sig !== "string" || !s.sig) return { trusted: false, status: "unsigned" };
  if (Number(s.v) !== CATALOGUE_SIG_VERSION || s.alg !== "ed25519") return { trusted: false, status: "malformed" };
  if (!Number.isInteger(cat.seq) || typeof cat.issuedAt !== "string") return { trusted: false, status: "malformed" };
  const msg = signedBytes(cat);
  const sig = Buffer.from(s.sig, "base64");
  const hit = keys.find((k) => { try { return cryptoVerify(null, msg, k, sig); } catch { return false; } });
  if (!hit) return { trusted: false, status: "untrusted" };
  if (validateCatalogue(cat).length) return { trusted: false, status: "malformed" };
  if (Date.parse(cat.expiresAt) <= now) return { trusted: false, status: "expired", keyId: publicKeyId(hit) };
  return { trusted: true, status: "ok", keyId: publicKeyId(hit) };
}

// policyKeys: the signed policy's mcpCatalogue.publicKeys (base64 SPKI DER or PEM strings).
export function catalogueTrustKeys({ policyKeys = [], env = process.env, anchorFile = DEFAULT_ANCHOR_FILE, builtin = BUILTIN_CATALOGUE_KEYS } = {}) {
  const parts = [...builtin, ...(Array.isArray(policyKeys) ? policyKeys.filter((k) => typeof k === "string") : [])];
  if (env && typeof env.MOORAI_CATALOGUE_PUBKEY === "string") parts.push(env.MOORAI_CATALOGUE_PUBKEY);
  if (anchorFile) { try { parts.push(readFileSync(anchorFile, "utf8")); } catch { /* no anchor file */ } }
  const seen = new Set(), out = [];
  for (const k of parseTrustedKeys(parts.join("\n"))) { const id = publicKeyId(k); if (id && !seen.has(id)) { seen.add(id); out.push(k); } }
  return out;
}

// ---- entry → reputation signals -----------------------------------------------------------------

const VERDICT_CODE = { "do-not-install": "catalogue-do-not-install", review: "catalogue-review", caution: "catalogue-caution" };
const VERDICT_EVIDENCE = { "no-findings": "catalogue-scanned-no-findings", "not-scanned": "catalogue-listed-not-scanned" };
const NONE = () => ({ signals: [], evidence: [] });

function findEntry(cat, ecosystem, name) {
  if (!cat || !Array.isArray(cat.entries)) return null;
  const k = `${ecosystem}:${String(name || "").toLowerCase()}`;
  return cat.entries.find((e) => e && entryKey(e) === k) || null;
}

// id = serverIdentity(decl) from cli/mcp-reputation.mjs; version = the resolved version or "unresolved".
export function catalogueSignals(cat, id, version) {
  if (!cat || !id || !(id.kind === "npm" || id.kind === "pypi") || !id.ref) return NONE();
  const e = findEntry(cat, id.kind, id.ref.name);
  if (!e) return NONE();
  if (e.status === "do-not-install") return { signals: [signal("catalogue-do-not-install")], evidence: [] };
  if (!version || version === "unresolved") return { signals: [], evidence: ["catalogue-listed"] };
  const v = (e.versions || []).find((x) => x && x.version === version);
  if (!v) return { signals: [], evidence: ["catalogue-other-version"] };
  if (VERDICT_CODE[v.verdict]) return { signals: [signal(VERDICT_CODE[v.verdict])], evidence: [] };
  return { signals: [], evidence: VERDICT_EVIDENCE[v.verdict] ? [VERDICT_EVIDENCE[v.verdict]] : [] };
}

// → "listed-match" | "digest-mismatch" | "listed" | "do-not-install" | "unknown"
export function catalogueSkillStatus(cat, name, treeSha256) {
  const e = findEntry(cat, "skill", name);
  if (!e) return "unknown";
  if (e.status === "do-not-install") return "do-not-install";
  const digests = (e.versions || []).map((v) => v && v.treeSha256).filter(Boolean);
  if (!digests.length) return "listed";
  const v = (e.versions || []).find((x) => x && x.treeSha256 === treeSha256);
  if (!v) return "digest-mismatch";
  return v.verdict === "do-not-install" ? "do-not-install" : "listed-match";
}

// ---- tree digest (skills, and the generator's --scan of a local package copy) -----------------------

const MAX_TREE_FILES = 5000, MAX_TREE_DEPTH = 16;
export function skillTreeDigest(root) {
  const files = [];
  const rec = (dir, depth) => {
    if (depth > MAX_TREE_DEPTH || files.length >= MAX_TREE_FILES) return;
    let ents;
    try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name === ".git" || e.name === "node_modules") continue;
      const full = join(dir, e.name);
      let st;
      try { st = lstatSync(full); } catch { continue; }
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) rec(full, depth + 1);
      else if (st.isFile() && files.length < MAX_TREE_FILES) files.push(full);
    }
  };
  rec(root, 0);
  const rows = files.map((f) => {
    let h = "unreadable";
    try { h = createHash("sha256").update(readFileSync(f)).digest("hex"); } catch { /* keep marker */ }
    return `${relative(root, f).split("\\").join("/")}\0${h}\n`;
  }).sort();
  return createHash("sha256").update(rows.join("")).digest("hex");
}

// ---- cache + fetch --------------------------------------------------------------------------------

function readJson(p) { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } }
function writeAtomic(path, obj) {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(obj));
    renameSync(tmp, path);
  } catch { /* the cache is an optimisation */ }
}

const pol = (p) => (p && typeof p === "object" ? p : {});
const keysFor = (o) => catalogueTrustKeys({ policyKeys: pol(o.policy).publicKeys, env: o.env || process.env, anchorFile: o.anchorFile === undefined ? DEFAULT_ANCHOR_FILE : o.anchorFile, builtin: o.builtin || BUILTIN_CATALOGUE_KEYS });

// The highest seq accepted per publisher key: { "<keyId>": seq }.
function readMarks(stateDir) { const m = readJson(join(stateDir, CATALOGUE_SEQ_FILE)); return m && typeof m === "object" && !Array.isArray(m) ? m : {}; }
function markOf(stateDir, keyId) { const n = readMarks(stateDir)[keyId]; return Number.isInteger(n) ? n : -1; }
function raiseMark(stateDir, keyId, seq) {
  const m = readMarks(stateDir);
  if (Number.isInteger(m[keyId]) && m[keyId] >= seq) return;
  m[keyId] = seq;
  writeAtomic(join(stateDir, CATALOGUE_SEQ_FILE), m);
}

// Past expiresAt a catalogue's positive verdicts are no longer trusted, but its deny side still is: the
// do-not-install entries and the negative per-version verdicts (do-not-install, review, caution) of the
// last verified copy. Dropping those on expiry would fail open (withholding a refresh would clear a
// denylist). An advisory entry is kept through its do-not-install status or a negative verdict.
const DENY_VERDICTS = new Set(["do-not-install", "review", "caution"]);
export function expiredDenyCatalogue(cat) {
  const entries = [];
  for (const e of (cat && Array.isArray(cat.entries) ? cat.entries : [])) {
    if (!e || typeof e !== "object") continue;
    const versions = (Array.isArray(e.versions) ? e.versions : []).filter((v) => v && DENY_VERDICTS.has(v.verdict));
    if (e.status === "do-not-install" || versions.length) entries.push({ ...e, versions });
  }
  return { ...cat, entries };
}

const MEMO = new Map();
// → { status, catalogue|null, keyId?, fetchedAt?, url?, expiredDeny? }
//   status: absent | disabled | ok | rollback-refused | <verifyCatalogue status>
//   expiredDeny: with status expired, the deny-only view of the last verified copy (expiredDenyCatalogue)
export function readCatalogue(opts = {}) {
  const stateDir = opts.stateDir || STATE_DIR;
  if (pol(opts.policy).enabled === false) return { status: "disabled", catalogue: null };
  const path = join(stateDir, CATALOGUE_FILE);
  let st;
  try { st = statSync(path); } catch { return { status: "absent", catalogue: null }; }
  const keys = keysFor(opts);
  const now = opts.now || Date.now();
  const memoKey = `${path}\0${st.mtimeMs}\0${st.size}\0${keys.map(publicKeyId).join(",")}`;
  let out = MEMO.get(memoKey);
  if (!out) {
    const f = readJson(path);
    const cat = f && f.catalogue;
    const v = verifyCatalogue(cat, { keys, now: -Infinity }); // memoised per file; expiry is checked per read below
    out = v.trusted ? { status: "ok", catalogue: cat, keyId: v.keyId, fetchedAt: f.fetchedAt, url: f.url } : { status: v.status, catalogue: null };
    MEMO.clear();
    MEMO.set(memoKey, out);
  }
  if (out.status !== "ok") return out;
  if (out.catalogue.seq < markOf(stateDir, out.keyId)) return { status: "rollback-refused", catalogue: null };
  if (Date.parse(out.catalogue.expiresAt) <= now) return { status: "expired", catalogue: null, keyId: out.keyId, expiredDeny: expiredDenyCatalogue(out.catalogue) };
  raiseMark(stateDir, out.keyId, out.catalogue.seq);
  return out;
}

export function catalogueUrl(p) {
  if (typeof pol(p).url !== "string") return null;
  try {
    const u = new URL(p.url);
    const loop = u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost");
    return u.protocol === "https:" || loop ? u.origin + u.pathname : null;
  } catch { return null; }
}

// → readCatalogue's shape + { refresh }  refresh: skipped | fresh | ok | offline | fetch-failed | too-large
//   | unparseable | rollback-refused | <verifyCatalogue status>
export async function refreshCatalogue(opts = {}) {
  const stateDir = opts.stateDir || STATE_DIR;
  const p = pol(opts.policy);
  const cur = readCatalogue(opts);
  const url = catalogueUrl(p);
  if (!url || p.enabled === false) return { ...cur, refresh: "skipped" };
  const now = opts.now || Date.now();
  const at = Number(cur.fetchedAt);
  const fresh = cur.catalogue && cur.url === url && Number.isFinite(at) && at <= now + SKEW_MS && now - at < TTL_MS;
  if (fresh) return { ...cur, refresh: "fresh" };
  if (isOffline()) return { ...cur, refresh: "offline" };
  let text;
  try {
    const res = await (opts.fetchImpl || globalThis.fetch)(url, { method: "GET", redirect: "error", signal: AbortSignal.timeout(5000) });
    if (!res || !res.ok) return { ...cur, refresh: "fetch-failed" };
    text = await res.text();
  } catch { return { ...cur, refresh: "fetch-failed" }; }
  if (text.length > MAX_BYTES) return { ...cur, refresh: "too-large" };
  let cat;
  try { cat = JSON.parse(text); } catch { return { ...cur, refresh: "unparseable" }; }
  const v = verifyCatalogue(cat, { keys: keysFor(opts), now });
  if (!v.trusted) return { ...cur, refresh: v.status };
  if ((cur.catalogue && cat.seq < cur.catalogue.seq) || cat.seq < markOf(stateDir, v.keyId)) return { ...cur, refresh: "rollback-refused" };
  writeAtomic(join(stateDir, CATALOGUE_FILE), { url, fetchedAt: now, catalogue: cat });
  raiseMark(stateDir, v.keyId, cat.seq);
  return { status: "ok", catalogue: cat, keyId: v.keyId, fetchedAt: now, url, refresh: "ok" };
}
