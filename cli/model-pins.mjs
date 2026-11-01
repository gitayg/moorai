// Model provenance pinning: run only the model files an administrator approved, by sha256.
//
// Static scanning (cli/model-scan.mjs) cannot see trojaned weights or a backdoor that waits for a trigger
// word. A pin answers a different question: is this the exact file the administrator approved? It proves
// which file runs, not that the file is free of a backdoor.
//
// WHO DECIDES. Only the root-owned admin binding (cli/server-mode.mjs systemConfig()) and the verified
// signed policy, in that order. The first of the two that carries either key decides both, wholesale: the
// admin binding's list is not widened by the policy's. User-writable state is never read here.
//
//   "modelPinMode": "off" | "report" | "ask" | "block"
//   "modelPins":    [{ "sha256": "<64 hex>", "name"?: string, "note"?: string }, …]
//
// Defaults and failure: neither key → "off". modelPins without a mode → "report". A mode that is not one
// of the four exact lowercase values → "block" (the administrator asked for pinning and the value cannot
// be read, so the strict reading applies). modelPins that is not an array, or an entry without a valid
// sha256, pins nothing (the entry is skipped, never widened to a match). Each problem is warned about by
// source and key, never the value, and flagged `invalid` for the posture report.
//
// The hash cache (~/.moorai/model-pin-hashes.json, 0600) maps a file's identity (real path, device, inode,
// size, mtime and ctime, hashed together: no path is stored) to its sha256, so a model too big to hash on
// the hook path can be checked against the sha256 the background scan computed. Any change to the file's
// content changes its ctime, which an unprivileged process cannot set back. The cache is user-writable: a
// same-user process that edits it can claim a pinned sha256 for an unpinned file. It is a measurement
// cache, not a trust source, and that limit is stated in docs/CAPABILITY_SPEC.md.
import { readFileSync, writeFileSync, mkdirSync, renameSync, statSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export const PIN_MODES = Object.freeze(["off", "report", "ask", "block"]);
export const PIN_CACHE_FILE = "model-pin-hashes.json";
export const PIN_CACHE_CAP = 5000;
export const MODEL_NOT_APPROVED = "MODEL_NOT_APPROVED";
const SHA = /^[0-9a-f]{64}$/;
const own = (o, k) => o !== null && typeof o === "object" && !Array.isArray(o) && Object.prototype.hasOwnProperty.call(o, k);
function defaultWarn(m) { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* a warning, never a decision */ } }

function normSha(v) {
  if (typeof v !== "string") return null;
  const s = v.trim().toLowerCase().replace(/^sha256[:-]/, "");
  return SHA.test(s) ? s : null;
}

// policy: the verified signed policy (or null). admin: the parsed admin binding (or null). Never throws.
// → { mode, source: "admin" | "policy" | "default", pins: Map<sha256, { name, note }>, invalid: boolean }
export function resolveModelPins(policy, { admin = null, warn = defaultWarn } = {}) {
  const w = typeof warn === "function" ? (m) => { try { warn(m); } catch { /* never throws */ } } : () => {};
  try {
    for (const [src, label, source] of [[admin, "admin binding", "admin"], [policy, "signed policy", "policy"]]) {
      if (!own(src, "modelPinMode") && !own(src, "modelPins")) continue;
      let invalid = false, mode;
      if (own(src, "modelPinMode")) {
        if (PIN_MODES.includes(src.modelPinMode)) mode = src.modelPinMode;
        else { mode = "block"; invalid = true; w(`modelPinMode in the ${label} is not one of ${PIN_MODES.join(", ")}; block applies`); }
      } else mode = "report";
      const pins = new Map();
      if (own(src, "modelPins")) {
        const list = src.modelPins;
        if (!Array.isArray(list)) { invalid = true; w(`modelPins in the ${label} is not a list; nothing is pinned`); }
        else {
          let bad = 0;
          for (const e of list.slice(0, 100_000)) {
            const sha = normSha(e && typeof e === "object" ? e.sha256 : null);
            if (!sha) { bad++; continue; }
            pins.set(sha, { name: typeof e.name === "string" ? e.name.slice(0, 200) : null, note: typeof e.note === "string" ? e.note.slice(0, 500) : null });
          }
          if (bad) { invalid = true; w(`modelPins in the ${label}: ${bad} entr${bad === 1 ? "y has" : "ies have"} no valid sha256 and pin nothing`); }
        }
      }
      return { mode, source, pins, invalid };
    }
  } catch { return { mode: "block", source: "default", pins: new Map(), invalid: true }; }
  return { mode: "off", source: "default", pins: new Map(), invalid: false };
}

export const pinsActive = (cfg) => !!cfg && cfg.mode !== "off";

// A scan record's approval. → "pinned" | "not-approved" | "unverified" (no sha256: over the size cap,
// unreadable), or null when pinning is off.
export function approvalOf(sha256, cfg) {
  if (!pinsActive(cfg)) return null;
  const s = normSha(sha256);
  if (!s) return "unverified";
  return cfg.pins.has(s) ? "pinned" : "not-approved";
}

// Adds `pin` to a scan record and moves its verdict to "not-approved" when the file is not pinned and the
// static verdict is no worse than clean. unsafe and suspicious are never lowered or replaced: a pin never
// overrides a static finding, and an unpinned unsafe file stays "unsafe" (with pin "not-approved").
export function applyPins(rec, cfg) {
  const a = approvalOf(rec && rec.sha256, cfg);
  if (!a) return rec;
  rec.pin = a;
  if (a !== "pinned" && rec.verdict !== "unsafe" && rec.verdict !== "suspicious") rec.verdict = "not-approved";
  return rec;
}

export function sizeClass(n) {
  const v = Number(n) || 0;
  if (v < 10 * 1024 ** 2) return "<10MB";
  if (v < 100 * 1024 ** 2) return "10-100MB";
  if (v < 1024 ** 3) return "100MB-1GB";
  if (v < 10 * 1024 ** 3) return "1-10GB";
  return ">10GB";
}
export const hashPrefix = (sha) => { const s = normSha(sha); return s ? s.slice(0, 12) : null; };

// ---- the hash cache ----
// The file's identity at this instant, or null. Hashed; no path is kept.
export function fileIdentity(path) {
  try {
    const st = statSync(path);
    if (!st.isFile()) return null;
    let real = path;
    try { real = realpathSync(path); } catch { /* keep the path */ }
    const key = createHash("sha256").update(`${real}\0${st.dev}\0${st.ino}\0${st.size}\0${st.mtimeMs}\0${st.ctimeMs}`).digest("hex").slice(0, 32);
    return { key, size: st.size };
  } catch { return null; }
}
export function readPinCache(stateDir) {
  try { const o = JSON.parse(readFileSync(join(stateDir, PIN_CACHE_FILE), "utf8")); return o && typeof o.files === "object" && o.files && !Array.isArray(o.files) ? o.files : {}; } catch { return {}; }
}
export function cachedSha(stateDir, ident, cache = null) {
  if (!ident) return null;
  const files = cache || readPinCache(stateDir);
  return normSha(files[ident.key]);
}
// Records sha256 for the identity taken BEFORE hashing, only when the file still has that identity after
// (a file rewritten mid-hash is not remembered). entries: [{ before, path, sha256 }]. Never throws.
export function rememberHashes(stateDir, entries) {
  try {
    const add = [];
    for (const e of entries || []) {
      const sha = normSha(e && e.sha256);
      if (!sha || !e.before) continue;
      const after = fileIdentity(e.path);
      if (after && after.key === e.before.key) add.push([e.before.key, sha]);
    }
    if (!add.length) return;
    const files = readPinCache(stateDir);
    for (const [k, s] of add) { delete files[k]; files[k] = s; }
    const keys = Object.keys(files);
    if (keys.length > PIN_CACHE_CAP) for (const k of keys.slice(0, keys.length - PIN_CACHE_CAP)) delete files[k];
    mkdirSync(stateDir, { recursive: true });
    const file = join(stateDir, PIN_CACHE_FILE), tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ files }), { mode: 0o600 });
    renameSync(tmp, file);
  } catch { /* a lost cache costs one re-hash */ }
}
