// Did the turn really update the threat model (#85)? A dummy must not clear the check: a new empty model file,
// or a whitespace- or comment-only edit. An update counts when it is to a threat-model file that existed when
// the turn began (or a path the signed policy names in threatModel.paths) and its content, with comments and
// all whitespace removed, differs from what it was. A model created during the turn counts only when the
// policy's threatclPath validates it ("pass"). With a threatclPath set (and runnable on this platform), any
// result but "pass" leaves the alert. Whether the update is adequate is not judged.
//
// Ledger fields, content-free (keyed hashes, cli/session-ledger.mjs localHash):
//   tms  on the UserPromptSubmit row: { modelKey: contentDigest } for the repository's threat-model files when
//        the turn began (at most 64; tmt: 1 when the walk was truncated or there were more, so a file missing
//        from tms is of unknown age).
//   tmb  on a threat-model write's PreToolUse row: { modelKey: contentDigest | "" (unreadable) | 0 (no file) }
//        before that call; the fallback when a turn has no tms (a host without UserPromptSubmit).
import { readFileSync, statSync } from "node:fs";
import { localHash } from "./session-ledger.mjs";
import { codeText } from "./boundary-signals.mjs";
import { realOf, protectedPathHit } from "./oversight-surfaces.mjs";
import { findThreatModels, repoRoot, threatModelPolicy } from "./boundary-model.mjs";

const READ_MAX = 1_048_576;
const MAX_SNAPSHOT = 64;
// The real path (for a file that does not exist yet, its nearest existing ancestor's real path plus the rest).
export const keyOf = (abs) => localHash(`tm:${realOf(abs) || abs}`);

// The model with comments (per its extension: #, //, /* */ outside strings; <!-- --> in Markdown and HTML) and
// all whitespace removed. Linear: codeText is a single-pass quote scanner, the HTML comments an indexOf loop.
export function normalizeModel(text, path = "") {
  let t = codeText(String(text).slice(0, READ_MAX), path);
  if (/\.(?:md|markdown|html?)$/i.test(path)) {
    let out = "", i = 0;
    for (;;) {
      const a = t.indexOf("<!--", i);
      if (a < 0) { out += t.slice(i); break; }
      out += t.slice(i, a);
      const b = t.indexOf("-->", a + 4);
      if (b < 0) break;
      i = b + 3;
    }
    t = out;
  }
  return t.replace(/\s+/g, "");
}
export const digestOfText = (text, path) => localHash(`tmc:${normalizeModel(text, path)}`);
export const EMPTY_DIGEST = () => localHash("tmc:");
// The digest of the file now, null when it cannot be read whole.
export function modelDigest(path) {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > READ_MAX) return null;
    return digestOfText(readFileSync(path, "utf8"), path);
  } catch { return null; }
}
// tmb's value for a file before a write: its digest, "" when it exists but cannot be read whole, 0 when absent.
export function beforeValue(path) {
  try { statSync(path); } catch { return 0; }
  return modelDigest(path) ?? "";
}

// UserPromptSubmit: the repository's threat-model files as the turn begins.
export function boundaryTurnSnapshot(cwd, policy) {
  try {
    if (policy && policy.threatPolicy && policy.threatPolicy[85] === "disabled") return {};
    const tm = threatModelPolicy(policy, () => {});
    const found = findThreatModels(repoRoot(typeof cwd === "string" && cwd ? cwd : process.cwd()), tm);
    const tms = {};
    for (const f of found.files.slice(0, MAX_SNAPSHOT)) tms[keyOf(f)] = modelDigest(f) ?? "";
    return { tms, ...(found.truncated || found.files.length > MAX_SNAPSHOT ? { tmt: 1 } : {}) };
  } catch { return {}; }
}

// written: this repository's threat-model files the turn wrote (absolute). turnStart: the turn's prompt row (or
// null). before: { key: tmb value } from the earliest established write of each key. → per file
// { existed, declared, substantive }.
export function assessModelWrites(written, { turnStart = null, before = {}, tm, root }) {
  const snap = turnStart && turnStart.tms && typeof turnStart.tms === "object" ? turnStart : null;
  const empty = EMPTY_DIGEST();
  return written.map((f) => {
    const k = keyOf(f);
    let existed, prior;
    if (snap && Object.prototype.hasOwnProperty.call(snap.tms, k)) { existed = true; prior = snap.tms[k]; }
    else if (snap && !snap.tmt) { existed = false; prior = null; }
    else { const b = Object.prototype.hasOwnProperty.call(before, k) ? before[k] : 0; existed = b !== 0; prior = existed ? b : null; }
    const declared = !!(tm && tm.paths && tm.paths.length && protectedPathHit(f, tm, { cwd: root, real: true }));
    const now = modelDigest(f);
    // Unreadable before or now ("" / null) is never substantive: the change cannot be shown.
    const substantive = now !== null && (existed ? typeof prior === "string" && prior !== "" && now !== prior : declared && now !== empty);
    return { existed, declared, substantive };
  });
}
