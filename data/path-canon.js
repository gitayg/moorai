// Win32 path-name canonical forms, for every check that matches a path against a protected or memory surface.
//
// Windows opens the same file under several spellings that a plain string match does not equate
// (learn.microsoft.com/windows/win32/fileio/naming-a-file and dotnet/standard/io/file-path-formats):
//   trailing dots and spaces  Win32 path normalisation strips them from every path segment, so "CLAUDE.md.",
//                             "CLAUDE.md. " and ".git/config." name CLAUDE.md and .git/config (a "\\?\" path skips
//                             normalisation; it is canonicalised here all the same, which only fails closed).
//   alternate data streams    NTFS reads "name:stream" and "name:stream:$TYPE"; "name::$DATA" is the file's own
//                             content (learn.microsoft.com/windows/win32/fileio/file-streams).
//   8.3 short names           "CLAUDE~1.MD" (up to six characters, ~N, up to a three-character extension) is an
//                             alias NTFS may give a long name (learn.microsoft.com/windows/win32/fileio/naming-a-file,
//                             "Short vs. Long Names"); the alias is opened like the long name.
// These rules apply on EVERY platform: the agent may write to a Windows share, a WSL path or a repository a Windows
// machine checks out, and an extra form only adds matches (fails closed). The forms are added beside the path as
// written; nothing is taken away. Pure and browser-safe.

// A segment that is only dots and spaces ("." "..", "...") is left as it is.
const DOTS_ONLY = /^[. ]+$/;
const DRIVE = /^[A-Za-z]:/;

function trimDotsSpaces(s) {
  let e = s.length;
  while (e > 0 && (s.charCodeAt(e - 1) === 46 || s.charCodeAt(e - 1) === 32)) e--;
  return e > 0 ? s.slice(0, e) : s;
}

// One segment: a drive prefix ("C:") is kept, the stream suffix (":stream", ":stream:$TYPE", "::$DATA") is dropped
// and trailing dots and spaces are stripped, repeated until nothing changes ("CLAUDE.md. ::$DATA" -> "CLAUDE.md").
// A drive-relative "C:CLAUDE.md" becomes "C:/CLAUDE.md".
export function canonSegment(seg) {
  const s0 = String(seg);
  if (!s0 || DOTS_ONLY.test(s0)) return s0;
  let drive = "", s = s0;
  if (DRIVE.test(s)) { drive = s.slice(0, 2); s = s.slice(2); if (!s) return drive; }
  for (let i = 0; i < 8; i++) {
    const c = s.indexOf(":");
    let next = c > 0 ? s.slice(0, c) : s;
    if (!DOTS_ONLY.test(next)) next = trimDotsSpaces(next);
    if (next === s) break;
    s = next;
  }
  return drive ? `${drive}/${s}` : s;
}

// The whole path, separators as "/", every segment canonicalised.
export function winCanonical(path) {
  return String(path || "").replace(/\\/g, "/").split("/").map(canonSegment).join("/");
}

// An 8.3 short-name segment: 1-6 characters, ~N, an optional extension of up to three characters.
export const SHORT_NAME_RE = /^[^~\\/]{1,6}~\d+(\.[^.]{0,3})?$/;
const SHORT_PARTS = /^([^~\\/]{1,6})~\d+(?:\.([^.]{0,3}))?$/;
export const hasShortName = (path) => String(path || "").replace(/\\/g, "/").split("/").some((s) => SHORT_NAME_RE.test(s));

// The 8.3 alias rules (NTFS): leading dots dropped, the base is the part before the last dot with spaces and dots
// removed, the extension its first three characters, both upper-cased, "+,;=[]" read as "_". The alias is the first
// six base characters (fewer when a collision makes NTFS use two characters and a four-hex-digit hash, "CL1A2B~1").
const n83 = (s) => s.toUpperCase().replace(/[ .]/g, "").replace(/[+,;=[\]]/g, "_");
// Could `short` be the 8.3 alias of `long`? Fails toward a match: any long name the alias could abbreviate.
export function shortNameMatches(short, long) {
  const m = SHORT_PARTS.exec(String(short));
  if (!m) return false;
  const stem = m[1].toUpperCase(), ext = (m[2] || "").toUpperCase();
  const l = String(long || "").replace(/^\.+/, "");
  if (!l) return false;
  const dot = l.lastIndexOf(".");
  const base = n83(dot >= 0 ? l.slice(0, dot) : l), lext = n83(dot >= 0 ? l.slice(dot + 1) : "").slice(0, 3);
  if (ext !== lext) return false;
  if (base.startsWith(stem)) return true;
  const hashed = /^(.{1,2})[0-9A-F]{4}$/.exec(stem);
  return !!hashed && base.startsWith(hashed[1]);
}

// The candidate long names a short segment stands for, from a list of literal names and, for glob segments with
// wildcards, a long name built to fit both the glob segment and the alias (checked against both).
function globSegRe(seg) {
  let b = "";
  for (const c of seg) b += c === "*" ? "[^/]*" : c === "?" ? "[^/]" : c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${b}$`, "i");
}
function globFills(short, seg) {
  const m = SHORT_PARTS.exec(short);
  if (!m) return [];
  const stem = m[1], ext = (m[2] || "").toLowerCase();
  const w = seg.search(/[*?]/);
  const head = n83(seg.slice(0, w).replace(/^\.+/, ""));
  const tail = stem.toUpperCase().startsWith(head) ? stem.slice(head.length).toLowerCase() : "";
  const rest = seg.slice(w + 1).replace(/\*/g, "").replace(/\?/g, "x");
  const fills = seg[w] === "?" ? [tail[0] || "x"] : [tail, ext ? `${tail}.${ext}` : tail, ext ? `.${ext}` : "", ""];
  const re = globSegRe(seg);
  return [...new Set(fills.map((f) => seg.slice(0, w) + f + rest))].filter((c) => re.test(c) && shortNameMatches(short, c));
}
export function shortNameCandidates(short, names = [], globSegs = []) {
  const m = SHORT_PARTS.exec(String(short));
  if (!m) return [];
  const out = new Set([m[2] !== undefined ? `${m[1]}.${m[2]}` : m[1]]);
  for (const n of names) if (shortNameMatches(short, n)) out.add(n);
  for (const g of globSegs) {
    if (!g || g === "**") continue;
    if (!/[*?]/.test(g)) { if (shortNameMatches(short, g)) out.add(g); continue; }
    for (const c of globFills(short, g)) out.add(c);
  }
  return [...out];
}

// Every spelling of `path` with each short segment replaced by one of its candidates (the segment as written is
// one of them). → { forms, overflow }: overflow when there would be more than `max` (the caller fails closed).
export function expandShortNames(path, names = [], globSegs = [], max = 1024) {
  const segs = String(path || "").replace(/\\/g, "/").split("/");
  const options = segs.map((s) => (SHORT_NAME_RE.test(s) ? [s, ...shortNameCandidates(s, names, globSegs)] : [s]));
  let total = 1;
  for (const o of options) { total *= o.length; if (total > max) return { forms: [], overflow: true }; }
  let acc = [[]];
  for (const o of options) acc = acc.flatMap((a) => o.map((x) => [...a, x]));
  return { forms: acc.map((a) => a.join("/")), overflow: false };
}
