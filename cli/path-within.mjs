// Is path P inside root R? One rule, by normalised path SEGMENTS, for every location gate:
// cli/ai-install-locations.mjs (install roots, venvs, the native Claude Code folder, the AI app and browser
// locations), cli/ai-cli-parents.mjs (inLocation, temp and C:\Windows folders) and cli/ai-api-callers.mjs.
// A string prefix is never a containment test: "/usr/local/lib-old/x" is not inside "/usr/local/lib" and
// "C:\Program Files Extra\x" is not inside "C:\Program Files".
//
// Normalisation, per platform:
//   win32   "\" and "/" are separators. Case-insensitive (NTFS and ReFS default; compared with toLowerCase).
//           Absolute means a drive ("C:\…", the letter folded) or UNC ("\\server\share\…"). The Win32 file
//           namespace and device prefixes "\\?\C:\…", "\\.\C:\…", "\??\C:\…" read as "C:\…", and
//           "\\?\UNC\server\share\…" as "\\server\share\…". Any other "\\?\" or "\\.\" form (a volume GUID, a
//           pipe), a drive-relative "C:x", a rooted "\x" and a segment holding ":" (an alternate data stream)
//           are refused.
//   darwin  "/" only. Case-insensitive: the default APFS volume is case- and normalisation-insensitive, so
//           segments are compared NFC-normalised and lower-cased. A case-sensitive volume is still compared
//           insensitively (it can only widen a match to a sibling that differs in case).
//   other   (linux) "/" only. Case-sensitive, compared byte for byte.
// Repeated and trailing separators are dropped. A path holding a "." or ".." segment (on Windows, any segment
// of dots only) is REFUSED, never resolved: resolving ".." by text is wrong across a symlink, and every path
// these gates see comes from the kernel or realpath and has none. A refused or relative path is inside nothing.
//
// Roots may hold globs: "*" in a segment matches any run of characters within that one segment ("*" alone is
// any one segment), and a "*:" drive matches any drive letter (never a UNC share). "Inside" means strictly
// below: a root is not inside itself.

export const foldsCase = (platform) => platform === "win32" || platform === "darwin";
// A Windows-shaped path ("C:\…", "\\…", "//…" with a drive or prefix) is read with Windows rules wherever it is
// seen, so a Windows process row is judged the same on any host.
export const looksWindows = (p) => /^([A-Za-z]:[\\/]|\\\\|\\\?\?\\)/.test(String(p ?? ""));

const fold = (s, platform) => (platform === "darwin" ? s.normalize("NFC").toLowerCase() : platform === "win32" ? s.toLowerCase() : s);

// → { head, segs, keys } or null. head: "/" (POSIX), "c:" style drive, "//server/share" (UNC), "*:" (root
// glob). segs keep the original spelling; keys are what is compared.
export function splitPath(path, platform, { root = false } = {}) {
  let s = String(path ?? "");
  if (!s || s.includes("\0")) return null;
  let head;
  if (platform === "win32") {
    s = s.replace(/\\/g, "/");
    const pre = /^(\/\/[?.]\/|\/\?\?\/)/.exec(s);
    if (pre) {
      const rest = s.slice(pre[0].length);
      if (/^UNC\//i.test(rest)) s = `//${rest.slice(4)}`;
      else if (/^[A-Za-z]:\//.test(rest)) s = rest;
      else return null;
    }
    let m;
    if ((m = /^([A-Za-z]|\*):\/(.*)$/.exec(s))) {
      if (m[1] === "*" && !root) return null;
      head = `${m[1].toLowerCase()}:`;
      s = m[2];
    } else if ((m = /^\/\/([^/]+)\/([^/]+)(?:\/(.*))?$/.exec(s))) {
      if (m[1] === "?" || m[1] === ".") return null;
      head = `//${m[1]}/${m[2]}`;
      s = m[3] || "";
    } else return null;
  } else {
    if (!s.startsWith("/")) return null;
    head = "/";
  }
  const segs = s.split("/").filter(Boolean);
  for (const g of segs) {
    if (g === "." || g === "..") return null;
    if (platform === "win32" && (/^\.+$/.test(g) || g.includes(":"))) return null;
  }
  return { head: fold(head, platform), segs, keys: segs.map((g) => fold(g, platform)) };
}

const globRe = (k) => new RegExp(`^${k.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "s");
const segMatch = (rootKey, key) => (rootKey.includes("*") ? globRe(rootKey).test(key) : rootKey === key);
const headMatch = (rootHead, head) => rootHead === head || (rootHead === "*:" && /^[a-z]:$/.test(head));

// The segments of `path` below `root` (original spelling), or null when path is not strictly inside root.
export function within(path, root, platform) {
  const p = splitPath(path, platform), r = splitPath(root, platform, { root: true });
  if (!p || !r || !headMatch(r.head, p.head) || p.keys.length <= r.keys.length) return null;
  for (let i = 0; i < r.keys.length; i++) if (!segMatch(r.keys[i], p.keys[i])) return null;
  return p.segs.slice(r.keys.length);
}
export const isWithin = (path, root, platform) => within(path, root, platform) !== null;

// The leading segments of path (as split by splitPath) rendered back as a "/"-separated path: "C:/Users/u".
export function joinHead(sp, n) {
  const body = sp.segs.slice(0, n).join("/");
  if (sp.head === "/") return `/${body}`;
  return `${sp.head.startsWith("//") ? sp.head : sp.head.toUpperCase()}/${body}`;
}

// Two names (segments) equal under the platform's case rule.
export const sameName = (a, b, platform) => fold(String(a), platform) === fold(String(b), platform);
