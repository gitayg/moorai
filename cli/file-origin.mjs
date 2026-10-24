// Where a file came from, without reading its content: the mark the operating system or the downloading
// application left on it. Origin-based session taint (data/session-risk.js, cli/session-state.mjs) calls
// fileOrigin on every path the agent reads, extracts or runs.
//
// fileOrigin(path, opts) -> null | { source, app, hostHash }
//   source   "quarantine"   macOS com.apple.quarantine is set (app: its third field, the downloading app)
//            "where-froms"  macOS com.apple.metadata:kMDItemWhereFroms is set and quarantine is not (the
//                           quarantine attribute was removed and the download URL left behind)
//            "zone"         Windows <path>:Zone.Identifier with ZoneId >= 3 (Internet or Restricted sites)
//            "download-dir" the path lies under the user's download directory and carries no mark
//                           (~/Downloads on every platform; on Linux also XDG_DOWNLOAD_DIR)
//   app      the downloading application's name from the quarantine record ("Chrome"), or null
//   hostHash the host of the first kMDItemWhereFroms URL (macOS) or of HostUrl / ReferrerUrl (Windows),
//            hashed with cli/content-hash.mjs contentHash (tenant-keyed), or null. The host is never returned
//            or stored in clear.
// null: the file has no mark and is not under a download directory, does not exist, or is not a regular file.
//
// HOW THE MARK IS READ. Node has no extended-attribute API.
//   macOS    /usr/bin/xattr -l <abs> (one spawn: the quarantine value and whether kMDItemWhereFroms exists),
//            then /usr/bin/xattr -px kMDItemWhereFroms <abs> only for a file that carries it (the value is a
//            binary plist, which `-l` cuts at the first NUL). /usr/bin/xattr is a native binary on current
//            macOS. Measured against /bin/ls -l@d, a zsh zgetattr script and a perl syscall: it was the fastest
//            (median per check in docs/CAPABILITY_SPEC.md).
//   Windows  fs reads the NTFS alternate data stream <path>:Zone.Identifier. No process is started.
//   Linux    no attribute is read; only the download-directory rule applies.
//
// CACHE. opts.cache = { get(key), set(key, value) } keyed by "<dev>:<ino>:<mtimeMs>:<size>", so a file is
// read once per content version. The cached value is { s, a, h } (source, app, hostHash) or null, never a path
// or a host. A mark removed later (xattr -d) does not change mtime, so the cached "outside" verdict stands: a
// stripped file still counts as outside. The download-directory rule is applied from the path on every call.
//
// FAIL CLOSED, NEVER THROWS. A mark that cannot be read (the spawn fails or times out, the stream cannot be
// opened for a reason other than "absent") is not cached, and the file counts as outside when it lies under a
// download directory; elsewhere the origin is unknown (null). opts.deadline (a performance.now() value) bounds
// the spawns of one hook call: past it no process is started and the same rule applies.
//
// PreToolUse and PostToolUse can both call it: synchronous, no state of its own beyond a per-process memo of the
// download directories. A cache miss on macOS costs one or two process starts; a hit costs one stat.
import { spawnSync } from "node:child_process";
import { readFileSync, statSync, realpathSync } from "node:fs";
import { resolve, join, win32, posix } from "node:path";
import os from "node:os";
import { contentHash } from "./content-hash.mjs";

export const ORIGIN_SOURCES = Object.freeze(["quarantine", "where-froms", "zone", "download-dir"]);
const XATTR = "/usr/bin/xattr";
const QUARANTINE = "com.apple.quarantine";
const WHERE_FROMS = "com.apple.metadata:kMDItemWhereFroms";
const SPAWN_MS = 1500;
const ERROR = Symbol("origin-read-error");

// "0081;6adca4d1;Chrome;FB371173-…" -> { flags, app }. The app field is set by the downloading program; only a
// short plain name is kept, anything else reads as "other".
export function parseQuarantine(value) {
  const s = String(value ?? "").trim();
  if (!s) return null;
  const f = s.split(";");
  const app = (f[2] || "").trim();
  return { flags: f[0] || "", app: !app ? null : /^[\w .()+-]{1,40}$/.test(app) ? app : "other" };
}

// The text of a Zone.Identifier stream -> { zoneId, hostUrl, referrerUrl } or null. INI-shaped:
//   [ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://…\r\nHostUrl=https://…
// UTF-16LE (with a byte-order mark) and UTF-8 are both accepted.
export function parseZoneIdentifier(input) {
  let text = input;
  if (Buffer.isBuffer(input)) text = input[0] === 0xff && input[1] === 0xfe ? input.subarray(2).toString("utf16le") : input.toString("utf8");
  text = String(text ?? "").replace(/^﻿/, "");
  if (!/\[ZoneTransfer\]/i.test(text)) return null;
  const val = (k) => { const m = text.match(new RegExp(`^[ \\t]*${k}[ \\t]*=[ \\t]*(.*?)[ \\t]*\\r?$`, "im")); return m ? m[1] : null; };
  const z = val("ZoneId");
  const zoneId = z !== null && /^\d{1,2}$/.test(z) ? Number(z) : null;
  if (zoneId === null) return null;
  return { zoneId, hostUrl: val("HostUrl"), referrerUrl: val("ReferrerUrl") };
}

// The strings of a kMDItemWhereFroms value: a binary plist (bplist00) or an XML plist, holding an array of
// URL strings (or one string). Bounded, never throws.
export function parseWhereFroms(buf) {
  try {
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf ?? ""), "latin1");
    if (b.length > 65536) return [];
    if (b.subarray(0, 8).toString("latin1") === "bplist00") return bplistStrings(b);
    return [...b.toString("utf8").matchAll(/<string>([^<]{1,2048})<\/string>/g)].map((m) => m[1]).slice(0, 16);
  } catch { return []; }
}
function bplistStrings(b) {
  if (b.length < 40) return [];
  const t = b.length - 32;
  const offSize = b[t + 6], refSize = b[t + 7];
  const num = Number(b.readBigUInt64BE(t + 8)), top = Number(b.readBigUInt64BE(t + 16)), tableAt = Number(b.readBigUInt64BE(t + 24));
  if (!offSize || !refSize || offSize > 8 || refSize > 8 || num > 4096 || top >= num || tableAt + num * offSize > t) return [];
  const uint = (at, n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + b[at + i]; return v; };
  const offset = (i) => uint(tableAt + i * offSize, offSize);
  const len = (at) => { const lo = b[at] & 0x0f; if (lo !== 0x0f) return [lo, at + 1]; const m = b[at + 1]; if ((m & 0xf0) !== 0x10) return [-1, at]; const n = 1 << (m & 0x0f); return [uint(at + 2, n), at + 2 + n]; };
  const str = (i) => {
    const at = offset(i);
    if (at >= t) return null;
    const kind = b[at] >> 4;
    const [n, s] = len(at);
    if (n < 0 || n > 4096) return null;
    if (kind === 0x5) return b.subarray(s, s + n).toString("latin1");
    if (kind === 0x6) { const u = Buffer.from(b.subarray(s, s + n * 2)); u.swap16(); return u.toString("utf16le"); }
    return null;
  };
  const at = offset(top);
  if (at >= t) return [];
  const kind = b[at] >> 4;
  if (kind === 0x5 || kind === 0x6) { const s = str(top); return s ? [s] : []; }
  if (kind !== 0xa) return [];
  const [n, s] = len(at);
  const out = [];
  for (let k = 0; k < Math.min(Math.max(n, 0), 16); k++) { const r = uint(s + k * refSize, refSize); if (r < num) { const v = str(r); if (v) out.push(v); } }
  return out;
}

// The lowercased host of a URL, or null (no host, not a URL).
export function hostOf(url) {
  try { const h = new URL(String(url || "").trim()).hostname.toLowerCase().replace(/^\[|\]$/g, ""); return h || null; } catch { return null; }
}

// XDG_DOWNLOAD_DIR from $XDG_CONFIG_HOME/user-dirs.dirs (default ~/.config/user-dirs.dirs). The value is
// "$HOME/…" or an absolute path (the format xdg-user-dirs-update writes). null when absent or malformed.
export function xdgDownloadDir({ home = os.homedir(), env = process.env, readFile = readFileSync } = {}) {
  try {
    const cfg = env && typeof env.XDG_CONFIG_HOME === "string" && env.XDG_CONFIG_HOME.startsWith("/") ? env.XDG_CONFIG_HOME : join(home, ".config");
    const text = String(readFile(join(cfg, "user-dirs.dirs"), "utf8"));
    const m = text.match(/^[ \t]*XDG_DOWNLOAD_DIR[ \t]*=[ \t]*"([^"\n]*)"/m);
    if (!m) return null;
    let v = m[1];
    if (v === "$HOME" || v === "$HOME/") return null; // the home directory itself is not a download directory
    if (v.startsWith("$HOME/")) v = posix.join(home, v.slice(6));
    else if (!v.startsWith("/")) return null;
    return v.replace(/\/+$/, "") || null;
  } catch { return null; }
}

// The download directories this rule watches, absolute. ~/Downloads everywhere; on Linux XDG_DOWNLOAD_DIR too.
const DL_MEMO = new Map();
export function downloadDirs({ platform = process.platform, home = os.homedir(), env = process.env, readFile = readFileSync } = {}) {
  const k = `${platform}\0${home}`;
  if (readFile === readFileSync && DL_MEMO.has(k)) return DL_MEMO.get(k);
  const p = platform === "win32" ? win32 : posix;
  const dirs = [p.join(home, "Downloads")];
  if (platform !== "win32" && platform !== "darwin") { const x = xdgDownloadDir({ home, env, readFile }); if (x && !dirs.includes(x)) dirs.push(x); }
  if (readFile === readFileSync) DL_MEMO.set(k, dirs);
  return dirs;
}

const fold = (s, ci) => (ci ? s.toLowerCase() : s);
// True when `path` is inside one of `dirs` (not the directory itself). Case-insensitive on macOS and Windows,
// whose default file systems are.
export function underDir(path, dirs, { platform = process.platform } = {}) {
  const win = platform === "win32", ci = win || platform === "darwin";
  const norm = (s) => fold(String(s).replace(win ? /\\/g : /$^/, "/").replace(/\/+$/, ""), ci);
  const p = norm(path);
  return dirs.some((d) => { const n = norm(d); return !!n && p.startsWith(n + "/"); });
}

function realOr(p) { try { return realpathSync(p); } catch { return p; } }

// The mark on one file: { s, a, h } | null | ERROR.
function readMark(abs, { platform, hash, spawn, readFile, deadline, now, home }) {
  if (platform === "darwin") {
    const env = { PATH: "/usr/bin:/bin", LC_ALL: "C", HOME: home };
    if (now() > deadline) return ERROR;
    const r = spawn(XATTR, ["-l", abs], { encoding: "latin1", timeout: SPAWN_MS, env, maxBuffer: 1 << 20 });
    if (!r || r.error || r.status === null) return ERROR;
    if (r.status !== 0) return /No such file/i.test(String(r.stderr || "")) ? null : ERROR;
    const out = String(r.stdout || "");
    const q = out.match(/^com\.apple\.quarantine: ([^\n]*)$/m);
    const wf = /^com\.apple\.metadata:kMDItemWhereFroms: /m.test(out);
    if (!q && !wf) return null;
    let h = null;
    if (wf && now() <= deadline) {
      const w = spawn(XATTR, ["-px", WHERE_FROMS, abs], { encoding: "latin1", timeout: SPAWN_MS, env, maxBuffer: 1 << 20 });
      if (w && !w.error && w.status === 0) {
        const hex = String(w.stdout || "").replace(/[^0-9a-f]/gi, "");
        const host = parseWhereFroms(Buffer.from(hex, "hex")).map(hostOf).find(Boolean);
        if (host) h = hash(host);
      }
    }
    if (q) { const pq = parseQuarantine(q[1]); return { s: "quarantine", a: pq ? pq.app : null, h }; }
    return { s: "where-froms", a: null, h };
  }
  if (platform === "win32") {
    let buf;
    try { buf = readFile(`${abs}:Zone.Identifier`); } catch (e) { return e && (e.code === "ENOENT" || e.code === "ENOTDIR") ? null : ERROR; }
    const z = parseZoneIdentifier(buf);
    if (!z || z.zoneId < 3) return null;
    const host = hostOf(z.hostUrl) || hostOf(z.referrerUrl);
    return { s: "zone", a: null, h: host ? hash(host) : null };
  }
  return null;
}

export function fileOrigin(path, { platform = process.platform, home = os.homedir(), env = process.env, cache = null, hash = contentHash, spawn = spawnSync, readFile = readFileSync, stat = statSync, deadline = Infinity, now = () => performance.now() } = {}) {
  try {
    if (typeof path !== "string" || !path || path.length > 4096 || /[\0\r\n]/.test(path)) return null;
    const abs = platform === "win32" ? win32.resolve(path) : resolve(path);
    const dirs = downloadDirs({ platform, home, env, readFile });
    const inDl = underDir(abs, dirs, { platform }) || underDir(realOr(abs), dirs.map(realOr), { platform });
    const dl = () => (inDl ? { source: "download-dir", app: null, hostHash: null } : null);
    let st;
    try { st = stat(abs); } catch { return null; }
    if (!st || !st.isFile()) return null;
    const key = `${st.dev}:${st.ino}:${st.mtimeMs}:${st.size}`;
    let mark = cache ? cache.get(key) : undefined;
    if (mark === undefined) {
      mark = readMark(abs, { platform, hash, spawn, readFile, deadline, now, home });
      if (mark !== ERROR && cache) cache.set(key, mark);
    }
    if (mark === ERROR || !mark) return dl();
    return { source: mark.s, app: mark.a ?? null, hostHash: mark.h ?? null };
  } catch { return null; }
}
