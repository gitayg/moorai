// Safe, dependency-free extraction of a registry artifact (npm .tgz, PyPI sdist .tar.gz / .zip, wheel).
//
// The archive is UNTRUSTED. Guarantees, each pinned by test/mcp-package-security.test.mjs:
//   * nothing is written outside `dest` — absolute names, drive letters, NUL bytes and any `..` segment
//     are refused, and the resolved path is re-checked to sit under `dest`;
//   * no symlink / hardlink / device entry is ever created, so nothing can be followed later;
//   * files are created with `wx` (never overwrite, never write through an existing entry) and 0644;
//   * caps on entry count, per-file size and total uncompressed size — a bomb stops, it does not fill disk.

import { gunzipSync, inflateRawSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";

// Caps are overridable from the environment so a small container can lower them (and a big scan can
// raise them) without a code change: MOORAI_SCAN_MAX_EXTRACT_MB / MOORAI_SCAN_MAX_FILE_MB.
export function envMb(name, dflt) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v * 1024 * 1024) : dflt;
}

export const LIMITS = {
  // 25000 scannable files: a published package is far below it, and a large source monorepo (metabase,
  // posthog) finishes inside it now that unreadable files are dropped during extraction. Hitting it is
  // still reported (archive-limits-exceeded) rather than passed off as a completed scan.
  maxEntries: Math.max(1, Math.floor(Number(process.env.MOORAI_SCAN_MAX_ENTRIES) || 25000)),
  maxFileBytes: envMb("MOORAI_SCAN_MAX_FILE_MB", 20 * 1024 * 1024),
  maxTotalBytes: envMb("MOORAI_SCAN_MAX_EXTRACT_MB", 512 * 1024 * 1024)
};

export function safeRelPath(name) {
  const n = String(name).replace(/\\/g, "/");
  if (!n || n.includes("\0")) return null;
  if (n.startsWith("/") || /^[a-zA-Z]:/.test(n)) return null;
  const parts = n.split("/").filter((p) => p !== "" && p !== ".");
  if (!parts.length || parts.some((p) => p === "..")) return null;
  return parts.join("/");
}

export function makeWriter(dest, limits) {
  const root = resolve(dest);
  const stats = { entries: 0, written: 0, skipped: 0, rejected: 0, bytes: 0, truncated: false };
  const target = (name) => {
    const rel = safeRelPath(name);
    if (!rel) return null;
    const full = resolve(root, rel);
    if (full !== root && !full.startsWith(root + sep)) return null;
    return full;
  };
  return {
    stats,
    tick() {
      stats.entries++;
      if (stats.entries > limits.maxEntries) { stats.truncated = true; return false; }
      return true;
    },
    dir(name) {
      const full = target(name);
      if (!full) { stats.rejected++; return; }
      mkdirSync(full, { recursive: true });
    },
    file(name, data) {
      const full = target(name);
      if (!full) { stats.rejected++; return; }
      if (data.length > limits.maxFileBytes) { stats.skipped++; return; }
      if (stats.bytes + data.length > limits.maxTotalBytes) { stats.truncated = true; return; }
      mkdirSync(join(full, ".."), { recursive: true });
      try {
        writeFileSync(full, data, { flag: "wx", mode: 0o644 });
        stats.bytes += data.length;
        stats.written++;
      } catch { stats.rejected++; }
    },
    skip() { stats.skipped++; }
  };
}

function cstr(buf, off, len) {
  const s = buf.subarray(off, off + len);
  const z = s.indexOf(0);
  return (z === -1 ? s : s.subarray(0, z)).toString("utf8");
}

function octal(buf, off, len) {
  if (buf[off] & 0x80) {
    let v = 0;
    for (let i = 1; i < len; i++) v = v * 256 + buf[off + i];
    return v;
  }
  const s = cstr(buf, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}

export function parsePax(data) {
  const out = {};
  let i = 0;
  const s = data.toString("utf8");
  while (i < s.length) {
    const sp = s.indexOf(" ", i);
    if (sp === -1) break;
    const len = parseInt(s.slice(i, sp), 10);
    if (!(len > 0)) break;
    const rec = s.slice(sp + 1, i + len - 1);
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

export function extractTar(buf, dest, limits = LIMITS) {
  const w = makeWriter(dest, limits);
  let off = 0;
  let paxPath = null;
  let longName = null;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const size = octal(h, 124, 12);
    const type = String.fromCharCode(h[156] || 48);
    const dataStart = off + 512;
    const dataEnd = dataStart + size;
    if (size < 0 || dataEnd > buf.length) throw new Error("truncated tar entry");
    const data = buf.subarray(dataStart, dataEnd);
    off = dataStart + Math.ceil(size / 512) * 512;

    if (type === "x") { paxPath = parsePax(data).path || null; continue; }
    if (type === "g") continue;
    if (type === "L") { longName = cstr(data, 0, data.length); continue; }

    let name = cstr(h, 0, 100);
    if (cstr(h, 257, 5) === "ustar") {
      const prefix = cstr(h, 345, 155);
      if (prefix) name = prefix + "/" + name;
    }
    if (longName) name = longName;
    if (paxPath) name = paxPath;
    longName = null; paxPath = null;

    if (!w.tick()) break;
    if (type === "0" || type === "\0" || type === "7") w.file(name, data);
    else if (type === "5") w.dir(name);
    else w.skip();
  }
  return w.stats;
}

export function extractZip(buf, dest, limits = LIMITS) {
  const w = makeWriter(dest, limits);
  const tail = Math.max(0, buf.length - 65557);
  let eocd = -1;
  for (let i = buf.length - 22; i >= tail; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("zip: no end-of-central-directory");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || p === 0xffffffff) throw new Error("zip64 not supported");
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw new Error("zip: bad central directory");
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const extAttr = buf.readUInt32LE(p + 38);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    p += 46 + nameLen + extraLen + commentLen;

    if (!w.tick()) break;
    const fileType = (extAttr >>> 16) & 0o170000;
    if (fileType === 0o120000) { w.skip(); continue; }
    if (name.endsWith("/")) { w.dir(name); continue; }
    if (size > limits.maxFileBytes) { w.skip(); continue; }
    if (local + 30 > buf.length || buf.readUInt32LE(local) !== 0x04034b50) throw new Error("zip: bad local header");
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + compSize);
    let data;
    if (method === 0) data = raw;
    else if (method === 8) {
      try { data = inflateRawSync(raw, { maxOutputLength: Math.max(size, 1) }); } catch { w.skip(); continue; }
    } else { w.skip(); continue; }
    if (data.length !== size) { w.skip(); continue; }
    w.file(name, data);
  }
  return w.stats;
}

// Detect by magic bytes, not by the (attacker-chosen) filename.
export function extractArchive(buf, dest, limits = LIMITS) {
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50) return { format: "zip", ...extractZip(buf, dest, limits) };
  let tar = buf;
  if (buf[0] === 0x1f && buf[1] === 0x8b) tar = gunzipSync(buf, { maxOutputLength: limits.maxTotalBytes + 512 * (limits.maxEntries + 2) });
  return { format: "tar", ...extractTar(tar, dest, limits) };
}
