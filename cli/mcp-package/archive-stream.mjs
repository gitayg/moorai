// Streaming tar extraction. Nothing is ever held in memory beyond the entry currently being written,
// so a 33 MB npm tarball and a 200 MB monorepo archive cost the same. Two shapes share one parser:
//
//   registry artifact   stripTop:false            — every entry is kept, names as the archive gives them
//   git repo archive    stripTop:true, subpath?   — the archive's top-level `<repo>-<sha>/` is stripped
//                                                   and, when a subpath is given, only entries under it
//                                                   are kept; everything else is skipped without being
//                                                   buffered. `skip` drops what is not the product
//                                                   (.git, node_modules, vendor …) before it costs a byte.
//
// Same guarantees as archive.mjs (makeWriter): no escape, no links, wx files, caps — the entry and byte
// caps count only the entries that are actually extracted.

import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { makeWriter, LIMITS, safeRelPath, parsePax } from "./archive.mjs";

const MAX_STREAM_BYTES = 2 * 1024 * 1024 * 1024;   // decompressed ceiling for the WHOLE archive

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

// Archive name → {rel, keep}. rel === null with keep === true means a hostile name: it is handed to the
// writer verbatim so the writer rejects (and counts) it rather than this filter silently dropping it.
function mapName(name, { stripTop, subpath, skip }) {
  const rel = safeRelPath(name);
  if (!rel) return { rel: null, keep: true };
  let inner = rel;
  if (stripTop) {
    const i = rel.indexOf("/");
    if (i < 0) return { rel: null, keep: false };      // the top-level directory itself
    inner = rel.slice(i + 1);
    if (subpath) {
      if (inner === subpath || !inner.startsWith(subpath + "/")) return { rel: null, keep: false };
      inner = inner.slice(subpath.length + 1);
    }
  }
  // `skip` is a regex (paths that are never the product) or a predicate (repo mode also drops what the
  // engine cannot read, so the entry budget is spent on scannable files).
  if (skip && (typeof skip === "function" ? skip(inner) : skip.test(inner))) return { rel: null, keep: false };
  return { rel: inner, keep: true };
}

// source: an async iterable of Buffers (an already-gunzipped tar byte stream).
// → {format:"tar", commit, matched, ...writer stats}
export async function extractTarStream(source, dest, { stripTop = false, subpath = "", skip = null, limits = LIMITS, maxStreamBytes = MAX_STREAM_BYTES } = {}) {
  const w = makeWriter(dest, limits);
  const sub = subpath ? safeRelPath(subpath) : "";
  if (subpath && !sub) throw new Error("bad subpath");
  const opts = { stripTop, subpath: sub, skip };
  let commit = null;
  let matched = 0;
  let pending = Buffer.alloc(0);
  let state = { kind: "header" };
  let paxPath = null, longName = null, total = 0, done = false;

  const onEntry = (h, data) => {
    const type = String.fromCharCode(h[156] || 48);
    if (type === "g") { const g = parsePax(data); if (g.comment && /^[0-9a-f]{40}$/.test(g.comment)) commit = g.comment; return; }
    if (type === "x") { paxPath = parsePax(data).path || null; return; }
    if (type === "L") { longName = cstr(data, 0, data.length); return; }
    let name = cstr(h, 0, 100);
    if (cstr(h, 257, 5) === "ustar") { const prefix = cstr(h, 345, 155); if (prefix) name = prefix + "/" + name; }
    if (longName) name = longName;
    if (paxPath) name = paxPath;
    longName = null; paxPath = null;
    const { rel, keep } = mapName(name, opts);
    if (!keep) return;
    if (!w.tick()) { done = true; return; }
    matched++;
    const target = rel === null ? name : rel;
    if (type === "0" || type === "\0" || type === "7") w.file(target, data);
    else if (type === "5") w.dir(target);
    else w.skip();
    if (w.stats.truncated) done = true;          // the byte cap was reached: stop reading the archive
  };

  // Does the header's entry need its data kept? Only for metadata records and kept entries.
  const wantsData = (h) => {
    const type = String.fromCharCode(h[156] || 48);
    if (type === "g" || type === "x" || type === "L") return true;
    let name = cstr(h, 0, 100);
    if (cstr(h, 257, 5) === "ustar") { const prefix = cstr(h, 345, 155); if (prefix) name = prefix + "/" + name; }
    if (longName) name = longName;
    if (paxPath) name = paxPath;
    return mapName(name, opts).keep;
  };

  for await (const chunk of source) {
    total += chunk.length;
    if (total > maxStreamBytes) { w.stats.truncated = true; done = true; break; }
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    let off = 0;
    for (;;) {
      if (done) break;
      if (state.kind === "header") {
        if (pending.length - off < 512) break;
        const h = pending.subarray(off, off + 512);
        if (h.every((b) => b === 0)) { done = true; break; }
        const size = octal(h, 124, 12);
        if (!(size >= 0)) throw new Error("bad tar header");
        const padded = Math.ceil(size / 512) * 512;
        state = { kind: "data", header: Buffer.from(h), size, padded, keep: wantsData(h), got: [], left: padded };
        off += 512;
      } else {
        const take = Math.min(state.left, pending.length - off);
        if (take <= 0 && state.left > 0) break;
        if (state.keep) {
          const already = state.padded - state.left;
          const useful = Math.max(0, Math.min(take, state.size - already));
          if (useful) state.got.push(Buffer.from(pending.subarray(off, off + useful)));
          if (already + useful > limits.maxFileBytes) { state.keep = "oversize"; state.got = []; }
        }
        state.left -= take;
        off += take;
        if (state.left === 0) {
          if (state.keep === true) onEntry(state.header, Buffer.concat(state.got));
          else {
            if (state.keep === "oversize") { w.tick(); w.skip(); }
            paxPath = null; longName = null;
          }
          state = { kind: "header" };
        }
      }
    }
    pending = pending.subarray(off);
    if (done) break;
  }
  if (typeof source.destroy === "function") source.destroy();
  if (!done && (state.kind !== "header" || pending.length)) throw new Error("truncated tar stream");
  return { format: "tar", commit, matched, ...w.stats };
}

// In-memory convenience wrapper kept for callers that already hold the gzipped bytes (tests).
export async function extractRepoSubpath(gzBuf, dest, subpath, limits = LIMITS) {
  const gunzip = createGunzip();
  Readable.from([gzBuf]).pipe(gunzip);
  return extractTarStream(gunzip, dest, { stripTop: true, subpath, limits });
}
