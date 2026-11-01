// Static model-file scanner: inspects model files WITHOUT loading or executing them and returns one
// content-free verdict per file — format, findings by class, severity, sha256.
//
//   pickle family  .pkl .pickle .joblib, legacy (non-zip) .pt/.pth/.ckpt/.bin   cli/model-scan-pickle.mjs
//   PyTorch zip    .pt .pth .bin .ckpt (every *.pkl entry, data.pkl included)    cli/model-scan-zip.mjs
//   Keras          .keras (config.json), .h5/.hdf5 (model_config, bounded search) cli/model-scan-keras.mjs
//   TF SavedModel  saved_model.pb (op names; heuristic)                         cli/model-scan-proto.mjs
//   ONNX           .onnx (op domains, external-data paths; heuristic)            cli/model-scan-proto.mjs
//   GGUF           .gguf, and extension-less files with the GGUF magic (Ollama blobs) cli/model-scan-gguf.mjs
//   SafeTensors    .safetensors (header only; a valid file is clean by design)  cli/model-scan-safetensors.mjs
//
// Verdict: "unsafe" (a critical or high finding), "suspicious" (medium), "clean" (low / info only),
// "allowed" (sha256 on the allow-list; not inspected), "unscanned" (over the size cap, or a format this
// scanner does not read). A file that cannot be parsed is never "clean": it carries a medium
// "malformed" finding. Static only: a backdoor that triggers on certain inputs, or trojaned weights,
// cannot be seen this way.
import { readdirSync, statSync, lstatSync, realpathSync, openSync, readSync, closeSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, extname, join, dirname, resolve } from "node:path";
import { FileSource, BufferSource, safeDetail } from "./model-scan-bytes.mjs";
import { scanPickle, looksLikePickle, PICKLE_LIMITS } from "./model-scan-pickle.mjs";
import { zipEntries, entryDataOffset, readEntry, looksLikeZip } from "./model-scan-zip.mjs";
import { scanGguf, looksLikeGguf } from "./model-scan-gguf.mjs";
import { scanSafetensors, looksLikeSafetensors } from "./model-scan-safetensors.mjs";
import { scanKerasZip, scanHdf5, looksLikeHdf5 } from "./model-scan-keras.mjs";
import { scanOnnx, scanSavedModel } from "./model-scan-proto.mjs";

export const SCAN_LIMITS = Object.freeze({
  maxFileBytes: 64 * 1024 ** 3,    // a file past this is "unscanned" (size-limit) and not hashed
  maxFiles: 2000,                  // a directory walk stops after this many candidate files
  maxTotalBytes: 256 * 1024 ** 3,  // …or after this many bytes of candidates
  maxDepth: 12,                    // directory depth
  maxEntries: 200_000,             // directory entries visited
  maxInflatedPickle: 1024 ** 3     // a deflated .pkl entry inside a zip is inflated up to this
});

export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const PICKLE_EXT = new Set([".pkl", ".pickle", ".joblib"]);
const TORCH_EXT = new Set([".pt", ".pth", ".bin", ".ckpt"]);
export const MODEL_EXTENSIONS = new Set([...PICKLE_EXT, ...TORCH_EXT, ".keras", ".h5", ".hdf5", ".onnx", ".gguf", ".safetensors"]);

export const isSavedModel = (p) => basename(p) === "saved_model.pb";
export const isModelPath = (p) => MODEL_EXTENSIONS.has(extname(p).toLowerCase()) || isSavedModel(p);

export function verdictOf(findings) {
  const top = maxSeverity(findings);
  if (SEVERITY_RANK[top] >= SEVERITY_RANK.high) return "unsafe";
  if (top === "medium") return "suspicious";
  return "clean";
}
export function maxSeverity(findings) {
  let top = "info", seen = false;
  for (const f of findings || []) { seen = true; if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[top]) top = f.severity; }
  return seen ? top : null;
}

export function sha256File(path) {
  const h = createHash("sha256");
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(4 * 1024 * 1024);
    let n;
    while ((n = readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally { closeSync(fd); }
  return h.digest("hex");
}

function head(src, n = 16) { return src.read(0, Math.min(n, src.size)); }

// Sniffs the bytes, then the extension. → format id or null (not a model file this scanner reads).
export function detectFormat(path, src) {
  const ext = extname(path).toLowerCase();
  const h = head(src);
  if (isSavedModel(path)) return "tf-savedmodel";
  if (ext === ".onnx") return "onnx";
  if (looksLikeGguf(h)) return "gguf";
  if (looksLikeZip(h)) return ext === ".keras" ? "keras" : "zip";
  if (looksLikeSafetensors(h, src.size)) return "safetensors";
  if (looksLikeHdf5(src)) return "keras-h5";
  if (looksLikePickle(h)) return TORCH_EXT.has(ext) ? "pytorch-legacy" : "pickle";
  // A pickle-family extension that sniffs as nothing above is still read as a pickle (protocol 0/1
  // streams have no PROTO header), so garbage there becomes a "malformed" finding, not a skip.
  if (PICKLE_EXT.has(ext) || (TORCH_EXT.has(ext) && ext !== ".bin")) return TORCH_EXT.has(ext) ? "pytorch-legacy" : "pickle";
  if (ext === ".gguf") return "gguf";
  if (ext === ".safetensors") return "safetensors";
  if (ext === ".keras") return "keras";
  if (ext === ".h5" || ext === ".hdf5") return "keras-h5";
  return null;
}

function mergeFindings(into, list, prefix) {
  for (const f of list) {
    const ex = into.find((x) => x.class === f.class);
    const details = (f.details || []).map((d) => (prefix ? `${prefix}: ${d}` : d));
    if (ex) { ex.count += f.count || 1; for (const d of details) if (ex.details.length < 40 && !ex.details.includes(d)) ex.details.push(d); if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[ex.severity]) ex.severity = f.severity; }
    else into.push({ class: f.class, severity: f.severity, count: f.count || 1, details: details.slice(0, 40) });
  }
}

// A zip: a .keras archive when it has config.json and no pickles, otherwise a PyTorch/joblib archive
// whose every *.pkl entry is walked.
function scanZip(src, findings, limits) {
  let entries;
  try { entries = zipEntries(src); } catch (e) { mergeFindings(findings, [{ class: "malformed", severity: "medium", details: [e.message || "unreadable zip"] }]); return "zip"; }
  const pkls = entries.filter((e) => /(?:^|\/)[^/]*\.pkl$/i.test(e.name));
  if (!pkls.length) {
    if (entries.some((e) => e.name === "config.json")) { mergeFindings(findings, scanKerasZip(src).findings); return "keras"; }
    mergeFindings(findings, [{ class: "unsupported-format", severity: "info", details: ["zip archive without a pickle or Keras config"] }]);
    return "zip";
  }
  const torchscript = entries.some((e) => /(?:^|\/)code\//.test(e.name)) && entries.some((e) => /constants\.pkl$/.test(e.name));
  for (const e of pkls) {
    try {
      let res;
      if (e.method === 0) {
        const start = entryDataOffset(src, e);
        res = scanPickle(src, start, start + e.csize);
      } else {
        const buf = readEntry(src, e, limits.maxInflatedPickle);
        if (!buf) { mergeFindings(findings, [{ class: "too-large", severity: "medium", details: [`${safeDetail(e.name, 60)} past the inflate cap`] }]); continue; }
        res = scanPickle(new BufferSource(buf), 0, buf.length);
      }
      mergeFindings(findings, res.findings, safeDetail(e.name, 60));
    } catch (err) {
      mergeFindings(findings, [{ class: "malformed", severity: "medium", details: [`${safeDetail(e.name, 60)}: ${err.message || "unreadable entry"}`] }]);
    }
  }
  return torchscript ? "torchscript" : "pytorch-zip";
}

// One file. → { path, format, size, sha256, verdict, severity, findings }
export function scanModelFile(path, { allowHashes = null, limits = SCAN_LIMITS, hash = true } = {}) {
  const rec = { path, format: null, size: 0, sha256: null, verdict: "unscanned", severity: null, findings: [] };
  let st;
  try { st = statSync(path); } catch { rec.findings.push({ class: "unreadable", severity: "info", count: 1, details: ["cannot stat the file"] }); return rec; }
  rec.size = st.size;
  if (!st.isFile()) { rec.findings.push({ class: "unsupported-format", severity: "info", count: 1, details: ["not a regular file"] }); return rec; }
  if (st.size > limits.maxFileBytes) { rec.findings.push({ class: "size-limit", severity: "low", count: 1, details: [`over ${limits.maxFileBytes} bytes`] }); rec.severity = "low"; return rec; }
  let src;
  try {
    if (hash) rec.sha256 = sha256File(path);
    if (rec.sha256 && allowHashes && allowHashes.has(rec.sha256)) { rec.verdict = "allowed"; return rec; }
    src = new FileSource(path);
    if (src.size === 0) { rec.findings.push({ class: "malformed", severity: "medium", count: 1, details: ["empty file"] }); rec.format = extname(path).slice(1).toLowerCase() || null; }
    else {
      const fmt = detectFormat(path, src);
      rec.format = fmt;
      const f = rec.findings;
      if (!fmt) { f.push({ class: "unsupported-format", severity: "info", count: 1, details: ["not a format this scanner reads"] }); rec.severity = "info"; return rec; }
      if (fmt === "pickle" || fmt === "pytorch-legacy") mergeFindings(f, scanPickle(src, 0, src.size, PICKLE_LIMITS).findings);
      else if (fmt === "zip") rec.format = scanZip(src, f, limits);
      else if (fmt === "keras") mergeFindings(f, scanKerasZip(src).findings);
      else if (fmt === "keras-h5") mergeFindings(f, scanHdf5(src).findings);
      else if (fmt === "gguf") mergeFindings(f, scanGguf(src).findings);
      else if (fmt === "safetensors") mergeFindings(f, scanSafetensors(src).findings);
      else if (fmt === "onnx") mergeFindings(f, scanOnnx(src, { dir: dirname(resolve(path)) }).findings);
      else if (fmt === "tf-savedmodel") mergeFindings(f, scanSavedModel(src).findings);
    }
  } catch (e) {
    rec.findings.push({ class: "malformed", severity: "medium", count: 1, details: [safeDetail(e && e.message || "unreadable")] });
  } finally { if (src) src.close(); }
  if (rec.format === "zip" && rec.findings.every((x) => x.class === "unsupported-format")) { rec.severity = "info"; return rec; }
  rec.severity = maxSeverity(rec.findings);
  rec.verdict = verdictOf(rec.findings);
  return rec;
}

// An extension-less file is a candidate when its first bytes are a GGUF, zip, pickle, SafeTensors or
// HDF5 header (Ollama and Hugging Face store blobs under content hashes, with no extension).
function sniffCandidate(path, size) {
  if (size < 8) return false;
  let fd;
  try {
    fd = openSync(path, "r");
    const b = Buffer.alloc(16);
    const n = readSync(fd, b, 0, 16, 0);
    const h = b.subarray(0, n);
    return looksLikeGguf(h) || looksLikeZip(h) || looksLikePickle(h) || looksLikeSafetensors(h, size) || h.subarray(0, 8).equals(Buffer.from([0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a]));
  } catch { return false; } finally { if (fd != null) try { closeSync(fd); } catch { /* closed */ } }
}

// Candidate model files under a path. Symlinked directories are not followed; a symlinked file is
// followed and de-duplicated by its real path. `since` (ms) keeps files modified at or after it.
// → { files: [{ path, size, mtimeMs }], truncated: { files, bytes, entries }, skippedLarge }
export function findModelFiles(root, { limits = SCAN_LIMITS, since = 0, sniff = true } = {}) {
  const out = [], seen = new Set();
  const truncated = { files: false, bytes: false, entries: false };
  let total = 0, entries = 0;
  const consider = (p, st) => {
    if (since && st.mtimeMs < since) return;
    if (!isModelPath(p) && !(sniff && !extname(p) && sniffCandidate(p, st.size))) return;
    let real = p;
    try { real = realpathSync(p); } catch { /* keep p */ }
    if (seen.has(real)) return;
    if (out.length >= limits.maxFiles) { truncated.files = true; return; }
    if (total + Math.min(st.size, limits.maxFileBytes) > limits.maxTotalBytes) { truncated.bytes = true; return; }
    seen.add(real);
    total += Math.min(st.size, limits.maxFileBytes);
    out.push({ path: p, size: st.size, mtimeMs: st.mtimeMs });
  };
  let rootSt;
  try { rootSt = statSync(root); } catch { return { files: out, truncated }; }
  if (rootSt.isFile()) { consider(root, rootSt); return { files: out, truncated }; }
  const walk = (dir, depth) => {
    if (depth > limits.maxDepth || truncated.files || truncated.bytes) return;
    let list;
    try { list = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of list) {
      if (++entries > limits.maxEntries) { truncated.entries = true; return; }
      const p = join(dir, d.name);
      if (d.isDirectory()) { walk(p, depth + 1); continue; }
      let st;
      try { st = d.isSymbolicLink() ? statSync(p) : lstatSync(p); } catch { continue; }
      if (st.isFile()) consider(p, st);
      if (truncated.files || truncated.bytes) return;
    }
  };
  walk(root, 0);
  return { files: out, truncated };
}

// A file or a directory. → { results: [record], truncated }
export function scanModelPath(root, { allowHashes = null, limits = SCAN_LIMITS, since = 0, sniff = true, onFile } = {}) {
  let st;
  try { st = statSync(root); } catch { return { results: [], truncated: { files: false, bytes: false, entries: false }, missing: true }; }
  if (st.isFile()) {
    const r = scanModelFile(root, { allowHashes, limits });
    if (onFile) onFile(r);
    return { results: [r], truncated: { files: false, bytes: false, entries: false } };
  }
  const { files, truncated } = findModelFiles(root, { limits, since, sniff });
  const results = [];
  for (const f of files) { const r = scanModelFile(f.path, { allowHashes, limits }); results.push(r); if (onFile) onFile(r); }
  return { results, truncated };
}

// Content-free counts over records, for the heartbeat / AIBOM: verdicts, formats and finding classes.
export function verdictCounts(records) {
  const out = { scanned: 0, unsafe: 0, suspicious: 0, clean: 0, allowed: 0, unscanned: 0, byFormat: {}, byClass: {} };
  for (const r of records || []) {
    out.scanned++;
    out[r.verdict] = (out[r.verdict] || 0) + 1;
    if (r.format) out.byFormat[r.format] = (out.byFormat[r.format] || 0) + 1;
    for (const f of r.findings || []) if (SEVERITY_RANK[f.severity] >= SEVERITY_RANK.medium) out.byClass[f.class] = (out.byClass[f.class] || 0) + 1;
  }
  return out;
}
