// Text extraction for the quarantined reader (cli/quarantine-reader.mjs). No dependencies:
//   plain text (txt, md, csv, json, logs, any file that sniffs as UTF-8 text)  read directly
//   html / htm / xhtml                                                         tags, scripts and styles stripped
//   docx / xlsx / pptx                                                         the OOXML parts read with the model
//                                                                              scanner's ZIP reader (cli/model-scan-zip.mjs)
//   pdf                                                                        pdftotext, when installed
//   doc / rtf / odt (macOS)                                                    /usr/bin/textutil -convert txt -stdout
// Anything else, or a file a converter cannot read, is "unsupported" and is never summarised.
// The text is capped at EXTRACT_CAP characters; the rest is not read and `truncated` says so.
import { openSync, readSync, closeSync, fstatSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { extname } from "node:path";
import { zipEntries, readEntry, looksLikeZip } from "./model-scan-zip.mjs";
import { FileSource } from "./model-scan-bytes.mjs";

export const EXTRACT_CAP = 200 * 1024;
const ENTRY_MAX = 16 * 1024 * 1024;
const CONVERT_MS = 5000;

const TEXT_EXT = new Set([".txt", ".text", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".log", ".xml", ".yaml", ".yml", ".ini", ".toml", ".rst", ".eml"]);
const HTML_EXT = new Set([".html", ".htm", ".xhtml"]);
const OOXML = { ".docx": /^word\/(?:document|footnotes|endnotes|comments|header\d*|footer\d*)\.xml$/, ".xlsx": /^xl\/(?:sharedStrings|worksheets\/sheet\d+|comments\d*)\.xml$/, ".pptx": /^ppt\/(?:slides\/slide\d+|notesSlides\/notesSlide\d+|comments\/comment\d*)\.xml$/ };
const TEXTUTIL_EXT = new Set([".doc", ".rtf", ".odt", ".wordml", ".webarchive"]);

function head(path, n) {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    const b = Buffer.alloc(Math.min(n, size));
    const got = readSync(fd, b, 0, b.length, 0);
    return { buf: b.subarray(0, got), size };
  } finally { closeSync(fd); }
}

// UTF-8 text with no NUL and few control characters in the sample.
function looksText(buf) {
  if (!buf.length) return true;
  if (buf.includes(0)) return false;
  let ctl = 0;
  for (const c of buf) if (c < 9 || (c > 13 && c < 32)) ctl++;
  if (ctl > buf.length / 100) return false;
  try { new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(0, Math.max(0, buf.length - 4))); return true; } catch { return false; }
}

const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,8});/gi, (m, e) => {
    if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : ""; }
    return ENT[e.toLowerCase()] ?? m;
  });
}
export function stripHtml(s) {
  return decodeEntities(String(s)
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, " ")
    .replace(/<\/(?:p|div|li|tr|h[1-6]|br|section|article|table)\s*>|<br\s*\/?>/gi, "\n")
    .replace(/<[^>]{0,4096}>/g, " "))
    .replace(/[ \t\f\v]+/g, " ").replace(/ ?\n ?/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}
// OOXML part -> text: paragraph and row ends become new lines, every tag goes.
function ooxmlText(xml) {
  return decodeEntities(xml.replace(/<\/(?:w:p|a:p|row|si)>/g, "\n").replace(/<w:tab\/>|<\/c>/g, "\t").replace(/<[^>]{0,4096}>/g, "")).replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
}

function ooxml(path, re) {
  const src = new FileSource(path);
  try {
    const parts = zipEntries(src).filter((e) => re.test(e.name)).sort((a, b) => a.name.localeCompare(b.name, "en", { numeric: true }));
    if (!parts.length) return null;
    let out = "";
    for (const e of parts) {
      const b = readEntry(src, e, ENTRY_MAX);
      if (!b) continue;
      out += ooxmlText(b.toString("utf8")) + "\n";
      if (out.length > EXTRACT_CAP) break;
    }
    return out;
  } finally { src.close(); }
}

const PDFTOTEXT = ["/opt/homebrew/bin/pdftotext", "/usr/local/bin/pdftotext", "/usr/bin/pdftotext"];
function pdftotext(path) {
  const bin = PDFTOTEXT.find((p) => existsSync(p));
  if (!bin) return null;
  return execFileSync(bin, ["-q", "-enc", "UTF-8", path, "-"], { timeout: CONVERT_MS, maxBuffer: EXTRACT_CAP * 8, stdio: ["ignore", "pipe", "ignore"] }).toString("utf8");
}
function textutil(path) {
  if (process.platform !== "darwin" || !existsSync("/usr/bin/textutil")) return null;
  return execFileSync("/usr/bin/textutil", ["-convert", "txt", "-stdout", path], { timeout: CONVERT_MS, maxBuffer: EXTRACT_CAP * 8, stdio: ["ignore", "pipe", "ignore"] }).toString("utf8");
}

function capped(text, format, bytes) {
  const t = String(text).replace(/\r\n?/g, "\n");
  return { kind: "text", format, text: t.length > EXTRACT_CAP ? t.slice(0, EXTRACT_CAP) : t, truncated: t.length > EXTRACT_CAP, bytes };
}
const unsupported = (format, bytes) => ({ kind: "unsupported", format, text: "", truncated: false, bytes });

// -> { kind: "text" | "unsupported", format, text, truncated, bytes }. Never throws.
export function extractText(path) {
  let h;
  try { h = head(path, EXTRACT_CAP + 1); } catch { return unsupported("unreadable", 0); }
  const ext = extname(path).toLowerCase();
  try {
    if (OOXML[ext]) {
      if (!looksLikeZip(h.buf)) return unsupported(ext.slice(1), h.size);
      const t = ooxml(path, OOXML[ext]);
      return t === null ? unsupported(ext.slice(1), h.size) : capped(t, ext.slice(1), h.size);
    }
    if (ext === ".pdf") { const t = pdftotext(path); return t === null ? unsupported("pdf", h.size) : capped(t, "pdf", h.size); }
    if (TEXTUTIL_EXT.has(ext)) { const t = textutil(path); return t === null ? unsupported(ext.slice(1), h.size) : capped(t, ext.slice(1), h.size); }
    if (!looksText(h.buf.subarray(0, 8192))) return unsupported(ext.slice(1) || "binary", h.size);
    const raw = h.buf.toString("utf8");
    const over = h.size > EXTRACT_CAP;
    if (HTML_EXT.has(ext)) { const r = capped(stripHtml(raw), "html", h.size); r.truncated ||= over; return r; }
    const r = capped(raw, TEXT_EXT.has(ext) ? ext.slice(1) : "text", h.size);
    r.truncated ||= over;
    return r;
  } catch { return unsupported(ext.slice(1) || "binary", h.size); }
}
