// Microsoft Purview / Microsoft Information Protection sensitivity labels already on a file, read from the
// file's METADATA only, and the admin's labelPolicy verdict for an AI agent reading it or sending it out.
//
// Where a label lives (Microsoft's own specifications; the URLs are in the README section):
//   * Office Open XML (.docx/.xlsx/.pptx): custom document properties in docProps/custom.xml named
//     MSIP_Label_<label GUID>_<Enabled|Name|SiteId|Method|SetDate|ContentBits|ActionId>, or, once a tenant
//     turns on co-authoring for labelled files, a <label id enabled method siteId removed/> element in the
//     docMetadata/LabelInfo.xml part. MS-OFFCRYPTO 2.6.3: where the LabelInfo part holds a label element for
//     a tenant (siteId), that element is the tenant's label and the custom properties of that tenant are
//     not read. LabelInfo carries no label NAME, so a name rule matches only a custom-property label.
//   * PDF: the same MSIP_Label_* keys, as custom keys of the document Info dictionary or as XMP properties.
//     A label's metadata stays unencrypted when the label also encrypts the PDF.
//   * A file a label ENCRYPTED (rights management) is an OLE compound file. Its content is not readable,
//     and the label is reported as unknown: the file is "protected". MS-OFFCRYPTO 2.2.2 / 2.2.10: an
//     ECMA-376 document under IRM holds an "EncryptedPackage" stream and a "DRMEncryptedDataSpace" stream;
//     an Office binary document holds "\x09DRMContent" / "\x09DRMDataSpace". A password-encrypted Office
//     file (EncryptedPackage with no DRM data space) is not a label and reads as "none".
//
// Bounded, metadata only, no dependency. The ZIP central directory is read from the END of the file
// (positioned reads, never the whole file), at most one or two named XML parts are inflated with
// node:zlib under maxOutputLength, and a PDF is read in a capped head and tail window. The document body
// is never decompressed or decoded. A label we could not establish on an Office/PDF candidate (a
// directory or part past its cap, ZIP64, an encrypted ZIP entry, bytes that do not parse) is state
// "unreadable", and the caller applies its surface's fail mode (cli/fail-mode.mjs).
//
// Content-free reporting: the finding names the label by GUID and by a keyed hash of its name, the
// action (read / send) and the verdict; its contentHash is the keyed hash of the resolved path. Neither
// the file's content nor a plain path is in it (a path is added only by the capture tier, as for every
// other file finding).
import { openSync, readSync, fstatSync, closeSync, constants as FS } from "node:fs";
import { inflateRawSync } from "node:zlib";
import { contentHash } from "./content-hash.mjs";

export const LABEL_CAPS = Object.freeze({
  directoryBytes: 1_048_576, // ZIP central directory
  entries: 20_000,           // ZIP central directory entries
  partBytes: 1_048_576,      // one XML part, compressed and inflated
  pdfWindow: 262_144,        // PDF head and tail windows
  cfbDirSectors: 256         // OLE directory sectors walked
});

export const LABEL_THREAT = 1; // #1 Sensitive data leak (AML.T0057 LLM Data Leakage)
export const LABEL_ACTIONS = Object.freeze(["notify", "justify", "block"]);
const OFFICE_EXT = /\.(?:doc|dot|xls|xlt|ppt|pot|pps|vsd)[xm]$|\.xlsb$/i;
const GUID_RE = /^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$/i;
const normGuid = (s) => { const m = GUID_RE.exec(String(s || "").trim()); return m ? m[1].toLowerCase() : ""; };
const truthy = (s) => /^(?:true|1)$/i.test(String(s || "").trim());
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// ---------------------------------------------------------------------------------------------
// The signed policy field
// ---------------------------------------------------------------------------------------------
// labelPolicy: {
//   rules: [ { match: { id: "<label GUID>" } | { name: "Highly Confidential" }, onRead?, onSend? }, ... ],
//   protected?: { onRead?, onSend? }      // a rights-managed file whose label cannot be read
// }
// onRead / onSend: "notify" | "justify" | "block"; an action left out does nothing for that file.
// Absent (or nothing valid in it) = inactive: no file is opened and nothing changes.
const MAX_RULES = 256, MAX_NAME = 256;
const RULE_KEYS = new Set(["match", "onRead", "onSend"]);
const POLICY_KEYS = new Set(["rules", "protected"]);
function stderrWarn(m) { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* a warning, never a decision */ } }

function actions(o, where, warn) {
  const out = {};
  for (const k of ["onRead", "onSend"]) {
    if (o[k] === undefined) continue;
    if (LABEL_ACTIONS.includes(o[k])) out[k === "onRead" ? "read" : "send"] = o[k];
    else warn(`labelPolicy.${where}.${k} ignored: notify, justify or block`);
  }
  return out;
}

export function labelPolicy(policy, warn = stderrWarn) {
  const none = { active: false, rules: [], protected: {} };
  const lp = isObj(policy) ? policy.labelPolicy : undefined;
  if (lp === undefined || lp === null) return none;
  if (!isObj(lp)) { warn("labelPolicy ignored: not an object"); return none; }
  if (Object.keys(lp).some((k) => !POLICY_KEYS.has(k))) warn("labelPolicy: unknown key ignored");
  const rules = [];
  if (lp.rules !== undefined) {
    if (!Array.isArray(lp.rules)) warn("labelPolicy.rules ignored: not a list");
    else {
      if (lp.rules.length > MAX_RULES) warn(`labelPolicy.rules: at most ${MAX_RULES} entries, the rest dropped`);
      lp.rules.slice(0, MAX_RULES).forEach((r, i) => {
        if (!isObj(r) || !isObj(r.match)) { warn(`labelPolicy.rules entry ${i} dropped: needs match { id } or { name }`); return; }
        if (Object.keys(r).some((k) => !RULE_KEYS.has(k))) warn(`labelPolicy.rules entry ${i}: unknown key ignored`);
        const id = r.match.id !== undefined ? normGuid(r.match.id) : "";
        const name = typeof r.match.name === "string" ? r.match.name.trim().toLowerCase() : "";
        if (r.match.id !== undefined && !id) { warn(`labelPolicy.rules entry ${i} dropped: match.id is not a GUID`); return; }
        if (!id && (!name || name.length > MAX_NAME || /[\u0000-\u001f]/.test(name))) { warn(`labelPolicy.rules entry ${i} dropped: match.name is 1-${MAX_NAME} characters of plain text`); return; }
        const act = actions(r, `rules[${i}]`, warn);
        if (!act.read && !act.send) { warn(`labelPolicy.rules entry ${i} dropped: no onRead or onSend`); return; }
        rules.push({ id, name: id ? "" : name, ...act });
      });
    }
  }
  let prot = {};
  if (lp.protected !== undefined) {
    if (isObj(lp.protected)) prot = actions(lp.protected, "protected", warn);
    else warn("labelPolicy.protected ignored: not an object");
  }
  return { active: rules.length > 0 || !!prot.read || !!prot.send, rules, protected: prot };
}

// ---------------------------------------------------------------------------------------------
// Reading the label
// ---------------------------------------------------------------------------------------------
function readAt(fd, pos, len) {
  const buf = Buffer.allocUnsafe(Math.max(0, len));
  let n = 0;
  while (n < len) { const r = readSync(fd, buf, n, len - n, pos + n); if (!r) break; n += r; }
  return buf.subarray(0, n);
}

const xmlText = (s) => s.replace(/<[^>]*>/g, "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Math.min(+d, 0x10ffff))).replace(/&amp;/g, "&").trim();
const attrsOf = (s) => { const a = {}; for (const m of s.matchAll(/([\w:]+)\s*=\s*"([^"]*)"/g)) a[m[1].replace(/^\w+:/, "")] = m[2]; return a; };

// MSIP_Label_<guid>_<Attr> → value, from any source; grouped per label GUID.
function groupMsip(pairs) {
  const by = new Map();
  for (const [g, attr, value] of pairs) {
    const id = normGuid(g);
    if (!id) continue;
    if (!by.has(id)) by.set(id, {});
    // An XMP closing tag (</pdfx:MSIP_Label_…_Name>) also reads as a key with an empty value: never let it
    // overwrite the value its opening tag carried.
    if (value || !(attr.toLowerCase() in by.get(id))) by.get(id)[attr.toLowerCase()] = value;
  }
  return [...by].map(([id, a]) => ({ id, name: a.name || "", enabled: truthy(a.enabled), siteId: normGuid(a.siteid), method: a.method || "" }));
}

// docProps/custom.xml: <property fmtid pid name="MSIP_Label_…_Enabled"><vt:lpwstr>true</vt:lpwstr></property>
export function customXmlLabels(xml) {
  const pairs = [];
  for (const m of xml.matchAll(/<(?:\w+:)?property\b([^>]*)>([\s\S]{0,4096}?)<\/(?:\w+:)?property>/g)) {
    const k = /\bname\s*=\s*"MSIP_Label_([0-9a-fA-F-]{36})_(\w+)"/.exec(m[1]);
    if (k) pairs.push([k[1], k[2], xmlText(m[2])]);
  }
  return groupMsip(pairs);
}

// docMetadata/LabelInfo.xml: <clbl:label id="{…}" enabled="1" method="Standard" siteId="{…}" removed="0"/>
export function labelInfoLabels(xml) {
  const out = [];
  for (const m of xml.matchAll(/<(?:\w+:)?label\b([^>]*)\/?>/g)) {
    const a = attrsOf(m[1]);
    const id = normGuid(a.id);
    if (!id) continue;
    const removed = truthy(a.removed);
    out.push({ id, name: "", enabled: !removed && truthy(a.enabled), removed, siteId: normGuid(a.siteId), method: a.method || "" });
  }
  return out;
}

// MS-OFFCRYPTO 2.6.3, policy not known to the reader: a tenant with a LabelInfo label element is read from
// LabelInfo only; a custom-property label of any other tenant still counts. A LabelInfo label borrows the
// NAME of the custom-property label with the same GUID (LabelInfo has no name attribute).
export function effectiveOfficeLabels(custom, info) {
  const infoSites = new Set(info.map((l) => l.siteId).filter(Boolean));
  const named = new Map(custom.filter((l) => l.name).map((l) => [l.id, l.name]));
  const fromInfo = info.filter((l) => !l.removed).map((l) => ({ ...l, name: named.get(l.id) || "", source: "labelinfo" }));
  const fromCustom = custom.filter((l) => !(l.siteId && infoSites.has(l.siteId))).map((l) => ({ ...l, source: "custom" }));
  return [...fromInfo, ...fromCustom.filter((l) => !fromInfo.some((x) => x.id === l.id))];
}

function zipPart(fd, size, e, caps) {
  if (e.flags & 1) throw new Error("encrypted-entry");
  if (e.comp > caps.partBytes || e.uncomp > caps.partBytes) throw new Error("part-cap");
  const loc = readAt(fd, e.off, 30);
  if (loc.length < 30 || loc.readUInt32LE(0) !== 0x04034b50) throw new Error("malformed");
  const start = e.off + 30 + loc.readUInt16LE(26) + loc.readUInt16LE(28);
  if (start + e.comp > size) throw new Error("malformed");
  const data = readAt(fd, start, e.comp);
  if (e.method === 0) return data.toString("utf8");
  if (e.method === 8) return inflateRawSync(data, { maxOutputLength: caps.partBytes }).toString("utf8");
  throw new Error("method");
}

function zipLabels(fd, size, caps) {
  const tailLen = Math.min(size, 22 + 65_535);
  const tail = readAt(fd, size - tailLen, tailLen);
  let at = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (tail.readUInt32LE(i) === 0x06054b50) { at = i; break; }
  if (at < 0) return { ooxml: false, why: "malformed" };
  const entries = tail.readUInt16LE(at + 10), cdSize = tail.readUInt32LE(at + 12), cdOff = tail.readUInt32LE(at + 16);
  if (entries === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) return { ooxml: false, why: "zip64" };
  if (cdSize > caps.directoryBytes || entries > caps.entries) return { ooxml: false, why: "directory-cap" };
  if (cdOff + cdSize > size) return { ooxml: false, why: "malformed" };
  const cd = readAt(fd, cdOff, cdSize);
  const want = {};
  let ooxml = false;
  for (let p = 0, k = 0; k < entries; k++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) return { ooxml, why: "malformed" };
    const nl = cd.readUInt16LE(p + 28);
    const name = cd.toString("utf8", p + 46, p + 46 + nl).toLowerCase();
    const e = { flags: cd.readUInt16LE(p + 8), method: cd.readUInt16LE(p + 10), comp: cd.readUInt32LE(p + 20), uncomp: cd.readUInt32LE(p + 24), off: cd.readUInt32LE(p + 42) };
    if (name === "[content_types].xml") ooxml = true;
    else if (name === "docprops/custom.xml") want.custom = e;
    else if (name === "docmetadata/labelinfo.xml") want.info = e;
    p += 46 + nl + cd.readUInt16LE(p + 30) + cd.readUInt16LE(p + 32);
  }
  if (!ooxml) return { ooxml, labels: [] };
  try {
    const custom = want.custom ? customXmlLabels(zipPart(fd, size, want.custom, caps)) : [];
    const info = want.info ? labelInfoLabels(zipPart(fd, size, want.info, caps)) : [];
    return { ooxml, labels: effectiveOfficeLabels(custom, info) };
  } catch (e) {
    return { ooxml, why: e && /^(?:part-cap|encrypted-entry|method)$/.test(e.message) ? e.message : "malformed" };
  }
}

// PDF literal string (…) with its escapes, or a <hex> string; UTF-16BE when it carries the FE FF mark.
function pdfString(lit, hex) {
  let bytes;
  if (hex !== undefined) {
    const h = hex.replace(/\s+/g, "");
    bytes = Buffer.from(h.length % 2 ? h + "0" : h, "hex");
  } else {
    const out = [];
    for (let i = 0; i < lit.length; i++) {
      const c = lit[i];
      if (c !== "\\") { out.push(c.charCodeAt(0) & 0xff); continue; }
      const n = lit[++i];
      if (/[0-7]/.test(n)) { let o = n; while (o.length < 3 && /[0-7]/.test(lit[i + 1] || "")) o += lit[++i]; out.push(parseInt(o, 8) & 0xff); }
      else out.push(({ n: 10, r: 13, t: 9, b: 8, f: 12 })[n] ?? (n || "").charCodeAt(0));
    }
    bytes = Buffer.from(out);
  }
  if (bytes[0] === 0xfe && bytes[1] === 0xff) { const b = Buffer.from(bytes.subarray(2, 2 + ((bytes.length - 2) & ~1))); return b.swap16().toString("utf16le"); }
  return bytes.toString("latin1");
}

function pdfLabels(fd, size, caps) {
  const head = readAt(fd, 0, Math.min(size, caps.pdfWindow));
  const tail = size > caps.pdfWindow ? readAt(fd, Math.max(caps.pdfWindow, size - caps.pdfWindow), Math.min(caps.pdfWindow, size - caps.pdfWindow)) : Buffer.alloc(0);
  const pairs = [];
  let isProtected = false;
  for (const buf of [head, tail]) {
    const s = buf.toString("latin1");
    if (/\/Filter\s*\/MicrosoftIRMServices\b/.test(s)) isProtected = true;
    // Info dictionary: /MSIP_Label_<g>_Name (Confidential) or <FEFF…>. XMP: <pdfx:MSIP_Label_<g>_Name>Confidential</…>
    // or pdfx:MSIP_Label_<g>_Name="Confidential".
    for (const m of s.matchAll(/MSIP_Label_([0-9a-fA-F-]{36})_([A-Za-z]+)(?:\s*\(((?:[^()\\]|\\[\s\S]){0,1024})\)|\s*<([0-9A-Fa-f\s]{0,4096})>|>([^<]{0,1024})<|\s*=\s*"([^"]{0,1024})")/g)) {
      const v = m[3] !== undefined ? pdfString(m[3]) : m[4] !== undefined ? pdfString(undefined, m[4]) : xmlText(m[5] ?? m[6] ?? "");
      pairs.push([m[1], m[2], v.trim()]);
    }
  }
  return { labels: groupMsip(pairs).map((l) => ({ ...l, source: "pdf" })), protected: isProtected };
}

// OLE compound file: the names in its directory, walked along the FAT chain from the header's DIFAT.
function cfbNames(fd, size, caps) {
  const h = readAt(fd, 0, 512);
  const shift = h.readUInt16LE(0x1e);
  if (shift !== 9 && shift !== 12) throw new Error("malformed");
  const ssz = 1 << shift, per = ssz / 4;
  const difat = [];
  for (let i = 0; i < 109; i++) difat.push(h.readUInt32LE(0x4c + i * 4));
  const next = (s) => {
    const idx = Math.floor(s / per);
    if (idx >= 109) throw new Error("directory-cap");
    const fs = difat[idx];
    if (fs >= 0xfffffffa) throw new Error("malformed");
    const b = readAt(fd, (fs + 1) * ssz + (s % per) * 4, 4);
    if (b.length < 4) throw new Error("malformed");
    return b.readUInt32LE(0);
  };
  const names = new Set();
  let s = h.readUInt32LE(0x30), n = 0;
  while (s < 0xfffffffa) {
    if (++n > caps.cfbDirSectors) throw new Error("directory-cap");
    if ((s + 1) * ssz >= size) throw new Error("malformed");
    const b = readAt(fd, (s + 1) * ssz, ssz);
    for (let e = 0; e + 128 <= b.length; e += 128) {
      const nl = b.readUInt16LE(e + 0x40);
      if (nl >= 2 && nl <= 64 && b[e + 0x42]) names.add(b.toString("utf16le", e, e + nl - 2));
    }
    s = next(s);
  }
  return names;
}

// → { state: "none"|"labelled"|"protected"|"unreadable", labels: [{ id, name, enabled, siteId, method, source }],
//     protected: boolean, why? }. Only labels with enabled true are returned. Never throws.
export function readSensitivityLabels(path, { caps = LABEL_CAPS } = {}) {
  const none = { state: "none", labels: [], protected: false };
  let fd = -1;
  try {
    fd = openSync(path, FS.O_RDONLY | (FS.O_NONBLOCK || 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.size < 8) return none;
    const size = st.size;
    const magic = readAt(fd, 0, 8);
    const office = OFFICE_EXT.test(String(path));
    let labels = [], prot = false;
    if (magic.readUInt32LE(0) === 0x04034b50) {
      const z = zipLabels(fd, size, caps);
      if (z.why) return office || z.ooxml ? { state: "unreadable", labels: [], protected: false, why: z.why } : none;
      labels = z.labels;
    } else if (magic.readUInt32BE(0) === 0xd0cf11e0 && magic.readUInt32BE(4) === 0xa1b11ae1) {
      let names;
      try { names = cfbNames(fd, size, caps); } catch (e) { return office ? { state: "unreadable", labels: [], protected: false, why: e && e.message === "directory-cap" ? "directory-cap" : "malformed" } : none; }
      prot = (names.has("EncryptedPackage") && names.has("DRMEncryptedDataSpace")) || names.has("\u0009DRMContent") || names.has("\u0009DRMDataSpace");
    } else if (magic.toString("latin1", 0, 5) === "%PDF-") {
      const p = pdfLabels(fd, size, caps);
      labels = p.labels;
      prot = p.protected;
    } else return none;
    labels = labels.filter((l) => l.enabled);
    if (labels.length) return { state: "labelled", labels, protected: prot };
    return prot ? { state: "protected", labels: [], protected: true } : none;
  } catch {
    return none; // the file could not be opened: the content scan of the same call sees the same
  } finally {
    if (fd >= 0) { try { closeSync(fd); } catch { /* closed */ } }
  }
}

// ---------------------------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------------------------
const RANK = { notify: 1, justify: 2, block: 3 };
const DECISION = { notify: "allow", justify: "ask", block: "deny" };
const EMPTY = () => ({ decision: "allow", reasons: [], findings: [], kill: false, killIds: [], alternatives: [], unevaluated: false });

// The strictest rule that applies to this file for `action` ("read" | "send") → { verdict, label, state } | null.
export function labelVerdict(lp, info, action) {
  let best = null;
  const take = (verdict, label, state) => { if (verdict && (!best || RANK[verdict] > RANK[best.verdict])) best = { verdict, label, state }; };
  for (const l of info.labels || []) {
    const name = (l.name || "").trim().toLowerCase();
    for (const r of lp.rules) if ((r.id && r.id === l.id) || (r.name && name && r.name === name)) take(r[action], l, "labelled");
  }
  if (info.protected) take(lp.protected[action], null, "protected");
  return best;
}

// One file, one action. decideText's shape plus `unevaluated` (a label could not be established on an
// Office or PDF file and the policy is active: the caller's fail mode decides). `read` is the label
// reader, injectable for tests; `hash` the keyed hash (cli/content-hash.mjs).
export function decideSensitivityLabel(engine, policy, path, action, { read = readSensitivityLabels, hash = contentHash, warn = () => {} } = {}) {
  const out = EMPTY();
  if (typeof path !== "string" || !path || (action !== "read" && action !== "send")) return out;
  const lp = labelPolicy(policy, warn);
  if (!lp.active) return out;
  const info = read(path);
  if (info.state === "unreadable") { out.unevaluated = true; return out; }
  const v = labelVerdict(lp, info, action);
  if (!v) return out;
  const t = engine && engine.threat ? engine.threat(LABEL_THREAT) : null;
  const what = v.state === "protected" ? "Rights-protected file" : "Sensitivity-labelled file";
  const sensitivityLabel = {
    state: v.state, action, verdict: v.verdict,
    ...(v.label ? { labelId: v.label.id, ...(v.label.name ? { labelNameHash: hash(`label-name:${v.label.name.trim().toLowerCase()}`) } : {}), source: v.label.source } : {})
  };
  out.findings.push({ threatId: LABEL_THREAT, category: `${what} ${action === "send" ? "sent" : "read"} by an AI agent`, riskLevel: (t && t.riskLevel) || "High", detectorId: "sensitivity-label", match: `label-path:${path}`, sensitivityLabel });
  out.decision = DECISION[v.verdict];
  if (v.verdict !== "notify") {
    out.reasons.push(`#${LABEL_THREAT} ${v.state === "protected" ? "rights-protected file" : "sensitivity label"}: your organization ${v.verdict === "block" ? "blocks" : "requires sign-off for"} AI agents ${action === "send" ? "sending" : "reading"} it`);
    if (t && t.saferAlternative) out.alternatives = [t.saferAlternative];
  }
  return out;
}

// The alert fields a reporter adds for a label finding (content-free; see the header).
export function labelAlertFields(f) {
  return f && f.sensitivityLabel ? { sensitivityLabel: f.sensitivityLabel } : {};
}
