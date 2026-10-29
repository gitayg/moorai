// Generated fixture files for the sensitivity-label tests: tiny Office Open XML packages, PDFs and OLE
// compound files built in memory. No real document is used; every GUID below is made up.
import { deflateRawSync, crc32 } from "node:zlib";

export const LABEL_ID = "1f2e3d4c-5b6a-4789-8abc-0123456789ab";
export const OTHER_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
export const SITE_ID = "99999999-8888-4777-8666-555555555555";

// entries: [{ name, data (string|Buffer), store? }] → a ZIP (deflate unless store).
export function zip(entries) {
  const locals = [], centrals = [];
  let off = 0;
  for (const e of entries) {
    const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data, "utf8");
    const method = e.store ? 0 : 8;
    const body = method ? deflateRawSync(raw) : raw;
    const name = Buffer.from(e.name, "utf8");
    const crc = crc32(raw) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(e.flags || 0, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(e.flags || 0, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, body);
    centrals.push(ch, name);
    off += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const CT = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`;
const DOC = `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly numbers</w:t></w:r></w:p></w:body></w:document>`;

// The custom.xml Office writes for a label: MSIP_Label_<guid>_<attr> text properties.
export function customXml(labels) {
  let pid = 2;
  const props = labels.flatMap((l) => Object.entries({ Enabled: l.enabled === false ? "false" : "true", SetDate: "2026-01-05T10:00:00Z", Method: l.method || "Privileged", Name: l.name, SiteId: l.siteId || SITE_ID, ActionId: "00000000-0000-4000-8000-000000000001", ContentBits: "0" })
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="${pid++}" name="MSIP_Label_${l.id}_${k}"><vt:lpwstr>${v}</vt:lpwstr></property>`));
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">${props.join("")}</Properties>`;
}

// docMetadata/LabelInfo.xml (MS-OFFCRYPTO 2.6.4): ids and siteIds braced, as Office writes them.
export function labelInfoXml(labels) {
  const els = labels.map((l) => `<clbl:label id="{${l.id}}" enabled="${l.enabled === false ? 0 : 1}" method="${l.removed ? "" : "Standard"}" siteId="{${l.siteId || SITE_ID}}" removed="${l.removed ? 1 : 0}" />`);
  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?><clbl:labelList xmlns:clbl="http://schemas.microsoft.com/office/2020/mipLabelMetadata">${els.join("")}</clbl:labelList>`;
}

// A .docx-shaped package. custom / labelInfo: label lists (omitted = no part); extra: more entries.
export function docx({ custom, labelInfo, extra = [], store = false } = {}) {
  const entries = [{ name: "[Content_Types].xml", data: CT, store }, { name: "word/document.xml", data: DOC, store }];
  if (custom) entries.push({ name: "docProps/custom.xml", data: customXml(custom), store });
  if (labelInfo) entries.push({ name: "docMetadata/LabelInfo.xml", data: labelInfoXml(labelInfo), store });
  return zip([...entries, ...extra]);
}

// A one-page PDF. info: label keys in the Info dictionary; xmp: in an XMP packet; protectedIrm: an
// Encrypt dictionary with the Microsoft IRM filter; padding: bytes of filler before the trailer.
export function pdf({ info = [], xmp = [], protectedIrm = false, padding = 0, hexName = false } = {}) {
  const infoKeys = info.map((l) => `/MSIP_Label_${l.id}_Enabled (${l.enabled === false ? "false" : "true"}) /MSIP_Label_${l.id}_SiteId (${SITE_ID}) /MSIP_Label_${l.id}_Name ${hexName ? "<FEFF" + Buffer.from(l.name, "utf16le").swap16().toString("hex").toUpperCase() + ">" : `(${l.name})`}`).join(" ");
  const xmpBody = xmp.map((l) => `<pdfx:MSIP_Label_${l.id}_Enabled>${l.enabled === false ? "false" : "true"}</pdfx:MSIP_Label_${l.id}_Enabled>\n<pdfx:MSIP_Label_${l.id}_Name>${l.name}</pdfx:MSIP_Label_${l.id}_Name>\n`).join("");
  const parts = [
    "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
    "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
    "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n",
    xmp.length ? `5 0 obj << /Type /Metadata /Subtype /XML >> stream\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:pdfx="http://ns.adobe.com/pdfx/1.3/">\n${xmpBody}</rdf:Description></rdf:RDF></x:xmpmeta>\nendstream endobj\n` : "",
    padding ? `% ${"x".repeat(padding)}\n` : "",
    protectedIrm ? "6 0 obj << /Filter /MicrosoftIRMServices /V 4 /Length 128 >> endobj\n" : "",
    `4 0 obj << /Producer (Test) ${infoKeys} >> endobj\n`,
    `trailer << /Root 1 0 R /Info 4 0 R${protectedIrm ? " /Encrypt 6 0 R" : ""} >>\n%%EOF\n`
  ];
  return Buffer.from(parts.join(""), "latin1");
}

// An OLE compound file (v3, 512-byte sectors): sector 0 = FAT, sector 1 = the directory. `names` become
// directory entries (the first is the root storage).
export function cfb(names) {
  const S = 512;
  const h = Buffer.alloc(S, 0);
  Buffer.from("d0cf11e0a1b11ae1", "hex").copy(h, 0);
  h.writeUInt16LE(0x3e, 0x18); h.writeUInt16LE(3, 0x1a); h.writeUInt16LE(0xfffe, 0x1c); h.writeUInt16LE(9, 0x1e); h.writeUInt16LE(6, 0x20);
  h.writeUInt32LE(1, 0x2c); h.writeUInt32LE(1, 0x30); h.writeUInt32LE(4096, 0x38); h.writeUInt32LE(0xfffffffe, 0x3c); h.writeUInt32LE(0xfffffffe, 0x44);
  for (let i = 0; i < 109; i++) h.writeUInt32LE(i === 0 ? 0 : 0xffffffff, 0x4c + i * 4);
  const fat = Buffer.alloc(S, 0xff);
  fat.writeUInt32LE(0xfffffffd, 0); fat.writeUInt32LE(0xfffffffe, 4);
  const sectors = Math.max(1, Math.ceil(names.length / 4));
  // the directory chain: sectors 1..sectors
  for (let i = 1; i <= sectors; i++) fat.writeUInt32LE(i === sectors ? 0xfffffffe : i + 1, i * 4);
  const dir = Buffer.alloc(S * sectors, 0);
  names.forEach((n, i) => {
    const e = i * 128;
    const nb = Buffer.from(n + "\u0000", "utf16le");
    nb.copy(dir, e);
    dir.writeUInt16LE(nb.length, e + 0x40);
    dir[e + 0x42] = i === 0 ? 5 : (n.startsWith("\u0006") ? 1 : 2);
  });
  return Buffer.concat([h, fat, dir, Buffer.alloc(S, 0)]);
}
