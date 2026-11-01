#!/usr/bin/env node
// Package MoorAI Browser Guard for the Chrome Web Store / Edge Add-ons upload, or as a self-hosted build.
//
//   node scripts/browser-ext-package.mjs [--out dist/browser-ext] [--console-origin https://console.example.com]
//
// The zip holds exactly the files the manifest and the options page reference (scripts, styles, icons,
// the managed-storage schema), never tests, docs, store text or policy templates. It is deterministic:
// sorted entries, one fixed timestamp, so the same sources give the same bytes.
//
// --console-origin builds a SELF-HOSTED variant whose manifest also lists that console origin under
// host_permissions, so a force-installed copy can post signals without the user granting the optional
// permission. Store builds leave it out (the user grants it on the options page). The source manifest is
// never modified.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { deflateRawSync, crc32 } from "node:zlib";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXT = join(ROOT, "browser-ext");

function die(m) { process.stderr.write(`browser-ext-package: ${m}\n`); process.exit(2); }
function arg(n) { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : undefined; }

export function runtimeFiles(manifest, optionsHtml) {
  const files = new Set(["manifest.json"]);
  const add = (f) => { if (typeof f === "string" && f) files.add(f.replace(/^\.\//, "")); };
  add(manifest.background && manifest.background.service_worker);
  add(manifest.options_page);
  add(manifest.storage && manifest.storage.managed_schema);
  for (const c of manifest.content_scripts || []) { (c.js || []).forEach(add); (c.css || []).forEach(add); }
  Object.values(manifest.icons || {}).forEach(add);
  Object.values((manifest.action && manifest.action.default_icon) || {}).forEach(add);
  for (const m of String(optionsHtml || "").matchAll(/<script\s+src="([^"]+)"/g)) add(m[1]);
  return [...files].sort();
}

function validate(m) {
  const err = [];
  if (m.manifest_version !== 3) err.push("manifest_version must be 3");
  if (m.key) err.push("remove the key field (the store assigns the id)");
  if (!m.description || m.description.length > 132) err.push("description must be 1-132 characters");
  for (const s of ["16", "48", "128"]) if (!m.icons || !m.icons[s]) err.push(`icons.${s} missing`);
  return err;
}

const DOS_TIME = 0, DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01 00:00
export function zipDeflate(entries) {
  const locals = [], centrals = [];
  let off = 0;
  for (const { name: n, data } of entries) {
    const name = Buffer.from(n, "utf8"), comp = deflateRawSync(data, { level: 9 }), crc = crc32(data) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(8, 8);
    lh.writeUInt16LE(DOS_TIME, 10); lh.writeUInt16LE(DOS_DATE, 12); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(DOS_TIME, 12); ch.writeUInt16LE(DOS_DATE, 14); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, name, comp); centrals.push(ch, name);
    off += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const manifest = JSON.parse(readFileSync(join(EXT, "manifest.json"), "utf8"));
  const errs = validate(manifest);
  if (errs.length) die(errs.join("; "));
  const origin = arg("--console-origin");
  let selfHosted = null;
  if (origin !== undefined) {
    let u;
    try { u = new URL(origin); } catch { die("--console-origin is not a URL"); }
    if (u.protocol !== "https:" || u.origin !== origin.replace(/\/+$/, "")) die("--console-origin must be an https origin with no path (https://console.example.com)");
    selfHosted = `${u.origin}/*`;
  }
  const files = runtimeFiles(manifest, readFileSync(join(EXT, manifest.options_page), "utf8"));
  for (const f of files) if (!existsSync(join(EXT, f))) die(`missing ${f}`);
  const entries = files.map((f) => {
    if (f === "manifest.json" && selfHosted) {
      const m = { ...manifest, host_permissions: [...new Set([...(manifest.host_permissions || []), selfHosted])] };
      return { name: f, data: Buffer.from(JSON.stringify(m, null, 2) + "\n") };
    }
    return { name: f, data: readFileSync(join(EXT, f)) };
  });
  const out = arg("--out") || join(ROOT, "dist", "browser-ext");
  mkdirSync(out, { recursive: true });
  const file = join(out, `moorai-browser-guard-${manifest.version}${selfHosted ? "-selfhosted" : ""}.zip`);
  writeFileSync(file, zipDeflate(entries));
  process.stdout.write(`wrote ${file} (${files.length} files)\n`);
}
