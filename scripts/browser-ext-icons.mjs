#!/usr/bin/env node
// Draws the Browser Guard toolbar and store icons (16, 32, 48, 128 px PNG) with no image tooling: a
// rounded teal square with a white shield, 4x4 supersampled, written with node:zlib.
//
//   node scripts/browser-ext-icons.mjs        → browser-ext/icons/icon{16,32,48,128}.png
import { writeFileSync, mkdirSync } from "node:fs";
import { deflateSync, crc32 } from "node:zlib";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "browser-ext", "icons");
const BG = [15, 118, 110], FG = [255, 255, 255];

// Shield outline in unit coordinates (0..1).
const SHIELD = [[0.5, 0.17], [0.78, 0.27], [0.76, 0.55], [0.5, 0.84], [0.24, 0.55], [0.22, 0.27]];
function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
function inRoundRect(x, y, r) {
  const cx = Math.min(Math.max(x, r), 1 - r), cy = Math.min(Math.max(y, r), 1 - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

function chunk(type, data) {
  const t = Buffer.from(type, "ascii");
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])) >>> 0);
  return Buffer.concat([len, t, data, crc]);
}

export function iconPng(size) {
  const SS = 4, rows = [];
  for (let py = 0; py < size; py++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let px = 0; px < size; px++) {
      let bg = 0, fg = 0;
      for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
        const x = (px + (sx + 0.5) / SS) / size, y = (py + (sy + 0.5) / SS) / size;
        if (!inRoundRect(x, y, 0.2)) continue;
        if (inPoly(x, y, SHIELD)) fg++; else bg++;
      }
      const n = SS * SS, a = (bg + fg) / n;
      const mix = (i) => (a ? Math.round((BG[i] * bg + FG[i] * fg) / (bg + fg)) : 0);
      row.set([mix(0), mix(1), mix(2), Math.round(a * 255)], 1 + px * 4);
    }
    rows.push(row);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  return Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(Buffer.concat(rows), { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  mkdirSync(OUT, { recursive: true });
  for (const s of [16, 32, 48, 128]) writeFileSync(join(OUT, `icon${s}.png`), iconPng(s));
  process.stdout.write(`wrote ${OUT}/icon{16,32,48,128}.png\n`);
}
