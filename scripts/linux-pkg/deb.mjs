// Assemble a .deb (deb(5)): ar archive of debian-binary, control.tar.gz and data.tar.gz.
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { tarball } from "./tar.mjs";
import { arArchive } from "./ar.mjs";

const gz = (b) => gzipSync(b, { level: 9 });

export function md5sums(dataEntries) {
  return dataEntries
    .filter((e) => e.type === "file")
    .map((e) => `${createHash("md5").update(e.data).digest("hex")}  ${e.path.replace(/^\.\//, "")}\n`)
    .join("");
}

export function installedSizeKiB(dataEntries) {
  return Math.max(1, Math.ceil(dataEntries.filter((e) => e.type === "file").reduce((n, e) => n + e.data.length, 0) / 1024));
}

// control: the control file text; scripts: { postinst?: Buffer, prerm?: Buffer, postrm?: Buffer }.
export function buildDeb({ control, scripts, dataEntries, mtime }) {
  const ctl = [
    { path: "./", type: "dir", mode: 0o755 },
    { path: "./control", type: "file", mode: 0o644, data: Buffer.from(control, "utf8") },
    { path: "./md5sums", type: "file", mode: 0o644, data: Buffer.from(md5sums(dataEntries), "utf8") }
  ];
  for (const name of ["postinst", "prerm", "postrm"]) {
    if (scripts[name]) ctl.push({ path: `./${name}`, type: "file", mode: 0o755, data: scripts[name] });
  }
  return arArchive([
    { name: "debian-binary", data: Buffer.from("2.0\n", "latin1") },
    { name: "control.tar.gz", data: gz(tarball(ctl, mtime)) },
    { name: "data.tar.gz", data: gz(tarball(dataEntries, mtime)) }
  ], mtime);
}

export function controlText(fields, description) {
  const lines = Object.entries(fields).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => `${k}: ${v}`);
  const [summary, ...body] = description;
  lines.push(`Description: ${summary}`);
  for (const l of body) lines.push(l ? ` ${l}` : " .");
  return `${lines.join("\n")}\n`;
}
