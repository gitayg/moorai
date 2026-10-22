// A minimal, deterministic POSIX ustar writer for the Linux packages. Every entry is owned by root:root
// (uid/gid 0) and stamped with one mtime, so the same tree and epoch always give the same bytes.
// Entries: { path, type: "dir" | "file" | "symlink", mode, data?: Buffer, target?: string }.

const BLOCK = 512;

function octal(n, width) {
  const s = n.toString(8);
  if (s.length > width - 1) throw new RangeError(`tar: ${n} does not fit in ${width} bytes`);
  return s.padStart(width - 1, "0") + "\0";
}

function put(buf, offset, width, str) {
  const b = Buffer.from(str, "utf8");
  if (b.length > width) throw new RangeError(`tar: field too long: ${str}`);
  b.copy(buf, offset);
}

// ustar keeps names of up to 100 bytes, or a prefix of up to 155 plus a name of up to 100 split at a "/".
function splitName(path) {
  if (Buffer.byteLength(path) <= 100) return { name: path, prefix: "" };
  for (let i = path.length - 1; i > 0; i--) {
    if (path[i] !== "/") continue;
    const prefix = path.slice(0, i);
    const name = path.slice(i + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100 && name.length > 0) return { name, prefix };
  }
  throw new RangeError(`tar: path too long for ustar: ${path}`);
}

function header(entry, mtime) {
  const h = Buffer.alloc(BLOCK);
  const path = entry.type === "dir" && !entry.path.endsWith("/") ? `${entry.path}/` : entry.path;
  const { name, prefix } = splitName(path);
  const size = entry.type === "file" ? entry.data.length : 0;
  put(h, 0, 100, name);
  put(h, 100, 8, octal(entry.mode & 0o7777, 8));
  put(h, 108, 8, octal(0, 8));
  put(h, 116, 8, octal(0, 8));
  put(h, 124, 12, octal(size, 12));
  put(h, 136, 12, octal(mtime, 12));
  h.fill(0x20, 148, 156);
  put(h, 156, 1, entry.type === "dir" ? "5" : entry.type === "symlink" ? "2" : "0");
  if (entry.type === "symlink") put(h, 157, 100, entry.target);
  put(h, 257, 6, "ustar\0");
  put(h, 263, 2, "00");
  put(h, 265, 32, "root");
  put(h, 297, 32, "root");
  put(h, 329, 8, octal(0, 8));
  put(h, 337, 8, octal(0, 8));
  put(h, 345, 155, prefix);
  let sum = 0;
  for (const byte of h) sum += byte;
  put(h, 148, 8, `${sum.toString(8).padStart(6, "0")}\0 `);
  return h;
}

export function tarball(entries, mtime) {
  const parts = [];
  for (const e of entries) {
    parts.push(header(e, mtime));
    if (e.type === "file") {
      parts.push(e.data);
      const pad = (BLOCK - (e.data.length % BLOCK)) % BLOCK;
      if (pad) parts.push(Buffer.alloc(pad));
    }
  }
  parts.push(Buffer.alloc(BLOCK * 2));
  return Buffer.concat(parts);
}
