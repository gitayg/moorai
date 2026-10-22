// The common ar format a .deb is built on (deb(5)): "!<arch>\n", then for each member a 60-byte header
// (name, mtime, uid, gid, octal mode, decimal size, "`\n"), the data, and a "\n" pad to an even offset.
// Member names here are short (debian-binary, control.tar.gz, data.tar.gz), so no extended-name table.

function field(value, width) {
  const s = String(value);
  if (s.length > width) throw new RangeError(`ar: ${s} does not fit in ${width} bytes`);
  return s.padEnd(width, " ");
}

export function arArchive(members, mtime) {
  const parts = [Buffer.from("!<arch>\n", "latin1")];
  for (const m of members) {
    if (m.name.length > 15) throw new RangeError(`ar: member name too long: ${m.name}`);
    const h = field(m.name, 16) + field(mtime, 12) + field(0, 6) + field(0, 6) + field("100644", 8) + field(m.data.length, 10) + "`\n";
    parts.push(Buffer.from(h, "latin1"), m.data);
    if (m.data.length % 2) parts.push(Buffer.from("\n", "latin1"));
  }
  return Buffer.concat(parts);
}
