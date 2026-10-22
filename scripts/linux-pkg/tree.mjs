// The file trees the Linux packages carry, as tar entries (scripts/linux-pkg/tar.mjs).
//
// Agent tree: the files package.json `files` ships to npm (tracked files only, read from the working
// tree), plus package.json, README.md and LICENSE, under /usr/lib/moorai; the Linux helpers under
// /usr/lib/moorai/linux; the systemd user units under /usr/lib/systemd/user; and one /usr/bin link per
// package.json `bin`.
// guardd tree: exactly what guardd/packaging/linux/install.sh stages, minus /etc/moorai (the postinst
// makes it), so the package and the script cannot drift apart.
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, readdirSync, lstatSync, mkdtempSync, rmSync, readlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix, relative, sep } from "node:path";

export const LIB = "usr/lib/moorai";
const LINUX_HELPERS = ["moorai-node", "moorai-install-hooks"];
const USER_UNITS = ["moorai-hooks.service", "moorai-serve.service"];

function trackedFiles(repo, paths) {
  const out = execFileSync("git", ["-C", repo, "ls-files", "-s", "--", ...paths], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return out.split("\n").filter(Boolean).map((line) => {
    const m = /^(\d{6}) [0-9a-f]+ \d\t(.+)$/.exec(line);
    if (!m) throw new Error(`unexpected git ls-files line: ${line}`);
    return { path: m[2], exec: m[1] === "100755", link: m[1] === "120000" };
  });
}

function addDirs(entries, seen, path) {
  const parts = path.split("/");
  for (let i = 1; i < parts.length; i++) {
    const d = `${parts.slice(0, i).join("/")}/`;
    if (!seen.has(d)) { seen.add(d); entries.push({ path: d, type: "dir", mode: 0o755 }); }
  }
}

export function withDirs(entries, base) {
  const seen = new Set();
  const out = [];
  if (base) { out.push({ path: base, type: "dir", mode: 0o755 }); seen.add(base); }
  for (const e of [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    addDirs(out, seen, e.path);
    out.push(e);
  }
  return out;
}

// The agent's files and links without directory entries. prefix: "./" for a .deb data member,
// "moorai-<v>/root/" for the tarball (whose builder adds its scripts, then calls withDirs).
export function agentEntries(repo, prefix = "./") {
  const pkg = JSON.parse(readFileSync(join(repo, "package.json"), "utf8"));
  const bins = new Set(Object.values(pkg.bin));
  const files = trackedFiles(repo, [...pkg.files, "package.json", "README.md", "LICENSE"]);
  const entries = [];
  for (const f of files) {
    if (f.link) throw new Error(`a symlink in the shipped files is not supported: ${f.path}`);
    const data = readFileSync(join(repo, f.path));
    entries.push({ path: `${prefix}${LIB}/${f.path}`, type: "file", mode: f.exec || bins.has(f.path) ? 0o755 : 0o644, data });
  }
  for (const h of LINUX_HELPERS) entries.push({ path: `${prefix}${LIB}/linux/${h}`, type: "file", mode: 0o755, data: readFileSync(join(repo, "packaging", "linux", h)) });
  for (const u of USER_UNITS) entries.push({ path: `${prefix}usr/lib/systemd/user/${u}`, type: "file", mode: 0o644, data: readFileSync(join(repo, "packaging", "linux", u)) });
  for (const [name, target] of Object.entries(pkg.bin)) entries.push({ path: `${prefix}usr/bin/${name}`, type: "symlink", mode: 0o777, target: `../lib/moorai/${target}` });
  entries.push({ path: `${prefix}usr/bin/moorai-install-hooks`, type: "symlink", mode: 0o777, target: "../lib/moorai/linux/moorai-install-hooks" });
  return entries;
}

export function agentTree(repo) {
  return withDirs(agentEntries(repo, "./"), "./");
}

function walk(root, dir, out) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    const st = lstatSync(p);
    const rel = relative(root, p).split(sep).join(posix.sep);
    if (st.isDirectory()) walk(root, p, out);
    else if (st.isSymbolicLink()) out.push({ path: `./${rel}`, type: "symlink", mode: 0o777, target: readlinkSync(p) });
    else out.push({ path: `./${rel}`, type: "file", mode: st.mode & 0o777, data: readFileSync(p) });
  }
}

export function guarddTree(repo, binary) {
  const stage = mkdtempSync(join(tmpdir(), "moorai-guardd-stage-"));
  try {
    const r = spawnSync("sh", [join(repo, "guardd", "packaging", "linux", "install.sh"), binary], { encoding: "utf8", env: { ...process.env, MOORAI_GUARDD_STAGE: stage } });
    if (r.status !== 0) throw new Error(`guardd install.sh refused the binary: ${(r.stderr || "").trim()}`);
    rmSync(join(stage, "etc"), { recursive: true, force: true });
    const entries = [];
    walk(stage, stage, entries);
    return withDirs(entries, "./");
  } finally { rmSync(stage, { recursive: true, force: true }); }
}
