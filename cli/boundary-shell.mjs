// Trust boundary changed without a threat-model update (#85), shell side: an install command that adds a
// dependency the project does not declare yet. npm / pnpm / yarn / bun add (or npm install <pkg>), pip
// install <pkg> (also python -m pip, uv pip), uv / poetry add, pipenv install <pkg>, cargo add, go get,
// bundle add, composer require, dotnet add package.
//
// Not counted: an install with no package (restoring the lockfile: npm install, npm ci, pip install -r),
// an editable or local install (pip install -e ., a path), a global tool (-g / --global), a dev / test
// dependency (-D, --save-dev, --dev, --group dev), and a package the project's manifest in cwd already
// declares (npm install express@latest is a bump). Judged per segment of the command (data/shell-parse.js),
// so an echo or a grep that mentions an install is not one. Content-free: returns signal names only.
//
// Linear time (this runs inside PreToolUse on agent-written commands and manifests): no line-anchored pattern
// lets \s span a newline, no two quantifiers overlap, manifest lines over LINE_MAX are blanked (a name on such
// a line is not seen, so an install of it counts as new), and a command over MAX_CMD is not cut and judged
// clean: it is "analysis-incomplete", as is a command the shell parser (or the check itself) fails on.
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { splitShell, commandOf, scanArgs, has, MAX_CMD } from "../data/shell-parse.js";
import { manifestDeps, LINE_MAX, BOUNDARY_INCOMPLETE } from "./boundary-signals.mjs";

const READ_MAX = 1_048_576;
function readSmall(p) { try { const st = statSync(p); return st.isFile() && st.size <= READ_MAX ? readFileSync(p, "utf8") : null; } catch { return null; } }
const shortLines = (t) => t.split("\n").map((l) => (l.length > LINE_MAX ? "" : l)).join("\n");

// The names cwd's manifests already declare, per ecosystem, dev sections included (installing one of those is
// not a new dependency either).
function declared(eco, cwd) {
  const out = new Set();
  if (!cwd) return out;
  const add = (s) => { if (s) for (const n of s) out.add(n); };
  if (eco === "npm") {
    const t = readSmall(join(cwd, "package.json"));
    try { const j = JSON.parse(t || "null"); for (const k of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) if (j && j[k] && typeof j[k] === "object") for (const n of Object.keys(j[k])) out.add(n.toLowerCase()); } catch { /* unreadable: nothing declared */ }
  } else if (eco === "pip") {
    for (const f of ["requirements.txt", "requirements-dev.txt", "requirements-test.txt", "dev-requirements.txt"]) { const t = readSmall(join(cwd, f)); if (t) add(manifestDeps("pip", t)); }
    const py = readSmall(join(cwd, "pyproject.toml"));
    if (py) { add(manifestDeps("pyproject", py)); for (const m of shortLines(py).matchAll(/^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*=/gm)) out.add(m[1].toLowerCase().replace(/[-_.]+/g, "-")); }
  } else if (eco === "cargo") {
    const t = readSmall(join(cwd, "Cargo.toml"));
    if (t) for (const m of shortLines(t).matchAll(/^[ \t]*([A-Za-z0-9_-]+)[ \t]*=/gm)) out.add(m[1].toLowerCase());
  } else if (eco === "go") { const t = readSmall(join(cwd, "go.mod")); if (t) add(manifestDeps("go", t)); }
  else if (eco === "gem") { const t = readSmall(join(cwd, "Gemfile")); if (t) add(manifestDeps("gem", t)); }
  else if (eco === "composer") {
    try { const j = JSON.parse(readSmall(join(cwd, "composer.json")) || "null"); for (const k of ["require", "require-dev"]) if (j && j[k]) for (const n of Object.keys(j[k])) out.add(n.toLowerCase()); } catch { /* nothing declared */ }
  }
  return out;
}

const LOCAL = /^(?:\.{0,2}[/\\]|~|file:|link:|workspace:|[A-Za-z]:\\)|\.(?:tgz|tar\.gz|whl|zip)$/i;
function npmName(spec) {
  if (LOCAL.test(spec)) return null;
  if (/^(?:git\+|https?:|github:|gitlab:|bitbucket:)/i.test(spec) || /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec)) return spec.toLowerCase();
  if (spec.startsWith("@")) { const i = spec.indexOf("@", 1); return (i > 0 ? spec.slice(0, i) : spec).toLowerCase(); }
  const i = spec.indexOf("@");
  return (i > 0 ? spec.slice(0, i) : spec).toLowerCase();
}
function pipName(spec) {
  if (LOCAL.test(spec) || spec === ".") return null;
  const egg = /#egg=([A-Za-z0-9._-]+)/.exec(spec);
  if (egg) return egg[1].toLowerCase().replace(/[-_.]+/g, "-");
  if (/^[a-z+]+:\/\//i.test(spec)) return spec.toLowerCase();
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(spec);
  return m ? m[1].toLowerCase().replace(/[-_.]+/g, "-") : null;
}
// A module path: the part before the first "/" is [\w.-] characters with a "." that is neither first nor last
// (a linear check; the pattern /^[\w.-]+\.[\w.-]+\// backtracks quadratically on a long run of dots).
function goName(spec) {
  const i = spec.indexOf("/");
  if (i < 3) return null;
  const host = spec.slice(0, i);
  return /^[\w.-]+$/.test(host) && host.slice(1, -1).includes(".") ? spec.split("@")[0].toLowerCase() : null;
}
const plain = (spec) => (LOCAL.test(spec) ? null : spec.split(/[@:=<>~^ ]/)[0].toLowerCase() || null);

const NPM_VALUED = ["--registry", "--prefix", "--cache", "--tag", "--workspace", "--filter", "--cwd", "--userconfig", "--dir"];
const PIP_VALUED = ["--index-url", "--extra-index-url", "--constraint", "--target", "--prefix", "--find-links", "--root", "--platform", "--python-version", "--src", "--requirement", "--editable"];
const CARGO_VALUED = ["--features", "--rename", "--package", "--manifest-path", "--registry", "--branch", "--tag", "--rev", "--target", "--path", "--git"];

// → [{ eco, names }] for one segment's command, or [] when it adds nothing.
function installsOf(toks, ps) {
  const c = commandOf(toks, ps);
  if (!c) return [];
  let bin = c.binary, rest = toks.slice(c.at + 1);
  if (/^python[\d.]*$|^py$/.test(bin) && rest[0] === "-m" && /^pip[\d.]*$/.test(rest[1] || "")) { bin = "pip"; rest = rest.slice(2); }
  if (bin === "uv" && rest[0] === "pip") { bin = "pip"; rest = rest.slice(1); }
  const sub = (rest[0] || "").toLowerCase(), args = rest.slice(1);
  const dev = (flags) => has(flags, "-D", "--save-dev", "--dev", "-d", "--save-optional-dev") || flags.some((f) => (f.name === "--group" || f.name === "-G") && /^(?:dev|test|lint|docs)$/i.test(f.value || ""));
  if (["npm", "pnpm", "yarn", "bun"].includes(bin) && (["add"].includes(sub) || (["install", "i", "isntall", "in"].includes(sub) && bin !== "yarn"))) {
    const { flags, positional } = scanArgs(args, { shortValued: "wC", longValued: NPM_VALUED });
    if (dev(flags) || has(flags, "-g", "--global", "--location")) return [];
    const names = positional.map(npmName).filter(Boolean);
    return names.length ? [{ eco: "npm", names }] : [];
  }
  if (/^pip[\d.]*$/.test(bin) && sub === "install") {
    const { flags, positional } = scanArgs(args, { shortValued: "irceft", longValued: PIP_VALUED });
    if (has(flags, "-r", "--requirement", "-e", "--editable")) return [];
    const names = positional.map(pipName).filter(Boolean);
    return names.length ? [{ eco: "pip", names }] : [];
  }
  if ((bin === "uv" || bin === "poetry") && sub === "add") {
    const { flags, positional } = scanArgs(args, { shortValued: "G", longValued: ["--group", "--optional", "--source", "--extra", "--python"] });
    if (dev(flags)) return [];
    const names = positional.map(pipName).filter(Boolean);
    return names.length ? [{ eco: "pip", names }] : [];
  }
  if (bin === "pipenv" && sub === "install") {
    const { flags, positional } = scanArgs(args, { longValued: ["--python", "--categories"] });
    if (dev(flags) || has(flags, "-r", "--requirements")) return [];
    const names = positional.map(pipName).filter(Boolean);
    return names.length ? [{ eco: "pip", names }] : [];
  }
  if (bin === "cargo" && sub === "add") {
    const { flags, positional } = scanArgs(args, { shortValued: "Fp", longValued: CARGO_VALUED });
    if (has(flags, "--dev") || has(flags, "--path")) return [];
    const names = positional.map(plain).filter(Boolean);
    return names.length ? [{ eco: "cargo", names }] : [];
  }
  if (bin === "go" && sub === "get") {
    const { positional } = scanArgs(args, {});
    const names = positional.map(goName).filter(Boolean);
    return names.length ? [{ eco: "go", names }] : [];
  }
  if (bin === "bundle" && sub === "add") {
    const { flags, positional } = scanArgs(args, { longValued: ["--version", "--group", "--source", "--git", "--branch", "--path"] });
    if (flags.some((f) => f.name === "--group" && /dev|test/i.test(f.value || "")) || has(flags, "--path")) return [];
    const names = positional.map(plain).filter(Boolean);
    return names.length ? [{ eco: "gem", names }] : [];
  }
  if (bin === "composer" && sub === "require") {
    const { flags, positional } = scanArgs(args, {});
    if (has(flags, "--dev")) return [];
    const names = positional.map(plain).filter(Boolean);
    return names.length ? [{ eco: "composer", names }] : [];
  }
  if (bin === "dotnet" && sub === "add" && (args[1] || "").toLowerCase() === "package" && args[2]) return [{ eco: "dotnet", names: [args[2].toLowerCase()] }];
  return [];
}

// The installs a command makes, as [{ eco, names }], whatever the manifests say; null when the command could not
// be read (the parser, or reading one of its segments, failed), which is never "no installs". parse: the shell
// splitter, for tests.
export function installedPackages(command, { ps = false, parse = splitShell } = {}) {
  if (typeof command !== "string" || !command || command.length > MAX_CMD) return [];
  let segs = [];
  try { segs = parse(command, ps, 0, { segs: [], heredocs: [] }).segs; } catch { return null; }
  const out = [];
  for (const s of segs) { try { out.push(...installsOf(s.tokens, s.ps)); } catch { return null; } }
  return out;
}

// cwd is the session's working directory: a package its manifest already declares is not new. After a cd in
// the command the directory is not known, and the package is counted.
export function boundaryCommandSignals(command, { cwd = "", ps = false, parse = splitShell } = {}) {
  try {
    if (typeof command === "string" && command.length > MAX_CMD) return [BOUNDARY_INCOMPLETE];
    const inst = installedPackages(command, { ps, parse });
    if (inst === null) return [BOUNDARY_INCOMPLETE];
    if (!inst.length) return [];
    const moved = /(?:^|[\s;&|(])(?:cd|pushd|Set-Location)\s/.test(command);
    const known = new Map();
    for (const { eco, names } of inst) {
      if (!known.has(eco)) known.set(eco, moved ? new Set() : declared(eco, cwd));
      if (names.some((n) => !known.get(eco).has(n))) return ["new-dependency"];
    }
    return [];
  } catch { return [BOUNDARY_INCOMPLETE]; }
}
