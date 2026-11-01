// Threat-model awareness for the trust-boundary change check (#85): does the repository keep a threat model,
// did the agent's own call write it, and (optionally) does threatcl accept it.
//
// A repository "has a threat model" when it holds a threatcl spec file (`*.hcl` with a top-level
// `threatmodel "<name>" {` block; threatcl, github.com/threatcl/threatcl), or a file matching a path the
// signed policy declares:
//   threatModel: { v: 1, paths: [...globs], require: "notify" | "block-stop", reportWithoutModel: false,
//                  threatclPath: "/opt/moorai/bin/threatcl" }
//     paths               up to 64 globs, matched like oversight.protectedPaths (cli/oversight-surfaces.mjs);
//     require             "notify" (default): an alert at Stop; "block-stop": on Claude Code, Stop is also
//                         answered decision "block" once per turn (cli/boundary-stop.mjs);
//     reportWithoutModel  report boundary changes in a repository with no threat model (default false);
//     threatclPath        the absolute path of the threatcl executable: the only one ever run (PATH is never
//                         searched), and only when it passes whichThreatcl's root-ownership checks.
// Read from the signed policy only (the hook's verified POLICY), never from ~/.moorai. A malformed entry is
// dropped with a warning that names its position, never its value. An older agent ignores the key.
//
// threatcl is never installed or downloaded, and never looked up on PATH: it runs only when the signed policy
// names it in threatModel.threatclPath and the session wrote a threat-model file; `threatcl validate <file>`
// then runs with a short timeout (no shell) and only pass / fail / timeout / error is recorded, its output
// discarded. The hook runs it, possibly outside the agent's sandbox, so the agent must not be able to plant or
// replace it: on POSIX every path component visited from / to the binary (each directory, each symlink and the
// symlinks' targets, and the binary) must be owned by root (uid 0), and each directory and the binary must not be
// group- or world-writable; neither the path nor its real path may be inside the repository or the session cwd.
// It is run by its real path. On Windows the hook never runs threatcl ("unsupported"): there is no owner or ACL
// check there, and no Windows box to validate one against, so a user-writable path would run. No acceptable
// binary: "unset" (no threatclPath), "absent" (missing, not a regular file or not executable), "untrusted" or
// "unsupported"; never a fallback to anything else. What the
// binary is given, and how it runs, is cli/boundary-threatcl-input.mjs: a model that could make it fetch or read
// anything else is "untrusted-input" and not run.
import { readFileSync, readdirSync, statSync, lstatSync, readlinkSync, accessSync, realpathSync, mkdtempSync, writeFileSync, rmSync, constants as FS } from "node:fs";
import { join, dirname, resolve, isAbsolute, relative, sep, extname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { threatclInputSafe, threatclEnv, threatclCommand, GATE_MAX, SANDBOX_EXEC } from "./boundary-threatcl-input.mjs";
import { globRe, protectedPathHit } from "./oversight-surfaces.mjs";
import { splitShell, commandOf, scanArgs, MAX_CMD } from "../data/shell-parse.js";

const MAX_ENTRIES = 64, MAX_LEN = 256;
const CONTROL_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const KNOWN = new Set(["v", "paths", "require", "reportWithoutModel", "threatclPath"]);
const MAX_PATH_LEN = 1024;
// An absolute path: rooted on POSIX; a drive-letter or UNC path on Windows (a path rooted on the current
// drive, with no drive letter, is not).
const absEntry = (p) => typeof p === "string" && (process.platform === "win32" ? /^(?:[A-Za-z]:[\\/]|\\\\[^\\/])/.test(p) : p.startsWith("/"));
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const stderrWarn = (m) => { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* best effort */ } };

export function threatModelPolicy(policy, warn = stderrWarn) {
  const none = { configured: false, paths: [], require: "notify", reportWithoutModel: false, threatclPath: null };
  const o = isObj(policy) ? policy.threatModel : undefined;
  if (o === undefined || o === null) return none;
  if (!isObj(o) || o.v !== 1) { warn("threatModel ignored: not { v: 1, ... }"); return none; }
  if (Object.keys(o).some((k) => !KNOWN.has(k))) warn("threatModel: unknown key ignored");
  const paths = [];
  if (o.paths !== undefined) {
    if (!Array.isArray(o.paths)) warn("threatModel.paths ignored: not a list");
    else {
      if (o.paths.length > MAX_ENTRIES) warn(`threatModel.paths: at most ${MAX_ENTRIES} entries, the rest dropped`);
      o.paths.slice(0, MAX_ENTRIES).forEach((p, i) => {
        if (typeof p !== "string" || !p.trim() || p.length > MAX_LEN || CONTROL_RE.test(p)) { warn(`threatModel.paths entry ${i} dropped: 1-${MAX_LEN} characters of plain text`); return; }
        try { paths.push({ glob: p.trim(), re: globRe(p.trim()) }); } catch { warn(`threatModel.paths entry ${i} dropped: not a valid glob`); }
      });
    }
  }
  let require = "notify";
  if (o.require !== undefined) { if (o.require === "notify" || o.require === "block-stop") require = o.require; else warn("threatModel.require ignored: notify or block-stop"); }
  let reportWithoutModel = false;
  if (o.reportWithoutModel !== undefined) { if (typeof o.reportWithoutModel === "boolean") reportWithoutModel = o.reportWithoutModel; else warn("threatModel.reportWithoutModel ignored: true or false"); }
  let threatclPath = null;
  if (o.threatclPath !== undefined) {
    const t = o.threatclPath;
    if (typeof t === "string" && t.length <= MAX_PATH_LEN && !CONTROL_RE.test(t) && absEntry(t)) threatclPath = t;
    else warn("threatModel.threatclPath ignored: an absolute path to the threatcl executable");
  }
  return { configured: true, paths, require, reportWithoutModel, threatclPath };
}

// A top-level `threatmodel "<name>" {` block, outside a comment.
const TM_BLOCK = /^[ \t]*threatmodel[ \t]+"[^"\n]*"[ \t]*\{/m;
export const isThreatModelText = (text) => typeof text === "string" && TM_BLOCK.test(text.slice(0, 1_048_576));
const isHcl = (p) => /\.hcl$/i.test(String(p || ""));

// The agent's Write / Edit of a threat-model file: a threatcl spec (before or after the write) or a path the
// policy declares.
export function threatModelWrite({ path = "", before = null, after = "", cwd = "", tm = null } = {}) {
  if (!path) return false;
  if (isHcl(path) && (isThreatModelText(before) || isThreatModelText(after))) return true;
  return !!(tm && tm.paths && tm.paths.length && protectedPathHit(path, tm, { cwd, real: true }));
}

const READ_MAX = 262_144;
function readSmall(p) { try { const st = statSync(p); return st.isFile() && st.size <= READ_MAX ? readFileSync(p, "utf8") : null; } catch { return null; } }

// The threat-model files a shell command writes (redirect, tee, sed / perl -i, cp / mv / install target),
// as absolute paths. A .hcl target counts when it is a threatcl spec now or the command carries one. A command
// the shell parser (or reading one of its segments) fails on credits no write: this module has no incomplete
// marker, and a threat-model write is what clears the #85 Stop check, so none is the strict answer
// (cli/boundary-shell.mjs reports the same command as analysis-incomplete). It never throws, so the caller still
// records the call's other fields. parse: the shell splitter, for tests.
const IN_PLACE = new Set(["sed", "gsed", "perl"]);
const COPY = new Set(["cp", "mv", "install", "rsync"]);
export function threatModelCommand(command, { cwd = "", tm = null, ps = false, parse = splitShell } = {}) {
  if (typeof command !== "string" || !command || command.length > MAX_CMD) return [];
  const base = typeof cwd === "string" && cwd ? cwd : process.cwd();
  let segs = [];
  try { segs = parse(command, ps, 0, { segs: [], heredocs: [] }).segs; } catch { return []; }
  const carries = /(?:^|\n)[ \t]*threatmodel[ \t]+"/.test(command);
  const out = new Set();
  const consider = (t) => {
    if (typeof t !== "string" || !t || /[$`\r\n\0]/.test(t)) return;
    const abs = isAbsolute(t) ? t : resolve(base, t);
    if (isHcl(t) && (carries || isThreatModelText(readSmall(abs)))) out.add(abs);
    else if (tm && tm.paths && tm.paths.length && protectedPathHit(t, tm, { cwd: base, real: true })) out.add(abs);
  };
  try {
    for (const s of segs) {
      for (const w of s.writes || []) consider(w);
      const c = commandOf(s.tokens, s.ps);
      if (!c) continue;
      const rest = s.tokens.slice(c.at + 1);
      if (c.binary === "tee") scanArgs(rest, {}).positional.forEach(consider);
      else if (IN_PLACE.has(c.binary) && rest.some((t) => /^-[A-Za-z]*i/.test(t) || t.startsWith("--in-place"))) {
        const { positional } = scanArgs(rest, { shortValued: c.binary === "perl" ? "e" : "ef", longValued: ["--expression", "--file"] });
        positional.slice(c.binary === "perl" || rest.some((t) => /^-[A-Za-z]*e/.test(t)) ? 0 : 1).forEach(consider);
      } else if (COPY.has(c.binary)) {
        const { positional } = scanArgs(rest, { shortValued: "tSm", longValued: ["--target-directory", "--suffix", "--mode"] });
        if (positional.length >= 2) consider(positional[positional.length - 1]);
      }
    }
  } catch { return []; }
  return [...out];
}

// The repository root: the nearest ancestor of cwd holding .git, else cwd.
export function repoRoot(cwd) {
  const start = typeof cwd === "string" && cwd ? resolve(cwd) : process.cwd();
  let cur = start;
  for (let i = 0; i < 64; i++) {
    try { statSync(join(cur, ".git")); return cur; } catch { /* keep walking */ }
    const up = dirname(cur);
    if (up === cur) break;
    cur = up;
  }
  return start;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "vendor", "dist", "build", "target", "out", ".venv", "venv", "__pycache__", ".tox", ".next", ".terraform", ".cache", "coverage", "bower_components", ".gradle", ".idea", ".vscode"]);
// Threat-model files under root, bounded: at most maxEntries directory entries, maxDepth levels, budgetMs.
// truncated: the walk stopped early, so an empty list is not a confirmed absence.
export function findThreatModels(root, tm, { maxEntries = 20_000, maxDepth = 8, budgetMs = 1000, now = Date.now } = {}) {
  const files = [];
  if (typeof root !== "string" || !root) return { files, truncated: false };
  const t0 = now();
  let seen = 0, truncated = false;
  const stack = [[root, 0]];
  while (stack.length) {
    const [dir, depth] = stack.pop();
    let ents;
    try { ents = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (++seen > maxEntries || now() - t0 > budgetMs) { truncated = true; return { files: files.sort(), truncated }; }
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && depth < maxDepth) stack.push([p, depth + 1]); else if (!SKIP_DIRS.has(e.name)) truncated = true; continue; }
      if (!e.isFile()) continue;
      if ((isHcl(e.name) && isThreatModelText(readSmall(p))) || (tm && tm.paths && tm.paths.length && protectedPathHit(p, tm, { cwd: root }))) files.push(p);
    }
  }
  return { files: files.sort(), truncated };
}

const realN = (p) => { try { return realpathSync.native(p); } catch { return null; } };
const fold = (p) => (process.platform === "darwin" || process.platform === "win32" ? p.toLowerCase() : p);
// p is base or below it (case-folded where the file system usually ignores case).
function within(p, base) {
  const r = relative(fold(base), fold(p));
  return r === "" || (r !== ".." && !r.startsWith(".." + sep) && !isAbsolute(r));
}
// The repository root and the session cwd, as written and through their real paths.
function projectRoots(cwd) {
  const c = resolve(typeof cwd === "string" && cwd ? cwd : process.cwd());
  const r = repoRoot(c);
  return [...new Set([c, r, realN(c), realN(r)].filter(Boolean))];
}
function insideProject(p, roots) {
  const rp = realN(p);
  return roots.some((b) => within(resolve(p), b) || (rp !== null && within(rp, b)));
}

// POSIX: walk an absolute path from / the way the kernel resolves it, following symlinks (at most 32), and
// require every component visited to be owned by uid 0, every directory and the final file to have no group or
// world write bit, and the final component to be a regular file. → { state: "ok", real } | { state: "absent" |
// "untrusted" }. `lstat` and `readlink` are parameters for tests only; no policy field or flag reaches them.
export function rootOwnedChain(abs, { lstat = lstatSync, readlink = readlinkSync } = {}) {
  if (typeof abs !== "string" || !abs.startsWith("/")) return { state: "untrusted" };
  const split = (p) => p.split("/").filter(Boolean);
  const dirOk = (st) => st.uid === 0 && st.isDirectory() && !(st.mode & 0o022);
  let st;
  try { st = lstat("/"); } catch { return { state: "absent" }; }
  if (!dirOk(st)) return { state: "untrusted" };
  let parts = split(abs), cur = "/", hops = 0;
  while (parts.length) {
    const name = parts.shift();
    if (name === ".") continue;
    if (name === "..") { cur = dirname(cur); continue; }
    const next = join(cur, name);
    try { st = lstat(next); } catch { return { state: "absent" }; }
    if (st.uid !== 0) return { state: "untrusted" };
    if (st.isSymbolicLink()) {
      if (++hops > 32) return { state: "untrusted" };
      let t;
      try { t = String(readlink(next)); } catch { return { state: "absent" }; }
      parts = [...split(t), ...parts];
      if (t.startsWith("/")) cur = "/";
      continue;
    }
    if (st.mode & 0o022) return { state: "untrusted" };
    if (parts.length) { if (!st.isDirectory()) return { state: "absent" }; }
    else if (!st.isFile()) return { state: "absent" };
    cur = next;
  }
  return cur === "/" ? { state: "absent" } : { state: "ok", real: cur };
}

// The threatcl to run for this session: { bin } (its real path) or { reason: "unset" | "absent" | "untrusted" |
// "unsupported" }. Only the verified policy's threatModel.threatclPath is considered; PATH is never searched.
// `platform` is a parameter for tests only.
export function whichThreatcl({ cwd = "", tm = null, platform = process.platform } = {}) {
  const p = tm && typeof tm.threatclPath === "string" && tm.threatclPath ? tm.threatclPath : "";
  if (!p) return { reason: "unset" };
  if (platform === "win32") return { reason: "unsupported" };
  if (!absEntry(p)) return { reason: "untrusted" };
  const roots = projectRoots(cwd);
  if (insideProject(p, roots)) return { reason: "untrusted" };
  const c = rootOwnedChain(p);
  if (c.state !== "ok") return { reason: c.state };
  const real = c.real;
  if (insideProject(real, roots)) return { reason: "untrusted" };
  try { accessSync(real, FS.X_OK); } catch { return { reason: "absent" }; }
  return { bin: real };
}

// `threatcl validate <file>` for each file, sequentially, within one total timeout (cli/boundary-threatcl-input.mjs
// says what is refused and how it runs). Every file is read once and checked first: one refused file is
// "untrusted-input" and threatcl is not spawned at all. Otherwise each checked copy is written to a fresh empty
// temporary directory, which is threatcl's working directory, and the copy (never the agent's file) is
// validated, with a minimal environment and, on macOS, network denied. "pass" when every run exits 0, "fail" when
// one exits non-zero, "timeout" past the budget, "error" when it cannot run, "none" for no files. Output is
// discarded; the directory is removed afterwards.
export function validateThreatModels(files, { bin, timeoutMs = 3000, now = Date.now } = {}) {
  const list = Array.isArray(files) ? files.slice(0, 8) : [];
  if (!list.length) return "none";
  if (!bin) return "error";
  const t0 = now();
  const checked = [];
  for (const f of list) {
    let buf;
    try { if (statSync(f).size > GATE_MAX) return "untrusted-input"; buf = readFileSync(f); } catch { return "error"; }
    if (buf.length > GATE_MAX || !threatclInputSafe(buf.toString("utf8"))) return "untrusted-input";
    const ext = extname(f);
    checked.push({ buf, ext: /^\.[A-Za-z0-9]{1,8}$/.test(ext) ? ext : ".hcl" });
  }
  try { accessSync(bin, FS.X_OK); } catch { return "error"; }
  const sandboxOk = process.platform === "darwin" && rootOwnedChain(SANDBOX_EXEC).state === "ok";
  let dir;
  try { dir = mkdtempSync(join(tmpdir(), "moorai-threatcl-")); } catch { return "error"; }
  const env = threatclEnv(dir);
  try {
    let result = "pass";
    for (let i = 0; i < checked.length; i++) {
      const left = timeoutMs - (now() - t0);
      if (left <= 0) return "timeout";
      const copy = join(dir, `model-${i}${checked[i].ext}`);
      let r;
      try {
        writeFileSync(copy, checked[i].buf, { mode: 0o600, flag: "wx" });
        const c = threatclCommand(bin, ["validate", copy], { sandboxOk });
        r = spawnSync(c.file, c.args, { cwd: dir, env, timeout: left, stdio: "ignore", shell: false, windowsHide: true, killSignal: "SIGKILL" });
      } catch { return "error"; }
      if (r.error) return r.error.code === "ETIMEDOUT" ? "timeout" : "error";
      if (r.signal) return "timeout";
      if (r.status !== 0) result = "fail";
    }
    return result;
  } finally { try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
}
