// Gives each unit-test process its own empty home and fails the process if a test reaches the real one.
//
// Loaded by hermetic-env.mjs, i.e. once per test file, before the file's imports run. The home the
// process was STARTED with is the guarded one; HOME/USERPROFILE are pointed at a fresh temp dir, so
// modules that resolve state paths at import time, and children spawned with `{ ...process.env }`,
// land there. Two ways back to the real home remain, and both are recorded rather than allowed:
//   * an in-process write (fs sync, callback, promise or stream API) to a path under the real home
//     outside the repository checkout;
//   * a child spawned with an explicit env whose HOME is unset (the child then resolves the real home
//     from the password database) or points inside the real home (outside the repository checkout).
// Nothing is blocked — the write or spawn proceeds exactly as before — but at exit each violation is
// printed with the test-file frame that caused it and the exit code is set to 1, which node --test
// reports as a failure of that file. Only this process's own calls are judged, so a concurrent run
// or an installed agent writing ~/.moorai cannot fail the suite.
import { createRequire, syncBuiltinESMExports } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const REPO = resolve(fileURLToPath(new URL("..", import.meta.url)));

const FS_PATH_ARGS = {
  writeFileSync: [0], appendFileSync: [0], mkdirSync: [0], mkdtempSync: [0], createWriteStream: [0],
  rmSync: [0], rmdirSync: [0], unlinkSync: [0], truncateSync: [0], utimesSync: [0], chmodSync: [0],
  renameSync: [0, 1], copyFileSync: [1], cpSync: [1], symlinkSync: [1], linkSync: [1],
  writeFile: [0], appendFile: [0], mkdir: [0], mkdtemp: [0], rm: [0], rmdir: [0], unlink: [0],
  truncate: [0], utimes: [0], chmod: [0], rename: [0, 1], copyFile: [1], cp: [1], symlink: [1], link: [1]
};
const OPEN_FNS = ["openSync", "open"];
const SPAWN_FNS = ["spawn", "spawnSync", "execFile", "execFileSync", "fork", "exec", "execSync"];

const asPath = (p) => {
  if (typeof p === "string") return p;
  if (Buffer.isBuffer(p)) return p.toString();
  if (p instanceof URL && p.protocol === "file:") return fileURLToPath(p);
  return null;
};
const inside = (p, dir) => p === dir || p.startsWith(dir.endsWith(sep) ? dir : dir + sep);
const writesFlag = (flags) => {
  if (typeof flags !== "number") return /[wa+]/.test(String(flags ?? "r"));
  const c = require("node:fs").constants;
  return (flags & (c.O_WRONLY | c.O_RDWR | c.O_CREAT | c.O_APPEND | c.O_TRUNC)) !== 0;
};

function caller() {
  const lines = (new Error().stack || "").split("\n").slice(1);
  const own = fileURLToPath(import.meta.url);
  const frame = lines.find((l) => !l.includes(own) && !l.includes("node:")) || lines[lines.length - 1] || "";
  const testFrame = lines.find((l) => /[\\/]test[\\/].*\.test\.mjs/.test(l));
  return (testFrame || frame).trim().replace(/^at /, "");
}

export function installHomeGuard() {
  const realHome = process.env.HOME || process.env.USERPROFILE;
  if (!realHome) return;
  const real = resolve(realHome);
  const testHome = mkdtempSync(join(tmpdir(), "moorai-test-home-"));
  process.env.HOME = testHome;
  process.env.USERPROFILE = testHome;
  process.env.MOORAI_TEST_REAL_HOME = real;

  const violations = [];
  const reached = (raw) => {
    const s = asPath(raw);
    if (s == null) return false;
    const p = resolve(s);
    return inside(p, real) && !inside(p, REPO) && !inside(p, testHome);
  };
  const record = (what) => {
    const v = `${what}\n      at ${caller()}`;
    if (violations.length < 50 && !violations.includes(v)) violations.push(v);
  };

  const wrap = (obj, name, check) => {
    const orig = obj[name];
    if (typeof orig !== "function") return;
    const wrapped = function (...args) { check(args); return orig.apply(this, args); };
    Object.defineProperties(wrapped, Object.getOwnPropertyDescriptors(orig));
    obj[name] = wrapped;
  };

  const fs = require("node:fs");
  for (const target of [fs, fs.promises]) {
    for (const [name, idx] of Object.entries(FS_PATH_ARGS)) {
      wrap(target, name, (args) => { for (const i of idx) if (reached(args[i])) record(`fs.${name}(${asPath(args[i])})`); });
    }
    for (const name of OPEN_FNS) {
      wrap(target, name, (args) => { if (writesFlag(args[1]) && reached(args[0])) record(`fs.${name}(${asPath(args[0])}, ${String(args[1])})`); });
    }
  }

  const cp = require("node:child_process");
  for (const name of SPAWN_FNS) {
    wrap(cp, name, (args) => {
      const opts = args.find((a, i) => i > 0 && a && typeof a === "object" && !Array.isArray(a));
      const env = opts && opts.env;
      if (!env) return;
      const h = env.HOME ?? env.USERPROFILE;
      if (h == null || h === "") record(`child_process.${name}(${String(args[0])}) with an env that has no HOME — the child resolves the real home`);
      else if (inside(resolve(String(h)), real) && !inside(resolve(String(h)), REPO)) record(`child_process.${name}(${String(args[0])}) with HOME=${h}`);
    });
  }
  syncBuiltinESMExports();

  process.on("exit", () => {
    if (violations.length) {
      process.stderr.write(`\nhome-guard: ${process.argv[1] || "this process"} reached the REAL home ${real}:\n` +
        violations.map((v) => `  ${v}\n`).join("") +
        "home-guard: tests must write only under the per-process HOME set by test/hermetic-env.mjs.\n");
      process.exitCode = 1;
    }
    try { rmSync(testHome, { recursive: true, force: true }); } catch {}
  });
}
