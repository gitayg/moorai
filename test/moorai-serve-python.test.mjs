// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/moorai-serve-python.test.mjs
//
// The Python client (clients/python, stdlib only) against a live `moorai serve`: its own unittest suite
// starts the sidecar itself. Skipped, and says so, where python3 is not installed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rmSync } from "node:fs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "clients", "python");
const py = spawnSync("python3", ["--version"], { encoding: "utf8" });
const skip = py.status === 0 ? false : "python3 not installed";

test("clients/python unittest suite passes against a live moorai serve", { skip }, (t) => {
  const r = spawnSync("python3", ["-B", "-m", "unittest", "discover", "-s", DIR, "-p", "test_*.py", "-v"], { cwd: DIR, encoding: "utf8", timeout: 90000, env: { ...process.env, NODE: process.execPath, PYTHONDONTWRITEBYTECODE: "1" } });
  rmSync(join(DIR, "__pycache__"), { recursive: true, force: true });
  t.diagnostic(`${py.stdout.trim() || py.stderr.trim()} · ${(r.stderr.match(/Ran \d+ tests[^\n]*/) || [""])[0]}`);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.match(r.stderr, /\nOK\s*$/);
});
