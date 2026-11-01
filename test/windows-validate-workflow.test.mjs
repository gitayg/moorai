// .github/workflows/windows-validate.yml must keep running the Windows validation suite on a real Windows
// runner: the validator in strict, Windows-required mode, the Windows-only and MXC test files, and the
// report uploaded as an artifact. A text check, so a refactor that drops a step goes red here and not
// silently on GitHub.
//
//   node --test test/windows-validate-workflow.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WF = join(ROOT, ".github", "workflows", "windows-validate.yml");
const text = () => (existsSync(WF) ? readFileSync(WF, "utf8") : "");

test("workflow: runs on windows-latest, on push, pull request and by hand", () => {
  const t = text();
  assert.ok(t, "windows-validate.yml is missing");
  assert.match(t, /runs-on:\s*windows-latest/);
  for (const k of ["push:", "pull_request:", "workflow_dispatch:"]) assert.ok(t.includes(k), k);
  assert.match(t, /permissions:\s*\n\s*contents:\s*read/);
});

test("workflow: runs the validator in strict, Windows-required mode and uploads the report", () => {
  const t = text();
  assert.match(t, /node cli\/moorai-windows-validate\.mjs[^\n]*--strict/);
  assert.match(t, /node cli\/moorai-windows-validate\.mjs[^\n]*--require-windows/);
  assert.match(t, /node cli\/moorai-windows-validate\.mjs[^\n]*--out /);
  assert.match(t, /uses:\s*actions\/upload-artifact@v5/);
  assert.match(t, /if:\s*always\(\)/, "the report must upload when the validator fails");
});

test("workflow: runs the Windows-only, validation, MXC and PowerShell test files one at a time", () => {
  const t = text();
  for (const f of ["test/windows-runtime.test.mjs", "test/windows-validate.test.mjs", "test/mxc-detect.test.mjs", "test/mxc-policy.test.mjs", "test/mxc-denials.test.mjs", "test/powershell-hook.test.mjs"]) {
    assert.ok(t.includes(f), f);
    assert.ok(existsSync(join(ROOT, f)), `${f} is named but does not exist`);
  }
  assert.match(t, /--test-concurrency=1/);
  assert.match(t, /--import \.\/test\/hermetic-env\.mjs/);
});
