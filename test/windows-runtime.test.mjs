// Windows runtime validation: the assertions only a real Windows host can make. Every test here is SKIPPED
// off Windows (it cannot be faked: the hook has no platform knob, and reg.exe and powershell.exe exist only
// there). It runs in .github/workflows/windows-validate.yml on windows-latest, and an operator can run it on
// any Windows box with a checkout:
//
//   node --test --import ./test/hermetic-env.mjs test/windows-runtime.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { release } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseBuild, readUbrFromRegistry, mxcCapableFrom } from "../cli/mxc-detect.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SKIP = process.platform !== "win32" && "needs a real Windows host";
const probes = await import("../cli/windows-validate-probes.mjs").catch(() => ({}));

test("Windows: os.release() parses to a build number, and reg.exe gives the UBR as an integer", { skip: SKIP }, () => {
  const build = parseBuild(release());
  assert.ok(Number.isInteger(build) && build >= 10240, `build: ${build}`);
  const ubr = readUbrFromRegistry();
  assert.ok(Number.isInteger(ubr) && ubr >= 0, `UBR: ${ubr}`);
  const capable = mxcCapableFrom(build, ubr);
  assert.ok(capable === true || capable === false || capable === null);
});

test("Windows: the full validation with --require-windows passes, every probe including the PowerShell host and MXC enforcement", { skip: SKIP }, async () => {
  const r = await probes.runValidation({ agentRoot: ROOT, requireWindows: true });
  const bad = r.probes.filter((p) => p.status !== "pass");
  assert.deepEqual(bad, [], JSON.stringify(bad));
  assert.equal(r.summary.verdict, "pass");
  assert.equal(r.platform, "win32");
  assert.ok(Number.isInteger(r.osBuild));
  for (const id of ["powershell-host", "mxc-registry", "mxc-enforce"]) assert.ok(r.probes.some((p) => p.id === id && p.status === "pass"), id);
});

test("Windows: the hook run through powershell.exe returns the same deny as the hook run directly", { skip: SKIP }, async () => {
  const r = await probes.runValidation({ agentRoot: ROOT, only: ["hook-powershell-block", "powershell-host"] });
  assert.deepEqual(r.probes.map((p) => [p.id, p.status, p.observed]), [["hook-powershell-block", "pass", "deny"], ["powershell-host", "pass", "deny"]]);
});
