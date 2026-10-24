// #85, shell side: a command the shell parser fails on is never judged clean. The install check reports
// analysis-incomplete; the threat-model-write check credits no write (a write is what clears the Stop check)
// and does not throw, so the call's other boundary fields are still recorded.
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-failclosed.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { boundaryCommandSignals, installedPackages } from "../cli/boundary-shell.mjs";
import { threatModelCommand } from "../cli/boundary-model.mjs";

const parse = () => { throw new Error("parser fault"); };
const cwd = "/tmp/proj";

test("boundary-shell: a parser fault is analysis-incomplete, not an empty result", () => {
  assert.deepEqual(boundaryCommandSignals("npm install left-pad", { cwd, parse }), ["analysis-incomplete"]);
  assert.equal(installedPackages("npm install left-pad", { parse }), null, "installedPackages reports the fault as null, not as no installs");
});

test("boundary-shell: any other fault inside the check is analysis-incomplete too", () => {
  const broken = () => ({ segs: [{ get tokens() { throw new Error("segment fault"); } }] });
  assert.deepEqual(boundaryCommandSignals("npm install left-pad", { cwd, parse: broken }), ["analysis-incomplete"]);
});

test("boundary-shell: a clean parse still reads installs (the seam changes nothing)", () => {
  assert.deepEqual(installedPackages("npm install left-pad"), [{ eco: "npm", names: ["left-pad"] }]);
});

test("boundary-model: a parser fault credits no threat-model write and does not throw", () => {
  let r;
  assert.doesNotThrow(() => { r = threatModelCommand("cat > security/tm.hcl <<'EOF'\nthreatmodel \"x\" {\nEOF", { cwd, parse }); });
  assert.deepEqual(r, []);
});

test("boundary-model: a fault reading a segment credits no write and does not throw", () => {
  const broken = () => ({ segs: [{ tokens: ["tee", "security/tm.hcl"], writes: [] }, { get tokens() { throw new Error("segment fault"); }, writes: [] }] });
  let r;
  assert.doesNotThrow(() => { r = threatModelCommand("tee security/tm.hcl", { cwd, parse: broken }); });
  assert.deepEqual(r, []);
});
