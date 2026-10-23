// Trust-boundary change signals (#85), judged on the agent's own change: positives per signal, the benign
// near-miss set with its false-positive rate, install commands, threat-model awareness, threatcl validation
// and the Stop-time assessment over ledger rows.
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-signals.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { BOUNDARY_SIGNALS, boundaryEditSignals } from "../cli/boundary-signals.mjs";
import { boundaryCommandSignals } from "../cli/boundary-shell.mjs";
import { threatModelPolicy, isThreatModelText, threatModelWrite, threatModelCommand, repoRoot, findThreatModels, whichThreatcl, validateThreatModels } from "../cli/boundary-model.mjs";
import { boundaryChanges } from "../cli/boundary-stop.mjs";
import { POSITIVE_EDITS, BENIGN_EDITS, POSITIVE_COMMANDS, BENIGN_COMMANDS } from "./boundary-fixtures.mjs";

const tmp = (tag) => mkdtempSync(join(tmpdir(), `moorai-tb-${tag}-`));
function put(dir, rel, text) { const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; }
const TM_HCL = `spec_version = "0.1.15"\n\nthreatmodel "Payments" {\n  author = "@sec"\n  description = "card flow"\n}\n`;

test("every positive edit fixture raises exactly its signal", () => {
  const cwd = tmp("pos");
  for (const f of POSITIVE_EDITS) {
    assert.deepEqual(boundaryEditSignals({ path: join(cwd, f.path), before: f.before, after: f.after, cwd }), f.expect, f.name);
  }
  const kinds = new Set(POSITIVE_EDITS.flatMap((f) => f.expect));
  for (const s of BOUNDARY_SIGNALS) if (s !== "analysis-incomplete") assert.ok(kinds.has(s), `no positive fixture for ${s}`);
});

test("benign near-misses: none fires (false-positive rate printed)", () => {
  const cwd = tmp("ben");
  assert.ok(BENIGN_EDITS.length + BENIGN_COMMANDS.length >= 30, "at least 30 benign near-misses");
  const fired = [];
  for (const f of BENIGN_EDITS) {
    const s = boundaryEditSignals({ path: join(cwd, f.path), before: f.before, after: f.after, cwd });
    if (s.length) fired.push(`${f.name}: ${s.join(",")}`);
  }
  for (const f of BENIGN_COMMANDS) {
    const dir = tmp("benc");
    for (const [rel, text] of Object.entries(f.manifests)) put(dir, rel, text);
    const s = boundaryCommandSignals(f.command, { cwd: dir });
    if (s.length) fired.push(`${f.name}: ${s.join(",")}`);
  }
  const total = BENIGN_EDITS.length + BENIGN_COMMANDS.length;
  console.log(`benign false positives: ${fired.length}/${total} (${((100 * fired.length) / total).toFixed(1)}%)`);
  assert.deepEqual(fired, []);
});

test("an Edit judged on snippets alone (file unreadable): a new route still fires, a rename does not", () => {
  const cwd = tmp("snip");
  const path = join(cwd, "src/server.js");
  assert.deepEqual(boundaryEditSignals({ path, before: 'app.get("/a", h);', after: 'app.get("/a", h);\napp.post("/b", h);', cwd }), ["new-route"]);
  assert.deepEqual(boundaryEditSignals({ path, before: 'app.get("/a", h);', after: 'app.get("/b", h);', cwd }), []);
});

test("signals are content-free names from the fixed list", () => {
  const cwd = tmp("cf");
  for (const f of POSITIVE_EDITS) for (const s of boundaryEditSignals({ path: join(cwd, f.path), before: f.before, after: f.after, cwd })) assert.ok(BOUNDARY_SIGNALS.includes(s), s);
});

test("install commands: each positive adds a dependency", () => {
  for (const f of POSITIVE_COMMANDS) {
    const dir = tmp("cmd");
    for (const [rel, text] of Object.entries(f.manifests)) put(dir, rel, text);
    assert.deepEqual(boundaryCommandSignals(f.command, { cwd: dir }), f.expect, f.name);
  }
});

test("a pathological command is bounded in time and never throws", () => {
  const t0 = Date.now();
  assert.deepEqual(boundaryCommandSignals("npm install " + "\\".repeat(50_000), { cwd: tmp("big") }).filter((s) => s !== "new-dependency"), []);
  boundaryEditSignals({ path: "/x/src/a.js", before: "", after: "'".repeat(200_000) + "http://" + "a.".repeat(50_000), cwd: "/x" });
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
});

// ---- threat-model awareness ----
test("threatModel policy: v1 only, paths, require, reportWithoutModel; malformed parts dropped with a warning", () => {
  const w = [];
  const p = threatModelPolicy({ threatModel: { v: 1, paths: ["security/models/**", 7], require: "block-stop", reportWithoutModel: true, extra: 1 } }, (m) => w.push(m));
  assert.equal(p.configured, true);
  assert.equal(p.require, "block-stop");
  assert.equal(p.reportWithoutModel, true);
  assert.deepEqual(p.paths.map((x) => x.glob), ["security/models/**"]);
  assert.ok(w.some((m) => /unknown key/.test(m)) && w.some((m) => /entry 1/.test(m)));
  assert.equal(threatModelPolicy({ threatModel: { v: 2 } }, () => {}).configured, false);
  assert.equal(threatModelPolicy({}, () => {}).require, "notify");
  assert.equal(threatModelPolicy({ threatModel: { v: 1, require: "kill" } }, () => {}).require, "notify");
  const abs = process.platform === "win32" ? "C:\\tools\\threatcl.exe" : "/opt/threatcl/bin/threatcl";
  assert.equal(threatModelPolicy({ threatModel: { v: 1, threatclPath: abs } }, () => {}).threatclPath, abs);
  for (const bad of ["bin/threatcl", "./threatcl", "threatcl", 7, "", "/opt/x\nthreatcl"]) {
    const ws = [];
    assert.equal(threatModelPolicy({ threatModel: { v: 1, threatclPath: bad } }, (m) => ws.push(m)).threatclPath, null, String(bad));
    assert.deepEqual(ws, ["threatModel.threatclPath ignored: an absolute path to the threatcl executable"]);
  }
  assert.equal(threatModelPolicy({}, () => {}).threatclPath, null);
});

test("a threatcl file is recognised by its threatmodel block, not by its extension", () => {
  assert.equal(isThreatModelText(TM_HCL), true);
  assert.equal(isThreatModelText(`resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n`), false);
  assert.equal(isThreatModelText(`# threatmodel "x" { is in a comment\n`), false);
});

test("findThreatModels: threatcl HCL files and policy-declared paths, skipping node_modules", () => {
  const root = tmp("find");
  put(root, ".git/HEAD", "ref: x\n");
  put(root, "infra/main.hcl", `resource "x" "y" {}\n`);
  put(root, "node_modules/pkg/tm.hcl", TM_HCL);
  assert.deepEqual(findThreatModels(root, threatModelPolicy({}, () => {})).files, []);
  const f = put(root, "security/payments.hcl", TM_HCL);
  assert.deepEqual(findThreatModels(root, threatModelPolicy({}, () => {})).files, [f]);
  const g = put(root, "docs/threat-model.yaml", "boundaries: []\n");
  assert.deepEqual(findThreatModels(root, threatModelPolicy({ threatModel: { v: 1, paths: ["docs/threat-model.yaml"] } }, () => {})).files.sort(), [g, f].sort());
  mkdirSync(join(root, "a/b/c"), { recursive: true });
  assert.equal(repoRoot(join(root, "a/b/c")), root);
});

test("threatModelWrite: the agent's write to a threatcl file or a declared path", () => {
  const cwd = tmp("tmw");
  const none = threatModelPolicy({}, () => {});
  assert.equal(threatModelWrite({ path: join(cwd, "security/tm.hcl"), before: TM_HCL, after: TM_HCL + "\n", cwd, tm: none }), true);
  assert.equal(threatModelWrite({ path: join(cwd, "security/tm.hcl"), before: null, after: TM_HCL, cwd, tm: none }), true);
  assert.equal(threatModelWrite({ path: join(cwd, "infra/main.hcl"), before: "a = 1\n", after: "a = 2\n", cwd, tm: none }), false);
  const dec = threatModelPolicy({ threatModel: { v: 1, paths: ["docs/threat-model.md"] } }, () => {});
  assert.equal(threatModelWrite({ path: join(cwd, "docs/threat-model.md"), before: "", after: "x", cwd, tm: dec }), true);
});

test("threatModelCommand: a shell write to a threat-model file is a touch; a read is not", () => {
  const cwd = tmp("tmc");
  const f = put(cwd, "security/tm.hcl", TM_HCL);
  const none = threatModelPolicy({}, () => {});
  assert.deepEqual(threatModelCommand("sed -i 's/card/card and wallet/' security/tm.hcl", { cwd, tm: none }), [f]);
  assert.deepEqual(threatModelCommand("cat >> security/tm.hcl <<'EOF'\n# more\nEOF", { cwd, tm: none }), [f]);
  assert.deepEqual(threatModelCommand("cat security/tm.hcl", { cwd, tm: none }), []);
  assert.deepEqual(threatModelCommand("echo hi > infra/main.hcl", { cwd, tm: none }), []);
});

// ---- threatcl validation (fake binary on PATH; never installed) ----
function fakeThreatcl(dir, body) {
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  chmodSync(bin, 0o755);
  const p = join(bin, "threatcl");
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return bin;
}
test("threatcl: only the policy's threatclPath; pass, fail and timeout recorded; a missing binary is an error", { skip: process.platform === "win32" }, () => {
  const d = tmp("tcl");
  const f = put(d, "tm.hcl", TM_HCL);
  assert.deepEqual(whichThreatcl({ cwd: d, tm: threatModelPolicy({}, () => {}) }), { reason: "unset" });
  assert.deepEqual(whichThreatcl({ cwd: d, tm: threatModelPolicy({ threatModel: { v: 1, threatclPath: join(d, "nowhere", "threatcl") } }, () => {}) }), { reason: "untrusted" });
  const okBin = fakeThreatcl(join(d, "ok"), `[ "$1" = validate ] && [ -f "$2" ] && echo "Validated 1 threatmodels in 1 files" && exit 0; exit 3`);
  const bin = join(okBin, "threatcl");
  assert.equal(validateThreatModels([f], { bin, timeoutMs: 3000 }), "pass");
  const badBin = fakeThreatcl(join(d, "bad"), `echo "error: invalid" >&2; exit 1`);
  assert.equal(validateThreatModels([f], { bin: join(badBin, "threatcl"), timeoutMs: 3000 }), "fail");
  const slowBin = fakeThreatcl(join(d, "slow"), `sleep 5`);
  assert.equal(validateThreatModels([f], { bin: join(slowBin, "threatcl"), timeoutMs: 300 }), "timeout");
  assert.equal(validateThreatModels([f], { bin: join(d, "missing/threatcl"), timeoutMs: 300 }), "error");
  assert.equal(validateThreatModels([], { bin, timeoutMs: 300 }), "none");
});

// ---- Stop-time assessment over ledger rows ----
test("boundaryChanges: allowed calls count, denied ones and an untracked Bash ask that never ran do not", () => {
  const rows = [
    { ev: "prompt" },
    { ev: "pre", tool: "Edit", decision: "allow", tb: ["new-dependency"] },
    { ev: "pre", tool: "Write", decision: "deny", tb: ["new-route"] },
    { ev: "pre", tool: "Bash", decision: "ask", u: "u1", tb: ["new-egress-host"] },
    { ev: "pre", tool: "Edit", decision: "allow", tb: ["new-route", "new-dependency"], a: "sub1" }
  ];
  const c = boundaryChanges(rows);
  assert.deepEqual(c.kinds, ["new-dependency", "new-route"]);
  assert.equal(c.count, 2);
  assert.equal(c.delegated, true);
  assert.equal(c.modelTouched, false);
  const touched = boundaryChanges([...rows, { ev: "pre", tool: "Edit", decision: "allow", tm: 1, tmk: "k1" }]);
  assert.equal(touched.modelTouched, true);
  assert.deepEqual(touched.modelKeys, ["k1"]);
  assert.equal(boundaryChanges([...rows, { ev: "pre", tool: "Edit", decision: "deny", tm: 1 }]).modelTouched, false, "a denied write to the model did not happen");
});

test("a symlinked doc path pointing at runtime code is judged as runtime code", { skip: process.platform === "win32" }, () => {
  const cwd = tmp("sym");
  put(cwd, "src/server.js", 'app.get("/a", h);\n');
  mkdirSync(join(cwd, "docs"), { recursive: true });
  symlinkSync(join(cwd, "src/server.js"), join(cwd, "docs/server.md"));
  assert.deepEqual(boundaryEditSignals({ path: join(cwd, "docs/server.md"), before: 'app.get("/a", h);\n', after: 'app.get("/a", h);\napp.post("/b", h);\n', cwd }), ["new-route"]);
});
