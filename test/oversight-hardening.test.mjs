// Weakening oversight (#84) hardening: the threat id (84, apart from the OT protocol read id 81 that
// shipped in 1.28.0), the linear sed and quote scanners (timed on pathological input in a child process,
// so a regression fails instead of hanging the suite), the length / time / script / size guards that fail
// closed, and protected-surface paths normalised through path.resolve and realpath.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-hardening.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { decideOversight } from "../cli/hook-core.mjs";
import { OT_THREAT } from "../cli/ot-protocol-client.mjs";
import { APPROVAL_THREATS } from "../data/human-approval.js";
import * as signalsMod from "../cli/oversight-signals.mjs";
import * as vocabMod from "../cli/oversight-vocab.mjs";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightPolicy, protectedPathHit } from "../cli/oversight-surfaces.mjs";
import { assessOversightDisclosure } from "../cli/oversight-disclosure.mjs";

const { oversightEditSignals } = signalsMod;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const INCOMPLETE = "analysis-incomplete";

// ---- threat id ----
test("threat id: weakening oversight is #84; OT protocol read stays 81 and write 82", () => {
  const { threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const t = threats.find((x) => x.id === 84);
  assert.ok(t, "threat 84 is missing");
  assert.equal(t.threat, "Weakening oversight");
  for (const id of [81, 82, 83]) assert.ok(!threats.some((x) => x.id === id), `threats.json must not define ${id}`);
  assert.ok(APPROVAL_THREATS.has(84) && !APPROVAL_THREATS.has(81) && !APPROVAL_THREATS.has(83));
  assert.deepEqual({ ...OT_THREAT }, { read: 81, write: 82 });
});

test("threat id: threatPolicy[81] (the OT read id) never changes the oversight verdict", () => {
  const base = decideOversight(null, ["wiring-removed"]);
  assert.equal(base.decision, "ask");
  assert.deepEqual(base.findings.map((f) => f.threatId), [84]);
  assert.match(base.reasons[0], /^#84 Weakening oversight/);
  for (const act of ["notify", "block", "kill", "disabled"]) {
    const d = decideOversight({ threatPolicy: { 81: act } }, ["wiring-removed"]);
    assert.deepEqual([d.decision, d.kill, d.findings.map((f) => f.threatId)], ["ask", false, [84]], `threatPolicy[81]=${act}`);
  }
});

test("threat id: threatPolicy[84] sets the oversight verdict, kill included", () => {
  const v = (act) => decideOversight({ threatPolicy: { 84: act } }, ["wiring-removed"]);
  assert.deepEqual([v("notify").decision, v("notify").findings.length], ["allow", 1]);
  assert.equal(v("block").decision, "deny");
  assert.deepEqual([v("kill").decision, v("kill").kill, v("kill").killIds], ["deny", true, [84]]);
  assert.deepEqual([v("disabled").decision, v("disabled").findings.length], ["allow", 0]);
});

// ---- ReDoS: pathological input, timed in a child that is killed if it hangs ----
const SHELL = pathToFileURL(join(ROOT, "cli/oversight-shell.mjs")).href;
const SIG = pathToFileURL(join(ROOT, "cli/oversight-signals.mjs")).href;
// body: an expression over `shell` and `sig`. → { ms (best of three), out }.
function timed(body) {
  const code = `const shell = await import(${JSON.stringify(SHELL)}); const sig = await import(${JSON.stringify(SIG)});
const f = () => (${body});
let best = Infinity, out;
for (let i = 0; i < 3; i++) { const s = process.hrtime.bigint(); out = f(); best = Math.min(best, Number(process.hrtime.bigint() - s) / 1e6); }
process.stdout.write(JSON.stringify({ ms: best, out }));`;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { encoding: "utf8", timeout: 15000 });
  assert.equal(r.signal, null, `timed out (killed with ${r.signal}): ${body.slice(0, 80)}`);
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}
const BOUND_MS = 50;
const N = 50_000;
const PATHOLOGICAL = [
  ["sed s/// script of backslashes", `shell.oversightCommandSignals("sed -i 's/" + "\\\\".repeat(${N}) + "' config/alerts.yaml")`],
  ["sed s||| script of backslashes", `shell.oversightCommandSignals("sed -i 's|" + "\\\\".repeat(${N}) + "|x' config/alerts.yaml")`],
  ["sed /re/d script of backslashes", `shell.oversightCommandSignals("sed -i '/" + "\\\\".repeat(${N}) + "' config/alerts.yaml")`],
  ["sed /re/,/re/d script of backslashes", `shell.oversightCommandSignals("sed -i '/a/,/" + "\\\\".repeat(${N}) + "' config/alerts.yaml")`],
  ["quoted run of escaped quotes and spaces", `sig.oversightEditSignals({ path: "src/app.py", before: "x = 1\\n", after: "x = \\"" + "\\\\\\" ".repeat(${N / 3}) + "\\n" })`],
  ["unclosed quote then spaces", `sig.oversightEditSignals({ path: "src/app.py", before: "x = 1\\n", after: "x = '" + " ".repeat(${N}) + "\\n" })`],
  ["whitespace run with no comment", `sig.oversightEditSignals({ path: "src/app.py", before: "x = 1\\n", after: "x" + " \\t".repeat(${N / 2}) + "y\\n" })`],
  ["YAML key then spaces", `sig.oversightEditSignals({ path: "config/app.yaml", before: "x: 1\\n", after: "key:" + " ".repeat(${N}) + "x\\n" })`],
  ["upper-case identifier", `sig.oversightEditSignals({ path: "src/app.py", before: "x = 1\\n", after: "A".repeat(${N}) + "1\\n" })`],
  ["run of slashes in the working directory", `sig.oversightEditSignals({ path: "a.py", cwd: "/".repeat(${N}) + "a", before: "x = 1\\n", after: "y = 2\\n" })`]
];
for (const [name, body] of PATHOLOGICAL) {
  test(`ReDoS: ${name} (${N / 1000} KB) is judged in under ${BOUND_MS} ms`, () => {
    const { ms } = timed(body);
    assert.ok(ms < BOUND_MS, `${name}: ${ms.toFixed(1)} ms`);
  });
}

test("sed scanner: well-formed substitutions and deletes are still read", () => {
  assert.deepEqual(oversightCommandSignals("sed -i 's/no_notify=False/no_notify=True/' eval_pipeline/config.py"), ["suppression-flag"]);
  assert.deepEqual(oversightCommandSignals("sed -i 's|alerts_enabled: true|alerts_enabled: false|g' config/app.yaml"), ["suppression-flag"]);
  assert.deepEqual(oversightCommandSignals("sed -i 's/a\\/b/c/' config/app.yaml"), []);
});

// ---- guards that fail closed ----
test("guard: a command longer than the analysis cap is held as incomplete, never cut and judged clean", () => {
  const s = oversightCommandSignals("echo x > config/app.yaml " + "#".repeat(300_000));
  assert.ok(s.includes(INCOMPLETE), JSON.stringify(s));
  assert.deepEqual(oversightCommandSignals("echo hello " + "a".repeat(300_000)), [INCOMPLETE]);
});

test("guard: a command whose analysis runs past the time budget is held as incomplete", () => {
  let t = 0;
  const now = () => (t += 1000);
  const s = oversightCommandSignals("echo a > config/a.yaml; echo b > config/b.yaml; rm notes.txt", { now });
  assert.ok(s.includes(INCOMPLETE), JSON.stringify(s));
  assert.deepEqual(oversightCommandSignals("echo a > config/a.yaml; rm notes.txt"), []);
});

test("guard: a sed script longer than the script cap is held as incomplete", () => {
  const s = oversightCommandSignals("sed -i 's/a/b/;" + "x".repeat(70_000) + "' config/app.yaml");
  assert.ok(s.includes(INCOMPLETE), JSON.stringify(s));
});

test("guard: a write larger than the analysis cap is held as incomplete, never cut and judged clean", () => {
  const big = "alerts:\n  recipients: [ops@example.com]\n" + "# filler\n".repeat(130_000);
  const s = oversightEditSignals({ path: "config/alerts.yaml", before: "a: 1\n", after: big });
  assert.ok(s.includes(INCOMPLETE), JSON.stringify(s));
  assert.deepEqual(oversightEditSignals({ path: "docs/big.md", before: "a\n", after: big }), []);
});

test("guard: a Write over an existing file too large to read is held as incomplete; a new file is not", () => {
  assert.deepEqual(oversightEditSignals({ path: "config/alerts.yaml", before: null, after: "a: 1\n", beforeUnread: true }), [INCOMPLETE]);
  assert.deepEqual(oversightEditSignals({ path: "config/alerts.yaml", before: null, after: "a: 1\n" }), []);
  assert.deepEqual(oversightEditSignals({ path: "docs/notes.md", before: null, after: "a\n", beforeUnread: true }), []);
});

test("guard: an incomplete analysis asks even where the policy lowers #84 to notify, and never kills", () => {
  assert.equal(decideOversight(null, [INCOMPLETE]).decision, "ask");
  assert.equal(decideOversight({ threatPolicy: { 84: "notify" } }, [INCOMPLETE]).decision, "ask");
  const k = decideOversight({ threatPolicy: { 84: "kill" } }, [INCOMPLETE]);
  assert.deepEqual([k.decision, k.kill], ["deny", false]);
  assert.equal(decideOversight({ threatPolicy: { 84: "disabled" } }, [INCOMPLETE]).decision, "allow");
  assert.equal(decideOversight({ threatPolicy: { 84: "kill" } }, ["wiring-removed", INCOMPLETE]).kill, true);
});

test("guard: an incomplete analysis is not an oversight change for the Stop disclosure check", () => {
  const rows = [{ ev: "pre", tool: "Write", decision: "ask", ov: [INCOMPLETE] }];
  assert.deepEqual(assessOversightDisclosure(rows, "done").changed, false);
});

// ---- protected surfaces: ../ and symlinks ----
function project() {
  const dir = mkdtempSync(join(tmpdir(), "ov-paths-"));
  const proj = join(dir, "proj");
  mkdirSync(join(proj, "ops/alerting"), { recursive: true });
  mkdirSync(join(proj, "src"), { recursive: true });
  mkdirSync(join(proj, "other"), { recursive: true });
  writeFileSync(join(proj, "ops/alerting/rules.yaml"), "a: 1\n");
  writeFileSync(join(proj, "other/x.yaml"), "a: 1\n");
  symlinkSync(join(proj, "ops/alerting"), join(proj, "innocent"));
  symlinkSync(join(proj, "ops/alerting/rules.yaml"), join(proj, "cfg.yaml"));
  symlinkSync(join(proj, "other"), join(proj, "elsewhere"));
  return { dir, proj };
}
const SURF = oversightPolicy({ oversight: { v: 1, protectedPaths: ["ops/alerting/**"] } }, () => {});
const PS = "protected-surface";

test("protected path: a write through a symlinked directory or file is judged on its real target", () => {
  const { dir, proj } = project();
  try {
    const ed = (rel, before = "a: 1\n") => oversightEditSignals({ path: join(proj, rel), before, after: "a: 2\n", surfaces: SURF, cwd: proj });
    assert.ok(ed("innocent/rules.yaml").includes(PS), "existing file through a directory link");
    assert.ok(ed("innocent/new.yaml", null).includes(PS), "new file through a directory link");
    assert.ok(ed("innocent/sub/new.yaml", null).includes(PS), "new file in a new directory through a link");
    assert.ok(ed("cfg.yaml").includes(PS), "file link");
    assert.ok(ed("ops/tmp/../alerting/rules.yaml").includes(PS), "../ inside the path");
    assert.ok(!ed("elsewhere/x.yaml").includes(PS), "a link to an unprotected directory");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("protected path: ../ and ./ are resolved against cwd even without the realpath lookup", () => {
  assert.ok(protectedPathHit("ops/tmp/../alerting/x.yaml", SURF, { cwd: "/srv/proj" }));
  assert.ok(protectedPathHit("/srv/proj/ops/./alerting/x.yaml", SURF, { cwd: "/srv/proj" }));
  assert.ok(protectedPathHit("x.yaml", SURF, { cwd: "/srv/proj/ops/alerting" }));
  assert.ok(!protectedPathHit("ops/tmp/../other/x.yaml", SURF, { cwd: "/srv/proj" }));
});

test("protected path: a shell path is resolved against cwd (../) and through symlinks", () => {
  const { dir, proj } = project();
  try {
    const sh = (cmd) => oversightCommandSignals(cmd, { surfaces: SURF, cwd: proj });
    assert.ok(sh("rm ops/tmp/../alerting/rules.yaml").includes(PS), "../ in a delete");
    assert.ok(sh("echo x > ops/./alerting/new.yaml").includes(PS), "./ in a redirect");
    assert.ok(oversightCommandSignals("rm rules.yaml", { surfaces: SURF, cwd: join(proj, "ops/alerting") }).includes(PS), "a relative path from a subdirectory");
    assert.ok(sh("rm innocent/rules.yaml").includes(PS), "delete through a directory link");
    assert.ok(sh("echo x > cfg.yaml").includes(PS), "redirect into a file link");
    assert.ok(!sh("rm elsewhere/x.yaml").includes(PS), "a link to an unprotected directory");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- the linear scanners read exactly what the regexes they replace read ----
const rng = (seed) => () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
const randomStrings = (alpha, count, maxLen, seed) => {
  const r = rng(seed), out = [];
  for (let t = 0; t < count; t++) { let s = ""; const n = 1 + Math.floor(r() * maxLen); for (let i = 0; i < n; i++) s += alpha[Math.floor(r() * alpha.length)]; out.push(s); }
  return out;
};
test("quote scanner: replaces the same strings as the 1.29.0 regex (seeded fuzz, newline-free lines)", () => {
  const old = (s) => s.replace(/(["'`])(?:(?!\1)[^\\\n]|\\.)*\s(?:(?!\1)[^\\\n]|\\.)*\1/g, '""');
  for (const s of randomStrings(["a", " ", "\\", "'", '"', "`", "\t", "b", "\r", "\u2028", "\u00a0"], 50_000, 14, 7)) assert.equal(signalsMod.proseless(s), old(s), JSON.stringify(s));
});
test("words(): the camel-case split matches the 1.29.0 regex (seeded fuzz)", () => {
  const old = (x) => { const parts = String(x || "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean); const o = [...parts]; for (let i = 0; i + 1 < parts.length; i++) o.push(parts[i] + parts[i + 1]); return o; };
  for (const s of randomStrings(["A", "B", "a", "b", "1", "_", "."], 50_000, 12, 11)) assert.deepEqual(vocabMod.words(s), old(s), JSON.stringify(s));
});
