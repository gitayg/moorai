// Weakening oversight (#84): where a write or a shell command really lands. A symlink named like a doc or a
// fixture is judged on its real target; a `cd` / `pushd` / Set-Location moves the paths of the segments after
// it (a subshell's `cd` stays inside it, a non-literal target fails closed); a move counts as a rename only
// when it stays inside the project with the same path class and an importable name.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-paths.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { oversightEditSignals } from "../cli/oversight-signals.mjs";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightPolicy } from "../cli/oversight-surfaces.mjs";
import { CASE1_NOTIFY_BEFORE, CASE1_ALERTS_YAML } from "./oversight-fixtures.mjs";

const INCOMPLETE = "analysis-incomplete";
// tmpdir() is itself a symlink on macOS (/var -> /private/var), so cwd is not its own real path here.
const proj = mkdtempSync(join(tmpdir(), "moorai-ovpaths-"));
after(() => rmSync(proj, { recursive: true, force: true }));
for (const d of ["src", "deploy", "config", "docs", "tests/fixtures", "monitoring", "lib/monitoring", "ops/alerting", "build"]) mkdirSync(join(proj, d), { recursive: true });
writeFileSync(join(proj, "src/notify.py"), CASE1_NOTIFY_BEFORE);
writeFileSync(join(proj, "deploy/eval.env"), "APP_PORT=8080\n");
writeFileSync(join(proj, "config/alerts.yaml"), CASE1_ALERTS_YAML);
writeFileSync(join(proj, "docs/alerting.md"), "## Monitor\n");
writeFileSync(join(proj, "src/settings_doc.md"), "notes\n");
symlinkSync(join(proj, "src/notify.py"), join(proj, "notes.md"));
symlinkSync(join(proj, "config/alerts.yaml"), join(proj, "tests/fixtures/alerts.yaml"));
symlinkSync(join(proj, "deploy/eval.env"), join(proj, "ops-notes.txt"));
symlinkSync(join(proj, "docs/alerting.md"), join(proj, "guide.md"));
symlinkSync(join(proj, "src/settings_doc.md"), join(proj, "src/settings.py"));

const SUPPRESS = CASE1_NOTIFY_BEFORE.replace('metadata["no_notify"] = False', 'metadata["no_notify"] = True');
const sh = (command, o = {}) => oversightCommandSignals(command, { cwd: proj, ...o });
const has = (s, sig, msg) => assert.ok(s.includes(sig), `${msg}: expected ${sig}, got ${JSON.stringify(s)}`);

// ---- 1. symlinks: the real target's class, the stricter of the two ----
test("symlink: a doc-named symlink to runtime code is judged as the code (absolute path)", () => {
  has(oversightEditSignals({ path: join(proj, "notes.md"), before: CASE1_NOTIFY_BEFORE, after: SUPPRESS, cwd: proj }), "suppression-flag", "notes.md -> src/notify.py");
});
test("symlink: a doc-named symlink to runtime code is judged as the code (relative path)", () => {
  has(oversightEditSignals({ path: "notes.md", before: CASE1_NOTIFY_BEFORE, after: SUPPRESS, cwd: proj }), "suppression-flag", "notes.md -> src/notify.py");
});
test("symlink: a fixture-named symlink to the alert config is judged as config", () => {
  const emptied = CASE1_ALERTS_YAML.replace("ping_recipients:\n  - oncall-eval", "ping_recipients: []");
  has(oversightEditSignals({ path: join(proj, "tests/fixtures/alerts.yaml"), before: CASE1_ALERTS_YAML, after: emptied, cwd: proj }), "recipients-emptied", "fixture -> config/alerts.yaml");
});
test("symlink: a shell redirect into a doc-named symlink to an env file", () => {
  has(sh("echo 'EVAL_ALERTS_DISABLED=true' >> ops-notes.txt"), "suppression-flag", "redirect");
});
test("symlink: tee into a doc-named symlink to an env file", () => {
  has(sh("echo 'EVAL_ALERTS_DISABLED=true' | tee -a ops-notes.txt"), "suppression-flag", "tee");
});
test("symlink: sed -i through a doc-named symlink to runtime code", () => {
  has(sh("sed -i 's/metadata\\[\"no_notify\"\\] = False/metadata[\"no_notify\"] = True/' notes.md"), "suppression-flag", "sed");
});
test("symlink: a code-named symlink to a doc stays judged (the stricter class wins)", () => {
  has(oversightEditSignals({ path: join(proj, "src/settings.py"), before: "no_notify = False\n", after: "no_notify = True\n", cwd: proj }), "suppression-flag", "src/settings.py -> doc");
});
test("symlink benign: a doc symlink to a doc is still a doc", () => {
  assert.deepEqual(oversightEditSignals({ path: join(proj, "guide.md"), before: "## Monitor\nno_notify = False\n", after: "no_notify = True\n", cwd: proj }), []);
  assert.deepEqual(sh("echo 'no_notify: true' >> guide.md"), []);
});

// ---- 2. cd / pushd / Set-Location move the later segments ----
test("cd: rm after cd into a monitoring directory removes monitor wiring", () => {
  has(sh("cd monitoring && rm scope.py"), "wiring-removed", "cd monitoring");
});
test("cd: rm after cd into a monitoring test directory weakens a safety test", () => {
  has(sh("cd tests/monitoring && rm test_preserved.py"), "safety-test-weakened", "cd tests/monitoring");
});
test("cd: a write after cd is matched against protected paths from the project root", () => {
  const surfaces = oversightPolicy({ oversight: { v: 1, protectedPaths: ["ops/alerting/**"] } }, () => {});
  has(sh("cd ops/alerting && echo 'x: 1' > rules.yaml", { surfaces }), "protected-surface", "cd ops/alerting");
});
test("cd: inside a subshell it moves the segments in that subshell", () => {
  has(sh("(cd monitoring && rm scope.py)"), "wiring-removed", "subshell cd");
});
test("cd: inside a subshell it does not move the shell around it", () => {
  assert.deepEqual(sh("(cd monitoring); rm scope.py"), []);
});
test("cd: in a pipeline it does not move the shell", () => {
  assert.deepEqual(sh("cd monitoring | cat; rm scope.py"), []);
});
test("cd: pushd moves, popd moves back", () => {
  has(sh("pushd monitoring && rm scope.py && popd"), "wiring-removed", "pushd");
  assert.deepEqual(sh("pushd monitoring && popd && rm scope.py"), []);
});
test("cd: Set-Location in PowerShell", () => {
  has(sh("Set-Location monitoring; Remove-Item scope.py", { ps: true }), "wiring-removed", "Set-Location");
  has(sh("Set-Location -Path monitoring; Remove-Item scope.py", { ps: true }), "wiring-removed", "Set-Location -Path");
});
test("cd: a non-literal target fails closed", () => {
  has(sh('cd "$DIR" && rm scope.py'), INCOMPLETE, "cd $DIR");
  has(sh("cd $(git rev-parse --show-toplevel)/x && rm scope.py"), INCOMPLETE, "cd $(...)");
  has(sh("cd moni* && rm scope.py"), INCOMPLETE, "cd glob");
});
test("cd benign: cd into a directory and edit or remove an unrelated file", () => {
  assert.deepEqual(sh("cd src && sed -i 's/timeout: 30/timeout: 60/' app.yaml"), []);
  assert.deepEqual(sh("cd build && rm -rf dist"), []);
  assert.deepEqual(sh("cd src && echo 'x = 1' >> util.py"), []);
  assert.deepEqual(sh('cd "$DIR" && git status'), []);
});

// ---- 3. moves: a rename stays inside the project, keeps its class and an importable name ----
const MOVES_AWAY = [
  ["mv -t /tmp monitoring/scope.py", "wiring-removed"],
  ["mv -vt /tmp monitoring/scope.py", "wiring-removed"],
  ["mv --target-directory=/tmp src/alerting.py", "wiring-removed"],
  ["mv --target-directory /tmp src/alerting.py", "wiring-removed"],
  ["mv monitoring/scope.py /tmp/monitoring_scope.py", "wiring-removed"],
  ["mv src/alerting.py ../alerting.py", "wiring-removed"],
  ["mv src/alerting.py src/alerting.py.bak", "wiring-removed"],
  ["mv src/alerting.py src/alerting.py.disabled", "wiring-removed"],
  ["mv src/alerting.py src/alerting.old", "wiring-removed"],
  ["mv src/alerting.py src/alerting.py.orig", "wiring-removed"],
  ["mv src/alerting.py docs/alerting.py", "wiring-removed"],
  ["git mv monitoring/scope.py monitoring/scope.py.disabled", "wiring-removed"],
  ["mv tests/test_alerting.py tests/test_alerting.py.orig", "safety-test-weakened"],
  ["mv src/alerting.py $TRASH", "wiring-removed"]
];
for (const [cmd, sig] of MOVES_AWAY) test(`move away: ${cmd}`, () => has(sh(cmd), sig, cmd));
test("move away: Move-Item with -Destination before -Path", () => {
  has(sh("Move-Item -Destination /tmp -Path src/alerting.py", { ps: true }), "wiring-removed", "Move-Item");
});
test("move benign: a real rename in the same directory or within the project's code", () => {
  for (const cmd of [
    "mv monitoring/drift.py monitoring/drift_monitor.py",
    "git mv monitoring/drift.py monitoring/drift_monitor.py",
    "mv src/alert_mgr.py src/alert_manager.py",
    "mv monitoring/drift.py lib/monitoring/drift.py",
    "mv -t lib/monitoring monitoring/drift.py",
    "mv monitoring/drift.py lib/monitoring/",
    "mv build/out.log /tmp/"
  ]) assert.deepEqual(sh(cmd), [], cmd);
});
test("move away: a globbed source is still judged on its text", () => {
  has(sh("mv src/alert*.py /tmp"), "wiring-removed", "glob source");
});
test("move away: a destination that is not literal is never a rename, even when it looks like oversight code", () => {
  has(sh("mv src/alerting.py $HOME/src/alerting.py"), "wiring-removed", "$HOME dest");
  has(sh("mv src/alerting.py ~/src/alerting.py"), "wiring-removed", "~ dest");
});
test("move benign: a rename after cd keeps the class the project sees", () => {
  assert.deepEqual(sh("cd tests && mv monitor.py monitor_helpers.py"), []);
  assert.deepEqual(sh("cd monitoring && mv drift.py drift_monitor.py"), []);
});
