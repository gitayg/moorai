// What counts as a threat-model update that clears #85, through the real hook process. An update clears only
// when it is to a model that existed when the turn began (or a path the policy names) and changes its content
// with comments and whitespace removed; a model created in the turn clears only when the policy's threatclPath
// validates it ("pass"); with a threatclPath set, anything but "pass" leaves the alert. Each step that writes
// is applied to the file on disk after its PreToolUse, as the host would.
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-update.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { startConsole, sandbox, runHook, ledger, settle } from "./lifecycle-harness.mjs";
import { ABS_SKIP, scalingRatio } from "./timing.mjs";

const CAT = "Trust boundary changed without a threat-model update";
const BASE = { captureTier: "content-free", threatPolicy: {} };
const TM_HCL = `spec_version = "0.1.15"\n\nthreatmodel "Payments" {\n  author = "@sec"\n  description = "card flow"\n}\n`;
const PKG = (deps) => JSON.stringify({ name: "svc", version: "1.0.0", dependencies: deps }, null, 2) + "\n";
const MODEL = "security/payments.hcl";
let n = 0;
const uid = () => `toolu_upd_${++n}`;
function put(sb, rel, text) { const p = join(sb.proj, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; }
const repo = (sb) => { put(sb, ".git/HEAD", "ref: refs/heads/main\n"); put(sb, "package.json", PKG({ express: "^4.19.0" })); put(sb, MODEL, TM_HCL); };
const prompt = { hook_event_name: "UserPromptSubmit", prompt: "add the http client" };
const stop = { hook_event_name: "Stop", stop_hook_active: false, last_assistant_message: "Done.", background_tasks: [], session_crons: [] };
const addDep = (sb) => ({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_use_id: uid(), tool_input: { file_path: join(sb.proj, "package.json"), old_string: '"express": "^4.19.0"', new_string: '"express": "^4.19.0",\n    "axios": "^1.7.0"' } });
// An Edit of rel replacing a with b: PreToolUse, then the change on disk.
const editApplied = (rel, a, b) => ({
  ev: (sb) => ({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_use_id: uid(), tool_input: { file_path: join(sb.proj, rel), old_string: a, new_string: b } }),
  apply: (sb) => { const p = join(sb.proj, rel); writeFileSync(p, readFileSync(p, "utf8").replace(a, b)); }
});
// A Write of a new file rel: PreToolUse, then the file on disk.
const writeApplied = (rel, content) => ({
  ev: (sb) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_use_id: uid(), tool_input: { file_path: join(sb.proj, rel), content } }),
  apply: (sb) => put(sb, rel, content)
});

async function run(policy, steps) {
  const c = await startConsole(policy);
  const sb = sandbox({ port: c.port, tag: "tbu" });
  repo(sb);
  for (const s of steps) {
    if (s && s.ev) { await runHook(sb, s.ev(sb)); s.apply(sb); continue; }
    await runHook(sb, typeof s === "function" ? s(sb) : s);
  }
  await settle();
  await c.close();
  const alerts = c.alerts.filter((a) => a.category === CAT);
  return { alerts, stopRow: ledger(sb).filter((r) => r.ev === "stop").at(-1) };
}
const rootBin = (p) => { try { const st = statSync(p); return st.uid === 0 && !(st.mode & 0o022); } catch { return false; } };
const noStandIn = process.platform === "win32" || !rootBin("/usr/bin/true") || !rootBin("/usr/bin/false");
const SUBSTANTIVE = editApplied(MODEL, 'description = "card flow"', 'description = "card flow; calls the axios-based FX client"');

test("a newly created empty model in the repository does not clear the alert (threatModel: created)", async () => {
  const { alerts, stopRow } = await run(BASE, [prompt, addDep, writeApplied("security/fx.hcl", 'threatmodel "FX" {\n}\n'), stop]);
  assert.equal(alerts.length, 1, "a dummy model cleared the check");
  assert.equal(alerts[0].trustBoundary.threatModel, "created");
  assert.equal(stopRow.tmr, "created");
});

test("a whitespace-only edit to an existing model does not clear the alert", async () => {
  const { alerts, stopRow } = await run(BASE, [prompt, addDep, editApplied(MODEL, '  author = "@sec"\n', '  author   =   "@sec"\n\n\n'), stop]);
  assert.equal(alerts.length, 1, "a whitespace edit cleared the check");
  assert.equal(alerts[0].trustBoundary.threatModel, "present");
  assert.equal(stopRow.tmr, "not-substantive");
});

test("a comment-only edit to an existing model does not clear the alert (#, // and /* */)", async () => {
  const { alerts } = await run(BASE, [prompt, addDep, editApplied(MODEL, '  author = "@sec"\n', '  # reviewed for the FX client\n  author = "@sec" // ok\n  /* axios */\n'), stop]);
  assert.equal(alerts.length, 1, "a comment edit cleared the check");
});

test("a substantive edit to an existing model clears the alert", async () => {
  const { alerts, stopRow } = await run(BASE, [prompt, addDep, SUBSTANTIVE, stop]);
  assert.equal(alerts.length, 0);
  assert.equal(stopRow.tbFlag, false);
});

test("with threatclPath set, a substantive edit clears only when validation passes (/usr/bin/false: no, /usr/bin/true: yes)", { skip: noStandIn }, async () => {
  const bad = await run({ ...BASE, threatModel: { v: 1, threatclPath: "/usr/bin/false" } }, [prompt, addDep, SUBSTANTIVE, stop]);
  assert.equal(bad.alerts.length, 1, "a failed validation cleared the check");
  assert.equal(bad.stopRow.tmv, "fail");
  assert.equal(bad.stopRow.tmr, "validation");
  const ok = await run({ ...BASE, threatModel: { v: 1, threatclPath: "/usr/bin/true" } }, [prompt, addDep, SUBSTANTIVE, stop]);
  assert.equal(ok.alerts.length, 0);
  assert.equal(ok.stopRow.tmv, "pass");
});

test("a new model clears only with a threatclPath that passes it: /usr/bin/true clears, no threatclPath does not", { skip: noStandIn }, async () => {
  const fx = writeApplied("security/fx.hcl", TM_HCL.replace("Payments", "FX"));
  const withTcl = await run({ ...BASE, threatModel: { v: 1, threatclPath: "/usr/bin/true" } }, [prompt, addDep, fx, stop]);
  assert.equal(withTcl.alerts.length, 0, "a new model validated by threatcl did not clear");
  const without = await run(BASE, [prompt, addDep, writeApplied("security/fx.hcl", TM_HCL.replace("Payments", "FX")), stop]);
  assert.equal(without.alerts.length, 1, "a new model without validation cleared the check");
  assert.equal(without.alerts[0].trustBoundary.threatModel, "created");
});

// ---- unit: the normaliser, and the fallback when a turn has no UserPromptSubmit snapshot ----
import { normalizeModel } from "../cli/boundary-update.mjs";
import { boundaryAtStop, boundaryWriteFields } from "../cli/boundary-stop.mjs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

test("normalizeModel: whitespace and comments (#, //, /* */, <!-- --> in Markdown) do not count; a value change does", () => {
  const base = normalizeModel(TM_HCL, "a.hcl");
  assert.equal(normalizeModel(TM_HCL.replace('  author = "@sec"\n', '\n\n  author   =\t"@sec"   # x\n  // y\n  /* z\n */\n'), "a.hcl"), base);
  assert.notEqual(normalizeModel(TM_HCL.replace("card flow", "card flow; FX"), "a.hcl"), base);
  assert.notEqual(normalizeModel(TM_HCL.replace('"card flow"', '"card # flow"'), "a.hcl"), base, "a # inside a string is content");
  assert.equal(normalizeModel("# Model\n\n- card flow\n<!-- reviewed -->\n", "tm.md"), normalizeModel("# Model\n- card flow\n", "tm.md"));
});

const HOSTILE = [["/*", 500000], ['"', 1000000], [" \n\t", 350000], ["<!--", 250000], ["#//", 340000]];

// A scaling ratio, not a wall-clock budget (test/timing.mjs): 200 ms read 234-302 ms on a shared CI runner.
// MEASURED (scalingRatio, M-series Mac): 5-19x for 8x the input, "#//" peaking at 20.4x once; a quadratic
// pass reads 64x, so the bound sits halfway between.
test("normalizeModel is linear: 8x the comment openers, quotes and whitespace cost < 32x", () => {
  for (const [u, n] of HOSTILE) {
    const small = u.repeat(n / 8), large = u.repeat(n);
    const r = scalingRatio(() => { normalizeModel(small, "x.md"); normalizeModel(small, "x.hcl"); }, () => { normalizeModel(large, "x.md"); normalizeModel(large, "x.hcl"); });
    assert.ok(r.ratio < 32, `${JSON.stringify(u)}: 8x the input cost ${r.ratio.toFixed(2)}x (${r.small.toFixed(3)}ms → ${r.large.toFixed(3)}ms)`);
  }
});

// The original absolute budget, kept OPT-IN (see test/timing.mjs): set MOORAI_PERF_ABS=1 on an idle machine.
test("normalizeModel: 1 MiB of comment openers, quotes and whitespace in well under 200 ms (opt-in: MOORAI_PERF_ABS=1)", { skip: ABS_SKIP }, () => {
  for (const [u, n] of HOSTILE) {
    const s = u.repeat(n);
    const t0 = performance.now();
    normalizeModel(s, "x.md");
    normalizeModel(s, "x.hcl");
    const ms = performance.now() - t0;
    assert.ok(ms < 200, `${ms.toFixed(1)} ms`);
  }
});

test("without a turn snapshot (no UserPromptSubmit), the write's own before-state decides: an existing model edited substantively clears, a new one does not", () => {
  const proj = mkdtempSync(join(tmpdir(), "moorai-tbu-fb-"));
  mkdirSync(join(proj, ".git"), { recursive: true });
  writeFileSync(join(proj, "package.json"), PKG({ express: "^4.19.0" }));
  const model = join(proj, "security", "payments.hcl");
  mkdirSync(dirname(model), { recursive: true });
  writeFileSync(model, TM_HCL);
  const dep = boundaryWriteFields("Edit", { file_path: join(proj, "package.json"), old_string: '"express": "^4.19.0"', new_string: '"express": "^4.19.0",\n    "axios": "^1.7.0"' }, join(proj, "package.json"), proj, BASE);
  assert.deepEqual(dep.tb, ["new-dependency"]);
  const ed = boundaryWriteFields("Edit", { file_path: model, old_string: "card flow", new_string: "card flow; FX" }, model, proj, BASE);
  writeFileSync(model, TM_HCL.replace("card flow", "card flow; FX"));
  const rows = [{ ev: "pre", tool: "Edit", decision: "allow", u: "a", ...dep }, { ev: "pre", tool: "Edit", decision: "allow", u: "b", ...ed }];
  assert.equal(boundaryAtStop({ rows, scope: rows, cwd: proj, policy: BASE }).flagged, false, "a substantive edit of an existing model did not clear");
  const fx = join(proj, "security", "fx.hcl");
  const nw = boundaryWriteFields("Write", { file_path: fx, content: 'threatmodel "FX" {\n}\n' }, fx, proj, BASE);
  writeFileSync(fx, 'threatmodel "FX" {\n}\n');
  const rows2 = [{ ev: "pre", tool: "Edit", decision: "allow", u: "a", ...dep }, { ev: "pre", tool: "Write", decision: "allow", u: "c", ...nw }];
  const r = boundaryAtStop({ rows: rows2, scope: rows2, cwd: proj, policy: BASE });
  assert.equal(r.flagged, true, "a new model cleared the check");
  assert.equal(r.threatModel, "created");
});
