// Trust boundary changed without a threat-model update (#85) through the real hook process: a manifest
// edit that adds a dependency in a repo holding a threatcl file, then Stop without touching the model.
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync, readFileSync, chmodSync, mkdtempSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { startConsole, sandbox, runHook, ledger, rawLedger, settle } from "./lifecycle-harness.mjs";

const CAT = "Trust boundary changed without a threat-model update";
const BASE = { captureTier: "content-free", threatPolicy: {} };
const TM_HCL = `spec_version = "0.1.15"\n\nthreatmodel "Payments" {\n  author = "@sec"\n  description = "card flow"\n}\n`;
const PKG = (deps) => JSON.stringify({ name: "svc", version: "1.0.0", dependencies: deps }, null, 2) + "\n";

function put(sb, rel, text) { const p = join(sb.proj, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; }
const uid = () => `toolu_${Math.random().toString(36).slice(2)}`;
const edit = (sb, rel, input, extra = {}) => ({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_use_id: uid(), tool_input: { file_path: join(sb.proj, rel), ...input }, ...extra });
const bash = (command, extra = {}) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: uid(), tool_input: { command }, ...extra });
const prompt = () => ({ hook_event_name: "UserPromptSubmit", prompt: "add the http client" });
const stop = (msg = "Done.", extra = {}) => ({ hook_event_name: "Stop", stop_hook_active: false, last_assistant_message: msg, background_tasks: [], session_crons: [], ...extra });
const SUB = { agent_id: "agent-9a1", agent_type: "general-purpose" };
const repo = (sb) => { put(sb, ".git/HEAD", "ref: refs/heads/main\n"); put(sb, "package.json", PKG({ express: "^4.19.0" })); put(sb, "security/payments.hcl", TM_HCL); };
const repoNoModel = (sb) => { put(sb, ".git/HEAD", "ref: refs/heads/main\n"); put(sb, "package.json", PKG({ express: "^4.19.0" })); };
const addDep = (sb, extra) => edit(sb, "package.json", { old_string: '"express": "^4.19.0"', new_string: '"express": "^4.19.0",\n    "axios": "^1.7.0"' }, extra);
// A step the host then performs on disk: { ev, apply }. An update clears #85 only when the file really changed.
const applied = (ev, rel, a, b) => ({ ev, apply: (sb) => { const p = join(sb.proj, rel); writeFileSync(p, readFileSync(p, "utf8").replace(a, b)); } });
const touchModel = applied((sb) => edit(sb, "security/payments.hcl", { old_string: 'description = "card flow"', new_string: 'description = "card flow; calls the axios-based FX client"' }), "security/payments.hcl", 'description = "card flow"', 'description = "card flow; calls the axios-based FX client"');
const sedModel = (cmd, extra) => applied(bash(cmd, extra), "security/payments.hcl", "card flow", "card flow and FX");
async function step(sb, s, opts) {
  if (s && s.ev) { const o = await runHook(sb, typeof s.ev === "function" ? s.ev(sb) : s.ev, opts); s.apply(sb); return o; }
  return runHook(sb, typeof s === "function" ? s(sb) : s, opts);
}

async function run(policy, setup, steps, { env = {} } = {}) {
  const c = await startConsole(policy);
  const sb = sandbox({ port: c.port, tag: "tb" });
  setup(sb);
  const outs = [];
  for (const s of steps) outs.push(await step(sb, s, { env }));
  await settle();
  await c.close();
  return { sb, outs, alerts: c.alerts };
}
const tbAlerts = (alerts) => alerts.filter((a) => a.category === CAT);

test("e2e: a dependency added in a repo with a threatcl model, then Stop without touching it, raises one content-free #85 alert", async () => {
  const { outs, alerts, sb } = await run(BASE, repo, [prompt(), addDep, stop()]);
  const pre = outs[1].json && outs[1].json.hookSpecificOutput ? outs[1].json.hookSpecificOutput.permissionDecision : "allow";
  assert.equal(pre, "allow", "the edit itself is not held");
  assert.equal(outs.at(-1).out, "", "notify mode prints nothing at Stop");
  const a = tbAlerts(alerts);
  assert.equal(a.length, 1, JSON.stringify(alerts.map((x) => x.category)));
  assert.deepEqual([a[0].threatId, a[0].reasonCode, a[0].stage, a[0].tool], [85, "BOUNDARY_UNMODELLED", "lifecycle", "hook:Stop"]);
  assert.deepEqual(a[0].trustBoundary, { kinds: ["new-dependency"], count: 1, threatModel: "present", scope: "turn", delegated: false, blocked: false });
  console.log("e2e #85 alert:", JSON.stringify({ threatId: a[0].threatId, category: a[0].category, riskLevel: a[0].riskLevel, reasonCode: a[0].reasonCode, trustBoundary: a[0].trustBoundary }));
  const blob = JSON.stringify(alerts) + rawLedger(sb);
  for (const s of ["axios", "package.json", "payments.hcl", "security/"]) assert.ok(!blob.includes(s), `content leaked: ${s}`);
  assert.deepEqual(ledger(sb).find((r) => r.ev === "pre" && r.tb).tb, ["new-dependency"], "the signal stays on the local ledger row");
});

test("e2e: touching the threat model in the same turn clears it", async () => {
  const { alerts, sb } = await run(BASE, repo, [prompt(), addDep, touchModel, stop()]);
  assert.equal(tbAlerts(alerts).length, 0);
  assert.equal(ledger(sb).find((r) => r.ev === "stop").tbFlag, false, "the check ran");
});

test("e2e: a shell edit of the model clears it too; an install command is a boundary change", async () => {
  const { alerts } = await run(BASE, repo, [prompt(), bash("npm install axios"), sedModel("sed -i 's/card flow/card flow and FX/' security/payments.hcl"), stop()]);
  assert.equal(tbAlerts(alerts).length, 0);
  const only = await run(BASE, repo, [prompt(), bash("npm install axios"), stop()]);
  assert.deepEqual(tbAlerts(only.alerts).map((a) => a.trustBoundary.kinds), [["new-dependency"]]);
});

test("e2e: require block-stop answers decision block once; stop_hook_active ends it without a second alert", async () => {
  const pol = { ...BASE, threatModel: { v: 1, require: "block-stop" } };
  const { outs, alerts } = await run(pol, repo, [prompt(), addDep, stop(), stop("Done.", { stop_hook_active: true })]);
  const first = outs.at(-2).json;
  assert.equal(first && first.decision, "block", outs.at(-2).out);
  assert.ok(/threat model/i.test(first.reason) && /why/i.test(first.reason), first.reason);
  assert.ok(!/axios|package\.json|payments/.test(first.reason), "the reason is content-free");
  console.log("e2e block output:", outs.at(-2).out);
  assert.equal(outs.at(-1).out, "", "never blocks twice");
  const a = tbAlerts(alerts);
  assert.equal(a.length, 1);
  assert.equal(a[0].trustBoundary.blocked, true);
});

test("e2e: block-stop then the agent updates the model: the second Stop is quiet", async () => {
  const pol = { ...BASE, threatModel: { v: 1, require: "block-stop" } };
  const { outs, alerts } = await run(pol, repo, [prompt(), addDep, stop(), touchModel, stop("Updated the threat model.", { stop_hook_active: true })]);
  assert.equal(outs[2].json.decision, "block");
  assert.equal(outs.at(-1).out, "");
  assert.equal(tbAlerts(alerts).length, 1);
});

test("e2e: stop_hook_active on the first Stop alerts but never blocks", async () => {
  const pol = { ...BASE, threatModel: { v: 1, require: "block-stop" } };
  const { outs, alerts } = await run(pol, repo, [prompt(), addDep, stop("Done.", { stop_hook_active: true })]);
  assert.equal(outs.at(-1).out, "");
  assert.equal(tbAlerts(alerts)[0].trustBoundary.blocked, false);
});

test("e2e: other hosts alert only under block-stop", async () => {
  const pol = { ...BASE, threatModel: { v: 1, require: "block-stop" } };
  const { outs, alerts } = await run(pol, repo, [prompt(), addDep, stop()], { env: { MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: "codex" } });
  assert.equal(outs.at(-1).out, "");
  assert.equal(tbAlerts(alerts).length, 1);
});

test("e2e: without a threat model no alert by default; reportWithoutModel reports it as absent", async () => {
  const off = await run(BASE, repoNoModel, [prompt(), addDep, stop()]);
  assert.equal(tbAlerts(off.alerts).length, 0);
  const on = await run({ ...BASE, threatModel: { v: 1, reportWithoutModel: true } }, repoNoModel, [prompt(), addDep, stop()]);
  const a = tbAlerts(on.alerts);
  assert.equal(a.length, 1);
  assert.equal(a[0].trustBoundary.threatModel, "absent");
});

test("e2e: a policy-declared threat-model path makes the repo modelled, and writing it clears the check", async () => {
  const pol = { ...BASE, threatModel: { v: 1, paths: ["docs/threat-model.md"] } };
  const setup = (sb) => { repoNoModel(sb); put(sb, "docs/threat-model.md", "# Threat model\n\n- card flow\n"); };
  const flagged = await run(pol, setup, [prompt(), addDep, stop()]);
  assert.equal(tbAlerts(flagged.alerts).length, 1);
  const cleared = await run(pol, setup, [prompt(), addDep, applied((sb) => edit(sb, "docs/threat-model.md", { old_string: "- card flow", new_string: "- card flow\n- FX client" }), "docs/threat-model.md", "- card flow", "- card flow\n- FX client"), stop()]);
  assert.equal(tbAlerts(cleared.alerts).length, 0);
});

test("e2e: a sub-agent's boundary change is judged at the parent's Stop (delegated) and at SubagentStop", async () => {
  const { alerts } = await run(BASE, repo, [prompt(), (sb) => addDep(sb, SUB), { hook_event_name: "SubagentStop", stop_hook_active: false, ...SUB, agent_transcript_path: "/tmp/a.jsonl", last_assistant_message: "Added axios." }, stop()]);
  const a = tbAlerts(alerts);
  assert.equal(a.length, 2, JSON.stringify(a.map((x) => x.trustBoundary)));
  assert.deepEqual(a.map((x) => [x.tool, x.trustBoundary.scope, x.trustBoundary.delegated]), [["hook:SubagentStop", "subagent", true], ["hook:Stop", "turn", true]]);
  assert.ok(a[0].parentSession, "a sub-agent's alert names the delegating session");
});

test("e2e: threatPolicy[85] disabled raises nothing", async () => {
  const { alerts } = await run({ ...BASE, threatPolicy: { 85: "disabled" } }, repo, [prompt(), addDep, stop()]);
  assert.equal(tbAlerts(alerts).length, 0);
});

test("e2e: a boundary change from an earlier turn is out of scope", async () => {
  const { alerts } = await run(BASE, repo, [prompt(), addDep, stop(), prompt(), stop()]);
  assert.equal(tbAlerts(alerts).length, 1);
});

// Root-owned stand-ins for a root-installed threatcl: /usr/bin/true exits 0, /usr/bin/false exits 1.
const rootBin = (p) => { try { const st = statSync(p); return st.uid === 0 && !(st.mode & 0o022); } catch { return false; } };
const noStandIn = process.platform === "win32" || !rootBin("/usr/bin/true") || !rootBin("/usr/bin/false");
test("e2e: the signed policy's root-owned threatModel.threatclPath validates the touched model at Stop; pass and fail recorded on the Stop row; fail alerts content-free", { skip: noStandIn }, async () => {
  const one = async (bin, steps) => {
    const c = await startConsole({ ...BASE, threatModel: { v: 1, threatclPath: bin } });
    const sb = sandbox({ port: c.port, tag: "tbv" });
    repo(sb);
    for (const s of steps) await step(sb, s);
    await settle();
    await c.close();
    return { sb, alerts: c.alerts };
  };
  const ok = await one("/usr/bin/true", [prompt(), addDep, touchModel, stop()]);
  const bad = await one("/usr/bin/false", [prompt(), touchModel, stop()]);
  assert.deepEqual([...ledger(ok.sb), ...ledger(bad.sb)].filter((r) => r.ev === "stop").map((r) => r.tmv), ["pass", "fail"]);
  assert.equal(ok.alerts.filter((a) => a.reasonCode === "BOUNDARY_MODEL_INVALID").length, 0);
  const v = bad.alerts.filter((a) => a.reasonCode === "BOUNDARY_MODEL_INVALID");
  assert.equal(v.length, 1);
  assert.deepEqual(v[0].threatModelValidation, { result: "fail", files: 1 });
  assert.ok(!JSON.stringify(bad.alerts).includes("payments.hcl"));
  assert.equal(tbAlerts(ok.alerts).length + tbAlerts(bad.alerts).length, 0);
});

test("e2e: a user-owned threatclPath is untrusted and not run; a threatcl on PATH is never run", { skip: process.platform === "win32" }, async () => {
  const fakeAt = (exit) => {
    const dir = join(mkdtempSync(join(tmpdir(), "moorai-tbp-")), "bin");
    mkdirSync(dir); chmodSync(dir, 0o755);
    const marker = join(dirname(dir), "ran");
    const p = join(dir, "threatcl");
    writeFileSync(p, `#!/bin/sh\necho ran >> "${marker}"\nexit ${exit}\n`); chmodSync(p, 0o755);
    return { dir, bin: p, ran: () => existsSync(marker) };
  };
  const chosen = fakeAt(1), onPath = fakeAt(0);
  const { sb } = await run({ ...BASE, threatModel: { v: 1, threatclPath: chosen.bin } }, repo, [prompt(), touchModel, stop()], { env: { PATH: `${onPath.dir}:${process.env.PATH}` } });
  assert.equal(chosen.ran(), false, "a user-owned threatclPath ran");
  assert.equal(onPath.ran(), false, "PATH was searched");
  assert.equal(ledger(sb).find((r) => r.ev === "stop").tmv, "untrusted");
  const none = await run(BASE, repo, [prompt(), touchModel, stop()], { env: { PATH: `${onPath.dir}:${process.env.PATH}` } });
  assert.equal(onPath.ran(), false, "a threatcl on PATH ran without threatclPath");
  assert.equal(none.outs.at(-1).code, 0);
  assert.equal(ledger(none.sb).find((r) => r.ev === "stop").tmv, "unset");
});

// ---- suppression: only a real threat-model write in this repository clears the check ----
import { symlinkSync } from "node:fs";
const write = (sb, abs, content, extra = {}) => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_use_id: uid(), tool_input: { file_path: abs, content }, ...extra });

test("suppression: a decoy threatcl file written outside the repository does not clear the check", async () => {
  const { alerts } = await run(BASE, repo, [prompt(), addDep, (sb) => write(sb, join(sb.home, "decoy", "tm.hcl"), TM_HCL), stop()]);
  assert.equal(tbAlerts(alerts).length, 1);
});

test("suppression: editing the threat model of a different repository does not clear the check", async () => {
  const setup = (sb) => { repo(sb); mkdirSync(join(sb.home, "other", ".git"), { recursive: true }); mkdirSync(join(sb.home, "other", "security"), { recursive: true }); writeFileSync(join(sb.home, "other", "security", "tm.hcl"), TM_HCL); };
  const { alerts } = await run(BASE, setup, [prompt(), addDep, (sb) => ({ hook_event_name: "PreToolUse", tool_name: "Edit", tool_use_id: uid(), tool_input: { file_path: join(sb.home, "other", "security", "tm.hcl"), old_string: 'description = "card flow"', new_string: 'description = "x"' } }), stop()]);
  assert.equal(tbAlerts(alerts).length, 1);
});

test("suppression: a symlink in the repository named like a model and pointing outside does not clear the check", { skip: process.platform === "win32" }, async () => {
  const setup = (sb) => { repo(sb); mkdirSync(join(sb.home, "outside"), { recursive: true }); writeFileSync(join(sb.home, "outside", "tm.hcl"), TM_HCL); symlinkSync(join(sb.home, "outside", "tm.hcl"), join(sb.proj, "security", "link.hcl")); };
  const { alerts } = await run(BASE, setup, [prompt(), addDep, (sb) => edit(sb, "security/link.hcl", { old_string: 'description = "card flow"', new_string: 'description = "y"' }), stop()]);
  assert.equal(tbAlerts(alerts).length, 1);
});

test("suppression: a model write that was asked on and never reported as run does not clear the check; one that ran does", async () => {
  const pol = { ...BASE, oversight: { v: 1, protectedPaths: ["security/**"] } };
  const sedCmd = "sed -i 's/card flow/card flow and FX/' security/payments.hcl";
  const asked = await run(pol, repo, [prompt(), addDep, sedModel(sedCmd, { tool_use_id: "toolu_tm1" }), stop()]);
  const pre = asked.outs[2].json.hookSpecificOutput.permissionDecision;
  assert.equal(pre, "ask", "the protected-path edit is held (#84)");
  assert.equal(tbAlerts(asked.alerts).length, 1, "an ask with no outcome did not run");
  const editAsked = await run(pol, repo, [prompt(), addDep, touchModel, stop()]);
  assert.equal(tbAlerts(editAsked.alerts).length, 1, "an Edit ask whose outcome the host never reports does not count as a model update");
  const ran = await run(pol, repo, [prompt(), addDep, sedModel(sedCmd, { tool_use_id: "toolu_tm2" }), { hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "toolu_tm2", tool_input: { command: sedCmd }, tool_response: { stdout: "", stderr: "", interrupted: false } }, stop()]);
  assert.equal(tbAlerts(ran.alerts).length, 0, "the ask ran (PostToolUse), so the model was updated");
});

test("suppression: a new threatcl file created under the repository root does not clear the check without validation (threatModel: created)", async () => {
  const fx = TM_HCL.replace("Payments", "FX");
  // The host performs the allowed Write after PreToolUse; the harness does that by hand before Stop.
  const { alerts } = await run(BASE, repo, [prompt(), addDep, (sb) => write(sb, join(sb.proj, "security", "fx.hcl"), fx), (sb) => { writeFileSync(join(sb.proj, "security", "fx.hcl"), fx); return stop(); }]);
  assert.equal(tbAlerts(alerts).length, 1);
  assert.equal(tbAlerts(alerts)[0].trustBoundary.threatModel, "created");
});
