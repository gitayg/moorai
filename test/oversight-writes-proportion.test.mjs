// Weakening oversight (#84): a write whose target is not literal (`cmd > "$out"`, `curl -o "$TMP/x"`,
// `cp src/* build/`) is proportionate to what is watched. With only the built-in memory-file protection on (no
// protectedPaths, memoryFiles not above notify) it raises memory-file, which is notify (an alert, no prompt)
// when #84 is not configured; with protectedPaths declared or memoryFiles ask / block it is
// analysis-incomplete under #84's action.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-writes-proportion.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightPolicy } from "../cli/oversight-surfaces.mjs";
import { decideOversight } from "../cli/hook-core.mjs";
import { startConsole, sandbox, runHook, settle } from "./lifecycle-harness.mjs";

const cwd = "/tmp/proj";
const CMDS = ["npm test > \"$out\"", "curl -o \"$TMP/x\" https://x.example.com/a", "cp src/* build/", "mv x $D", "> $F"];
const judge = (policy, cmd) => {
  const signals = oversightCommandSignals(cmd, { surfaces: oversightPolicy(policy, () => {}), cwd });
  return { signals, decision: decideOversight(policy, signals, "prompt").decision };
};

test("no policy: a non-literal write target is memory-file at notify (an alert, no prompt)", () => {
  for (const c of CMDS) {
    const { signals, decision } = judge({}, c);
    assert.deepEqual(signals, ["memory-file"], c);
    assert.equal(decision, "allow", c);
    assert.equal(decideOversight({}, signals, "prompt").findings.length, 1, `${c}: still alerts`);
  }
  assert.equal(judge({ oversight: { v: 1, memoryFiles: "notify" } }, CMDS[0]).decision, "allow", "memoryFiles notify: same");
});

test("protectedPaths declared: a non-literal write target stays analysis-incomplete (a prompt)", () => {
  const pol = { oversight: { v: 1, protectedPaths: ["ops/alerting/**"] } };
  for (const c of CMDS) assert.deepEqual(judge(pol, c), { signals: ["analysis-incomplete"], decision: "ask" }, c);
});

test("memoryFiles ask / block (or protectMemoryFiles: true): analysis-incomplete under #84's action", () => {
  for (const pol of [{ oversight: { v: 1, memoryFiles: "block" } }, { oversight: { v: 1, memoryFiles: "ask" } }, { oversight: { v: 1, protectMemoryFiles: true } }]) {
    for (const c of CMDS) assert.deepEqual(judge(pol, c), { signals: ["analysis-incomplete"], decision: "ask" }, `${JSON.stringify(pol)} ${c}`);
  }
  assert.equal(judge({ threatPolicy: { 84: "block" }, oversight: { v: 1, protectedPaths: ["ops/**"] } }, CMDS[0]).decision, "deny", "#84 block with a declared surface");
});

test("hook: with no policy `npm test > \"$out\"` is allowed and alerts once", async () => {
  const c = await startConsole({ captureTier: "content-free", threatPolicy: {} });
  const sb = sandbox({ port: c.port, tag: "ovprop" });
  const r = await runHook(sb, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "toolu_prop1", tool_input: { command: "npm test > \"$out\"" } });
  await settle();
  await c.close();
  const decision = r.json && r.json.hookSpecificOutput ? r.json.hookSpecificOutput.permissionDecision : "allow";
  assert.equal(decision, "allow");
  assert.equal(c.alerts.filter((a) => a.category === "Weakening oversight").length, 1);
});
