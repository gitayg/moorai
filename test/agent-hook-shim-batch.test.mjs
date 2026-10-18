// A host call that maps to several Claude calls (cli/agent-hooks/shim.mjs evaluateAll). The calls run as
// one hook process each, in sequence, inside the host's hook timeout, and a host treats a timed-out hook
// as non-blocking. So the batch is bounded: duplicates are judged once, more than BATCH_MAX distinct calls
// or a batch that outruns its deadline is held for confirmation (ask), never waved through.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateAll, batchOf, BATCH_MAX } from "../cli/agent-hooks/shim.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const write = (file_path, content = "x") => ({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path, content }, session_id: "s" });

test("batchOf: identical calls collapse to one", () => {
  const a = write("/w/a.txt"), b = write("/w/b.txt");
  assert.deepEqual(batchOf([a, b, { ...a }, null, { ...b }]), [a, b]);
});

test("evaluateAll: more distinct calls than BATCH_MAX are held for confirmation without spawning the hook", () => {
  const many = Array.from({ length: BATCH_MAX + 1 }, (_, i) => write(`/w/f${i}.txt`));
  const t0 = Date.now();
  const v = evaluateAll(many);
  assert.equal(v.decision, "ask");
  assert.match(v.reason, /too many/i);
  assert.ok(Date.now() - t0 < 2000, "the cap must refuse before running any check");
});

function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), "moorai-batch-"));
  try { return fn(home, { ...process.env, HOME: home, USERPROFILE: home }); } finally { rmTree(home); }
}
test("evaluateAll: a batch whose deadline has passed is held before running another check", () => withHome((home, env) => {
  const v = evaluateAll([write(join(home, "a.txt")), write(join(home, "b.txt"))], { env, deadlineMs: 0 });
  assert.deepEqual([v.decision, /time/i.test(v.reason)], ["ask", true]);
}));
test("evaluateAll: a check that times out inside a batch holds the call, never allows it", () => withHome((home, env) => {
  const v = evaluateAll([write(join(home, "a.txt")), write(join(home, "b.txt"))], { env, timeoutMs: 1 });
  assert.deepEqual([v.decision, /time/i.test(v.reason)], ["ask", true]);
}));
