// The origin field (cli/origin.mjs): one row per basis of the contract's table, per host, and the rules that
// keep a claim from being stronger than the table allows.
//
//   node --test --import ./test/hermetic-env.mjs test/origin.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { ORIGIN_BASES, ORIGIN_KINDS, ORIGIN_STATUSES, originFor, askOutcomeOrigin, guardOrigin, sanitizeOrigin } from "../cli/origin.mjs";

// The console's server/origin.js pins this exact literal too: change both or neither.
const PINNED = '{"bypass-mode":{"kind":"agent","status":"observed"},"headless":{"kind":"agent","status":"observed"},"no-moorai-ask":{"kind":"agent","status":"inferred"},"host-no-thread-id":{"kind":"agent","status":"inferred"},"subagent-id":{"kind":"delegated","status":"observed"},"policy-exception":{"kind":"override","status":"observed"},"local-exception":{"kind":"override","status":"inferred"},"break-glass":{"kind":"override","status":"observed"},"jit-elevation":{"kind":"override","status":"observed"},"guard-tty":{"kind":"override","status":"observed"},"guard-flag":{"kind":"override","status":"inferred"},"post-after-ask":{"kind":"approved-ask","status":"inferred"},"failure-after-ask":{"kind":"approved-ask","status":"inferred"},"no-execution-before-stop":{"kind":"unknown","status":"not-established"},"ask-pending":{"kind":"unknown","status":"not-established"},"ask-not-trackable":{"kind":"unknown","status":"not-established"},"unrecognised":{"kind":"unknown","status":"not-established"}}';

test("ORIGIN_BASES equals the pinned literal the console holds", () => {
  assert.equal(JSON.stringify(ORIGIN_BASES), PINNED);
  for (const [b, r] of Object.entries(ORIGIN_BASES)) {
    assert.ok(ORIGIN_KINDS.includes(r.kind), b);
    assert.ok(ORIGIN_STATUSES.includes(r.status), b);
  }
  assert.ok(Object.isFrozen(ORIGIN_BASES) && Object.isFrozen(ORIGIN_BASES["no-moorai-ask"]));
});

const CC = { host: "claude-code", shim: false };
const SHIMS = ["codex", "copilot", "cursor", "gemini", "droid"];
const pick = (o) => [o.kind, o.status, o.basis, o.thread, o.hostPrompt];

test("Claude Code: each basis row it can reach", () => {
  assert.deepEqual(pick(originFor({ ...CC, permissionMode: "default" })), ["agent", "inferred", "no-moorai-ask", "main", "unknown"]);
  assert.deepEqual(pick(originFor({ ...CC, permissionMode: "acceptEdits" })), ["agent", "inferred", "no-moorai-ask", "main", "unknown"]);
  assert.deepEqual(pick(originFor({ ...CC, permissionMode: "bypassPermissions" })), ["agent", "observed", "bypass-mode", "main", "not-shown"]);
  assert.deepEqual(pick(originFor({ ...CC, serverMode: true })), ["agent", "observed", "headless", "main", "not-shown"]);
  const sub = originFor({ ...CC, agentId: "agent-7", agentType: "Explore", parentBinding: "exact", subagentType: "Explore" });
  assert.deepEqual(pick(sub), ["delegated", "observed", "subagent-id", "subagent", "unknown"]);
  assert.equal(sub.parentBinding, "exact");
  assert.equal(sub.subagentType, "Explore");
  assert.equal(originFor({ ...CC, agentId: "a", parentBinding: "inferred" }).parentBinding, "inferred");
  assert.equal(originFor({ ...CC, agentId: "a" }).parentBinding, "none");
  assert.equal(originFor({ ...CC, agentId: "a", subagentType: "h2:abc123" }).subagentType, "h2:abc123");
  // parentBinding / subagentType never on a main-thread record.
  const main = originFor({ ...CC, parentBinding: "exact", subagentType: "Explore" });
  assert.equal(main.parentBinding, undefined);
  assert.equal(main.subagentType, undefined);
});

test("overrides win over every other kind; exception says which store", () => {
  const c = originFor({ ...CC, agentId: "a", permissionMode: "bypassPermissions", exception: "console" });
  assert.deepEqual([c.kind, c.status, c.basis, c.exception, c.thread], ["override", "observed", "policy-exception", "console", "subagent"]);
  const l = originFor({ ...CC, exception: "local" });
  assert.deepEqual([l.kind, l.status, l.basis, l.exception], ["override", "inferred", "local-exception", "local"]);
  assert.deepEqual(pick(originFor({ ...CC, breakGlass: true })).slice(0, 3), ["override", "observed", "break-glass"]);
  assert.deepEqual(pick(originFor({ ...CC, jitElevation: true })).slice(0, 3), ["override", "observed", "jit-elevation"]);
  assert.equal(originFor({ ...CC, breakGlass: true }).exception, undefined);
  assert.equal(originFor({ ...CC, exception: "elsewhere" }).kind, "agent");
});

test("shim hosts: thread not distinguishable, never delegated or approved-ask, bypass ignored", () => {
  for (const host of SHIMS) {
    for (const extra of [{}, { agentId: "a", agentType: "Explore" }, { permissionMode: "bypassPermissions" }]) {
      const o = originFor({ host, shim: true, ...extra });
      assert.deepEqual(pick(o), ["agent", "inferred", "host-no-thread-id", "not-distinguishable", "unknown"], `${host} ${JSON.stringify(extra)}`);
      assert.notEqual(o.kind, "delegated");
      assert.notEqual(o.kind, "approved-ask");
      assert.equal(o.parentBinding, undefined);
    }
    assert.equal(originFor({ host, shim: true, serverMode: true }).basis, "headless");
    assert.equal(originFor({ host, shim: true, exception: "console" }).basis, "policy-exception");
    assert.equal(originFor({ host, shim: true, exception: "console" }).thread, "not-distinguishable");
  }
});

test("intent mismatch is carried only when it fired; its absence never says aligned", () => {
  assert.equal(originFor({ ...CC, intentMismatch: true }).intent, "mismatch");
  assert.equal("intent" in originFor({ ...CC }), false);
});

test("ask outcomes: post / failure after an ask are inferred approvals, a Stop is not established", () => {
  const r = { seqFrom: 18204, seqTo: 18205 };
  const a = askOutcomeOrigin({ event: "PostToolUse", thread: "main", resolves: r });
  assert.deepEqual([a.kind, a.status, a.basis, a.hostPrompt], ["approved-ask", "inferred", "post-after-ask", "unknown"]);
  assert.deepEqual(a.resolves, r);
  assert.equal(askOutcomeOrigin({ event: "PostToolUseFailure" }).basis, "failure-after-ask");
  assert.equal(askOutcomeOrigin({ event: "PostToolUseFailure" }).status, "inferred");
  for (const ev of ["Stop", "SubagentStop"]) {
    const s = askOutcomeOrigin({ event: ev });
    assert.deepEqual([s.kind, s.status, s.basis], ["unknown", "not-established", "no-execution-before-stop"]);
  }
  const u = askOutcomeOrigin({ event: "untracked", thread: "not-distinguishable" });
  assert.deepEqual([u.kind, u.status, u.basis, u.thread], ["unknown", "not-established", "ask-not-trackable", "not-distinguishable"]);
  // A malformed range is dropped, never guessed.
  assert.equal(askOutcomeOrigin({ event: "PostToolUse", resolves: { seqFrom: 5, seqTo: 3 } }).resolves, undefined);
  assert.equal(askOutcomeOrigin({ event: "PostToolUse", resolves: { seqFrom: null, seqTo: 3 } }).resolves, undefined);
});

test("guard: a TTY answer is observed, --decide is inferred", () => {
  const t = guardOrigin({ interactive: true });
  assert.deepEqual([t.kind, t.status, t.basis], ["override", "observed", "guard-tty"]);
  const f = guardOrigin({ interactive: false });
  assert.deepEqual([f.kind, f.status, f.basis], ["override", "inferred", "guard-flag"]);
});

test("sanitizeOrigin: kind and status come from the table, never from the claim; unknown shapes are dropped", () => {
  const claim = { v: 1, kind: "approved-ask", status: "observed", basis: "post-after-ask", thread: "main", hostPrompt: "unknown" };
  const s = sanitizeOrigin(claim);
  assert.equal(s.status, "inferred");
  const wrongKind = sanitizeOrigin({ v: 1, kind: "override", status: "observed", basis: "no-moorai-ask", thread: "main" });
  assert.deepEqual([wrongKind.kind, wrongKind.status], ["agent", "inferred"]);
  assert.equal(sanitizeOrigin({ v: 1, basis: "made-up", thread: "main" }), undefined);
  assert.equal(sanitizeOrigin({ v: 2, basis: "headless", thread: "main" }), undefined);
  assert.equal(sanitizeOrigin({ v: 1, basis: "headless", thread: "side" }), undefined);
  assert.equal(sanitizeOrigin(null), undefined);
  assert.equal(sanitizeOrigin([1]), undefined);
  const extra = sanitizeOrigin({ v: 1, basis: "headless", thread: "main", hostPrompt: "not-shown", cmd: "rm -rf /", subagentType: "x" });
  assert.deepEqual(Object.keys(extra).sort(), ["basis", "hostPrompt", "kind", "status", "thread", "v"]);
  assert.equal(sanitizeOrigin({ v: 1, basis: "subagent-id", thread: "subagent", subagentType: "acme merger review" }).subagentType, undefined);
  for (const o of [originFor({ ...CC }), originFor({ ...CC, agentId: "a", subagentType: "Plan", parentBinding: "exact" }), askOutcomeOrigin({ event: "PostToolUse", resolves: { seqFrom: 1, seqTo: 2 } }), guardOrigin({ interactive: true }), originFor({ ...CC, exception: "local", intentMismatch: true })]) {
    assert.deepEqual(sanitizeOrigin(o), o);
  }
});
