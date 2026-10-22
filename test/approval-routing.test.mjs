// F14 approval routing, the pure parts (cli/approval-routing.mjs): rule validation, matching, request ids, the
// signed approvals list, and the held-verdict state machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION } from "../cli/hook-core.mjs";
import { approvalRules, ruleMatches, matchRule, newRequestId, mcpToolOf, actionHashOf, signedApprovals, decideHeld, emptyState, readApprovalState, writeApprovalState, approvalAlert, approvalGate, REQUEST_ID_RE, PENDING_MAX, RULES_MAX, APPROVALS_FILE } from "../cli/approval-routing.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const RULE = { id: "ot-setpoint", label: "OT setpoint or mode change", match: { threatId: [43, 46] }, holds: ["block", "ask"], group: "ot-approvers" };
const valid = (r) => approvalRules({ approvalRouting: { v: 1, rules: [r] } }, { warn: () => {} });
const hash = (s) => `h2:${createHash("sha256").update(String(s)).digest("hex").slice(0, 16)}`;

test("rules: defaults applied; a malformed rule is dropped with a warning naming its id and never a value", () => {
  const [r] = valid(RULE);
  assert.deepEqual(r, { ...RULE, timeoutSec: 600, onTimeout: "deny", grant: "once", grantTtlSec: 900 });
  const warns = [];
  const rules = approvalRules({ approvalRouting: { v: 1, rules: [
    { ...RULE, id: "bad-timeout", timeoutSec: 5 },
    { ...RULE, id: "bad-label", label: "SECRET-LABEL-VALUE\u0007" },
    { ...RULE, id: "otop-alone", match: { otOp: ["write"] } },
    { ...RULE, id: "unknown-key", extra: 1 },
    { ...RULE, id: "BAD ID with spaces" },
    { ...RULE, id: "fine" },
    { ...RULE, id: "fine" }
  ] } }, { warn: (m) => warns.push(m) });
  assert.deepEqual(rules.map((x) => x.id), ["fine"]);
  assert.equal(warns.length, 6);
  for (const id of ["bad-timeout", "bad-label", "otop-alone", "unknown-key"]) assert.ok(warns.some((w) => w.includes(`"${id}"`)), id);
  assert.ok(warns.some((w) => w.includes("#4")), "an invalid id is named by its index");
  assert.ok(warns.some((w) => w.includes("duplicate")));
  assert.ok(warns.every((w) => !w.includes("SECRET-LABEL-VALUE") && !w.includes("BAD ID")), "no value echoed");
  assert.deepEqual(approvalRules({ approvalRouting: { v: 2, rules: [RULE] } }, { warn: () => {} }), [], "a wrong envelope is ignored");
  assert.deepEqual(approvalRules({}, { warn: () => assert.fail("no warning without the key") }), []);
  const many = approvalRules({ approvalRouting: { v: 1, rules: Array.from({ length: RULES_MAX + 3 }, (_, i) => ({ ...RULE, id: `r${i}` })) } }, { warn: () => {} });
  assert.equal(many.length, RULES_MAX);
});

test("match: every key set must match; threat and egress ids must all be covered; holds is honoured", () => {
  const [r] = valid(RULE);
  assert.ok(ruleMatches(r, "block", { threatIds: [43] }));
  assert.ok(ruleMatches(r, "ask", { threatIds: [43, 46] }));
  assert.ok(!ruleMatches(r, "block", { threatIds: [43, 3] }), "an uncovered second threat is not lifted");
  assert.ok(!ruleMatches(r, "block", { threatIds: [] }));
  const [blockOnly] = valid({ ...RULE, holds: ["block"] });
  assert.ok(!ruleMatches(blockOnly, "ask", { threatIds: [43] }));
  const [mcp] = valid({ ...RULE, match: { mcpTool: ["historian/write_value"], threatId: [43] } });
  assert.ok(ruleMatches(mcp, "block", { threatIds: [43], mcpTool: "historian/write_value" }));
  assert.ok(!ruleMatches(mcp, "block", { threatIds: [43], mcpTool: "historian/read_value" }));
  assert.ok(!ruleMatches(mcp, "block", { mcpTool: "historian/write_value" }), "both keys must match");
  const [eg] = valid({ ...RULE, match: { egressRuleId: ["ot-subnets"], reasonCode: ["EGRESS_RULE"] } });
  assert.ok(ruleMatches(eg, "block", { egressRuleIds: ["ot-subnets"], reasonCode: "EGRESS_RULE" }));
  assert.ok(!ruleMatches(eg, "block", { egressRuleIds: ["ot-subnets", "other"], reasonCode: "EGRESS_RULE" }));
  assert.ok(!ruleMatches(eg, "block", { egressRuleIds: [], reasonCode: "EGRESS_RULE" }), "a default-block carries no rule id");
  const [fn] = valid({ ...RULE, match: { functionTool: ["set_setpoint*"] } });
  assert.ok(ruleMatches(fn, "block", { functionTool: "Set-Setpoint_temp" }));
  assert.ok(!ruleMatches(fn, "block", { threatIds: [43] }), "the hook supplies no function name");
  assert.equal(matchRule([blockOnly, r], "ask", { threatIds: [46] }).id, "ot-setpoint");
  assert.equal(matchRule([blockOnly], "ask", { threatIds: [46] }), null);
});

test("ids and hashes: apr_ + 26 Crockford base32, mcp tool names, keyed action hash over canonical input", () => {
  for (let i = 0; i < 200; i++) assert.match(newRequestId(), REQUEST_ID_RE);
  assert.equal(newRequestId(Buffer.alloc(16, 0)), "apr_00000000000000000000000000");
  assert.equal(newRequestId(Buffer.alloc(16, 0xff)), "apr_7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
  assert.equal(mcpToolOf("mcp__historian__write_value"), "historian/write_value");
  assert.equal(mcpToolOf("Bash"), "");
  const seen = [];
  const h = (s) => { seen.push(s); return "h2:0123456789abcdef"; };
  actionHashOf("Bash", { b: 1, a: "x" }, h);
  assert.equal(seen[0], 'approval\u0000Bash\u0000{"a":"x","b":1}', "key-sorted canonical JSON");
});

const key = generateKeyPairSync("ed25519");
const other = generateKeyPairSync("ed25519");
function signedPolicy(p, k = key, tenant = "acme") {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant, iat, digest: policyDigest(p) })), k.privateKey).toString("base64");
  return { ...p, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant, iat, sig } };
}
const GRANT = { requestId: "apr_0000000000000000000000000A", ruleId: "ot-setpoint", actionHash: "h2:0123456789abcdef", decision: "approve", grant: "once", decidedAt: "2026-10-21T10:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" };

test("signed approvals: read only from a body whose signature verifies under a held key", () => {
  const p = signedPolicy({ approvals: [GRANT, { ...GRANT, requestId: "bad" }, { ...GRANT, requestId: "apr_0000000000000000000000000B", decision: "maybe" }] });
  const g = signedApprovals(p, { keys: [key.publicKey], tenant: "acme" });
  assert.equal(g.length, 1, "invalid entries skipped");
  assert.equal(g[0].requestId, GRANT.requestId);
  assert.deepEqual(signedApprovals(p, { keys: [], tenant: "acme" }), [], "no key held: no grant");
  assert.deepEqual(signedApprovals(p, { keys: [other.publicKey], tenant: "acme" }), [], "another key");
  assert.deepEqual(signedApprovals(p, { keys: [key.publicKey], tenant: "other" }), [], "another tenant");
  assert.deepEqual(signedApprovals({ ...p, approvals: [{ ...GRANT, validUntil: "2199-01-01T00:00:00.000Z" }] }, { keys: [key.publicKey], tenant: "acme" }), [], "tampered after signing");
  assert.deepEqual(signedApprovals({ approvals: [GRANT] }, { keys: [key.publicKey], tenant: "acme" }), [], "unsigned");
});

const [R] = valid({ ...RULE, timeoutSec: 60 });
const T0 = Date.parse("2026-10-21T10:00:00.000Z");
let n = 0;
const ids = () => `apr_${String(++n).padStart(26, "0")}`;

test("state machine: request, reuse, grant once, used, a different action, deny, expiry", () => {
  const AH = "h2:aaaaaaaaaaaaaaaa", BH = "h2:bbbbbbbbbbbbbbbb";
  let r = decideHeld({ rule: R, verdict: "block", actionHash: AH, threatId: 43, state: emptyState(), nowMs: T0, newId: ids });
  assert.equal(r.outcome, "deny");
  assert.equal(r.events.length, 1);
  const req = r.events[0];
  assert.equal(req.kind, "APPROVAL_REQUESTED");
  assert.equal(req.expiresAt, "2026-10-21T10:01:00.000Z");
  let st = r.state;
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, state: st, nowMs: T0 + 1000, newId: ids });
  assert.equal(r.requestId, req.requestId);
  assert.equal(r.events.length, 0, "reused, no alert");
  const grant = { requestId: req.requestId, ruleId: R.id, actionHash: AH, decision: "approve", grant: "once", decidedAtMs: T0 + 2000, validUntilMs: T0 + 900000 };
  r = decideHeld({ rule: R, verdict: "block", actionHash: BH, grants: [grant], state: st, nowMs: T0 + 3000, newId: ids });
  assert.equal(r.outcome, "deny", "a different action is not covered");
  st = r.state;
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, grants: [grant], state: st, nowMs: T0 + 3000, newId: ids });
  assert.equal(r.outcome, "allow");
  assert.deepEqual(r.events.map((e) => e.kind), ["APPROVAL_USED"]);
  assert.ok(!r.state.pending.some((p) => p.requestId === req.requestId), "pending resolved");
  st = r.state;
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, grants: [grant], state: st, nowMs: T0 + 4000, newId: ids });
  assert.equal(r.outcome, "deny", "once: used");
  assert.deepEqual(r.events.map((e) => e.kind), ["APPROVAL_REQUESTED"]);
  // allowGrant false (an early stop): a grant is never honoured there, only held.
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, grants: [{ ...grant, requestId: "apr_0000000000000000000000000Z" }], state: emptyState(), nowMs: T0, allowGrant: false, newId: ids });
  assert.equal(r.outcome, "deny");
  // deny grant
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, grants: [{ ...grant, decision: "deny" }], state: emptyState(), nowMs: T0, newId: ids });
  assert.equal(r.outcome, "deny");
  assert.match(r.reason, /^Denied by approver \(OT setpoint or mode change/);
  assert.equal(r.events.length, 0);
  // expired grant ignored
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, grants: [{ ...grant, validUntilMs: T0 - 1 }], state: emptyState(), nowMs: T0, newId: ids });
  assert.equal(r.outcome, "deny");
  // expiry of a pending request with no decision
  const p0 = decideHeld({ rule: R, verdict: "block", actionHash: BH, state: emptyState(), nowMs: T0, newId: ids });
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, state: p0.state, nowMs: T0 + 61000, newId: ids });
  assert.deepEqual(r.events.map((e) => e.kind), ["APPROVAL_EXPIRED", "APPROVAL_REQUESTED"]);
  assert.equal(r.events[0].requestId, p0.requestId);
  r = decideHeld({ rule: R, verdict: "block", actionHash: AH, state: r.state, nowMs: T0 + 62000, newId: ids });
  assert.equal(r.events.length, 0, "expired once");
});

test("state file: 0600, bounded to the newest 256 pending requests, junk read as empty", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-approvals-"));
  try {
    let st = emptyState();
    for (let i = 0; i < PENDING_MAX + 5; i++) st = decideHeld({ rule: R, verdict: "block", actionHash: `h2:${String(i).padStart(16, "0")}`, state: st, nowMs: T0, newId: ids }).state;
    assert.equal(st.pending.length, PENDING_MAX);
    assert.ok(writeApprovalState(dir, st));
    const back = readApprovalState(dir);
    assert.equal(back.pending.length, PENDING_MAX);
    assert.equal(back.pending.at(-1).actionHash, `h2:${String(PENDING_MAX + 4).padStart(16, "0")}`);
    if (process.platform !== "win32") assert.equal(statSync(join(dir, APPROVALS_FILE)).mode & 0o777, 0o600);
    writeFileSync(join(dir, APPROVALS_FILE), "not json");
    assert.deepEqual(readApprovalState(dir), emptyState());
  } finally { rmTree(dir); }
});

test("alerts: content-free shapes for requested, used and expired", () => {
  const a = approvalAlert({ kind: "APPROVAL_REQUESTED", requestId: "apr_X", ruleId: "r", actionHash: "h2:0123456789abcdef", threatId: 43, verdict: "ask", requestedAt: "t0", expiresAt: "t1" }, { tool: "Bash" });
  assert.deepEqual(a, { threatId: 43, stage: "PreToolUse", tool: "hook:Bash", contentHash: "h2:0123456789abcdef", category: "Approval requested", riskLevel: "High", decision: "deny", reasonCode: "APPROVAL_REQUESTED", approval: { v: 1, requestId: "apr_X", ruleId: "r", surface: "hook", verdict: "ask", actionHash: "h2:0123456789abcdef", requestedAt: "t0", expiresAt: "t1" } });
  assert.equal(approvalAlert({ kind: "APPROVAL_USED", requestId: "apr_X", ruleId: "r", actionHash: "h" }).riskLevel, "Info");
  assert.equal(approvalAlert({ kind: "APPROVAL_EXPIRED", requestId: "apr_X", ruleId: "r", actionHash: "h" }).reasonCode, "APPROVAL_EXPIRED");
});

test("gate: unenrolled, unroutable reasons, kill actions and killOnCritical are never routed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-approvals-gate-"));
  try {
    const policy = { approvalRouting: { v: 1, rules: [RULE] } };
    const posts = [];
    const mk = (o = {}) => approvalGate({ load: async () => ({ policy, trust: { keys: [] } }), tenant: "acme", hash, threatAction: () => "block", post: (a) => posts.push(a), stateDir: dir, warn: () => {}, ...o });
    const v = { decision: "deny", reason: "blocked", alternatives: [], rewrite: null };
    assert.equal(await mk({ enabled: false }).overlay(v, { tool: "Bash", ti: {}, found: [43] }), null);
    for (const basis of ["FAIL_CLOSED", "POLICY_TAMPER", "BEHAVIOR_SIGNAL", "CONTAINMENT_UNAVAILABLE", "PROFILE_DRIFT"]) assert.equal(await mk().overlay(v, { tool: "Bash", found: [43], basis }), null, basis);
    assert.equal(await mk({ threatAction: () => "kill" }).overlay(v, { tool: "Bash", found: [43] }), null);
    assert.equal(await mk().overlay(v, { tool: "Bash", found: [43], killOnCritical: true }), null);
    assert.equal(await mk().overlay({ ...v, decision: "allow" }, { tool: "Bash", found: [43] }), null);
    assert.equal(posts.length, 0);
    const held = await mk().overlay(v, { tool: "Bash", ti: { command: "x" }, found: [43], basis: "DETECTOR_MATCH" });
    assert.equal(held.decision, "deny");
    assert.match(held.reason, /^Held for approval: OT setpoint or mode change \(request apr_/);
    assert.equal(posts.length, 1);
    // A notify-only threat on the same call does not stop the match; an uncovered enforcing threat does.
    const mixed = approvalGate({ load: async () => ({ policy, trust: { keys: [] } }), tenant: "acme", hash, threatAction: (id) => (id === 7 ? "notify" : "block"), post: () => {}, stateDir: dir, warn: () => {} });
    assert.ok(await mixed.overlay(v, { tool: "Bash", ti: { command: "y" }, found: [43, 7] }));
    assert.equal(await mixed.overlay(v, { tool: "Bash", ti: { command: "z" }, found: [43, 3] }), null);
  } finally { rmTree(dir); }
});

test("gate: an egress grant is honoured at the early egress check only, never at the final verdict", async () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-approvals-egress-"));
  try {
    const rule = { ...RULE, id: "ot-egress", grant: "ttl", match: { egressRuleId: ["ot-subnets"], reasonCode: ["EGRESS_RULE"] } };
    const ti = { command: "curl https://hist.plant.example/" };
    const ah = actionHashOf("Bash", ti, hash);
    const g = { requestId: "apr_0000000000000000000000000C", ruleId: "ot-egress", actionHash: ah, decision: "approve", grant: "ttl", decidedAt: new Date().toISOString(), validUntil: new Date(Date.now() + 600000).toISOString() };
    const policy = signedPolicy({ approvalRouting: { v: 1, rules: [rule] }, approvals: [g] });
    const posts = [];
    const mk = () => approvalGate({ load: async () => ({ policy, trust: { keys: [key.publicKey] } }), tenant: "acme", hash, post: (a) => posts.push(a), stateDir: dir, warn: () => {} });
    const wp = { decision: "deny", reasonCode: "EGRESS_RULE", alerts: [{ reasonCode: "EGRESS_RULE", egressAction: "block", egressRuleId: "ot-subnets" }] };
    const gate = mk();
    assert.equal(await gate.liftEgress(wp, { tool: "Bash", ti }), true, "lifted at the egress check");
    assert.equal(posts.filter((a) => a.reasonCode === "APPROVAL_USED").length, 1);
    // The same grant reaching the final verdict with an EGRESS_RULE basis (the egress stop came first) never allows.
    const gate2 = mk();
    await gate2.liftEgress({ ...wp, alerts: [{ ...wp.alerts[0] }] }, { tool: "Bash", ti: { command: "other" } });
    const v = await gate2.overlay({ decision: "deny", reason: "egress", alternatives: [], rewrite: null }, { tool: "Bash", ti, found: [], basis: "EGRESS_RULE" });
    assert.equal(v.decision, "deny", JSON.stringify(v));
    // A default-block (no rule id) is not matched by an egressRuleId rule.
    assert.equal(await mk().liftEgress({ ...wp, alerts: [{ reasonCode: "EGRESS_RULE", egressAction: "block" }] }, { tool: "Bash", ti }), false);
  } finally { rmTree(dir); }
});
