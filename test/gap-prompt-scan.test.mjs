// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/gap-prompt-scan.test.mjs
//
// UserPromptSubmit on v1.1.0 (4b6cde7) captured intent only: the prompt never reached the detection
// engine, so an event-triggered or headless run — `claude -p` fed from an issue, a webhook or a schedule,
// a poll response, a system message — handed third-party text to the model unexamined. The hooks
// reference (code.claude.com/docs/en/hooks.md) gives the prompt's `source` ("user" for typed input,
// "sdk", "system", "poll_event", "schedule_wakeup", "loop_wakeup") and lets the event block with
// `{"decision": "block", "reason": …}`.
//
// Now: a prompt that is not a person's (`source` present and not "user", or any prompt in MoorAI server
// mode) is scanned at stage "prompt" as inbound content and reported content-free; a person's typed
// prompt stays unscanned unless policy.promptScan is "all"; policy.promptScanAction "block" blocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const PS = await import("../cli/prompt-scan.mjs").catch(() => ({}));
const V2 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector2-indirect-content.json"), "utf8"));
const INJECTED = V2.attacks.find((s) => s.id === "v2-web-004").text; // #3 inj-override-structural at stage prompt
const MARK = "supersedes your operator instructions"; // a span of the prompt that must never leave the hook
const BENIGN = "Please fix the flaky test in auth.spec.ts and open a PR.";
const PII = "Bug report from jane.doe@example.com: login fails. Call me at +1 415 555 0134."; // #15 dlp-phone only

test("plan: which prompts are scanned, by source, server mode and policy", () => {
  assert.equal(typeof PS.promptScanPlan, "function", "cli/prompt-scan.mjs exports promptScanPlan");
  const plan = (policy, input, server = false) => PS.promptScanPlan(policy, { prompt: "x", ...input }, { server });
  for (const source of ["system", "poll_event", "schedule_wakeup", "loop_wakeup", "sdk", "agent_sdk", "something-new"]) {
    const p = plan({}, { source });
    assert.equal(p.scan, true, source);
    assert.equal(p.origin, "event", source);
    assert.equal(p.action, "report");
  }
  assert.equal(plan({}, { source: "something-new" }).source, "other", "unknown sources are labelled, never echoed");
  for (const input of [{ source: "user" }, {}]) assert.equal(plan({}, input).scan, false, JSON.stringify(input));
  assert.deepEqual([plan({}, { source: "user" }, true).scan, plan({}, { source: "user" }, true).origin], [true, "server"]);
  assert.equal(plan({ promptScan: "all" }, { source: "user" }).scan, true);
  assert.equal(plan({ promptScan: "off" }, { source: "poll_event" }).scan, false);
  assert.equal(plan({ promptScan: "off" }, { source: "user" }, true).scan, false);
  assert.equal(plan({ promptScan: "bogus" }, { source: "user" }).mode, "untrusted", "unknown mode → default");
  assert.equal(plan({ promptScanAction: "block" }, { source: "system" }).action, "block");
  assert.equal(plan({ promptScanAction: "deny" }, { source: "system" }).action, "report");
  assert.equal(PS.promptScanPlan({}, { source: "system", prompt: "   " }).scan, false, "an empty prompt is not scanned");
  const act = (id) => (id === 54 ? "block" : "notify");
  const ids = (fs) => PS.promptBlockers(fs, act).map((f) => f.threatId);
  assert.deepEqual(ids([{ threatId: 3 }, { threatId: 15 }, { threatId: 39 }, { threatId: 54 }, { threatId: 40 }, { threatId: 0 }]), [3, 54, 40], "instruction threats and block/kill threats block; PII and secrets do not");
});

// ---- the real hook ----
function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}
function runHook(sb, payload, env = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [HOOK], { cwd: sb.proj, env: { ...process.env, HOME: sb.home, USERPROFILE: sb.home, MOORAI_OFFLINE_MODE: "", MOORAI_MODE: "", ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let o = "";
    c.stdout.on("data", (d) => (o += d));
    c.on("close", (code) => resolve({ code, out: o.trim(), json: o.trim() ? JSON.parse(o) : null }));
    c.stdin.end(JSON.stringify({ session_id: "s-gap-prompt", transcript_path: "/tmp/t.jsonl", cwd: sb.proj, hook_event_name: "UserPromptSubmit", ...payload }));
  });
}
async function withPolicy(policy, fn, { enrolled = true } = {}) {
  const { srv, port, alerts } = await startServer(policy);
  const home = mkdtempSync(join(tmpdir(), "moorai-gapprompt-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-gapprompt-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", ...(enrolled ? { installToken: "tok-gap-prompt" } : {}) }));
  try { return await fn({ home, proj }, alerts); } finally { srv.close(); rmSync(home, { recursive: true, force: true }); rmSync(proj, { recursive: true, force: true }); }
}
const promptAlerts = (alerts) => alerts.filter((a) => a.stage === "prompt" && a.tool === "hook:UserPromptSubmit");

test("hook: an event-triggered prompt is scanned and reported content-free; nothing is printed", async () => {
  await withPolicy({ captureTier: "full-capture" }, async (sb, alerts) => {
    const r = await runHook(sb, { source: "poll_event", prompt: INJECTED });
    assert.equal(r.code, 0);
    assert.equal(r.out, "", "report mode prints nothing (stdout on this event is added to Claude's context)");
    const got = promptAlerts(alerts);
    assert.ok(got.some((a) => a.threatId === 3), `expected #3 at stage prompt, got ${JSON.stringify(got.map((a) => a.threatId))}`);
    for (const a of got) {
      assert.equal(a.promptOrigin, "event");
      assert.equal(a.promptSource, "poll_event");
      assert.notEqual(a.riskLevel, "Blocked");
    }
    assert.ok(!JSON.stringify(alerts).includes(MARK), "no span of the prompt leaves the hook, even under full-capture");
  });
});

test("hook: a person's typed prompt stays unscanned by default and is scanned under promptScan \"all\"", async () => {
  await withPolicy({ captureTier: "content-free" }, async (sb, alerts) => {
    await runHook(sb, { source: "user", prompt: INJECTED });
    await runHook(sb, { prompt: INJECTED });
    assert.deepEqual(promptAlerts(alerts), [], "typed (or source-less) prompts are not scanned by default");
  });
  await withPolicy({ captureTier: "content-free", promptScan: "all" }, async (sb, alerts) => {
    await runHook(sb, { source: "user", prompt: INJECTED });
    assert.ok(promptAlerts(alerts).some((a) => a.threatId === 3 && a.promptOrigin === "person"));
  });
  await withPolicy({ captureTier: "content-free", promptScan: "off" }, async (sb, alerts) => {
    await runHook(sb, { source: "system", prompt: INJECTED });
    assert.deepEqual(promptAlerts(alerts), [], "off scans nothing");
  });
});

test("hook: in server mode every prompt is third-party content, whatever its source", async () => {
  await withPolicy({ captureTier: "content-free" }, async (sb, alerts) => {
    const r = await runHook(sb, { source: "user", prompt: INJECTED }, { MOORAI_MODE: "server", MOORAI_SERVER_URL: "", MOORAI_TENANT: "", MOORAI_INSTALL_TOKEN: "" });
    assert.equal(r.code, 0);
    assert.ok(promptAlerts(alerts).some((a) => a.threatId === 3 && a.promptOrigin === "server"), JSON.stringify(promptAlerts(alerts)));
  });
});

test("hook: promptScanAction \"block\" blocks a flagged event prompt with a content-free reason; a clean one passes", async () => {
  await withPolicy({ captureTier: "content-free", promptScanAction: "block" }, async (sb, alerts) => {
    const r = await runHook(sb, { source: "system", prompt: INJECTED });
    assert.equal(r.json?.decision, "block", r.out || "(nothing)");
    assert.match(r.json.reason, /^MoorAI: /);
    assert.match(r.json.reason, /#3/);
    assert.ok(!r.out.includes(MARK), "the reason never quotes the prompt");
    assert.ok(promptAlerts(alerts).some((a) => a.threatId === 3 && a.riskLevel === "Blocked"));
    const ok = await runHook(sb, { source: "system", prompt: BENIGN });
    assert.equal(ok.out, "", "a clean event prompt passes silently");
    const typed = await runHook(sb, { source: "user", prompt: INJECTED });
    assert.equal(typed.out, "", "a typed prompt is still not scanned, so never blocked");
    const before = promptAlerts(alerts).length;
    const pii = await runHook(sb, { source: "poll_event", prompt: PII });
    assert.equal(pii.out, "", "a finding that carries no instructions (PII) is reported, not blocked");
    assert.ok(promptAlerts(alerts).slice(before).some((a) => a.threatId === 15 && a.riskLevel !== "Blocked"));
  });
});

test("hook: an unenrolled device never blocks a prompt; it tells the user instead", async () => {
  await withPolicy({ captureTier: "content-free", promptScanAction: "block" }, async (sb) => {
    const r = await runHook(sb, { source: "poll_event", prompt: INJECTED });
    assert.equal(r.json?.decision, undefined, r.out);
    assert.match(r.json?.systemMessage || "", /MoorAI/);
    assert.ok(!r.out.includes(MARK));
  }, { enrolled: false });
});
