// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/escalation-credited-base.test.mjs
//
// #21 miss-recovery runs on what the DECISION credited, not on a raw re-scan. The escalation worker used
// to compute `base = engine.scan(text, stage)` and call escalateMiss only when that was empty. On inbound
// content `decideInbound` drops outbound-only threats, so a text whose only match is one of those was
// reported as nothing AND never reached the model: silent. MEASURED BEFORE THIS CHANGE on the inbound tune
// split (scripts/drop-rate.mjs, opted-in posture, hook:PostToolUse): 3 of 7 drops were this case
// (`suppressed-finding-blocks-miss-recovery`).
//
// The real hook and the real detached worker, a fake console and a fake Ollama on 127.0.0.1. No real model
// and no network. The sample is synthetic: `rm -rf ./build-cache` in a release note raises #32
// out-code-exec (High) on a raw scan at "output", and decideInbound drops it (#32 is output-only).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine } from "../cli/hook-core.mjs";
import { decideInbound } from "../cli/inbound.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const SUPPRESSED = "Release notes for the placeholder project. Maintenance tip: rm -rf ./build-cache clears stale output.";
const POLICY = { tenant: "t", threatPolicy: {}, captureTier: "content-free", modelEscalation: true, semanticEscalation: "local" };

function startConsole() {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.setHeader("content-type", "application/json"); return res.end(JSON.stringify(POLICY)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}

// A loopback Ollama that flags everything it is asked about and counts the generate calls.
function startFakeOllama() {
  const calls = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/api/tags") return res.end(JSON.stringify({ models: [{ name: "llama3:latest" }] }));
      if (req.url === "/api/generate") { calls.push(b.length); return res.end(JSON.stringify({ response: JSON.stringify({ risk: true, category: "placeholder-risk", confidence: 0.9 }) })); }
      res.statusCode = 404; res.end("{}");
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, calls })));
}

function sandbox(port) {
  const home = mkdtempSync(join(tmpdir(), "moorai-esc-credited-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "t", installToken: "tok-esc-credited" }));
  return home;
}

function run(args, env, stdin) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [HOOK, ...args], { env: { ...process.env, ...env }, stdio: ["pipe", "ignore", "ignore"] });
    c.on("close", resolve);
    c.stdin.end(stdin || "");
  });
}

async function waitFor(fn, ms = 8000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return true; await new Promise((r) => setTimeout(r, 50)); }
  return fn();
}

test("precondition: the sample's only raw finding is one the inbound decision drops", () => {
  const engine = buildEngine({});
  assert.deepEqual(engine.scan(SUPPRESSED, "output").map((f) => f.threat.id), [32]);
  assert.deepEqual(decideInbound(engine, POLICY, SUPPRESSED, { surface: "web", stage: "output" }).findings, []);
});

test("PostToolUse: a result whose only match the decision dropped reaches the model and is reported (#58)", async () => {
  const con = await startConsole();
  const ol = await startFakeOllama();
  const home = sandbox(con.port);
  const env = { HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "", MOORAI_LOCAL_HOST: `http://127.0.0.1:${ol.port}` };
  try {
    await run([], env, JSON.stringify({ hook_event_name: "PostToolUse", session_id: "s-esc", tool_use_id: "toolu_esc", tool_name: "WebFetch",
      tool_input: { url: "https://docs.example.com/p", prompt: "Summarise this page" }, tool_response: SUPPRESSED }));
    assert.ok(await waitFor(() => con.alerts.some((a) => a.threatId === 58)), `no #58 from the worker; model calls ${ol.calls.length}; alerts ${JSON.stringify(con.alerts.map((a) => [a.threatId, a.category]))}`);
    assert.equal(ol.calls.length, 1, "one model call");
    assert.ok(!con.alerts.some((a) => a.threatId === 32), "the dropped finding is still not reported");
    assert.ok(!JSON.stringify(con.alerts).includes("build-cache"), "content-free");
  } finally { con.srv.close(); ol.srv.close(); }
});

test("worker: a job whose decision credited a finding does not run miss-recovery (the contract is unchanged)", async () => {
  const con = await startConsole();
  const ol = await startFakeOllama();
  const home = sandbox(con.port);
  const job = join(home, ".moorai", "escalate-credited.json");
  writeFileSync(job, JSON.stringify({ policy: POLICY, text: SUPPRESSED, stage: "output", tool: "hook:WebFetch", credited: [32] }), { mode: 0o600 });
  try {
    await run(["escalate", job], { HOME: home, USERPROFILE: home, MOORAI_LOCAL_HOST: `http://127.0.0.1:${ol.port}` });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(ol.calls.length, 0, "no model call");
    assert.ok(!con.alerts.some((a) => a.threatId === 58));
  } finally { con.srv.close(); ol.srv.close(); }
});
