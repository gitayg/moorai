// The live host-conformance tier (scripts/host-conformance.mjs), driven without any real host or model:
//   * the scripted Anthropic Messages endpoint a host is pointed at (scripts/conformance/scripted-anthropic.mjs):
//     it plays ONE planned tool_use, then reads back only whether the host returned an error result;
//   * the stand-in console (scripts/conformance/stand-in-console.mjs): signed policy + alert capture;
//   * the per-case judge for Claude Code (scripts/conformance/claude-code.mjs);
//   * the runner: plan-only without --live, not-installed targets recorded as such, and one full
//     Claude Code pass against test/fixtures/conformance/fake-claude.mjs, a stand-in host that runs the
//     hooks MoorAI installed (real cli/moorai-hook.mjs) the way Claude Code's contract describes.
// The real hosts run only under `npm run test:live`.
//
//   node --test --import ./test/hermetic-env.mjs test/host-conformance.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey } from "node:crypto";
import { startScriptedAnthropic } from "../scripts/conformance/scripted-anthropic.mjs";
import { startStandInConsole } from "../scripts/conformance/stand-in-console.mjs";
import { CLAUDE_CASES, judgeClaudeCase } from "../scripts/conformance/claude-code.mjs";
import { verifyReport, HOST_REPORT_TYPE } from "../cli/conformance-report.mjs";
import { verifyPolicySignature } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER = join(ROOT, "scripts", "host-conformance.mjs");
const FAKE_CLAUDE = join(ROOT, "test", "fixtures", "conformance", "fake-claude.mjs");

const post = (url, body) => fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
function sseEvents(text) {
  return text.split("\n\n").filter((b) => b.trim()).map((b) => JSON.parse(b.split("\n").find((l) => l.startsWith("data: ")).slice(6)));
}
const BASH = [{ name: "Bash", input_schema: { type: "object" } }, { name: "Read", input_schema: { type: "object" } }];

test("scripted endpoint: plays the planned tool_use once over SSE, then reads back the result as booleans", async () => {
  const m = await startScriptedAnthropic({ toolName: "Bash", toolInput: { command: "echo moorai-conformance-ok" }, okMarker: "moorai-conformance-ok" });
  try {
    const r = await post(`${m.url}/v1/messages?beta=true`, { model: "x", stream: true, tools: BASH, messages: [{ role: "user", content: [{ type: "text", text: "go" }] }] });
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type"), /text\/event-stream/);
    const ev = sseEvents(await r.text());
    assert.deepEqual(ev.map((e) => e.type), ["message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"]);
    const start = ev[1].content_block;
    assert.equal(start.type, "tool_use");
    assert.equal(start.name, "Bash");
    assert.match(start.id, /^toolu_/);
    assert.deepEqual(JSON.parse(ev[2].delta.partial_json), { command: "echo moorai-conformance-ok" });
    assert.equal(ev[4].delta.stop_reason, "tool_use");
    assert.equal(m.stats().toolUseSent, true);
    assert.equal(m.stats().toolResult, null);

    const done = await post(`${m.url}/v1/messages`, {
      model: "x", stream: false, tools: BASH,
      messages: [
        { role: "assistant", content: [start] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: start.id, is_error: false, content: "moorai-conformance-ok\n" }] },
        { role: "system", content: [{ type: "text", text: "reminder" }] }
      ]
    }).then((x) => x.json());
    assert.equal(done.stop_reason, "end_turn");
    assert.equal(done.content[0].type, "text");
    const s = m.stats();
    assert.deepEqual(s.toolResult, { isError: false, mentionsMoorAI: false, okMarker: true });
    assert.equal(s.requests, 2);
    assert.equal(s.toolRequests, 2);
    assert.equal(JSON.stringify(s).includes("moorai-conformance-ok"), false, "stats carry booleans, never the tool output");
  } finally { await m.close(); }
});

test("scripted endpoint: a second tool request before any result gets text, not another tool_use", async () => {
  const m = await startScriptedAnthropic({ toolName: "Bash", toolInput: { command: "x" } });
  try {
    await post(`${m.url}/v1/messages`, { model: "x", tools: BASH, messages: [{ role: "user", content: "go" }] });
    const again = await post(`${m.url}/v1/messages`, { model: "x", tools: BASH, messages: [{ role: "user", content: "go" }] }).then((x) => x.json());
    assert.equal(again.content[0].type, "text");
    assert.equal(m.stats().toolUsesSent, 1);
  } finally { await m.close(); }
});

test("scripted endpoint: an error result that names MoorAI is recorded as such", async () => {
  const m = await startScriptedAnthropic({ toolName: "Bash", toolInput: { command: "x" } });
  try {
    const first = await post(`${m.url}/v1/messages`, { model: "x", tools: BASH, messages: [{ role: "user", content: "go" }] }).then((x) => x.json());
    const id = first.content[0].id;
    await post(`${m.url}/v1/messages`, { model: "x", tools: BASH, messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: id, is_error: true, content: [{ type: "text", text: "MoorAI: blocked via Bash" }] }] }] });
    assert.deepEqual(m.stats().toolResult, { isError: true, mentionsMoorAI: true, okMarker: false });
  } finally { await m.close(); }
});

test("scripted endpoint: auxiliary calls without the planned tool, count_tokens, and the marker check", async () => {
  const m = await startScriptedAnthropic({ toolName: "Bash", toolInput: {}, marker: "AKIAIOSFODNN7EXAMPLE" });
  try {
    const aux = await post(`${m.url}/v1/messages`, { model: "x", messages: [{ role: "user", content: "title this" }] }).then((x) => x.json());
    assert.equal(aux.content[0].type, "text");
    const ct = await post(`${m.url}/v1/messages/count_tokens`, { model: "x", messages: [] }).then((x) => x.json());
    assert.equal(typeof ct.input_tokens, "number");
    assert.equal(m.stats().markerSeen, false);
    await post(`${m.url}/v1/messages`, { model: "x", messages: [{ role: "user", content: "key AKIAIOSFODNN7EXAMPLE" }] });
    const s = m.stats();
    assert.equal(s.markerSeen, true);
    assert.equal(s.auxRequests, 2);
    assert.equal(s.toolUseSent, false);
  } finally { await m.close(); }
});

test("stand-in console serves a policy the hook's own verifier accepts, and records alerts and posture", async () => {
  const policy = { captureTier: "content-free", threatPolicy: { 39: "block" } };
  const c = await startStandInConsole({ policy });
  try {
    const pk = await fetch(`${c.url}/api/policy/pubkey`).then((r) => r.json());
    const served = await fetch(`${c.url}/api/policy?tenant=${c.tenant}`).then((r) => r.json());
    assert.equal(served.threatPolicy[39], "block");
    const key = createPublicKey({ key: Buffer.from(pk.publicKey, "base64"), format: "der", type: "spki" });
    const v = verifyPolicySignature(served, { keys: [key], tenant: c.tenant });
    assert.equal(v.status, "ok", JSON.stringify(v));
    await post(`${c.url}/api/alerts`, { category: "Output & Code", riskLevel: "Blocked", decision: "deny" });
    await post(`${c.url}/api/agent-posture`, { heartbeat: { host: "claude-code" } });
    assert.equal(c.alerts.length, 1);
    assert.equal(c.postures.length, 1);
  } finally { await c.close(); }
});

const obs = (o) => ({ exitCode: 0, toolUseSent: true, toolResult: null, markerSeen: false, alerts: [], serverGotCall: null, ...o });
const def = (id) => CLAUDE_CASES.find((c) => c.id === id);

test("judge: shell-allow passes only when the tool ran and its output came back", () => {
  assert.equal(judgeClaudeCase(def("shell-allow"), obs({ toolResult: { isError: false, mentionsMoorAI: false, okMarker: true } })).status, "pass");
  assert.equal(judgeClaudeCase(def("shell-allow"), obs({ toolResult: { isError: true, mentionsMoorAI: true, okMarker: false } })).status, "fail");
  assert.equal(judgeClaudeCase(def("shell-allow"), obs({ toolUseSent: false })).status, "fail");
});

test("judge: shell-deny passes only on a MoorAI error result plus a Blocked alert", () => {
  const blocked = { category: "Output & Code", riskLevel: "Blocked", decision: "deny" };
  const r = judgeClaudeCase(def("shell-deny"), obs({ toolResult: { isError: true, mentionsMoorAI: true, okMarker: false }, alerts: [blocked] }));
  assert.equal(r.status, "pass");
  assert.equal(r.observed, "deny");
  assert.equal(r.checks.toolRan, false);
  assert.deepEqual(r.alert, { category: "Output & Code", riskLevel: "Blocked", decision: "deny", reasonCode: null });
  assert.equal(judgeClaudeCase(def("shell-deny"), obs({ toolResult: { isError: false, mentionsMoorAI: false, okMarker: false }, alerts: [blocked] })).status, "fail", "the tool ran");
  assert.equal(judgeClaudeCase(def("shell-deny"), obs({ toolResult: { isError: true, mentionsMoorAI: false, okMarker: false }, alerts: [blocked] })).status, "fail", "refused by something other than MoorAI");
  assert.equal(judgeClaudeCase(def("shell-deny"), obs({ toolResult: { isError: true, mentionsMoorAI: true, okMarker: false }, alerts: [] })).status, "fail", "no alert reached the console");
});

test("judge: prompt-block passes only when the prompt never reached the model and an alert was sent", () => {
  const blocked = { category: "Identity & Access", riskLevel: "Blocked", decision: "deny" };
  assert.equal(judgeClaudeCase(def("prompt-block"), obs({ toolUseSent: false, markerSeen: false, alerts: [blocked] })).status, "pass");
  assert.equal(judgeClaudeCase(def("prompt-block"), obs({ toolUseSent: false, markerSeen: true, alerts: [blocked] })).status, "fail");
  assert.equal(judgeClaudeCase(def("prompt-block"), obs({ toolUseSent: false, markerSeen: false, alerts: [] })).status, "fail");
});

test("judge: mcp-deny passes only when the MCP server never received the call", () => {
  const blocked = { category: "MCP tool call", riskLevel: "Blocked", decision: "deny" };
  assert.equal(judgeClaudeCase(def("mcp-deny"), obs({ toolResult: { isError: true, mentionsMoorAI: true, okMarker: false }, serverGotCall: false, alerts: [blocked] })).status, "pass");
  assert.equal(judgeClaudeCase(def("mcp-deny"), obs({ toolResult: { isError: true, mentionsMoorAI: true, okMarker: false }, serverGotCall: true, alerts: [blocked] })).status, "fail");
  assert.equal(judgeClaudeCase(def("mcp-allow"), obs({ toolResult: { isError: false, mentionsMoorAI: false, okMarker: true }, serverGotCall: true })).status, "pass");
  assert.equal(judgeClaudeCase(def("mcp-allow"), obs({ toolResult: { isError: false, mentionsMoorAI: false, okMarker: true }, serverGotCall: false })).status, "fail");
});

test("runner without --live prints the plan and runs nothing", () => {
  const out = mkdtempSync(join(tmpdir(), "moorai-conf-plan-"));
  const r = spawnSync(process.execPath, [RUNNER, "--out-dir", out], { encoding: "utf8", timeout: 30000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /plan only/i);
  assert.match(r.stdout, /claude-code/);
  assert.deepEqual(readdirSync(out), []);
});

test("runner --live with no hosts installed: every target recorded as not installed, signed, exit 0", () => {
  const out = mkdtempSync(join(tmpdir(), "moorai-conf-none-"));
  const r = spawnSync(process.execPath, [RUNNER, "--live", "--out-dir", out, "--no-sandbox"], {
    encoding: "utf8", timeout: 60000,
    env: { ...process.env, PATH: join(tmpdir(), "moorai-no-such-bin-dir"), MOORAI_CONFORMANCE_APPS_DIR: join(tmpdir(), "moorai-no-such-apps") }
  });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const files = readdirSync(out).filter((f) => f.endsWith(".json"));
  assert.ok(files.length >= 5, `one report per target: ${files}`);
  for (const f of files) {
    const rep = JSON.parse(readFileSync(join(out, f), "utf8"));
    assert.equal(rep.type, HOST_REPORT_TYPE);
    assert.equal(verifyReport(rep).ok, true, f);
    assert.equal(rep.targets[0].ran, false, f);
    assert.equal(rep.targets[0].reason, "not-installed", f);
  }
});

test("runner --live against a stand-in Claude Code: the real MoorAI hook allows, denies and blocks", async () => {
  const out = mkdtempSync(join(tmpdir(), "moorai-conf-fake-"));
  const keyDir = mkdtempSync(join(tmpdir(), "moorai-conf-k-"));
  const r = spawnSync(process.execPath, [RUNNER, "--live", "--host", "claude-code", "--bin", `claude-code=${FAKE_CLAUDE}`, "--out-dir", out, "--key", join(keyDir, "k.pem"), "--no-sandbox", "--cases", "shell-allow,shell-deny,prompt-block"], { encoding: "utf8", timeout: 180000 });
  const files = readdirSync(out);
  assert.equal(files.length, 1, `${files} ${r.stderr}`);
  assert.match(files[0], /^claude-code-2\.1\.295\.json$/);
  const rep = JSON.parse(readFileSync(join(out, files[0]), "utf8"));
  assert.equal(verifyReport(rep).ok, true);
  assert.equal(rep.signature.ephemeral, false);
  const t = rep.targets[0];
  assert.equal(t.ran, true);
  assert.equal(t.model, "scripted");
  const by = Object.fromEntries(t.cases.map((c) => [c.id, c]));
  assert.equal(by["shell-allow"].status, "pass", JSON.stringify(by["shell-allow"]));
  assert.equal(by["shell-deny"].status, "pass", JSON.stringify(by["shell-deny"]));
  assert.equal(by["prompt-block"].status, "pass", JSON.stringify(by["prompt-block"]));
  assert.equal(by["shell-deny"].alert.riskLevel, "Blocked");
  assert.equal(r.status, 0, r.stderr);
  const raw = readFileSync(join(out, files[0]), "utf8");
  for (const leak of ["dev/tcp", "AKIA", "moorai-conformance-ok", "echo "]) assert.equal(raw.includes(leak), false, `report carries ${leak}`);
  assert.ok(existsSync(join(keyDir, "k.pem")));
});
