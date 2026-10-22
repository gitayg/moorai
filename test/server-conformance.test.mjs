// The AI Servers live conformance tier (scripts/server-conformance.mjs), driven without Ollama:
//   * the upstream recorder between MoorAI's model proxy and the model server
//     (scripts/conformance/upstream-recorder.mjs): forwards bytes unchanged and records, per request, only
//     whether a marker string left in the request and whether the upstream answer carried a tool call;
//   * the per-case judge (scripts/conformance/model-proxy-cases.mjs);
//   * the runner: plan-only without --live, and a full pass against an in-test model server that speaks
//     the OpenAI Chat Completions, Anthropic Messages, Ollama /api/chat and Responses shapes, with the real
//     moorai-model-proxy process in enforce mode in between, plus the official MCP SDK client and server
//     through the real MCP gateway.
// Real Ollama runs only under `npm run test:live`.
//
//   node --test --import ./test/hermetic-env.mjs test/server-conformance.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startUpstreamRecorder, toolCallIn } from "../scripts/conformance/upstream-recorder.mjs";
import { SERVER_CASES, judgeServerCase } from "../scripts/conformance/model-proxy-cases.mjs";
import { verifyReport, SERVER_REPORT_TYPE } from "../cli/conformance-report.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER = join(ROOT, "scripts", "server-conformance.mjs");
const MARK = "AKIAIOSFODNN7EXAMPLE";

// A model server that always calls the offered tool, in each provider's shape.
function fakeModelServer() {
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const path = req.url.split("?")[0];
      const j = (() => { try { return JSON.parse(b); } catch { return {}; } })();
      const json = (o) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
      if (req.method === "GET" && path === "/api/version") return json({ version: "0.0.1-fake" });
      if (req.method === "GET" && path === "/api/tags") return json({ models: [{ name: "fake-model:latest" }] });
      const tool = Array.isArray(j.tools) && j.tools.length ? j.tools[0] : null;
      const name = tool ? (tool.function ? tool.function.name : tool.name) : null;
      if (path === "/v1/chat/completions") {
        const message = name ? { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name, arguments: '{"path":"./build"}' } }] } : { role: "assistant", content: "OK" };
        if (!j.stream) return json({ id: "c1", object: "chat.completion", model: j.model, choices: [{ index: 0, message, finish_reason: name ? "tool_calls" : "stop" }] });
        res.writeHead(200, { "content-type": "text/event-stream" });
        const delta = name ? { role: "assistant", tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name, arguments: '{"path":"./build"}' } }] } : { role: "assistant", content: "OK" };
        res.write(`data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
        res.write(`data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: name ? "tool_calls" : "stop" }] })}\n\n`);
        return res.end("data: [DONE]\n\n");
      }
      if (path === "/v1/messages") {
        const content = name ? [{ type: "tool_use", id: "toolu_1", name, input: { path: "./build" } }] : [{ type: "text", text: "OK" }];
        return json({ id: "m1", type: "message", role: "assistant", model: j.model, content, stop_reason: name ? "tool_use" : "end_turn", usage: { input_tokens: 1, output_tokens: 1 } });
      }
      if (path === "/api/chat") {
        const message = name ? { role: "assistant", content: "", tool_calls: [{ function: { name, arguments: { path: "./build" } } }] } : { role: "assistant", content: "OK" };
        return json({ model: j.model, created_at: "2026-10-21T00:00:00Z", message, done: true, done_reason: "stop" });
      }
      if (path === "/v1/responses") return json({ id: "r1", object: "response", status: "completed", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "OK" }] }] });
      res.writeHead(404); res.end("{}");
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((d) => { srv.closeAllConnections?.(); srv.close(d); }) })));
}

test("toolCallIn recognises a tool call in each provider shape, and nothing else", () => {
  assert.equal(toolCallIn('{"choices":[{"message":{"tool_calls":[{"id":"c","function":{"name":"x"}}]}}]}'), true);
  assert.equal(toolCallIn('data: {"choices":[{"delta":{"tool_calls":[{"index":0}]}}]}\n\n'), true);
  assert.equal(toolCallIn('{"content":[{"type":"tool_use","id":"t","name":"x","input":{}}]}'), true);
  assert.equal(toolCallIn('{"message":{"role":"assistant","tool_calls":[{"function":{"name":"x"}}]},"done":true}\n'), true);
  assert.equal(toolCallIn('{"output":[{"type":"function_call","name":"x"}]}'), true);
  assert.equal(toolCallIn('{"choices":[{"message":{"content":"OK","tool_calls":[]}}]}'), false);
  assert.equal(toolCallIn('{"content":[{"type":"text","text":"tool_use is a word"}]}'), false);
});

test("upstream recorder forwards unchanged and keeps booleans only", async () => {
  const up = await fakeModelServer();
  const rec = await startUpstreamRecorder({ upstream: up.url, marker: MARK });
  try {
    const a = await fetch(`${rec.url}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }) });
    const aj = await a.json();
    assert.equal(aj.choices[0].message.content, "OK");
    await fetch(`${rec.url}/v1/chat/completions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ model: "m", messages: [{ role: "user", content: `key ${MARK}` }], tools: [{ type: "function", function: { name: "delete_project_files" } }] }) }).then((r) => r.text());
    assert.deepEqual(rec.log.map((e) => ({ markerSeen: e.markerSeen, toolCallSeen: e.toolCallSeen, status: e.status })), [
      { markerSeen: false, toolCallSeen: false, status: 200 },
      { markerSeen: true, toolCallSeen: true, status: 200 }
    ]);
    assert.equal(JSON.stringify(rec.log).includes(MARK), false);
    assert.equal(JSON.stringify(rec.log).includes("delete_project_files"), false);
  } finally { await rec.close(); await up.close(); }
});

const blocked = { category: "Identity & Access", riskLevel: "Blocked", decision: "deny" };
const up = (o) => ({ requests: 1, markerSeen: false, toolCallSeen: false, ...o });
const def = (id) => SERVER_CASES.find((c) => c.id === id);

test("judge: allow cases need a 200 in the provider's shape that came from the upstream", () => {
  assert.equal(judgeServerCase(def("openai-chat-allow"), { status: 200, okShape: true, upstream: up(), alerts: [] }).status, "pass");
  assert.equal(judgeServerCase(def("openai-chat-allow"), { status: 200, okShape: true, upstream: up({ requests: 0 }), alerts: [] }).status, "fail");
  assert.equal(judgeServerCase(def("openai-chat-stream-allow"), { status: 200, okShape: true, doneMarker: false, upstream: up(), alerts: [] }).status, "fail");
});

test("judge: deny cases need a 403 refusal, no upstream sight of the marker, and a Blocked alert", () => {
  const ok = { status: 403, errorShape: true, upstream: up({ requests: 0 }), alerts: [blocked] };
  assert.equal(judgeServerCase(def("openai-chat-secret-deny"), ok).status, "pass");
  assert.equal(judgeServerCase(def("openai-chat-secret-deny"), { ...ok, upstream: up({ markerSeen: true }) }).status, "fail");
  assert.equal(judgeServerCase(def("openai-chat-secret-deny"), { ...ok, alerts: [] }).status, "fail");
  assert.equal(judgeServerCase(def("openai-chat-secret-deny"), { ...ok, status: 200 }).status, "fail");
});

test("judge: withhold cases are inconclusive when the model made no tool call, and fail if one was released", () => {
  assert.equal(judgeServerCase(def("openai-chat-toolcall-withhold"), { status: 200, okShape: true, toolCallReleased: false, upstream: up(), alerts: [] }).status, "inconclusive");
  assert.equal(judgeServerCase(def("openai-chat-toolcall-withhold"), { status: 403, errorShape: true, toolCallReleased: false, upstream: up({ toolCallSeen: true }), alerts: [blocked] }).status, "pass");
  assert.equal(judgeServerCase(def("openai-chat-toolcall-withhold"), { status: 200, okShape: true, toolCallReleased: true, upstream: up({ toolCallSeen: true }), alerts: [blocked] }).status, "fail");
  // A stream that released the call and only then ended in an error is still a released call.
  assert.equal(judgeServerCase(def("openai-chat-stream-toolcall-withhold"), { status: 200, errorShape: true, toolCallReleased: true, upstream: up({ toolCallSeen: true }), alerts: [blocked] }).status, "fail");
});

test("provider SDK rows say installed-but-not-run apart from not installed", async () => {
  const { sdkTargets } = await import("../scripts/conformance/server-rows.mjs");
  const none = sdkTargets({ js: () => false, py: () => false });
  assert.ok(none.length >= 8 && none.every((t) => t.ran === false && t.reason === "sdk-not-installed"));
  const all = sdkTargets({ js: () => true, py: () => true });
  assert.ok(all.every((t) => t.ran === false && t.reason === "no-live-tier"));
});

test("judge: the Responses API case records the documented gap rather than a pass", () => {
  assert.equal(judgeServerCase(def("openai-responses-secret"), { status: 200, okShape: true, upstream: up({ markerSeen: true }), alerts: [] }).status, "gap");
  assert.equal(judgeServerCase(def("openai-responses-secret"), { status: 403, errorShape: true, upstream: up({ requests: 0 }), alerts: [blocked] }).status, "pass");
});

test("judge: the MCP SDK deny case fails if the SDK server received the call or no alert came", async () => {
  const { judgeSdkGateway } = await import("../scripts/conformance/mcp-sdk-gateway.mjs");
  const j = { ok: true, tools: ["echo"], calls: [{ name: "echo", isError: false, text: "hello-moorai" }, { name: "echo", isError: true, text: "MoorAI blocked this MCP tool call: echo argument matches a denied pattern" }] };
  const alert = { category: "MCP: denied tool argument", riskLevel: "Blocked", decision: "deny" };
  assert.deepEqual(judgeSdkGateway(j, { gotBenign: true, gotDenied: false }, [alert]).map((c) => c.status), ["pass", "pass"]);
  assert.deepEqual(judgeSdkGateway(j, { gotBenign: true, gotDenied: true }, [alert]).map((c) => c.status), ["pass", "fail"]);
  assert.deepEqual(judgeSdkGateway(j, { gotBenign: true, gotDenied: false }, []).map((c) => c.status), ["pass", "fail"]);
  assert.deepEqual(judgeSdkGateway(j, { gotBenign: false, gotDenied: false }, [alert]).map((c) => c.status), ["fail", "pass"]);
});

test("runner without --live prints the plan and starts nothing", () => {
  const out = mkdtempSync(join(tmpdir(), "moorai-srv-plan-"));
  const r = spawnSync(process.execPath, [RUNNER, "--out-dir", out], { encoding: "utf8", timeout: 30000 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /plan only/i);
  assert.deepEqual(readdirSync(out), []);
});

function runAsync(args) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.stderr.on("data", (d) => (stderr += d));
    c.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("runner --live against an in-test model server: the real model proxy refuses, withholds and forwards; the MCP SDK pair runs through the gateway", async () => {
  const fake = await fakeModelServer();
  const out = mkdtempSync(join(tmpdir(), "moorai-srv-live-"));
  try {
    const r = await runAsync([RUNNER, "--live", "--upstream", fake.url, "--model", "fake-model:latest", "--out-dir", out]);
    const files = readdirSync(out).filter((f) => f.endsWith(".json"));
    const reps = Object.fromEntries(files.map((f) => { const j = JSON.parse(readFileSync(join(out, f), "utf8")); return [j.targets[0].id, j]; }));
    for (const rep of Object.values(reps)) { assert.equal(rep.type, SERVER_REPORT_TYPE); assert.equal(verifyReport(rep).ok, true); }
    const mp = reps["model-proxy-ollama"];
    assert.ok(mp, `files: ${files} ${r.stderr}`);
    assert.equal(mp.targets[0].ran, true);
    assert.equal(mp.targets[0].modelName, "fake-model:latest");
    assert.equal(mp.targets[0].version, "0.0.1-fake");
    const by = Object.fromEntries(mp.targets[0].cases.map((c) => [c.id, c]));
    for (const id of ["openai-chat-allow", "openai-chat-stream-allow", "openai-chat-secret-deny", "openai-chat-toolcall-withhold", "openai-chat-stream-toolcall-withhold", "anthropic-messages-allow", "anthropic-messages-secret-deny", "anthropic-toolcall-withhold", "ollama-chat-allow", "ollama-chat-secret-deny", "ollama-chat-toolcall-withhold"]) {
      assert.equal(by[id] && by[id].status, "pass", `${id}: ${JSON.stringify(by[id])}`);
    }
    assert.equal(by["openai-responses-secret"].status, "gap");
    const gw = reps["mcp-gateway-mcp-sdk"];
    assert.ok(gw, `files: ${files}`);
    assert.deepEqual(gw.targets[0].cases.map((c) => [c.id, c.status]), [["sdk-echo-allow", "pass"], ["sdk-echo-deny", "pass"]]);
    for (const [id, rep] of Object.entries(reps)) if (id.startsWith("sdk-")) { assert.equal(rep.targets[0].ran, false); assert.ok(["sdk-not-installed", "no-live-tier"].includes(rep.targets[0].reason), id); }
    assert.ok(reps["server-image-amd64"], "the amd64 image row is recorded");
    const raw = files.map((f) => readFileSync(join(out, f), "utf8")).join("\n");
    for (const leak of [MARK, "AKIAIOSFODNN7", "wJalrXUtn", "delete_project_files", "./build", "Reply with"]) assert.equal(raw.includes(leak), false, `report carries ${leak}`);
    assert.equal(r.status, 0, r.stderr + r.stdout);
  } finally { await fake.close(); }
});
