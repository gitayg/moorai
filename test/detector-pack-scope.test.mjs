// Detector-pack `scope` (data/pack-scope.js): a scoped pack detector runs only at call sites of the kinds it
// lists (user-prompt, tool-result, command), on every surface that applies packs, whatever its stage. One
// marker string in every input; each detector carries its own threat id, so which detectors fired is read off
// the threat ids alone (the alerts carry no detector id and no content).
//
//   node --test --import ./test/hermetic-env.mjs test/detector-pack-scope.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { compilePacks } from "../data/detector-packs.js";
import { buildEngine, decideText } from "../cli/hook-core.mjs";
import { decideInbound } from "../cli/inbound.mjs";
import { maskResult } from "../cli/result-mask.mjs";
import { decideToolCall } from "../packages/agent-sdk/src/decide.mjs";
import { createMoorAI } from "../packages/agent-sdk/src/runtime.mjs";
import { moorAIHooks } from "../packages/agent-sdk/src/index.mjs";
import { responseDetectors } from "../model-proxy/response-scan.mjs";
import { createChecker } from "../model-proxy/check.mjs";
import { outboundItems } from "../model-proxy/openai.mjs";
import { createEvaluator } from "../cli/inference-hook/evaluate.mjs";
import { createReplayer } from "../cli/ingest/replay.mjs";
import { createServer } from "../cli/moorai-serve.mjs";
import { explainText } from "../cli/explain-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const MARK = "zq-scope-marker-7731";
// Threat ids per detector: instruction (#3, #40, #60) and data-class (#9, #1) threats, none of which the
// inbound rules drop, so a detector firing where it must not is visible on a tool result too.
const UP = 40, CMD = 60, TR = 3, UNP = 9, UNO = 1;
// The scoped detectors' stages point the other way from their scope, so a match proves the stage was ignored.
const PACK = { packId: "qscope", detectors: [
  { detectorId: "up", threatId: UP, stage: "output", scope: ["user-prompt"], patterns: [MARK] },
  { detectorId: "cmd", threatId: CMD, stage: "output", scope: ["command"], patterns: [MARK] },
  { detectorId: "tr", threatId: TR, stage: "prompt", scope: ["tool-result"], patterns: [MARK] },
  { detectorId: "unp", threatId: UNP, stage: "prompt", patterns: [MARK] },
  { detectorId: "uno", threatId: UNO, stage: "output", patterns: [MARK] }
] };
const POLICY = { captureTier: "content-free", promptScan: "all", detectorPacks: [PACK] };
const SCOPED = [UP, CMD, TR];
const ids = (findings) => [...new Set(findings.map((f) => f.threatId ?? f.threat.id))].filter((id) => [UP, CMD, TR, UNP, UNO].includes(id)).sort((a, b) => a - b);
const sorted = (a) => [...a].sort((x, y) => x - y);
// The marker only inside a script the command carries: a base64 payload decoded into a shell, and a
// PowerShell -EncodedCommand. The command text itself does not hold the marker.
const DECODED = `echo ${Buffer.from(`echo ${MARK}`).toString("base64")} | base64 -d | sh`;
const ENCODED = `powershell -EncodedCommand ${Buffer.from(`Write-Output ${MARK}`, "utf16le").toString("base64")}`;

test("compilePacks keeps a known scope, drops unknown kinds, drops a detector whose scope has none it knows", () => {
  const c = compilePacks([{ packId: "p", detectors: [
    { detectorId: "a", threatId: 3, scope: ["command", "future-kind", "command", "user-prompt"], patterns: ["x"] },
    { detectorId: "b", threatId: 3, patterns: ["x"] },
    { detectorId: "c", threatId: 3, scope: "command", patterns: ["x"] },
    { detectorId: "d", threatId: 3, scope: ["future-kind"], patterns: ["x"] },
    { detectorId: "e", threatId: 3, scope: [], patterns: ["x"] }
  ] }]);
  assert.deepEqual(c.map((d) => d.detectorId), ["pack:p:a", "pack:p:b", "pack:p:c"]);
  assert.deepEqual(c[0].scope, ["user-prompt", "command"]);
  assert.equal("scope" in c[1], false, "no scope: the detector object is the one compilePacks always made");
  assert.equal("scope" in c[2], false, "a scope that is not an array is no scope");
});

test("control: no built-in detector fires any of the five threat ids on the marker inputs", () => {
  const e = buildEngine(null);
  for (const t of [MARK, `echo ${MARK}`, `Write-Output ${MARK}`]) for (const st of ["prompt", "file", "output"]) assert.deepEqual(ids(e.scan(t, st, { scope: "command" })), [], `${st}: ${t}`);
});

test("engine: a scoped detector runs only where ctx.scope names its kind, at any stage; unscoped ones by stage as before", () => {
  const e = buildEngine(POLICY);
  assert.deepEqual(ids(e.scan(MARK, "prompt")), [UNP], "no scope named: only the unscoped prompt-stage detector");
  assert.deepEqual(ids(e.scan(MARK, "output")), [UNO]);
  assert.deepEqual(ids(e.scan(MARK, "file", { scope: "user-prompt" })), [UNP, UP]);
  assert.deepEqual(ids(e.scan(MARK, "prompt", { scope: "command" })), [UNP, CMD]);
  assert.deepEqual(ids(e.scan(MARK, "output", { scope: "tool-result" })), [UNO, TR]);
  assert.deepEqual(ids(e.scan(MARK, "prompt", { scope: "other" })), [UNP], "an unknown call-site kind runs no scoped detector");
  // Unscoped packs: exactly the pre-scope behaviour (prompt-stage packs also run at file, output-stage only at output).
  const plain = buildEngine({ detectorPacks: [{ packId: "p", detectors: [{ detectorId: "a", threatId: UNP, patterns: [MARK] }, { detectorId: "b", threatId: UNO, stage: "output", patterns: [MARK] }] }] });
  assert.deepEqual([ids(plain.scan(MARK, "prompt")), ids(plain.scan(MARK, "file")), ids(plain.scan(MARK, "output")), ids(plain.scan(MARK, "tool"))], [[UNP], [UNP], [UNO], []]);
  // Paths that read the detector list by stage directly (redact, explain) follow the same rule.
  const onlyScoped = buildEngine({ detectorPacks: [{ packId: "x", detectors: [{ detectorId: "a", threatId: UP, stage: "prompt", scope: ["user-prompt"], patterns: [MARK] }] }] });
  assert.equal(onlyScoped.redact(MARK, "prompt"), MARK, "redact names no call-site kind");
  const row = explainText(e, POLICY, MARK, "prompt", { ctx: { scope: "command" } }).findings.find((r) => r.detectorId === "pack:qscope:cmd");
  assert.equal(row && row.why, "pattern matched");
});

test("SDK decideToolCall: command on Bash and PowerShell only, tool-result on Read file content; never on WebFetch, MCP, Task or Write", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-scope-"));
  try {
    writeFileSync(join(dir, "notes.txt"), `see ${MARK}\n`);
    const e = buildEngine(POLICY);
    const call = (tool, toolInput) => ids(decideToolCall(e, POLICY, { tool, toolInput, cwd: dir, systemConfig: null }).findings);
    assert.deepEqual(call("Bash", { command: `echo ${MARK}` }), [UNP, CMD]);
    assert.deepEqual(call("PowerShell", { command: `Write-Output ${MARK}` }), [UNP, CMD]);
    assert.deepEqual(call("Bash", { command: DECODED }), [UNP, CMD]);
    assert.deepEqual(call("Read", { file_path: join(dir, "notes.txt") }), [TR, UNP]);
    assert.deepEqual(call("WebFetch", { url: "https://example.com/", prompt: MARK }), [UNP]);
    assert.deepEqual(call("mcp__notes__save", { body: MARK }), [UNP]);
    assert.deepEqual(call("Task", { prompt: MARK }), [UNP]);
    assert.deepEqual(call("Write", { file_path: join(dir, "out.txt"), content: MARK }), [UNO]);
  } finally { rmTree(dir); }
});

test("inbound (every tool-result surface): the tool-result detector fires, the user-prompt and command ones do not", () => {
  const e = buildEngine(POLICY);
  assert.deepEqual(ids(decideInbound(e, POLICY, `result: ${MARK}`, { surface: "web", stage: "output" }).findings), [UNO, TR]);
  assert.deepEqual(ids(decideInbound(e, POLICY, `result: ${MARK}`, { surface: "door", stage: "file" }).findings), [TR, UNP], "the MCP proxy and gateway scan results at stage file");
  assert.deepEqual(ids(decideText(e, POLICY, MARK, "output", { ctx: { targetPath: "/w/a.txt" } }).findings), [UNO], "a Write's content is no scope");
});

test("mask: a span only a tool-result-scoped detector finds is masked on a result", () => {
  const policy = { captureTier: "content-free", detectorPacks: [{ packId: "m", detectors: [{ detectorId: "k", threatId: 39, scope: ["tool-result"], patterns: ["zqkey-[0-9]{8}"] }] }] };
  const e = buildEngine(policy);
  const r = maskResult(e, policy, { content: [{ type: "text", text: "token zqkey-12345678 here" }] }, { stage: "file" });
  assert.ok(r && !r.failed, `mask applied: ${JSON.stringify(r && r.fallback)}`);
  assert.deepEqual(r.ids, [39]);
  assert.ok(!JSON.stringify(r.value).includes("zqkey-12345678"));
});

test("model proxy: a scoped detector is never a response-text detector", () => {
  const scoped = buildEngine({ detectorPacks: [{ packId: "r", detectors: [{ detectorId: "s", threatId: 39, stage: "output", scope: ["tool-result"], patterns: ["zq"] }] }] });
  const plain = buildEngine({ detectorPacks: [{ packId: "r", detectors: [{ detectorId: "s", threatId: 39, stage: "output", patterns: ["zq"] }] }] });
  const base = responseDetectors(buildEngine({})).length;
  assert.equal(responseDetectors(plain).length, base + 1);
  assert.equal(responseDetectors(scoped).length, base);
});

async function runtime(policy) {
  const posts = [];
  const reporter = { post: (a) => posts.push(a), flush: async () => {}, enrolled: false };
  return { rt: await createMoorAI({ policy, reporter, intentStore: false, secretTracker: false }), posts };
}
const postedBy = (posts, tool) => sorted(new Set(posts.filter((a) => a.tool === tool).map((a) => a.threatId).filter((id) => [UP, CMD, TR, UNP, UNO].includes(id))));

test("model proxy request: a user message is user-prompt, a tool-role message tool-result, a system message neither", async () => {
  const { rt, posts } = await runtime(POLICY);
  const checker = createChecker(rt, { enforce: false, cwd: process.cwd(), onUnevaluated: () => {} });
  await checker.checkRequest(outboundItems({ messages: [
    { role: "system", content: `sys ${MARK}` },
    { role: "user", content: `user ${MARK}` },
    { role: "tool", tool_call_id: "c1", content: `tool ${MARK}` }
  ] }));
  assert.deepEqual(postedBy(posts, "hook:prompt"), [UNP, UP]);
  assert.deepEqual(postedBy(posts, "hook:tool_result"), [UNO, TR]);
  assert.deepEqual(postedBy(posts, "hook:system"), [UNP]);
  // The same text as a system message and then as a user message: each is judged as its own kind.
  posts.length = 0;
  await checker.checkRequest(outboundItems({ messages: [{ role: "system", content: `same ${MARK}` }, { role: "user", content: `same ${MARK}` }] }));
  assert.deepEqual([postedBy(posts, "hook:system"), postedBy(posts, "hook:prompt")], [[UNP], [UNP, UP]]);
  // Tool calls in the reply: a shell-named function with a command maps to Bash; another function is an argument scan.
  posts.length = 0;
  await checker.checkToolCalls([{ name: "bash", input: { command: `echo ${MARK}` } }, { name: "notes_save", input: { body: MARK } }]);
  assert.deepEqual([postedBy(posts, "hook:Bash"), postedBy(posts, "hook:notes_save")], [[UNP, CMD], [UNP]]);
});

test("inference hook: user text is user-prompt, a mapped shell tool call is command, any other tool call neither", async () => {
  const { rt } = await runtime(POLICY);
  const seen = [];
  const spy = { ready: () => rt.ready(), scan: async (t, st, ctx, meta) => { const r = await rt.scan(t, st, ctx, meta); seen.push([meta.tool, ids(r.threatIds.map((threatId) => ({ threatId })))]); return r; } };
  const ev = createEvaluator(spy);
  await ev.evaluate({ type: "prompt", request_id: "r1", messages: [{ role: "user", content: [{ type: "text", text: `hi ${MARK}` }] }] });
  await ev.evaluate({ type: "tool_call", request_id: "r2", messages: [{ role: "assistant", content: [{ type: "tool_use", tool_name: "bash", input: { command: `echo ${MARK}` } }, { type: "tool_use", tool_name: "notes_save", input: { body: MARK } }] }] });
  assert.deepEqual(seen, [["prompt", [UNP, UP]], ["bash", [UNP, CMD]], ["notes_save", [UNP]]]);
});

test("SDK UserPromptSubmit callback: the user-prompt detector fires on the prompt", async () => {
  const posts = [];
  const hooks = moorAIHooks({ policy: POLICY, reporter: { post: (a) => posts.push(a), flush: async () => {}, enrolled: false }, intentStore: false, secretTracker: false });
  await hooks.UserPromptSubmit[0].hooks[0]({ hook_event_name: "UserPromptSubmit", prompt: `please ${MARK}`, session_id: "s" });
  assert.deepEqual(postedBy(posts, "hook:UserPromptSubmit"), [UNP, UP]);
});

test("transcript replay (moorai-ingest): the same kinds as the live hook", () => {
  const r = createReplayer(POLICY, { actor: "a" });
  const pre = (tool_name, tool_input, o) => ids(r.pre({ tool_name, tool_input }, o).findings);
  assert.deepEqual(r.prompt({ prompt: `please ${MARK}` }).findings.map((f) => f.threatId).filter((id) => SCOPED.includes(id)), [UP]);
  assert.deepEqual(pre("Bash", { command: `echo ${MARK}` }), [UNP, CMD]);
  assert.deepEqual(pre("PowerShell", { command: ENCODED }), [UNP, CMD]);
  assert.deepEqual(pre("Read", { file_path: "/w/notes.txt" }, { readText: `see ${MARK}` }), [TR, UNP]);
  assert.deepEqual(pre("WebFetch", { url: "https://example.com/", prompt: MARK }), [UNP]);
  assert.deepEqual(ids(r.post("Bash", { stdout: `out ${MARK}` }).findings), [UNO, TR]);
});

test("moorai-serve /v1/scan: ctx.scope names the kind; inbound content is tool-result", async () => {
  const TOKEN = "scope-token-0123456789abcdef";
  const s = await createServer({ port: 0, tokens: [TOKEN], policy: POLICY, env: {}, systemConfig: null });
  const req = (body) => new Promise((res, rej) => {
    const u = new URL("/v1/scan", s.url);
    const data = JSON.stringify(body);
    const q = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), authorization: `Bearer ${TOKEN}` } }, (resp) => { let b = ""; resp.on("data", (d) => (b += d)); resp.on("end", () => res(ids(JSON.parse(b).threatIds.map((threatId) => ({ threatId }))))); });
    q.on("error", rej); q.write(data); q.end();
  });
  try {
    assert.deepEqual(await req({ text: MARK }), [UNP]);
    assert.deepEqual(await req({ text: MARK, ctx: { scope: "user-prompt" } }), [UNP, UP]);
    assert.deepEqual(await req({ text: MARK, ctx: { scope: "command" } }), [UNP, CMD]);
    assert.deepEqual(await req({ text: MARK, stage: "output", ctx: { inbound: true, scope: "command" } }), [UNO, TR]);
  } finally { await s.close(); }
});

// ---- the real hook process: a local console serves the policy and collects the content-free alerts ----
function consoleServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let body = ""; req.on("data", (d) => (body += d));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(policy)); }
      res.writeHead(404); res.end();
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${srv.address().port}`, alerts, close: () => srv.close() })));
}
function runHook(sb, env, payload) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: sb.proj, env });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (status) => (status !== 0 ? rej(new Error(`hook exit ${status}: ${err}`)) : res(out)));
    c.stdin.end(JSON.stringify(payload));
  });
}

test("hook process: each scoped detector fires only at its kind of call site (prompt, Bash, PowerShell, Read, results), never on WebFetch or MCP arguments", async () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-scope-hook-"));
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(proj, "notes.txt"), `see ${MARK}\n`);
  const sb = { home, proj };
  const c = await consoleServer(POLICY);
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), CLAUDE_PROJECT_DIR: proj, MOORAI_MODE: "server", MOORAI_SERVER_URL: c.url, MOORAI_TENANT: "qs", MOORAI_INSTALL_TOKEN: "tok-qs-7731", MOORAI_SERVICE_ID: "qs-bot" };
  const base = { session_id: "qs", transcript_path: "", cwd: proj, permission_mode: "default" };
  const pre = (tool_name, tool_input) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "tu-1", ...base });
  const post = (tool_name, tool_input, tool_response) => ({ hook_event_name: "PostToolUse", tool_name, tool_input, tool_response, tool_use_id: "tu-1", ...base });
  const cases = [
    ["UserPromptSubmit", { hook_event_name: "UserPromptSubmit", prompt: `please ${MARK}`, ...base }, "hook:UserPromptSubmit", [UNP, UP]],
    ["Bash", pre("Bash", { command: `echo ${MARK}` }), "hook:Bash", [UNP, CMD]],
    ["PowerShell", pre("PowerShell", { command: `Write-Output ${MARK}` }), "hook:PowerShell", [UNP, CMD]],
    ["Bash decoded payload", pre("Bash", { command: DECODED }), "hook:Bash", [UNP, CMD]],
    ["Read", pre("Read", { file_path: join(proj, "notes.txt") }), "hook:Read", [TR, UNP]],
    ["Bash reading a file", pre("Bash", { command: "cat notes.txt" }), "hook:Bash", [TR, UNP]],
    ["WebFetch call", pre("WebFetch", { url: "https://example.com/", prompt: MARK }), "hook:WebFetch", [UNP]],
    ["MCP call", pre("mcp__notes__save", { body: MARK }), "hook:mcp__notes__save", [UNP]],
    ["Bash result", post("Bash", { command: "ls" }, { stdout: `out ${MARK}`, stderr: "", interrupted: false }), "hook:Bash", [UNO, TR]],
    ["WebFetch result", post("WebFetch", { url: "https://example.com/", prompt: "x" }, { result: `page ${MARK}`, code: 200 }), "hook:WebFetch", [UNO, TR]]
  ];
  try {
    const got = [];
    for (const [name, payload, tool] of cases) {
      c.alerts.length = 0;
      await runHook(sb, env, payload);
      got.push([name, postedBy(c.alerts, tool)]);
    }
    assert.deepEqual(got, cases.map(([name, , , want]) => [name, want]));
    for (const id of SCOPED) assert.ok(got.some(([, g]) => g.includes(id)), `#${id} fired somewhere`);
  } finally { c.close(); rmTree(home); }
});

test("hook process: a mask resolves through a scoped detector, on a command and on a result", async () => {
  const KEY = "zqkey-12345678";
  const policy = { captureTier: "content-free", threatPolicy: { 39: "mask" }, detectorPacks: [{ packId: "mk", detectors: [
    { detectorId: "c", threatId: 39, scope: ["command"], patterns: ["zqkey-[0-9]{8}"] },
    { detectorId: "r", threatId: 39, scope: ["tool-result"], patterns: ["zqkey-[0-9]{8}"] }
  ] }] };
  const home = mkdtempSync(join(tmpdir(), "moorai-scope-mask-"));
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  const c = await consoleServer(policy);
  const env = { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), CLAUDE_PROJECT_DIR: proj, MOORAI_MODE: "server", MOORAI_SERVER_URL: c.url, MOORAI_TENANT: "qs", MOORAI_INSTALL_TOKEN: "tok-qs-7731", MOORAI_SERVICE_ID: "qs-bot" };
  const base = { session_id: "qm", transcript_path: "", cwd: proj, permission_mode: "default", tool_use_id: "tu-1" };
  try {
    const pre = JSON.parse(await runHook({ home, proj }, env, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `echo ${KEY}` }, ...base }));
    const cmd = pre.hookSpecificOutput && pre.hookSpecificOutput.updatedInput && pre.hookSpecificOutput.updatedInput.command;
    assert.ok(typeof cmd === "string" && cmd.startsWith("echo [MOORAI:") && !cmd.includes(KEY), `command rewritten: ${JSON.stringify(pre)}`);
    const post = JSON.parse(await runHook({ home, proj }, env, { hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_response: { stdout: `out ${KEY}`, stderr: "", interrupted: false }, ...base }));
    const out = post.hookSpecificOutput && post.hookSpecificOutput.updatedToolOutput;
    assert.ok(out && !JSON.stringify(out).includes(KEY) && JSON.stringify(out).includes("[MOORAI:"), `result rewritten: ${JSON.stringify(post)}`);
  } finally { c.close(); rmTree(home); }
});
