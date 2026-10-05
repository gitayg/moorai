// Declared workload profiles end to end: the real hook process (scripted stdin, a local console serving the
// policy and collecting alerts) and the SDK's PreToolUse callback over the same profile.
//
// The trust test mirrors test/settings-env-trust.test.mjs: a repository must not be able to declare its own
// baseline. Profiles come only from the verified console policy and the root-owned machine-wide config, so a
// `workloadProfiles` key in the repo's .claude/settings.json (top level or `env`), in a repo-local
// .moorai/config.json or in ~/.moorai/config.json must change nothing.
//
//   node --test --import ./test/hermetic-env.mjs test/workload-profile-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import http from "node:http";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const SDK = pathToFileURL(join(ROOT, "packages", "agent-sdk", "src", "index.mjs")).href;
const BLOCK_SVC = { id: "ci-bot", match: { serviceId: "wp-bot" }, tools: ["Read", "mcp__github__*"], hosts: ["api.github.com"], action: "block" };
const REPORT_REPO = { id: "app-repo", match: { repo: "github:acme/app" }, tools: ["Read", "Bash"], hosts: ["api.github.com"], action: "report" };

function sandbox() {
  const home = mkdtempSync(join(tmpdir(), "moorai-wph-"));
  const proj = join(home, "proj");
  mkdirSync(join(proj, ".git"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(proj, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:Acme/App.git\n');
  return { home, proj };
}
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
const serverEnv = (sb, url, extra = {}) => ({ PATH: process.env.PATH || "/usr/bin:/bin", HOME: sb.home, USERPROFILE: sb.home, XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state"), CLAUDE_PROJECT_DIR: sb.proj, MOORAI_MODE: "server", MOORAI_SERVER_URL: url, MOORAI_TENANT: "wp", MOORAI_INSTALL_TOKEN: "tok-wp-9e1", MOORAI_SERVICE_ID: "wp-bot", ...extra });
const envelope = (sb, tool_name, tool_input) => ({ hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "tu-1", session_id: "wp", transcript_path: "", cwd: sb.proj, permission_mode: "default" });

function runHook(sb, env, payload) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: sb.proj, env });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (status) => { if (status !== 0) return rej(new Error(`hook exit ${status}: ${err}`)); const t = out.trim(); res(t ? JSON.parse(t) : {}); });
    c.stdin.end(JSON.stringify(payload));
  });
}
const decisionOf = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || "allow";
const reasonOf = (o) => (o.hookSpecificOutput && o.hookSpecificOutput.permissionDecisionReason) || "";
const drift = (alerts) => alerts.filter((a) => a.reasonCode === "PROFILE_DRIFT");

async function withConsole(policy, fn) {
  const sb = sandbox();
  const c = await consoleServer(policy);
  try { return await fn(sb, c); } finally { c.close(); rmSync(sb.home, { recursive: true, force: true }); }
}

test("server mode, serviceId profile with action block: an out-of-profile tool is denied and a PROFILE_DRIFT alert names only the profile and kind", async () => {
  await withConsole({ captureTier: "content-free", workloadProfiles: [BLOCK_SVC] }, async (sb, c) => {
    const o = await runHook(sb, serverEnv(sb, c.url), envelope(sb, "Bash", { command: "echo MARKER-7731 > out.txt" }));
    assert.equal(decisionOf(o), "deny");
    assert.equal(reasonOf(o), 'MoorAI: outside the declared workload profile "ci-bot" (tool not in the profile)');
    const d = drift(c.alerts);
    assert.equal(d.length, 1);
    assert.deepEqual([d[0].driftKind, d[0].driftItem, d[0].profileId, d[0].riskLevel, d[0].tool, d[0].device], ["tool", "Bash", "ci-bot", "Blocked", "hook:Bash", "svc:wp-bot"]);
    assert.ok(!JSON.stringify(c.alerts).includes("MARKER-7731"), "no command text leaves");
    assert.equal(d[0].workload && d[0].workload.pid, process.pid, "server mode: CONTRACT C1 workload.pid is the agent process (the hook's parent)");
    const ok = await runHook(sb, serverEnv(sb, c.url), envelope(sb, "mcp__github__get_issue", { url: "https://api.github.com/repos/a/b" }));
    assert.equal(decisionOf(ok), "allow");
    assert.equal(drift(c.alerts).length, 1, "in-profile call raises nothing");
  });
});

test("repo profile with action report: drift is reported, the call is allowed", async () => {
  await withConsole({ captureTier: "content-free", workloadProfiles: [REPORT_REPO] }, async (sb, c) => {
    const o = await runHook(sb, serverEnv(sb, c.url, { MOORAI_SERVICE_ID: "someone-else" }), envelope(sb, "Bash", { command: "curl -s https://paste.example/upload?k=v" }));
    assert.equal(decisionOf(o), "allow");
    const d = drift(c.alerts);
    assert.deepEqual(d.map((a) => [a.driftKind, a.driftItem, a.profileId, a.decision]), [["host", "paste.example", "app-repo", "allow"]]);
    assert.ok(!JSON.stringify(d).includes("upload?k=v"));
  });
});

test("a repository cannot supply its own profile (settings env, settings top level, repo-local and user config are all ignored)", async () => {
  const planted = JSON.stringify([{ ...BLOCK_SVC, id: "planted" }]);
  const plant = (sb) => {
    mkdirSync(join(sb.proj, ".claude"), { recursive: true });
    writeFileSync(join(sb.proj, ".claude", "settings.json"), JSON.stringify({ workloadProfiles: JSON.parse(planted), env: { MOORAI_WORKLOAD_PROFILES: planted, workloadProfiles: planted } }));
    mkdirSync(join(sb.proj, ".moorai"), { recursive: true });
    writeFileSync(join(sb.proj, ".moorai", "config.json"), JSON.stringify({ workloadProfiles: JSON.parse(planted) }));
    writeFileSync(join(sb.home, ".moorai", "config.json"), JSON.stringify({ workloadProfiles: JSON.parse(planted) }));
  };
  // The planted copies only: nothing changes.
  await withConsole({ captureTier: "content-free" }, async (sb, c) => {
    plant(sb);
    const o = await runHook(sb, serverEnv(sb, c.url, { MOORAI_WORKLOAD_PROFILES: planted }), envelope(sb, "Bash", { command: "ls" }));
    assert.equal(decisionOf(o), "allow");
    assert.equal(drift(c.alerts).length, 0);
  });
  // Positive control: the same profile from the console policy does deny in the same sandbox.
  await withConsole({ captureTier: "content-free", workloadProfiles: JSON.parse(planted) }, async (sb, c) => {
    plant(sb);
    const o = await runHook(sb, serverEnv(sb, c.url), envelope(sb, "Bash", { command: "ls" }));
    assert.equal(decisionOf(o), "deny");
    assert.equal(drift(c.alerts)[0].profileId, "planted");
  });
});

test("unenrolled device: a block profile coaches, never denies", async () => {
  await withConsole({ captureTier: "content-free", workloadProfiles: [{ ...REPORT_REPO, action: "block" }] }, async (sb, c) => {
    writeFileSync(join(sb.home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: "wp" }));
    const env = { PATH: process.env.PATH, HOME: sb.home, USERPROFILE: sb.home, XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state"), CLAUDE_PROJECT_DIR: sb.proj };
    const o = await runHook(sb, env, envelope(sb, "Write", { file_path: join(sb.proj, "a.txt"), content: "hello" }));
    assert.equal(o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision, undefined, "no permissionDecision on an unenrolled device");
    assert.match(o.systemMessage || "", /outside the declared workload profile "app-repo"/);
    assert.equal(c.alerts.length, 0, "an unenrolled device posts nothing");
  });
});

test("malformed profiles are ignored and reported once; the valid profile still applies", async () => {
  await withConsole({ captureTier: "content-free", workloadProfiles: [{ id: "bad", match: { serviceId: "wp-bot", branch: "main" }, action: "block" }, BLOCK_SVC] }, async (sb, c) => {
    const o = await runHook(sb, serverEnv(sb, c.url), envelope(sb, "Bash", { command: "ls" }));
    assert.equal(decisionOf(o), "deny");
    assert.match(reasonOf(o), /"ci-bot"/);
    await runHook(sb, serverEnv(sb, c.url), envelope(sb, "Read", { file_path: join(sb.proj, ".git", "config") }));
    const rej = c.alerts.filter((a) => a.category === "Workload profile ignored (malformed)");
    assert.equal(rej.length, 1, "reported once, not per call");
    assert.deepEqual(rej[0].profileRejected, [{ source: "policy", index: 0, id: "bad", reason: "unknown match key" }]);
  });
});

test("SDK PreToolUse callback reaches the same verdict and reason as the hook on a repo profile", async () => {
  const policy = { captureTier: "content-free", workloadProfiles: [{ ...REPORT_REPO, action: "block" }] };
  await withConsole(policy, async (sb, c) => {
    const env = serverEnv(sb, c.url);
    const calls = [["Write", { file_path: join(sb.proj, "a.txt"), content: "x" }], ["Bash", { command: "curl https://paste.example/" }], ["Bash", { command: "curl https://api.github.com/" }], ["Read", { file_path: join(sb.proj, ".git", "config") }]];
    const hook = [];
    for (const [t, i] of calls) { const o = await runHook(sb, env, envelope(sb, t, i)); hook.push([decisionOf(o), reasonOf(o)]); }
    const WORKER = `const { moorAIHooks } = await import(process.argv[1]); let s = ""; for await (const ch of process.stdin) s += ch; const { inputs } = JSON.parse(s); const pre = moorAIHooks({}).PreToolUse[0].hooks[0]; const out = []; for (const i of inputs) out.push(await pre(i, i.tool_use_id, { signal: AbortSignal.timeout(30000) })); process.stdout.write(JSON.stringify(out));`;
    const sdk = await new Promise((res, rej) => {
      const ch = spawn(process.execPath, ["--input-type=module", "-e", WORKER, SDK], { cwd: sb.proj, env });
      let out = "", err = ""; ch.stdout.on("data", (d) => (out += d)); ch.stderr.on("data", (d) => (err += d));
      ch.on("close", (st) => (st ? rej(new Error(err)) : res(JSON.parse(out))));
      ch.stdin.end(JSON.stringify({ inputs: calls.map(([t, i]) => envelope(sb, t, i)) }));
    });
    assert.deepEqual(sdk.map((o) => [decisionOf(o), reasonOf(o)]), hook);
    assert.deepEqual(hook.map((h) => h[0]), ["deny", "deny", "allow", "allow"]);
  });
});

test("enrolled laptop: a repo profile reports drift without a serviceId, and the alert carries no workload object", async () => {
  await withConsole({ captureTier: "content-free", workloadProfiles: [BLOCK_SVC, REPORT_REPO] }, async (sb, c) => {
    writeFileSync(join(sb.home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: "wp", installToken: "tok-wp-laptop" }));
    const env = { PATH: process.env.PATH, HOME: sb.home, USERPROFILE: sb.home, XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state"), CLAUDE_PROJECT_DIR: sb.proj };
    const o = await runHook(sb, env, envelope(sb, "Write", { file_path: join(sb.proj, "a.txt"), content: "hello" }));
    assert.equal(decisionOf(o), "allow", "the serviceId block profile does not match a laptop");
    const d = drift(c.alerts);
    assert.deepEqual(d.map((a) => [a.driftKind, a.driftItem, a.profileId]), [["tool", "Write", "app-repo"]]);
    assert.equal(d[0].workload, undefined);
  });
});

test("SDK decideToolCall: a serviceId profile matches the serviceId the caller passes, and only that one", async () => {
  const { decideToolCall } = await import(SDK);
  const { buildEngine } = await import(pathToFileURL(join(ROOT, "cli", "hook-core.mjs")).href);
  const policy = { captureTier: "content-free", workloadProfiles: [BLOCK_SVC] };
  const engine = buildEngine(policy);
  const call = (serviceId) => decideToolCall(engine, policy, { tool: "Bash", toolInput: { command: "ls" }, cwd: tmpdir(), serviceId, systemConfig: null });
  const d = call("wp-bot");
  assert.equal(d.decision, "deny");
  assert.equal(d.reason, 'outside the declared workload profile "ci-bot" (tool not in the profile)');
  assert.deepEqual(d.signals.filter((s) => s.reasonCode === "PROFILE_DRIFT").map((s) => [s.driftKind, s.profileId]), [["tool", "ci-bot"]]);
  assert.equal(call("other-bot").decision, "allow");
  assert.equal(call("").decision, "allow");
});

// Flips to a plain pass once packages/agent-sdk/src/runtime.mjs toolCall() passes `serviceId: sm.serviceId`
// to decideToolCall (that file is outside this change's ownership; see the wave report).
test("SDK runtime: createMoorAI({ serviceId }) applies a serviceId profile", async () => {
  const { createMoorAI } = await import(pathToFileURL(join(ROOT, "packages", "agent-sdk", "src", "runtime.mjs")).href);
  const posted = [];
  const rt = await createMoorAI({ serviceId: "wp-bot", policy: { captureTier: "content-free", workloadProfiles: [BLOCK_SVC] }, systemConfig: null, reporter: { post: (a) => posted.push(a), flush: async () => {}, enrolled: true } });
  const v = await rt.toolCall({ tool: "Bash", input: { command: "ls" }, cwd: tmpdir() });
  assert.equal(v.decision, "deny");
  assert.equal(posted.filter((a) => a.reasonCode === "PROFILE_DRIFT").length, 1);
});
