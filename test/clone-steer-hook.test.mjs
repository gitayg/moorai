// Install-path steering (#40) and clone-then-run (#80) through the REAL hook process: a Read of the
// measured skill file (file stage), the skill text returned by WebFetch (output stage), and the clone-and-run
// Bash command (prompt stage), each with a local console collecting the alerts. Placeholder names only.
//
//   node --test --import ./test/hermetic-env.mjs test/clone-steer-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { SKILL, CLONE_RUN, README_FROM_SOURCE, CONTRIBUTING } from "./fixtures/install-steering.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

async function withConsole(policy, fn) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(policy)); }
      if (req.method === "POST") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); return res.end("{}"); }
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = mkdtempSync(join(tmpdir(), "moorai-cs-"));
  const proj = join(home, "proj");
  mkdirSync(join(proj, ".claude", "skills", "relnotes"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "cs", installToken: "tok-cs" }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  try { return await fn({ home, proj, alerts }); } finally { srv.close(); rmTree(home); }
}
function runHook({ home, proj }, payload) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") } });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (status) => {
      if (status !== 0) return rej(new Error(`hook exit ${status}: ${err}`));
      const t = out.trim(); const o = t ? JSON.parse(t) : {};
      res({ out: t, decision: o.hookSpecificOutput?.permissionDecision || "allow", reason: o.hookSpecificOutput?.permissionDecisionReason || "" });
    });
    c.stdin.end(JSON.stringify({ session_id: "cs", cwd: proj, tool_use_id: "tu", transcript_path: "", permission_mode: "default", ...payload }));
  });
}
const bash = (sb, command) => runHook(sb, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const read = (sb, rel, text) => { const p = join(sb.proj, rel); writeFileSync(p, text); return runHook(sb, { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: p } }); };
const settle = () => new Promise((r) => setTimeout(r, 300));
const ids = (alerts) => alerts.map((a) => a.threatId);
const POLICY = { captureTier: "content-free" };
const noNames = (alerts) => { const raw = JSON.stringify(alerts); return !raw.includes("relnotes") && !raw.includes("example-org"); };

test("hook e2e, file stage: reading the measured skill file reports #40 (report-only on Read), content-free", async () => {
  await withConsole(POLICY, async (sb) => {
    const r = await read(sb, ".claude/skills/relnotes/SKILL.md", SKILL);
    assert.equal(r.decision, "allow");
    await settle();
    // Detection alerts only: report() also posts a stage-"coach" literacy touchpoint for the same threat.
    const hits = sb.alerts.filter((a) => a.threatId === 40 && a.stage !== "coach");
    assert.ok(hits.length >= 1, `alerts: ${JSON.stringify(ids(sb.alerts))}`);
    assert.ok(hits.every((a) => a.stage === "file"), JSON.stringify(hits.map((a) => a.stage)));
    assert.ok(noNames(sb.alerts), "the alert carries no repository or package name");
  });
});

test("hook e2e, output stage: the same text returned by WebFetch is reported (#40) with an advisory to the agent", async () => {
  await withConsole(POLICY, async (sb) => {
    const r = await runHook(sb, { hook_event_name: "PostToolUse", tool_name: "WebFetch", tool_input: { url: "https://docs.example.com/relnotes", prompt: "How do I install this?" }, tool_response: SKILL });
    await settle();
    assert.ok(sb.alerts.some((a) => a.threatId === 40 && a.stage === "output"), `alerts: ${JSON.stringify(sb.alerts.map((a) => [a.threatId, a.stage]))}`);
    assert.match(r.out, /#40/);
    assert.ok(noNames(sb.alerts));
  });
});

test("hook e2e, prompt stage: the clone-and-run command is reported (#80) and allowed by default; a policy can ask or block", async () => {
  await withConsole(POLICY, async (sb) => {
    const r = await bash(sb, CLONE_RUN);
    assert.equal(r.decision, "allow", JSON.stringify(r));
    await settle();
    assert.ok(ids(sb.alerts).includes(80), `alerts: ${JSON.stringify(ids(sb.alerts))}`);
    assert.ok(noNames(sb.alerts), "the alert carries no repository name");
  });
  await withConsole({ captureTier: "content-free", threatPolicy: { 80: "justify" } }, async (sb) => {
    const r = await bash(sb, CLONE_RUN);
    assert.equal(r.decision, "ask", JSON.stringify(r));
    assert.match(r.reason, /#80/);
  });
  await withConsole({ captureTier: "content-free", threatPolicy: { 80: "block" } }, async (sb) => {
    assert.equal((await bash(sb, CLONE_RUN)).decision, "deny");
  });
});

test("hook e2e: a README build-from-source section, CONTRIBUTING steps, a plain clone and a named-package install stay quiet", async () => {
  await withConsole(POLICY, async (sb) => {
    await read(sb, "README.md", README_FROM_SOURCE);
    await read(sb, "CONTRIBUTING.md", CONTRIBUTING);
    await read(sb, "QUICKSTART.md", "Quick start: " + CLONE_RUN + "\n");
    assert.equal((await bash(sb, "git clone https://github.com/example-org/relnotes.git")).decision, "allow");
    assert.equal((await bash(sb, "npm install relnotes")).decision, "allow");
    await settle();
    const got = ids(sb.alerts).filter((id) => id === 40 || id === 80);
    assert.deepEqual(got, [], `alerts: ${JSON.stringify(sb.alerts.map((a) => [a.threatId, a.stage]))}`);
  });
});
