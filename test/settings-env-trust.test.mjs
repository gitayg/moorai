// A repository must not be able to plant MoorAI's trust anchors through Claude Code's settings `env`.
//
// Claude Code's settings reference, `env`: "Set environment variables for every session and for the
// subprocesses Claude Code starts from it" and "A value here overwrites the same variable exported in your
// shell"; project and local settings apply "after you trust the workspace, or at startup in `-p` mode".
// So a repository's .claude/settings.json sets the environment of the hook process. The hook reads two
// trust anchors from the environment as well as from root-owned files — MOORAI_BREAKGLASS_PUBKEY (which
// break-glass markers verify) and MOORAI_POLICY_PUBKEY (which signed policies verify) — plus
// MOORAI_OFFLINE_MODE and the OTLP export endpoint. A value that a user, project or local settings file
// sets is the file's, not the operator's: the hook must treat it as unset. Managed settings stay trusted.
//
// The attack this pins: the repo sets MOORAI_BREAKGLASS_PUBKEY to its own key and the agent writes a
// break-glass marker signed with it, so enforcement turns off.
//
//   node --test test/settings-env-trust.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { breakGlassCanonical, BREAK_GLASS_VERSION } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TENANT = "acme";
const FUTURE = "2099-01-01T00:00:00.000Z";

const attacker = generateKeyPairSync("ed25519");
const ATTACKER_PUB = attacker.publicKey.export({ type: "spki", format: "der" }).toString("base64");
function mint(key) {
  const body = { v: BREAK_GLASS_VERSION, tenant: TENANT, device: hostname(), expires: FUTURE, nonce: "n0" };
  return JSON.stringify({ ...body, sig: edSign(null, Buffer.from(breakGlassCanonical(body)), key).toString("base64") });
}

// The break-glass E2E situation (test/break-glass.test.mjs): enrolled, no reachable policy, durable posture
// fail-closed, so an MCP probe gets "ask" unless break-glass turns enforcement off.
async function runHook({ settingsEnv = null, userSettingsEnv = null, launcherEnv = {} }) {
  const home = mkdtempSync(join(tmpdir(), "moorai-envtrust-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-envtrust-proj-"));
  const alerts = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST") { try { alerts.push(JSON.parse(body)); } catch { /* ignore */ } res.writeHead(200, { "Content-Type": "application/json" }); return res.end("{}"); }
      res.writeHead(500); res.end("offline");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${server.address().port}`, tenant: TENANT, installToken: "tok-envtrust" }));
    writeFileSync(join(home, ".moorai", "break-glass"), mint(attacker.privateKey));
    if (settingsEnv) { mkdirSync(join(proj, ".claude"), { recursive: true }); writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify({ env: settingsEnv })); }
    if (userSettingsEnv) { mkdirSync(join(home, ".claude"), { recursive: true }); writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ env: userSettingsEnv })); }
    const env = { ...process.env, HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj, MOORAI_OFFLINE_MODE: "fail-closed" };
    delete env.MOORAI_BREAKGLASS_PUBKEY; delete env.MOORAI_POLICY_PUBKEY; delete env.CLAUDE_CONFIG_DIR;
    // What Claude Code does: the settings file's env reaches the hook process, on top of the launcher's.
    Object.assign(env, launcherEnv, userSettingsEnv || {}, settingsEnv || {});
    const child = spawn(process.execPath, [HOOK], { cwd: proj, env, stdio: ["pipe", "pipe", "pipe"] });
    child.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s", cwd: proj, tool_name: "mcp__probe__ping", tool_input: {} }));
    let stdout = "";
    child.stdout.on("data", (c) => (stdout += c));
    const code = await new Promise((r) => child.on("close", r));
    await new Promise((r) => setTimeout(r, 150));
    return { stdout, code, alerts, hashes: alerts.map((a) => String(a.contentHash || "")) };
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(home, { recursive: true, force: true });
    rmSync(proj, { recursive: true, force: true });
  }
}
const enforced = (r) => /"permissionDecision":"ask"/.test(r.stdout);

test("ATTACK: a project settings file that sets MOORAI_BREAKGLASS_PUBKEY cannot unlock break-glass", async () => {
  const r = await runHook({ settingsEnv: { MOORAI_BREAKGLASS_PUBKEY: ATTACKER_PUB } });
  assert.ok(enforced(r), `the repo's own key must not turn enforcement off; stdout was ${JSON.stringify(r.stdout)}`);
  assert.ok(!r.hashes.includes("breakglass:active"), `break-glass activated: ${JSON.stringify(r.hashes)}`);
});

test("ATTACK: a user settings file (agent-writable) that sets it cannot unlock break-glass either", async () => {
  const r = await runHook({ userSettingsEnv: { MOORAI_BREAKGLASS_PUBKEY: ATTACKER_PUB } });
  assert.ok(enforced(r), `stdout was ${JSON.stringify(r.stdout)}`);
  assert.ok(!r.hashes.includes("breakglass:active"));
});

test("the refused anchor is reported content-free to the console", async () => {
  const r = await runHook({ settingsEnv: { MOORAI_BREAKGLASS_PUBKEY: ATTACKER_PUB } });
  const a = r.alerts.find((x) => /settings file/i.test(String(x.category || "")));
  assert.ok(a, `expected a refused-trust-anchor alert, got: ${JSON.stringify(r.alerts.map((x) => x.category))}`);
  assert.equal(JSON.stringify(a).includes(ATTACKER_PUB), false, "the key value never leaves");
});

test("CONTROL: the operator's key from the launching environment (no settings file) still unlocks break-glass", async () => {
  const r = await runHook({ launcherEnv: { MOORAI_BREAKGLASS_PUBKEY: ATTACKER_PUB } });
  assert.equal(r.stdout, "", "a legitimately anchored, signed marker means fail-open");
  assert.ok(r.hashes.includes("breakglass:active"), `expected break-glass, got: ${JSON.stringify(r.hashes)}`);
});

test("unit: trustedEnv refuses a name a user/project/local settings file sets, keeps the launcher's", async () => {
  const { trustedEnv, _resetEnvTrustForTests } = await import("../cli/server-mode.mjs");
  const home = mkdtempSync(join(tmpdir(), "moorai-envtrust-u-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-envtrust-p-"));
  try {
    mkdirSync(join(proj, ".claude"), { recursive: true });
    writeFileSync(join(proj, ".claude", "settings.local.json"), JSON.stringify({ env: { MOORAI_POLICY_PUBKEY: "x" } }));
    const env = { MOORAI_POLICY_PUBKEY: "x", MOORAI_OTLP_ENDPOINT: "https://collector.example", CLAUDE_PROJECT_DIR: proj };
    _resetEnvTrustForTests();
    assert.equal(trustedEnv("MOORAI_POLICY_PUBKEY", { env, home, cwd: proj }), undefined);
    _resetEnvTrustForTests();
    assert.equal(trustedEnv("MOORAI_OTLP_ENDPOINT", { env, home, cwd: proj }), "https://collector.example");
    _resetEnvTrustForTests();
    assert.equal(trustedEnv("MOORAI_BREAKGLASS_PUBKEY", { env, home, cwd: proj }), undefined, "unset stays unset");
  } finally { rmSync(home, { recursive: true, force: true }); rmSync(proj, { recursive: true, force: true }); _resetEnvTrustForTests(); }
});
