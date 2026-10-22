// The setup-step installer for cloud coding agents (cli/cloud-setup.mjs, cli/moorai-cloud-setup.mjs):
// which hosts are supported and which are blocked, the root-owned server-mode file it writes, the hook
// wrappers and the host's hook registration, the OIDC path, and that the token is never printed.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/cloud-setup.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { planCloudSetup, applyPlan, CLOUD_SETUP_HOSTS, hooksFor } from "../cli/cloud-setup.mjs";
import { resolveServerMode, cloudAgentPosture } from "../cli/server-mode.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-cloud-setup.mjs");
const MWT = "mwt_" + "c".repeat(43);
const WID = "wkl-0123456789ab";
const binding = { MOORAI_SERVER_URL: "https://console.example", MOORAI_TENANT: "acme", MOORAI_INSTALL_TOKEN: MWT };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

test("hosts: Copilot coding agent and Claude Code cloud sessions are supported, Codex cloud is blocked with its reason", async () => {
  assert.deepEqual(Object.keys(CLOUD_SETUP_HOSTS).sort(), ["claude-code-web", "codex-cloud", "copilot-coding-agent"]);
  const p = await planCloudSetup({ host: "codex-cloud", env: binding, installDir: "/opt/moorai", nodePath: "/usr/bin/node" });
  assert.equal(p.ok, false);
  assert.equal(p.blocked, true);
  assert.equal(p.exitCode, 3);
  assert.match(p.reason, /not supported with cloud orchestration/);
  assert.equal(p.files, undefined);
  const u = await planCloudSetup({ host: "devin", env: binding, installDir: "/opt/moorai", nodePath: "/usr/bin/node" });
  assert.equal(u.ok, false);
  assert.equal(u.exitCode, 2);
});

test("copilot: server-mode system file, wrappers, and a repository hooks file that calls the wrapper", async () => {
  const p = await planCloudSetup({ host: "copilot-coding-agent", env: { ...binding, MOORAI_SERVICE_ID: "acme-web-copilot" }, installDir: "/opt/moorai", nodePath: "/opt/hostedtoolcache/node/22/bin/node" });
  assert.equal(p.ok, true, p.error);
  const sys = p.files.find((f) => f.path === "/etc/moorai/config.json");
  assert.equal(sys.mode, 0o644);
  const cfg = JSON.parse(sys.content);
  assert.deepEqual(cfg, { mode: "server", serverUrl: "https://console.example", tenant: "acme", installToken: MWT, cloudHost: "copilot-coding-agent", workloadAttestation: "static-token", serviceId: "acme-web-copilot" });
  const hook = p.files.find((f) => f.path === "/opt/moorai/bin/moorai-agent-hook");
  assert.equal(hook.mode, 0o755);
  assert.equal(hook.content, "#!/bin/sh\nexec '/opt/hostedtoolcache/node/22/bin/node' '/opt/moorai/cli/moorai-agent-hook.mjs' \"$@\"\n");
  assert.ok(p.files.find((f) => f.path === "/opt/moorai/bin/moorai-hook"));
  assert.equal(p.hooks.target, ".github/hooks/moorai.json");
  const h = JSON.parse(p.hooks.content);
  assert.equal(h.version, 1);
  for (const ev of ["preToolUse", "postToolUse", "userPromptSubmitted"]) {
    assert.equal(h.hooks[ev].length, 1, ev);
    assert.equal(h.hooks[ev][0].bash, "/opt/moorai/bin/moorai-agent-hook copilot");
    assert.equal(h.hooks[ev][0].powershell, undefined);
  }
  // The system file it writes resolves to a cloud agent in server mode.
  const sm = resolveServerMode({ env: {}, system: cfg });
  assert.equal(sm.active, true);
  assert.deepEqual(cloudAgentPosture(sm), { host: "copilot-coding-agent", attestation: "static-token" });
  assert.ok(!JSON.stringify(p.summary).includes(MWT));
  assert.match(p.summary.token, /^sha256:[0-9a-f]{12}$/);
});

test("claude-code-web: a managed-settings hooks block that calls the wrapper for every MoorAI event", async () => {
  const p = await planCloudSetup({ host: "claude-code-web", env: binding, installDir: "/opt/moorai", nodePath: "/usr/local/bin/node" });
  assert.equal(p.ok, true, p.error);
  assert.equal(JSON.parse(p.files.find((f) => f.path === "/etc/moorai/config.json").content).cloudHost, "claude-code-web");
  assert.equal(p.hooks.target, "server-managed settings (or the repository's .claude/settings.json)");
  const h = JSON.parse(p.hooks.content).hooks;
  for (const ev of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"]) assert.ok(Array.isArray(h[ev]) && h[ev].length, ev);
  const cmds = Object.values(h).flat().flatMap((e) => e.hooks.map((x) => x.command));
  assert.ok(cmds.length > 4);
  for (const c of cmds) assert.match(c, /^\/opt\/moorai\/bin\/moorai-hook(?: |$)/, c);
  assert.ok(h.PreToolUse.some((e) => e.matcher === "Bash"));
});

test("the committed examples are what the installer generates for /opt/moorai", async () => {
  for (const [host, file] of [["copilot-coding-agent", "examples/cloud/copilot-hooks.json"], ["claude-code-web", "examples/cloud/claude-code-web-hooks.json"]]) {
    assert.equal(readFileSync(join(ROOT, file), "utf8"), hooksFor(host, "/opt/moorai").content, file);
  }
});

test("a binding is required: console URL, tenant, and a token (static or minted)", async () => {
  let p = await planCloudSetup({ host: "copilot-coding-agent", env: { MOORAI_TENANT: "acme", MOORAI_INSTALL_TOKEN: MWT }, installDir: "/opt/moorai", nodePath: "/n" });
  assert.equal(p.ok, false); assert.match(p.error, /MOORAI_SERVER_URL/);
  p = await planCloudSetup({ host: "copilot-coding-agent", env: { MOORAI_SERVER_URL: "https://c.example", MOORAI_INSTALL_TOKEN: MWT }, installDir: "/opt/moorai", nodePath: "/n" });
  assert.equal(p.ok, false); assert.match(p.error, /MOORAI_TENANT/);
  p = await planCloudSetup({ host: "copilot-coding-agent", env: { MOORAI_SERVER_URL: "https://c.example", MOORAI_TENANT: "acme" }, installDir: "/opt/moorai", nodePath: "/n" });
  assert.equal(p.ok, false); assert.match(p.error, /MOORAI_INSTALL_TOKEN/);
});

test("OIDC: MOORAI_WORKLOAD_ID + MOORAI_OIDC=github mint a scoped token and record github-oidc", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push(String(url));
    if (String(url).startsWith("https://pipelines.example")) return json(200, { value: "eyJ.SECRET_JWT.sig" });
    if (String(url) === "https://console.example/api/workload/token") return json(200, { token: MWT, expiresAt: "2026-10-21T18:00:00.000Z" });
    return json(404, {});
  };
  const env = { MOORAI_SERVER_URL: "https://console.example", MOORAI_TENANT: "acme", MOORAI_WORKLOAD_ID: WID, MOORAI_OIDC: "github", ACTIONS_ID_TOKEN_REQUEST_URL: "https://pipelines.example/t?v=1", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "REQ" };
  const p = await planCloudSetup({ host: "copilot-coding-agent", env, installDir: "/opt/moorai", nodePath: "/n", fetchImpl });
  assert.equal(p.ok, true, p.error);
  const cfg = JSON.parse(p.files.find((f) => f.path === "/etc/moorai/config.json").content);
  assert.equal(cfg.installToken, MWT);
  assert.equal(cfg.workloadId, WID);
  assert.equal(cfg.workloadAttestation, "github-oidc");
  assert.equal(p.summary.attestation, "github-oidc");
  assert.equal(p.summary.expiresAt, "2026-10-21T18:00:00.000Z");
  assert.equal(calls.length, 2);
  // A refused exchange stops the setup with the console's code and writes nothing.
  const refused = await planCloudSetup({ host: "copilot-coding-agent", env, installDir: "/opt/moorai", nodePath: "/n", fetchImpl: async (u) => (String(u).startsWith("https://pipelines") ? json(200, { value: "eyJ.x.y" }) : json(401, { error: "claim-not-allowed" })) });
  assert.equal(refused.ok, false);
  assert.equal(refused.exitCode, 4);
  assert.match(refused.error, /claim-not-allowed/);
  assert.equal(refused.files, undefined);
});

test("applyPlan writes under --root with the planned modes", async () => {
  const root = mkdtempSync(join(tmpdir(), "moorai-cloud-"));
  try {
    const p = await planCloudSetup({ host: "copilot-coding-agent", env: binding, installDir: "/opt/moorai", nodePath: "/n" });
    const written = applyPlan(p, { root });
    assert.deepEqual(written.sort(), ["/etc/moorai/config.json", "/opt/moorai/bin/moorai-agent-hook", "/opt/moorai/bin/moorai-hook"]);
    assert.equal(statSync(join(root, "etc/moorai/config.json")).mode & 0o777, 0o644);
    assert.equal(statSync(join(root, "opt/moorai/bin/moorai-hook")).mode & 0o777, 0o755);
    assert.equal(JSON.parse(readFileSync(join(root, "etc/moorai/config.json"), "utf8")).installToken, MWT);
  } finally { rmTree(root); }
});

test("CLI: writes under --root, prints a fingerprint and never the token; refuses /etc when not root; codex exits 3", () => {
  const root = mkdtempSync(join(tmpdir(), "moorai-cloud-cli-"));
  try {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, ...binding };
    let r = spawnSync(process.execPath, [CLI, "copilot-coding-agent", "--root", root, "--install-dir", "/opt/moorai"], { env, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!(r.stdout + r.stderr).includes(MWT), "token printed");
    assert.match(r.stdout, /token sha256:[0-9a-f]{12}/);
    assert.ok(existsSync(join(root, "etc/moorai/config.json")));
    r = spawnSync(process.execPath, [CLI, "claude-code-web", "--print-hooks", "--install-dir", "/opt/moorai"], { env, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(JSON.parse(r.stdout).hooks.PreToolUse);
    r = spawnSync(process.execPath, [CLI, "codex-cloud", "--root", root], { env, encoding: "utf8" });
    assert.equal(r.status, 3);
    assert.match(r.stderr, /blocked/);
    if (typeof process.getuid === "function" && process.getuid() !== 0) {
      r = spawnSync(process.execPath, [CLI, "copilot-coding-agent"], { env, encoding: "utf8" });
      assert.equal(r.status, 2);
      assert.match(r.stderr, /run as root/);
    }
  } finally { rmTree(root); }
});
