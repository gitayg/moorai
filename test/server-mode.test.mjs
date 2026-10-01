// Server mode (cli/server-mode.mjs): configuration precedence, the settings-file tamper refusal, the
// headless-ask mapping, the service identity — and that loadConfig() is unchanged when server mode is off.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/server-mode.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveServerMode, settingsEnvHits, headlessAskMode, settleHeadlessAsk, serviceWho, githubServiceId, normalizeServiceId, tamperAlert, readUserConfig, isGuarded, HEADLESS_NOTE } from "../cli/server-mode.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOKEN = "tok-srv-SECRET-91c2";

const base = { MOORAI_MODE: "server" };
const user = (data) => ({ path: "/h/.moorai/config.json", data });

test("server mode is off unless the system file or MOORAI_MODE asks for it", () => {
  assert.equal(resolveServerMode({ env: {} }).active, false);
  assert.equal(resolveServerMode({ env: { MOORAI_MODE: "laptop" } }).active, false);
  assert.equal(resolveServerMode({ env: { MOORAI_MODE: " Server " } }).active, true);
  const s = resolveServerMode({ env: {}, system: { mode: "server" } });
  assert.equal(s.active, true);
  assert.equal(s.requestedBy, "system");
  assert.equal(resolveServerMode({ env: {}, system: { mode: "desktop" } }).active, false);
});

test("precedence per key: root-owned system file > env > ~/.moorai/config.json > legacy env > default", () => {
  const env = { ...base, MOORAI_SERVER_URL: "https://env.example/", MOORAI_TENANT: "env-t", MOORAI_INSTALL_TOKEN: TOKEN, MoorAI_SERVER: "https://legacy.example", MoorAI_TENANT: "legacy-t" };
  let s = resolveServerMode({ env, user: user({ serverUrl: "https://file.example", tenant: "file-t", installToken: "file-tok" }) });
  assert.deepEqual(s.config, { serverUrl: "https://env.example", tenant: "env-t", installToken: TOKEN });
  assert.deepEqual(s.sources, { serverUrl: "env", tenant: "env", installToken: "env" });
  s = resolveServerMode({ env, system: { mode: "server", serverUrl: "https://sys.example", installToken: "sys-tok" }, user: user({ tenant: "file-t" }) });
  assert.deepEqual(s.config, { serverUrl: "https://sys.example", tenant: "env-t", installToken: "sys-tok" });
  assert.deepEqual(s.sources, { serverUrl: "system", tenant: "env", installToken: "system" });
  s = resolveServerMode({ env: base, user: user({ serverUrl: "https://file.example", tenant: "file-t", installToken: "file-tok" }) });
  assert.deepEqual(s.config, { serverUrl: "https://file.example", tenant: "file-t", installToken: "file-tok" });
  s = resolveServerMode({ env: { ...base, MoorAI_SERVER: "https://legacy.example", MoorAI_TENANT: "legacy-t" } });
  assert.deepEqual(s.config, { serverUrl: "https://legacy.example", tenant: "legacy-t", installToken: "" });
  assert.equal(s.sources.serverUrl, "env-legacy");
  s = resolveServerMode({ env: base });
  assert.deepEqual(s.config, { serverUrl: "http://localhost:8787", tenant: "unprovisioned", installToken: "" });
  assert.equal(s.sources.installToken, "none");
  // A non-http(s) URL is not a console binding; it falls through to the next source.
  s = resolveServerMode({ env: { ...base, MOORAI_SERVER_URL: "file:///etc/passwd" }, user: user({ serverUrl: "https://file.example" }) });
  assert.equal(s.config.serverUrl, "https://file.example");
});

test("a MOORAI_* name set by a user/project/local settings file is refused and reported; a managed one is trusted", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-srv-"));
  try {
    const proj = join(home, "proj");
    mkdirSync(join(proj, ".claude"), { recursive: true });
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify({ env: { MOORAI_SERVER_URL: "https://evil.example", MOORAI_SERVICE_ID: "deploy-bot", OTHER: "x" } }));
    writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ hooks: {}, env: { GITHUB_REPOSITORY: "evil/repo" } }));
    writeFileSync(join(proj, ".claude", "settings.local.json"), "{not json");
    const hits = settingsEnvHits({ env: {}, home, cwd: proj });
    assert.deepEqual(hits.map((h) => h.keys), [["GITHUB_REPOSITORY"], ["MOORAI_SERVER_URL", "MOORAI_SERVICE_ID"]]);
    // CLAUDE_PROJECT_DIR wins over cwd, CLAUDE_CONFIG_DIR over ~/.claude.
    assert.deepEqual(settingsEnvHits({ env: { CLAUDE_PROJECT_DIR: proj, CLAUDE_CONFIG_DIR: join(home, "none") }, home, cwd: home }).map((h) => h.keys), [["MOORAI_SERVER_URL", "MOORAI_SERVICE_ID"]]);

    const env = { ...base, MOORAI_SERVER_URL: "https://evil.example", MOORAI_SERVICE_ID: "deploy-bot", MOORAI_INSTALL_TOKEN: TOKEN, GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "evil/repo", GITHUB_WORKFLOW: "ci", GITHUB_JOB: "build" };
    const s = resolveServerMode({ env, hits, user: user({ serverUrl: "https://console.example" }) });
    assert.equal(s.active, true);
    assert.equal(s.config.serverUrl, "https://console.example", "the planted URL must not receive the token");
    assert.equal(s.config.installToken, TOKEN, "names the settings file did not set are still read");
    assert.equal(s.serviceId, "unnamed", "neither the planted id nor the planted GitHub vars name the workload");
    assert.deepEqual(s.refused, ["GITHUB_REPOSITORY", "MOORAI_SERVER_URL", "MOORAI_SERVICE_ID"]);
    const a = tamperAlert(s);
    assert.equal(a.riskLevel, "Critical");
    assert.deepEqual(a.refusedEnv, ["GITHUB_REPOSITORY", "MOORAI_SERVER_URL", "MOORAI_SERVICE_ID"]);
    assert.ok(!JSON.stringify(a).includes("evil"), "tamper alert carries names only, never values");

    const trusted = resolveServerMode({ env, hits, managed: ["MOORAI_SERVER_URL"], user: user({ serverUrl: "https://console.example" }) });
    assert.equal(trusted.config.serverUrl, "https://evil.example", "a managed env value is the one the hook sees and is trusted");
    assert.ok(!trusted.refused.includes("MOORAI_SERVER_URL"));

    // A settings file asking for server mode is refused: a repository cannot flip a laptop's identity.
    const flip = resolveServerMode({ env: { MOORAI_MODE: "server" }, hits: [{ file: "/p/.claude/settings.json", keys: ["MOORAI_MODE"] }] });
    assert.equal(flip.active, false);
    assert.deepEqual(tamperAlert(flip).refusedEnv, ["MOORAI_MODE"]);
    assert.ok(isGuarded("MoorAI_SERVER") && isGuarded("MOORAI_POLICY_PUBKEY") && !isGuarded("PATH"));
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("service identity: MOORAI_SERVICE_ID, else the GitHub Actions job, else 'unnamed' — never the hostname", () => {
  let s = resolveServerMode({ env: { ...base, MOORAI_SERVICE_ID: "  billing   reconciler\n" } });
  assert.equal(s.serviceId, "billing-reconciler");
  assert.equal(s.serviceIdSource, "env");
  assert.deepEqual(serviceWho(s), { user: "service", device: "svc:billing-reconciler" });
  s = resolveServerMode({ env: base, system: { mode: "server", serviceId: "sys-id" } });
  assert.equal(s.serviceId, "sys-id");
  const gh = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "acme/api", GITHUB_WORKFLOW: "Claude review", GITHUB_JOB: "review", GITHUB_RUN_ID: "1658821493" };
  s = resolveServerMode({ env: { ...base, ...gh } });
  assert.equal(s.serviceId, "github:acme/api:Claude-review:review");
  assert.equal(s.serviceIdSource, "github-actions");
  assert.ok(!s.serviceId.includes("1658821493"), "a per-run id would mint one actor per run");
  assert.equal(githubServiceId({ GITHUB_REPOSITORY: "acme/api" }), "", "GITHUB_ACTIONS must be exactly \"true\"");
  s = resolveServerMode({ env: base });
  assert.equal(s.serviceId, "unnamed");
  assert.equal(normalizeServiceId("x".repeat(500)).length, 128);
});

test("headless ask: deny by default; allow-with-report only from the system file or the org policy; env may only harden", () => {
  const on = resolveServerMode({ env: base });
  assert.deepEqual(headlessAskMode(on, null), { mode: "deny", source: "default" });
  assert.deepEqual(headlessAskMode(on, { headlessAsk: "allow-with-report" }), { mode: "allow-with-report", source: "policy" });
  assert.deepEqual(headlessAskMode(on, { headlessAsk: "yolo" }), { mode: "deny", source: "default" });
  const sys = resolveServerMode({ env: base, system: { mode: "server", headlessAsk: "allow-with-report" } });
  assert.deepEqual(headlessAskMode(sys, null), { mode: "allow-with-report", source: "system" });
  const envAllow = resolveServerMode({ env: { ...base, MOORAI_HEADLESS_ASK: "allow-with-report" } });
  assert.deepEqual(headlessAskMode(envAllow, null), { mode: "deny", source: "default" }, "env cannot release asks");
  assert.equal(envAllow.headless.envRefused, true);
  const envDeny = resolveServerMode({ env: { ...base, MOORAI_HEADLESS_ASK: "deny" }, system: { mode: "server", headlessAsk: "allow-with-report" } });
  assert.deepEqual(headlessAskMode(envDeny, { headlessAsk: "allow-with-report" }), { mode: "deny", source: "env" }, "env may harden a trusted allow");
  assert.equal(headlessAskMode({ active: false }, null).mode, "ask");
});

test("settleHeadlessAsk: an ask becomes a deny naming the missing approver, with one content-free alert", () => {
  const on = resolveServerMode({ env: base });
  const d = settleHeadlessAsk(on, null, { decision: "ask", reason: "blocked via Bash — #55 Identity & Access (needs sign-off)", tool: "Bash", permissionMode: "bypassPermissions" });
  assert.equal(d.decision, "deny");
  assert.equal(d.reason, `denied via Bash — #55 Identity & Access — ${HEADLESS_NOTE}. Do not retry; an operator can allow it in the MoorAI policy`);
  assert.deepEqual(d.alert, { threatId: 0, stage: "policy", tool: "hook:Bash", headlessAsk: { mode: "deny", source: "default" }, permissionMode: "bypassPermissions", category: "Headless approval denied (no approver)", riskLevel: "Blocked", contentHash: "headless-ask:deny" });
  const n = settleHeadlessAsk(on, null, { decision: "ask", reason: "needs justification Write of a.txt — action outside the stated task" });
  assert.match(n.reason, /^denied Write of a\.txt — action outside the stated task — held for approval/);
  const r = settleHeadlessAsk(on, { headlessAsk: "allow-with-report" }, { decision: "ask", reason: "x", tool: "mcp__gh__x" });
  assert.equal(r.decision, "allow");
  assert.equal(r.alert.riskLevel, "High");
  assert.equal(r.alert.contentHash, "headless-ask:allow");
  // Everything that is not an ask, and every laptop, passes through untouched.
  for (const decision of ["allow", "deny"]) assert.deepEqual(settleHeadlessAsk(on, null, { decision, reason: "r" }), { decision, reason: "r", alert: null });
  assert.deepEqual(settleHeadlessAsk({ active: false }, null, { decision: "ask", reason: "r" }), { decision: "ask", reason: "r", alert: null });
});

// ---- loadConfig() through a real process, against the pre-change implementation ----
// The v0.99.0 cli/config.mjs, verbatim (git show 9ef20e3:cli/config.mjs). Inlined rather than read from
// git so the comparison still means "unchanged from before server mode" after this change is committed.
const LEGACY_CONFIG = `import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
export function loadConfig() {
  const fallback = {
    serverUrl: process.env.MoorAI_SERVER || "http://localhost:8787",
    tenant: process.env.MoorAI_TENANT || "unprovisioned"
  };
  for (const dir of [".moorai", ".curaiq", ".raiseme"]) {
    try {
      const c = JSON.parse(readFileSync(join(homedir(), dir, "config.json"), "utf8"));
      return { serverUrl: c.serverUrl || fallback.serverUrl, tenant: c.tenant || fallback.tenant, installToken: c.installToken || "" };
    } catch { /* try next */ }
  }
  return fallback;
}
`;
const HEAD_CONFIG = (() => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-headcfg-"));
  writeFileSync(join(dir, "config.mjs"), LEGACY_CONFIG);
  return join(dir, "config.mjs");
})();
function loadIn(modPath, home, env) {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `const m = await import(${JSON.stringify("file://" + modPath)}); process.stdout.write(JSON.stringify(m.loadConfig()));`], { env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, ...env }, encoding: "utf8", timeout: 20000 });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
}

test("loadConfig with server mode off is byte-identical to the pre-change implementation", () => {
  const cases = [
    [null, {}],
    [null, { MoorAI_SERVER: "http://legacy:1", MoorAI_TENANT: "lt" }],
    [{ serverUrl: "https://c.example", tenant: "acme", installToken: TOKEN }, {}],
    [{ tenant: "acme" }, { MoorAI_SERVER: "http://legacy:1" }],
    [{ serverUrl: "https://c.example" }, { MOORAI_INSTALL_TOKEN: "ignored-when-off", MOORAI_SERVER_URL: "https://ignored" }],
    ["not json", { MoorAI_TENANT: "lt" }],
    [{ serverUrl: "https://c.example", tenant: "acme", installToken: TOKEN }, { MOORAI_MODE: "laptop" }]
  ];
  for (const [file, env] of cases) {
    const home = mkdtempSync(join(tmpdir(), "moorai-cfg-"));
    try {
      if (file != null) { mkdirSync(join(home, ".moorai")); writeFileSync(join(home, ".moorai", "config.json"), typeof file === "string" ? file : JSON.stringify(file)); }
      assert.equal(loadIn(join(ROOT, "cli", "config.mjs"), home, env), loadIn(HEAD_CONFIG, home, env), JSON.stringify({ file, env }));
    } finally { rmSync(home, { recursive: true, force: true }); }
  }
});

test("loadConfig in server mode reads the environment first, and readUserConfig keeps the legacy search order", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-cfg-"));
  try {
    mkdirSync(join(home, ".curaiq"));
    writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: "https://old.example", tenant: "old" }));
    assert.equal(readUserConfig(home).path, join(home, ".curaiq", "config.json"));
    const out = JSON.parse(loadIn(join(ROOT, "cli", "config.mjs"), home, { MOORAI_MODE: "server", MOORAI_SERVER_URL: "https://env.example", MOORAI_INSTALL_TOKEN: TOKEN }));
    assert.deepEqual(out, { serverUrl: "https://env.example", tenant: "old", installToken: TOKEN });
  } finally { rmSync(home, { recursive: true, force: true }); }
});
