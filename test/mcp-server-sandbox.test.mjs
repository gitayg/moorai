// mcpServerSandbox (mcp-proxy/sandbox-spawn.mjs): the stdio guard starts the real MCP server under a macOS
// Seatbelt network profile built from egressRules / egressDefault (cli/sandbox-policy.mjs) when the admin
// binding or the verified policy asks for it. Pure planning is tested here; the guard wiring and the real
// kernel check are in test/mcp-server-sandbox-guard.test.mjs.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-server-sandbox.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { sandboxPolicy } from "../cli/sandbox-policy.mjs";
import { REASON } from "../cli/provenance.mjs";
import {
  SERVER_SANDBOX_MODES, SANDBOX_EXEC, SERVER_SANDBOX_CATEGORY, SERVER_SANDBOX_UNEXPRESSED_CATEGORY,
  resolveServerSandbox, sandboxBackend, sandboxEgress, planServerSpawn, serverSandboxNotes, serverSandboxAlerts,
  serverSandboxPosture, refusedChild
} from "../mcp-proxy/sandbox-spawn.mjs";

const CMD = "npx";
const ARGS = ["-y", "@example/server", "--flag", "a b"];
const MAC = { platform: "darwin", exists: (p) => p === SANDBOX_EXEC };
const BLOCK = { mcpServerSandbox: "network", egressDefault: "block" };
const plan = (o) => planServerSpawn({ cmd: CMD, args: ARGS, ...MAC, failMode: "open", coach: false, warn: () => {}, ...o });

test("modes and default: no key anywhere is off", () => {
  assert.deepEqual([...SERVER_SANDBOX_MODES], ["off", "network"]);
  assert.deepEqual(resolveServerSandbox(null, { admin: null }), { mode: "off", source: "default" });
  assert.deepEqual(resolveServerSandbox({}, { admin: {} }), { mode: "off", source: "default" });
});

test("admin binding wins over the signed policy; an invalid value warns by key and falls through", () => {
  assert.deepEqual(resolveServerSandbox({ mcpServerSandbox: "network" }, { admin: { mcpServerSandbox: "off" } }), { mode: "off", source: "admin" });
  assert.deepEqual(resolveServerSandbox({ mcpServerSandbox: "off" }, { admin: { mcpServerSandbox: "network" } }), { mode: "network", source: "admin" });
  assert.deepEqual(resolveServerSandbox({ mcpServerSandbox: "network" }, { admin: null }), { mode: "network", source: "policy" });
  const warned = [];
  assert.deepEqual(resolveServerSandbox({ mcpServerSandbox: "network" }, { admin: { mcpServerSandbox: "NETWORK" }, warn: (m) => warned.push(m) }), { mode: "network", source: "policy" });
  assert.equal(warned.length, 1);
  assert.match(warned[0], /mcpServerSandbox in the admin binding/);
  assert.doesNotMatch(warned[0], /NETWORK/);
});

test("backend: Seatbelt on darwin with sandbox-exec present, nothing elsewhere", () => {
  assert.equal(sandboxBackend(MAC), "seatbelt");
  assert.equal(sandboxBackend({ platform: "darwin", exists: () => false }), null);
  assert.equal(sandboxBackend({ platform: "linux", exists: () => true }), null);
  assert.equal(sandboxBackend({ platform: "win32", exists: () => true }), null);
});

test("off: argv is exactly the real command, untouched", () => {
  for (const policy of [null, {}, { mcpServerSandbox: "off", egressDefault: "block" }]) {
    const p = plan({ policy });
    assert.equal(p.state, "off");
    assert.equal(p.cmd, CMD);
    assert.deepEqual(p.args, ARGS);
    assert.deepEqual(p.unexpressed, []);
  }
});

test("network on macOS: sandbox-exec -p <profile> <cmd> <args...>, the profile built by sandboxPolicy", () => {
  const p = plan({ policy: BLOCK });
  assert.equal(p.state, "sandboxed");
  assert.equal(p.cmd, SANDBOX_EXEC);
  assert.equal(p.args[0], "-p");
  assert.deepEqual(p.args.slice(2), [CMD, ...ARGS]);
  const want = sandboxPolicy({ egressDefault: "block" }, "seatbelt").policy;
  assert.ok(p.args[1].startsWith(`(version 1)\n(allow default)\n${want}`));
  assert.match(p.args[1], /^\(deny network-outbound\)$/m);
  assert.match(p.args[1], /\(allow network-outbound \(remote ip "localhost:\*"\)\)/);
  assert.equal(p.blocksNonLoopback, true);
});

// Measured on macOS 27.0 with sandbox-exec: without these, dns.lookup of a public name still resolves through
// mDNSResponder (a DNS exfil channel) and osascript / open reach other apps; with them a public lookup is
// ENOTFOUND, localhost still resolves, loopback still connects, and exec of open / osascript is EPERM.
const CONTAIN_LINES = [
  '(deny mach-lookup (global-name "com.apple.mDNSResponder") (global-name "com.apple.mDNSResponderHelper") (global-name "com.apple.nsurlsessiond") (global-name "com.apple.coreservices.launchservicesd") (global-name "com.apple.lsd.mapdb") (global-name "com.apple.lsd.open"))',
  "(deny appleevent-send)",
  '(deny network-outbound (literal "/private/var/run/mDNSResponder"))',
  '(deny process-exec (literal "/usr/bin/open") (literal "/usr/bin/osascript"))'
];

test("egressDefault block: DNS, daemon IPC, AppleEvents and exec of open / osascript are denied too", () => {
  const p = plan({ policy: BLOCK });
  const lines = p.args[1].split("\n");
  for (const l of CONTAIN_LINES) assert.ok(lines.includes(l), `profile has ${l}`);
  // After the generated section: the mDNSResponder socket deny must come after the unix-socket allow
  // (between filtered rules the last match wins).
  assert.ok(lines.indexOf(CONTAIN_LINES[2]) > lines.indexOf("(allow network-outbound (remote unix-socket))"));
  assert.match(p.args[1], /^\(version 1\)\n\(allow default\)\n/);
  const notes = serverSandboxNotes(p, "srv").join("\n");
  assert.match(notes, /own network connections and DNS/);
  assert.match(notes, /not full containment/);
  assert.match(notes, /file and process access are not restricted/);
  assert.match(notes, /EXPERIMENTAL/);
  assert.match(notes, /LaunchAgent or cron job, edit MCP-client or MoorAI config, or run launchctl/);
  assert.match(notes, /runs later outside the sandbox/);
});

test("egressDefault not block: none of the containment lines (the server keeps DNS and app hand-off)", () => {
  const p = plan({ policy: { mcpServerSandbox: "network" } });
  for (const l of CONTAIN_LINES) assert.equal(p.args[1].includes(l), false, `no ${l}`);
});

test("network without egressDefault block: sandboxed, but it blocks no non-loopback host (and says so)", () => {
  const p = plan({ policy: { mcpServerSandbox: "network" } });
  assert.equal(p.state, "sandboxed");
  assert.equal(p.blocksNonLoopback, false);
  assert.doesNotMatch(p.args[1], /\(deny network-outbound\)/);
  assert.ok(serverSandboxNotes(p, "srv").some((l) => /restricts no non-loopback host/.test(l)));
});

test("rules come from the policy then the admin binding; default from the policy, else the admin binding", () => {
  const eg = sandboxEgress({ egressRules: [{ host: "a.example", action: "allow" }] }, { egressRules: [{ host: "localhost", port: 5432, action: "block" }], egressDefault: "block" });
  assert.deepEqual(eg.egressRules.map((r) => r.host), ["a.example", "localhost"]);
  assert.equal(eg.egressDefault, "block");
  assert.deepEqual(eg.origin, [{ source: "policy", index: 0 }, { source: "admin", index: 0 }]);
  assert.equal(sandboxEgress({ egressDefault: "allow" }, { egressDefault: "block" }).egressDefault, "allow");
  const p = plan({ policy: { mcpServerSandbox: "network" }, admin: { egressRules: [{ host: "localhost", port: 5432, action: "block" }], egressDefault: "block" } });
  assert.match(p.args[1], /\(deny network-outbound \(remote ip "localhost:5432"\)\)/);
  assert.match(p.args[1], /^\(deny network-outbound\)$/m);
});

test("unexpressed rules are reported with their source and index, never silently widened", () => {
  const policy = { ...BLOCK, egressRules: [{ id: "gh", host: "api.github.com", action: "allow" }] };
  const admin = { egressRules: [{ host: "*.corp.example", action: "allow" }] };
  const p = plan({ policy, admin });
  assert.equal(p.state, "sandboxed");
  assert.deepEqual(p.unexpressed.map((u) => [u.source, u.index, u.effect, u.reason]), [["policy", 0, "omitted", "seatbelt-host"], ["admin", 0, "omitted", "seatbelt-host"]]);
  assert.equal(p.unexpressed[0].id, "gh");
  // The profile still denies them: an omitted allow under default-block stays denied.
  assert.doesNotMatch(p.args[1], /github|corp/);
  assert.match(p.args[1], /^\(deny network-outbound\)$/m);
  const notes = serverSandboxNotes(p, "srv");
  assert.equal(notes.filter((l) => /not expressed/.test(l)).length, 2);
  const alerts = serverSandboxAlerts(p, { server: "srv", failModeSource: "default" });
  const ux = alerts.find((a) => a.category === SERVER_SANDBOX_UNEXPRESSED_CATEGORY);
  assert.ok(ux, "an alert lists the unexpressed rules");
  assert.equal(ux.unexpressedCount, 2);
  assert.deepEqual(ux.unexpressed.map((u) => u.reason), ["seatbelt-host", "seatbelt-host"]);
  assert.equal(JSON.stringify(ux).includes("github"), false, "content-free: no host names");
});

test("unsupported platform, fail mode open: runs unsandboxed, argv unchanged, one High alert and a stderr line", () => {
  for (const env of [{ platform: "linux", exists: () => true }, { platform: "win32", exists: () => true }, { platform: "darwin", exists: () => false }]) {
    const p = plan({ policy: BLOCK, ...env });
    assert.equal(p.state, "unavailable");
    assert.equal(p.cmd, CMD);
    assert.deepEqual(p.args, ARGS);
    assert.equal(p.why, env.platform === "darwin" ? "no-sandbox-exec" : "platform");
    const alerts = serverSandboxAlerts(p, { server: "srv", failModeSource: "default" });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].category, SERVER_SANDBOX_CATEGORY);
    assert.equal(alerts[0].riskLevel, "High");
    assert.equal(alerts[0].reasonCode, REASON.CONTAINMENT_UNAVAILABLE);
    assert.equal(alerts[0].failMode, "open");
    assert.equal(alerts[0].mcpServer, "srv");
    assert.ok(serverSandboxNotes(p, "srv").some((l) => /UNSANDBOXED/.test(l)));
  }
});

test("unsupported platform, fail mode closed: refused, nothing to spawn, a Blocked deny alert", () => {
  const p = plan({ policy: BLOCK, platform: "linux", failMode: "closed" });
  assert.equal(p.state, "refused");
  assert.equal(p.cmd, null);
  assert.equal(p.args, null);
  const [a] = serverSandboxAlerts(p, { server: "srv", failModeSource: "policy" });
  assert.equal(a.riskLevel, "Blocked");
  assert.equal(a.decision, "deny");
  assert.equal(a.failMode, "closed");
  assert.equal(a.failModeSource, "policy");
  assert.equal(a.reasonCode, REASON.CONTAINMENT_UNAVAILABLE);
  assert.ok(serverSandboxNotes(p, "srv").some((l) => /not started/.test(l)));
});

test("coach mode never refuses: closed but coaching runs unsandboxed with the alert", () => {
  const p = plan({ policy: BLOCK, platform: "linux", failMode: "closed", coach: true });
  assert.equal(p.state, "unavailable");
  assert.equal(p.cmd, CMD);
});

test("off on an unsupported platform is still off: no alert, no note", () => {
  const p = plan({ policy: { egressDefault: "block" }, platform: "linux", failMode: "closed" });
  assert.equal(p.state, "off");
  assert.deepEqual(serverSandboxAlerts(p, { server: "srv" }), []);
  assert.deepEqual(serverSandboxNotes(p, "srv"), []);
});

test("posture: on / unavailable / off from static prerequisites", () => {
  assert.deepEqual(serverSandboxPosture(BLOCK, { admin: null, ...MAC }), { mode: "network", state: "on" });
  assert.deepEqual(serverSandboxPosture(BLOCK, { admin: null, platform: "linux", exists: () => true }), { mode: "network", state: "unavailable" });
  assert.deepEqual(serverSandboxPosture({}, { admin: null, ...MAC }), { mode: "off", state: "off" });
});

test("refusedChild: a stand-in that ends with code 1 and swallows writes", async () => {
  const c = refusedChild();
  c.stdin.write("{}\n");
  const [code] = await new Promise((r) => c.on("exit", (...a) => r(a)));
  assert.equal(code, 1);
  await new Promise((r) => c.on("close", r));
  assert.doesNotThrow(() => c.kill("SIGTERM"));
});
