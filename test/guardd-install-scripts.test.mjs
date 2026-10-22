// Install path for moorai-guardd, the privileged helper (docs/proposals/guardd-contract.md §4.3, §11.3):
// the Linux systemd units, the macOS LaunchDaemon plist and pkg scripts, the Windows service script.
// Every installer is exercised in STAGE mode (MOORAI_GUARDD_STAGE=<temp dir>): the files are laid out
// under a temp root, no service manager is called and nothing is chowned. Nothing here installs anything
// on the machine running the tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, statSync, existsSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const PKG = join(REPO, "guardd", "packaging");
const IS_WIN = process.platform === "win32";

function fakeBinary(dir, testInjection = false) {
  const p = join(dir, "moorai-guardd");
  writeFileSync(p, `#!/bin/sh\n[ "$1" = "--build-info" ] && echo "moorai-guardd 0.1.0 test-injection=${testInjection}"\nexit 0\n`);
  chmodSync(p, 0o755);
  return p;
}
function runInstaller(script, args, env = {}) {
  return spawnSync("sh", [script, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
}
const mode = (p) => statSync(p).mode & 0o7777;
const unitKeys = (text) => {
  const out = {};
  for (const line of text.split("\n")) {
    const m = /^([A-Za-z]+)=(.*)$/.exec(line.trim());
    if (m) (out[m[1]] ||= []).push(m[2]);
  }
  return out;
};

// ---------------- Linux ----------------
test("linux: the socket unit matches contract §3.1 (path, 0666 socket, root-owned 0755 directory)", () => {
  const k = unitKeys(readFileSync(join(PKG, "linux", "moorai-guardd.socket"), "utf8"));
  assert.deepEqual(k.ListenStream, ["/run/moorai/hook.sock"]);
  assert.deepEqual(k.SocketMode, ["0666"]);
  assert.deepEqual(k.SocketUser, ["root"]);
  assert.deepEqual(k.SocketGroup, ["root"]);
  assert.deepEqual(k.DirectoryMode, ["0755"]);
  assert.deepEqual(k.Accept, ["no"]);
  assert.deepEqual(k.WantedBy, ["sockets.target"]);
});

test("linux: the service unit runs as root under the contract §4.3 hardening, with no arguments", () => {
  const text = readFileSync(join(PKG, "linux", "moorai-guardd.service"), "utf8");
  const k = unitKeys(text);
  assert.equal(k.User, undefined, "no User= (root)");
  assert.equal(k.DynamicUser, undefined);
  assert.deepEqual(k.ExecStart, ["/usr/sbin/moorai-guardd"], "the helper takes no arguments (§10.2)");
  for (const [key, want] of [["ProtectSystem", "strict"], ["ProtectHome", "read-only"], ["NoNewPrivileges", "yes"],
    ["PrivateTmp", "yes"], ["StateDirectory", "moorai"], ["StateDirectoryMode", "0700"], ["RuntimeDirectory", "moorai"],
    ["RuntimeDirectoryMode", "0755"], ["RuntimeDirectoryPreserve", "yes"], ["Restart", "always"], ["UMask", "0077"]]) {
    assert.deepEqual(k[key], [want], key);
  }
  assert.ok(k.Requires?.[0].includes("moorai-guardd.socket"));
  assert.deepEqual(k.WantedBy, ["multi-user.target"]);
  // The helper rewrites secret.json after a bound registration (§4.1), so /etc/moorai must stay writable
  // under ProtectSystem=strict. Nothing else is opened up.
  assert.deepEqual(k.ReadWritePaths, ["-/etc/moorai"]);
  // A bounded capability set; never the full root set and never CAP_SYS_ADMIN.
  const caps = (k.CapabilityBoundingSet || [""])[0].split(/\s+/).filter(Boolean);
  assert.ok(caps.length > 0 && caps.length <= 6, `bounded set: ${caps}`);
  assert.ok(!caps.includes("CAP_SYS_ADMIN"));
  assert.equal(k.Environment, undefined, "no environment can steer the helper (§10.2)");
});

test("linux: install.sh refuses to run unprivileged without a stage root", { skip: IS_WIN || process.getuid?.() === 0 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  try {
    const r = runInstaller(join(PKG, "linux", "install.sh"), [fakeBinary(dir)], { MOORAI_GUARDD_STAGE: "" });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /as root/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("linux: install.sh stage mode lays out the binary and both units with the contract modes", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  const stage = join(dir, "root");
  try {
    const r = runInstaller(join(PKG, "linux", "install.sh"), [fakeBinary(dir)], { MOORAI_GUARDD_STAGE: stage });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(mode(join(stage, "usr/sbin/moorai-guardd")), 0o755);
    for (const u of ["moorai-guardd.service", "moorai-guardd.socket"]) {
      const p = join(stage, "usr/lib/systemd/system", u);
      assert.equal(mode(p), 0o644, u);
      assert.equal(readFileSync(p, "utf8"), readFileSync(join(PKG, "linux", u), "utf8"), `${u} copied verbatim`);
    }
    assert.equal(mode(join(stage, "etc/moorai")), 0o755);
    // Stage mode names the service-manager steps it skipped, so a reviewer sees the real-install plan.
    assert.match(r.stdout, /plan: systemctl daemon-reload/);
    assert.match(r.stdout, /plan: systemctl enable --now moorai-guardd\.socket moorai-guardd\.service/);
    // It never writes secret.json or config.json: those are MDM's (§4.1).
    assert.equal(existsSync(join(stage, "etc/moorai/secret.json")), false);
    assert.equal(existsSync(join(stage, "etc/moorai/config.json")), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("linux: install.sh refuses a binary built with test-injection (§10.2, §11.2)", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  try {
    const r = runInstaller(join(PKG, "linux", "install.sh"), [fakeBinary(dir, true)], { MOORAI_GUARDD_STAGE: join(dir, "root") });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /test-injection/);
    assert.equal(existsSync(join(dir, "root/usr/sbin/moorai-guardd")), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("linux: install.sh refuses a relative or missing binary path", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  try {
    const rel = runInstaller(join(PKG, "linux", "install.sh"), ["moorai-guardd"], { MOORAI_GUARDD_STAGE: join(dir, "root") });
    assert.notEqual(rel.status, 0);
    const missing = runInstaller(join(PKG, "linux", "install.sh"), [join(dir, "nope")], { MOORAI_GUARDD_STAGE: join(dir, "root") });
    assert.notEqual(missing.status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("linux: uninstall.sh stage mode removes the binary and units and keeps admin inputs", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  const stage = join(dir, "root");
  try {
    assert.equal(runInstaller(join(PKG, "linux", "install.sh"), [fakeBinary(dir)], { MOORAI_GUARDD_STAGE: stage }).status, 0);
    writeFileSync(join(stage, "etc/moorai/config.json"), "{}");
    const r = runInstaller(join(PKG, "linux", "uninstall.sh"), [], { MOORAI_GUARDD_STAGE: stage });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(existsSync(join(stage, "usr/sbin/moorai-guardd")), false);
    assert.equal(existsSync(join(stage, "usr/lib/systemd/system/moorai-guardd.service")), false);
    assert.equal(existsSync(join(stage, "usr/lib/systemd/system/moorai-guardd.socket")), false);
    assert.equal(existsSync(join(stage, "etc/moorai/config.json")), true, "admin inputs are not the uninstaller's");
    assert.match(r.stdout, /plan: systemctl disable --now moorai-guardd\.service moorai-guardd\.socket/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------- macOS ----------------
const PLIST = join(PKG, "macos", "run.glick.moorai.guardd.plist");
test("macos: the LaunchDaemon plist matches contract §4.3 (root, KeepAlive, RunAtLoad, no arguments)", () => {
  const t = readFileSync(PLIST, "utf8");
  const val = (key) => new RegExp(`<key>${key}</key>\\s*(<true/>|<false/>|<(\\w+)>[^<]*</\\2>)`).exec(t)?.[1];
  assert.equal(val("Label"), "<string>run.glick.moorai.guardd</string>");
  assert.equal(val("KeepAlive"), "<true/>");
  assert.equal(val("RunAtLoad"), "<true/>");
  assert.equal(val("StandardErrorPath"), "<string>/Library/Logs/MoorAI/guardd.log</string>");
  assert.ok(!/<key>UserName<\/key>/.test(t), "root: UserName unset");
  assert.ok(!/<key>EnvironmentVariables<\/key>/.test(t), "no environment can steer the helper (§10.2)");
  const args = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(t)[1].match(/<string>[^<]*<\/string>/g);
  assert.deepEqual(args, ["<string>/Library/PrivilegedHelperTools/moorai-guardd</string>"]);
});

test("macos: the plist lints clean with plutil", { skip: process.platform !== "darwin" }, () => {
  const r = spawnSync("/usr/bin/plutil", ["-lint", PLIST], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test("macos: install.sh stage mode lays out the helper, the plist and the log directory", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  const stage = join(dir, "root");
  try {
    const r = runInstaller(join(PKG, "macos", "install.sh"), [fakeBinary(dir)], { MOORAI_GUARDD_STAGE: stage });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(mode(join(stage, "Library/PrivilegedHelperTools/moorai-guardd")), 0o755);
    const pl = join(stage, "Library/LaunchDaemons/run.glick.moorai.guardd.plist");
    assert.equal(mode(pl), 0o644);
    assert.equal(readFileSync(pl, "utf8"), readFileSync(PLIST, "utf8"));
    assert.equal(mode(join(stage, "Library/Logs/MoorAI")), 0o750);
    assert.equal(mode(join(stage, "private/etc/moorai")), 0o755);
    assert.match(r.stdout, /plan: launchctl bootstrap system \/Library\/LaunchDaemons\/run\.glick\.moorai\.guardd\.plist/);
    assert.match(r.stdout, /plan: launchctl kickstart -k system\/run\.glick\.moorai\.guardd/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("macos: install.sh refuses a test-injection binary and an unprivileged real install", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-inst-"));
  try {
    const ti = runInstaller(join(PKG, "macos", "install.sh"), [fakeBinary(dir, true)], { MOORAI_GUARDD_STAGE: join(dir, "root") });
    assert.notEqual(ti.status, 0);
    assert.match(ti.stderr, /test-injection/);
    if (process.getuid?.() !== 0) {
      const r = runInstaller(join(PKG, "macos", "install.sh"), [fakeBinary(dir)], { MOORAI_GUARDD_STAGE: "" });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /as root/);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("macos: pkg scripts boot the daemon out before an upgrade and bootstrap it after", () => {
  const pre = readFileSync(join(PKG, "macos", "scripts", "preinstall"), "utf8");
  const post = readFileSync(join(PKG, "macos", "scripts", "postinstall"), "utf8");
  assert.match(pre, /launchctl bootout system\/run\.glick\.moorai\.guardd/);
  assert.match(post, /launchctl bootstrap system/);
  assert.match(post, /chown root:wheel/);
  assert.match(post, /chmod 0644 .*run\.glick\.moorai\.guardd\.plist/);
  for (const s of ["preinstall", "postinstall", "build-pkg.sh"]) {
    const p = join(PKG, "macos", s === "build-pkg.sh" ? s : join("scripts", s));
    assert.ok(mode(p) & 0o100, `${s} is executable`);
  }
});

test("macos: build-pkg.sh builds a pkg whose payload is the staged layout", { skip: process.platform !== "darwin" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guardd-pkg-"));
  try {
    const out = join(dir, "moorai-guardd.pkg");
    const r = spawnSync("sh", [join(PKG, "macos", "build-pkg.sh"), fakeBinary(dir), out, "0.1.0"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const files = spawnSync("/usr/sbin/pkgutil", ["--payload-files", out], { encoding: "utf8" }).stdout.split("\n");
    assert.ok(files.includes("./Library/PrivilegedHelperTools/moorai-guardd"), files.join(","));
    assert.ok(files.includes("./Library/LaunchDaemons/run.glick.moorai.guardd.plist"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------- Windows ----------------
const PS1 = join(PKG, "windows", "install.ps1");
// Service access rights in SDDL that let a principal stop, reconfigure or re-permission the service.
const DANGEROUS = ["WP", "DC", "WD", "WO", "SD", "GA", "GW"];
function aces(sddl) {
  return [...sddl.matchAll(/\(A;;([A-Z]+);;;([A-Z]{2}|S-[0-9-]+)\)/g)].map((m) => ({ rights: m[1].match(/../g), sid: m[2] }));
}

test("windows: install.ps1 registers MoorAIGuard as an auto-start LocalSystem service with restart recovery", () => {
  const t = readFileSync(PS1, "utf8");
  assert.match(t, /\$ServiceName\s*=\s*'MoorAIGuard'/);
  assert.match(t, /start=\s*auto/);
  assert.match(t, /obj=\s*LocalSystem/);
  assert.match(t, /'moorai-guardd\.exe'/);
  // §4.3: restart three times, then every 60 s (sc repeats the last action).
  assert.match(t, /actions=\s*restart\/\d+\/restart\/\d+\/restart\/60000/);
  assert.match(t, /failureflag/);
  assert.match(t, /--build-info/);
  assert.match(t, /test-injection=false/);
});

test("windows: the service DACL lets only SYSTEM and Administrators stop or reconfigure it", () => {
  const t = readFileSync(PS1, "utf8");
  const sddl = /\$ServiceSddl\s*=\s*'([^']+)'/.exec(t)?.[1];
  assert.ok(sddl && sddl.startsWith("D:"), "an explicit DACL");
  const list = aces(sddl);
  assert.ok(list.length >= 3);
  for (const a of list) {
    const bad = a.rights.filter((r) => DANGEROUS.includes(r));
    if (a.sid === "SY" || a.sid === "BA") continue;
    assert.deepEqual(bad, [], `${a.sid} must not hold ${bad}`);
    assert.ok(!a.rights.includes("RP") || a.sid === "SY" || a.sid === "BA", `${a.sid} must not start it`);
  }
  const ba = list.find((a) => a.sid === "BA");
  assert.ok(ba && ["WP", "DC", "WD"].every((r) => ba.rights.includes(r)), "Administrators keep full control");
  const sy = list.find((a) => a.sid === "SY");
  assert.ok(sy && sy.rights.includes("WP") && sy.rights.includes("RP"));
  assert.ok(list.some((a) => a.sid === "AU" && a.rights.includes("LC")), "any signed-in user can query state");
  assert.match(t, /sdset/);
});

test("windows: install.ps1 resolves ProgramData from HKLM ProfileList, never %ProgramData%", () => {
  const t = readFileSync(PS1, "utf8");
  assert.match(t, /SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList/);
  assert.ok(!/\$env:ProgramData/i.test(t));
  assert.ok(!/\$env:ProgramFiles/i.test(t));
  assert.match(t, /\[switch\]\$DryRun/);
});

test("the guardd-install CI contract paths exist (one script per OS)", () => {
  for (const p of ["linux/install.sh", "macos/install.sh", "windows/install.ps1"]) assert.ok(existsSync(join(PKG, p)), p);
});
