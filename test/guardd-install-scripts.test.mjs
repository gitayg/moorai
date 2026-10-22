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

// Contract §4.1/§4.2 DACLs on <PD>\MoorAI, as SDDL constants install.ps1 applies as the WHOLE DACL.
const ACL_PS1 = join(PKG, "windows", "acl-checks.ps1");
// install.ps1 without comments (the <# #> header and # lines), so an order or absence check reads code only.
const psCode = (t) => t.replace(/<#[\s\S]*?#>/g, "").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
const sddlVar = (t, name) => new RegExp(`\\$${name}\\s*=\\s*'([^']+)'`).exec(t)?.[1];
const RIGHTS = { FA: 0x1f01ff, FR: 0x120089 };
const ACE_FLAGS = ["OI", "CI", "NP", "IO", "ID"];
function parseDacl(sddl) {
  const m = /^D:([A-Z]*)((?:\([^)]*\))*)$/.exec(sddl || "");
  assert.ok(m, `a DACL-only SDDL: ${sddl}`);
  const aces = [...m[2].matchAll(/\(([^)]*)\)/g)].map((x) => {
    const [type, flags, rights, , , sid] = x[1].split(";");
    const mask = RIGHTS[rights] ?? (/^0x[0-9a-f]+$/i.test(rights) ? parseInt(rights, 16) : NaN);
    return { type, flags: flags.match(/../g) || [], mask, sid };
  });
  for (const a of aces) {
    assert.ok(Number.isInteger(a.mask), `numeric or known rights in ${sddl}`);
    for (const f of a.flags) assert.ok(ACE_FLAGS.includes(f), `known ACE flag ${f}`);
  }
  return { protected: m[1].includes("P"), aces };
}
// Any right that adds, changes, deletes or re-permissions (same set as acl-checks.ps1 $WriteMask).
const WRITE_BITS = [0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000];
const writes = (mask) => WRITE_BITS.some((b) => (mask & b) !== 0);
const inherits = (a) => a.flags.includes("OI") || a.flags.includes("CI");

test("windows: <PD>\\MoorAI grants Users read on the folder itself only, never inherited by state, secret or any later file", () => {
  const t = readFileSync(PS1, "utf8");
  const d = parseDacl(sddlVar(t, "DataDirSddl"));
  assert.ok(d.protected, "protected: ProgramData's Users create rights are not inherited");
  const by = Object.fromEntries(d.aces.map((a) => [a.sid, a]));
  assert.deepEqual(Object.keys(by).sort(), ["BA", "BU", "SY"]);
  for (const s of ["SY", "BA"]) assert.deepEqual([by[s].type, by[s].mask, by[s].flags.sort()], ["A", 0x1f01ff, ["CI", "OI"]], s);
  assert.equal(by.BU.type, "A");
  assert.deepEqual(by.BU.flags, [], "Users read applies to the folder itself, no OI/CI");
  assert.ok(!writes(by.BU.mask), "Users read only");
  // No icacls call hands Users (or anyone) an inheritable grant on the data directory.
  assert.ok(!/& \$Icacls \$DataDir\b/.test(psCode(t)), "the data-dir DACL is not set with icacls");
});

test("windows: state is SYSTEM-only and protected, run is SYSTEM/Administrators full + Users read, secret.json SYSTEM/Administrators only", () => {
  const t = readFileSync(PS1, "utf8");
  const st = parseDacl(sddlVar(t, "StateDirSddl"));
  assert.ok(st.protected);
  assert.deepEqual(st.aces.map((a) => [a.type, a.sid, a.mask, a.flags.sort().join("")]), [["A", "SY", 0x1f01ff, "CIOI"]]);
  const run = parseDacl(sddlVar(t, "RunDirSddl"));
  assert.ok(run.protected);
  assert.deepEqual(Object.fromEntries(run.aces.map((a) => [a.sid, [a.mask, a.flags.sort().join("")]])),
    { SY: [0x1f01ff, "CIOI"], BA: [0x1f01ff, "CIOI"], BU: [0x120089, "CIOI"] });
  const sec = parseDacl(sddlVar(t, "SecretSddl"));
  assert.ok(sec.protected);
  assert.deepEqual(sec.aces.map((a) => [a.sid, a.mask]).sort(), [["BA", 0x1f01ff], ["SY", 0x1f01ff]]);
  assert.match(t, /\$StateDir\s*=\s*Join-Path \$DataDir 'state'/);
  assert.match(t, /\$RunDir\s*=\s*Join-Path \$DataDir 'run'/);
  assert.match(t, /\$SecretPath\s*=\s*Join-Path \$DataDir 'secret\.json'/);
});

test("windows: every MoorAI data DACL replaces the whole DACL (never icacls /grant:r, which keeps other entries) and owner is SYSTEM", () => {
  const t = readFileSync(PS1, "utf8");
  const c = psCode(t);
  for (const v of ["DataDir", "StateDir", "RunDir", "SecretPath"]) {
    assert.ok(!new RegExp(`\\$Icacls \\$${v}\\b[^\\n]*/grant:r`).test(c), `${v}: no /grant:r`);
    const sddl = v === "SecretPath" ? "SecretSddl" : `${v}Sddl`;
    assert.match(c, new RegExp(`Set-ExactDacl \\$${v} \\$${sddl}\\b`), `${v} gets the whole ${sddl}`);
    assert.match(c, new RegExp(`Invoke-Icacls \\$${v} /setowner '\\*S-1-5-18'`), `${v}: owner SYSTEM`);
  }
  for (const v of ["StateDir", "RunDir"]) assert.match(c, new RegExp(`Invoke-Icacls \\$${v} /setowner '\\*S-1-5-18' /T`), `${v}: owner SYSTEM below too`);
  const body = /function Set-ExactDacl[\s\S]*?\n}\n/.exec(c)?.[0] || "";
  assert.match(body, /SetAccessControl/);
  assert.match(body, /ReparsePoint/);
  const nso = /function New-SecurityObject[\s\S]*?\n}\n/.exec(c)?.[0] || "";
  assert.match(nso, /SetSecurityDescriptorSddlForm\(\$Sddl, \[System\.Security\.AccessControl\.AccessControlSections\]::Access\)/);
  // A missing directory is created with its DACL in place, never with New-Item (which inherits
  // ProgramData's Users create rights until the DACL lands).
  for (const v of ["DataDir", "StateDir", "RunDir"]) {
    assert.match(c, new RegExp(`New-DirWithDacl \\$${v} \\$${v}Sddl`), v);
    assert.ok(!new RegExp(`New-Item[^\\n]*-Path \\$${v}\\b`).test(c), `${v}: no New-Item`);
  }
});

test("windows: install.ps1 refuses a pre-existing data tree that is a reparse point, not admin-owned or writable by others, before changing anything", () => {
  const t = readFileSync(PS1, "utf8");
  const c = psCode(t);
  const fn = /function Assert-NotSquatted[\s\S]*?\n}\n/.exec(c)?.[0] || "";
  assert.match(fn, /if \(Test-IsReparsePoint \$i\) \{ [^}]*reparse point[^}]*\} else \{ Get-SquatProblem/, "every entry is checked for a reparse point");
  assert.match(fn, /Get-SquatProblem \(Get-LiveSddl \$i\.FullName\)/, "every entry's owner and DACL is checked");
  assert.match(fn, /Get-ChildItem -LiteralPath \$Path -Recurse -Force/, "everything below, hidden entries included");
  assert.ok(!/FollowSymlink/.test(c), "never follows a junction or symbolic link");
  assert.match(fn, /throw/);
  assert.match(c, /function Test-IsReparsePoint[\s\S]*?\[System\.IO\.FileAttributes\]::ReparsePoint/);
  // The first check runs before anything changes: the service, the binary and every ACL.
  const first = c.indexOf("Assert-NotSquatted $DataDir");
  assert.ok(first > 0);
  for (const later of ["$Sc stop", "Copy-Item", "New-DirWithDacl $DataDir", "Set-ExactDacl $DataDir", "Reset-ChildAcls $DataDir"]) {
    assert.ok(c.indexOf(later) > first, `${later} after the first check`);
  }
  // And again after creating the directory (another user could have created it first), before its DACL.
  const step = c.slice(c.indexOf("New-DirWithDacl $DataDir"));
  assert.ok(step.indexOf("Assert-NotSquatted $DataDir") >= 0 && step.indexOf("Assert-NotSquatted $DataDir") < step.indexOf("Set-ExactDacl $DataDir"));
  assert.match(t, /^\. \(Join-Path \$PSScriptRoot 'acl-checks\.ps1'\)$/m);
});

test("windows: acl-checks.ps1 Get-SquatProblem refuses any owner but SYSTEM/Administrators and any write-type right for anyone else", () => {
  const a = psCode(readFileSync(ACL_PS1, "utf8"));
  assert.match(a, /\$script:AdminSids = @\('S-1-5-18', 'S-1-5-32-544'\)/);
  const expr = /\$script:WriteMask = ([^\n]+)/.exec(a)?.[1] || "";
  const mask = expr.split("-bor").map((x) => parseInt(x.trim(), 16)).reduce((x, y) => x | y, 0);
  for (const b of WRITE_BITS) assert.ok(mask & b, `WriteMask has 0x${b.toString(16)}`);
  for (const r of [0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000]) assert.equal(mask & r, 0, `read-type 0x${r.toString(16)} is not a write`);
  const fn = /function Get-SquatProblem[\s\S]*?\n}\n/.exec(a)?.[0] || "";
  assert.match(fn, /\$script:AdminSids -notcontains \$sd\.Owner\.Value/, "owner check");
  assert.match(fn, /Get-NullDaclProblem/, "a NULL DACL is refused");
  assert.match(fn, /\$ace\.AccessMask -band \$script:WriteMask/, "write rights for a non-admin principal");
  assert.ok(!/InheritOnly/.test(fn), "inherit-only ACEs are not skipped");
});

test("windows: install.ps1 resets every ACL under <PD>\\MoorAI, then sets state's protected DACL, and checks the result", () => {
  const c = psCode(readFileSync(PS1, "utf8"));
  const fn = /function Reset-ChildAcls[\s\S]*?\n}\n/.exec(c)?.[0] || "";
  assert.match(fn, /Invoke-Icacls \(Join-Path \$Path '\*'\) \/reset \/T/);
  assert.ok(!/\/C\b/.test(fn), "a failure stops the install (no /C)");
  const reset = c.indexOf("Reset-ChildAcls $DataDir");
  assert.ok(reset > 0 && reset < c.indexOf("Set-ExactDacl $StateDir"), "the data-dir reset would otherwise undo state's DACL");
  assert.ok(reset < c.indexOf("Set-ExactDacl $RunDir") && reset < c.indexOf("Set-ExactDacl $SecretPath"));
  for (const v of ["StateDir", "RunDir"]) assert.match(c, new RegExp(`Reset-ChildAcls \\$${v}`));
  for (const v of ["DataDir", "StateDir", "RunDir"]) assert.match(c, new RegExp(`\\$${v} = \\$${v}Sddl`), `${v} verified`);
  assert.match(c, /Get-DaclMismatch \(Get-LiveSddl \$d\) \$want\[\$d\] 'S-1-5-18'/);
  assert.match(c, /Get-DaclMismatch \(Get-LiveSddl \$SecretPath\) \$SecretSddl 'S-1-5-18'/);
  assert.match(c, /Get-AccessProblem \(Get-LiveSddl \$i\.FullName\) @\('S-1-5-18'\)/, "every state entry SYSTEM only");
  // The secret's prior exposure is read before anything changes, and reported.
  const pre = c.indexOf("$SecretWasExposed = Get-AccessProblem (Get-LiveSddl $SecretPath) $script:AdminSids");
  assert.ok(pre > 0 && pre < c.indexOf("$Sc stop"));
  assert.match(c, /if \(\$SecretWasExposed\) \{\s*Write-Warning/);
});

test("windows: Users read goes to the public admin inputs one file at a time, never to secret.json", () => {
  const t = readFileSync(PS1, "utf8");
  const list = /\$PublicInputs = @\(([^)]*)\)/.exec(t)?.[1] || "";
  const names = [...list.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  assert.ok(names.includes("config.json"));
  assert.ok(!names.some((n) => /secret|state|run|device/.test(n)), names.join(","));
  const c = psCode(t);
  assert.match(c, /Invoke-Icacls \$p \/grant '\*S-1-5-32-545:\(R\)'/);
  const usersGrants = [...c.matchAll(/'\*S-1-5-32-545:([^']*)'/g)].map((m) => m[1]);
  assert.deepEqual(usersGrants.filter((g) => /\(OI\)|\(CI\)/.test(g)), ["(OI)(CI)RX"], "the only inherited Users grant is on Program Files\\MoorAI (the binary)");
});

// Runs the checks themselves; .NET's security-descriptor types exist on Windows only.
const PWSH = IS_WIN ? ["pwsh", "powershell"].find((x) => spawnSync(x, ["-NoProfile", "-Command", "1"], { encoding: "utf8" }).status === 0) : null;
test("windows: acl-checks.ps1 verdicts on real descriptors (squatted, hardened, extra ACE, unprotected)", { skip: !PWSH && "needs PowerShell on Windows" }, () => {
  const cases = {
    hardenedByMdm: ["Get-SquatProblem", "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"],
    userOwned: ["Get-SquatProblem", "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)"],
    programDataDefault: ["Get-SquatProblem", "O:BAD:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)"],
    everyoneFull: ["Get-SquatProblem", "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)"],
    nullDacl: ["Get-SquatProblem", "O:SYD:NO_ACCESS_CONTROL"],
  };
  const lines = Object.entries(cases).map(([k, [fn, s]]) => `$r['${k}'] = [string](${fn} '${s}')`);
  lines.push("$r['secretUsersRead'] = [string](Get-AccessProblem 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)' @('S-1-5-18','S-1-5-32-544'))");
  lines.push("$r['secretOk'] = [string](Get-AccessProblem 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)' @('S-1-5-18','S-1-5-32-544'))");
  lines.push("$r['exact'] = [string](Get-DaclMismatch 'O:SYG:SYD:PAI(A;OICI;FA;;;SY)' 'D:P(A;OICI;FA;;;SY)' 'S-1-5-18')");
  lines.push("$r['extra'] = [string](Get-DaclMismatch 'O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BU)' 'D:P(A;OICI;FA;;;SY)' 'S-1-5-18')");
  lines.push("$r['unprotected'] = [string](Get-DaclMismatch 'O:SYD:(A;OICI;FA;;;SY)' 'D:P(A;OICI;FA;;;SY)' 'S-1-5-18')");
  lines.push("$r['adminOwner'] = [string](Get-DaclMismatch 'O:BAD:P(A;OICI;FA;;;SY)' 'D:P(A;OICI;FA;;;SY)' 'S-1-5-18')");
  const script = `$ErrorActionPreference='Stop'; . '${ACL_PS1.replace(/'/g, "''")}'; $r=[ordered]@{}; ${lines.join("; ")}; $r | ConvertTo-Json -Compress`;
  const r = spawnSync(PWSH, ["-NoProfile", "-Command", script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const v = JSON.parse(r.stdout.trim());
  assert.equal(v.hardenedByMdm, "");
  for (const k of ["userOwned", "programDataDefault", "everyoneFull", "nullDacl", "secretUsersRead", "extra", "unprotected", "adminOwner"]) assert.notEqual(v[k], "", k);
  assert.equal(v.secretOk, "");
  assert.equal(v.exact, "");
});

test("the guardd-install CI contract paths exist (one script per OS)", () => {
  for (const p of ["linux/install.sh", "macos/install.sh", "windows/install.ps1"]) assert.ok(existsSync(join(PKG, p)), p);
});
