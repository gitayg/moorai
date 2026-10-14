// Inhibit System Recovery (MITRE ATT&CK T1490) issued through an AI coding agent's shell
// (data/detectors.js, INHIBIT_RECOVERY, part of destructive-command #43).
//
// THE GAP. destructive-command matched rm -rf, DROP TABLE, force-push and disk formats, but the commands
// that remove a machine's way back — shadow-copy deletion, a boot configuration that skips recovery, a
// deleted backup catalog, deleted Time Machine or file-system snapshots, deleted cloud snapshots and
// recovery points — fired nothing (ATT&CK v20 gap analysis, probe: `vssadmin delete shadows` and
// `tmutil deletelocalsnapshots` both "-- none --").
//
// Stage: "prompt", like the rest of #43 — the Bash hook scans the command text there (cli/moorai-hook.mjs,
// `decideText(engine, policy, ti.command, "prompt")`). The listing, creating, enabling and growing forms of
// the same tools are the hard negatives: they are what an agent runs while doing ordinary backup work.
//
//   node --test --import ./test/hermetic-env.mjs test/inhibit-recovery.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as DETECTOR_MODULE from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { scalingRatio } from "./timing.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { DETECTORS, INHIBIT_RECOVERY } = DETECTOR_MODULE;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
const scan = (text, stage = "prompt") => engine.scan(text, stage).map((f) => `${f.detectorId}#${f.threat.id}`);
const DET = "destructive-command#43";

const POSITIVES = [
  // Windows Volume Shadow Copy: delete, or shrink the store until Windows drops the copies
  "vssadmin delete shadows /all /quiet",
  "vssadmin.exe Delete Shadows /All /Quiet",
  "cmd.exe /c vssadmin delete shadows /for=C: /oldest",
  "C:\\Windows\\System32\\vssadmin.exe delete shadows /shadow={c1a2b3c4-0000-0000-0000-000000000000}",
  "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB",
  "vssadmin Resize ShadowStorage /For=D: /On=D: /MaxSize=320 MB",
  "wmic shadowcopy delete",
  "wmic.exe shadowcopy where \"ID='{c1a2b3c4}'\" delete",
  "wmic /node:localhost shadowcopy delete /nointeractive",
  "Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }",
  "gwmi win32_shadowcopy | % {$_.Delete()}",
  "Get-CimInstance -ClassName Win32_ShadowCopy | Remove-CimInstance",
  "powershell -c \"Get-CimInstance Win32_ShadowCopy | Remove-CimInstance -Confirm:$false\"",
  // Windows boot configuration: no recovery environment, ignore boot failures; Windows RE off
  "bcdedit /set {default} recoveryenabled No",
  "bcdedit.exe /set {current} recoveryenabled no",
  "bcdedit /set recoveryenabled off",
  "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
  "bcdedit.exe /set {default} bootstatuspolicy IgnoreAllFailures",
  "reagentc /disable",
  "reagentc.exe /Disable",
  // Windows Server Backup: the catalog, the backups, the scheduled backup
  "wbadmin delete catalog -quiet",
  "wbadmin DELETE SYSTEMSTATEBACKUP -keepVersions:0",
  "wbadmin delete backup -keepVersions:0 -quiet",
  "wbadmin.exe delete systemstatebackup -deleteoldest",
  "wbadmin disable backup -quiet",
  // macOS: Time Machine local snapshots and backups, APFS snapshots
  "tmutil deletelocalsnapshots /",
  "sudo tmutil deletelocalsnapshots 2026-10-01-120000",
  "for s in $(tmutil listlocalsnapshotdates / | tail -n +2); do tmutil deletelocalsnapshots $s; done",
  "sudo tmutil delete -d /Volumes/Backup -t 2026-10-01-120000",
  "sudo tmutil delete /Volumes/TM/Backups.backupdb/mac/2026-10-01-120000",
  "sudo tmutil disable",
  "tmutil disablelocal",
  "/usr/bin/tmutil deletelocalsnapshots /System/Volumes/Data",
  "diskutil apfs deleteSnapshot / -uuid 1C2D3E4F-0000-0000-0000-000000000000",
  "diskutil apfs deletesnapshot disk3s5 -name com.apple.TimeMachine.2026-10-01-120000.local",
  // Linux and hypervisor snapshots
  "zfs destroy tank/home@daily-2026-10-01",
  "sudo zfs destroy -r tank@autosnap_2026-10-01",
  "zfs destroy rpool/ROOT/ubuntu@%",
  "sudo timeshift --delete-all --yes",
  "vim-cmd vmsvc/snapshot.removeall 12",
  // Cloud snapshots, recovery points and backup vaults
  "aws ec2 delete-snapshot --snapshot-id snap-0123456789abcdef0",
  "aws rds delete-db-snapshot --db-snapshot-identifier prod-nightly",
  "aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier prod-nightly",
  "aws backup delete-recovery-point --backup-vault-name Default --recovery-point-arn arn:aws:ec2:us-east-1::snapshot/snap-0123",
  "aws backup delete-backup-vault --backup-vault-name prod-vault",
  "gcloud compute snapshots delete prod-disk-snap --quiet",
  "az snapshot delete --resource-group prod --name osdisk-snap",
  "az backup protection disable --container-name vm1 --item-name vm1 --vault-name v --resource-group rg --delete-backup-data true --yes"
];

const NEGATIVES = [
  // the same tools doing ordinary backup work
  "vssadmin list shadows",
  "vssadmin list shadowstorage",
  "vssadmin create shadow /for=C:",
  "vssadmin resize shadowstorage /for=C: /on=D: /maxsize=UNBOUNDED",
  "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=20%",
  "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=50GB",
  "wmic shadowcopy list brief",
  "wmic shadowcopy call create Volume=C:\\",
  "Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate",
  "Get-CimInstance Win32_ShadowCopy | Measure-Object",
  "bcdedit /enum all",
  "bcdedit /set {current} recoveryenabled yes",
  "bcdedit /set {default} bootstatuspolicy displayallfailures",
  "bcdedit /timeout 10",
  "reagentc /info",
  "reagentc /enable",
  "wbadmin get versions",
  "wbadmin start backup -backupTarget:E: -include:C: -quiet",
  "wbadmin enable backup -addtarget:E: -schedule:21:00",
  "wbadmin get items -version:10/01/2026-21:00",
  "tmutil listlocalsnapshots /",
  "tmutil localsnapshot",
  "tmutil status",
  "tmutil enable",
  "tmutil listbackups",
  "tmutil startbackup --auto",
  "tmutil addexclusion ./node_modules",
  "man tmutil",
  "diskutil apfs listSnapshots /",
  "zfs list -t snapshot",
  "zfs snapshot tank/home@before-upgrade",
  "zfs rollback tank/home@before-upgrade",
  "timeshift --list",
  "timeshift --create --comments before-upgrade",
  "vim-cmd vmsvc/snapshot.get 12",
  "vim-cmd vmsvc/snapshot.create 12 pre-patch",
  "aws ec2 describe-snapshots --owner-ids self",
  "aws ec2 create-snapshot --volume-id vol-0123456789abcdef0",
  "aws rds create-db-snapshot --db-instance-identifier prod --db-snapshot-identifier prod-manual",
  "aws backup list-recovery-points-by-backup-vault --backup-vault-name Default",
  "aws backup start-backup-job --backup-vault-name Default --resource-arn arn:aws:ec2:x --iam-role-arn arn:aws:iam::1:role/b",
  "gcloud compute snapshots list",
  "az snapshot create --resource-group prod --name osdisk-snap --source osdisk",
  "az backup protection disable --container-name vm1 --item-name vm1 --vault-name v --resource-group rg --yes",
  // the names in paths, package names and other words
  "cat docs/tmutil-deletelocalsnapshots.md",
  "npm install vssadmin-wrapper",
  "ls ./scripts/wbadmin_delete_catalog_test/",
  "git checkout feature/zfs-destroy-guard"
];

test("baseline: destructive-command (#43) still fires on the forms it had", () => {
  for (const cmd of ["rm -rf /tmp/x", "DROP TABLE users;", "mkfs.ext4 /dev/sdb1"]) assert.ok(scan(cmd).includes(DET), cmd);
});

for (const cmd of POSITIVES) {
  test(`T1490 positive: destructive-command fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}

for (const cmd of NEGATIVES) {
  test(`T1490 negative: destructive-command stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: destructive-command holds the INHIBIT_RECOVERY pattern objects by reference", () => {
  assert.ok(Array.isArray(INHIBIT_RECOVERY) && INHIBIT_RECOVERY.length > 0, "INHIBIT_RECOVERY is exported");
  const d = DETECTORS.find((x) => x.detectorId === "destructive-command");
  for (const rx of INHIBIT_RECOVERY) assert.ok(d.patterns.includes(rx), `missing ${rx}`);
});

test("ATT&CK: #43 credits T1490 as partial, with the bound in the reason", () => {
  const c = threats.threats.find((t) => t.id === 43).attack.find((x) => x.id === "T1490");
  assert.ok(c, "#43 has a T1490 credit");
  assert.equal(c.coverage, "partial");
  assert.match(c.reason, /shadow/);
});

// [prefix, repeated unit, repeat count at ~60 KB]
const COST_INPUTS = [
  ["", "vssadmin ", 6700],
  ["", "vssadmin resize shadowstorage /maxsize= ", 1500],
  ["", "wmic shadowcopy where x ", 2500],
  ["", "Win32_ShadowCopy | ", 3200],
  ["", "bcdedit /set {default} ", 2600],
  ["", "tmutil delete ", 4300],
  ["", "zfs destroy a ", 4300],
  ["", "aws backup ", 5500],
  ["", "az backup protection disable ", 2000]
];
const costInput = ([pre, unit, n], k = 1) => pre + unit.repeat(n * k);

// A ReDoS is a complexity change: 4x the input may cost at most 10x (linear reads ~4x, quadratic ~16x).
// Each pattern is timed on its own: the detector stops at its first matching pattern, so timing the
// whole list would never reach a slow pattern that sits behind one that matches the same input.
test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  for (const rx of INHIBIT_RECOVERY) {
    for (const c of COST_INPUTS) {
      const s = costInput(c), big = costInput(c, 4);
      const r = scalingRatio(() => rx.test(s), () => rx.test(big), 3, 10);
      assert.ok(r.ratio < 10, `${rx} on ${JSON.stringify(c[1])}: 4x the input cost ${r.ratio.toFixed(2)}x`);
    }
  }
});

// End to end through the real PreToolUse Bash and PowerShell branches, no org policy: #43 is justify by
// default (data/human-approval.js), so the hook asks.
function runHook(home, tool_name, command) {
  const res = spawnSync("node", [join(ROOT, "cli", "moorai-hook.mjs")], {
    input: JSON.stringify({ session_id: "t1490", tool_name, tool_input: { command } }),
    cwd: home,
    encoding: "utf8",
    timeout: 30000,
    env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "t1490" }
  });
  assert.equal(res.status, 0, res.stderr);
  const out = (res.stdout || "").trim();
  if (!out) return "allow";
  return JSON.parse(out).hookSpecificOutput?.permissionDecision || "allow";
}

test("hook e2e: recovery-inhibiting commands ask before they run; their listing forms are allowed", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-t1490-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "t1490", installToken: "tok-t1490" }));
    assert.equal(runHook(home, "Bash", "tmutil deletelocalsnapshots /"), "ask");
    assert.equal(runHook(home, "Bash", "aws ec2 delete-snapshot --snapshot-id snap-0123456789abcdef0"), "ask");
    assert.equal(runHook(home, "PowerShell", "vssadmin delete shadows /all /quiet"), "ask");
    assert.equal(runHook(home, "Bash", "tmutil listlocalsnapshots /"), "allow");
    assert.equal(runHook(home, "PowerShell", "vssadmin list shadows"), "allow");
  } finally { rmTree(home); }
});
