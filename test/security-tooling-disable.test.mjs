// Disabling defensive tooling through an AI coding agent: EDR and audit daemons (MITRE ATT&CK T1685), the
// host firewall (T1686) and macOS Gatekeeper's quarantine flag (T1553.001). data/security-tooling.js
// SECURITY_TOOLING_DISABLE, part of action-security-config (#46).
//
// THE GAP. #46 shipped ufw/firewalld/netsh, Defender and spctl, but stopping an EDR or audit daemon,
// flushing iptables/nft/pfctl, and removing the quarantine attribute fired nothing (ATT&CK v20 gap
// analysis, probes: falcon, auditd, iptables-flush, xattr all "-- none --").
//
//   node --test --import ./test/hermetic-env.mjs test/security-tooling-disable.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { SECURITY_TOOLING_DISABLE } from "../data/security-tooling.js";

const { DETECTORS } = DETECTOR_MODULE;
const DET = "action-security-config#46";

const POSITIVES = [
  "sudo systemctl stop auditd",
  "sudo systemctl disable --now falcon-sensor",
  "systemctl mask osqueryd.service",
  "sudo service auditd stop",
  "sudo launchctl bootout system/com.crowdstrike.falcon.Agent",
  "launchctl unload /Library/LaunchDaemons/com.sentinelone.sentineld.plist",
  "sc stop CSFalconService && sc stop mdatp",
  "Stop-Service -Name wdavdaemon -Force",
  "Add-MpPreference -ExclusionPath C:\\Users\\dev\\tools",
  "sudo iptables -F",
  "iptables --flush && ip6tables -F",
  "sudo nft flush ruleset",
  "sudo pfctl -d",
  "sudo pfctl -F all",
  "xattr -d com.apple.quarantine ./payload.app",
  "xattr -rd com.apple.quarantine /Applications/Tool.app",
  "xattr -cr ./downloaded-app.app"
];

const NEGATIVES = [
  "systemctl status auditd",
  "systemctl start falcon-sensor",
  "systemctl restart elastic-agent",
  "sudo service auditd status",
  "launchctl list",
  "sc query CSFalconService",
  "Get-Service wdavdaemon",
  "Get-MpPreference",
  "sudo iptables -L -n",
  "iptables -S",
  "nft list ruleset",
  "sudo pfctl -s rules",
  "xattr -l ./file",
  "xattr -p com.apple.quarantine ./file",
  "systemctl stop myapp",
  "systemctl stop falcon",
  "docker stop osquery-dev"
];

for (const cmd of POSITIVES) {
  test(`T1685/T1686/T1553.001 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: action-security-config holds the SECURITY_TOOLING_DISABLE pattern objects by reference", () => {
  const d = DETECTORS.find((x) => x.detectorId === "action-security-config");
  for (const rx of SECURITY_TOOLING_DISABLE) assert.ok(d.patterns.includes(rx), `missing ${rx}`);
});

test("ATT&CK: #46's T1685, T1686 and T1553.001 credits name the newly covered forms", () => {
  assert.match(credit(46, "T1685").reason, /EDR|daemon|auditd/i);
  assert.match(credit(46, "T1686").reason, /iptables|nft|pfctl/i);
  assert.match(credit(46, "T1553.001").reason, /quarantine|xattr/i);
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(SECURITY_TOOLING_DISABLE, [
    ["", "launchctl bootout auditd ", 2000],
    ["", "systemctl stop auditd ", 2700],
    ["", "service auditd stop ", 3000],
    ["", "sc stop auditd ", 3700],
    ["", "Add-MpPreference -ExclusionPath x ", 1600],
    ["", "iptables -F ", 5000],
    ["", "nft flush ruleset ", 3200],
    ["", "pfctl -d ", 6000],
    ["", "xattr -d com.apple.quarantine ", 1800],
    ["", "xattr -cr ", 6000]
  ]);
});

test("hook e2e: stopping an EDR daemon or flushing the firewall asks (no policy: #46 is justify); status is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "sudo systemctl stop auditd" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "sudo iptables -F" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "xattr -rd com.apple.quarantine /Applications/Tool.app" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "systemctl status auditd" }), "allow");
  });
});
