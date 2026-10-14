// Sudo and Sudo Caching (MITRE ATT&CK T1548.003) through an AI coding agent: granting passwordless or
// broader sudo by editing the sudoers policy. data/detectors.js SUDOERS_WRITE, part of
// action-security-config (#46).
//
// THE GAP. #46 matched `add … sudoers`, but the common forms — `… | sudo tee -a /etc/sudoers`, a write
// into /etc/sudoers.d/, `visudo -f`, a written NOPASSWD rule — fired nothing (ATT&CK v20 gap analysis,
// probe: the `tee -a` form "-- none --").
//
//   node --test --import ./test/hermetic-env.mjs test/sudoers-write.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { SUDOERS_WRITE } from "../data/detectors.js";

const { DETECTORS } = DETECTOR_MODULE;
const DET = "action-security-config#46";

const POSITIVES = [
  "echo 'deploy ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
  "echo 'deploy ALL=(ALL) NOPASSWD: ALL' | sudo tee -a /etc/sudoers",
  "echo '%wheel ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/wheel",
  "cat > /etc/sudoers.d/90-deploy <<EOF",
  "printf '%s\\n' \"$RULE\" >> /etc/sudoers.d/custom",
  "sudo visudo -f /etc/sudoers.d/deploy",
  "tee -a /etc/sudoers",
  "sudo tee -a /etc/sudoers < rule.txt",
  "echo \"user ALL=(ALL:ALL) NOPASSWD:/usr/bin/apt\" >> /etc/sudoers.d/apt"
];

const NEGATIVES = [
  "sudo cat /etc/sudoers",
  "cat /etc/sudoers.d/README",
  "grep NOPASSWD /etc/sudoers",
  "sudo grep -r NOPASSWD /etc/sudoers.d/",
  "visudo -c",
  "sudo visudo -c -f /etc/sudoers.d/deploy",
  "ls -la /etc/sudoers.d/",
  "sudo -l",
  "sudo apt-get update",
  "diff /etc/sudoers /etc/sudoers.bak"
];

for (const cmd of POSITIVES) {
  test(`T1548.003 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1548.003 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: action-security-config holds the SUDOERS_WRITE pattern objects by reference", () => {
  const d = DETECTORS.find((x) => x.detectorId === "action-security-config");
  for (const rx of SUDOERS_WRITE) assert.ok(d.patterns.includes(rx), `missing ${rx}`);
});

test("ATT&CK: #46 credits T1548.003 as partial", () => {
  assert.equal(credit(46, "T1548.003")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(SUDOERS_WRITE, [
    ["", ">> /etc/sudoers ", 3200],
    ["", "tee /etc/sudoers ", 3000],
    ["", "visudo -f ", 4600],
    ["", "echo NOPASSWD: ", 3700]
  ]);
});

test("hook e2e: a sudoers write asks (no policy: #46 is justify); reading or validating is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "echo 'deploy ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "sudo visudo -f /etc/sudoers.d/deploy" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "sudo cat /etc/sudoers" }), "allow");
    assert.equal(runHook(home, "Bash", { command: "visudo -c" }), "allow");
  });
});
