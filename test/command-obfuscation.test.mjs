// Command Obfuscation (MITRE ATT&CK T1027.010) through an AI coding agent: a base64/hex payload decoded
// straight into a shell, or a PowerShell -EncodedCommand. data/detectors.js obf-command-encoding (#50)
// flags the shape; cli/hook-core.mjs decodedCommandPayloads decodes it so the real payload meets the
// command detectors (reverse shell #54, cred access #55, …).
//
// THE GAP. `echo <b64> | base64 -d | sh` fired nothing (ATT&CK v20 gap analysis probe); the encoder hid
// the payload from a literal scan.
//
//   node --test --import ./test/hermetic-env.mjs test/command-obfuscation.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { decodedCommandPayloads } from "../cli/hook-core.mjs";

const { DETECTORS, OBFUSCATED_EXEC } = DETECTOR_MODULE;
const DET = "obf-command-encoding#50";
const b64 = (s) => Buffer.from(s).toString("base64");
const hex = (s) => Buffer.from(s).toString("hex");

// A DESTRUCTIVE payload (#43), deliberately: the engine's normalize pass already re-runs the injection and
// reverse-shell detectors over decoded base64, so those would be caught even without decodedCommandPayloads.
// destructive-command is NOT in that rescan set, so only the hook's decode-then-rescan catches it — which
// makes decodedCommandPayloads load-bearing and the mutation detectable.
const PAYLOAD = "rm -rf / --no-preserve-root";

const POSITIVES = [
  `echo ${b64("whoami")} | base64 -d | bash`,
  `echo ${b64("whoami")} | base64 --decode | sh`,
  `printf ${b64("id")} | base64 -D | zsh`,
  `base64 -d <<< ${b64("ls")} | sh`,
  `echo ${hex("id")} | xxd -r -p | sh`,
  `eval $(echo ${b64("ls")} | base64 -d)`,
  "powershell -enc aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=",
  "pwsh -EncodedCommand VwBoAG8AQQBtAEkAPQBpAGQA"
];

const NEGATIVES = [
  `echo ${b64("hello")} | base64 -d > out.bin`,
  `cat payload | base64 -d | tee decoded.txt`,
  "echo hello | base64",
  "openssl rand -base64 32",
  "base64 README.md",
  "git log --format='%H'",
  "curl -s https://example.com | jq .",
  "echo aGVsbG8= > note.txt",
  "xxd file.bin | head"
];

for (const cmd of POSITIVES) {
  test(`T1027.010 positive: ${DET} fires on ${JSON.stringify(cmd.slice(0, 48))}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1027.010 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("decode-then-rescan: a destructive payload hidden in base64 is recovered and trips #43", () => {
  const decoded = decodedCommandPayloads(`echo ${b64(PAYLOAD)} | base64 -d | bash`);
  assert.deepEqual(decoded, [PAYLOAD]);
  assert.ok(scan(PAYLOAD).some((x) => x.endsWith("#43")), scan(PAYLOAD).join(","));
});

test("decode-then-rescan: a non-shell decode (to a file) yields no payload", () => {
  assert.deepEqual(decodedCommandPayloads(`echo ${b64("whoami")} | base64 -d > out.bin`), []);
});

test("wiring: obf-command-encoding holds the OBFUSCATED_EXEC pattern objects by reference", () => {
  const d = DETECTORS.find((x) => x.detectorId === "obf-command-encoding");
  assert.equal(d.patterns, OBFUSCATED_EXEC);
});

test("ATT&CK: #50 credits T1027.010 as partial", () => {
  assert.equal(credit(50, "T1027.010")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(OBFUSCATED_EXEC, [
    ["", "echo QUJD | base64 -d | sh ", 1700],
    ["", "eval $(echo QUJD | base64 -d) ", 1700],
    ["", "powershell -enc QUJDREVGRw== ", 1800]
  ]);
});

test("hook e2e: a base64-decoded destructive command is caught on the DECODED payload (ask), not the encoder", () => {
  withHome((home) => {
    // #43 is justify; it is caught only because the hook decodes the payload and re-scans it.
    assert.equal(runHook(home, "Bash", { command: `echo ${b64(PAYLOAD)} | base64 -d | bash` }), "ask");
    // decoding to a file (not a shell) yields no payload, so nothing to re-scan.
    assert.equal(runHook(home, "Bash", { command: `echo ${b64("whoami")} | base64 -d > out.bin` }), "allow");
  });
});
