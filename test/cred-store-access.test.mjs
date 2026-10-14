// Harvesting credentials from where they live, through an AI coding agent: shell history (MITRE ATT&CK
// T1552.003), web-browser stores (T1555.003), application access-token files (T1528) and a full keychain
// dump (T1555.001). data/detectors.js cred-file-access (#55).
//
// THE GAP. #55 read .env, cloud creds, SSH keys and /etc/shadow, but gh/docker/azure/gcloud token stores,
// browser login/cookie stores, `security dump-keychain` and a secret-mining read of shell history fired
// nothing (ATT&CK v20 gap analysis, probes: dump, browser, history, imds among the "-- none --").
//
//   node --test --import ./test/hermetic-env.mjs test/cred-store-access.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { DETECTORS } from "../data/detectors.js";

const DET = "cred-file-access#55";

const POSITIVES = [
  "cat ~/.config/gh/hosts.yml",
  "cat ~/.azure/msal_token_cache.bin",
  "cat ~/.config/gcloud/access_tokens.db",
  "security dump-keychain -d login.keychain",
  "cp '~/Library/Application Support/Google/Chrome/Default/Login Data' /tmp/x",
  "sqlite3 ~/.config/BraveSoftware/Brave-Browser/Default/Cookies 'select * from cookies'",
  "cat ~/Library/Application\\ Support/Firefox/Profiles/ab12.default/key4.db",
  "strings ~/.mozilla/firefox/ab12.default/logins.json",
  "cp '~/Library/Application Support/Microsoft Edge/Default/Local State' .",
  "grep -i password ~/.bash_history",
  "grep -i -E 'aws_secret' ~/.zsh_history",
  "cat ~/.bash_history | grep -i token"
];

const NEGATIVES = [
  "cat ~/.bash_history",
  "grep deploy ~/.bash_history",
  "history | grep ssh",
  "cat ./chrome-notes.md",
  "echo 'Local State of the app is fine'",
  "security find-certificate -a",
  "cat ./Cookies.md",
  "cp ~/project/Login\\ Data.txt /tmp/",
  "cat ~/.config/myapp/settings.yml",
  "grep -i token ./app.log"
];

for (const cmd of POSITIVES) {
  test(`cred-store positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`cred-store negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("ATT&CK: #55 credits T1552.003, T1555.003 and T1528; T1555.001 now names dump-keychain", () => {
  assert.equal(credit(55, "T1552.003")?.coverage, "partial");
  assert.equal(credit(55, "T1555.003")?.coverage, "partial");
  assert.equal(credit(55, "T1528")?.coverage, "partial");
  assert.match(credit(55, "T1555.001").reason, /dump/i);
});

test("pattern cost: 60KB adversarial inputs scan in linear time for the new #55 patterns", () => {
  const d = DETECTORS.find((x) => x.detectorId === "cred-file-access");
  assertLinear(d.patterns, [
    ["", "cat a/Google/Chrome/Default/Login ", 1600],
    ["", "security dump-keychain ", 2700],
    ["", "grep -i password .bash_history ", 1800],
    ["", ".bash_history | grep secret ", 2000],
    ["", "cat ~/.config/gh/hosts.yml ", 2000]
  ]);
});

test("hook e2e: a browser store read, a keychain dump and a history-secret grep ask (no policy: #55 is justify)", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "security dump-keychain -d login.keychain" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "grep -i password ~/.zsh_history" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "cat ~/.config/gh/hosts.yml" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "cat ~/.bash_history" }), "allow");
  });
});
