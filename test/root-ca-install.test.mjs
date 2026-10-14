// Adversary-in-the-Middle (MITRE ATT&CK T1557) and Install Root Certificate (T1553.004) through an AI
// coding agent: the transit check wired into the hook (#67) and root-CA installs in the agent's shell
// (data/detectors.js ROOT_CA_INSTALL, part of action-security-config #46).
//
// THE GAP. decideTransit (cli/hook-core.mjs) was built and unit-tested but no shipped hook called it, so an
// agent launched with HTTPS_PROXY plus NODE_EXTRA_CA_CERTS, or a command that starts one that way, was not
// reported; and a command that adds a certificate to a trust store fired nothing (ATT&CK v20 gap analysis).
//
//   node --test --import ./test/hermetic-env.mjs test/root-ca-install.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DETECTOR_MODULE, ROOT, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { transitEnvText, decideTransit } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const { DETECTORS, ROOT_CA_INSTALL } = DETECTOR_MODULE;
const DET = "action-security-config#46";

const POSITIVES = [
  "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain proxy-ca.pem",
  "security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ca.crt",
  "certutil -addstore -f Root C:\\temp\\ca.cer",
  "certutil.exe -addstore \"Root\" ca.cer",
  "certutil -enterprise -addstore AuthRoot ca.cer",
  "Import-Certificate -FilePath .\\ca.cer -CertStoreLocation Cert:\\LocalMachine\\Root",
  "Import-Certificate -FilePath ca.cer -CertStoreLocation Cert:\\CurrentUser\\Root",
  "sudo cp mitm-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates",
  "sudo cp ca.pem /usr/local/share/ca-certificates/corp.crt",
  "sudo install -m 644 ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust",
  "cat ca.pem | sudo tee /usr/local/share/ca-certificates/ca.crt",
  "echo \"$CERT\" > /etc/pki/ca-trust/source/anchors/x.pem",
  "sudo trust anchor ./ca.crt",
  "keytool -importcert -noprompt -alias corp -file ca.crt -cacerts -storepass changeit",
  "keytool -import -alias corp -file ca.crt -keystore $JAVA_HOME/lib/security/cacerts"
];

const NEGATIVES = [
  "security find-certificate -a -c Corp",
  "security verify-cert -c server.pem",
  "security dump-trust-settings",
  "certutil -viewstore root",
  "certutil -store Root",
  "certutil -addstore My client.pfx",
  "Get-ChildItem Cert:\\LocalMachine\\Root",
  "Import-Certificate -FilePath client.cer -CertStoreLocation Cert:\\CurrentUser\\My",
  "sudo update-ca-certificates",
  "sudo apt-get install -y ca-certificates && update-ca-certificates",
  "ls /usr/local/share/ca-certificates/",
  "cat /usr/local/share/ca-certificates/corp.crt",
  "cp /usr/local/share/ca-certificates/corp.crt ./backup/",
  "trust list --filter=ca-anchors",
  "trust anchor --remove ./old-ca.crt",
  "keytool -list -cacerts -storepass changeit",
  "keytool -importcert -alias app -file app.crt -keystore ./app.jks",
  "cat docs/security-add-trusted-cert.md",
  "openssl x509 -in ca.crt -noout -text"
];

for (const cmd of POSITIVES) {
  test(`T1553.004 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1553.004 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: action-security-config holds the ROOT_CA_INSTALL pattern objects by reference", () => {
  assert.ok(Array.isArray(ROOT_CA_INSTALL) && ROOT_CA_INSTALL.length > 0);
  const d = DETECTORS.find((x) => x.detectorId === "action-security-config");
  for (const rx of ROOT_CA_INSTALL) assert.ok(d.patterns.includes(rx), `missing ${rx}`);
});

test("ATT&CK: #46 credits T1553.004; #67 credits T1557 and T1553.004 as partial now that the hook calls decideTransit", () => {
  assert.equal(credit(46, "T1553.004")?.coverage, "partial");
  assert.equal(credit(67, "T1557")?.coverage, "partial");
  assert.equal(credit(67, "T1553.004")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(ROOT_CA_INSTALL, [
    ["", "security ", 6700],
    ["", "certutil -addstore ", 3200],
    ["", "Import-Certificate Cert:\\ ", 2400],
    ["", "cp a ", 12000],
    ["cp ", "a /usr/local/share/ca-certificates/b ", 1600],
    ["", "> /etc/pki ", 5500],
    ["", "trust anchor ", 4600],
    ["", "keytool -import ", 3700]
  ]);
});

test("transitEnvText: proxy URLs and CA variable names only; a CA path never reaches the text", () => {
  const t = transitEnvText({ HTTPS_PROXY: "http://127.0.0.1:8080", NODE_EXTRA_CA_CERTS: "/home/me/secret-dir/evil.crt", PATH: "/usr/bin", HOME: "/home/me" });
  assert.equal(t, "HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS=set");
  assert.equal(transitEnvText({ PATH: "/usr/bin" }), "");
  assert.equal(transitEnvText({ SSL_CERT_FILE: "C:\\Program Files\\corp ca\\ca.pem" }), "SSL_CERT_FILE=set");
  const d = decideTransit({}, t);
  assert.deepEqual([d.proxies, d.caVars, d.decision], [["127.0.0.1"], ["NODE_EXTRA_CA_CERTS"], "allow"]);
});

// ---- end to end through the real hook ----

test("hook e2e: a root-CA install asks before it runs (no policy: #46 is justify); a listing is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem" }), "ask");
    assert.equal(runHook(home, "PowerShell", { command: "certutil -addstore -f Root C:\\temp\\ca.cer" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "security find-certificate -a -c Corp" }), "allow");
  });
});

test("hook e2e: a command that starts a program behind an unsanctioned proxy is denied when policy.transitAllow is set, reported otherwise", () => {
  const cmd = "HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS=/tmp/x.crt node app.js";
  withHome((home) => assert.equal(runHook(home, "Bash", { command: cmd }), "allow"));
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: cmd }), "deny");
    assert.equal(runHook(home, "Bash", { command: "HTTPS_PROXY=http://proxy.corp.example:3128 node app.js" }), "allow");
    assert.equal(runHook(home, "Bash", { command: "node app.js" }), "allow");
  }, { transitAllow: ["proxy.corp.example"] });
});

test("hook e2e: an agent launched behind an unsanctioned proxy has every tool call denied when policy.transitAllow is set", () => {
  const env = { HTTPS_PROXY: "http://127.0.0.1:8080", NODE_EXTRA_CA_CERTS: "/tmp/x.crt" };
  withHome((home) => assert.equal(runHook(home, "Bash", { command: "ls" }, env), "allow"));
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "ls" }, env), "deny");
    assert.equal(runHook(home, "Read", { file_path: join(home, "x.txt") }, env), "deny");
    assert.equal(runHook(home, "Bash", { command: "ls" }, { HTTPS_PROXY: "http://proxy.corp.example:3128" }), "allow");
    assert.equal(runHook(home, "Bash", { command: "ls" }), "allow");
  }, { transitAllow: ["proxy.corp.example"] });
});

// The report half: the agent's environment override reaches the console as a #67 alert, once per session,
// with no CA path and no proxy credential in it.
test("hook e2e: the agent-environment override is reported as #67 once per session, content-free", async () => {
  const alerts = [];
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => { b += c; });
    req.on("end", () => { if (req.method === "POST") { try { alerts.push(JSON.parse(b)); } catch { /* not json */ } } res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const home = mkdtempSync(join(tmpdir(), "moorai-transit-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", installToken: "tok-transit" }));
    writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free" }));
    const call = () => new Promise((resolve) => {
      const child = spawn(process.execPath, [join(ROOT, "cli", "moorai-hook.mjs")], { cwd: home, env: { ...process.env, HOME: home, USERPROFILE: home, HTTPS_PROXY: "http://user:hunter2@127.0.0.1:8080", NODE_EXTRA_CA_CERTS: "/home/me/secret-dir/evil.crt", NO_PROXY: "127.0.0.1,localhost" } });
      child.stdout.on("data", () => {}); child.stderr.on("data", () => {});
      child.stdin.end(JSON.stringify({ session_id: "transit-once", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }));
      child.on("exit", resolve);
    });
    await call(); await call();
    const t67 = alerts.filter((a) => a.threatId === 67 && !String(a.category).startsWith("Literacy:"));
    assert.equal(t67.length, 1, `expected one #67 alert, got ${t67.length}: ${JSON.stringify(alerts.map((a) => [a.threatId, a.category]))}`);
    const s = JSON.stringify(t67[0]);
    for (const leak of ["hunter2", "secret-dir", "evil.crt"]) assert.ok(!s.includes(leak), `leaked ${leak}`);
  } finally { server.close(); rmTree(home); }
});
