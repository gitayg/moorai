// The MDM deploy scripts write the admin binding (trust-anchor design phase 1A) to the machine config, and
// that file is readable by every local account (/etc/moorai/config.json 0644; %ProgramData%\MoorAI\
// config.json with Users read). So it must never carry the install token: serverUrl and tenant only. The
// token stays in the enrolled user's own 0600 file.
//
//   node --test --import ./test/hermetic-env.mjs test/mdm-machine-config.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const JAMF = readFileSync(join(ROOT, "packaging", "mdm", "jamf", "moorai-jamf-deploy.sh"), "utf8");
const INTUNE = readFileSync(join(ROOT, "packaging", "mdm", "intune", "Install-MoorAI.ps1"), "utf8");

// From `name() {` to the closing `}` alone on a line that is followed by a blank line or a comment (a
// heredoc's JSON `}` is followed by its terminator, so it does not end the function).
function shellFunction(src, name) {
  const start = src.indexOf(`${name}() {`);
  assert.ok(start >= 0, `${name} not found`);
  const m = /\n}\n(?=\n|#|[a-z_]+\(\) \{)/g;
  m.lastIndex = start;
  const end = m.exec(src);
  assert.ok(end, `end of ${name} not found`);
  return src.slice(start, end.index + 3);
}
function psFunction(src, name) {
  const start = src.indexOf(`function ${name} {`);
  assert.ok(start >= 0, `${name} not found`);
  const end = src.indexOf("\n}\n", start);
  return src.slice(start, end + 3);
}

test("Jamf (static): the machine-config writer sets serverUrl and tenant, removes any installToken, and never writes one", () => {
  const fn = shellFunction(JAMF, "write_machine_config");
  assert.match(fn, /json_set "\$tmp" serverUrl "\$SERVER_URL"/);
  assert.match(fn, /json_set "\$tmp" tenant "\$TENANT"/);
  assert.match(fn, /plutil -remove installToken "\$tmp"/);
  assert.doesNotMatch(fn, /INSTALL_TOKEN/, "the token variable never reaches the machine config");
  assert.match(fn, /chown root:wheel "\$tmp" && \/bin\/chmod 0644 "\$tmp"/);
});

test("Jamf (run, macOS): against a scratch anchor directory, an existing installToken is removed, other keys kept, and the token is not written", { skip: process.platform !== "darwin" && "plutil is macOS-only" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-jamf-"));
  try {
    writeFileSync(join(dir, "config.json"), JSON.stringify({ updates: "off", installToken: "tok-left-by-an-admin", serverUrl: "https://old.example" }));
    // The function as shipped, with only the root-only steps stubbed: the id check and the chown.
    const fn = shellFunction(JAMF, "json_set") + shellFunction(JAMF, "write_machine_config")
      .replace('"$(/usr/bin/id -u)" -ne 0', '"0" -ne 0')
      .replace("/usr/sbin/chown root:wheel \"$tmp\"", "true");
    const script = `set -u\nANCHOR_DIR=${JSON.stringify(dir)}\nSERVER_URL="https://moorai.acme.internal"\nTENANT="acme"\nINSTALL_TOKEN="tok-SECRET-should-not-appear"\nlog() { :; }\ndie() { echo "DIE $1" >&2; exit 1; }\n${fn}\nwrite_machine_config\n`;
    const r = spawnSync("/bin/bash", ["-c", script], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const raw = readFileSync(join(dir, "config.json"), "utf8");
    const cfg = JSON.parse(raw);
    assert.deepEqual(cfg, { updates: "off", serverUrl: "https://moorai.acme.internal", tenant: "acme" });
    assert.ok(!raw.includes("tok-"), raw);
    // and from nothing
    rmTree(join(dir, "config.json"));
    assert.equal(spawnSync("/bin/bash", ["-c", script], { encoding: "utf8" }).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(join(dir, "config.json"), "utf8")), { serverUrl: "https://moorai.acme.internal", tenant: "acme" });
    assert.ok(!existsSync(join(dir, ".config.json")), "no temp file left behind");
  } finally { rmTree(dir); }
});

test("Jamf (static): the token still goes to the enrolled user's own 0600 file", () => {
  const fn = shellFunction(JAMF, "write_enroll_config");
  assert.match(fn, /"installToken": "\$\{INSTALL_TOKEN\}"/);
  assert.match(fn, /chmod 600 "\$cfg_file"/);
  assert.match(fn, /cfg_dir="\$\{home\}\/\.moorai"/);
});

test("Intune (static): the machine-config writer sets serverUrl and tenant and removes installToken; the token goes to the user's file with a user-only ACL", () => {
  const fn = psFunction(INTUNE, "Write-MachineConfig");
  assert.match(fn, /\$cfg\["serverUrl"\] = \$ServerUrl/);
  assert.match(fn, /\$cfg\["tenant"\]\s+= \$Tenant/);
  assert.match(fn, /\$cfg\.Remove\("installToken"\)/);
  assert.doesNotMatch(fn, /\$InstallToken/, "the token parameter never reaches the machine config");
  const user = psFunction(INTUNE, "Write-EnrollConfig");
  assert.match(user, /installToken = \$InstallToken/);
  assert.match(user, /\/inheritance:r/);
  assert.match(INTUNE, /Get-MachineProgramData/, "the anchor directory comes from HKLM, not %ProgramData%");
});
