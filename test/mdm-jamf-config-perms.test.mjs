// The Jamf deploy script writes ~/.moorai/config.json, which holds the tenant install token, as root
// and then chowns it to the user. The final `chmod 700/600` used to be the only thing making it
// private, so between the write and the chmod the token sat in a 0644 file inside a 0755 directory.
//
// The script calls every tool by absolute path, so a PATH stub cannot intercept it. Instead this test
// runs the REAL write_enroll_config body with only /bin/chmod and /usr/sbin/chown swapped for
// recording stubs. With the belt-and-braces chmods neutralised, the modes left on disk are exactly
// the modes the directory and file were created with, which is what an observer sees during the
// write.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, statSync, lstatSync, symlinkSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rmTree } from "./fs-cleanup.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "packaging", "mdm", "jamf", "moorai-jamf-deploy.sh");
const TOKEN = "it_live_TESTTOKEN0123456789";

function extractFunction() {
  const lines = readFileSync(SCRIPT, "utf8").split("\n");
  const start = lines.findIndex((l) => /^write_enroll_config\(\) \{/.test(l));
  assert.ok(start >= 0, "write_enroll_config not found in the deploy script");
  // The JSON heredoc also has a bare "}" line, so take the last one before the next section banner.
  const next = lines.findIndex((l, i) => i > start && l.startsWith("# ---"));
  const end = lines.slice(0, next).lastIndexOf("}");
  const body = lines.slice(start, end + 1).join("\n");
  const chmods = (body.match(/\/bin\/chmod /g) || []).length;
  const chowns = (body.match(/\/usr\/sbin\/chown /g) || []).length;
  // If the script stops calling these by these paths, the stubs below would silently stop applying.
  assert.ok(chmods >= 1 && chowns >= 1, `expected /bin/chmod and /usr/sbin/chown in the function (got ${chmods}/${chowns})`);
  return body.replaceAll("/bin/chmod ", "chmod_stub ").replaceAll("/usr/sbin/chown ", "chown_stub ");
}

function runWrite(home) {
  const log = join(home, "..", "calls.log");
  const harness = `
set -u
log() { :; }
chmod_stub() { echo "chmod $*" >> "${log}"; }
chown_stub() { echo "chown $*" >> "${log}"; }
SERVER_URL="https://console.example.test"
TENANT="acme"
INSTALL_TOKEN="${TOKEN}"
umask 022
${extractFunction()}
write_enroll_config "$(id -un)" "${home}"
echo "caller-umask=$(umask)"
`;
  const r = spawnSync("bash", ["-c", harness], { encoding: "utf8" });
  assert.equal(r.status, 0, `harness failed: ${r.stderr}`);
  let calls = "";
  try { calls = readFileSync(log, "utf8"); } catch { /* no stub calls recorded */ }
  return { stdout: r.stdout, calls };
}

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "moorai-jamf-"));
  const home = join(root, "home");
  mkdirSync(home);
  return { root, home, dir: join(home, ".moorai"), file: join(home, ".moorai", "config.json") };
}

const mode = (p) => statSync(p).mode & 0o777;

test("JAMF-CONFIG: dir and token file are created private, not made private afterwards", { skip: process.platform === "win32" }, () => {
  const s = sandbox();
  try {
    const { stdout, calls } = runWrite(s.home);
    assert.equal(mode(s.dir) & 0o077, 0, `~/.moorai created with mode ${mode(s.dir).toString(8)}`);
    assert.equal(mode(s.file) & 0o077, 0, `config.json created with mode ${mode(s.file).toString(8)}`);
    assert.equal(JSON.parse(readFileSync(s.file, "utf8")).installToken, TOKEN);
    // The umask must be scoped to the write, not leak into the rest of the deploy script.
    assert.match(stdout, /caller-umask=0022/);
    // Ownership semantics and the belt-and-braces chmods are unchanged.
    assert.match(calls, new RegExp(`chown -R ${userInfo().username} ${s.dir}`));
    assert.match(calls, new RegExp(`chmod 700 ${s.dir}`));
    assert.match(calls, new RegExp(`chmod 600 ${s.file}`));
  } finally { rmTree(s.root); }
});

test("JAMF-CONFIG: a pre-existing world-readable config.json is not rewritten in place", { skip: process.platform === "win32" }, () => {
  const s = sandbox();
  try {
    mkdirSync(s.dir, { mode: 0o700 });
    writeFileSync(s.file, "{}");
    chmodSync(s.file, 0o644);
    runWrite(s.home);
    assert.equal(mode(s.file) & 0o077, 0, `token written into a file with mode ${mode(s.file).toString(8)}`);
    assert.equal(JSON.parse(readFileSync(s.file, "utf8")).installToken, TOKEN);
  } finally { rmTree(s.root); }
});

test("JAMF-CONFIG: a config.json symlink is replaced, never written through", { skip: process.platform === "win32" }, () => {
  const s = sandbox();
  try {
    mkdirSync(s.dir, { mode: 0o700 });
    const target = join(s.root, "outside-target");
    writeFileSync(target, "untouched");
    symlinkSync(target, s.file);
    runWrite(s.home);
    assert.equal(readFileSync(target, "utf8"), "untouched", "the script wrote through a symlink the user planted");
    assert.ok(lstatSync(s.file).isFile(), "config.json should now be a regular file");
    assert.equal(mode(s.file) & 0o077, 0);
  } finally { rmTree(s.root); }
});
