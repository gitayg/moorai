// The Linux agent package (scripts/build-linux-package.mjs): a .deb and a tarball of the CLI, hooks and
// engine, with systemd user units and a per-user hook installer, plus an optional moorai-guardd .deb.
// The archives are read back with the system `tar` (an independent reader of the tar streams), the
// tarball is installed into a temp root, and the installed hook is run against a real PreToolUse payload.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, existsSync, readlinkSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildLinuxPackages } from "../scripts/build-linux-package.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const PKG = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8"));
const IS_WIN = process.platform === "win32";
const EPOCH = 1767225600; // 2026-01-01T00:00:00Z

let OUT; let BUILT; let WORK;

// Minimal reader for the ar container (the only part not read back by the system tar).
function readAr(buf) {
  assert.equal(buf.subarray(0, 8).toString("latin1"), "!<arch>\n");
  const members = [];
  let off = 8;
  while (off < buf.length) {
    const h = buf.subarray(off, off + 60).toString("latin1");
    assert.equal(h.slice(58, 60), "`\n", "ar member header terminator");
    const name = h.slice(0, 16).trim().replace(/\/$/, "");
    const size = Number(h.slice(48, 58).trim());
    members.push({ name, mode: h.slice(40, 48).trim(), uid: h.slice(28, 34).trim(), data: buf.subarray(off + 60, off + 60 + size) });
    off += 60 + size + (size % 2);
  }
  return members;
}
function tarList(tgzPath) {
  const r = spawnSync("tar", ["--numeric-owner", "-tvzf", tgzPath], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.split("\n").filter(Boolean);
}
function tarNames(tgzPath) {
  const r = spawnSync("tar", ["-tzf", tgzPath], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.split("\n").filter(Boolean);
}
function extractMember(deb, name, dir) {
  const m = readAr(readFileSync(deb)).find((x) => x.name === name);
  const p = join(dir, `${name}`);
  writeFileSync(p, m.data);
  return p;
}
function fakeGuardd(dir, testInjection = false) {
  const p = join(dir, "moorai-guardd");
  writeFileSync(p, `#!/bin/sh\n[ "$1" = "--build-info" ] && echo "moorai-guardd 0.1.0 test-injection=${testInjection}"\nexit 0\n`);
  chmodSync(p, 0o755);
  return p;
}

before(async () => {
  WORK = mkdtempSync(join(tmpdir(), "moorai-linuxpkg-"));
  OUT = join(WORK, "out");
  BUILT = await buildLinuxPackages({ outDir: OUT, sourceDateEpoch: EPOCH, guarddBinary: fakeGuardd(WORK), guarddArch: "amd64" });
});
after(() => { rmSync(WORK, { recursive: true, force: true }); });

test("the builder names the artifacts by package.json version", () => {
  assert.equal(BUILT.deb, join(OUT, `moorai_${PKG.version}_all.deb`));
  assert.equal(BUILT.tarball, join(OUT, `moorai-${PKG.version}-linux.tar.gz`));
  assert.equal(BUILT.guarddDeb, join(OUT, "moorai-guardd_0.1.0_amd64.deb"));
  assert.equal(BUILT.rpmSpec, join(OUT, "moorai.spec"));
  for (const p of [BUILT.deb, BUILT.tarball, BUILT.guarddDeb, BUILT.rpmSpec]) assert.ok(existsSync(p), p);
});

test("deb: an ar archive of debian-binary 2.0, control.tar.gz and data.tar.gz, in that order", () => {
  const m = readAr(readFileSync(BUILT.deb));
  assert.deepEqual(m.map((x) => x.name), ["debian-binary", "control.tar.gz", "data.tar.gz"]);
  assert.equal(m[0].data.toString(), "2.0\n");
  for (const x of m) assert.equal(x.uid, "0");
});

test("deb control: package metadata, Node as a recommendation, no personal names", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "ctl-"));
  const tgz = extractMember(BUILT.deb, "control.tar.gz", dir);
  const names = tarNames(tgz);
  for (const n of ["./control", "./md5sums", "./postinst", "./prerm"]) assert.ok(names.includes(n), n);
  spawnSync("tar", ["-xzf", tgz, "-C", dir]);
  const control = readFileSync(join(dir, "control"), "utf8");
  const field = (k) => new RegExp(`^${k}: (.*)$`, "m").exec(control)?.[1];
  assert.equal(field("Package"), "moorai");
  assert.equal(field("Version"), PKG.version);
  assert.equal(field("Architecture"), "all");
  assert.equal(field("Maintainer"), "MoorAI <noreply@moorai.dev>");
  assert.equal(field("Recommends"), "nodejs (>= 18)");
  assert.ok(Number(field("Installed-Size")) > 1000);
  assert.ok(control.endsWith("\n"));
  assert.ok(!/\b(itay|glick|opswat)\b/i.test(control));
  assert.ok(statSync(join(dir, "postinst")).mode & 0o100);
  assert.ok(statSync(join(dir, "prerm")).mode & 0o100);
});

test("deb md5sums match the data payload byte for byte", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "md5-"));
  const ctl = extractMember(BUILT.deb, "control.tar.gz", dir);
  const data = extractMember(BUILT.deb, "data.tar.gz", dir);
  mkdirSync(join(dir, "c")); mkdirSync(join(dir, "d"));
  spawnSync("tar", ["-xzf", ctl, "-C", join(dir, "c")]);
  assert.equal(spawnSync("tar", ["-xzf", data, "-C", join(dir, "d")]).status, 0);
  const lines = readFileSync(join(dir, "c", "md5sums"), "utf8").trim().split("\n");
  assert.ok(lines.length > 300);
  for (const l of lines) {
    const [sum, path] = l.split(/\s+/);
    assert.equal(createHash("md5").update(readFileSync(join(dir, "d", path))).digest("hex"), sum, path);
  }
});

test("deb data: the agent tree, one /usr/bin link per package.json bin, user units, root-owned", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "data-"));
  const tgz = extractMember(BUILT.deb, "data.tar.gz", dir);
  const names = tarNames(tgz);
  const verbose = tarList(tgz);
  assert.ok(names.includes("./usr/lib/moorai/cli/moorai-hook.mjs"));
  assert.ok(names.includes("./usr/lib/moorai/package.json"));
  assert.ok(names.includes("./usr/lib/moorai/linux/moorai-install-hooks"));
  assert.ok(names.includes("./usr/lib/moorai/linux/moorai-node"));
  assert.ok(names.includes("./usr/lib/systemd/user/moorai-hooks.service"));
  assert.ok(names.includes("./usr/lib/systemd/user/moorai-serve.service"));
  assert.ok(names.includes("./usr/bin/moorai-install-hooks"));
  for (const [bin, target] of Object.entries(PKG.bin)) {
    const line = verbose.find((l) => l.includes(`./usr/bin/${bin} -> `));
    assert.ok(line, `link for ${bin}`);
    assert.ok(line.endsWith(`-> ../lib/moorai/${target}`), line);
  }
  // Ownership: every entry uid 0 / gid 0 (--numeric-owner: bsdtar prints "0 0", GNU tar "0/0").
  for (const l of verbose) assert.match(l, /\s0\s+0\s|\s0\/0\s/, l);
  // Nothing outside the npm `files` set: of the top-level test/ tree only the red-team corpus, no host
  // app, no VCS, no secrets. (Directories npm ships whole, such as egress-proxy/, keep their own tests.)
  for (const n of names) {
    assert.ok(!/\/(src-tauri|\.git|node_modules|guardd)\//.test(n), n);
    if (n.startsWith("./usr/lib/moorai/test/")) assert.ok(["./usr/lib/moorai/test/", "./usr/lib/moorai/test/redteam/", "./usr/lib/moorai/test/redteam/corpus.json"].includes(n), n);
    assert.ok(!/\.(session-secret|local)$|signing-key|appcrane-key/.test(n), n);
  }
});

test("deb data: bin targets and the linux helpers are executable, other files 0644", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "modes-"));
  const tgz = extractMember(BUILT.deb, "data.tar.gz", dir);
  const verbose = tarList(tgz);
  const modeOf = (path) => verbose.find((l) => l.endsWith(` ${path}`) || l.includes(` ${path} -> `))?.slice(0, 10);
  assert.equal(modeOf("./usr/lib/moorai/cli/moorai-hook.mjs"), "-rwxr-xr-x");
  assert.equal(modeOf("./usr/lib/moorai/linux/moorai-install-hooks"), "-rwxr-xr-x");
  assert.equal(modeOf("./usr/lib/moorai/package.json"), "-rw-r--r--");
  assert.equal(modeOf("./usr/lib/systemd/user/moorai-hooks.service"), "-rw-r--r--");
});

test("the build is reproducible for a fixed SOURCE_DATE_EPOCH", async () => {
  const out2 = join(WORK, "out2");
  const b2 = await buildLinuxPackages({ outDir: out2, sourceDateEpoch: EPOCH });
  const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
  assert.equal(sha(b2.deb), sha(BUILT.deb));
  assert.equal(sha(b2.tarball), sha(BUILT.tarball));
  assert.equal(b2.guarddDeb, undefined, "no guardd package without a binary");
});

test("user units: the hook installer is a oneshot at login; the engine sidecar restarts on failure", () => {
  const hooks = readFileSync(join(REPO, "packaging", "linux", "moorai-hooks.service"), "utf8");
  const serve = readFileSync(join(REPO, "packaging", "linux", "moorai-serve.service"), "utf8");
  assert.match(hooks, /^Type=oneshot$/m);
  assert.match(hooks, /^ExecStart=\/usr\/lib\/moorai\/linux\/moorai-install-hooks$/m);
  assert.match(hooks, /^WantedBy=default\.target$/m);
  assert.match(serve, /^ExecStart=\/usr\/lib\/moorai\/linux\/moorai-node \/usr\/lib\/moorai\/cli\/moorai-serve\.mjs$/m);
  assert.match(serve, /^Restart=on-failure$/m);
  assert.match(serve, /^NoNewPrivileges=yes$/m);
  for (const u of [hooks, serve]) assert.ok(!/^User=/m.test(u), "user units run as the user");
});

test("moorai-node refuses a Node older than 18 with a clear message", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "oldnode-"));
  writeFileSync(join(dir, "node"), "#!/bin/sh\necho 16.20.2\n");
  chmodSync(join(dir, "node"), 0o755);
  const r = spawnSync("sh", [join(REPO, "packaging", "linux", "moorai-node"), "--check"], { encoding: "utf8", env: { PATH: `${dir}:/usr/bin:/bin`, HOME: dir } });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /Node\.js 18 or newer/);
  const ok = spawnSync("sh", [join(REPO, "packaging", "linux", "moorai-node"), "--check"], { encoding: "utf8", env: { PATH: `${join(process.execPath, "..")}:/usr/bin:/bin`, HOME: dir } });
  assert.equal(ok.status, 0, ok.stderr);
});

test("tarball: install.sh refuses / when unprivileged and installs into MOORAI_ROOT", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "tgz-"));
  assert.equal(spawnSync("tar", ["-xzf", BUILT.tarball, "-C", dir]).status, 0);
  const top = join(dir, `moorai-${PKG.version}`);
  if (process.getuid?.() !== 0) {
    const r = spawnSync("sh", [join(top, "install.sh")], { encoding: "utf8", env: { ...process.env, MOORAI_ROOT: "" } });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /as root/);
  }
  const root = join(dir, "root");
  const r = spawnSync("sh", [join(top, "install.sh")], { encoding: "utf8", env: { ...process.env, MOORAI_ROOT: root } });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(join(root, "usr/lib/moorai/cli/moorai-hook.mjs")));
  assert.equal(readlinkSync(join(root, "usr/bin/moorai-hook")), "../lib/moorai/cli/moorai-hook.mjs");
  assert.ok(existsSync(join(root, "usr/bin/moorai-hook")), "the link resolves");
  assert.ok(existsSync(join(root, "usr/lib/systemd/user/moorai-hooks.service")));
  assert.equal(statSync(join(root, "etc/moorai")).mode & 0o777, 0o755);
});

test("installed into a temp root: the hook installer registers hooks and the installed hook blocks a credential read", { skip: IS_WIN }, () => {
  const dir = mkdtempSync(join(WORK, "e2e-"));
  assert.equal(spawnSync("tar", ["-xzf", BUILT.tarball, "-C", dir]).status, 0);
  const root = join(dir, "root");
  assert.equal(spawnSync("sh", [join(dir, `moorai-${PKG.version}`, "install.sh")], { env: { ...process.env, MOORAI_ROOT: root } }).status, 0);
  const home = join(dir, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const env = { PATH: `${join(process.execPath, "..")}:/usr/bin:/bin`, HOME: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local/state"), MoorAI_SERVER: "http://127.0.0.1:1" };
  const inst = spawnSync("sh", [join(root, "usr/lib/moorai/linux/moorai-install-hooks")], { encoding: "utf8", env });
  assert.equal(inst.status, 0, inst.stderr);
  const settings = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"));
  const cmd = settings.hooks.PreToolUse[0].hooks[0].command;
  assert.ok(cmd.includes(join(root, "usr/lib/moorai/cli/moorai-hook.mjs")), cmd);
  // The fixture is the public AWS EXAMPLE key pair the repo's tests use; it grants access to nothing.
  const cred = join(home, "proj", ".env");
  writeFileSync(cred, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
  writeFileSync(join(home, "proj", "math.js"), "export const add = (a, b) => a + b;\n");
  const [nodeBin, hookPath] = JSON.parse(`[${cmd.replace(/" "/, '","')}]`);
  const run = (file) => spawnSync(nodeBin, [hookPath], { input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: file }, session_id: "linuxpkg" }), encoding: "utf8", env: { ...env, MOORAI_OFFLINE_MODE: "fail-closed" }, timeout: 20000 });
  const deny = run(cred);
  assert.equal(JSON.parse(deny.stdout).hookSpecificOutput.permissionDecision, "deny", deny.stdout + deny.stderr);
  const allow = run(join(home, "proj", "math.js"));
  assert.equal(allow.stdout.trim(), "", "a source file read stays allowed");
});

test("guardd deb: binary, system units and a postinst that starts the service only under systemd", { skip: IS_WIN }, () => {
  const m = readAr(readFileSync(BUILT.guarddDeb));
  assert.deepEqual(m.map((x) => x.name), ["debian-binary", "control.tar.gz", "data.tar.gz"]);
  const dir = mkdtempSync(join(WORK, "gd-"));
  const data = extractMember(BUILT.guarddDeb, "data.tar.gz", dir);
  const v = tarList(data);
  const line = (p) => v.find((l) => l.endsWith(` ${p}`));
  assert.ok(line("./usr/sbin/moorai-guardd")?.startsWith("-rwxr-xr-x"));
  assert.ok(line("./usr/lib/systemd/system/moorai-guardd.service")?.startsWith("-rw-r--r--"));
  assert.ok(line("./usr/lib/systemd/system/moorai-guardd.socket")?.startsWith("-rw-r--r--"));
  const ctl = extractMember(BUILT.guarddDeb, "control.tar.gz", dir);
  mkdirSync(join(dir, "c"));
  spawnSync("tar", ["-xzf", ctl, "-C", join(dir, "c")]);
  const control = readFileSync(join(dir, "c", "control"), "utf8");
  assert.match(control, /^Package: moorai-guardd$/m);
  assert.match(control, /^Architecture: amd64$/m);
  assert.match(control, /^Version: 0\.1\.0$/m);
  const postinst = readFileSync(join(dir, "c", "postinst"), "utf8");
  assert.match(postinst, /\[ -d \/run\/systemd\/system \]/);
  assert.match(postinst, /systemctl enable --now moorai-guardd\.socket moorai-guardd\.service/);
  const prerm = readFileSync(join(dir, "c", "prerm"), "utf8");
  assert.match(prerm, /systemctl disable --now moorai-guardd\.service moorai-guardd\.socket/);
});

test("guardd deb: a binary built with test-injection is refused", { skip: IS_WIN }, async () => {
  const dir = mkdtempSync(join(WORK, "gdti-"));
  await assert.rejects(buildLinuxPackages({ outDir: join(dir, "o"), sourceDateEpoch: EPOCH, guarddBinary: fakeGuardd(dir, true), guarddArch: "amd64" }), /test-injection/);
});

test("rpm spec: generated for rpmbuild with the same tree and the same scripts", () => {
  const spec = readFileSync(BUILT.rpmSpec, "utf8");
  assert.match(spec, /^Name:\s+moorai$/m);
  assert.match(spec, new RegExp(`^Version:\\s+${PKG.version.replace(/\./g, "\\.")}$`, "m"));
  assert.match(spec, /^BuildArch:\s+noarch$/m);
  assert.match(spec, /^Recommends:\s+nodejs >= 18$/m);
  assert.match(spec, /^\/usr\/lib\/moorai$/m);
  assert.match(spec, /^\/usr\/lib\/systemd\/user\/moorai-hooks\.service$/m);
  assert.ok(!/\b(itay|glick|opswat)\b/i.test(spec));
});

test("gzip streams carry no build-time timestamp", () => {
  const tgz = readFileSync(BUILT.tarball);
  assert.equal(tgz.readUInt32LE(4), 0, "gzip MTIME field is zero");
  assert.ok(gunzipSync(tgz).length > 0);
});
