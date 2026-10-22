// Agent-side detection of the moorai-guardd install (cli/guardd-install.mjs): is the helper installed,
// running and answering with a valid device-key proof? Every case runs against a temp root with the
// ownership walk trusting the test's own uid, the way guardd's own tests use Paths::under (contract
// §11.2); a fake helper speaks the real frames from cli/guardd-client.mjs over a Unix socket.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, chownSync, rmSync, linkSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { generateKeyPairSync, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { encodeFrame, FrameDecoder, helloProofInput, keyIdOfSpki } from "../cli/guardd-client.mjs";
import { helperInstallStatus, guarddLayout, HELPER_STATES, POSTURE_KEYS } from "../cli/guardd-install.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const IS_WIN = process.platform === "win32";
const UID = process.getuid ? process.getuid() : 0;

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  return { spki, privateKey, keyId: keyIdOfSpki(spki) };
}

function makeRoot({ binary = false, units = false, pub = null } = {}) {
  // Short base: the Unix socket path limit is 104 bytes on macOS.
  const root = mkdtempSync(join(IS_WIN ? tmpdir() : "/tmp", "gd-"));
  if (binary) {
    mkdirSync(join(root, "usr/sbin"), { recursive: true });
    writeFileSync(join(root, "usr/sbin/moorai-guardd"), "#!/bin/sh\n");
    chmodSync(join(root, "usr/sbin/moorai-guardd"), 0o755);
  }
  if (units) {
    mkdirSync(join(root, "usr/lib/systemd/system"), { recursive: true });
    for (const u of ["moorai-guardd.service", "moorai-guardd.socket"]) writeFileSync(join(root, "usr/lib/systemd/system", u), "[Unit]\n");
  }
  mkdirSync(join(root, "run/moorai"), { recursive: true, mode: 0o755 });
  chmodSync(join(root, "run/moorai"), 0o755);
  if (pub) writeFileSync(join(root, "run/moorai/device.pub"), `${pub}\n`, { mode: 0o644 });
  return root;
}

// A fake helper. `behave` decides the reply to hello: "ok", "wrong-key", "not-ready", "silent", "key-mismatch".
function fakeHelper(root, kp, behave = "ok", other = null) {
  const sock = join(root, "run/moorai/hook.sock");
  const server = createServer((c) => {
    const d = new FrameDecoder();
    c.on("data", (chunk) => {
      d.push(chunk);
      let m;
      while ((m = d.next())) {
        if (behave === "silent") continue;
        if (behave === "not-ready") { c.write(encodeFrame({ v: 1, id: m.id, op: "error", code: "not_ready", message: "no binding", reqOp: "hello" })); continue; }
        const helperVersion = "0.1.0";
        const signer = behave === "wrong-key" ? other : kp;
        const keyId = behave === "key-mismatch" ? other.keyId : kp.keyId;
        const proof = sign(null, Buffer.from(helloProofInput(m.nonce, keyId, helperVersion)), signer.privateKey).toString("base64");
        c.write(encodeFrame({ v: 1, id: m.id, op: "hello", proto: 1, helperVersion, tenant: "tenant-secret-name", deviceId: "d".repeat(32), keyId, caps: ["call", "hello"], proof }));
      }
    });
    c.on("error", () => {});
  });
  return new Promise((res) => server.listen(sock, () => res(server)));
}

const opts = (root, extra = {}) => ({ platform: "linux", root, trustUid: UID, timeoutMs: 400, ...extra });

test("the layout constants follow contract §3.1 / §4.3 per OS", () => {
  assert.equal(guarddLayout("linux").endpoint, "/run/moorai/hook.sock");
  assert.equal(guarddLayout("linux").binary, "/usr/sbin/moorai-guardd");
  assert.deepEqual(guarddLayout("linux").units, ["/usr/lib/systemd/system/moorai-guardd.service", "/usr/lib/systemd/system/moorai-guardd.socket"]);
  assert.equal(guarddLayout("darwin").endpoint, "/private/var/run/moorai/hook.sock");
  assert.equal(guarddLayout("darwin").binary, "/Library/PrivilegedHelperTools/moorai-guardd");
  assert.deepEqual(guarddLayout("darwin").units, ["/Library/LaunchDaemons/run.glick.moorai.guardd.plist"]);
  assert.equal(guarddLayout("win32").endpoint, "\\\\.\\pipe\\MoorAI.Hook");
  assert.equal(guarddLayout("win32").service, "MoorAIGuard");
});

test("nothing installed → not-installed, no probe attempted", { skip: IS_WIN }, async () => {
  const root = makeRoot();
  try {
    const s = await helperInstallStatus(opts(root));
    assert.deepEqual(s, { state: "not-installed", binary: false, service: false, endpoint: "absent", devicePub: "absent", hello: "skipped" });
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("binary without units (or units without binary) → partial", { skip: IS_WIN }, async () => {
  const a = makeRoot({ binary: true });
  const b = makeRoot({ units: true });
  try {
    assert.equal((await helperInstallStatus(opts(a))).state, "partial");
    assert.equal((await helperInstallStatus(opts(b))).state, "partial");
  } finally { rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
});

test("units under /lib/systemd/system count as installed too (non-merged-usr distributions)", { skip: IS_WIN }, async () => {
  const root = makeRoot({ binary: true });
  try {
    mkdirSync(join(root, "lib/systemd/system"), { recursive: true });
    for (const u of ["moorai-guardd.service", "moorai-guardd.socket"]) writeFileSync(join(root, "lib/systemd/system", u), "[Unit]\n");
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.service, true);
    assert.equal(s.state, "installed-not-running");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("installed, no socket → installed-not-running", { skip: IS_WIN }, async () => {
  const root = makeRoot({ binary: true, units: true });
  try {
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.state, "installed-not-running");
    assert.equal(s.endpoint, "absent");
    assert.equal(s.hello, "skipped");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("installed and answering hello with a valid device-key proof → healthy", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "ok");
  try {
    const s = await helperInstallStatus(opts(root));
    assert.deepEqual(s, { state: "healthy", binary: true, service: true, endpoint: "ok", devicePub: "ok", hello: "ok", helperVersion: "0.1.0" });
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a proof signed by another key → untrusted / bad-proof (a squatter cannot sign)", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "wrong-key", keypair());
  try {
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.state, "untrusted");
    assert.equal(s.hello, "bad-proof");
    assert.equal(s.helperVersion, undefined);
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a reply naming another key id → untrusted / key-mismatch", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "key-mismatch", keypair());
  try {
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.state, "untrusted");
    assert.equal(s.hello, "key-mismatch");
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a helper with no console binding yet → not-ready", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "not-ready");
  try {
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.state, "not-ready");
    assert.equal(s.hello, "not-ready");
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a helper that never answers → unreachable / timeout, bounded by timeoutMs", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "silent");
  try {
    const t0 = Date.now();
    const s = await helperInstallStatus(opts(root, { timeoutMs: 150 }));
    assert.ok(Date.now() - t0 < 1500);
    assert.equal(s.state, "unreachable");
    assert.equal(s.hello, "timeout");
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a stale socket file nobody listens on → unreachable / error", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const sock = join(root, "run/moorai/hook.sock");
  const keep = join(root, "run/moorai/keep.sock");
  try {
    // A crashed helper leaves the socket inode behind. libuv unlinks the path on close, so keep a second
    // link to the inode and put it back once nothing listens.
    const dead = createServer();
    await new Promise((r) => dead.listen(sock, r));
    linkSync(sock, keep);
    await new Promise((r) => dead.close(r));
    renameSync(keep, sock);
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.endpoint, "ok");
    assert.equal(s.state, "unreachable");
    assert.equal(s.hello, "error");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a socket in a group- or world-writable directory is refused before any connect → untrusted", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "ok");
  try {
    chmodSync(join(root, "run/moorai"), 0o777);
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.endpoint, "untrusted");
    assert.equal(s.state, "untrusted");
    assert.equal(s.hello, "skipped", "no frame is sent to an endpoint a user could have planted");
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a group-writable directory whose group is not root's is refused → untrusted", { skip: IS_WIN || process.getgid?.() === 0 }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "ok");
  try {
    // BSD gives a new directory its parent's group (wheel, gid 0, under /tmp on macOS); set the test
    // user's own primary group so the directory is group-writable by a non-root group.
    chownSync(join(root, "run/moorai"), UID, process.getgid());
    chmodSync(join(root, "run/moorai"), 0o775);
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.endpoint, "untrusted");
    assert.equal(s.state, "untrusted");
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a regular file at the endpoint path is not a socket → untrusted", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  try {
    writeFileSync(join(root, "run/moorai/hook.sock"), "", { mode: 0o644 });
    const s = await helperInstallStatus(opts(root));
    assert.equal(s.endpoint, "untrusted");
    assert.equal(s.state, "untrusted");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a socket owned by another uid than the trusted one is refused → untrusted", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "ok");
  try {
    const s = await helperInstallStatus(opts(root, { trustUid: UID + 4242 }));
    assert.equal(s.endpoint, "untrusted");
    assert.equal(s.state, "untrusted");
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("a device.pub that is writable by others, or not an ed25519 key, is refused", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const a = makeRoot({ binary: true, units: true, pub: kp.spki });
  const b = makeRoot({ binary: true, units: true, pub: "bm90IGEga2V5" });
  const sa = await fakeHelper(a, kp, "ok");
  const sb = await fakeHelper(b, kp, "ok");
  try {
    chmodSync(join(a, "run/moorai/device.pub"), 0o666);
    const s1 = await helperInstallStatus(opts(a));
    assert.equal(s1.devicePub, "untrusted");
    assert.equal(s1.state, "untrusted");
    const s2 = await helperInstallStatus(opts(b));
    assert.equal(s2.devicePub, "invalid");
    assert.equal(s2.state, "untrusted");
  } finally { sa.close(); sb.close(); rmSync(a, { recursive: true, force: true }); rmSync(b, { recursive: true, force: true }); }
});

test("probe:false reports a trusted endpoint without connecting → running-unprobed", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "ok");
  let connections = 0;
  srv.on("connection", () => { connections++; });
  try {
    const s = await helperInstallStatus(opts(root, { probe: false }));
    assert.equal(s.state, "running-unprobed");
    assert.equal(s.hello, "skipped");
    assert.equal(connections, 0);
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("the status is content-free: enums and a version only, never a path, tenant or device id", { skip: IS_WIN }, async () => {
  const kp = keypair();
  const root = makeRoot({ binary: true, units: true, pub: kp.spki });
  const srv = await fakeHelper(root, kp, "ok");
  try {
    const s = await helperInstallStatus(opts(root));
    const text = JSON.stringify(s);
    assert.ok(!text.includes(root) && !text.includes("tenant-secret-name") && !text.includes("d".repeat(32)) && !text.includes(kp.keyId));
    for (const k of Object.keys(s)) assert.ok(POSTURE_KEYS.includes(k), k);
    assert.ok(HELPER_STATES.includes(s.state));
  } finally { srv.close(); rmSync(root, { recursive: true, force: true }); }
});

test("windows: the service state comes from the SCM query; no binary and no service → not-installed", async () => {
  const root = mkdtempSync(join(tmpdir(), "gdw-"));
  try {
    const none = await helperInstallStatus({ platform: "win32", root, serviceQuery: () => "absent", probe: false });
    assert.equal(none.state, "not-installed");
    mkdirSync(join(root, "Program Files", "MoorAI"), { recursive: true });
    writeFileSync(join(root, "Program Files", "MoorAI", "moorai-guardd.exe"), "MZ");
    const stopped = await helperInstallStatus({ platform: "win32", root, serviceQuery: () => "stopped", probe: false });
    assert.equal(stopped.state, "installed-not-running");
    assert.equal(stopped.service, true);
    const nopub = await helperInstallStatus({ platform: "win32", root, serviceQuery: () => "running", probe: false });
    assert.equal(nopub.state, "unverified", "running, but no device.pub to check a proof against");
    assert.equal(nopub.endpoint, "ok");
    mkdirSync(join(root, "ProgramData", "MoorAI", "run"), { recursive: true });
    writeFileSync(join(root, "ProgramData", "MoorAI", "run", "device.pub"), `${keypair().spki}\n`);
    const running = await helperInstallStatus({ platform: "win32", root, serviceQuery: () => "running", probe: false });
    assert.equal(running.state, "running-unprobed");
    assert.equal(running.devicePub, "ok");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("moorai-helper status --json on this machine prints one known state and exits 0", () => {
  const r = spawnSync(process.execPath, [join(REPO, "cli", "moorai-helper.mjs"), "status", "--json"], { encoding: "utf8", timeout: 15000 });
  assert.equal(r.status, 0, r.stderr);
  const s = JSON.parse(r.stdout);
  assert.ok(HELPER_STATES.includes(s.state), s.state);
  for (const k of Object.keys(s)) assert.ok(POSTURE_KEYS.includes(k), k);
});

test("moorai-helper takes no path or root flag (contract §10.2: nothing user-supplied names the endpoint)", () => {
  const r = spawnSync(process.execPath, [join(REPO, "cli", "moorai-helper.mjs"), "status", "--root", "/tmp"], { encoding: "utf8", timeout: 15000 });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /unknown option/);
});
