// End to end with the REAL helper: the moorai-guardd-test binary (the production helper over an injected tree,
// guardd/src/bin/moorai-guardd-test.rs, feature test-injection, unprivileged) registers its device key with a
// test console using a one-time enrolment secret, fetches /api/policy device-signed, and the hook's own loader
// reads that policy through the helper's socket and gets the console receipt. The test console
// (test/fixtures/guardd/fake-console.mjs) decides receipts with the console's receiptAuthFor and
// verifySignedRequest copied verbatim (test/fixtures/guardd/console-verifier.mjs), so a receipt arriving
// means guardd's signature verified under the console's own check.
//
// Needs cargo and macOS (the Linux and Windows platform layers are not implemented); skipped otherwise.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, chmodSync, existsSync, mkdtempSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { consoleKeyPair, startFakeConsole } from "./fixtures/guardd/fake-console.mjs";
import { shortTempRoot } from "./fixtures/guardd/fake-helper.mjs";
import { connect } from "../cli/guardd-client.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CHILD = join(ROOT, "test", "fixtures", "guardd", "load-policy-child.mjs");
const TENANT = "acme", TOKEN = "tok-guardd-e2e", SECRET = "mes_0123456789abcdef0123456789abcdef";
const ACTOR = "h2:a1b2c3d4e5f60718";
const KEY = consoleKeyPair();
const HAS_CARGO = spawnSync("cargo", ["--version"], { encoding: "utf8" }).status === 0;
const SKIP = process.platform !== "darwin" ? "the helper's platform layer exists for macOS only" : !HAS_CARGO ? "needs cargo to build moorai-guardd-test" : false;
let BIN = "";

before(() => {
  if (SKIP) return;
  const r = spawnSync("cargo", ["build", "--quiet", "--manifest-path", join(ROOT, "guardd", "Cargo.toml"), "--features", "test-injection", "--bin", "moorai-guardd-test", "--message-format=short"], { encoding: "utf8", timeout: 600_000 });
  assert.equal(r.status, 0, r.stderr);
  const target = process.env.CARGO_TARGET_DIR || join(ROOT, "guardd", "target");
  BIN = join(target, "debug", "moorai-guardd-test");
  assert.ok(existsSync(BIN), BIN);
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms, what) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (fn()) return; await sleep(50); }
  throw new Error(`timed out waiting for ${what}`);
}

// An injected tree laid out as guardd's Paths::under: etc/{config,secret,policy.pub}, state/, run/.
async function helperWorld({ enrollSecret = SECRET, hangPolicy = false } = {}) {
  const c = await startFakeConsole({ tenant: TENANT, token: TOKEN, key: KEY, enrollSecret: SECRET, hangPolicy,
    approvals: [{ requestId: "apr_01JB9X00000000000000000001", actor: ACTOR, device: hostname(), token: TOKEN, receipt: "console.receipt.wire" }] });
  const root = shortTempRoot("ge-");
  mkdirSync(join(root, "etc"));
  chmodSync(join(root, "etc"), 0o755);
  const put = (f, text, mode) => { writeFileSync(join(root, "etc", f), text); chmodSync(join(root, "etc", f), mode); };
  put("config.json", JSON.stringify({ serverUrl: c.url, tenant: TENANT, helper: "optional" }), 0o644);
  put("secret.json", JSON.stringify({ installToken: TOKEN, ...(enrollSecret ? { enrollSecret } : {}) }), 0o600);
  put("policy.pub", `${KEY.spki}\n`, 0o644);
  const proc = spawn(BIN, ["--root", root], { stdio: ["ignore", "ignore", "pipe"] });
  let log = "";
  proc.stderr.on("data", (d) => (log += d));
  await until(() => existsSync(join(root, "state", "registration.json")) && existsSync(join(root, "run", "hook.sock")), 15_000, "registration and the socket");
  const connectOpts = { root, trustUid: process.getuid(), endpoint: "/run/hook.sock", devicePubPath: "/run/device.pub" };
  return { c, root, proc, connectOpts, log: () => log,
    close: async () => { proc.kill("SIGTERM"); await new Promise((r) => (proc.exitCode !== null ? r() : proc.on("exit", r))); await c.close(); rmTree(root); } };
}

function load(home, { console: c, helper }) {
  const arg = JSON.stringify({ config: { serverUrl: c.url, tenant: TENANT, installToken: TOKEN }, actor: ACTOR, helper });
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD, arg], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_POLICY_PUBKEY: KEY.spki } });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("exit", (code) => { try { resolve(JSON.parse(out)); } catch { reject(new Error(`child exit ${code}: ${err || out}`)); } });
  });
}
const home = () => { const h = mkdtempSync(join(tmpdir(), "moorai-ge2e-")); mkdirSync(join(h, ".moorai")); return h; };
// The connect budget is CONNECT_BUDGET_MS (50 ms) in production; a loaded test machine gets 2 s here.
const helperOpts = (w) => ({ mode: "optional", connectOpts: w.connectOpts, budgetMs: 2000 });

test("E2E: a bound helper's signed fetch gets the console receipt, and the hook reads it through the helper", { skip: SKIP, timeout: 120_000 }, async () => {
  const w = await helperWorld();
  try {
    const reg = w.c.log.find((e) => e.path === "/api/devices/register");
    assert.deepEqual(reg.registered, { bound: true, device: hostname() }, "registered with the enrolment secret, as the hook names this device");
    const r = await load(home(), { console: w.c, helper: helperOpts(w) });
    assert.equal(r.via, "helper", JSON.stringify(r));
    assert.equal(r.source, "fresh");
    assert.deepEqual(r.rejected, []);
    assert.equal(r.approvals.length, 1);
    assert.equal(r.approvals[0].receipt, "console.receipt.wire", "the console receipt reached the hook");
    const fetches = w.c.log.filter((e) => e.path === "/api/policy");
    const last = fetches[fetches.length - 1];
    assert.equal(last.url, `/api/policy?tenant=${TENANT}&actor=${encodeURIComponent(ACTOR)}`, "the hook's actor, in the hook's query form");
    assert.equal(last.signed, true);
    assert.equal(last.receiptAuth, true, "the console's verifySignedRequest accepted guardd's signature over req.url");
    assert.equal(last.token, TOKEN);
    // The same console, fetched the old way (install token only): the approval, never its receipt.
    const direct = await load(home(), { console: w.c, helper: null });
    assert.equal(direct.via, "");
    assert.equal(direct.approvals[0].receipt, undefined);
  } finally { await w.close(); }
});

test("E2E: an unbound helper (no enrolment secret) still serves the policy, but the console withholds the receipt", { skip: SKIP, timeout: 120_000 }, async () => {
  const w = await helperWorld({ enrollSecret: "" });
  try {
    assert.equal(w.c.log.find((e) => e.path === "/api/devices/register").registered.bound, false);
    const r = await load(home(), { console: w.c, helper: helperOpts(w) });
    assert.equal(r.via, "helper");
    assert.equal(r.approvals[0].receipt, undefined);
    const last = w.c.log.filter((e) => e.path === "/api/policy").pop();
    assert.equal(last.signed, true);
    assert.equal(last.receiptAuth, false);
  } finally { await w.close(); }
});

test("E2E: a console that accepts and never answers: the helper's on-demand fetch is bounded (reqwest timeout)", { skip: SKIP, timeout: 120_000 }, async () => {
  const w = await helperWorld({ hangPolicy: true });
  try {
    const c = await connect({ ...w.connectOpts, budgetMs: 2000 });
    assert.ok(c.client, c.reason);
    try {
      const t0 = Date.now();
      const p = await c.client.policy({ actor: ACTOR }, 5000);
      const dt = Date.now() - t0;
      assert.equal(p.source, "none");
      assert.ok(dt >= 900 && dt < 1300 + 700, `on-demand bounded near 1000 ms, got ${dt} ms`);
    } finally { c.client.close(); }
    const r = await load(home(), { console: w.c, helper: helperOpts(w) });
    assert.equal(r.via, "", "nothing fresh from the helper: the direct path decides (here: no policy at all)");
  } finally { await w.close(); }
});
