// The hook reads its signed policy through moorai-guardd when the helper answers (cli/guardd-policy.mjs,
// cli/hook-core.mjs loadVerifiedPolicy `helper`), and otherwise keeps the direct install-token path exactly
// as before. Each case runs the hook's own loader in a child with a sandbox HOME against a local console
// (test/fixtures/guardd/fake-console.mjs) and an in-process helper endpoint in an injected tree
// (test/fixtures/guardd/fake-helper.mjs). The real helper binary end to end: test/guardd-policy-e2e.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { consoleKeyPair, signPolicy, startFakeConsole } from "./fixtures/guardd/fake-console.mjs";
import { startFakeHelper, shortTempRoot, deviceKeyPair } from "./fixtures/guardd/fake-helper.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CHILD = join(ROOT, "test", "fixtures", "guardd", "load-policy-child.mjs");
const TENANT = "acme", TOKEN = "tok-guardd-policy";
const ACTOR = "h2:a1b2c3d4e5f60718";
const KEY = consoleKeyPair();

function sandbox() {
  const home = mkdtempSync(join(tmpdir(), "moorai-gpolicy-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  return home;
}

function load(home, { console: c, helper = null, anchor = true }) {
  const arg = JSON.stringify({ config: { serverUrl: c.url, tenant: TENANT, installToken: TOKEN }, actor: ACTOR, helper });
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD, arg], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_POLICY_PUBKEY: anchor ? KEY.spki : "" } });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("exit", (code) => { try { resolve(JSON.parse(out)); } catch { reject(new Error(`child exit ${code}: ${err || out}`)); } });
  });
}

const helperPolicy = (extra = {}, iat) => signPolicy({ marker: "helper", tenant: TENANT, approvals: [{ requestId: "apr_1", ruleId: "hub-priv", actionHash: "h2:0000000000000000", decision: "approve", grant: "once", decidedAt: new Date().toISOString(), validUntil: new Date(Date.now() + 600000).toISOString(), receipt: "console.receipt" }], ...extra }, KEY, TENANT, iat);
const policyFetches = (c) => c.log.filter((e) => e.path === "/api/policy");

async function world(behavior) {
  const c = await startFakeConsole({ tenant: TENANT, token: TOKEN, key: KEY, basePolicy: { marker: "direct", captureTier: "content-free" } });
  const root = shortTempRoot("gp-");
  const h = behavior ? await startFakeHelper(root, { tenant: TENANT, ...behavior }) : null;
  const connectOpts = h ? h.connectOpts : { root, trustUid: process.getuid(), endpoint: "/run/hook.sock", devicePubPath: "/run/device.pub" };
  return { c, h, helper: { mode: "optional", connectOpts }, close: async () => { if (h) await h.close(); await c.close(); rmTree(root); } };
}

const skipWin = process.platform === "win32" && "unix-socket test tree";

test("helper present: the policy comes through it, verified, with the console receipt; no direct fetch", { skip: skipWin }, async () => {
  const w = await world({ policy: () => ({ source: "fresh", policy: helperPolicy(), iat: new Date().toISOString() }) });
  try {
    const r = await load(sandbox(), { console: w.c, helper: w.helper });
    assert.equal(r.via, "helper");
    assert.equal(r.source, "fresh");
    assert.equal(r.marker, "helper");
    assert.equal(r.approvals[0].receipt, "console.receipt");
    assert.deepEqual(r.rejected, []);
    assert.equal(policyFetches(w.c).length, 0, "no install-token fetch while the helper answers");
    const asked = w.h.requests.filter((m) => m.op === "policy");
    assert.equal(asked.length, 1);
    assert.equal(asked[0].actor, ACTOR, "the hook's keyed actor is named so the helper's fetch carries this device's approvals");
  } finally { await w.close(); }
});

test("helper absent: the direct install-token fetch, unchanged", { skip: skipWin }, async () => {
  const w = await world(null);
  try {
    const r = await load(sandbox(), { console: w.c, helper: w.helper });
    assert.equal(r.via, "");
    assert.equal(r.marker, "direct");
    assert.equal(r.source, "fresh");
    const f = policyFetches(w.c);
    assert.equal(f.length, 1);
    assert.equal(f[0].signed, false);
    assert.equal(f[0].url, `/api/policy?tenant=${TENANT}&actor=${encodeURIComponent(ACTOR)}`);
  } finally { await w.close(); }
});

test("helper hangs: the policy wait is bounded, then the direct path decides", { skip: skipWin }, async () => {
  const w = await world({ policy: () => "hang" });
  try {
    const r = await load(sandbox(), { console: w.c, helper: { ...w.helper, policyTimeoutMs: 400 } });
    assert.equal(r.via, "");
    assert.equal(r.marker, "direct");
    assert.ok(r.ms >= 400, `waited the bound (${r.ms} ms)`);
    assert.ok(r.ms < 400 + 3000, `and not much more (${r.ms} ms)`);
  } finally { await w.close(); }
});

test("helper hangs: the production bound is POLICY_FETCH_TIMEOUT_MS, inside the hook budget", { skip: skipWin }, async () => {
  const { POLICY_FETCH_TIMEOUT_MS } = await import("../cli/guardd-client.mjs");
  const { HOOK_DECISION_BUDGET_MS } = await import("../cli/hook-fail.mjs");
  assert.equal(POLICY_FETCH_TIMEOUT_MS, 1300);
  assert.ok(POLICY_FETCH_TIMEOUT_MS + 1500 + 50 < HOOK_DECISION_BUDGET_MS);
  const w = await world({ policy: () => "hang" });
  try {
    const r = await load(sandbox(), { console: w.c, helper: w.helper });
    assert.equal(r.marker, "direct");
    assert.ok(r.ms >= POLICY_FETCH_TIMEOUT_MS && r.ms < POLICY_FETCH_TIMEOUT_MS + 3000, `${r.ms} ms`);
  } finally { await w.close(); }
});

for (const [name, reply, status] of [
  ["unsigned", () => ({ source: "fresh", policy: JSON.stringify({ marker: "helper", approvals: [{ receipt: "forged" }] }) }), "unsigned"],
  ["signed by another key", () => ({ source: "fresh", policy: signPolicy({ marker: "helper", tenant: TENANT }, consoleKeyPair(), TENANT) }), "untrusted"],
  ["another tenant's signed policy", () => ({ source: "fresh", policy: signPolicy({ marker: "helper", tenant: "other" }, KEY, "other") }), "mismatch"]
]) {
  test(`helper returns a policy that does not verify (${name}): refused, reported, direct path`, { skip: skipWin }, async () => {
    const w = await world({ policy: reply });
    try {
      const r = await load(sandbox(), { console: w.c, helper: w.helper });
      assert.equal(r.via, "");
      assert.equal(r.marker, "direct");
      assert.ok(r.rejected.some((x) => x.source === "helper"), JSON.stringify(r.rejected));
      if (status !== "mismatch") assert.deepEqual(r.rejected.filter((x) => x.source === "helper"), [{ source: "helper", status }]);
      assert.equal(policyFetches(w.c).length, 1);
    } finally { await w.close(); }
  });
}

test("helper copy older than the device's last verified policy: refused as a rollback, not reported, direct path", { skip: skipWin }, async () => {
  const w = await world({ policy: () => ({ source: "fresh", policy: helperPolicy({}, new Date(Date.now() - 3600_000).toISOString()) }) });
  try {
    const home = sandbox();
    const first = await load(home, { console: w.c, helper: null });
    assert.equal(first.marker, "direct");
    const r = await load(home, { console: w.c, helper: w.helper });
    assert.equal(r.via, "");
    assert.equal(r.marker, "direct");
    assert.equal(r.rejected.filter((x) => x.source === "helper").length, 0);
  } finally { await w.close(); }
});

for (const [name, behavior] of [
  ["a stale copy (console unreachable from the helper)", { policy: () => ({ source: "cache", policy: helperPolicy() }) }],
  ["no policy yet", { policy: () => ({ source: "none" }) }],
  ["another tenant's helper", { tenant: "other", policy: () => ({ source: "fresh", policy: helperPolicy() }) }],
  ["a hello proof by a key other than device.pub's", { proofKey: deviceKeyPair(), policy: () => ({ source: "fresh", policy: helperPolicy() }) }],
  ["the connection closes", { policy: () => "close" }]
]) {
  test(`helper with ${name}: not used, direct path, nothing reported`, { skip: skipWin }, async () => {
    const w = await world(behavior);
    try {
      const r = await load(sandbox(), { console: w.c, helper: w.helper });
      assert.equal(r.via, "");
      assert.equal(r.marker, "direct");
      assert.deepEqual(r.rejected, []);
      assert.equal(policyFetches(w.c).length, 1);
    } finally { await w.close(); }
  });
}

test("an unpinned device (first contact) never asks the helper: the direct fetch pins it", { skip: skipWin }, async () => {
  const w = await world({ policy: () => ({ source: "fresh", policy: helperPolicy() }) });
  try {
    const r = await load(sandbox(), { console: w.c, helper: w.helper, anchor: false });
    assert.equal(r.marker, "direct");
    assert.equal(w.h.requests.length, 0, "no connection at all");
  } finally { await w.close(); }
});

test("machine config helper: \"off\" never connects", { skip: skipWin }, async () => {
  const w = await world({ policy: () => ({ source: "fresh", policy: helperPolicy() }) });
  try {
    const r = await load(sandbox(), { console: w.c, helper: { ...w.helper, mode: "off" } });
    assert.equal(r.marker, "direct");
    assert.equal(w.h.requests.length, 0);
  } finally { await w.close(); }
});

test("a world-writable test tree fails the ownership walk: the helper is untrusted and not used", { skip: skipWin }, async () => {
  const w = await world({ policy: () => ({ source: "fresh", policy: helperPolicy() }) });
  try {
    const { chmodSync } = await import("node:fs");
    chmodSync(join(w.helper.connectOpts.root, "run"), 0o777);
    const r = await load(sandbox(), { console: w.c, helper: w.helper });
    assert.equal(r.marker, "direct");
    assert.equal(w.h.requests.length, 0, "refused before connecting");
  } finally { await w.close(); }
});

test("the default (helper: null, every caller but the hook) is the direct path", { skip: skipWin }, async () => {
  const w = await world({ policy: () => ({ source: "fresh", policy: helperPolicy() }) });
  try {
    const r = await load(sandbox(), { console: w.c, helper: null });
    assert.equal(r.marker, "direct");
    assert.equal(w.h.requests.length, 0);
  } finally { await w.close(); }
});

test("the hook passes the helper option from the machine config", () => {
  const src = (p) => import("node:fs").then((fs) => fs.readFileSync(join(ROOT, p), "utf8"));
  return src("cli/moorai-hook.mjs").then((s) => {
    assert.match(s, /loadVerifiedPolicy\(CONFIG, \{ actor: [^\n]*\n\s*helper: \{ mode: ADMIN && typeof ADMIN\.helper === "string" \? ADMIN\.helper : "optional"/);
  });
});
