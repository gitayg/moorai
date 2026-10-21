// The device bundle (cli/moorai-outbox.mjs export): what a disconnected device hands over by file. A stored
// zip, a manifest listing each file's SHA-256, and manifest.mac, an HMAC-SHA256 keyed with the install token
// over "moorai-device-bundle|v1|<sha256 hex of manifest.json>" (the same assurance as a live POST).
//
//   node --test --import ./test/hermetic-env.mjs test/moorai-outbox.test.mjs
//   MOORAI_UPDATE_GOLDEN=1 node --test --import ./test/hermetic-env.mjs test/moorai-outbox.test.mjs   # rewrite the golden fixture
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { buildDeviceBundle, deviceBundleZip, DEVICE_BUNDLE_SCHEMA, DEVICE_SIGNED_PREFIX } from "../cli/moorai-outbox.mjs";
import { enqueueAlerts } from "../cli/alert-outbox.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GOLDEN = join(ROOT, "test", "fixtures", "device-bundle", "golden.json");
const CLI = join(ROOT, "cli", "moorai-outbox.mjs");
const sha = (s) => createHash("sha256").update(s).digest("hex");
const TOKEN = "tok-golden-device-bundle";
const CONFIG = { serverUrl: "http://console.invalid", tenant: "acme", installToken: TOKEN };
const CREATED = new Date("2026-10-21T09:20:00.000Z");
const BUNDLE_ID = "3b91c0de-5f6a-4c1e-9d2b-7a8e6f40e04f";
const IDENT = { user: "dev-user", device: "dev-host", platform: "darwin" };

// Fixed inputs: three numbered alerts (one carried a capture-tier field), one unnumbered, fixed oids and times.
function fixedDir() {
  const dir = mkdtempSync(join(tmpdir(), "moorai-bundle-"));
  const base = { threatId: 2, category: "Indirect prompt injection", riskLevel: "Blocked", stage: "file", tool: "Bash", contentHash: "h2:4c1d", ...IDENT, tenant: "acme", appVersion: "1.27.0", reasonCode: "DETECTOR_MATCH", enforcement: "AS_CONFIGURED", policyId: "pol:acme:2026-10-20T00:00:00Z:abc" };
  const alerts = [
    { ...base, ts: "2026-10-21T09:14:07.123Z", seq: 18204, chainHead: "1".repeat(64), origin: { v: 1, kind: "agent", status: "inferred", basis: "no-moorai-ask", thread: "main", hostPrompt: "unknown" } },
    { ...base, ts: "2026-10-21T09:14:08.000Z", seq: 18205, chainHead: "2".repeat(64), matchText: "SECRET-SPAN" },
    { ...base, ts: "2026-10-21T09:14:09.000Z", seq: 18206, chainHead: "3".repeat(64) },
    { ...base, ts: "2026-10-21T09:14:10.000Z", category: "Intent: user override", threatId: 0, riskLevel: "Info" }
  ];
  enqueueAlerts(alerts, { via: "deferred", dir, now: Date.parse("2026-10-21T09:15:00.000Z"), oids: ["a".repeat(32), "b".repeat(32), "c".repeat(32), "d".repeat(32)] });
  writeFileSync(join(dir, ".chain-alerts.head.json"), JSON.stringify({ seq: 18206, chash: "3".repeat(64) }));
  return dir;
}
const build = (dir, extra = {}) => buildDeviceBundle({ config: CONFIG, dir, now: CREATED, bundleId: BUNDLE_ID, identity: IDENT, appVersion: "1.27.0", ...extra });

test("manifest: schema, tenant, identity, seq summary, auth; files listed with their digests", () => {
  const dir = fixedDir();
  try {
    const b = build(dir);
    const m = JSON.parse(b.files["manifest.json"]);
    assert.equal(m.schema, DEVICE_BUNDLE_SCHEMA);
    assert.equal(m.kind, "device");
    assert.equal(m.bundleId, BUNDLE_ID);
    assert.equal(m.tenant, "acme");
    assert.equal(m.createdAt, CREATED.toISOString());
    assert.deepEqual(m.identity, IDENT);
    assert.deepEqual(m.seq, { from: 18204, to: 18206, count: 3, unnumbered: 1, chainHeadAtExport: "3".repeat(64) });
    assert.deepEqual(m.outbox, { dropped: { full: 0, aged: 0, rejected: 0, oversize: 0 }, droppedRanges: [] });
    assert.equal(m.auth.alg, "hmac-sha256");
    assert.equal(m.auth.tokenId, sha(TOKEN).slice(0, 16));
    assert.equal(b.manifestSha256, sha(b.files["manifest.json"]));
    for (const f of m.files) assert.equal(f.sha256, sha(b.files[f.path]), f.path);
    assert.deepEqual(m.files.map((f) => f.path), ["VERIFY.txt", "alerts.jsonl"]);
    const lines = b.files["alerts.jsonl"].trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(lines.map((a) => a.seq ?? null), [18204, 18205, 18206, null]);
    assert.equal(lines[1].delivery.via, "bundle");
    assert.equal(lines[1].delivery.captureStripped, true);
    assert.match(lines[1].delivery.rhash, /^[0-9a-f]{32}$/);
    assert.equal(lines[0].delivery.oid, "a".repeat(32));
    const all = Object.values(b.files).join("\n");
    assert.ok(!all.includes("SECRET-SPAN"), "capture-tier content never in a bundle");
    assert.ok(!all.includes(TOKEN), "the token itself is never in a bundle");
  } finally { rmTree(dir); }
});

test("manifest.mac verifies with exactly the VERIFY.txt recipe; one flipped byte of alerts.jsonl fails its digest", () => {
  const dir = fixedDir();
  try {
    const b = build(dir);
    assert.equal(DEVICE_SIGNED_PREFIX, "moorai-device-bundle|v1|");
    const verify = b.files["VERIFY.txt"];
    assert.ok(verify.includes(`printf '${DEVICE_SIGNED_PREFIX}%s'`));
    assert.ok(verify.includes("openssl dgst -sha256 -mac HMAC -macopt key:<install token>"));
    const msg = DEVICE_SIGNED_PREFIX + sha(b.files["manifest.json"]);
    assert.equal(createHmac("sha256", TOKEN).update(msg).digest("base64"), b.files["manifest.mac"]);
    assert.notEqual(createHmac("sha256", TOKEN).update("moorai-diamond-bundle|v1|" + sha(b.files["manifest.json"])).digest("base64"), b.files["manifest.mac"], "domain-separated");
    const m = JSON.parse(b.files["manifest.json"]);
    const entry = m.files.find((f) => f.path === "alerts.jsonl");
    const buf = Buffer.from(b.files["alerts.jsonl"]);
    buf[10] ^= 1;
    assert.notEqual(sha(buf), entry.sha256);
    // The recipe itself, with openssl, when it is installed.
    const o = spawnSync("openssl", ["version"], { encoding: "utf8" });
    if (o.status === 0) {
      const work = mkdtempSync(join(tmpdir(), "moorai-bundle-ossl-"));
      try {
        writeFileSync(join(work, "manifest.json"), b.files["manifest.json"]);
        const digest = spawnSync("openssl", ["dgst", "-sha256", "-r", "manifest.json"], { cwd: work, encoding: "utf8" }).stdout.slice(0, 64);
        writeFileSync(join(work, "signed-message.txt"), DEVICE_SIGNED_PREFIX + digest);
        const mac = spawnSync("sh", ["-c", `openssl dgst -sha256 -mac HMAC -macopt key:${TOKEN} -binary signed-message.txt | openssl base64 -A`], { cwd: work, encoding: "utf8" }).stdout.trim();
        assert.equal(mac, b.files["manifest.mac"]);
      } finally { rmTree(work); }
    }
  } finally { rmTree(dir); }
});

test("zip: stored entries in manifest order, readable by unzip, deterministic", () => {
  const dir = fixedDir();
  try {
    const b = build(dir);
    const z1 = deviceBundleZip(b), z2 = deviceBundleZip(build(dir));
    assert.ok(z1.equals(z2), "same inputs, same bytes");
    assert.equal(z1.readUInt32LE(0), 0x04034b50);
    assert.equal(z1.readUInt16LE(8), 0, "method 0: stored");
    if (spawnSync("unzip", ["-v"], { encoding: "utf8" }).status === 0) {
      const work = mkdtempSync(join(tmpdir(), "moorai-bundle-zip-"));
      try {
        writeFileSync(join(work, "b.zip"), z1);
        const l = spawnSync("unzip", ["-Z1", "b.zip"], { cwd: work, encoding: "utf8" });
        assert.equal(l.status, 0, l.stderr);
        assert.deepEqual(l.stdout.trim().split("\n"), ["manifest.json", "manifest.mac", "VERIFY.txt", "alerts.jsonl"]);
        assert.equal(spawnSync("unzip", ["-tq", "b.zip"], { cwd: work }).status, 0);
      } finally { rmTree(work); }
    }
  } finally { rmTree(dir); }
});

test("--include-trail adds actions.jsonl from the allow-trail queue", () => {
  const dir = fixedDir();
  try {
    writeFileSync(join(dir, "action-trail.jsonl"), JSON.stringify({ ts: "2026-10-21T09:00:00.000Z", seq: 1, event: "PreToolUse", tool: "Bash", decision: "allow", basis: "default" }) + "\n{torn\n");
    const b = build(dir, { includeTrail: true });
    assert.equal(b.files["actions.jsonl"].trim().split("\n").length, 1);
    assert.deepEqual(JSON.parse(b.files["manifest.json"]).files.map((f) => f.path), ["VERIFY.txt", "alerts.jsonl", "actions.jsonl"]);
  } finally { rmTree(dir); }
});

test("export copies, never removes: the outbox is unchanged after a bundle", () => {
  const dir = fixedDir();
  try {
    const before = readFileSync(join(dir, "alert-outbox.jsonl"), "utf8");
    build(dir);
    assert.equal(readFileSync(join(dir, "alert-outbox.jsonl"), "utf8"), before);
  } finally { rmTree(dir); }
});

test("no install token: no bundle", () => {
  const dir = fixedDir();
  try { assert.throws(() => buildDeviceBundle({ config: { serverUrl: "x", tenant: "acme" }, dir, now: CREATED }), /install token/); }
  finally { rmTree(dir); }
});

test("golden fixture: regenerated deterministically from the fixed inputs", () => {
  const dir = fixedDir();
  try {
    const b = build(dir);
    const golden = {
      note: "Generated by test/moorai-outbox.test.mjs from fixed inputs (MOORAI_UPDATE_GOLDEN=1 rewrites it). The console's test/fixtures/device-bundle/golden.json is a byte-identical copy.",
      installToken: TOKEN, tenant: CONFIG.tenant, createdAt: CREATED.toISOString(), bundleId: BUNDLE_ID,
      manifestSha256: b.manifestSha256, files: b.files, zipBase64: deviceBundleZip(b).toString("base64")
    };
    const text = JSON.stringify(golden, null, 2) + "\n";
    if (process.env.MOORAI_UPDATE_GOLDEN === "1") { mkdirSync(dirname(GOLDEN), { recursive: true }); writeFileSync(GOLDEN, text); }
    assert.ok(existsSync(GOLDEN), "golden fixture missing (run with MOORAI_UPDATE_GOLDEN=1)");
    assert.equal(readFileSync(GOLDEN, "utf8"), text);
  } finally { rmTree(dir); }
});

test("CLI: status --json and export --out write what the functions build", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-bundle-cli-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify(CONFIG));
    enqueueAlerts([{ threatId: 1, category: "x", riskLevel: "High", stage: "file", tool: "Read", ts: "2026-10-21T09:00:00.000Z", contentHash: "h2:x", seq: 3, chainHead: "f".repeat(64) }], { via: "deferred", dir: join(home, ".moorai") });
    const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home };
    const s = spawnSync(process.execPath, [CLI, "status", "--json"], { env, encoding: "utf8" });
    assert.equal(s.status, 0, s.stderr);
    const st = JSON.parse(s.stdout);
    assert.equal(st.pending, 1);
    assert.equal(st.state, "pending");
    const out = join(home, "b.zip");
    const e = spawnSync(process.execPath, [CLI, "export", "--out", out], { env, encoding: "utf8" });
    assert.equal(e.status, 0, e.stderr);
    assert.equal(readFileSync(out).readUInt32LE(0), 0x04034b50);
    const again = spawnSync(process.execPath, [CLI, "export", "--out", out], { env, encoding: "utf8" });
    assert.notEqual(again.status, 0, "an existing file is never overwritten");
    assert.equal(spawnSync(process.execPath, [CLI, "bogus"], { env, encoding: "utf8" }).status, 2);
  } finally { rmTree(home); }
});
