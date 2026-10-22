// moorai-native-settings: compile one policy for every host, and check what is on disk.
// Golden files: test/fixtures/native-settings/<platform>/<host>/<file> from policy.json (a reviewed snapshot;
// regenerate with `node cli/moorai-native-settings.mjs compile --host all --policy
// test/fixtures/native-settings/policy.json --platform <p> --out test/fixtures/native-settings/<p>
// --mcp-identities test/fixtures/native-settings/mcp-identities.json` and review the diff; <p> = linux).
//
//   node --test --import ./test/hermetic-env.mjs test/native-settings-cli.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-native-settings.mjs");
const FIX = join(ROOT, "test", "fixtures", "native-settings");
const run = (args, opts = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", ...opts });

function walk(dir) {
  return readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? walk(p) : [p]; });
}

// File contents do not depend on the platform (only the paths do, tested in native-settings.test.mjs), so
// the one snapshot is checked against all three.
for (const platform of ["darwin", "linux", "win32"]) {
  test(`golden: every host's files for ${platform} match the reviewed snapshot byte for byte`, () => {
    const out = mkdtempSync(join(tmpdir(), "moorai-native-cli-"));
    const r = run(["compile", "--host", "all", "--policy", join(FIX, "policy.json"), "--platform", platform, "--out", out, "--mcp-identities", join(FIX, "mcp-identities.json")]);
    assert.equal(r.status, 0, r.stderr);
    const want = walk(join(FIX, "linux")).map((p) => relative(join(FIX, "linux"), p)).sort();
    const got = walk(out).map((p) => relative(out, p)).sort();
    assert.deepEqual(got, want);
    for (const rel of want) assert.equal(readFileSync(join(out, rel), "utf8"), readFileSync(join(FIX, "linux", rel), "utf8"), rel);
  });
}

test("compile prints one JSON report per host with the file text and the unexpressed list", () => {
  const r = run(["compile", "--host", "claude-code", "--policy", join(FIX, "policy.json"), "--platform", "linux"]);
  assert.equal(r.status, 0, r.stderr);
  const j = JSON.parse(r.stdout);
  assert.equal(j.hosts.length, 1);
  assert.equal(j.hosts[0].host, "claude-code");
  assert.equal(j.hosts[0].files[0].path, "/etc/claude-code/managed-settings.d/50-moorai.json");
  assert.equal(typeof j.hosts[0].files[0].text, "string");
  assert.ok(Array.isArray(j.hosts[0].unexpressed));
});

test("compile refuses an unknown host and a missing policy", () => {
  assert.equal(run(["compile", "--host", "windsurf", "--policy", join(FIX, "policy.json")]).status, 1);
  assert.equal(run(["compile", "--host", "codex", "--policy", "/nonexistent/policy.json"]).status, 2);
});

test("check: in-sync after the compiled files are placed under a root, drift after an edit (exit 3)", () => {
  const root = mkdtempSync(join(tmpdir(), "moorai-native-root-"));
  const c = run(["compile", "--host", "claude-code", "--policy", join(FIX, "policy.json"), "--platform", "linux"]);
  const f = JSON.parse(c.stdout).hosts[0].files[0];
  const p = join(root, f.path);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, f.text);
  let r = run(["check", "--host", "claude-code", "--policy", join(FIX, "policy.json"), "--platform", "linux", "--root", root, "--home", root]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(JSON.parse(r.stdout).hosts["claude-code"].state, "in-sync");
  const doc = JSON.parse(f.text);
  doc.permissions.deny = [];
  writeFileSync(p, JSON.stringify(doc));
  r = run(["check", "--host", "claude-code", "--policy", join(FIX, "policy.json"), "--platform", "linux", "--root", root, "--home", root]);
  assert.equal(r.status, 3);
  assert.equal(JSON.parse(r.stdout).hosts["claude-code"].state, "drift");
});

test("signature: with --pubkey a signed policy compiles, a tampered one is refused", () => {
  const key = generateKeyPairSync("ed25519");
  const policy = JSON.parse(readFileSync(join(FIX, "policy.json"), "utf8"));
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: "t1", iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  const dir = mkdtempSync(join(tmpdir(), "moorai-native-sig-"));
  writeFileSync(join(dir, "policy.json"), JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: "t1", iat, sig } }));
  writeFileSync(join(dir, "policy.pub"), key.publicKey.export({ type: "spki", format: "pem" }));
  const ok = run(["compile", "--host", "codex", "--policy", join(dir, "policy.json"), "--pubkey", join(dir, "policy.pub"), "--tenant", "t1"]);
  assert.equal(ok.status, 0, ok.stderr);
  writeFileSync(join(dir, "bad.json"), JSON.stringify({ ...policy, mcpAllow: ["anything"], policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: "t1", iat, sig } }));
  const bad = run(["compile", "--host", "codex", "--policy", join(dir, "bad.json"), "--pubkey", join(dir, "policy.pub"), "--tenant", "t1"]);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /untrusted/);
  // a signed policy with no key given compiles but says the signature was not checked
  const unchecked = run(["compile", "--host", "codex", "--policy", join(dir, "policy.json")]);
  assert.equal(unchecked.status, 0);
  assert.match(unchecked.stderr, /signature not checked/);
});
