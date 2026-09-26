// Per-file runner:  node --test test/cred-safer-hint.test.mjs
//
// #55 (credential / secret-file access) names a safer way to do the task, and that line has to fit the
// credential the agent actually reached for. A single per-threat line told an agent reading
// ~/.aws/credentials to "Read .env.example for the variable names", which is advice for a different
// file. The hint is picked per credential KIND from a fixed table (data/cred-alternatives.js); it is
// fixed text, so it never carries the matched path or any other part of the input.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine, decideText, decideCredFileRead } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const { threats } = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const T55 = threats.find((t) => t.id === 55);

const HINT = {
  aws: "Let the AWS CLI or SDK load the profile itself; `aws sts get-caller-identity` or `aws configure list` (keys masked) shows which identity is active.",
  ssh: "Let ssh use the key through ssh-agent; `ssh-add -l` lists loaded keys by fingerprint. Never read the private key itself.",
  kube: "Let kubectl load the kubeconfig; `kubectl config current-context` or `kubectl config view --minify` (secrets redacted by default) shows the active context.",
  npm: "Let npm read .npmrc itself; `npm whoami` shows which account the registry token belongs to.",
  env: "Read .env.example for the variable names and let the app load the values at runtime.",
  generic: "Let the tool that owns the credential load it at runtime, and check the active identity with that tool's own command instead of reading the secret file."
};

// [command, expected kind, the path the hint must never contain]
const CASES = [
  ["cat ~/.aws/credentials", "aws", "~/.aws/credentials"],
  ["awk '/aws_access_key_id/' ~/.aws/credentials", "aws", "~/.aws/credentials"],
  ["cat ~/.ssh/id_ed25519", "ssh", "~/.ssh/id_ed25519"],
  ["cat ~/.kube/config", "kube", "~/.kube/config"],
  ["cat .env", "env", "cat .env"],
  ["cat ~/.npmrc", "npm", "~/.npmrc"],
  ["cat ~/.pgpass", "generic", "~/.pgpass"]
];

const engine = buildEngine(null);
const noPath = (hint, path) => {
  assert.ok(!hint.includes(path), `hint echoes the matched path ${path}: ${hint}`);
  assert.ok(!hint.includes("~/"), `hint carries a home-relative path: ${hint}`);
};

test("threats.json #55 carries the generic fallback, not the .env-specific line", () => {
  assert.equal(T55.saferAlternative, HINT.generic);
});

for (const [cmd, kind, path] of CASES) {
  test(`decideText: ${cmd} → the ${kind} hint`, () => {
    const d = decideText(engine, null, cmd, "prompt");
    assert.ok(d.findings.some((f) => f.threatId === 55), `#55 must fire on ${cmd}`);
    assert.notEqual(d.decision, "allow");
    assert.equal(d.alternatives[0], HINT[kind]);
    noPath(d.alternatives[0], path);
  });
}

test("decideCredFileRead: a Read of the path gets the same kind's hint", () => {
  for (const [p, kind] of [["~/.aws/credentials", "aws"], ["/home/u/.ssh/id_rsa", "ssh"], ["/home/u/.kube/config", "kube"], ["/srv/app/.env", "env"], ["/home/u/.npmrc", "npm"], ["/home/u/.pgpass", "generic"]]) {
    const d = decideCredFileRead(engine, null, p);
    assert.notEqual(d.decision, "allow", p);
    assert.equal(d.alternatives[0], HINT[kind], p);
    noPath(d.alternatives[0], p);
  }
});

function sandbox() {
  const home = mkdtempSync(join(tmpdir(), "moorai-credhint-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "credhint", installToken: "tok-credhint" }));
  return home;
}
function runHook(home, payload) {
  const res = spawnSync("node", [HOOK], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", session_id: "ch", ...payload }),
    cwd: home, encoding: "utf8", timeout: 30000,
    env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "credhint" }
  });
  assert.equal(res.status, 0, res.stderr);
  const out = (res.stdout || "").trim();
  if (!out) return { decision: "allow", reason: "" };
  const o = JSON.parse(out).hookSpecificOutput || {};
  return { decision: o.permissionDecision || "allow", reason: o.permissionDecisionReason || "" };
}
const saferPart = (reason) => { const i = reason.indexOf(" Safer: "); return i < 0 ? "" : reason.slice(i + 8); };

test("hook end to end: each Bash read gets its kind's hint, and the hint never echoes the path", () => {
  const home = sandbox();
  try {
    for (const [cmd, kind, path] of CASES) {
      const r = runHook(home, { tool_name: "Bash", tool_input: { command: cmd } });
      assert.notEqual(r.decision, "allow", cmd);
      assert.match(r.reason, /#55 Identity & Access/, cmd);
      assert.equal(saferPart(r.reason), HINT[kind], `${cmd}: ${r.reason}`);
      noPath(saferPart(r.reason), path);
    }
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("hook end to end: a Read of ~/.aws/credentials gets the AWS hint", () => {
  const home = sandbox();
  try {
    const f = join(home, ".aws", "credentials");
    mkdirSync(dirname(f), { recursive: true });
    writeFileSync(f, "[default]\nregion = us-east-1\n");
    const r = runHook(home, { tool_name: "Read", tool_input: { file_path: f } });
    assert.notEqual(r.decision, "allow");
    assert.equal(saferPart(r.reason), HINT.aws, r.reason);
    noPath(saferPart(r.reason), f);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
