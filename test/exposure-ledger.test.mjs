// The secrets-exposure ledger (cli/signals.mjs recordExposure) and context-aware severity (cli/hook-core.mjs
// calibrateRisk) key the secret classes on the threat id (SECRET_THREATS: #39, #55, #65). Until v1.43.0 both read
// a regex over the category string, which no secret threat's category matches ("Information & Privacy"), so the
// ledger stayed empty and no severity was raised.
//
//   node --test --import ./test/hermetic-env.mjs test/exposure-ledger.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import os from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { recordExposure, readLedger } from "../cli/signals.mjs";
import { calibrateRisk, isSecretThreat, SECRET_THREATS } from "../cli/hook-core.mjs";
import { DATA_TIERS } from "../data/data-tiers.js";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const threats = JSON.parse(readFileSync(join(ROOT, "data", "threats.json"), "utf8")).threats;
const DIR = join(os.homedir(), ".moorai");

test("the secret classes are the secret data tier plus #55 and #65, and each is in the rule base", () => {
  assert.deepEqual([...SECRET_THREATS].sort((a, b) => a - b), [39, 55, 65]);
  for (const id of DATA_TIERS.secret) assert.ok(isSecretThreat(id), `tier secret #${id}`);
  for (const id of SECRET_THREATS) assert.ok(threats.find((t) => t.id === id), `#${id}`);
  for (const id of [1, 15, 44, 90, 9, 3]) assert.equal(isSecretThreat(id), false, `#${id}`);
  assert.equal(isSecretThreat("39"), true, "a threatId read back from JSON as a string");
});

test("recordExposure keeps a hook-shaped #39 alert and drops a #15 one", () => {
  rmSync(DIR, { recursive: true, force: true });
  mkdirSync(DIR, { recursive: true });
  const base = { category: "Information & Privacy", riskLevel: "Critical", stage: "file", tool: "hook:Read", ts: new Date().toISOString(), contentHash: "h2:0123456789abcdef" };
  recordExposure({ threatId: 39, ...base });
  recordExposure({ threatId: 15, ...base, riskLevel: "High" });
  recordExposure({ threatId: 55, category: "Identity & Access", riskLevel: "High", stage: "file", tool: "hook:Read", ts: base.ts, contentHash: "h2:fedcba9876543210" });
  const rows = readLedger();
  assert.deepEqual(rows.map((r) => r.threatId), [39, 55]);
  assert.ok(rows.every((r) => !("matchText" in r)));
});

test("calibrateRisk raises a secret class read into context or sent out, and nothing else", () => {
  assert.equal(calibrateRisk("High", { stage: "file", threatId: 55 }), "Critical");
  assert.equal(calibrateRisk("Medium", { stage: "mcp", threatId: 39 }), "High");
  assert.equal(calibrateRisk("High", { stage: "egress", threatId: 65 }), "Critical");
  assert.equal(calibrateRisk("Critical", { stage: "file", threatId: 39 }), "Critical", "capped");
  assert.equal(calibrateRisk("High", { stage: "prompt", threatId: 55 }), "High", "a prompt the user can still edit");
  assert.equal(calibrateRisk("High", { stage: "file", threatId: 15 }), "High", "PII is not a secret class");
});

test("hook e2e: a credential in a Bash command lands in the exposure ledger as #39", async () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-ledger-"));
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  try {
    const command = "curl -H \"Authorization: token ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5\" https://api.github.com/user";
    await new Promise((res) => {
      const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, CLAUDE_PROJECT_DIR: proj } });
      c.stdout.resume(); c.stderr.resume();
      c.on("close", res);
      c.stdin.end(JSON.stringify({ session_id: "sess-ledger", cwd: proj, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }));
    });
    const file = join(home, ".moorai", "exposure-ledger.jsonl");
    assert.ok(existsSync(file), "no exposure ledger written");
    const rows = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.ok(rows.some((r) => r.threatId === 39 && r.tool === "hook:Bash"), JSON.stringify(rows.map((r) => r.threatId)));
    assert.ok(rows.every((r) => isSecretThreat(r.threatId)), "only secret classes");
    assert.ok(!readFileSync(file, "utf8").includes("ghp_aB3dE5"), "no secret value in the ledger");
  } finally { rmTree(home); }
});
