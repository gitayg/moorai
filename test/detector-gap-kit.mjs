// Shared harness for the ATT&CK v20 gap tests (root-ca-install, shell-history, ssh-authorized-keys, …):
// the shipped engine, a findings list per text, the per-pattern linear-time check and the real hook run
// end to end with no org policy. Not a test file itself (no .test.mjs suffix).
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as DETECTOR_MODULE from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { scalingRatio } from "./timing.mjs";
import { rmTree } from "./fs-cleanup.mjs";

export { DETECTOR_MODULE };
export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
export const engine = new DetectionEngine(threats, DETECTOR_MODULE.DETECTORS, CONTENT_RULES);
export const scan = (text, stage = "prompt", ctx) => engine.scan(text, stage, ctx).map((f) => `${f.detectorId}#${f.threat.id}`);
export const credit = (threatId, techniqueId) => threats.threats.find((t) => t.id === threatId).attack.find((x) => x.id === techniqueId);

// A ReDoS is a complexity change: 4x the input may cost at most 10x (linear reads ~4x, quadratic ~16x).
// Each pattern is timed on its own, because a detector stops at its first matching pattern.
// inputs: [prefix, repeated unit, repeat count at ~60 KB]
export function assertLinear(patterns, inputs) {
  for (const rx of patterns) {
    for (const [pre, unit, n] of inputs) {
      const s = pre + unit.repeat(n), big = pre + unit.repeat(n * 4);
      const r = scalingRatio(() => rx.test(s), () => rx.test(big), 3, 10);
      assert.ok(r.ratio < 10, `${rx} on ${JSON.stringify(unit)}: 4x the input cost ${r.ratio.toFixed(2)}x`);
    }
  }
}

// One PreToolUse call through the real hook, no org policy. Returns the permission decision.
export function runHook(home, tool_name, tool_input, env = {}) {
  const res = spawnSync("node", [join(ROOT, "cli", "moorai-hook.mjs")], {
    input: JSON.stringify({ session_id: "gap-kit", hook_event_name: "PreToolUse", tool_name, tool_input }),
    cwd: home,
    encoding: "utf8",
    timeout: 30000,
    env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "gap-kit", ...env }
  });
  assert.equal(res.status, 0, res.stderr);
  const out = (res.stdout || "").trim();
  if (!out) return "allow";
  return JSON.parse(out).hookSpecificOutput?.permissionDecision || "allow";
}

export function withHome(fn, policy) {
  const home = mkdtempSync(join(tmpdir(), "moorai-gap-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "gap-kit", installToken: "tok-gap-kit" }));
    if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
    return fn(home);
  } finally { rmTree(home); }
}
