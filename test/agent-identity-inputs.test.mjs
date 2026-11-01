// F12 agent identity (contract F28 §1.1): the console derives agentId = HMAC(tenantKey, "agent:" + agentName +
// "|" + anchor) from fields the agent already sends, so the agent sends nothing new for F12. What the agent
// owes is that every record it emits names the agent in the console's vocabulary (cli/agent-names.mjs
// AGENT_NAMES, or "unknown" where the host cannot be named), next to the device. This file pins that for the
// records this build adds: the credential exposure read log (rolled into byHost keys) and the usage buckets.
//
//   node --test test/agent-identity-inputs.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";
import { AGENT_NAMES } from "../cli/agent-names.mjs";
import { createUsageMeter } from "../model-proxy/token-usage.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const NAMES = new Set([...AGENT_NAMES, "unknown"]);

function box(t) {
  const empty = mkdtempSync(join(tmpdir(), "moorai-agent-id-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: "http://127.0.0.1:1", tenant: "acme", installToken: "tok-test" } });
  t.after(() => { sb.cleanup(); rmTree(empty); });
  mkdirSync(join(sb.home, ".ssh"), { recursive: true });
  writeFileSync(join(sb.home, ".ssh", "id_ed25519"), "k");
  const run = (env) => spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(sb.home, ".ssh", "id_ed25519") }, session_id: "s-1", cwd: sb.proj }),
    env: sb.env(env), encoding: "utf8", timeout: 20000
  });
  return { ...sb, run };
}
const hostsLogged = (home) => readFileSync(join(home, ".moorai", "credential-exposure.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((e) => e.t === "r").map((e) => e.h);

test("CREDENTIAL READ LOG: the agent is named in the console vocabulary: claude-code, an adapter's host, or unknown", (t) => {
  const b = box(t);
  b.run({});
  b.run({ MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: "codex" });
  b.run({ MOORAI_HOOK_HOST: "shim", MOORAI_HOOK_AGENT: "not-an-agent" });
  const hosts = hostsLogged(b.home);
  assert.deepEqual(hosts, ["claude-code", "codex", "unknown"]);
  for (const h of hosts) assert.ok(NAMES.has(h), h);
});

test("USAGE BUCKETS: agentName is in the console vocabulary", async () => {
  const calls = [];
  const m = createUsageMeter({ config: { serverUrl: "http://c.test", installToken: "t" }, identity: { user: "u", device: "d", platform: "darwin" }, enrolled: true, fetch: async (u, i) => { calls.push(JSON.parse(i.body)); return { ok: true, status: 200 }; }, flushMs: 0 });
  for (const agentName of ["claude-code", "model-proxy"]) { const c = m.begin({ provider: "anthropic", model: "claude-fake", agentName }); c.body({ usage: { input_tokens: 1, output_tokens: 1 } }); c.end(); }
  await m.flush();
  for (const b of calls[0].buckets) assert.ok(NAMES.has(b.agentName), b.agentName);
  assert.equal(calls[0].device, "d");
});
