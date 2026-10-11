// The registry mirrors and the offline switch (cli/mcp-package/endpoints.mjs) decide where the MCP guard's
// and gateway's reputation lookup (policy mcpReputation.lookup = "registry") gets a package's metadata and
// tarball, and whether it looks at all. Claude Code applies a settings file's `env` block to the session,
// and the hook and the stdio MCP servers it starts inherit it, so a cloned repository's
// .claude/settings.json, or the agent editing ~/.claude/settings.json, could point the lookup at a mirror
// that serves a clean copy of a malicious package (npx still runs the real one), or turn it off. These
// names now follow the hook's trusted-environment rule (cli/server-mode.mjs trustedEnv): a value a user,
// project or local settings file sets is ignored; the shell environment and managed settings still work.
//
//   node --test --import ./test/hermetic-env.mjs test/registry-env-trust.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessServer } from "../cli/mcp-reputation.mjs";
import { _resetEnvTrustForTests } from "../cli/server-mode.mjs";
import { endpoint, isOffline, DEFAULT_ENDPOINTS, MIRROR_ENV } from "../cli/mcp-package/endpoints.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const NAMES = [...Object.values(MIRROR_ENV), "MOORAI_OFFLINE", "CLAUDE_PROJECT_DIR"];

async function session(settingsEnv, processEnv, fn) {
  const root = mkdtempSync(join(tmpdir(), "moorai-regtrust-"));
  const proj = join(root, "proj"), stateDir = join(root, "state"), home = join(root, "home");
  for (const d of [join(proj, ".claude"), stateDir, home]) mkdirSync(d, { recursive: true });
  if (settingsEnv) writeFileSync(join(proj, ".claude", "settings.json"), JSON.stringify({ env: settingsEnv }));
  const saved = Object.fromEntries(NAMES.map((k) => [k, process.env[k]]));
  for (const k of NAMES) delete process.env[k];
  Object.assign(process.env, { CLAUDE_PROJECT_DIR: proj }, processEnv);
  _resetEnvTrustForTests();
  try { return await fn({ stateDir, home }); } finally {
    for (const k of NAMES) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    _resetEnvTrustForTests();
    rmTree(root);
  }
}
function recorder() {
  const calls = [];
  return { calls, fetchImpl: async (url) => { calls.push(String(url)); return new Response("", { status: 599 }); } };
}
const DECL = { command: "npx", args: ["-y", "some-new-mcp@1.0.0"] };

test("TRUST: a mirror a repository's settings file sets does not steer the guard's reputation lookup", () =>
  session({ MOORAI_NPM_REGISTRY: "https://npm.evil.test/" }, { MOORAI_NPM_REGISTRY: "https://npm.evil.test/" }, async ({ stateDir, home }) => {
    const { calls, fetchImpl } = recorder();
    await assessServer(DECL, { stateDir, home, fetchImpl, policy: { lookup: "registry" } });
    assert.deepEqual(calls.filter((u) => u.includes("evil")), [], calls.join("\n"));
    assert.ok(calls.some((u) => u.startsWith(DEFAULT_ENDPOINTS.npm)), calls.join("\n"));
  }));

test("TRUST: MOORAI_OFFLINE from a settings file does not switch the guard's reputation lookup off", () =>
  session({ MOORAI_OFFLINE: "1" }, { MOORAI_OFFLINE: "1" }, async ({ stateDir, home }) => {
    const { calls, fetchImpl } = recorder();
    const rep = await assessServer(DECL, { stateDir, home, fetchImpl, policy: { lookup: "registry" } });
    assert.ok(calls.length >= 1, "the lookup was skipped");
    assert.ok(!rep.evidence.includes("registry-not-checked-offline"), JSON.stringify(rep.evidence));
  }));

test("QUIET: a mirror and the offline switch set in the shell environment still apply", async () => {
  await session(null, { MOORAI_NPM_REGISTRY: "https://npm.mirror.example/" }, async ({ stateDir, home }) => {
    const { calls, fetchImpl } = recorder();
    await assessServer(DECL, { stateDir, home, fetchImpl, policy: { lookup: "registry" } });
    assert.ok(calls.length >= 1 && calls.every((u) => u.startsWith("https://npm.mirror.example/")), calls.join("\n"));
    assert.equal(endpoint("npm"), "https://npm.mirror.example/");
  });
  await session(null, { MOORAI_OFFLINE: "1" }, async ({ stateDir, home }) => {
    const { calls, fetchImpl } = recorder();
    assert.equal(isOffline(), true);
    await assessServer(DECL, { stateDir, home, fetchImpl, policy: { lookup: "registry" } });
    assert.deepEqual(calls, []);
  });
});
