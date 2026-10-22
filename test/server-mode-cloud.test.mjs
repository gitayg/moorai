// Cloud coding agents in server mode (cli/server-mode.mjs, CONTRACT-F28 §5): the workload id, the OIDC
// switch, the cloud host and the cloudAgent heartbeat field; the settings-file refusal for the new names.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/server-mode-cloud.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveServerMode, cloudAgentPosture, isGuarded, ENV, CLOUD_HOSTS, WORKLOAD_ATTESTATIONS } from "../cli/server-mode.mjs";

const base = { MOORAI_MODE: "server" };
const WID = "wkl-5c1e0a9b2d3f";
const MWT = "mwt_" + "A".repeat(43);

test("the contract's enums", () => {
  assert.deepEqual([...CLOUD_HOSTS], ["copilot-coding-agent", "codex-cloud", "claude-code-web", "ci", "other"]);
  assert.deepEqual([...WORKLOAD_ATTESTATIONS], ["github-oidc", "static-token"]);
  assert.equal(ENV.workloadId, "MOORAI_WORKLOAD_ID");
  assert.equal(ENV.oidc, "MOORAI_OIDC");
  assert.equal(ENV.cloudHost, "MOORAI_CLOUD_HOST");
});

test("workload id: system file > env; only wkl- + 12 hex is accepted", () => {
  let s = resolveServerMode({ env: { ...base, MOORAI_WORKLOAD_ID: WID } });
  assert.equal(s.workloadId, WID);
  assert.equal(s.sources.workloadId, "env");
  s = resolveServerMode({ env: { ...base, MOORAI_WORKLOAD_ID: WID }, system: { mode: "server", workloadId: "wkl-000000000001" } });
  assert.equal(s.workloadId, "wkl-000000000001");
  assert.equal(s.sources.workloadId, "system");
  for (const bad of ["wkl-XYZ", "wkl-5c1e0a9b2d3", "act-5c1e0a9b2d3f", " wkl-5c1e0a9b2d3f0"]) assert.equal(resolveServerMode({ env: { ...base, MOORAI_WORKLOAD_ID: bad } }).workloadId, "", bad);
});

test("OIDC: only \"github\" turns on the exchange, and only with a workload id", () => {
  assert.equal(resolveServerMode({ env: { ...base, MOORAI_OIDC: "github", MOORAI_WORKLOAD_ID: WID } }).oidc, "github");
  assert.equal(resolveServerMode({ env: { ...base, MOORAI_OIDC: "GitHub", MOORAI_WORKLOAD_ID: WID } }).oidc, "github");
  assert.equal(resolveServerMode({ env: { ...base, MOORAI_OIDC: "gitlab", MOORAI_WORKLOAD_ID: WID } }).oidc, "");
  assert.equal(resolveServerMode({ env: { ...base, MOORAI_OIDC: "github" } }).oidc, "");
  assert.equal(resolveServerMode({ env: base, system: { mode: "server", oidc: "github", workloadId: WID } }).oidc, "github");
});

test("cloud host: system file > env > CLAUDE_CODE_REMOTE; unknown values are dropped", () => {
  assert.equal(resolveServerMode({ env: { ...base, MOORAI_CLOUD_HOST: "copilot-coding-agent" } }).cloudHost, "copilot-coding-agent");
  assert.equal(resolveServerMode({ env: { ...base, MOORAI_CLOUD_HOST: "my-laptop" } }).cloudHost, "");
  let s = resolveServerMode({ env: { ...base, CLAUDE_CODE_REMOTE: "true" } });
  assert.equal(s.cloudHost, "claude-code-web");
  assert.equal(s.sources.cloudHost, "detected");
  assert.equal(resolveServerMode({ env: { ...base, CLAUDE_CODE_REMOTE: "1" } }).cloudHost, "");
  s = resolveServerMode({ env: { ...base, MOORAI_CLOUD_HOST: "ci" }, system: { mode: "server", cloudHost: "codex-cloud" } });
  assert.equal(s.cloudHost, "codex-cloud");
});

test("cloudAgent heartbeat field: host plus attestation, null when not a cloud agent", () => {
  assert.equal(cloudAgentPosture(resolveServerMode({ env: {} })), null);
  assert.equal(cloudAgentPosture(resolveServerMode({ env: base })), null);
  assert.equal(cloudAgentPosture(null), null);
  // A static token (mwt_ or a classic install token) reads static-token.
  assert.deepEqual(cloudAgentPosture(resolveServerMode({ env: { ...base, MOORAI_CLOUD_HOST: "claude-code-web", MOORAI_INSTALL_TOKEN: MWT } })), { host: "claude-code-web", attestation: "static-token" });
  // A token the setup step minted through the OIDC exchange is recorded as such in the root-owned file.
  const sys = { mode: "server", cloudHost: "copilot-coding-agent", installToken: MWT, workloadId: WID, workloadAttestation: "github-oidc" };
  assert.deepEqual(cloudAgentPosture(resolveServerMode({ env: base, system: sys })), { host: "copilot-coding-agent", attestation: "github-oidc" });
  // github-oidc from the environment is not believed: the environment is not where a minted token is recorded.
  assert.deepEqual(cloudAgentPosture(resolveServerMode({ env: { ...base, MOORAI_CLOUD_HOST: "ci", MOORAI_INSTALL_TOKEN: MWT, MOORAI_WORKLOAD_ATTESTATION: "github-oidc" } })), { host: "ci", attestation: "static-token" });
  // github-oidc recorded in the file while the token in force came from the environment is not believed.
  assert.deepEqual(cloudAgentPosture(resolveServerMode({ env: { ...base, MOORAI_INSTALL_TOKEN: MWT }, system: { mode: "server", cloudHost: "copilot-coding-agent", workloadAttestation: "github-oidc" } })), { host: "copilot-coding-agent", attestation: "static-token" });
  // github-oidc without an mwt_ token in force is not believed either.
  assert.deepEqual(cloudAgentPosture(resolveServerMode({ env: base, system: { ...sys, installToken: "classic-install-token" } })), { host: "copilot-coding-agent", attestation: "static-token" });
});

test("a settings file's env block cannot set the new names (MOORAI_ prefix is guarded)", () => {
  for (const n of ["MOORAI_WORKLOAD_ID", "MOORAI_OIDC", "MOORAI_CLOUD_HOST"]) assert.ok(isGuarded(n), n);
  const hits = [{ file: "/repo/.claude/settings.json", keys: ["MOORAI_CLOUD_HOST", "MOORAI_OIDC", "MOORAI_WORKLOAD_ID"] }];
  const s = resolveServerMode({ env: { ...base, MOORAI_WORKLOAD_ID: WID, MOORAI_OIDC: "github", MOORAI_CLOUD_HOST: "ci" }, hits });
  assert.equal(s.workloadId, "");
  assert.equal(s.oidc, "");
  assert.equal(s.cloudHost, "");
  assert.deepEqual(s.refused, ["MOORAI_CLOUD_HOST", "MOORAI_OIDC", "MOORAI_WORKLOAD_ID"]);
  // A managed settings env block is trusted.
  const m = resolveServerMode({ env: { ...base, MOORAI_CLOUD_HOST: "ci" }, hits, managed: ["MOORAI_CLOUD_HOST"] });
  assert.equal(m.cloudHost, "ci");
});

test("server mode off: no cloud fields are resolved", () => {
  const s = resolveServerMode({ env: { MOORAI_CLOUD_HOST: "ci", MOORAI_WORKLOAD_ID: WID, CLAUDE_CODE_REMOTE: "true" } });
  assert.equal(s.active, false);
  assert.equal(s.cloudHost, undefined);
  assert.equal(s.workloadId, undefined);
});
