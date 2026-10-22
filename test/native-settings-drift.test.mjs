// Drift between what MoorAI compiles for each host and what is on disk (cli/native-settings-drift.mjs).
// Files are written under a temp root that stands in for "/", so no system path is touched.
//
//   node --test --import ./test/hermetic-env.mjs test/native-settings-drift.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { nativeSettings, renderFile } from "../cli/native-settings.mjs";
import { nativeDrift, nativeSettingsPosture, resolveNativePath } from "../cli/native-settings-drift.mjs";

const POLICY = {
  tagActions: { exec: "block" },
  mcpAllow: ["github"],
  egressRules: [{ host: "evil.example.com", action: "block" }, { host: "*.example.com", action: "allow" }],
  egressDefault: "block"
};

function rootWith(host, { mutate, platform = "linux", policy = POLICY } = {}) {
  const root = mkdtempSync(join(tmpdir(), "moorai-native-")), home = join(root, "home");
  const r = nativeSettings(policy, host, { platform });
  for (const f of r.files) {
    const p = resolveNativePath(f.path, { root, home });
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, renderFile(f));
  }
  if (mutate) mutate(r, (f) => resolveNativePath(f.path, { root, home }));
  return { root, home, r };
}

test("in sync: the compiled files on disk read back as in-sync", () => {
  for (const host of ["claude-code", "codex", "copilot", "cursor", "gemini"]) {
    const { root, home } = rootWith(host);
    const d = nativeDrift(nativeSettings(POLICY, host, { platform: "linux" }), { root, home });
    assert.equal(d.state, "in-sync", `${host}: ${JSON.stringify(d)}`);
  }
});

test("drift: a deny entry removed by hand is a weakening finding on that key", () => {
  const { root, home, r } = rootWith("claude-code", {
    mutate: (r, at) => {
      const p = at(r.files[0]);
      const c = JSON.parse(readFileSync(p, "utf8"));
      c.permissions.deny = c.permissions.deny.filter((x) => x !== "Bash");
      writeFileSync(p, JSON.stringify(c));
    }
  });
  const d = nativeDrift(r, { root, home });
  assert.equal(d.state, "drift");
  assert.deepEqual(d.files[0].findings, [{ key: "permissions.deny", kind: "missing-entries", count: 1, weakens: true }]);
});

test("drift: an extra allow-list entry widens; an extra deny entry does not", () => {
  const { root, home, r } = rootWith("claude-code", {
    mutate: (r, at) => {
      const p = at(r.files[0]);
      const c = JSON.parse(readFileSync(p, "utf8"));
      c.allowedMcpServers.push({ serverName: "other" });
      c.permissions.deny.push("Read");
      writeFileSync(p, JSON.stringify(c));
    }
  });
  const d = nativeDrift(r, { root, home });
  assert.equal(d.state, "drift");
  assert.deepEqual(d.files[0].findings, [{ key: "allowedMcpServers", kind: "extra-entries", count: 1, weakens: true }, { key: "permissions.deny", kind: "extra-entries", count: 1, weakens: false }]);
});

test("drift: a scalar flipped and a key deleted", () => {
  const { root, home, r } = rootWith("claude-code", {
    mutate: (r, at) => {
      const p = at(r.files[0]);
      const c = JSON.parse(readFileSync(p, "utf8"));
      c.sandbox.enabled = false;
      delete c.allowManagedMcpServersOnly;
      writeFileSync(p, JSON.stringify(c));
    }
  });
  const f = nativeDrift(r, { root, home }).files[0].findings;
  assert.deepEqual(f, [{ key: "allowManagedMcpServersOnly", kind: "key-absent", weakens: true }, { key: "sandbox.enabled", kind: "value-changed", weakens: true }]);
});

test("drift: a whole-file TOML edited by hand is content-changed", () => {
  const { root, home, r } = rootWith("codex", {
    mutate: (r, at) => { const p = at(r.files[0]); writeFileSync(p, readFileSync(p, "utf8").replace('"deny"', '"allow"')); }
  });
  const d = nativeDrift(r, { root, home });
  assert.equal(d.state, "drift");
  assert.deepEqual(d.files[0].findings, [{ key: "*", kind: "content-changed", weakens: true }]);
});

test("drift: a key-merged file ignores keys MoorAI does not own", () => {
  const { root, home, r } = rootWith("cursor", {
    mutate: (r, at) => {
      const p = at(r.files[0]);
      const c = JSON.parse(readFileSync(p, "utf8"));
      writeFileSync(p, JSON.stringify({ ...c, editor: { vimMode: true }, version: 1 }));
    }
  });
  assert.equal(nativeDrift(r, { root, home }).state, "in-sync");
});

test("absent and unreadable files", () => {
  const root = mkdtempSync(join(tmpdir(), "moorai-native-"));
  const r = nativeSettings(POLICY, "claude-code", { platform: "linux" });
  assert.equal(nativeDrift(r, { root, home: root }).state, "absent");
  // a directory where the file should be cannot be read as a file
  mkdirSync(resolveNativePath(r.files[0].path, { root, home: root }), { recursive: true });
  assert.equal(nativeDrift(r, { root, home: root }).state, "unreadable");
  // a file that is not JSON
  const root2 = mkdtempSync(join(tmpdir(), "moorai-native-"));
  const p = resolveNativePath(r.files[0].path, { root: root2, home: root2 });
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, "{ not json");
  assert.equal(nativeDrift(r, { root: root2, home: root2 }).state, "unreadable");
});

test("posture: one content-free record per host for the heartbeat", () => {
  const { root, home } = rootWith("claude-code", {
    mutate: (r, at) => {
      const p = at(r.files[0]);
      const c = JSON.parse(readFileSync(p, "utf8"));
      c.permissions.deny = [];
      writeFileSync(p, JSON.stringify(c));
    }
  });
  const pos = nativeSettingsPosture({ policy: POLICY, platform: "linux", root, home });
  assert.equal(pos.v, 1);
  assert.deepEqual(Object.keys(pos.hosts), ["claude-code", "codex", "copilot", "cursor", "gemini"]);
  assert.deepEqual(pos.hosts["claude-code"], { state: "drift", files: 1, findings: 1, weakening: 1, unexpressed: pos.hosts["claude-code"].unexpressed });
  assert.equal(pos.hosts.codex.state, "absent");
  assert.equal(nativeSettingsPosture({ policy: {}, platform: "linux", root, home }).hosts.codex.state, "not-applicable");
  const s = JSON.stringify(pos);
  for (const leak of ["Bash", "github", "example.com", root]) assert.ok(!s.includes(leak), `posture leaks ${leak}`);
});
