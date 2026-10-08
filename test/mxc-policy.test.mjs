// MXC launch policy (cli/mxc-policy.mjs, mirrored at launch time by src-tauri/src/mxc.rs).
//
// Three layers, each able to fail on its own:
//   1. the golden cases in test/fixtures/mxc/policy-cases.json — the SAME file `cargo test` replays
//      against the Rust builder, so the two implementations cannot drift apart silently;
//   2. every produced policy validates against microsoft/mxc's stable schema 1.0.0
//      (test/fixtures/mxc/mxc-config.schema.1.0.0.json, vendored unmodified from microsoft/mxc @ 7cd00d1,
//      MIT — test/fixtures/mxc/LICENSE-microsoft-mxc.md);
//   3. the security properties stated directly, so a fixture regenerated from a broken builder still
//      fails here.
//
//   node --test test/mxc-policy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import {
  buildMxcPolicy, isUnder, PATH_CLASSES, AGENT_STATE, AGENT_RO, MOORAI_STATE, TOOLCHAIN_RO, AGENT_TMP,
  MXC_SCHEMA_VERSION, DEFAULT_MODEL_PROXY_PORT
} from "../cli/mxc-policy.mjs";

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");
const CASES = JSON.parse(read("test/fixtures/mxc/policy-cases.json"));
const SCHEMA = JSON.parse(read("test/fixtures/mxc/mxc-config.schema.1.0.0.json"));
const existsFrom = (c) => (p) => c.existing === "*" || c.existing.some((e) => e.toLowerCase().replace(/\//g, "\\") === p.toLowerCase());

const ENV = {
  USERPROFILE: "C:\\Users\\dev", APPDATA: "C:\\Users\\dev\\AppData\\Roaming", LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local",
  ProgramData: "C:\\ProgramData", ProgramFiles: "C:\\Program Files", SystemRoot: "C:\\Windows"
};
const input = (o = {}) => ({
  agent: "claude", workspace: "C:\\src\\proj", env: ENV, agentBin: "C:\\Users\\dev\\.local\\bin\\claude.exe",
  commandLine: "C:\\Users\\dev\\.local\\bin\\claude.exe", captureDenials: true,
  denialsOutputPath: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\mxc-runs\\r1\\denials.json", ...o
});

test("golden cases: the Node builder reproduces every expected object (Rust replays the same file)", () => {
  assert.ok(CASES.length >= 8);
  for (const c of CASES) assert.deepStrictEqual(buildMxcPolicy(c.input, { exists: existsFrom(c) }), c.expected, c.name);
});

test("every successful policy validates against microsoft/mxc stable schema 1.0.0", () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  const validate = ajv.compile(SCHEMA);
  let n = 0;
  for (const c of CASES.filter((x) => x.expected.ok)) {
    assert.ok(validate(c.expected.policy), `${c.name}: ${ajv.errorsText(validate.errors)}`);
    n++;
  }
  assert.ok(n >= 5, "schema check ran over the success cases");
  // The validator is live: a field the contract does not define is rejected.
  const bad = structuredClone(CASES[0].expected.policy);
  bad.network.proxy = "http://127.0.0.1:8791";
  assert.equal(validate(bad), false, "retired network.proxy must not validate");
});

test("never mutates host ACLs, never selects an AppContainer fallback", () => {
  const r = buildMxcPolicy(input());
  assert.equal(r.ok, true);
  assert.deepEqual(r.policy.fallback, { allowDaclMutation: false });
  assert.equal(r.policy.version, MXC_SCHEMA_VERSION);
  assert.equal(r.policy.containment, "processcontainer");
  assert.equal(r.policy.processContainer.leastPrivilege, false);
});

test("UI is relaxed exactly enough for PowerShell, and no further", () => {
  const { policy } = buildMxcPolicy(input());
  assert.deepEqual(policy.ui, { disable: false, clipboard: "none", injection: false });
  assert.deepEqual(policy.processContainer.ui, { isolation: "desktop", desktopSystemControl: false, systemSettings: "none", ime: false });
});

test("network: deny-by-default, host loopback for the model proxy, no WinHTTP proxy, numeric allow-list only", () => {
  const { policy } = buildMxcPolicy(input());
  assert.deepEqual(policy.network, { egress: { default: "deny" }, ingress: { default: "deny", hostLoopback: "allow" } });
  assert.equal(policy.runtimeConfig, undefined, "moorai-model-proxy is a base-URL proxy, not a CONNECT proxy");
  assert.ok(policy.process.env.includes(`ANTHROPIC_BASE_URL=http://127.0.0.1:${DEFAULT_MODEL_PROXY_PORT}/anthropic`));
  const codex = buildMxcPolicy(input({ agent: "codex", modelProxyPort: 9900, egressAllow: ["140.82.112.0/20"] })).policy;
  assert.ok(codex.process.env.includes("OPENAI_BASE_URL=http://127.0.0.1:9900/openai"));
  assert.deepEqual(codex.network.egress.allow, [{ to: [{ cidr: "140.82.112.0/20" }], ports: [{ protocol: "tcp", port: 443 }] }]);
  assert.equal(buildMxcPolicy(input({ egressAllow: ["github.com"] })).reasonCode, "egress-not-numeric");
});

test("the profile root is never granted and protected paths never appear in a grant", () => {
  for (const agent of ["claude", "codex", "copilot"]) {
    const { policy } = buildMxcPolicy(input({ agent, hookRoots: ["C:\\Users\\dev\\.ssh\\x", "C:\\Users\\dev\\AppData\\Roaming\\npm\\node_modules\\moorai"] }));
    const grants = [...policy.filesystem.readwritePaths, ...policy.filesystem.readonlyPaths];
    for (const g of grants) {
      assert.ok(!isUnder("C:\\Users\\dev", g), `${agent}: ${g} would expose the whole profile`);
      for (const c of PATH_CLASSES.filter((x) => x.deny)) {
        for (const tpl of c.paths) {
          const p = tpl.replace("{HOME}", "C:\\Users\\dev").replace("{APPDATA}", ENV.APPDATA).replace("{LOCALAPPDATA}", ENV.LOCALAPPDATA).replace("{PROGRAMDATA}", ENV.ProgramData).replace("{SYSTEMROOT}", ENV.SystemRoot);
          assert.ok(!isUnder(g, p), `${agent}: grant ${g} is inside protected ${c.id}`);
        }
      }
    }
    assert.equal(policy.filesystem.readwritePaths[0], "C:\\src\\proj");
  }
  for (const ws of ["C:\\Users\\dev", "C:\\Users", "C:\\", "C:\\Users\\dev\\.aws\\x", "C:\\Windows\\Temp\\x"]) {
    assert.equal(buildMxcPolicy(input({ workspace: ws })).ok, false, `workspace ${ws} must be refused`);
  }
});

test("explicit denies: all protected paths when the host has native FS deny, only carve-outs under a grant otherwise", () => {
  const full = buildMxcPolicy(input({ fsDenySupported: true })).policy.filesystem.deniedPaths;
  assert.ok(full.includes("C:\\Users\\dev\\.ssh") && full.includes("C:\\Users\\dev\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
  assert.deepEqual(buildMxcPolicy(input({ fsDenySupported: false })).policy.filesystem.deniedPaths, []);
  const carved = buildMxcPolicy(input({ fsDenySupported: false, hookRoots: ["C:\\Users\\dev\\Documents"] })).policy.filesystem.deniedPaths;
  assert.deepEqual(carved, ["C:\\Users\\dev\\Documents\\WindowsPowerShell", "C:\\Users\\dev\\Documents\\PowerShell"]);
});

test("git safe.directory is scoped to the workspace, through protected (command-scope) config", () => {
  const env = buildMxcPolicy(input()).policy.process.env;
  assert.deepEqual(env.filter((e) => e.startsWith("GIT_CONFIG_")), ["GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=C:/src/proj"]);
  assert.ok(!env.some((e) => e.endsWith("=*")));
});

test("certificates: extra roots via the additive NODE_EXTRA_CA_CERTS, inherited CA files stay readable", () => {
  const r = buildMxcPolicy(input({ extraCaCerts: "C:\\corp\\roots.pem", env: { ...ENV, SSL_CERT_FILE: "C:\\corp\\bundle.pem" } }));
  assert.ok(r.policy.process.env.includes("NODE_EXTRA_CA_CERTS=C:\\corp\\roots.pem"));
  assert.ok(!r.policy.process.env.some((e) => e.startsWith("SSL_CERT_FILE=")), "SSL_CERT_FILE replaces OpenSSL's bundle; never set it");
  assert.ok(r.policy.filesystem.readonlyPaths.includes("C:\\corp\\roots.pem") && r.policy.filesystem.readonlyPaths.includes("C:\\corp\\bundle.pem"));
});

test("MoorAI's hook keeps working inside: its package readable, its three state legs writable", () => {
  const r = buildMxcPolicy(input({ hookRoots: ["D:\\tools\\moorai"] }));
  assert.ok(r.policy.filesystem.readonlyPaths.includes("D:\\tools\\moorai"));
  for (const leg of ["C:\\Users\\dev\\.moorai", "C:\\Users\\dev\\AppData\\Roaming\\MoorAI", "C:\\Users\\dev\\AppData\\Local\\MoorAI"]) {
    assert.ok(r.policy.filesystem.readwritePaths.includes(leg), leg);
    assert.ok(r.ensureDirs.includes(leg), `host creates ${leg}`);
  }
});

test("trust boundary: the host's install dir and launch state are never granted; broad roots never pass", () => {
  // per-user install at %LOCALAPPDATA%\MoorAI = the hook's breadcrumb leg: the leg is dropped, the dir denied
  const perUser = buildMxcPolicy(input({ hostAppDir: "C:\\Users\\dev\\AppData\\Local\\MoorAI", fsDenySupported: true }));
  const grants = [...perUser.policy.filesystem.readwritePaths, ...perUser.policy.filesystem.readonlyPaths];
  assert.ok(!grants.some((g) => isUnder(g, "C:\\Users\\dev\\AppData\\Local\\MoorAI") || isUnder("C:\\Users\\dev\\AppData\\Local\\MoorAI", g)), grants.join(" | "));
  assert.ok(perUser.policy.filesystem.deniedPaths.includes("C:\\Users\\dev\\AppData\\Local\\MoorAI"));
  assert.equal(buildMxcPolicy(input({ hostAppDir: "C:\\src\\proj\\target" })).reasonCode, "workspace-overlaps-host-app");
  // %LOCALAPPDATA%\MoorAI Host holds mxc.json and the run dirs: protected in every direction
  assert.equal(buildMxcPolicy(input({ workspace: "C:\\Users\\dev\\AppData\\Local\\MoorAI Host\\w" })).reasonCode, "workspace-in-protected");
  assert.equal(buildMxcPolicy(input({ workspace: "C:\\Users\\dev\\AppData\\Local" })).reasonCode, "workspace-contains-protected");
  assert.ok(buildMxcPolicy(input({ fsDenySupported: true })).policy.filesystem.deniedPaths.includes("C:\\Users\\dev\\AppData\\Local\\MoorAI Host"));
  // hook roots naming the profile, its parent or an AppData tree are dropped
  const ro = buildMxcPolicy(input({ hookRoots: ["C:\\Users", "C:\\Users\\dev\\AppData", "C:\\Users\\dev\\AppData\\Roaming", "C:\\Users\\dev\\AppData\\Local", "D:\\tools\\moorai"] })).policy.filesystem.readonlyPaths;
  assert.ok(ro.includes("D:\\tools\\moorai"));
  for (const b of ["C:\\Users", "C:\\Users\\dev\\AppData", "C:\\Users\\dev\\AppData\\Roaming", "C:\\Users\\dev\\AppData\\Local"]) assert.ok(!ro.includes(b), b);
});

test("Rust tables are the JS tables (src-tauri/src/mxc.rs)", () => {
  const rs = read("src-tauri/src/mxc.rs");
  const strs = (block) => [...block.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\\\/g, "\\"));
  const constBlock = (name) => {
    const i = rs.indexOf(`pub const ${name}`);
    assert.ok(i >= 0, `Rust const ${name}`);
    return rs.slice(rs.indexOf("&[", i) + 2, rs.indexOf("];", i));
  };
  assert.deepEqual(strs(constBlock("AGENT_STATE_CLAUDE")), AGENT_STATE.claude);
  assert.deepEqual(strs(constBlock("AGENT_STATE_CODEX")), AGENT_STATE.codex);
  assert.deepEqual(strs(constBlock("AGENT_STATE_COPILOT")), AGENT_STATE.copilot);
  assert.deepEqual(strs(constBlock("AGENT_RO_CLAUDE")), AGENT_RO.claude);
  assert.deepEqual(strs(constBlock("MOORAI_STATE")), MOORAI_STATE);
  assert.deepEqual(strs(constBlock("TOOLCHAIN_RO")), TOOLCHAIN_RO);
  assert.equal(strs(rs.match(/pub const AGENT_TMP: &str = ("[^"]+");/)[1])[0], AGENT_TMP);
  const rows = [...constBlock("PATH_CLASSES").matchAll(/PathClass \{ id: "([^"]+)", risk: "([^"]+)", deny: (true|false), paths: &\[([^\]]*)\] \}/g)]
    .map((m) => ({ id: m[1], risk: m[2], deny: m[3] === "true", paths: strs(m[4]) }));
  assert.deepEqual(rows, PATH_CLASSES);
});

test("CLI writes the same policy the builder returns", () => {
  const cli = fileURLToPath(new URL("../cli/mxc-policy.mjs", import.meta.url));
  const r = spawnSync(process.execPath, [cli, "--agent", "claude", "--workspace", "C:\\src\\proj", "--command", "claude.exe"], { env: { ...process.env, ...ENV }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const expected = buildMxcPolicy({ agent: "claude", workspace: "C:\\src\\proj", commandLine: "claude.exe", env: { ...process.env, ...ENV }, hookRoots: [], egressAllow: [], captureDenials: false });
  assert.deepStrictEqual(JSON.parse(r.stdout), expected.policy);
  const bad = spawnSync(process.execPath, [cli, "--agent", "claude", "--workspace", "C:\\", "--command", "x"], { env: { ...process.env, ...ENV }, encoding: "utf8" });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /workspace-volume-root/);
});
