// Shadow-AI discovery tests. Same throwaway-HOME harness as posture.test.mjs (set env.HOME, clear
// XDG_*), but here the inventory itself is what we control: we run the REAL shadow CLI end-to-end and
// feed it a real AIBOM inventory by seeding the very files the AIBOM reads under a throwaway HOME. That
// proves the whole consume-inventory → classify-against-allow-list chain, not a stub of it.
//
//   node --test test/shadow.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SHADOW = join(ROOT, "cli", "moorai-shadow.mjs");

// Seed the exact sources the AIBOM collectors read: local Ollama models (dir listing), MCP servers
// (~/.claude.json), and editor AI extensions (~/.vscode/extensions dir names). Returns the HOME.
function seedHome({ sanctioned, ollama = [], mcp = {}, extensions = [] } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-shadow-"));
  const olib = join(home, ".ollama/models/manifests/registry.ollama.ai/library");
  for (const name of ollama) mkdirSync(join(olib, name), { recursive: true });
  if (!ollama.length) mkdirSync(olib, { recursive: true });
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: mcp }));
  const ext = join(home, ".vscode/extensions");
  mkdirSync(ext, { recursive: true });
  for (const name of extensions) mkdirSync(join(ext, name), { recursive: true });
  if (sanctioned) {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://localhost:1", tenant: "t", sanctioned }));
  }
  return home;
}

function run(home, args = [], extraEnv = {}) {
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME; // resolve config under the throwaway HOME
  delete env.MOORAI_SANCTIONED; delete env.MOORAI_AIBOM_JSON; // clear ambient BEFORE applying test overrides
  Object.assign(env, extraEnv); // test overrides win
  for (const [k, v] of Object.entries(extraEnv)) if (v === undefined) delete env[k];
  try {
    const stdout = execFileSync(process.execPath, [SHADOW, ...args], { env, encoding: "utf8" });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status ?? 1, stdout: e.stdout?.toString() || "" };
  }
}
const json = (r) => JSON.parse(r.stdout);

// A realistic little device: two local models, two MCP servers, one AI extension.
const BASE = {
  ollama: ["llama3", "qwen2.5-coder"],
  mcp: {
    github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: "x" } },
    filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] }
  },
  extensions: ["anthropic.claude-code-1.2.3", "github.copilot-1.0.0"]
};

test("sanctioned items are excluded; only the unsanctioned ones are reported", () => {
  const home = seedHome({
    ...BASE,
    sanctioned: { models: ["llama3"], mcpServers: ["github"], extensions: ["anthropic.claude-code"] }
  });
  try {
    const d = json(run(home, ["--json"]));
    assert.equal(d.allowlistConfigured, true);
    assert.equal(d.allowlistSource, "config");
    const names = d.shadow.map((x) => x.name);
    // sanctioned → absent
    assert.ok(!names.includes("llama3"), "sanctioned model excluded");
    assert.ok(!names.includes("github"), "sanctioned MCP server excluded");
    assert.ok(!names.includes("anthropic.claude-code"), "sanctioned extension excluded (versionless match)");
    // unsanctioned → present, one per kind
    assert.ok(names.includes("qwen2.5-coder"), "unsanctioned model reported");
    assert.ok(names.includes("filesystem"), "unsanctioned MCP server reported");
    assert.ok(names.includes("github.copilot"), "unsanctioned extension reported");
    assert.equal(d.summary.shadow, 3);
    assert.deepEqual(d.summary.byKind, { model: 1, "mcp-server": 1, extension: 1 });
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("MCP server with network+credential scope ranks 'high' and carries a scope note", () => {
  const home = seedHome({
    mcp: { github: { command: "npx", args: ["@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: "x" }, url: "https://mcp.example" } },
    sanctioned: { models: [], mcpServers: [], extensions: ["nothing"] } // configured, but not for MCP → github is shadow
  });
  try {
    const d = json(run(home, ["--json"]));
    const gh = d.shadow.find((x) => x.name === "github");
    assert.ok(gh, "github surfaced as shadow");
    assert.equal(gh.risk, "high");
    assert.match(gh.note, /network/);
    assert.match(gh.note, /credential/);
    // note is metadata only — no token value anywhere
    assert.ok(!/GITHUB_TOKEN|[=]\s*x\b/.test(JSON.stringify(gh)), "no env value leaks");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("--strict exits 1 when a shadow item exists, 0 when the device is clean", () => {
  const dirty = seedHome({ ...BASE, sanctioned: { models: ["llama3"], mcpServers: ["github"], extensions: ["anthropic.claude-code"] } });
  try {
    assert.equal(run(dirty, ["--strict"]).code, 1, "shadow present → non-zero");
  } finally { rmSync(dirty, { recursive: true, force: true }); }

  const clean = seedHome({
    ollama: ["llama3"], mcp: { github: { command: "x" } }, extensions: ["github.copilot-1.0.0"],
    sanctioned: { models: ["llama3"], mcpServers: ["github"], extensions: ["github.copilot"] }
  });
  try {
    const r = run(clean, ["--strict", "--json"]);
    assert.equal(r.code, 0, "all sanctioned → zero exit");
    assert.equal(json(r).summary.shadow, 0);
  } finally { rmSync(clean, { recursive: true, force: true }); }
});

test("no allow-list configured: everything is 'unclassified', nothing implied sanctioned", () => {
  const home = seedHome(BASE); // no `sanctioned`
  try {
    const r = run(home, ["--json"]);
    const d = json(r);
    assert.equal(d.allowlistConfigured, false);
    assert.equal(d.allowlistSource, "none");
    assert.equal(d.shadow.length, 0, "nothing is called shadow without a list");
    // The AIBOM is HOME-scoped, so a throwaway HOME sees ONLY what seedHome() wrote — assert the six
    // seeded assets are all present-and-unclassified by NAME (robust to any real machine inventory,
    // which never enters the throwaway HOME) rather than pinning a raw total.
    const names = new Set(d.unclassified.map((x) => x.name));
    for (const n of ["llama3", "qwen2.5-coder", "github", "filesystem", "anthropic.claude-code", "github.copilot"])
      assert.ok(names.has(n), `${n} should be unclassified`);
    assert.equal(d.summary.unclassified, d.unclassified.length);
    // human output says so explicitly
    assert.match(run(home).stdout, /No allow-list configured/);
    // --strict must still fail: a device we cannot classify is not attestable
    assert.equal(run(home, ["--strict"]).code, 1);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("MOORAI_SANCTIONED env overrides config (inline JSON) and wins", () => {
  const home = seedHome({ ...BASE, sanctioned: { models: [], mcpServers: [], extensions: [] } });
  try {
    // config sanctions nothing; env sanctions everything in BASE → zero shadow
    const env = { MOORAI_SANCTIONED: JSON.stringify({ models: ["llama3", "qwen2.5-coder"], mcpServers: ["github", "filesystem"], extensions: ["anthropic.claude-code", "github.copilot"] }) };
    const d = json(run(home, ["--json"], env));
    assert.equal(d.allowlistSource, "env");
    assert.equal(d.summary.shadow, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("fail-open: a broken AIBOM snapshot yields a clean partial result, not a crash", () => {
  const home = seedHome({ sanctioned: { models: ["x"], mcpServers: [], extensions: [] } });
  try {
    const r = run(home, ["--json"], { MOORAI_AIBOM_JSON: "/no/such/inventory.json" });
    assert.equal(r.code, 0, "must not crash");
    const d = json(r);
    assert.equal(d.inventoryDegraded, true);
    assert.equal(d.shadow.length, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("output is content-free: only names/metadata, never prompts/tokens/args", () => {
  const home = seedHome({
    mcp: { github: { command: "npx", args: ["--secret-flag", "SUPERSECRETVALUE"], env: { GITHUB_TOKEN: "tok_LEAKME" } } },
    sanctioned: { models: [], mcpServers: [], extensions: ["x"] }
  });
  try {
    const out = run(home, ["--json"]).stdout;
    assert.ok(!out.includes("SUPERSECRETVALUE"), "no arg value in output");
    assert.ok(!out.includes("tok_LEAKME"), "no token value in output");
    assert.ok(!out.includes("GITHUB_TOKEN"), "no env var NAME/value in output");
    assert.ok(out.includes("github"), "server name is present (that IS the content-free datum)");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
