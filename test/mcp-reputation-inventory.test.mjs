// The first-seen MCP reputation in the two inventory surfaces — the AIBOM and shadow-AI discovery — run
// end-to-end as the real CLIs against a throwaway HOME. AIBOM discovery counts as "first sight": it scores
// and caches, offline, and emits nothing but the score, band and category codes.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-reputation-inventory.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");
const SHADOW = join(ROOT, "cli", "moorai-shadow.mjs");
const SECRET = "ghp_inventorySecretValue123";
const LOCAL = "/Users/alice/clients/acme-merger";

function seed() {
  const home = mkdtempSync(join(tmpdir(), "moorai-repinv-"));
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
    files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", LOCAL] },
    squat: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesytem", LOCAL], env: { GITHUB_TOKEN: SECRET } }
  } }));
  return home;
}

function run(cli, home, args = []) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: join(home, "no-probe.json") };
  delete env.MOORAI_SANCTIONED; delete env.MOORAI_AIBOM_JSON;
  return execFileSync(process.execPath, [cli, ...args], { env, encoding: "utf8" });
}

test("AIBOM: every MCP server carries its reputation (score, band, codes), scored offline and cached", () => {
  const home = seed();
  try {
    const bom = JSON.parse(run(AIBOM, home));
    const by = Object.fromEntries(bom.mcpServers.map((s) => [s.name, s]));
    assert.equal(by.files.reputation.band, "good", JSON.stringify(by.files));
    assert.ok(by.squat.reputation.reasons.includes("mcp-typosquat"), JSON.stringify(by.squat));
    assert.ok(by.squat.reputation.score < 60);
    assert.deepEqual(Object.keys(by.squat.reputation).sort(), ["band", "reasons", "score"]);
    const comp = bom.components.find((c) => c.type === "mcp-server" && c.name === "squat");
    assert.equal(comp.reputation.band, by.squat.reputation.band);
    assert.equal(bom.summary.mcpLowReputation, 1);
    assert.ok(existsSync(join(home, ".moorai", "mcp-reputation.json")), "AIBOM discovery is a first sight: it caches");
    const out = JSON.stringify(bom);
    for (const leak of [SECRET, LOCAL]) assert.equal(out.includes(leak), false, `AIBOM leaked ${leak}`);
    const md = run(AIBOM, home, ["--format", "md"]);
    assert.match(md, /\| squat \| claude \| stdio \| .* \| \d+\/100 (poor|bad) \(.*mcp-typosquat.*\) \|/);
  } finally { rmTree(home); }
});

test("shadow: an MCP server's reputation is shown, and a poor one ranks high risk", () => {
  const home = seed();
  try {
    const d = JSON.parse(run(SHADOW, home, ["--json"]));
    const squat = d.unclassified.find((x) => x.kind === "mcp-server" && x.name === "squat");
    assert.ok(squat.reputation && squat.reputation.reasons.includes("mcp-typosquat"), JSON.stringify(squat));
    assert.equal(squat.risk, "high");
    const files = d.unclassified.find((x) => x.kind === "mcp-server" && x.name === "files");
    assert.equal(files.reputation.band, "good");
    const human = run(SHADOW, home);
    assert.match(human, /squat .*reputation \d+\/100 (poor|bad)/);
    assert.equal(human.includes(SECRET), false);
    assert.equal(readFileSync(join(home, ".claude.json"), "utf8").includes(SECRET), true, "sanity: the secret was in the config");
  } finally { rmTree(home); }
});
