// Declared governance in the AIBOM (cli/aibom-declarations.mjs + data/sbom.js + moorai-aibom). Pinned:
//   1. VALIDATOR — signed policy aibomDeclarations: "<kind>:<name>" keys (agent / mcp / key / model), the five
//      string fields with their limits, control characters rejected, unknown fields ignored, an invalid
//      entry dropped and counted while the rest apply.
//   2. JOIN — each component and MCP server entry is declared, undeclared or not declarable, with the key it
//      is declared under; keys at rest keep their collector shape and get a list of their own; the summary
//      counts them.
//   3. CYCLONEDX — a model's purpose and intended users in modelCard.considerations (useCases / users), the
//      other fields in moorai:declaration:* properties, undeclared flagged, counts in metadata.properties;
//      only validated fields reach the BOM.
//   4. CLI — --policy <file> end to end (json, md, cyclonedx, spdx); no policy → every entry undeclared.
//
//   node --test test/aibom-declarations.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import { aibomDeclarations, annotateDeclarations, cleanDeclaration, declarationKey, keyDeclarationKey, DECLARATION_LIMITS } from "../cli/aibom-declarations.mjs";
import { toCycloneDX, toSpdx } from "../data/sbom.js";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");
const KEY_HASH = "h2:0123456789abcdef";
const quiet = () => {};
const props = (c) => Object.fromEntries((c.properties || []).map((p) => [p.name, p.value]));

test("VALIDATOR: valid entries kept and trimmed, unknown fields ignored, absent policy is empty", () => {
  const r = aibomDeclarations({ aibomDeclarations: {
    "agent:claude-code": { owner: "  team:Platform ", purpose: "Coding assistant", extra: "ignored" },
    "mcp:github": { dataUse: "Repository metadata only", retention: "30 days", intendedUsers: "Engineering" },
    [`key:Anthropic:${KEY_HASH}`]: { owner: "sec@example.com" },
    "model:claude-opus-4-5": { purpose: "Code review", intendedUsers: "Developers", owner: null }
  } }, quiet);
  assert.equal(r.dropped, 0);
  assert.deepEqual(r.entries.get("agent:claude-code"), { owner: "team:Platform", purpose: "Coding assistant" });
  assert.deepEqual(r.entries.get("mcp:github"), { dataUse: "Repository metadata only", retention: "30 days", intendedUsers: "Engineering" });
  assert.deepEqual(r.entries.get(`key:Anthropic:${KEY_HASH}`), { owner: "sec@example.com" });
  assert.deepEqual(r.entries.get("model:claude-opus-4-5"), { purpose: "Code review", intendedUsers: "Developers" });
  for (const p of [undefined, null, {}, { aibomDeclarations: null }]) assert.deepEqual(aibomDeclarations(p, quiet), { entries: new Map(), dropped: 0 });
  const warned = [];
  assert.equal(aibomDeclarations({ aibomDeclarations: ["x"] }, (m) => warned.push(m)).entries.size, 0);
  assert.match(warned[0], /aibomDeclarations ignored: not an object/);
});

test("VALIDATOR: each limit holds at the boundary and fails one past it", () => {
  for (const [f, max] of Object.entries(DECLARATION_LIMITS)) {
    assert.deepEqual(cleanDeclaration({ [f]: "é".repeat(max) }).declaration, { [f]: "é".repeat(max) }, `${f} at ${max}`);
    assert.match(cleanDeclaration({ [f]: "a".repeat(max + 1) }).error, new RegExp(`^${f}: at most ${max} characters`), `${f} at ${max + 1}`);
  }
});

test("VALIDATOR: an invalid entry is dropped and counted, the others still apply", () => {
  const warned = [];
  const r = aibomDeclarations({ aibomDeclarations: {
    "mcp:ok": { owner: "team:A" },
    "mcp:line": { purpose: "two\nlines" },
    "mcp:bell": { owner: "a\u0007b" },
    "mcp:zw": { retention: "30​days" },
    "mcp:ls": { dataUse: "a b" },
    "mcp:num": { retention: 30 },
    "mcp:empty": {},
    "mcp:blank": { owner: "   " },
    "mcp:onlyunknown": { color: "red" },
    "mcp:notobj": "owner",
    "agent:aider": { owner: "team:A" },
    "agent:claude": { owner: "team:A" },
    "mcp: padded": { owner: "team:A" },
    [`mcp:${"x".repeat(65)}`]: { owner: "team:A" },
    "mcp:esc\u001b[31m": { owner: "team:A" },
    "key:Anthropic:h2:xyz": { owner: "team:A" },
    "model:": { owner: "team:A" },
    "skill:docx": { owner: "team:A" },
    "nokind": { owner: "team:A" }
  } }, (m) => warned.push(m));
  assert.deepEqual([...r.entries.keys()], ["mcp:ok"]);
  assert.equal(r.dropped, 18);
  assert.equal(warned.length, 18);
  assert.ok(warned.every((m) => /^aibomDeclarations entry \d+ dropped: /.test(m)));
  assert.ok(!warned.some((m) => m.includes("esc") || m.includes("two")), "a warning never echoes the entry");
});

test("JOIN: declaration keys and statuses per entry; summary counts components, keys on their own", () => {
  assert.equal(declarationKey({ type: "agent", name: "claude" }), "agent:claude-code");
  assert.equal(declarationKey({ type: "agent", name: "codex" }), "agent:codex");
  assert.equal(declarationKey({ type: "agent", name: "aider" }), null);
  assert.equal(declarationKey({ type: "skill", name: "docx" }), null);
  assert.equal(declarationKey({ type: "editor-extension", name: "GitHub.copilot" }), null);
  assert.equal(declarationKey({ type: "mcp-server", name: " spaced" }), null);
  assert.equal(declarationKey({ type: "model", name: "llama3.1" }), "model:llama3.1");
  assert.equal(keyDeclarationKey({ provider: "OpenAI", keyHash: "h2:nokey" }), "key:OpenAI:h2:nokey");
  const bom = {
    components: [
      { type: "model", name: "opus" }, { type: "model", name: "llama3.1" }, { type: "agent", name: "claude" }, { type: "agent", name: "aider" },
      { type: "mcp-server", name: "github", scope: "claude" }, { type: "skill", name: "docx" }
    ],
    mcpServers: [{ name: "github", scope: "claude" }, { name: "github", scope: "cursor" }],
    apiKeysAtRest: [{ provider: "Anthropic", locationClass: "shell-rc", location: "~/.zshrc", keyHash: KEY_HASH }, { provider: "Anthropic", locationClass: "dotenv", location: "~/.env", keyHash: KEY_HASH },
      { provider: "OpenAI", locationClass: "dotenv", location: null, keyHash: "h2:fedcba9876543210" }]
  };
  const decl = aibomDeclarations({ aibomDeclarations: { "model:opus": { purpose: "Code review" }, "mcp:github": { owner: "team:A" }, [`key:Anthropic:${KEY_HASH}`]: { retention: "none" }, "mcp:x": { owner: "" } } }, quiet);
  const { summary: s, keys } = annotateDeclarations(bom, decl);
  assert.deepEqual(s, { declared: 2, undeclared: 2, notDeclarable: 2, apiKeysAtRestDeclared: 1, apiKeysAtRestUndeclared: 1, declarationsInPolicy: 3, declarationsDropped: 1 });
  assert.deepEqual(bom.components.map((c) => [c.declarationStatus, c.declarationKey ?? null]), [
    ["declared", "model:opus"], ["undeclared", "model:llama3.1"], ["undeclared", "agent:claude-code"], ["not-declarable", null], ["declared", "mcp:github"], ["not-declarable", null]
  ]);
  assert.deepEqual(bom.components[0].declared, { purpose: "Code review" });
  assert.equal(bom.components[1].declared, undefined);
  assert.deepEqual(bom.mcpServers.map((m) => m.declarationStatus), ["declared", "declared"]);
  assert.deepEqual(keys, [{ declarationKey: `key:Anthropic:${KEY_HASH}`, declarationStatus: "declared", declared: { retention: "none" } }, { declarationKey: "key:OpenAI:h2:fedcba9876543210", declarationStatus: "undeclared" }]);
  for (const k of bom.apiKeysAtRest) assert.deepEqual(Object.keys(k).sort(), ["keyHash", "location", "locationClass", "provider"], "a key at rest keeps its collector shape");
});

function annotatedBom() {
  const bom = {
    device: "testbox", generatedAt: "2026-01-01T00:00:00.000Z", summary: {},
    components: [
      { type: "model", name: "opus", provider: "Anthropic", local: false },
      { type: "model", name: "llama3.1", provider: "ollama", local: true },
      { type: "agent", name: "claude" },
      { type: "mcp-server", name: "github", riskLevel: "high", capabilities: { net: true, fs: false, cred: true }, transport: "stdio" },
      { type: "skill", name: "docx", kind: "skill" }
    ]
  };
  const { summary: s } = annotateDeclarations(bom, aibomDeclarations({ aibomDeclarations: {
    "model:opus": { owner: "team:ML", purpose: "Code review", dataUse: "Source code, no customer data", retention: "Provider default, 30 days", intendedUsers: "Developers" },
    "mcp:github": { owner: "team:Platform", purpose: "Read issues", dataUse: "Issue metadata", retention: "Not stored", intendedUsers: "Engineering" },
    "agent:nope": { owner: "x" }
  } }, quiet));
  Object.assign(bom.summary, s, { declarationsSource: "file" });
  return bom;
}

test("CYCLONEDX: model card considerations for models, properties elsewhere, undeclared flagged, counts in metadata", () => {
  const cdx = toCycloneDX(annotatedBom());
  const opus = cdx.components.find((c) => c.name === "opus");
  assert.deepEqual(opus.modelCard, { considerations: { users: ["Developers"], useCases: ["Code review"] } });
  const po = props(opus);
  assert.equal(po["moorai:declaration"], "declared");
  assert.equal(po["moorai:declaration:key"], "model:opus");
  assert.equal(po["moorai:declaration:owner"], "team:ML");
  assert.equal(po["moorai:declaration:dataUse"], "Source code, no customer data");
  assert.equal(po["moorai:declaration:retention"], "Provider default, 30 days");
  assert.equal(po["moorai:declaration:purpose"], undefined, "a model's purpose is in its model card");
  assert.equal(po["moorai:declaration:intendedUsers"], undefined, "a model's intended users are in its model card");
  const gh = props(cdx.components.find((c) => c.name === "github"));
  assert.deepEqual([gh["moorai:declaration"], gh["moorai:declaration:owner"], gh["moorai:declaration:purpose"], gh["moorai:declaration:dataUse"], gh["moorai:declaration:retention"], gh["moorai:declaration:intendedUsers"]],
    ["declared", "team:Platform", "Read issues", "Issue metadata", "Not stored", "Engineering"]);
  assert.equal(cdx.components.find((c) => c.name === "github").modelCard, undefined);
  const llama = cdx.components.find((c) => c.name === "llama3.1");
  assert.deepEqual([props(llama)["moorai:declaration"], props(llama)["moorai:declaration:key"], llama.modelCard], ["undeclared", "model:llama3.1", undefined]);
  assert.deepEqual([props(cdx.components.find((c) => c.name === "claude"))["moorai:declaration"], props(cdx.components.find((c) => c.name === "docx"))["moorai:declaration"]], ["undeclared", "not-declarable"]);
  assert.equal(props(cdx.components.find((c) => c.name === "docx"))["moorai:declaration:key"], undefined);
  assert.deepEqual(props(cdx.metadata), { "moorai:declarations:declared": "2", "moorai:declarations:undeclared": "2", "moorai:declarations:notDeclarable": "1", "moorai:declarations:declarationsDropped": "1", "moorai:declarations:source": "file" });
  const spdx = toSpdx(annotatedBom());
  assert.match(spdx.packages.find((p) => p.name === "github").comment, /declaration=declared$/);
  assert.match(spdx.packages.find((p) => p.name === "llama3.1").comment, /declaration=undeclared$/);
});

test("CYCLONEDX: only validated declaration fields reach the BOM", () => {
  const bom = annotatedBom();
  const SENTINEL = "STRAY-FIELD-DO-NOT-EMIT";
  Object.assign(bom.components[3].declared, { secret: SENTINEL });
  bom.components[2].declarationStatus = "declared";
  bom.components[2].declared = { owner: `bad\n${SENTINEL}` };
  bom.components[4].declarationStatus = "bogus";
  bom.components[4].declarationKey = `skill:${SENTINEL}`;
  const cdx = JSON.stringify(toCycloneDX(bom));
  assert.ok(!cdx.includes(SENTINEL), "a stray or invalid field reached the CycloneDX BOM");
  assert.ok(!JSON.stringify(toSpdx(bom)).includes(SENTINEL));
  const out = toCycloneDX(bom);
  assert.equal(props(out.components[3])["moorai:declaration:owner"], "team:Platform");
  assert.equal(props(out.components[4])["moorai:declaration"], undefined);
});

function fixtureHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-aibom-decl-"));
  mkdirSync(join(home, ".claude"), { recursive: true });
  writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ model: "opus" }));
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] }, idle: { command: "npx", args: ["-y", "some-idle-mcp"] } } }));
  const fixture = join(home, "probe.json");
  writeFileSync(fixture, JSON.stringify({}));
  const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture };
  delete env.CODEX_HOME; delete env.COPILOT_HOME;
  return { home, env };
}

test("CLI: --policy declarations reach json, md, cyclonedx and spdx; invalid entries counted", () => {
  const { home, env } = fixtureHome();
  try {
    const pol = join(home, "policy.json");
    writeFileSync(pol, JSON.stringify({ aibomDeclarations: {
      "model:opus": { owner: "team:ML", purpose: "Code review", intendedUsers: "Developers", retention: "30 days" },
      "mcp:github": { owner: "team:Platform", dataUse: "Issue | PR metadata" },
      "agent:claude-code": { purpose: "two\nlines" }
    } }));
    const run = (...a) => execFileSync(process.execPath, [AIBOM, "--policy", pol, ...a], { env, encoding: "utf8" });
    const d = JSON.parse(run());
    assert.deepEqual([d.summary.declared, d.summary.undeclared, d.summary.declarationsDropped, d.summary.declarationsSource], [2, 2, 1, "file"]);
    assert.deepEqual(d.components.find((c) => c.type === "agent" && c.name === "claude").declarationStatus, "undeclared");
    assert.deepEqual(d.mcpServers.find((s) => s.name === "github").declared, { owner: "team:Platform", dataUse: "Issue | PR metadata" });
    const md = run("--format", "md");
    assert.match(md, /## Declared governance \(policy aibomDeclarations\)/);
    assert.match(md, /2 declared, 2 undeclared, \d+ with no console item to declare them under; 1 invalid policy entries dropped\. Source: file\./);
    assert.match(md, /\| mcp-server \| github \| declared \| mcp:github \| team:Platform \| — \| Issue \\\| PR metadata \| — \| — \|/);
    assert.match(md, /\| mcp-server \| idle \| undeclared \| mcp:idle \| — \| — \| — \| — \| — \|/);
    const cdx = JSON.parse(run("--format", "cyclonedx"));
    assert.deepEqual(cdx.components.find((c) => c.name === "opus").modelCard, { considerations: { users: ["Developers"], useCases: ["Code review"] } });
    assert.equal(props(cdx.components.find((c) => c.name === "idle"))["moorai:declaration"], "undeclared");
    assert.equal(props(cdx.metadata)["moorai:declarations:declared"], "2");
    assert.match(JSON.parse(run("--format", "spdx")).packages.find((p) => p.name === "github").comment, /declaration=declared/);
    const bad = spawnSync(process.execPath, [AIBOM, "--policy", join(home, "missing.json")], { env, encoding: "utf8" });
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /moorai-aibom: --policy .*missing\.json/);
  } finally { rmTree(home); }
});

test("CLI: no policy on the device → every declarable entry is undeclared, source none", () => {
  const { home, env } = fixtureHome();
  try {
    const d = JSON.parse(execFileSync(process.execPath, [AIBOM], { env, encoding: "utf8" }));
    assert.equal(d.summary.declarationsSource, "none");
    assert.deepEqual([d.summary.declared, d.summary.undeclared, d.summary.declarationsInPolicy], [0, 4, 0]);
    assert.ok(d.components.every((c) => c.declared === undefined));
  } finally { rmTree(home); }
});
