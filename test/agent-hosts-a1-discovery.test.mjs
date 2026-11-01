// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/agent-hosts-a1-discovery.test.mjs
//
// Discovery for the hosts whose adapters were built from vendor documentation (Antigravity, Windsurf,
// Kiro, Cline): the host-drift manifest, the AI-CLI parent walk, the AI-caller identity names and install
// locations, the skill surface (hook and MCP config files an agent could rewrite) and the agent-state store
// (each host's own transcripts). Paths and names are the vendors' documented ones; none was measured on an
// install.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { rmTree } from "./fs-cleanup.mjs";
import { loadManifest } from "../cli/agent-hooks/host-version.mjs";
import { classifyImage } from "../cli/ai-cli-parents.mjs";
import { KNOWN_AGENTS } from "../cli/ai-api-callers.mjs";
import { PRODUCTS } from "../cli/ai-install-locations.mjs";
import { skillSurfaceKind, SKILL_SURFACE_KINDS } from "../data/skill-surface.js";
import { agentStateKind, agentStateTamperHit } from "../data/agent-state-paths.js";
import { ROOT } from "./agent-hook-harness.mjs";

const NEW_HOSTS = ["antigravity", "windsurf", "kiro", "cline"];

test("host-drift manifest: every new adapter is listed with its adapter and tests, and claims no tested version", () => {
  const m = loadManifest();
  for (const id of NEW_HOSTS) {
    const h = m.hosts[id];
    assert.ok(h, `${id} in data/host-versions.json`);
    assert.ok(existsSync(join(ROOT, h.adapter)), `${id} adapter ${h.adapter}`);
    assert.ok(h.tests.length && h.tests.every((t) => existsSync(join(ROOT, t))), `${id} tests`);
    assert.equal(h.tested, undefined, `${id}: no binary was run, so no tested version`);
    assert.match(h.liveNote, /no live tier/);
    assert.match(h.verifiedAgainst, /docs|documentation/i);
  }
});

test("AI-CLI parent walk: agy, kiro-cli and cline are agent processes; Kiro's helper is a normal IDE parent at its install location", () => {
  for (const image of ["agy", "kiro-cli", "cline"]) assert.equal(classifyImage(image, "", { platform: "darwin" }), "agent", image);
  assert.equal(classifyImage("Kiro Helper (Plugin)", "/Applications/Kiro.app/Contents/Frameworks/Kiro Helper (Plugin).app/Contents/MacOS/Kiro Helper (Plugin)", { platform: "darwin" }), "normal");
  assert.equal(classifyImage("Kiro", "/Applications/Kiro.app/Contents/MacOS/Kiro", { platform: "darwin" }), "normal");
  assert.equal(classifyImage("Kiro", "/Users/u/Downloads/x/Kiro.app/Contents/MacOS/Kiro", { platform: "darwin" }), "unknown", "a name alone at an unexpected place is not normal");
});

test("AI-caller identity: the new CLIs are known names with documented install locations", () => {
  for (const n of ["agy", "kiro-cli", "cline"]) assert.ok(KNOWN_AGENTS.includes(n), n);
  const byId = Object.fromEntries(PRODUCTS.map((p) => [p.id, p]));
  assert.deepEqual(byId["antigravity-cli"].names, ["agy"]);
  assert.ok(byId["antigravity-cli"].mac.includes("~/.local/bin|agy"));
  assert.ok(byId["antigravity-cli"].win.includes("%L/agy/bin"));
  assert.ok(byId["kiro-cli"].mac.includes("brew:kiro-cli"));
  assert.ok(byId.cline.linux.includes("npm:cline"));
});

test("skill surface: the hook and MCP config files of the new hosts are classified (and in the vocabulary)", () => {
  const cases = [
    [".gemini/config/hooks.json", "antigravity-hooks"],
    ["proj/.agents/hooks.json", "antigravity-hooks"],
    [".gemini/antigravity-cli/settings.json", "antigravity-hooks"],
    [".gemini/config/mcp_config.json", "antigravity-mcp"],
    ["proj/.agents/mcp_config.json", "antigravity-mcp"],
    [".codeium/windsurf/hooks.json", "windsurf-hooks"],
    [".codeium/hooks.json", "windsurf-hooks"],
    ["proj/.devin/hooks.json", "windsurf-hooks"],
    ["proj/.windsurf/hooks.json", "windsurf-hooks"],
    ["/Library/Application Support/Devin/hooks.json", "windsurf-hooks"],
    ["/etc/windsurf/hooks.json", "windsurf-hooks"],
    ["C:\\ProgramData\\Devin\\hooks.json", "windsurf-hooks"],
    [".cline/hooks/PreToolUse", "cline-hook"],
    ["Documents/Cline/Hooks/PreToolUse", "cline-hook"],
    ["proj/.clinerules/hooks/PreToolUse", "cline-hook"],
    [".kiro/hooks/moorai.json", "kiro-hook"],
  ];
  for (const [p, kind] of cases) {
    assert.equal(skillSurfaceKind(p), kind, p);
    assert.ok(SKILL_SURFACE_KINDS.includes(kind), kind);
  }
  assert.equal(skillSurfaceKind("proj/.agents/notes.json"), null);
  assert.equal(skillSurfaceKind("proj/src/hooks.json"), null);
});

test("AIBOM: the four hosts are listed as agents by their documented homes, with their MCP servers, content-free", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-a1-aibom-"));
  try {
    const put = (rel, obj) => { mkdirSync(dirname(join(home, rel)), { recursive: true }); writeFileSync(join(home, rel), JSON.stringify(obj)); };
    const srv = (name) => ({ mcpServers: { [name]: { command: "npx", args: ["-y", `${name}-mcp`], env: { API_TOKEN: "SECRETVALUE123" } } } });
    put(".gemini/config/mcp_config.json", srv("ag-srv"));
    put(".codeium/windsurf/mcp_config.json", srv("ws-srv"));
    put(".kiro/settings/mcp.json", srv("kiro-srv"));
    put(".cline/data/settings/cline_mcp_settings.json", srv("cline-srv"));
    const fixture = join(home, "probe.json");
    writeFileSync(fixture, "{}");
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture };
    const out = execFileSync(process.execPath, [join(ROOT, "cli", "moorai-aibom.mjs")], { env, encoding: "utf8" });
    const d = JSON.parse(out);
    assert.deepEqual(d.agentHosts.map((h) => h.agent).sort(), ["antigravity", "cline", "kiro", "windsurf"]);
    assert.deepEqual(d.mcpServers.map((s) => `${s.scope}:${s.name}`).sort(), ["antigravity:ag-srv", "cline:cline-srv", "kiro:kiro-srv", "windsurf:ws-srv"]);
    for (const a of ["antigravity", "cline", "kiro", "windsurf"]) assert.ok(d.components.some((c) => c.type === "agent" && c.name === a), a);
    assert.equal(d.summary.agents, 4);
    assert.ok(!out.includes("SECRETVALUE123"), "an MCP env value never reaches the AIBOM");
  } finally { rmTree(home); }
});

test("agent state: each new host's own transcript store is history, and rewriting it is a tamper hit", () => {
  assert.equal(agentStateKind("~/.gemini/antigravity-cli/brain/ec33ebf9/.system_generated/logs/transcript.jsonl"), "history");
  assert.equal(agentStateKind("~/.gemini/antigravity/brain/c1"), "history");
  assert.equal(agentStateKind("~/.gemini/antigravity-ide/brain"), "history");
  assert.equal(agentStateKind("~/.windsurf/transcripts/traj-1.jsonl"), "history");
  assert.equal(agentStateKind("~/.windsurf"), "container");
  assert.equal(agentStateKind("~/.cline/data/sessions/s1/messages.json"), "history");
  assert.equal(agentStateKind("~/.cline"), "container");
  assert.equal(agentStateKind("proj/.cline/hooks/PreToolUse"), null);
  assert.equal(agentStateKind("~/.gemini/config/hooks.json"), null);
  assert.equal(agentStateTamperHit("rm -rf ~/.windsurf/transcripts"), true);
  assert.equal(agentStateTamperHit("cat ~/.windsurf/transcripts/traj-1.jsonl"), false);
  assert.equal(agentStateTamperHit("node -e \"require('fs').writeFileSync(process.env.HOME + '/.cline/data/sessions/s/m.json', '[]')\""), true);
});
