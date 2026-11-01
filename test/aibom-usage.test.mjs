// Installed vs actually used (cli/aibom-usage.mjs + moorai-aibom). The AIBOM lists what is configured;
// each entry is joined to the on-device use records and carries lastUsed / calls30d / usageStatus. Pinned:
//   1. JOIN — a fixture inventory against a fixture destination map + MCP usage tally + transcript buckets:
//      per-server last use and 30-day count, the largest-surface-per-day rule (never the sum), the
//      mcp__ name normalisation, the configured Claude Code model only.
//   2. NOT OBSERVABLE vs NEVER SEEN — no record of a kind → null/null/"not-observable", never 0.
//   3. --unused-days — configured-but-unused MCP servers listed with a reason; an entry is a candidate
//      only when the record reaches back N days, else "undecided"; not-observable entries never listed.
//   4. EXPORTS — CycloneDX properties and the SPDX comment carry the use fields; shapes stay valid.
//
//   node --test test/aibom-usage.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";
import { annotateUsage, mcpUsageIndex, mcpKey, modelMatcher, unusedCandidates, configSurfaces, hookedHosts } from "../cli/aibom-usage.mjs";
import { toCycloneDX, toSpdx } from "../data/sbom.js";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");
const DAY = 86400000;
const NOW = Date.UTC(2026, 9, 28, 12);
const iso = (daysAgo, now = NOW) => new Date(now - daysAgo * DAY).toISOString();
const day = (daysAgo, now = NOW) => iso(daysAgo, now).slice(0, 10);

function fixtureSources(now = NOW) {
  return {
    destinations: [
      { ts: iso(60, now), tool: "Bash", kind: "host", name: "api.github.com", decision: "allow" },
      { ts: iso(45, now), tool: "mcp__old-server__x", kind: "mcp", name: "old-server", decision: "allow" },
      { ts: iso(2, now), tool: "mcp__github__list", kind: "mcp", name: "github", decision: "allow" },
      { ts: iso(2, now), tool: "mcp__github__get", kind: "mcp", name: "github", decision: "deny" },
      { ts: iso(1, now), tool: "mcp__my_server__t", kind: "mcp", name: "my_server", decision: "allow" }
    ],
    // day 2: the hook tally (3) and the guard (5) both saw github — the guard's 5 counts, not 3+5.
    tally: { days: { [day(2, now)]: { "hook|claude-code": { github: 3 }, "proxy|claude-desktop": { github: 5 } }, [day(40, now)]: { "gateway|gateway": { "gw-only": 7 } } } },
    transcript: [
      { hour: iso(3, now).slice(0, 13) + ":00:00Z", agentName: "claude-code", provider: "anthropic", model: "claude-opus-4-5-20251101", requests: 4 },
      { hour: iso(35, now).slice(0, 13) + ":00:00Z", agentName: "claude-code", provider: "anthropic", model: "claude-opus-4-5-20251101", requests: 9 },
      { hour: iso(3, now).slice(0, 13) + ":00:00Z", agentName: "claude-code", provider: "anthropic", model: "claude-haiku-4-5", requests: 2 }
    ]
  };
}

function fixtureBom() {
  return {
    providers: [{ provider: "Anthropic", agent: "claude", model: "opus" }, { provider: "OpenAI", agent: "codex", model: "gpt-5" }],
    // claude-code's hook is registered (HOOKS below); cursor's is not, so a cursor entry is watched only
    // when it goes through the guard or the gateway.
    mcpServers: [{ name: "github", scope: "claude" }, { name: "github", scope: "cursor", watchedBy: ["guard"] }, { name: "my server", scope: "claude" }, { name: "old-server", scope: "claude" }, { name: "idle", scope: "claude" }, { name: "gw-only", scope: "cursor", watchedBy: ["gateway"] }],
    components: [
      { type: "model", name: "opus", provider: "Anthropic", local: false },
      { type: "model", name: "gpt-5", provider: "OpenAI", local: false },
      { type: "model", name: "llama3.1", provider: "ollama", local: true },
      { type: "agent", name: "aider" },
      { type: "mcp-server", name: "github", scope: "claude" }, { type: "mcp-server", name: "github", scope: "cursor", watchedBy: ["guard"] }, { type: "mcp-server", name: "my server", scope: "claude" },
      { type: "mcp-server", name: "old-server", scope: "claude" }, { type: "mcp-server", name: "idle", scope: "claude" }, { type: "mcp-server", name: "gw-only", scope: "cursor", watchedBy: ["gateway"] },
      { type: "editor-extension", name: "GitHub.copilot", version: "1.2.3" },
      { type: "skill", name: "docx", kind: "skill" }
    ]
  };
}
const HOOKS = new Set(["claude-code"]);
const pick = (o) => ({ lastUsed: o.lastUsed, calls30d: o.calls30d, usageStatus: o.usageStatus });
const comp = (b, type, name) => b.components.find((c) => c.type === type && c.name === name);

test("JOIN: MCP servers get last use and a 30-day count; one call seen by two surfaces counts once", () => {
  const b = fixtureBom();
  annotateUsage(b, { sources: fixtureSources(), now: NOW, home: "/nonexistent", hooks: HOOKS });
  assert.deepEqual(pick(comp(b, "mcp-server", "github")), { lastUsed: day(2), calls30d: 5, usageStatus: "used" });
  assert.deepEqual(pick(b.mcpServers.find((s) => s.scope === "cursor" && s.name === "github")), { lastUsed: day(2), calls30d: 5, usageStatus: "used" });
  assert.deepEqual(pick(comp(b, "mcp-server", "my server")), { lastUsed: day(1), calls30d: 1, usageStatus: "used" }, "config name matched through mcp__ normalisation");
  assert.deepEqual(pick(comp(b, "mcp-server", "old-server")), { lastUsed: day(45), calls30d: 0, usageStatus: "used" });
  assert.deepEqual(pick(comp(b, "mcp-server", "gw-only")), { lastUsed: day(40), calls30d: 0, usageStatus: "used" }, "gateway tally counts");
  assert.deepEqual(pick(comp(b, "mcp-server", "idle")), { lastUsed: null, calls30d: 0, usageStatus: "never-seen" });
  assert.equal(mcpKey("My Server"), "my_server");
});

test("JOIN: the configured Claude Code model is matched by family alias; other models are not observable", () => {
  const b = fixtureBom();
  const ev = annotateUsage(b, { sources: fixtureSources(), now: NOW, home: "/nonexistent", hooks: HOOKS });
  assert.deepEqual(pick(comp(b, "model", "opus")), { lastUsed: day(3), calls30d: 4, usageStatus: "used" }, "haiku requests are not opus's; 35-day-old ones are outside 30 d");
  assert.deepEqual(pick(comp(b, "model", "gpt-5")), { lastUsed: null, calls30d: null, usageStatus: "not-observable" });
  assert.deepEqual(pick(comp(b, "model", "llama3.1")), { lastUsed: null, calls30d: null, usageStatus: "not-observable" });
  assert.equal(ev.models.since, day(35));
  assert.ok(modelMatcher("claude-opus-4-5")("claude-opus-4-5-20251101"));
  assert.ok(!modelMatcher("claude-opus-4")("claude-opus-4-5-20251101"), "4 is not 4-5");
  assert.ok(!modelMatcher("sonnet")("claude-opus-4-5-20251101"));
  assert.ok(modelMatcher("opusplan")("claude-sonnet-4-5") && modelMatcher("sonnet[1m]")("claude-sonnet-4-5"));
});

test("NOT OBSERVABLE vs NEVER SEEN: no record of a kind is null, never 0 and never 'never-seen'", () => {
  const b = fixtureBom();
  const bare = (b) => { for (const x of [...b.components, ...b.mcpServers]) delete x.watchedBy; return b; };
  const ev = annotateUsage(bare(b), { sources: { destinations: [], tally: { days: {} }, transcript: null }, now: NOW, home: "/nonexistent", hooks: new Set() });
  for (const c of b.components) assert.deepEqual(pick(c), { lastUsed: null, calls30d: null, usageStatus: "not-observable" }, `${c.type}:${c.name}`);
  assert.equal(ev.mcpServers.recorded, false);
  assert.equal(ev.models.observable, false);
  // A record that exists but names nothing for this server is the other case: never seen, count 0.
  const b2 = fixtureBom();
  annotateUsage(b2, { sources: { destinations: [{ ts: iso(1), tool: "Bash", kind: "host", name: "example.com" }], tally: { days: {} }, transcript: [] }, now: NOW, home: "/nonexistent", hooks: HOOKS });
  assert.deepEqual(pick(comp(b2, "mcp-server", "idle")), { lastUsed: null, calls30d: 0, usageStatus: "never-seen" });
  assert.deepEqual(pick(comp(b2, "model", "opus")), { lastUsed: null, calls30d: 0, usageStatus: "never-seen" });
  assert.deepEqual(pick(comp(b2, "editor-extension", "GitHub.copilot")), { lastUsed: null, calls30d: null, usageStatus: "not-observable" });
  assert.deepEqual(pick(comp(b2, "agent", "aider")), { lastUsed: null, calls30d: null, usageStatus: "not-observable" });
});

test("--unused-days: idle and stale servers are candidates; a short record makes never-seen undecided", () => {
  const b = fixtureBom();
  const ev = annotateUsage(b, { sources: fixtureSources(), now: NOW, home: "/nonexistent", hooks: HOOKS });
  const r = unusedCandidates(b, 30, ev, NOW);
  assert.deepEqual(r.candidates.map((x) => x.name), ["idle", "old-server", "gw-only"], "never seen first, then the oldest last use");
  assert.match(r.candidates.find((x) => x.name === "idle").reason, new RegExp(`no call on record since ${day(60)}`));
  assert.match(r.candidates.find((x) => x.name === "old-server").reason, new RegExp(`last used ${day(45)}`));
  assert.ok(!r.candidates.some((x) => x.name === "github" || x.name === "gpt-5"), "used and not-observable entries are never listed");
  // MCP record reaches back 60 days: at 90 days nothing never-seen can be decided.
  const r90 = unusedCandidates(b, 90, ev, NOW);
  assert.deepEqual(r90.candidates.map((x) => x.name), []);
  assert.deepEqual(r90.undecided.map((x) => x.name), ["idle"]);
  assert.equal(new Set(r.candidates.concat(r.undecided).map((x) => `${x.type}|${x.name}`)).size, r.candidates.length + r.undecided.length, "github's two scopes are one entry");
});

test("EXPORTS: CycloneDX properties and SPDX comments carry usageStatus / lastUsed / calls30d; nothing else leaks", () => {
  const b = { bomFormat: "MoorAI-AIBOM", specVersion: "1.0", device: "box", generatedAt: "2026-10-28T00:00:00.000Z", ...fixtureBom() };
  annotateUsage(b, { sources: fixtureSources(), now: NOW, home: "/nonexistent", hooks: HOOKS });
  comp(b, "mcp-server", "idle").lastUsed = "not a date SECRET"; // a malformed field never reaches an SBOM
  const cdx = toCycloneDX(b);
  const props = (name) => Object.fromEntries(cdx.components.find((c) => c.name === name).properties.map((p) => [p.name, p.value]));
  assert.deepEqual([props("github")["moorai:usageStatus"], props("github")["moorai:lastUsed"], props("github")["moorai:calls30d"]], ["used", day(2), "5"]);
  assert.equal(props("gpt-5")["moorai:usageStatus"], "not-observable");
  assert.ok(!("moorai:calls30d" in props("gpt-5")) && !("moorai:lastUsed" in props("gpt-5")), "null is omitted, never 0");
  assert.equal(props("idle")["moorai:calls30d"], "0");
  for (const c of cdx.components) for (const p of c.properties || []) assert.ok(typeof p.name === "string" && typeof p.value === "string");
  const spdx = toSpdx(b);
  assert.match(spdx.packages.find((p) => p.name === "github").comment, new RegExp(`usageStatus=used; lastUsed=${day(2)}; calls30d=5`));
  assert.match(spdx.packages.find((p) => p.name === "llama3.1").comment, /usageStatus=not-observable/);
  assert.ok(!JSON.stringify(cdx).includes("SECRET") && !JSON.stringify(spdx).includes("SECRET"));
});

test("CLI end-to-end: fixture HOME → AIBOM fields, Use column, --unused-days, --sort, exports", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-aibom-usage-"));
  try {
    const now = Date.now();
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: {
      github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] },
      idle: { command: "npx", args: ["-y", "some-idle-mcp"] }
    } }));
    mkdirSync(join(home, ".claude", "projects", "p"), { recursive: true });
    writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ model: "opus", hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "node /x/cli/moorai-hook.mjs" }] }] } }));
    mkdirSync(join(home, ".cursor"), { recursive: true });
    writeFileSync(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { "cursor-only": { command: "npx", args: ["-y", "cursor-only-mcp"] } } }));
    const sess = join(home, ".claude", "projects", "p", "s.jsonl");
    writeFileSync(sess, "");
    utimesSync(sess, new Date(now - 4 * DAY), new Date(now - 4 * DAY));
    const st = join(home, ".moorai");
    mkdirSync(st, { recursive: true });
    const src = fixtureSources(now);
    writeFileSync(join(st, "destinations.jsonl"), src.destinations.map((r) => JSON.stringify(r)).join("\n") + "\n");
    writeFileSync(join(st, "mcp-usage.json"), JSON.stringify({ v: 1, ...src.tally }));
    writeFileSync(join(st, "token-usage-transcript.json"), JSON.stringify({ v: 1, files: {}, buckets: src.transcript }));
    const fixture = join(home, "probe.json");
    writeFileSync(fixture, JSON.stringify({}));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture };
    delete env.CODEX_HOME; delete env.COPILOT_HOME;
    const run = (...a) => execFileSync(process.execPath, [AIBOM, ...a], { env, encoding: "utf8" });

    const d = JSON.parse(run());
    const gh = d.mcpServers.find((s) => s.name === "github");
    assert.deepEqual(pick(gh), { lastUsed: day(2, now), calls30d: 5, usageStatus: "used" });
    assert.deepEqual(pick(d.mcpServers.find((s) => s.name === "idle")), { lastUsed: null, calls30d: 0, usageStatus: "never-seen" });
    assert.deepEqual(gh.watchedBy, ["hook:claude-code"]);
    assert.deepEqual(pick(d.mcpServers.find((s) => s.name === "cursor-only")), { lastUsed: null, calls30d: null, usageStatus: "not-observable" }, "Cursor's hook is not registered");
    assert.deepEqual(pick(d.components.find((c) => c.type === "model" && c.name === "opus")), { lastUsed: day(3, now), calls30d: 4, usageStatus: "used" });
    assert.deepEqual(pick(d.components.find((c) => c.type === "agent" && c.name === "claude")), { lastUsed: day(4, now), calls30d: null, usageStatus: "used" });
    assert.equal(d.usageEvidence.mcpServers.since, day(60, now));
    assert.equal(d.summary.used, 3);
    assert.equal(d.summary.neverSeen, 1);

    const md = run("--format", "md");
    assert.match(md, /\| github \| claude \| .* \| used · last \d{4}-\d{2}-\d{2} · 5 calls\/30 d \(hook:claude-code\) \|/);
    assert.match(md, /\| idle \| claude \| .* \| never seen \(hook:claude-code\) \|/);
    assert.match(md, /\| cursor-only \| cursor \| .* \| not observable \(no MoorAI hook, guard or gateway on it\) \|/);
    assert.match(md, /## Installed vs used \(last 30 days\)/);

    const un = JSON.parse(run("--unused-days", "30"));
    assert.deepEqual(un.candidates.map((x) => [x.type, x.name]), [["mcp-server", "idle"]]);
    assert.deepEqual(un.candidates[0].scopes, ["claude"]);
    assert.match(un.candidates[0].reason, /^configured; no call on record since \d{4}-\d{2}-\d{2} \(watched by hook:claude-code\)$/);
    assert.ok(!un.undecided.some((x) => x.name === "cursor-only"));
    assert.match(run("--unused-days", "30", "--format", "md"), /\| mcp-server \| idle \(claude\) \| — \| configured; no call on record since /);
    const bad = spawnSync(process.execPath, [AIBOM, "--unused-days", "0"], { env, encoding: "utf8" });
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /--unused-days takes a whole number/);

    const asc = JSON.parse(run("--sort", "unused")).mcpServers.map((s) => s.name);
    const desc = JSON.parse(run("--sort", "used")).mcpServers.map((s) => s.name);
    assert.deepEqual(asc, ["idle", "github", "cursor-only"]);
    assert.deepEqual(desc, ["github", "idle", "cursor-only"]);

    const cdx = JSON.parse(run("--format", "cyclonedx"));
    assert.equal(cdx.specVersion, "1.6");
    const p = Object.fromEntries(cdx.components.find((c) => c.name === "github").properties.map((x) => [x.name, x.value]));
    assert.equal(p["moorai:calls30d"], "5");
    const spdx = JSON.parse(run("--format", "spdx"));
    assert.equal(spdx.spdxVersion, "SPDX-2.3");
    assert.match(spdx.packages.find((x) => x.name === "idle").comment, /usageStatus=never-seen; calls30d=0/);
    assert.match(run("--format", "csv"), /"mcp-server","github",".*usageStatus=used; lastUsed=\d{4}-\d{2}-\d{2}; calls30d=5"/);
  } finally { rmTree(home); }
});

test("PER HOST: a server only an unwatched host declares is not observable and never a candidate; under a watched host it is never-seen", () => {
  const src = fixtureSources();
  const build = (entries) => ({ providers: [], mcpServers: entries.map((e) => ({ ...e })), components: entries.map((e) => ({ type: "mcp-server", ...e })) });
  // Records exist (the claude-code hook has been writing them), but nothing watches cursor's config.
  const only = build([{ name: "lonely", scope: "cursor", watchedBy: [] }]);
  const ev1 = annotateUsage(only, { sources: src, now: NOW, home: "/nonexistent", hooks: HOOKS });
  assert.deepEqual(pick(only.mcpServers[0]), { lastUsed: null, calls30d: null, usageStatus: "not-observable" });
  assert.deepEqual(only.mcpServers[0].watchedBy, []);
  const r1 = unusedCandidates(only, 30, ev1, NOW);
  assert.deepEqual([r1.candidates.length, r1.undecided.length], [0, 0], "an unwatched entry is never listed");
  // The same server under the watched host: never seen, and a candidate whose reason names the watcher.
  const both = build([{ name: "lonely", scope: "cursor", watchedBy: [] }, { name: "lonely", scope: "claude", watchedBy: [] }]);
  const ev2 = annotateUsage(both, { sources: src, now: NOW, home: "/nonexistent", hooks: HOOKS });
  assert.deepEqual(pick(both.mcpServers[1]), { lastUsed: null, calls30d: 0, usageStatus: "never-seen" });
  assert.deepEqual(both.mcpServers[1].watchedBy, ["hook:claude-code"]);
  assert.deepEqual(pick(both.mcpServers[0]), { lastUsed: null, calls30d: null, usageStatus: "not-observable" });
  const r2 = unusedCandidates(both, 30, ev2, NOW);
  assert.deepEqual(r2.candidates.map((x) => [x.name, x.scopes, x.watchedBy]), [["lonely", ["claude"], ["hook:claude-code"]]]);
  assert.match(r2.candidates[0].reason, /watched by hook:claude-code\)$/);
  // cursor's hook registered too → the cursor entry is watched on its own.
  const ev3 = annotateUsage(only, { sources: src, now: NOW, home: "/nonexistent", hooks: new Set(["cursor"]) });
  assert.deepEqual([only.mcpServers[0].usageStatus, only.mcpServers[0].watchedBy], ["never-seen", ["hook:cursor"]]);
  assert.ok(ev3.mcpServers.hookedHosts.includes("cursor"));
});

test("PER HOST: the guard and the gateway are read off the config; the hook off the host's hook file", () => {
  assert.deepEqual(configSurfaces({ command: "node", args: ["/opt/moorai/mcp-proxy/moorai-mcp-guard.mjs", "--server", "gh", "--", "npx", "x"] }), ["guard"]);
  assert.deepEqual(configSurfaces({ command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] }), []);
  assert.deepEqual(configSurfaces({ type: "http", url: "http://127.0.0.1:8848/github" }), ["gateway"]);
  assert.deepEqual(configSurfaces({ type: "http", url: "https://api.example.com/mcp" }), []);
  const home = mkdtempSync(join(tmpdir(), "moorai-hooked-"));
  try {
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(join(home, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "node /x/cli/moorai-hook.mjs" }] }] } }));
    mkdirSync(join(home, ".cursor"), { recursive: true });
    writeFileSync(join(home, ".cursor", "hooks.json"), JSON.stringify({ version: 1, hooks: {} }));
    const env = { ...process.env, HOME: home }; delete env.CODEX_HOME; delete env.COPILOT_HOME;
    assert.deepEqual([...hookedHosts({ home, env, managedSources: [] })], ["claude-code"]);
  } finally { rmTree(home); }
});
