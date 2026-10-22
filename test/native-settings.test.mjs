// One MoorAI policy compiled into each host's native settings (cli/native-settings.mjs).
//
// Three layers:
//   1. the portable subset read from the policy (tagActions, entitlements, mcpAllow/mcpGate, egressRules);
//   2. per-host output: the documented file, path and keys, and every rule the host cannot carry reported;
//   3. a never-widen property: small evaluators written here from each host's documented semantics, NOT
//      from the generator, decide probe calls under the compiled file; wherever the native file is looser
//      than the MoorAI intent the report must say so (coarsened / omitted / may-be-inert), and wherever it is
//      stricter it must say narrowed.
//
//   node --test --import ./test/hermetic-env.mjs test/native-settings.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { nativeSettings, portableIntent, renderFile, NATIVE_HOSTS } from "../cli/native-settings.mjs";

const POLICY = {
  tagActions: { exec: "block", network: "ask", "read-private": "block" },
  mcpAllow: ["github", "bad name"],
  egressRules: [
    { id: "no-evil", host: "evil.example.com", action: "block" },
    { host: "*.example.com", port: 443, action: "allow" },
    { host: "api.partner.test", path: "/v1*", action: "allow" },
    { host: "paste.test", method: "POST", action: "block" }
  ],
  egressDefault: "block"
};

const unexp = (r, pred) => r.unexpressed.filter(pred);
const file = (r, suffix) => r.files.find((f) => f.path.endsWith(suffix));

// ---------- 1. portable intent ----------

test("intent: tagActions block/ask map to the built-in tools carrying that tag", () => {
  const i = portableIntent(POLICY);
  assert.deepEqual(i.tools.deny, ["Bash", "Monitor", "PowerShell"]);
  assert.deepEqual(i.tools.ask, ["WebFetch", "WebSearch"]);
  assert.equal(i.tools.allowOnly, null);
  // exec and network also tag MCP tools and parsed shell commands: the tool-name layer is coarser.
  assert.ok(unexp(i, (u) => u.source === "tagActions" && u.item === "exec" && u.effect === "coarsened").length);
  assert.ok(unexp(i, (u) => u.source === "tagActions" && u.item === "network" && u.effect === "coarsened").length);
  // read-private is decided from content, never from a tool name.
  assert.ok(unexp(i, (u) => u.source === "tagActions" && u.item === "read-private" && u.effect === "omitted").length);
});

test("intent: alert/allow tag actions and invalid entries never reach the native deny list", () => {
  const i = portableIntent({ tagActions: { write: "alert", read: "allow", bogus: "block", exec: "nope" } });
  assert.deepEqual(i.tools.deny, []);
  assert.deepEqual(i.tools.ask, []);
  assert.ok(unexp(i, (u) => u.source === "tagActions" && u.effect === "invalid").length >= 2);
});

test("intent: entitlements are an allow-only tool list only in block mode", () => {
  assert.deepEqual(portableIntent({ entitlementMode: "block", entitlements: { tools: ["Read", "Grep"] } }).tools.allowOnly, ["Grep", "Read"]);
  assert.equal(portableIntent({ entitlementMode: "alert", entitlements: { tools: ["Read"] } }).tools.allowOnly, null);
  assert.equal(portableIntent({ entitlements: { tools: ["Read"] } }).tools.allowOnly, null);
  // A JIT elevation can let a call through MoorAI that a static native allow-list would refuse.
  const j = portableIntent({ entitlementMode: "block", entitlements: { tools: ["Read"] }, elevations: [{ actor: "a", capability: "tool:Bash" }] });
  assert.ok(unexp(j, (u) => u.source === "elevations" && u.effect === "narrowed").length);
});

test("intent: MCP allow-list follows decideMcpServer (empty list without the gate is no list)", () => {
  assert.equal(portableIntent({ mcpAllow: [] }).mcp.allowOnly, null);
  assert.deepEqual(portableIntent({ mcpAllow: [], mcpGate: true }).mcp.allowOnly, []);
  assert.deepEqual(portableIntent({ mcpGate: true }).mcp.allowOnly, []);
  assert.deepEqual(portableIntent({ mcpAllow: ["b", "a", "a"] }).mcp.allowOnly, ["a", "b"]);
  // entitlements.mcp in block mode narrows the set further.
  assert.deepEqual(portableIntent({ mcpAllow: ["a", "b"], entitlementMode: "block", entitlements: { mcp: ["b", "c"] } }).mcp.allowOnly, ["b"]);
  assert.deepEqual(portableIntent({ entitlementMode: "block", entitlements: { mcp: ["c"] } }).mcp.allowOnly, ["c"]);
});

test("intent: a tag exception makes a native tag deny stricter than MoorAI", () => {
  const i = portableIntent({ tagActions: { exec: "block" }, exceptions: [{ id: "x1", rule: "tag:exec", pattern: "npm test", expires: "2099-01-01" }] });
  assert.ok(unexp(i, (u) => u.source === "exceptions" && u.item === "exec" && u.effect === "narrowed").length);
});

// ---------- 2. per host ----------

test("hosts: the five hosts and their documented paths per platform", () => {
  assert.deepEqual(NATIVE_HOSTS, ["claude-code", "codex", "copilot", "cursor", "gemini"]);
  const paths = (host, platform) => nativeSettings(POLICY, host, { platform }).files.map((f) => f.path);
  assert.deepEqual(paths("claude-code", "darwin"), ["/Library/Application Support/ClaudeCode/managed-settings.d/50-moorai.json"]);
  assert.deepEqual(paths("claude-code", "linux"), ["/etc/claude-code/managed-settings.d/50-moorai.json"]);
  assert.deepEqual(paths("claude-code", "win32"), ["C:\\Program Files\\ClaudeCode\\managed-settings.d\\50-moorai.json"]);
  assert.deepEqual(paths("codex", "linux"), ["/etc/codex/requirements.toml"]);
  assert.deepEqual(paths("codex", "win32"), ["C:\\ProgramData\\OpenAI\\Codex\\requirements.toml"]);
  assert.deepEqual(paths("copilot", "darwin"), ["/Library/Application Support/GitHubCopilot/managed-settings.json"]);
  assert.deepEqual(paths("copilot", "linux"), ["/etc/github-copilot/managed-settings.json"]);
  assert.deepEqual(paths("cursor", "linux"), ["~/.cursor/cli-config.json"]);
  assert.deepEqual(paths("gemini", "darwin").sort(), ["/Library/Application Support/GeminiCli/policies/moorai.toml", "/Library/Application Support/GeminiCli/settings.json"]);
});

test("hosts: an unknown host or platform is refused", () => {
  assert.equal(nativeSettings(POLICY, "windsurf").ok, false);
  assert.equal(nativeSettings(POLICY, "windsurf").reasonCode, "unsupported-host");
  assert.equal(nativeSettings(POLICY, "codex", { platform: "plan9" }).reasonCode, "unsupported-platform");
});

test("hosts: an empty policy writes no file anywhere", () => {
  for (const h of NATIVE_HOSTS) {
    const r = nativeSettings({}, h, { platform: "linux" });
    assert.equal(r.ok, true, h);
    assert.deepEqual(r.files, [], h);
  }
});

test("claude-code: permissions, MCP allow-list and the sandbox from one policy", () => {
  const r = nativeSettings(POLICY, "claude-code", { platform: "linux" });
  const c = r.files[0].content;
  assert.deepEqual(c.permissions.deny, ["Bash", "Monitor", "PowerShell", "WebFetch(domain:evil.example.com)"]);
  assert.deepEqual(c.permissions.ask, ["WebFetch", "WebSearch"]);
  assert.deepEqual(c.allowedMcpServers, [{ serverName: "github" }]);
  assert.equal(c.allowManagedMcpServersOnly, true);
  assert.equal(c.sandbox.enabled, true);
  assert.equal(c.sandbox.failIfUnavailable, true);
  assert.equal(c.sandbox.allowUnsandboxedCommands, false);
  assert.deepEqual(c.sandbox.network.deniedDomains, ["evil.example.com"]);
  assert.deepEqual(c.sandbox.network.allowedDomains, ["*.example.com:443", "api.partner.test"]);
  assert.equal(c.sandbox.network.allowManagedDomainsOnly, true);
  // "bad name" is outside the serverName charset Claude Code accepts in allowedMcpServers: the native
  // list refuses a server MoorAI allows.
  assert.ok(unexp(r, (u) => u.source === "mcpAllow" && u.effect === "narrowed" && u.reason === "claude-code-server-name-charset").length);
  // the path-limited allow is wider natively; the method-limited block is MoorAI's alone.
  assert.ok(unexp(r, (u) => u.source === "egressRules" && u.index === 2 && u.effect === "coarsened").length);
  assert.ok(unexp(r, (u) => u.source === "egressRules" && u.index === 3 && u.effect === "omitted").length);
  assert.equal(r.files[0].scope, "managed");
  assert.equal(r.files[0].merge, "whole");
});

test("claude-code: an allow followed by an overlapping block is narrowed natively (deny wins there)", () => {
  const r = nativeSettings({ egressRules: [{ host: "*.example.com", action: "allow" }, { host: "evil.example.com", action: "block" }], egressDefault: "block" }, "claude-code", { platform: "linux" });
  assert.ok(unexp(r, (u) => u.source === "egressRules" && u.index === 0 && u.effect === "narrowed").length);
  const r2 = nativeSettings({ egressRules: [{ host: "evil.example.com", action: "block" }, { host: "*.example.com", action: "allow" }], egressDefault: "block" }, "claude-code", { platform: "linux" });
  assert.equal(unexp(r2, (u) => u.effect === "narrowed" && u.source === "egressRules").length, 0);
});

test("claude-code: blocks without a block default leave the sandbox off and say the lists may be inert", () => {
  const r = nativeSettings({ egressRules: [{ host: "evil.example.com", action: "block" }] }, "claude-code", { platform: "linux" });
  const c = r.files[0].content;
  assert.equal(c.sandbox.enabled, undefined);
  assert.deepEqual(c.sandbox.network.deniedDomains, ["evil.example.com"]);
  assert.ok(c.permissions.deny.includes("WebFetch(domain:evil.example.com)"));
  assert.ok(unexp(r, (u) => u.source === "egressRules" && u.effect === "may-be-inert" && u.reason === "claude-code-sandbox-off").length);
});

test("claude-code: allow-only tools become denies of every other built-in, reported as coarser for new tools", () => {
  const r = nativeSettings({ entitlementMode: "block", entitlements: { tools: ["Read", "Grep", "Glob"] } }, "claude-code", { platform: "linux" });
  const deny = r.files[0].content.permissions.deny;
  assert.ok(deny.includes("Bash") && deny.includes("Write") && deny.includes("WebFetch"));
  assert.ok(!deny.includes("Read") && !deny.includes("Grep") && !deny.includes("Glob"));
  assert.ok(unexp(r, (u) => u.source === "entitlements" && u.effect === "coarsened").length);
});

test("claude-code: the approval gate with nothing approved is an empty allowedMcpServers (no server allowed)", () => {
  const c = nativeSettings({ mcpGate: true }, "claude-code", { platform: "linux" }).files[0].content;
  assert.deepEqual(c.allowedMcpServers, []);
  assert.equal(c.allowManagedMcpServersOnly, true);
});

test("codex: requirements.toml carries web search, the MCP identity allow-list and the managed network proxy", () => {
  const p = { tagActions: { network: "block", write: "block" }, mcpAllow: ["github", "docs"], egressRules: [{ host: "evil.example.com", action: "block" }, { host: "*.example.com", action: "allow" }], egressDefault: "block" };
  const r = nativeSettings(p, "codex", { platform: "linux", mcpIdentities: { github: { url: "https://api.githubcopilot.com/mcp/" } } });
  const t = r.files[0].content;
  assert.equal(r.files[0].format, "toml");
  assert.match(t, /^allowed_web_search_modes = \[\]$/m);
  assert.match(t, /^\[allowed_permission_profiles\]\n":read-only" = true$/m);
  assert.match(t, /^\[mcp_servers\.github\]\nidentity = \{ url = "https:\/\/api\.githubcopilot\.com\/mcp\/" \}$/m);
  assert.doesNotMatch(t, /mcp_servers\.docs/);
  assert.match(t, /^\[experimental_network\]\nenabled = true\nmanaged_allowed_domains_only = true$/m);
  assert.match(t, /^\[experimental_network\.domains\]\n"\*\.example\.com" = "allow"\n"evil\.example\.com" = "deny"$/m);
  // docs has no identity: Codex would disable a server MoorAI allows.
  assert.ok(unexp(r, (u) => u.source === "mcpAllow" && u.effect === "narrowed" && u.reason === "codex-mcp-identity-required").length);
  // Codex has no per-tool deny for the shell.
  assert.ok(unexp(nativeSettings({ tagActions: { exec: "block" } }, "codex", { platform: "linux" }), (u) => u.source === "tagActions" && u.effect === "omitted" && u.reason === "codex-no-tool-deny").length);
});

test("codex: blocks with an allow default do not lock the proxy to managed domains, and say the unlisted case is unstated", () => {
  const r = nativeSettings({ egressRules: [{ host: "evil.example.com", action: "block" }] }, "codex", { platform: "linux" });
  assert.match(r.files[0].content, /^\[experimental_network\]\nenabled = true\nmanaged_allowed_domains_only = false$/m);
  assert.ok(unexp(r, (u) => u.source === "egressDefault" && u.effect === "approximated" && u.reason === "codex-unlisted-domain-unstated").length);
  assert.ok(r.notes.some((n) => n.reason === "codex-network-experimental"));
});

test("codex: no identity known for any allowed server leaves the list out and says it is wider", () => {
  const r = nativeSettings({ mcpAllow: ["github"] }, "codex", { platform: "linux" });
  assert.deepEqual(r.files, []);
  assert.ok(unexp(r, (u) => u.source === "mcpAllow" && u.effect === "coarsened" && u.reason === "codex-mcp-identity-required").length);
  // nothing approved under the gate: an empty mcp_servers table disables every server, which is exact.
  const g = nativeSettings({ mcpGate: true }, "codex", { platform: "linux" });
  assert.match(g.files[0].content, /^\[mcp_servers\]$/m);
});

test("copilot: managed permissions, MCP allow-list and limitTo", () => {
  const r = nativeSettings(POLICY, "copilot", { platform: "linux" });
  const c = r.files[0].content;
  assert.deepEqual(c.permissions.deny, ["Domain(evil.example.com)", "PowerShell(*)", "Shell(*)"]);
  assert.deepEqual(c.permissions.limitTo, ["*.example.com", "api.partner.test"]);
  assert.deepEqual(c.allowedMcpServers, [{ serverName: "bad name" }, { serverName: "github" }]);
  assert.equal(r.files[0].merge, "keys");
  // limitTo does not restrict shell commands.
  assert.ok(unexp(r, (u) => u.source === "egressDefault" && u.effect === "coarsened" && u.reason === "copilot-limitto-not-shell").length);
  // the port-limited allow is domain-wide natively.
  assert.ok(unexp(r, (u) => u.source === "egressRules" && u.index === 1 && u.effect === "coarsened").length);
});

test("cursor: user-scope cli-config.json permissions, and no file mechanism for an MCP allow-list", () => {
  const r = nativeSettings({ tagActions: { exec: "block", network: "block" }, mcpAllow: ["github"], egressRules: [{ host: "evil.example.com", action: "block" }] }, "cursor", { platform: "darwin" });
  const f = r.files[0];
  assert.equal(f.scope, "user");
  assert.equal(f.merge, "keys");
  assert.deepEqual(f.content.permissions.deny, ["Shell(*)", "WebFetch(*)", "WebFetch(evil.example.com)"]);
  assert.ok(unexp(r, (u) => u.source === "mcpAllow" && u.effect === "coarsened" && u.reason === "cursor-mcp-allowlist-no-file").length);
  assert.ok(r.notes.some((n) => n.reason === "cursor-user-writable"));
});

test("gemini: admin-tier policy TOML for tool denies, settings.json for the MCP allow-list, no network policy", () => {
  const r = nativeSettings(POLICY, "gemini", { platform: "linux" });
  const toml = file(r, "moorai.toml").content;
  assert.match(toml, /\[\[rule\]\]\ntoolName = "run_shell_command"\ndecision = "deny"\npriority = 900\n/);
  assert.match(toml, /\[\[rule\]\]\ntoolName = "read_many_files"\ndecision = "deny"/);
  assert.match(toml, /\[\[rule\]\]\ntoolName = "web_fetch"\ndecision = "ask_user"/);
  assert.deepEqual(file(r, "settings.json").content.mcp.allowed, ["bad name", "github"]);
  assert.ok(unexp(r, (u) => u.source === "egressDefault" && u.effect === "omitted" && u.reason === "gemini-no-network-policy").length);
  assert.ok(unexp(r, (u) => u.source === "egressRules" && u.index === 0 && u.effect === "omitted").length);
  const g = nativeSettings({ mcpGate: true }, "gemini", { platform: "linux" });
  assert.match(file(g, "moorai.toml").content, /\[\[rule\]\]\nmcpName = "\*"\ndecision = "deny"/);
});

test("determinism: key order and list order of the policy do not change any output byte", () => {
  const a = { tagActions: { exec: "block", write: "ask" }, mcpAllow: ["b", "a"], egressRules: POLICY.egressRules, egressDefault: "block" };
  const b = { egressDefault: "block", egressRules: POLICY.egressRules, mcpAllow: ["a", "b"], tagActions: { write: "ask", exec: "block" } };
  for (const h of NATIVE_HOSTS) {
    const ra = nativeSettings(a, h, { platform: "linux" }), rb = nativeSettings(b, h, { platform: "linux" });
    assert.deepEqual(ra.files.map(renderFile), rb.files.map(renderFile), h);
    assert.deepEqual(ra.unexpressed, rb.unexpressed, h);
  }
});

test("content-free report: unexpressed lines name sources, indexes, tags and tools, never a host or server", () => {
  for (const h of NATIVE_HOSTS) {
    const s = JSON.stringify(nativeSettings(POLICY, h, { platform: "linux" }).unexpressed);
    for (const leak of ["evil.example.com", "example.com", "partner.test", "paste.test", "github", "bad name"]) assert.ok(!s.includes(leak), `${h} leaks ${leak}`);
  }
});

// ---------- 3. never widen (independent evaluators) ----------

const RANK = { allow: 0, ask: 1, deny: 2 };
const TOOLS = ["Bash", "PowerShell", "Monitor", "Read", "Glob", "Grep", "LS", "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Task"];

// MoorAI's intent for a built-in tool call, from the policy (data/tool-tags.js BUILTIN_TOOL_TAGS semantics).
const TAG_OF = { Read: "read", Glob: "read", Grep: "read", LS: "read", Write: "write", Edit: "write", MultiEdit: "write", NotebookEdit: "write", WebFetch: "network", WebSearch: "network", Bash: "exec", PowerShell: "exec", Monitor: "exec" };
function intentTool(p, t) {
  let d = "allow";
  const a = p.tagActions?.[TAG_OF[t]];
  if (a === "block") d = "deny"; else if (a === "ask") d = "ask";
  if (p.entitlementMode === "block" && p.entitlements?.tools?.length && !p.entitlements.tools.includes(t)) d = "deny";
  return d;
}
function intentMcp(p, s) {
  const gate = p.mcpGate === true, list = p.mcpAllow;
  let ok = gate ? Array.isArray(list) && list.includes(s) : !Array.isArray(list) || !list.length || list.includes(s);
  if (p.entitlementMode === "block" && p.entitlements?.mcp?.length && !p.entitlements.mcp.includes(s)) ok = false;
  return ok ? "allow" : "deny";
}
// Claude Code, from code.claude.com/docs/en/permissions + managed-mcp: deny > ask > allow; a bare tool name
// matches every use of it; allowedMcpServers unset = all, [] = none, serverName exact.
function claudeTool(c, t) {
  const p = c.permissions || {};
  if ((p.deny || []).includes(t)) return "deny";
  if ((p.ask || []).includes(t)) return "ask";
  return "allow";
}
function claudeMcp(c, s) {
  if ((c.deniedMcpServers || []).some((e) => e.serverName === s)) return "deny";
  if (!Array.isArray(c.allowedMcpServers)) return "allow";
  return c.allowedMcpServers.some((e) => e.serverName === s) ? "allow" : "deny";
}

const PROPERTY_POLICIES = [
  POLICY,
  { tagActions: { write: "block", read: "ask" } },
  { entitlementMode: "block", entitlements: { tools: ["Read", "Bash"], mcp: ["github"] }, mcpAllow: ["github", "jira"] },
  { entitlementMode: "alert", entitlements: { tools: ["Read"] }, mcpGate: true, mcpAllow: ["x_y", "ok-1"] },
  { tagActions: { network: "block", exec: "ask" }, mcpAllow: ["has.dot", "fine"] }
];

test("never widen: Claude Code tools and MCP servers are never looser than MoorAI unless reported", () => {
  for (const p of PROPERTY_POLICIES) {
    const r = nativeSettings(p, "claude-code", { platform: "linux" });
    const c = r.files[0]?.content || {};
    for (const t of TOOLS) {
      const want = intentTool(p, t), got = claudeTool(c, t);
      if (RANK[got] < RANK[want]) assert.ok(r.unexpressed.some((u) => ["coarsened", "omitted"].includes(u.effect) && (u.tool === t || u.item === TAG_OF[t])), `${t} looser natively without a report: ${JSON.stringify(p)}`);
      if (RANK[got] > RANK[want]) assert.ok(r.unexpressed.some((u) => u.effect === "narrowed"), `${t} stricter natively without a report`);
    }
    for (const s of ["github", "jira", "x_y", "ok-1", "has.dot", "fine", "bad name", "other"]) {
      const want = intentMcp(p, s), got = claudeMcp(c, s);
      if (RANK[got] < RANK[want]) assert.fail(`MCP ${s} looser natively: ${JSON.stringify(p)}`);
      if (RANK[got] > RANK[want]) assert.ok(r.unexpressed.some((u) => u.source === "mcpAllow" && u.effect === "narrowed"), `MCP ${s} stricter natively without a report: ${JSON.stringify(p)}`);
    }
  }
});

// Gemini CLI, from geminicli.com/docs/reference/policy-engine: a deny rule for the tool name denies it;
// ask_user prompts. mcp.allowed is the server allow-list; mcpName "*" deny refuses every server.
const GEMINI_NAME = { Bash: "run_shell_command", Read: "read_file", Write: "write_file", Edit: "replace", WebFetch: "web_fetch", WebSearch: "google_web_search", Task: "invoke_agent" };
function geminiRules(toml) {
  return toml.split("[[rule]]").slice(1).map((b) => Object.fromEntries([...b.matchAll(/^(\w+) = (".*?"|\d+)$/gm)].map((m) => [m[1], m[2].startsWith('"') ? JSON.parse(m[2]) : Number(m[2])])));
}
test("never widen: Gemini CLI tools are never looser than MoorAI unless reported", () => {
  for (const p of PROPERTY_POLICIES) {
    const r = nativeSettings(p, "gemini", { platform: "linux" });
    const rules = geminiRules(r.files.find((f) => f.path.endsWith(".toml"))?.content || "");
    for (const t of Object.keys(GEMINI_NAME)) {
      const hit = rules.filter((x) => x.toolName === GEMINI_NAME[t] && !x.mcpName);
      const got = hit.some((x) => x.decision === "deny") ? "deny" : hit.some((x) => x.decision === "ask_user") ? "ask" : "allow";
      const want = intentTool(p, t);
      if (RANK[got] < RANK[want]) assert.ok(r.unexpressed.some((u) => ["coarsened", "omitted"].includes(u.effect) && (u.tool === t || u.item === TAG_OF[t])), `gemini ${t} looser without a report`);
      if (RANK[got] > RANK[want]) assert.ok(r.unexpressed.some((u) => u.effect === "narrowed"), `gemini ${t} stricter without a report`);
    }
  }
});
