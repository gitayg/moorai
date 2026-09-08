// The SKILL SURFACE an AI coding agent auto-loads — the successor to the narrower "rules files" table.
// Matching is on the PATH only (a filename category, content-free); the file's content is scanned by
// the existing injection detectors, and only the kind + a one-way fingerprint ever leaves the device.
//
// WHY THIS IS WIDER THAN CLAUDE.md/.cursorrules. A modern agent does not load one rules file, it loads
// a whole surface: skills, subagent definitions, slash commands, MCP server configs, and settings files
// that can carry HOOKS (arbitrary shell commands at lifecycle events). Every one of those is auto-loaded
// or auto-discoverable, which makes every one of them worth poisoning — a single injected directive in
// any of them steers every future prompt, and a hook entry in a settings file is straight code execution.
//
// PROVENANCE OF THIS TABLE — the paths below were checked against Claude Code's own documentation
// (code.claude.com/docs/en/{memory,settings,mcp,hooks-guide,plugins,managed-settings}) and, where the
// entry exists on a real install, against the on-disk layout of ~/.claude. Entries that are documented
// but that we have NOT observed on disk are marked "doc-only" — they are still matched (a path match
// costs nothing and the docs are the harness's own contract), but the distinction is recorded rather
// than blurred. See docs/CAPABILITY_SPEC.md for the verified/doc-only split.
//
// SCOPE NOTE: this table spans several harnesses on purpose. .cursorrules/.windsurfrules/.clinerules
// and AGENTS.md are NOT read by Claude Code — they belong to Cursor / Windsurf / Cline / Codex — and
// claude_desktop_config.json belongs to Claude Desktop, which MoorAI guards through mcp-proxy/. MoorAI
// governs the device, not one vendor's CLI, so a path stays in the table if ANY governed agent loads it.

// [regex, kind, observed]. `kind` is the label that leaves the device; keep it stable, it is a
// vocabulary the console groups on. `observed` is true when the path was confirmed on a real install.
// Order matters: the FIRST match wins, so the specific entries precede the generic ones.
const SURFACE = [
  // ---- settings that can carry hooks (arbitrary command execution) — the highest-value target ----
  [/(^|[/\\])managed-settings\.d[/\\][^/\\]+\.json$/i, "claude-managed-settings", false],
  [/(^|[/\\])managed-settings\.json$/i, "claude-managed-settings", false],
  [/(^|[/\\])\.claude[/\\]settings(\.local)?\.json$/i, "claude-settings", true],
  [/(^|[/\\])\.claude[/\\]hooks([/\\].+)?$/i, "claude-hook", true],
  [/(^|[/\\])hooks[/\\]hooks\.json$/i, "plugin-hooks", false],

  // ---- MCP server configuration (which tools and data sources the agent can reach at all) ----
  [/(^|[/\\])managed-mcp\.json$/i, "managed-mcp", false],
  [/(^|[/\\])\.mcp\.json$/i, ".mcp.json", false],
  [/(^|[/\\])\.claude\.json$/i, "claude-user-config", true],
  [/(^|[/\\])claude_desktop_config\.json$/i, "claude-desktop-config", false],

  // ---- the skill surface proper: skills, subagents, slash commands ----
  [/(^|[/\\])\.claude[/\\]skills([/\\].+)?$/i, "claude-skill", true],
  [/(^|[/\\])\.claude[/\\]agents([/\\].+)?\.md$/i, "claude-agent", true],
  [/(^|[/\\])\.claude[/\\]commands([/\\].+)?$/i, "claude-command", true],
  [/(^|[/\\])plugins[/\\].+[/\\]agents[/\\][^/\\]+\.md$/i, "plugin-agent", false],
  [/(^|[/\\])SKILL\.md$/i, "claude-skill", true],

  // ---- plugin manifests and the background work they can declare ----
  [/(^|[/\\])\.claude-plugin[/\\](plugin|marketplace)\.json$/i, "claude-plugin", true],
  [/(^|[/\\])monitors[/\\]monitors\.json$/i, "plugin-monitors", false],
  [/(^|[/\\])\.lsp\.json$/i, "plugin-lsp", false],

  // ---- instruction / memory files loaded into context at session start ----
  [/(^|[/\\])\.claude[/\\]rules([/\\].+)?\.md$/i, "claude-rule", false],
  [/(^|[/\\])\.claude[/\\]projects[/\\][^/\\]+[/\\]memory[/\\][^/\\]+\.md$/i, "claude-memory", true],
  [/(^|[/\\])CLAUDE\.local\.md$/i, "CLAUDE.local.md", false],
  [/(^|[/\\])CLAUDE\.md$/i, "CLAUDE.md", true],
  [/(^|[/\\])AGENTS?\.md$/i, "AGENTS.md", false],

  // ---- other vendors' equivalents ----
  [/(^|[/\\])\.cursorrules$/i, ".cursorrules", false],
  [/(^|[/\\])\.cursor[/\\]rules([/\\].+)?$/i, ".cursor/rules", false],
  [/(^|[/\\])\.cursor[/\\]mcp\.json$/i, "cursor-mcp", false],

  // ---- other clients' DEDICATED MCP-config files (paths confirmed from each client's own docs/code) ----
  // Cline: code reads ~/.cline/data/settings/cline_mcp_settings.json (VS Code extension globalStorage
  //   uses the same filename); the ~/.cline/mcp.json in the overview docs is a documented-but-wrong path.
  [/(^|[/\\])cline_mcp_settings\.json$/i, "cline-mcp", false],
  // Windsurf (Cascade): ~/.codeium/windsurf/mcp_config.json.
  [/(^|[/\\])\.codeium[/\\]windsurf[/\\]mcp_config\.json$/i, "windsurf-mcp", false],
  // VS Code: workspace .vscode/mcp.json (dedicated MCP file — distinct from the .mcp.json entry above).
  [/(^|[/\\])\.vscode[/\\]mcp\.json$/i, "vscode-mcp", false],
  // Continue: dedicated per-server files under .continue/mcpServers/ (the mcpServers block inside
  //   .continue/config.yaml is NOT matched — a general config file, not an MCP-dedicated surface).
  [/(^|[/\\])\.continue[/\\]mcpServers[/\\][^/\\]+\.(ya?ml|json)$/i, "continue-mcp", false],
  // Zed: MCP ("context servers") live inside settings.json — global ~/.config/zed/settings.json or
  //   project .zed/settings.json. Anchored to the zed dir so it cannot clash with .claude/settings.json.
  [/(^|[/\\])\.?zed[/\\]settings\.json$/i, "zed-mcp", false],
  // Amazon Q Developer: global ~/.aws/amazonq/mcp.json or workspace .amazonq/mcp.json.
  [/(^|[/\\])\.?amazonq[/\\]mcp\.json$/i, "amazon-q-mcp", false],
  // Kiro: workspace .kiro/settings/mcp.json or user ~/.kiro/settings/mcp.json.
  [/(^|[/\\])\.kiro[/\\]settings[/\\]mcp\.json$/i, "kiro-mcp", false],

  [/(^|[/\\])\.windsurfrules$/i, ".windsurfrules", false],
  [/(^|[/\\])\.clinerules$/i, ".clinerules", false],
  [/(^|[/\\])\.github[/\\]copilot-instructions\.md$/i, "copilot-instructions", false],
  [/(^|[/\\])\.codex[/\\]config\.toml$/i, "codex-config", false]
];

export const SKILL_SURFACE_KINDS = [...new Set(SURFACE.map(([, kind]) => kind))];
export const SKILL_SURFACE_OBSERVED = [...new Set(SURFACE.filter(([, , o]) => o).map(([, kind]) => kind))];

export function skillSurfaceKind(path) {
  const p = String(path || "");
  for (const [re, kind] of SURFACE) if (re.test(p)) return kind;
  return null;
}
export function isSkillSurface(path) { return skillSurfaceKind(path) !== null; }
