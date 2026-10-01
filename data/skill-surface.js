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
  // Gemini CLI settings carry `hooks` and `mcpServers` (geminicli.com/docs/hooks, /docs/reference/configuration):
  //   .gemini/settings.json, ~/.gemini/settings.json, /etc/gemini-cli/settings.json,
  //   C:\ProgramData\gemini-cli\settings.json, /Library/Application Support/GeminiCli/settings.json, and the
  //   system-defaults.json beside each system file.
  [/(^|[/\\])(\.gemini|gemini-cli|GeminiCli)[/\\](settings|system-defaults)\.json$/i, "gemini-settings", false],
  // Kiro hooks run shell commands at session events (kiro.dev/docs/hooks): "Each hook file is a standalone
  //   JSON file at `.kiro/hooks/<id>.json`."
  [/(^|[/\\])\.kiro[/\\]hooks[/\\].+$/i, "kiro-hook", false],

  // ---- MCP server configuration (which tools and data sources the agent can reach at all) ----
  [/(^|[/\\])managed-mcp\.json$/i, "managed-mcp", false],
  [/(^|[/\\])\.mcp\.json$/i, ".mcp.json", false],
  [/(^|[/\\])\.claude\.json$/i, "claude-user-config", true],
  [/(^|[/\\])claude_desktop_config\.json$/i, "claude-desktop-config", false],
  // Amp (ampcode.com/docs/customize/mcp): `amp.mcpServers` in ~/.config/amp/settings.json or .amp/settings.json.
  [/(^|[/\\])(\.amp|\.config[/\\]amp)[/\\]settings\.json$/i, "amp-settings", false],
  // OpenCode (opencode.ai/docs/rules): opencode.json / ~/.config/opencode/opencode.json name extra
  //   instruction files in its `instructions` field.
  [/(^|[/\\])opencode\.json$/i, "opencode-config", false],

  // ---- the skill surface proper: skills, subagents, slash commands ----
  [/(^|[/\\])\.claude[/\\]skills([/\\].+)?$/i, "claude-skill", true],
  [/(^|[/\\])\.claude[/\\]agents([/\\].+)?\.md$/i, "claude-agent", true],
  [/(^|[/\\])\.claude[/\\]commands([/\\].+)?$/i, "claude-command", true],
  [/(^|[/\\])plugins[/\\].+[/\\]agents[/\\][^/\\]+\.md$/i, "plugin-agent", false],
  // Other agents' slash commands / workflows / prompt files / subagents — injected verbatim when invoked.
  // Cursor (cursor.com/changelog/1-6): "Commands are stored in `.cursor/commands/[command].md`".
  [/(^|[/\\])\.cursor[/\\]commands[/\\].+\.md$/i, "cursor-command", false],
  // Windsurf / Devin Desktop (docs.devin.ai/desktop/cascade/workflows): .devin/workflows/*.md,
  //   .windsurf/workflows/*.md, ~/.codeium/windsurf/global_workflows/*.md, and the system dirs
  //   /Library/Application Support/{Devin,Windsurf}/workflows, /etc/{devin,windsurf}/workflows,
  //   C:\ProgramData\{Devin,Windsurf}\workflows.
  [/(^|[/\\])\.?(windsurf|devin)[/\\](global_)?workflows[/\\].+\.md$/i, "windsurf-workflow", false],
  // Cline workflows: .clinerules/workflows/ and ~/Documents/Cline/Workflows (cline.bot blog; see report).
  [/(^|[/\\])(\.clinerules[/\\]workflows|Cline[/\\]Workflows)[/\\].+\.md$/i, "cline-workflow", false],
  // GitHub Copilot in VS Code (code.visualstudio.com/docs/copilot/customization/{prompt-files,custom-agents}):
  //   prompt files in the ".github/prompts folder"; custom agents = "any `.md` files in the `.github/agents`
  //   folder", user level "~/.copilot/agents".
  [/(^|[/\\])\.github[/\\]prompts[/\\].+\.prompt\.md$/i, "copilot-prompt", false],
  [/(^|[/\\])\.(github|copilot)[/\\]agents[/\\][^/\\]+\.md$/i, "copilot-agent", false],
  // Codex custom prompts (learn.chatgpt.com/docs/custom-prompts, deprecated but still loaded): ~/.codex/prompts/*.md.
  [/(^|[/\\])\.codex[/\\]prompts[/\\][^/\\]+\.md$/i, "codex-prompt", false],
  // Gemini CLI custom commands (geminicli.com/docs/cli/custom-commands): ~/.gemini/commands/ and
  //   <project>/.gemini/commands/, TOML, subdirectories namespace the command.
  [/(^|[/\\])\.gemini[/\\]commands[/\\].+\.toml$/i, "gemini-command", false],
  // OpenCode (opencode.ai/docs/{commands,agents}): ~/.config/opencode/{commands,agents}/ and .opencode/{commands,agents}/.
  [/(^|[/\\])(\.opencode|\.config[/\\]opencode)[/\\]commands[/\\].+\.md$/i, "opencode-command", false],
  [/(^|[/\\])(\.opencode|\.config[/\\]opencode)[/\\]agents[/\\].+\.md$/i, "opencode-agent", false],
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
  // AGENTS.md also covers Amp's AGENT.md fallback (ampcode.com/docs/customize/agents-md).
  [/(^|[/\\])AGENTS?\.md$/i, "AGENTS.md", false],
  // Codex (learn.chatgpt.com/docs/agent-configuration/agents-md): AGENTS.override.md wins over AGENTS.md.
  [/(^|[/\\])AGENTS\.override\.md$/i, "AGENTS.override.md", false],
  // Gemini CLI (geminicli.com/docs/cli/gemini-md): ~/.gemini/GEMINI.md and GEMINI.md in workspace dirs/parents.
  [/(^|[/\\])GEMINI\.md$/i, "GEMINI.md", false],
  // Copilot targeted instructions (code.visualstudio.com/docs/copilot/customization/custom-instructions):
  //   `.github/instructions`, searched "recursively", and "~/.copilot/instructions" at user scope.
  [/(^|[/\\])\.(github|copilot)[/\\]instructions[/\\].+\.instructions\.md$/i, "copilot-path-instructions", false],
  // Kiro: steering in `.kiro/steering/` and `~/.kiro/steering/` (kiro.dev/docs/steering); specs in
  //   .kiro/specs/<name>/, and "Kiro automatically includes all spec files ... in the conversation context"
  //   (kiro.dev/docs/specs/best-practices).
  [/(^|[/\\])\.kiro[/\\]steering[/\\].+\.md$/i, "kiro-steering", false],
  [/(^|[/\\])\.kiro[/\\]specs[/\\].+\.md$/i, "kiro-spec", false],

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
  // Windsurf rules (docs.devin.ai/desktop/cascade/memories): .devin/rules/*.md, .windsurf/rules/*.md, the
  //   system dirs {Devin,Windsurf}/rules, and ~/.codeium/windsurf/memories/global_rules.md.
  [/(^|[/\\])\.?(windsurf|devin)[/\\]rules[/\\].+\.md$/i, "windsurf-rule", false],
  [/(^|[/\\])windsurf[/\\]memories[/\\]global_rules\.md$/i, "windsurf-global", false],
  // Cline (docs.cline.bot/features/cline-rules): `.clinerules/` is a DIRECTORY of rules (or a legacy single
  //   file), plus .cline/rules/, ~/Documents/Cline/Rules, ~/.cline/rules, ~/Cline/Rules.
  [/(^|[/\\])\.clinerules([/\\].+)?$/i, ".clinerules", false],
  [/(^|[/\\])(\.cline[/\\]rules|Cline[/\\]Rules)[/\\].+\.md$/i, "cline-rule", false],
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
