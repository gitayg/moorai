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
  // Factory Droid hooks run shell commands at lifecycle events (docs.factory.com reference/hooks-reference,
  //   droid-cli/settings, enterprise/hierarchical-settings-and-org-control): ~/.factory/hooks.json and
  //   .factory/hooks.json, the `hooks` key of settings.json / settings.local.json beside them, the legacy
  //   .factory/hooks/hooks.json, and the org-managed settings.json (/etc/factory, /Library/Application
  //   Support/Factory, C:\Program Files\Factory). Before the generic plugin-hooks entry: first match wins.
  [/(^|[/\\])\.factory[/\\](hooks|settings(\.local)?)\.json$/i, "droid-settings", false],
  [/(^|[/\\])\.factory[/\\]hooks[/\\]hooks\.json$/i, "droid-settings", false],
  [/(^|[/\\])(etc[/\\]factory|Application Support[/\\]Factory|Program Files[/\\]Factory)[/\\]settings\.json$/i, "droid-settings", false],
  [/(^|[/\\])hooks[/\\]hooks\.json$/i, "plugin-hooks", false],
  // Gemini CLI settings carry `hooks` and `mcpServers` (geminicli.com/docs/hooks, /docs/reference/configuration):
  //   .gemini/settings.json, ~/.gemini/settings.json, /etc/gemini-cli/settings.json,
  //   C:\ProgramData\gemini-cli\settings.json, /Library/Application Support/GeminiCli/settings.json, and the
  //   system-defaults.json beside each system file.
  [/(^|[/\\])(\.gemini|gemini-cli|GeminiCli)[/\\](settings|system-defaults)\.json$/i, "gemini-settings", false],
  // Kiro hooks run shell commands at session events (kiro.dev/docs/hooks): "Each hook file is a standalone
  //   JSON file at `.kiro/hooks/<id>.json`."
  [/(^|[/\\])\.kiro[/\\]hooks[/\\].+$/i, "kiro-hook", false],
  // Antigravity hooks (antigravity.google/docs/hooks): workspace `.agents/hooks.json`, global
  //   `~/.gemini/config/hooks.json`, and for the CLI a `hooks` entry in ~/.gemini/antigravity-cli/settings.json.
  [/(^|[/\\])(\.gemini[/\\]config|\.agents)[/\\]hooks\.json$/i, "antigravity-hooks", false],
  [/(^|[/\\])\.gemini[/\\]antigravity-cli[/\\]settings\.json$/i, "antigravity-hooks", false],
  // Windsurf / Devin Desktop Cascade hooks (docs.devin.ai/desktop/cascade/hooks): user ~/.codeium/windsurf/
  //   hooks.json (JetBrains ~/.codeium/hooks.json), workspace .devin/hooks.json (legacy .windsurf/hooks.json),
  //   system /Library/Application Support/{Devin,Windsurf}, /etc/{devin,windsurf}, C:\ProgramData\{Devin,Windsurf}.
  [/(^|[/\\])(\.codeium[/\\]windsurf|\.codeium|\.devin|\.windsurf)[/\\]hooks\.json$/i, "windsurf-hooks", false],
  [/(^|[/\\])(etc[/\\](devin|windsurf)|Application Support[/\\](Devin|Windsurf)|ProgramData[/\\](Devin|Windsurf))[/\\]hooks\.json$/i, "windsurf-hooks", false],
  // Cline hook scripts, one executable per hook type (cline.bot/blog/cline-v3-36-hooks; dirs from
  //   docs.cline.bot/getting-started/config): ~/.cline/hooks/, ~/Documents/Cline/Hooks/, .cline/hooks/ and the
  //   legacy .clinerules/hooks/. Before the generic .clinerules entry: first match wins.
  [/(^|[/\\])(\.cline[/\\]hooks|Cline[/\\]Hooks|\.clinerules[/\\]hooks)[/\\][^/\\]+$/i, "cline-hook", false],

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
  // OpenClaw (docs.openclaw.ai/concepts/agent-workspace, checked 2026-10-23), workspace ~/.openclaw/workspace:
  //   SOUL.md "Loaded every session"; MEMORY.md is curated long-term memory, loaded "in the main, private
  //   session"; memory/YYYY-MM-DD.md, "read today + yesterday on session start". AGENTS.md (also loaded) is
  //   matched below. After claude-memory, so Claude Code's own memory/MEMORY.md keeps its kind.
  [/(^|[/\\])SOUL\.md$/i, "openclaw-soul", false],
  [/(^|[/\\])\.openclaw[/\\]workspace[/\\]memory[/\\][^/\\]+\.md$/i, "openclaw-memory", false],
  [/(^|[/\\])MEMORY\.md$/i, "openclaw-memory", false],
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
  // Antigravity (antigravity.google/docs/cli/gcli-migration): global ~/.gemini/config/mcp_config.json,
  //   workspace .agents/mcp_config.json.
  [/(^|[/\\])(\.gemini[/\\]config|\.agents)[/\\]mcp_config\.json$/i, "antigravity-mcp", false],

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
  [/(^|[/\\])\.codex[/\\]config\.toml$/i, "codex-config", false],

  // ---- IDE auto-run surfaces — files an editor or container runtime executes when a folder opens, which
  //      ATT&CK v20 names under T1195.001 (Compromise Software Dependencies and Development Tools) ----
  // VS Code: a task with `"runOptions": { "runOn": "folderOpen" }` runs its shell command on open.
  //   (code.visualstudio.com/docs/editor/tasks#_run-behavior).
  [/(^|[/\\])\.vscode[/\\]tasks\.json$/i, "vscode-tasks", false],
  // JetBrains run configurations — shell/other commands launched from the IDE — live in .idea/workspace.xml
  //   and .idea/runConfigurations/*.xml (jetbrains.com/help/idea/run-debug-configuration.html).
  [/(^|[/\\])\.idea[/\\]workspace\.xml$/i, "idea-workspace", false],
  [/(^|[/\\])\.idea[/\\]runConfigurations[/\\][^/\\]+\.xml$/i, "idea-run-config", false],
  // Dev Containers: onCreate/postCreate/postStart commands run a shell when the container is built or
  //   attached (containers.dev/implementors/json_reference).
  [/(^|[/\\])\.devcontainer([/\\][^/\\]+)?[/\\]devcontainer\.json$/i, "devcontainer", false],
  [/(^|[/\\])\.devcontainer\.json$/i, "devcontainer", false]
];

export const SKILL_SURFACE_KINDS = [...new Set(SURFACE.map(([, kind]) => kind))];
export const SKILL_SURFACE_OBSERVED = [...new Set(SURFACE.filter(([, , o]) => o).map(([, kind]) => kind))];

// The PERSISTENT-INSTRUCTION subset: files the agent loads as standing instructions or memory at the start
// of every session, so a write into one outlives the conversation that made it. Skills, commands, subagent
// definitions and configs are left out: installing one of those is its own act, judged elsewhere.
// cli/oversight-surfaces.mjs protects these paths by default (a write asks under #84 protected-surface).
export const PERSISTENT_INSTRUCTION_KINDS = Object.freeze([
  "claude-memory", "CLAUDE.md", "CLAUDE.local.md", "claude-rule",
  "AGENTS.md", "AGENTS.override.md", "GEMINI.md",
  ".cursorrules", ".cursor/rules", ".windsurfrules", "windsurf-rule", "windsurf-global",
  ".clinerules", "cline-rule", "copilot-instructions", "copilot-path-instructions", "kiro-steering",
  "openclaw-soul", "openclaw-memory"
]);
const PERSISTENT = new Set(PERSISTENT_INSTRUCTION_KINDS);
export function persistentInstructionKind(path) {
  const k = skillSurfaceKind(path);
  return k && PERSISTENT.has(k) ? k : null;
}

// The AGENT-SETTINGS subset: agent and editor files whose documented effect is to skip an approval prompt or to run
// a command with no further prompt (a hook, an MCP server the client starts, a task that runs on folder open, an
// approval or sandbox mode). A write into one is how an agent widens its own permissions, so
// cli/oversight-surfaces.mjs watches these beside the persistent-instruction files (signal "memory-file").
// The kinds from SURFACE above, with the docs each entry already cites:
//   claude-settings, claude-managed-settings  permissions.allow / defaultMode and `hooks` (code.claude.com/docs/en/settings)
//   claude-hook                               hook scripts the settings run (code.claude.com/docs/en/hooks-guide)
//   claude-user-config                        ~/.claude.json: user and local MCP servers (code.claude.com/docs/en/mcp)
//   droid-settings, gemini-settings, kiro-hook, antigravity-hooks, windsurf-hooks, cline-hook, plugin-hooks
//                                             lifecycle hooks that run shell commands (the docs cited at each entry)
//   managed-mcp, .mcp.json, claude-desktop-config, amp-settings, opencode-config, cursor-mcp, cline-mcp,
//   windsurf-mcp, vscode-mcp, continue-mcp, zed-mcp, amazon-q-mcp, kiro-mcp, antigravity-mcp
//                                             an MCP server entry is a command the client launches; Visual Studio reads
//                                             %USERPROFILE%\.mcp.json, <solution>\.mcp.json, .vscode\mcp.json and
//                                             .cursor\mcp.json and restarts the servers when the file is saved
//                                             (learn.microsoft.com/visualstudio/ide/mcp-servers)
//   codex-config                              approval_policy, sandbox_mode and mcp_servers in .codex/config.toml
//   vscode-tasks                              a task with runOptions.runOn "folderOpen" runs on open
// Skills, commands, prompt files, subagent definitions, JetBrains run configurations and dev containers are left
// out: each is used only when someone invokes or opens it, and installing one is the "extension-install" origin gate.
const SETTINGS_FROM_SURFACE = [
  "claude-settings", "claude-managed-settings", "claude-hook", "claude-user-config",
  "droid-settings", "gemini-settings", "kiro-hook", "antigravity-hooks", "windsurf-hooks", "cline-hook", "plugin-hooks",
  "managed-mcp", ".mcp.json", "claude-desktop-config", "amp-settings", "opencode-config", "cursor-mcp", "cline-mcp",
  "windsurf-mcp", "vscode-mcp", "continue-mcp", "zed-mcp", "amazon-q-mcp", "kiro-mcp", "antigravity-mcp",
  "codex-config", "vscode-tasks"
];
// Settings files SURFACE does not list (they carry no instructions to scan), matched here only:
const SETTINGS_ONLY = [
  // VS Code workspace settings: chat.tools.terminal.autoApprove and chat.tools.global.autoApprove skip the
  //   confirmation for terminal commands and tools (code.visualstudio.com/docs/agents/approvals), and
  //   task.allowAutomaticTasks lets a folderOpen task run.
  [/(^|[/\\])\.vscode[/\\]settings\.json$/i, "vscode-settings"],
  // Cursor: permissions.json, ~/.cursor/ or <workspace>/.cursor/, mcpAllowlist and terminalAllowlist "can run without
  //   approval" (cursor.com/docs/reference/permissions); the CLI's permissions.allow, <project>/.cursor/cli.json and
  //   ~/.cursor/cli-config.json (cursor.com/docs/cli/reference/permissions).
  [/(^|[/\\])\.cursor[/\\](permissions|cli|cli-config)\.json$/i, "cursor-permissions"],
  // Visual Studio: per-solution settings in settings.VisualStudio.json beside the .sln / .slnx (Visual Studio blog,
  //   September 2026), and <solution>\.vs\mcp.json, an MCP configuration "Specific to Visual Studio"
  //   (learn.microsoft.com/visualstudio/ide/mcp-servers). CVE-2026-103572 (Visual Studio and SSMS Copilot) reached
  //   code execution by writing these settings and MCP files under a trailing-dot name.
  [/(^|[/\\])settings\.VisualStudio\.json$/i, "visualstudio-settings"],
  [/(^|[/\\])\.vs[/\\]mcp\.json$/i, "visualstudio-mcp"]
];
export const AGENT_SETTINGS_KINDS = Object.freeze([...SETTINGS_FROM_SURFACE, ...SETTINGS_ONLY.map(([, k]) => k)]);
const SETTINGS = new Set(SETTINGS_FROM_SURFACE);
export function agentSettingsKind(path) {
  const k = skillSurfaceKind(path);
  if (k && SETTINGS.has(k)) return k;
  const p = String(path || "");
  for (const [re, kind] of SETTINGS_ONLY) if (re.test(p)) return kind;
  return null;
}

export function skillSurfaceKind(path) {
  const p = String(path || "");
  for (const [re, kind] of SURFACE) if (re.test(p)) return kind;
  return null;
}
export function isSkillSurface(path) { return skillSurfaceKind(path) !== null; }
