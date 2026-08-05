// Backslash-inspired, content-free — recognize the "rules"/config files coding agents auto-load into
// context, so poisoned or drifting instructions in them can be flagged. Matching is on the PATH only
// (a filename category, content-free); the file's content is scanned by the existing injection
// detectors, and only a one-way fingerprint of it ever leaves the device.
const RULES = [
  [/(^|[/\\])CLAUDE\.md$/i, "CLAUDE.md"],
  [/(^|[/\\])AGENTS?\.md$/i, "AGENTS.md"],
  [/(^|[/\\])\.cursorrules$/i, ".cursorrules"],
  [/(^|[/\\])\.cursor[/\\]rules([/\\].+)?$/i, ".cursor/rules"],
  [/(^|[/\\])\.windsurfrules$/i, ".windsurfrules"],
  [/(^|[/\\])\.clinerules$/i, ".clinerules"],
  [/(^|[/\\])\.github[/\\]copilot-instructions\.md$/i, "copilot-instructions"],
  [/(^|[/\\])\.mcp\.json$/i, ".mcp.json"],
  [/(^|[/\\])\.claude[/\\](settings|hooks)[^/\\]*$/i, "claude-config"],
  [/(^|[/\\])\.claude[/\\]skills([/\\].+)?$/i, "claude-skill"]
];

export function rulesFileKind(path) {
  const p = String(path || "");
  for (const [re, kind] of RULES) if (re.test(p)) return kind;
  return null;
}
export function isRulesFile(path) { return rulesFileKind(path) !== null; }
