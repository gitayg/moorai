// #88: an agent launching, installing or scheduling another AI agent (AML.T0103). Spread into DETECTORS.
//
// The decision is data/agent-launch.js: a shell command that starts an agent CLI in its non-interactive form
// (claude -p, codex exec, gemini -p, aider --message, cursor-agent -p, opencode run, goose run, npx
// @anthropic-ai/claude-code -p …), installs one (a global npm install, pip / pipx / uv, brew, winget, or a
// vendor install script fetched and run), or schedules one (cron, launchd, systemd, at, schtasks /
// Register-ScheduledTask naming an agent CLI).
//
// Boundaries:
//   #66 sub-agent / A2A delegation is the agent's OWN sub-agent tool (Claude Code's Agent / Task tool), which
//       the hook records in its Task branch; that call is not a shell command and never reaches these
//       detectors as one. #88 is the second agent started from the shell: its own process, its own
//       permissions, none of the parent's approvals.
//   #57 unsanctioned install judges the SOURCE (a remote script piped to a shell, a URL / git / alternate
//       index install, npx -y). An agent CLI from a vendor script (`curl -fsSL https://claude.ai/install.sh |
//       bash`) is both acts and raises both findings; a registry install (`npm i -g @openai/codex`) is not
//       #57's and raises #88 alone. #57's detectors are unchanged.
//   #46 agent persistence flags the cron / launchd / systemd / schtasks foothold whatever it runs; #88 adds
//       the finding that what is scheduled is an AI agent.
//
// Stages: "prompt", where the hook and the Agent SDK judge a Bash / PowerShell command (ctx.shell), as
// destructive-command (#43), clone-then-run (#80) and agent-persistence (#46) do. Text the agent reads
// (ctx.inbound, ctx.targetPath, ctx.template) and an unlabelled markdown document describe a launch and do
// not perform one. In text not labelled a command, a markdown inline code span (`claude -p`) is a name
// written in prose, not a command substitution: measured on the 286 paragraphs of README.md and docs/*.md
// that name an agent CLI, reading backticks the shell's way fired on 15, all of them prose. A person's turn
// marked prose (ctx.prose) that only asks about or explains an agent CLI stands down, by #43's rule
// (data/destructive-mention.js); a request keeps the finding. "output" carries
// only one case: a Write of a launchd plist, systemd unit or cron table (ctx.targetPath) that names an agent
// CLI. A model's reply, a README or a fetched page that shows `claude -p` is not judged.
//
// ONCE: refine() runs once per text and the reported match is one character, so no command, package or
// prompt ever reaches a finding.
import { agentCommandHit, agentScheduleHit, agentScheduleFileHit, AGENT_HINT, AGENT_MENTION } from "./agent-launch.js";
import { mentionOnly } from "./destructive-mention.js";

const ONCE = /^[\s\S]/;
const MD_FENCE = /^[ \t]{0,3}(?:```|~~~)/m;
const INLINE_CODE = /`[^`\n]{0,400}`/g;
const readContent = (ctx) => !!ctx && (!!ctx.inbound || !!ctx.targetPath || Object.prototype.hasOwnProperty.call(ctx, "template"));
const shellOf = (ctx) => (ctx && (ctx.shell === "sh" || ctx.shell === "ps") ? ctx.shell : "");

export function agentDeployHit(text, ctx) {
  if (typeof text !== "string" || !AGENT_HINT.test(text)) return false;
  const sh = shellOf(ctx);
  if (!sh && (readContent(ctx) || MD_FENCE.test(text))) return false;
  if (!sh && ctx && ctx.prose === true && mentionOnly(text, [AGENT_MENTION])) return false;
  const cmd = sh ? text : text.replace(INLINE_CODE, " ");
  return agentCommandHit(cmd, { ps: sh ? sh === "ps" : undefined }) || agentScheduleHit(cmd);
}

export const AGENT_DEPLOY_DETECTORS = [
  {
    detectorId: "agent-deploy",
    threatId: 88,
    stages: ["prompt"],
    mode: "warn",
    hint: "Starts, installs or schedules another AI agent from a shell command (claude -p, codex exec, gemini -p, aider --message, opencode run, an agent CLI install, or a cron / launchd / systemd / scheduled-task agent run).",
    patterns: [ONCE],
    refine: (_m, text, ctx) => agentDeployHit(text, ctx)
  },
  {
    detectorId: "agent-deploy-schedule-file",
    threatId: 88,
    stages: ["output"],
    mode: "warn",
    hint: "Writes a launchd plist, systemd unit or cron table that runs an AI agent CLI.",
    patterns: [ONCE],
    refine: (_m, text, ctx) => !!ctx && typeof ctx.targetPath === "string" && agentScheduleFileHit(ctx.targetPath, text)
  }
];
