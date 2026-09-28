// The PROTECTED INSTRUCTION FILES an AI coding agent runs under, and the path-only signal "a network
// upload reads one of them". Browser-safe (no node: imports). Content-free: paths and command shapes only.
//
// PROVENANCE — every name below was checked against the tool's own documentation on 2026-09-27:
//   Claude Code  code.claude.com/docs/en/memory: ./CLAUDE.md, ./.claude/CLAUDE.md, ./CLAUDE.local.md,
//                ~/.claude/CLAUDE.md, .claude/rules/**/*.md, ~/.claude/rules/, managed policy
//                /Library/Application Support/ClaudeCode/CLAUDE.md, /etc/claude-code/CLAUDE.md,
//                C:\Program Files\ClaudeCode\CLAUDE.md; loaded from cwd and every directory above it.
//   Codex        learn.chatgpt.com/docs/agent-configuration/agents-md: AGENTS.md, AGENTS.override.md,
//                in $CODEX_HOME (default ~/.codex) and from the git root down to cwd.
//   Copilot      docs.github.com .../add-repository-instructions: .github/copilot-instructions.md,
//                .github/instructions/NAME.instructions.md, AGENTS.md, CLAUDE.md, GEMINI.md.
//   Cursor       cursor.com/docs/context/rules: .cursor/rules (.mdc), AGENTS.md. `.cursorrules` is no
//                longer in Cursor's docs but Cline still reads it (below), so it stays.
//   Gemini CLI   geminicli.com/docs/cli/gemini-md: ~/.gemini/GEMINI.md, GEMINI.md in workspace dirs and
//                parents (the name is configurable via context.fileName — a custom name is not seen).
//   Windsurf     docs.devin.ai/desktop/cascade/memories: ~/.codeium/windsurf/memories/global_rules.md,
//                .devin/rules/*.md, .windsurf/rules/*.md, .windsurfrules.
//   Cline        docs.cline.bot/features/cline-rules: .clinerules/ (or file), .cline/rules/,
//                ~/Documents/Cline/Rules, ~/.cline/rules, and it also reads .cursorrules,
//                .windsurfrules, AGENTS.md, ~/.agents/AGENTS.md.

// The upload shapes come from the leaf data/outbound-upload.js (not data/detectors.js, which imports this
// module through data/detectors-instruction-leak.js — reading it from there would be an import cycle).
import { OUTBOUND_UPLOAD } from "./outbound-upload.js";

// [regex on a normalized forward-slash path, kind]. First match wins. `kind` is a stable label.
export const INSTRUCTION_FILES = [
  [/(^|\/)\.claude\/rules\/.+\.md$/i, "claude-rule"],
  [/(^|\/)CLAUDE\.local\.md$/i, "CLAUDE.local.md"],
  [/(^|\/)CLAUDE\.md$/i, "CLAUDE.md"],
  [/(^|\/)AGENTS\.override\.md$/i, "AGENTS.override.md"],
  [/(^|\/)AGENTS\.md$/i, "AGENTS.md"],
  [/(^|\/)GEMINI\.md$/i, "GEMINI.md"],
  [/(^|\/)\.github\/copilot-instructions\.md$/i, "copilot-instructions"],
  [/(^|\/)\.github\/instructions\/[^/]+\.instructions\.md$/i, "copilot-path-instructions"],
  [/(^|\/)\.cursorrules$/i, ".cursorrules"],
  [/(^|\/)\.cursor\/rules\/.+\.mdc?$/i, ".cursor/rules"],
  [/(^|\/)\.windsurfrules$/i, ".windsurfrules"],
  [/(^|\/)\.(?:windsurf|devin)\/rules\/.+\.md$/i, "windsurf-rule"],
  [/(^|\/)windsurf\/memories\/global_rules\.md$/i, "windsurf-global"],
  [/(^|\/)\.clinerules(?:\/.+\.md)?$/i, ".clinerules"],
  [/(^|\/)\.cline\/rules\/.+\.md$/i, "cline-rule"],
  [/(^|\/)Cline\/Rules\/.+\.md$/, "cline-rule"]
];

export function instructionFileKind(path) {
  if (typeof path !== "string" || !path) return null;
  const p = path.replace(/\\/g, "/");
  for (const [re, kind] of INSTRUCTION_FILES) if (re.test(p)) return kind;
  return null;
}

export const isInstructionFilePath = (path) => instructionFileKind(path) !== null;

// ---------------------------------------------------------------------------------------------------
// Path-only egress: an upload command whose DATA is a rules file. `curl -d "$(cat CLAUDE.md)" https://…`
// never contains the file's text — the shell expands it after the hook has looked — so no content
// fingerprint can see it. What the command does show is WHICH file feeds the upload.
//
// Fires only when the rules-file reference is in a data position of an upload in the same command
// segment (segments split on ; && || and newlines, NOT on a single |, so `cat X | curl -d @-` stays
// one segment). Silent on: the name inside a URL (a download or an API path), `-o`/`-O`/`--output`/
// `-OutFile`/`>` targets (a download INTO the file), a JSON string that merely names the file, git
// operations, and every non-upload command.
// ---------------------------------------------------------------------------------------------------

// The file names above as they appear in a shell word (no directory anchoring needed; a preceding path
// is allowed). Kept to names distinctive enough that a bare mention is unambiguous.
const NAME = String.raw`(?:[\w.~\-\/\\]{0,200}[\/\\])?(?:CLAUDE(?:\.local)?\.md|AGENTS(?:\.override)?\.md|GEMINI\.md|copilot-instructions\.md|[\w.\-]{1,100}\.instructions\.md|\.cursorrules|\.windsurfrules|\.clinerules|global_rules\.md|\.cursor[\/\\]rules[\/\\][\w.\-\/\\]{1,200}\.mdc?|\.claude[\/\\]rules[\/\\][\w.\-\/\\]{1,200}\.md)`;

export const INSTRUCTION_NAME_RE = new RegExp(`(?<![\\w.\\-])${NAME}(?![\\w.\\-])`, "i");

// The engine-side prefilter for the path detector: no unbounded quantifier, so it passes the ReDoS guard
// (src/safe-regex.js) the engine compiles every pattern through. refine() does the real work.
export const INSTRUCTION_NAME_PREFILTER = /(?:CLAUDE(?:\.local)?|AGENTS(?:\.override)?|GEMINI)\.md|copilot-instructions\.md|\.instructions\.md|\.cursorrules|\.windsurfrules|\.clinerules|global_rules\.md|\.cursor[\/\\]rules|\.claude[\/\\]rules/i;

const READERS = String.raw`(?:cat|tac|head|tail|less|more|base64|base32|xxd|od|hexdump|gzip|bzip2|xz|zstd|tar|zip|openssl|gpg|jq|yq|sed|awk|cut|tr|sort|uniq|iconv|type|Get-Content|gc)`;

// A rules file in a DATA position of the command. Each needs an upload sink in the same segment.
const DATA_POS = [
  new RegExp(String.raw`@\s?["']?${NAME}`, "i"),                                          // curl -d @CLAUDE.md, -F f=@AGENTS.md
  new RegExp(String.raw`(?:\$\(|\x60)\s*${READERS}\b[^)\x60\n]{0,200}?${NAME}`, "i"),        // "$(cat CLAUDE.md)", `base64 AGENTS.md`
  new RegExp(String.raw`\$\(\s*<\s*["']?${NAME}`, "i"),                                     // "$(<CLAUDE.md)"
  new RegExp(String.raw`(?<![<\-])<\s?["']?${NAME}`, "i"),                                  // curl --data-binary @- < CLAUDE.md
  new RegExp(String.raw`(?:-T|--upload-file|-InFile)\s{1,4}["']?${NAME}`),                  // curl -T CLAUDE.md, iwr -InFile
  new RegExp(String.raw`-Body\s{1,4}\(?\s*(?:Get-Content|gc)\b[^)\n]{0,200}?${NAME}`, "i")  // irm -Body (Get-Content CLAUDE.md)
];
// `cat CLAUDE.md | … | curl …` — a reader on the rules file, then a pipe, with the upload AFTER it.
const PIPED = new RegExp(String.raw`\b${READERS}\b[^|;&\n]{0,200}?${NAME}[^|;&\n]{0,200}?\|([\s\S]*)$`, "i");

// Commands that ARE an upload by themselves when a rules file is an operand.
const SELF_UPLOAD = [
  new RegExp(String.raw`\bgh\s{1,4}gist\s{1,4}create\b[^\n]{0,300}?${NAME}`, "i"),
  new RegExp(String.raw`\b(?:scp|rsync)\b[^\n]{0,300}?${NAME}[^\n]{0,300}?\s[\w.\-]+@?[\w.\-]*:`, "i"),
  new RegExp(String.raw`\b(?:aws\s{1,4}s3\s{1,4}(?:cp|mv)|gsutil\s{1,4}(?:cp|mv)|rclone\s{1,4}(?:copy|copyto|move))\s[^\n]{0,300}?${NAME}[^\n]{0,300}?\s(?:s3|gs|[\w\-]+):`, "i")
];

const splitSegments = (t) => t.split(/;|&&|\|\||\n/);

export function rulesFileEgressHit(text) {
  if (typeof text !== "string" || !text || text.length > 65536) return false;
  if (!INSTRUCTION_NAME_RE.test(text)) return false;
  for (const seg of splitSegments(text)) {
    if (!INSTRUCTION_NAME_RE.test(seg)) continue;
    if (SELF_UPLOAD.some((r) => r.test(seg))) return true;
    const upload = OUTBOUND_UPLOAD.some((r) => r.test(seg));
    if (!upload) continue;
    if (DATA_POS.some((r) => r.test(seg))) return true;
    const p = PIPED.exec(seg);
    if (p && OUTBOUND_UPLOAD.some((r) => r.test(p[1]))) return true;
  }
  return false;
}
