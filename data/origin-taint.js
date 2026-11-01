// Origin-based session taint: what an outside-origin read gates, and the facts of one call that the gate reads.
//
// Reading a file that came from outside (cli/file-origin.mjs: a macOS quarantine or kMDItemWhereFroms mark, a
// Windows Zone.Identifier of zone 3 or 4, a path under the download directory) taints the session for
// sessionRisk.windowMin with no content analysis. A document from a messaging app or a browser can carry a prompt
// injection no detector recognises; inside the window the actions below take the configured level.
//
// ONE TABLE, POLICY-OVERRIDABLE. ORIGIN_GATES names every gated action class. The level for a class is
// sessionRisk.originGates[class] when set, else sessionRisk.originTaint ("off" | "notify" | "ask" | "block",
// default "notify"). Both come from the signed policy or the root-owned admin binding only (the admin binding
// wins, as for failMode); data/session-risk.js sessionRiskConfig resolves them.
//
// Pure and browser-safe: text in, classes out. Every pattern is bounded to one shell segment.
import { skillSurfaceKind, persistentInstructionKind } from "./skill-surface.js";
import { winCanonical } from "./path-canon.js";

export const ORIGIN_LEVELS = Object.freeze(["off", "notify", "ask", "block"]);
export const ORIGIN_DEFAULT_LEVEL = "notify";

export const ORIGIN_GATES = Object.freeze({
  outbound: "an upload, a data-carrying request, a gist, a push to a URL or an MCP write",
  "memory-write": "a write to a memory or instruction file (#84 memory files)",
  "extension-install": "adding an MCP server or installing a skill, plugin, command, agent or auto-run config",
  "exec-outside": "running a file that came from outside, or was extracted from one",
  "git-push": "git push",
  message: "sending a message or an email"
});
export const ORIGIN_GATE_CLASSES = Object.freeze(Object.keys(ORIGIN_GATES));
const RANK = { off: 0, notify: 1, ask: 2, block: 3 };
export const strictestLevel = (levels) => levels.reduce((m, l) => (RANK[l] > RANK[m] ? l : m), "off");

const B = "(?<![\\w.\\/-])";
// git push, with git's global options before the subcommand (`git -C dir push`, `git -c k=v push`).
const GIT_PUSH = new RegExp(`${B}git(?:\\s+(?:-[Cc]\\s+\\S+|--?[\\w-]+(?:=\\S+)?))*\\s+push(?![\\w-])`);
// An agent CLI adding an MCP server or installing a plugin, extension or skill.
const EXT_CLI = new RegExp(
  `${B}(?:claude|codex|gemini|qwen|amp|opencode|cursor-agent|kiro-cli|copilot)\\s+(?:mcp\\s+(?:add(?:-json|-from-claude-desktop)?|install|import)|plugins?\\s+(?:install|add|enable|marketplace\\s+add)|extensions?\\s+(?:install|link))(?![\\w-])` +
  `|${B}code(?:-insiders)?(?:\\.cmd)?\\s+[^;&|\\n]{0,200}?--(?:add-mcp|install-extension)(?![\\w-])` +
  `|${B}(?:npx|bunx|pnpm\\s+dlx)\\s+(?:-y\\s+|--yes\\s+)?(?:@smithery\\/cli|smithery|install-mcp|add-mcp|skills)(?:@\\S+)?\\s+[^;&|\\n]{0,200}?(?:install|add)(?![\\w-])`, "i");
// A command that writes something somewhere: a copy, move, link, tee, redirect, unpack, clone or download to a file.
const WRITEISH = new RegExp(`${B}(?:cp|mv|ln|tee|install|rsync|ditto|unzip|tar|bsdtar|7z|7za|7zz|Copy-Item|Move-Item|Set-Content|Out-File|Expand-Archive)\\s|${B}git\\s+clone\\s|\\s-(?:o|O|-output)\\s|(?<![0-9&>])>{1,2}(?!&)\\s*[^\\s&|;]`, "i");
// Sending a message or an email from a shell.
const MESSAGE_CLI = new RegExp(`${B}(?:mail|mailx|sendmail|mutt|neomutt|msmtp|swaks)(?:\\s|$)|\\bSend-MailMessage\\b|${B}osascript\\b[^;&|\\n]{0,400}?\\b(?:Messages|Mail)\\b[^;&|\\n]{0,400}?\\bsend\\b`, "i");
// An MCP tool that sends a message: send_message, post_message, reply_email, chat.postMessage, send_email, create_draft.
const MESSAGE_TOOL = /(?:^|[_\-.])(?:send|post|reply|forward)[_\-.]?(?:an?[_\-.])?(?:message|messages|msg|email|emails|mail|dm|chat|comment|text|sms)(?:$|[_\-.])|chat[_.]?postmessage|(?:^|[_\-.])(?:send|create)[_\-.]?(?:draft|email|mail)(?:$|[_\-.])/i;

function local(tool) {
  const t = String(tool || "");
  return (t.startsWith("mcp__") ? t.split("__").slice(2).join("__") : t).replace(/([a-z0-9])([A-Z])/g, "$1_$2");
}
export function mcpMessageTool(tool) { return String(tool || "").startsWith("mcp__") && MESSAGE_TOOL.test(local(tool)); }

// A path whose write installs an agent extension: a skill-surface file that is not a persistent-instruction file
// (those are "memory-write"): an MCP config, a skill, a command, an agent definition, a plugin manifest, a hook
// config, an IDE auto-run config (data/skill-surface.js). Matched as written and in its Win32 canonical form
// (data/path-canon.js: ".mcp.json.", ".vscode/tasks.json::$DATA").
export function extensionPath(path) {
  const p = String(path || "");
  return !!p && [...new Set([p, winCanonical(p)])].some((f) => skillSurfaceKind(f) !== null && persistentInstructionKind(f) === null);
}

// The gated classes one shell command carries, other than "outbound" (data/session-risk.js classifyEvent) and
// "memory-write" (the #84 oversight signals) and "exec-outside" (resolved against the files it runs).
export function shellGateClasses(command) {
  const s = String(command || "").slice(0, 65536);
  const out = new Set();
  if (GIT_PUSH.test(s)) out.add("git-push");
  if (EXT_CLI.test(s)) out.add("extension-install");
  else if (WRITEISH.test(s) && s.split(/[\s'"`=;&|<>()]+/).some((t) => t.length <= 4096 && extensionPath(t))) out.add("extension-install");
  if (MESSAGE_CLI.test(s)) out.add("message");
  return [...out];
}

// ---- removing the origin mark ----
//
// xattr -d / -c / -w on com.apple.quarantine or kMDItemWhereFroms (and -c, which clears every attribute),
// Unblock-File, Remove-Item / Clear-Content / Set-Content -Stream Zone.Identifier, a redirect into
// <file>:Zone.Identifier, Sysinternals streams -d, ditto --noqtn / --noextattr, and a Python removexattr of the
// quarantine attribute. Copying a file's bytes into a new file (cat, rsync without -E) also leaves the mark behind
// and is not listed here; the read of the original is what taints then.
const XATTR_STRIP = new RegExp(`${B}xattr\\s+(?=(?:[^;&|\\n]*\\s)?-[A-Za-z]*[dcw])([^;&|\\n]*)`, "i");
const XATTR_HIT = /(?:^|\s)-[A-Za-z]*c[A-Za-z]*(?=\s|$)|com\.apple\.(?:quarantine|metadata:kMDItemWhereFroms)/i;
const STRIP = [
  /\bUnblock-File\b([^;|\n]*)/i,
  /\b(?:Remove-Item|ri|rm|del|erase|Clear-Content|clc|Set-Content|sc|Add-Content|ac)\b[^;|\n]*-Stream\s+['"]?Zone\.Identifier\b/i,
  /(?:>|\bOut-File\b[^;|\n]*)\s*['"]?[^\s'";|]*:Zone\.Identifier\b/i,
  new RegExp(`${B}streams(?:64)?(?:\\.exe)?(?:\\s[^;&|\\n]*?)?\\s[-/][A-Za-z]*d(?=\\s|$)`, "i"),
  new RegExp(`${B}ditto\\s[^;&|\\n]*--no(?:qtn|extattr)\\b`),
  /\b(?:removexattr|xattr\.remove(?:xattr)?)\s*\([^)]{0,300}quarantine/i
];
// -> { hit, targets: [literal paths the stripping command names] }. Targets are best effort (xattr and
// Unblock-File arguments that are not options or attribute names); the hit itself does not depend on them.
export function originStripFacts(command) {
  const s = String(command || "").slice(0, 65536);
  const targets = [];
  let hit = false;
  for (const seg of s.split(/[;&|\n]+/)) {
    const m = seg.match(XATTR_STRIP);
    if (m && XATTR_HIT.test(` ${m[1]}`)) {
      hit = true;
      const toks = m[1].trim().split(/\s+/).map((t) => t.replace(/^['"]|['"]$/g, ""));
      for (let i = 0; i < toks.length; i++) {
        const t = toks[i];
        if (/^-[A-Za-z]*w[A-Za-z]*$/.test(t)) { i += 2; continue; } // -w name value
        if (/^-[A-Za-z]*[dp][A-Za-z]*$/.test(t)) { i += 1; continue; } // -d name
        if (t.startsWith("-") || /^com\.apple\./i.test(t)) continue;
        if (t && !t.includes("$")) targets.push(t);
      }
      continue;
    }
    for (const re of STRIP) {
      const r = seg.match(re);
      if (!r) continue;
      hit = true;
      if (re === STRIP[0] && r[1]) {
        const toks = r[1].trim().split(/\s+/).map((t) => t.replace(/^['"]|['"]$/g, ""));
        for (let i = 0; i < toks.length; i++) { const t = toks[i]; if (/^-(?:path|literalpath|lp)$/i.test(t)) { if (toks[i + 1]) targets.push(toks[++i]); continue; } if (!t.startsWith("-") && t && !t.includes("$")) targets.push(t); }
      }
      break;
    }
  }
  return { hit, targets: [...new Set(targets)].slice(0, 16) };
}

// The ask / alert reason: "session read an internet-origin file (Chrome)".
const SOURCE_LABEL = { zone: "Windows Internet zone", "download-dir": "download folder", "where-froms": "download record", "mark-removed": "origin mark removed" };
export function originReason(src) {
  const s = src && typeof src === "object" ? src : {};
  if (s.source === "mark-removed") return "session removed a file's origin mark";
  const label = (typeof s.app === "string" && s.app) || SOURCE_LABEL[s.source] || "outside origin";
  return `session read an internet-origin file (${label})`;
}
