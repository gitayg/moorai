// One MoorAI policy -> each agent host's own settings files. Pure: no filesystem, no clock, no network.
//
//   nativeSettings(policy, host, { platform, mcpIdentities })
//     -> { ok:true, host, platform, files:[{ path, format, scope, merge, content }], unexpressed, notes }
//      | { ok:false, reasonCode, reason }
//
// host: claude-code | codex | copilot | cursor | gemini.  platform: darwin | linux | win32.
// files[].path    the location the host's docs name for an administrator's file (cursor: the user's own file,
//                 "~/..."; the host documents no managed one).
// files[].merge   "whole": MoorAI owns the file; "keys": MoorAI owns only the keys it writes.
// unexpressed     every part of the policy the host's file cannot carry, never silently widened
//                 (cli/native-settings/intent.mjs lists the fields and effects).
// mcpIdentities   { serverName: { command } | { url } } — admin input for Codex, which matches an MCP server by
//                 its command or URL, never by the name MoorAI's mcpAllow uses.
//
// The native file is a second layer: MoorAI's own hook still judges every call it sees. Design notes and the
// per-host schema quotes: docs/CAPABILITY_SPEC.md "Native settings from one policy".

import { portableIntent } from "./native-settings/intent.mjs";
import { claudeCode } from "./native-settings/claude-code.mjs";
import { codex } from "./native-settings/codex.mjs";
import { copilot } from "./native-settings/copilot.mjs";
import { cursor } from "./native-settings/cursor.mjs";
import { gemini } from "./native-settings/gemini.mjs";

export { portableIntent };
export const NATIVE_HOSTS = Object.freeze(["claude-code", "codex", "copilot", "cursor", "gemini"]);
export const NATIVE_PLATFORMS = Object.freeze(["darwin", "linux", "win32"]);
const COMPILERS = { "claude-code": claudeCode, codex, copilot, cursor, gemini };

export function nativeSettings(policy, host, { platform = "linux", mcpIdentities = {} } = {}) {
  if (!NATIVE_HOSTS.includes(host)) return { ok: false, reasonCode: "unsupported-host", reason: `host must be one of ${NATIVE_HOSTS.join(", ")}` };
  if (!NATIVE_PLATFORMS.includes(platform)) return { ok: false, reasonCode: "unsupported-platform", reason: `platform must be one of ${NATIVE_PLATFORMS.join(", ")}` };
  const intent = portableIntent(policy);
  const ids = mcpIdentities && typeof mcpIdentities === "object" ? mcpIdentities : {};
  const r = COMPILERS[host](intent, { platform, mcpIdentities: ids });
  return { ok: true, host, platform, files: r.files, unexpressed: [...intent.unexpressed, ...r.unexpressed], notes: r.notes };
}

// The exact bytes MoorAI writes for a file (and compares against on a drift check).
export function renderFile(f) {
  return f.format === "toml" ? f.content : JSON.stringify(f.content, null, 2) + "\n";
}
