// GitHub Copilot CLI managed settings from the portable intent. Pure.
//
// Schema, quoted from docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference
// (read 2026-10-21; MoorAI's Copilot adapter is verified against @github/copilot 1.0.63):
//   locations: macOS "/Library/Application Support/GitHubCopilot/managed-settings.json", Windows
//     "%ProgramFiles%\GitHubCopilot\managed-settings.json", Linux "/etc/github-copilot/managed-settings.json";
//     "Copilot CLI rejects file-based managed settings that are symlinks, not owned by root, or world-writable."
//   permissions: { "deny": ["Shell(rm -rf *)", "Domain(*.evil.example)"], "ask": [...], "allow": ["Read(**)"] };
//     families Bash(...)/Shell(...), PowerShell(...), Read(...), Edit(...)/Write(...), Domain(...); "Use
//     `<command> *` (for example, `git push *`) to match a command prefix"; "deny always wins, then ask, then
//     allow". The docs show no bare "every command" form, so MoorAI writes Shell(*) / PowerShell(*), which
//     is reported as approximated until a run proves the CLI reads it that way.
//   limitTo: "Only `Domain(...)` entries are supported in `limitTo`." "Any agent network request to a domain
//     outside the list is denied without prompting." "An empty `limitTo` list denies every domain request."
//     "`limitTo` doesn't restrict `shell`, `read`, or `write` operations by themselves."
//   allowedMcpServers / deniedMcpServers: { "serverName": ... } | { "serverUrl": ... }; "Leaving this key
//     unset allows all non-default servers; an empty array denies all of them."; "Trusted first-party servers (for example, the
//     built-in GitHub MCP server) are always exempt from both lists."
//   "Most managed keys lock the entire row", so MoorAI owns the keys it writes and merges by key.
//   The managed `sandbox` key's network rule shape (`userPolicy.*`) is not published, so egress goes to
//   Domain() rules and limitTo only.

import { mapTools } from "./tools.mjs";
import { domainPlan, domainStrings } from "./egress.mjs";

const TAG = "copilot";
const PATH = {
  darwin: "/Library/Application Support/GitHubCopilot/managed-settings.json",
  linux: "/etc/github-copilot/managed-settings.json",
  win32: "C:\\Program Files\\GitHubCopilot\\managed-settings.json"
};
// Tools MoorAI's Copilot adapter maps (bash, powershell, view, create, edit, str_replace_editor,
// apply_patch, web_fetch, web_search, task). Web tools are refused through limitTo below.
const MAP = { Bash: ["Shell(*)"], PowerShell: ["PowerShell(*)"], Read: ["Read(**)"], Write: ["Write(**)"], Edit: ["Edit(**)"], MultiEdit: ["Edit(**)"], WebFetch: ["@net"], WebSearch: ["@net"], Task: null };
const WILDCARD = new Set(["Shell(*)", "PowerShell(*)"]);

export function copilot(intent, { platform }) {
  const unexpressed = [];
  const t = mapTools(intent, TAG, { deny: MAP, ask: { ...MAP, WebFetch: null, WebSearch: null } });
  unexpressed.push(...t.unexpressed);
  const deny = new Set(t.deny.filter((k) => k !== "@net"));
  const noNet = t.deny.includes("@net");
  for (const k of [...t.deny, ...t.ask]) if (WILDCARD.has(k)) unexpressed.push({ source: "tagActions", tool: k.startsWith("Shell") ? "Bash" : "PowerShell", effect: "approximated", reason: `${TAG}-wildcard-form-unverified` });
  if (noNet) unexpressed.push({ source: "tagActions", item: "network", effect: "approximated", reason: `${TAG}-limitto-covers-agent-requests` });
  const permissions = {}, out = {};

  const eg = intent.egress;
  let limitTo = noNet ? [] : null;
  if (eg.set) {
    const plan = domainPlan(eg, { ports: false, ip: "approximated", suffix: "approximated" }, TAG);
    unexpressed.push(...plan.unexpressed);
    for (const b of plan.blocks) {
      for (const h of domainStrings(b)) deny.add(`Domain(${h})`);
      unexpressed.push({ source: "egressRules", index: b.index, ...(b.id ? { id: b.id } : {}), fields: ["binary"], effect: "coarsened", reason: `${TAG}-domain-rules-not-shell` });
    }
    if (eg.dflt === "block") {
      if (!noNet) limitTo = [...new Set(plan.allows.flatMap((a) => domainStrings(a)))].sort();
      unexpressed.push({ source: "egressDefault", effect: "coarsened", reason: `${TAG}-limitto-not-shell` });
    }
  }
  if (deny.size) permissions.deny = [...deny].sort();
  if (t.ask.length) permissions.ask = t.ask;
  if (limitTo) permissions.limitTo = limitTo;
  if (Object.keys(permissions).length) out.permissions = permissions;

  if (intent.mcp.allowOnly) {
    out.allowedMcpServers = intent.mcp.allowOnly.map((serverName) => ({ serverName }));
    unexpressed.push({ source: "mcpAllow", effect: "coarsened", reason: `${TAG}-first-party-servers-exempt` });
  }
  const files = Object.keys(out).length ? [{ path: PATH[platform], format: "json", scope: "managed", merge: "keys", content: out }] : [];
  return { files, unexpressed, notes: [{ reason: `${TAG}-root-owned-file-required` }] };
}
