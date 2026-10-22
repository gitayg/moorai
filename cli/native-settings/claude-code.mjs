// Claude Code managed settings from the portable intent. Pure.
//
// Schema, quoted from code.claude.com/docs (read 2026-10-21; Claude Code 2.1.295 installed here):
//   managed-settings: "File-based: `managed-settings.json`, an optional `managed-settings.d/` directory, and
//     `managed-mcp.json` in the system directory: `/Library/Application Support/ClaudeCode/` on macOS,
//     `/etc/claude-code/` on Linux and WSL, and `C:\Program Files\ClaudeCode\` on Windows."
//     "If several teams own parts of one policy, put each part in its own file in `managed-settings.d/`".
//     MoorAI owns one drop-in, managed-settings.d/50-moorai.json, so it never edits the admin's own file.
//   permissions.deny: "List the tool uses Claude Code blocks." A bare tool name ("Bash") is every use.
//   permissions.ask: "List the tool uses that prompt you for confirmation even in a permission mode that
//     would otherwise approve them".  Order: deny, then ask, then allow; allow never overrides a deny.
//   allowedMcpServers / allowManagedMcpServersOnly (managed-mcp): "Unset (default): All servers allowed |
//     Empty array []: No servers allowed ... | Populated: Only matching servers allowed"; "In
//     `allowedMcpServers`, `serverName` is limited to letters, numbers, hyphens, and underscores."
//     "When `allowManagedMcpServersOnly` is `true`, allowlists from user, project, and local settings are
//     ignored." A serverName entry matches the label, as MoorAI's own mcpAllow does.
//   sandbox (sandboxing): "The sandbox covers shell commands only. Claude's file tools, MCP servers, and
//     hooks run outside it." network.allowedDomains / deniedDomains ("Blocks domains for sandboxed
//     commands, even inside an allowed wildcard"); "An `allowedDomains` entry with no port allows every
//     port on that host"; "if `allowManagedDomainsOnly` is set in managed settings, non-allowed domains are
//     blocked automatically instead of prompting"; failIfUnavailable: "Refuse to start when the sandbox
//     can't, instead of running unsandboxed"; allowUnsandboxedCommands false disables the unsandboxed retry.
//     "`allowedDomains` doesn't limit WebFetch" — WebFetch(domain:...) permission rules do.
//     The docs do not say whether "*.example.com" also matches example.com itself (MoorAI's does not).

import { CANON_TOOLS } from "./intent.mjs";
import { mapTools } from "./tools.mjs";
import { domainPlan, domainStrings } from "./egress.mjs";

const TAG = "claude-code";
const DIR = {
  darwin: "/Library/Application Support/ClaudeCode/managed-settings.d/50-moorai.json",
  linux: "/etc/claude-code/managed-settings.d/50-moorai.json",
  win32: "C:\\Program Files\\ClaudeCode\\managed-settings.d\\50-moorai.json"
};
const NAME_OK = /^[A-Za-z0-9_-]+$/;
const IDENTITY = Object.fromEntries(CANON_TOOLS.map((t) => [t, [t]]));

export function claudeCode(intent, { platform }) {
  const unexpressed = [];
  const t = mapTools(intent, TAG, { deny: IDENTITY, ask: IDENTITY });
  unexpressed.push(...t.unexpressed);
  const deny = new Set(t.deny), content = {};

  if (intent.mcp.allowOnly) {
    const ok = intent.mcp.allowOnly.filter((s) => NAME_OK.test(s));
    for (let k = ok.length; k < intent.mcp.allowOnly.length; k++) unexpressed.push({ source: "mcpAllow", effect: "narrowed", reason: `${TAG}-server-name-charset` });
    content.allowedMcpServers = ok.map((serverName) => ({ serverName }));
    content.allowManagedMcpServersOnly = true;
  }

  const eg = intent.egress;
  if (eg.set) {
    const plan = domainPlan(eg, { ports: true, ip: "exact", suffix: "approximated" }, TAG);
    unexpressed.push(...plan.unexpressed);
    const network = {};
    const allowed = [...new Set(plan.allows.flatMap((x) => domainStrings(x, { ports: true })))].sort();
    const denied = [...new Set(plan.blocks.flatMap((x) => domainStrings(x, { ports: true })))].sort();
    if (allowed.length) network.allowedDomains = allowed;
    if (denied.length) network.deniedDomains = denied;
    // WebFetch runs outside the sandbox: a host block is also a WebFetch(domain:...) deny rule. Port-limited
    // blocks have no WebFetch form, so WebFetch to that host and port is MoorAI's alone.
    for (const b of plan.blocks) {
      if (b.ports) unexpressed.push({ source: "egressRules", index: b.index, ...(b.id ? { id: b.id } : {}), fields: ["port"], effect: "coarsened", reason: `${TAG}-webfetch-no-port` });
      else deny.add(`WebFetch(domain:${domainStrings(b)[0]})`);
    }
    const sandbox = {};
    if (eg.dflt === "block") {
      Object.assign(sandbox, { enabled: true, failIfUnavailable: true, allowUnsandboxedCommands: false });
      network.allowManagedDomainsOnly = true;
      // allowManagedDomainsOnly governs sandboxed commands; WebFetch to an unlisted host is MoorAI's alone,
      // and the sandbox also confines file writes, which MoorAI's egress default does not.
      unexpressed.push({ source: "egressDefault", effect: "coarsened", reason: `${TAG}-webfetch-not-sandboxed` });
      unexpressed.push({ source: "egressDefault", effect: "narrowed", reason: `${TAG}-sandbox-filesystem` });
    } else {
      for (const x of [...plan.allows, ...plan.blocks].sort((a, b) => a.index - b.index)) {
        unexpressed.push({ source: "egressRules", index: x.index, ...(x.id ? { id: x.id } : {}), fields: ["host"], effect: "may-be-inert", reason: `${TAG}-sandbox-off` });
      }
    }
    if (Object.keys(network).length) sandbox.network = network;
    if (Object.keys(sandbox).length) content.sandbox = sandbox;
  }

  const permissions = {};
  if (deny.size) permissions.deny = [...deny].sort();
  if (t.ask.length) permissions.ask = t.ask;
  const out = {};
  if (Object.keys(permissions).length) out.permissions = permissions;
  Object.assign(out, content);
  const files = Object.keys(out).length ? [{ path: DIR[platform], format: "json", scope: "managed", merge: "whole", content: out }] : [];
  return { files, unexpressed, notes: [{ reason: `${TAG}-managed-dropin` }] };
}
