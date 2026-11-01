// Cursor (cursor-agent CLI) permissions from the portable intent. Pure.
//
// Schema, quoted from cursor.com/docs/cli/reference/permissions (read 2026-10-21; cursor-agent
// 2026.05.27-fe9a6e2 installed here, whose default config carries `permissions:{allow:["Shell(ls)"],deny:[]}`):
//   files: "`~/.cursor/cli-config.json` (global)", "`<project>/.cursor/cli.json` (project-specific)".
//   tokens: Shell(commandBase) — "`commandBase` is the first token in the command line"; Read(pathOrGlob);
//     Write(pathOrGlob); WebFetch(domainOrPattern) — "`*` matches all domains, `*.example.com` matches
//     subdomains, and `example.com` matches only that exact domain"; Mcp(server:tool).
//     "Glob patterns use `**`, `*`, and `?` wildcards"; "Deny rules take precedence over allow rules".
//   The page describes no enterprise, MDM or team policy file. Cursor's team MCP and auto-run controls live
//   in its team dashboard (a server setting, not a file), so the only file MoorAI can write is the user's own
//   cli-config.json, which the user — and an agent running as the user — can edit. MoorAI merges the
//   `permissions.deny` key and reports every later edit as drift.
//   Allow entries auto-approve, so MoorAI never writes one (that would remove a prompt).

import { mapTools } from "./tools.mjs";
import { domainPlan, domainStrings } from "./egress.mjs";

const TAG = "cursor";
// Tools MoorAI's Cursor adapter maps (beforeShellExecution, beforeReadFile, preToolUse Write/Fetch, task).
const MAP = { Bash: ["Shell(*)"], Read: ["Read(**)"], Write: ["Write(**)"], Edit: ["Write(**)"], MultiEdit: ["Write(**)"], WebFetch: ["WebFetch(*)"], WebSearch: null, Task: null };

export function cursor(intent) {
  const unexpressed = [];
  const t = mapTools(intent, TAG, { deny: MAP, ask: null });
  unexpressed.push(...t.unexpressed);
  if (t.deny.includes("Shell(*)")) unexpressed.push({ source: "tagActions", tool: "Bash", effect: "approximated", reason: `${TAG}-wildcard-form-unverified` });
  const deny = new Set(t.deny);
  if (intent.mcp.allowOnly) unexpressed.push({ source: "mcpAllow", effect: "coarsened", reason: `${TAG}-mcp-allowlist-no-file` });

  const eg = intent.egress;
  if (eg.set) {
    const plan = domainPlan(eg, { ports: false, ip: "approximated", suffix: "exact" }, TAG);
    unexpressed.push(...plan.unexpressed);
    for (const b of plan.blocks) {
      for (const h of domainStrings(b)) deny.add(`WebFetch(${h})`);
      unexpressed.push({ source: "egressRules", index: b.index, ...(b.id ? { id: b.id } : {}), fields: ["binary"], effect: "coarsened", reason: `${TAG}-webfetch-only` });
    }
    if (eg.dflt === "block") unexpressed.push({ source: "egressDefault", effect: "omitted", reason: `${TAG}-no-default-deny` });
  }
  const files = deny.size ? [{ path: "~/.cursor/cli-config.json", format: "json", scope: "user", merge: "keys", content: { permissions: { deny: [...deny].sort() } } }] : [];
  return { files, unexpressed, notes: [{ reason: `${TAG}-user-writable` }] };
}
