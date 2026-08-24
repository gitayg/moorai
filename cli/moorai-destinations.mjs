#!/usr/bin/env node
// MoorAI — per-agent destination map. "Where did this agent actually reach?" Summarizes the on-device,
// content-free log the hook appends every time an agent/tool touches an external destination: a HOST
// (from a Bash command or an MCP tool argument) or an MCP SERVER NAME, together with the hook's own
// allow/ask/deny verdict for that call, a running count, and first/last-seen timestamps.
//
// This is the observed counterpart to the console's allow-lists: the console says which destinations
// are APPROVED, this says which were REACHED. Reads only local files; no server, no account, nothing
// leaves. (The hook separately emits one content-free alert the first time an agent reaches a given
// destination, over the existing /api/alerts path — there is no second telemetry channel.)
//
// Content-free by construction: a host is a host, never a URL path or query string — the extractor in
// data/model-endpoints.js does not capture them, so there is nothing to strip here.
//
//   node cli/moorai-destinations.mjs                 # summary (default)
//   node cli/moorai-destinations.mjs --format md     # Markdown report
//   node cli/moorai-destinations.mjs --format json   # raw rollup
//   node cli/moorai-destinations.mjs --help

import { readDestinations, DESTINATIONS_PATH } from "./signals.mjs";
import { rollupDestinations } from "../data/destination-map.js";

const HELP = `MoorAI destinations — per-agent map of the external destinations each agent reached.

Usage:
  moorai-destinations [--format summary|md|json]

Reads one on-device log (nothing leaves the machine):
  ${DESTINATIONS_PATH}

Every entry is content-free: agent/tool, destination kind (host | mcp), the host or MCP server
name, the hook's allow/ask/deny verdict, and timestamps. No URL path, query string, request
body, tool argument or response is stored or shown.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }
const fmt = argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : "summary";

const roll = rollupDestinations(readDestinations());

function verdict(d) {
  return Object.entries(d.decisions).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ");
}

function toMarkdown(r) {
  let out = `# MoorAI — per-agent destination map\n\n`
    + `Content-free, on-device. ${r.destinations} destination(s) across ${r.agents.length} agent(s), ${r.entries} observation(s)`
    + (r.firstSeen ? `  ·  ${r.firstSeen} → ${r.lastSeen}` : "") + `\n\n`
    + `Hosts and MCP server names only — never a URL path, query string, argument or response.\n`;
  for (const a of r.agents) {
    out += `\n### ${a.tool}  —  ${a.reached} destination(s)${a.denied ? `, ${a.denied} with denials` : ""}\n\n`
      + `| kind | destination | calls | verdicts | first seen | last seen |\n|---|---|---|---|---|---|\n`
      + a.destinations.map((d) => `| ${d.kind} | ${d.name} | ${d.count} | ${verdict(d)} | ${d.firstSeen} | ${d.lastSeen} |`).join("\n") + "\n";
  }
  if (!r.agents.length) out += `\nNo destinations recorded yet.\n`;
  return out + `\n---\nA destination here is one that was OBSERVED, not one that is approved. Compare against your\norg's MCP allow-list and model-endpoint allow-list to find reach the policy did not intend.\n`;
}

function toSummary(r) {
  if (!r.entries) return `No agent destinations recorded yet.\n(${DESTINATIONS_PATH})\n`;
  let out = `MoorAI destination map — ${r.destinations} destination(s), ${r.agents.length} agent(s), ${r.entries} observation(s)\n`
    + `${r.firstSeen} → ${r.lastSeen}\n`;
  for (const a of r.agents) {
    out += `\n  ${a.tool}${a.denied ? `  (${a.denied} destination(s) with denials)` : ""}\n`;
    for (const d of a.destinations) out += `    ${String(d.count).padStart(4)}  ${d.kind.padEnd(4)}  ${d.name}  [${verdict(d)}]\n`;
  }
  return out;
}

if (fmt === "json") process.stdout.write(JSON.stringify(roll, null, 2) + "\n");
else if (fmt === "md") process.stdout.write(toMarkdown(roll));
else process.stdout.write(toSummary(roll));
