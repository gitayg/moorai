#!/usr/bin/env node
// MoorAI — standalone AI Bill of Materials (AIBOM). Generates a content-free inventory of the AI
// assets configured on THIS machine — providers, models (cloud + local), agent CLIs, and MCP servers
// with capability scope (network / filesystem / credential) — for GRC, audits, and EU AI Act
// record-keeping. Runs the local collectors only; no server, no account, nothing leaves the machine.
//
// Content-free by construction: it reports asset NAMES and COUNTS and infers MCP capability from
// launch config + env var KEYS only — never token values, never the contents of any credential file.
//
//   node cli/moorai-aibom.mjs                 # JSON (default)
//   node cli/moorai-aibom.mjs --format md     # Markdown for a report
//   node cli/moorai-aibom.mjs --format csv    # CSV (components)
//   npm run aibom -- --format md

import { readFileSync, readdirSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { join } from "node:path";
import { readAgentEvents } from "./signals.mjs";

const HOME = homedir();
const read = (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } };
const readJson = (p) => { const t = read(p); if (!t) return null; try { return JSON.parse(t); } catch { return null; } };
const listDir = (p) => { try { return readdirSync(p, { withFileTypes: true }); } catch { return []; } };
// Minimal `key = "value"` (TOML) / `key: value` (YAML) scan — tolerant, no dependency.
const cfgVal = (txt, key, sep) => {
  for (const line of (txt || "").split("\n")) {
    const l = line.trim();
    if (l.startsWith(key)) {
      const rest = l.slice(key.length).trimStart();
      if (rest.startsWith(sep)) { const v = rest.slice(1).trim().replace(/^["']|["']$/g, "").trim(); if (v) return v; }
    }
  }
  return null;
};

// ---- providers / models / agents ----
function providers() {
  const out = [];
  const claude = readJson(join(HOME, ".claude", "settings.json"));
  if (claude) out.push({ provider: "Anthropic", agent: "claude", model: claude.model || null, source: "settings.json" });
  const codex = read(join(HOME, ".codex", "config.toml"));
  if (codex) out.push({ provider: cfgVal(codex, "model_provider", "=") || "OpenAI", agent: "codex", model: cfgVal(codex, "model", "="), source: "config.toml" });
  const aider = read(join(HOME, ".aider.conf.yml"));
  if (aider) out.push({ provider: "Aider", agent: "aider", model: cfgVal(aider, "model", ":"), source: "aider.conf.yml" });
  return out;
}

function localModels() {
  const out = [];
  for (const e of listDir(join(HOME, ".ollama/models/manifests/registry.ollama.ai/library"))) out.push({ runtime: "ollama", name: e.name });
  for (const dir of [join(HOME, ".lmstudio/models"), join(HOME, ".cache/lm-studio/models")])
    for (const e of listDir(dir)) if (e.isDirectory()) out.push({ runtime: "lmstudio", name: e.name });
  return out;
}

// ---- MCP servers + capability scope (env KEYS only, never values) ----
function mcpCaps(cfg) {
  const parts = [cfg.command || "", ...(Array.isArray(cfg.args) ? cfg.args : [])].join(" ").toLowerCase();
  const remote = !!cfg.url || cfg.type === "sse" || cfg.transport === "sse";
  const net = remote || ["fetch", "brave-search", "puppeteer", "playwright", "firecrawl", "http"].some((k) => parts.includes(k));
  const fs = parts.includes("filesystem") || parts.includes("server-files") || parts.includes(" files ");
  let cred = ["github", "gitlab", "slack", "aws", "gdrive", "google-drive", "notion", "stripe", "jira"].some((k) => parts.includes(k));
  if (cfg.env && typeof cfg.env === "object")
    for (const k of Object.keys(cfg.env)) if (["TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL"].some((s) => k.toUpperCase().includes(s))) { cred = true; break; }
  return { net, fs, cred };
}
function mcpLevel(caps) { let s = 0; if (caps.net) s += 25; if (caps.fs) s += 25; if (caps.cred) s += 35; if (caps.net && caps.cred) s += 15; return s >= 60 ? "high" : s >= 30 ? "med" : "low"; }
function mcpServers() {
  const seen = new Set(), out = [];
  const add = (map, scope) => { if (!map) return; for (const [name, cfg] of Object.entries(map)) { const k = `${scope}:${name}`; if (!name || seen.has(k)) continue; seen.add(k); const caps = mcpCaps(cfg || {}); out.push({ name, scope, transport: (cfg.url || cfg.type === "sse" || cfg.transport === "sse") ? "remote" : "stdio", caps, level: mcpLevel(caps) }); } };
  const claude = readJson(join(HOME, ".claude.json"));
  if (claude) { add(claude.mcpServers, "claude"); if (claude.projects) for (const p of Object.values(claude.projects)) add(p.mcpServers, "claude"); }
  add(readJson(join(HOME, ".cursor", "mcp.json"))?.mcpServers, "cursor");
  return out;
}

// ---- editor AI extensions (the harness, + version) & agent skills/plugins ----
// The CSA HF post-mortem calls for telemetry to include "model and harness versions… VS Code
// extensions, skills, MCP servers, plugins." Directory listings only — names + versions, never content.
const AI_EXT = /copilot|continue|codeium|cody|tabnine|claude|cline|roo.?code|kilocode|supermaven|codegpt|aws.?toolkit|amazon.*q|windsurf|augment|sourcegraph|pieces|blackbox|codewhisperer/i;
function editorExtensions() {
  const out = [], seen = new Set();
  const dirs = [".vscode/extensions", ".vscode-insiders/extensions", ".vscode-server/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscodium/extensions"];
  for (const rel of dirs) {
    const editor = rel.split("/")[0].replace(/^\./, "");
    for (const e of listDir(join(HOME, rel))) {
      if (!e.isDirectory() || !AI_EXT.test(e.name)) continue;
      const m = e.name.match(/^(.*?)-(\d+\.\d+\.\d+.*)$/); // publisher.name-1.2.3
      const id = m ? m[1] : e.name, version = m ? m[2] : null;
      const k = editor + ":" + id; if (seen.has(k)) continue; seen.add(k);
      out.push({ editor, id, version });
    }
  }
  return out;
}
function agentSkills() {
  const out = [];
  for (const [dir, kind] of [[".claude/plugins", "plugin"], [".claude/skills", "skill"], [".claude/commands", "command"]])
    for (const e of listDir(join(HOME, dir))) if (e.name && !e.name.startsWith(".")) out.push({ kind, name: e.name.replace(/\.(md|js|mjs|json)$/, "") });
  return out;
}

// ---- usage / cost signal (content-free) — call volume from the on-device agent-events log, mapped
// to OWASP LLM10 (Unbounded Consumption). Counts are exact; spend is a coarse estimate for relative
// comparison, not billing. Never reads a prompt — only event counts, tool, and risk.
const MODEL_PRICE = [[/opus/i, 45], [/sonnet/i, 9], [/haiku/i, 2], [/gpt-5|gpt-4o|o[34]\b/i, 8], [/gpt-4/i, 30], [/gpt-3\.5/i, 1], [/gemini/i, 5], [/llama|mistral|qwen|deepseek|phi/i, 0]];
const AVG_TOKENS_PER_CALL = 3000;
const priceFor = (m) => { if (!m) return null; for (const [re, p] of MODEL_PRICE) if (re.test(m)) return p; return null; };
function usage(prov) {
  const ev = readAgentEvents(); if (!ev.length) return null;
  const byTool = {}, byRisk = {};
  for (const e of ev) { const t = (e.sig || "").split("|")[0] || "unknown"; byTool[t] = (byTool[t] || 0) + 1; const r = e.risk || "Low"; byRisk[r] = (byRisk[r] || 0) + 1; }
  const ts = ev.map((e) => e.ts).filter((x) => typeof x === "number").sort((a, b) => a - b);
  const primaryModel = (prov.find((p) => p.agent === "claude") || prov[0] || {}).model || null;
  const price = priceFor(primaryModel);
  const roughSpendUsd = price != null ? +((ev.length * AVG_TOKENS_PER_CALL / 1e6) * price).toFixed(2) : null;
  return {
    events: ev.length,
    window: { from: ts[0] ? new Date(ts[0]).toISOString() : null, to: ts.length ? new Date(ts[ts.length - 1]).toISOString() : null },
    byTool, byRisk, primaryModel, roughSpendUsd,
    basis: `≈${AVG_TOKENS_PER_CALL} tokens/call × list price for ${primaryModel || "unknown"}`,
    note: "Call counts are exact and content-free. roughSpendUsd is a coarse estimate for relative comparison — not billing."
  };
}

function buildAibom() {
  const prov = providers(), local = localModels(), mcp = mcpServers();
  const ext = editorExtensions(), skills = agentSkills();
  const use = usage(prov);
  const models = [...prov.filter((p) => p.model).map((p) => ({ name: p.model, provider: p.provider, local: false })),
    ...local.map((m) => ({ name: m.name, provider: m.runtime, local: true }))];
  const components = [
    ...models.map((m) => ({ type: "model", name: m.name, provider: m.provider, local: m.local })),
    ...[...new Set(prov.map((p) => p.agent))].map((a) => ({ type: "agent", name: a })),
    ...mcp.map((s) => ({ type: "mcp-server", name: s.name, riskLevel: s.level, capabilities: s.caps, transport: s.transport })),
    ...ext.map((x) => ({ type: "editor-extension", name: x.id, editor: x.editor, version: x.version })),
    ...skills.map((s) => ({ type: "skill", name: s.name, kind: s.kind }))
  ];
  return {
    bomFormat: "MoorAI-AIBOM", specVersion: "1.0", scope: "device", device: hostname(), generatedAt: new Date().toISOString(),
    summary: { providers: new Set(prov.map((p) => p.provider)).size, models: models.length, localModels: local.length, agents: new Set(prov.map((p) => p.agent)).size, mcpServers: mcp.length, mcpHighRisk: mcp.filter((s) => s.level === "high").length, editorAiExtensions: ext.length, skills: skills.length, calls: use ? use.events : 0, roughSpendUsd: use ? use.roughSpendUsd : null },
    providers: prov, localModels: local, mcpServers: mcp, editorExtensions: ext, skills, usage: use, components
  };
}

// ---- renderers ----
function toMarkdown(d) {
  const cap = (c) => [c.net && "net", c.fs && "fs", c.cred && "cred"].filter(Boolean).join(" · ") || "—";
  const s = d.summary;
  return `# MoorAI — AI Bill of Materials\n\n`
    + `**Device:** ${d.device}  ·  **Generated:** ${d.generatedAt}  ·  **Scope:** this device only\n\n`
    + `Content-free inventory — asset names and counts only. No tokens, prompts, or file contents.\n\n`
    + `| Providers | Models | Local models | Agent CLIs | MCP servers | High-risk MCP | AI extensions | Skills |\n|---|---|---|---|---|---|---|---|\n`
    + `| ${s.providers} | ${s.models} | ${s.localModels} | ${s.agents} | ${s.mcpServers} | ${s.mcpHighRisk} | ${s.editorAiExtensions} | ${s.skills} |\n\n`
    + `## AI providers & models\n\n| Provider | Agent | Model | Source |\n|---|---|---|---|\n`
    + (d.providers.map((p) => `| ${p.provider} | ${p.agent} | ${p.model || "—"} | ${p.source} |`).join("\n") || "| — | — | — | — |")
    + (d.localModels.length ? `\n\n## Local models\n\n| Runtime | Model |\n|---|---|\n` + d.localModels.map((m) => `| ${m.runtime} | ${m.name} |`).join("\n") : "")
    + `\n\n## MCP servers\n\n| Server | Scope | Transport | Capabilities | Risk |\n|---|---|---|---|---|\n`
    + (d.mcpServers.map((m) => `| ${m.name} | ${m.scope} | ${m.transport} | ${cap(m.caps)} | ${m.level} |`).join("\n") || "| — | — | — | — | — |")
    + (d.editorExtensions.length ? `\n\n## Editor AI extensions (harness + version)\n\n| Editor | Extension | Version |\n|---|---|---|\n` + d.editorExtensions.map((x) => `| ${x.editor} | ${x.id} | ${x.version || "—"} |`).join("\n") : "")
    + (d.skills.length ? `\n\n## Agent skills & plugins\n\n| Kind | Name |\n|---|---|\n` + d.skills.map((x) => `| ${x.kind} | ${x.name} |`).join("\n") : "")
    + (d.usage ? `\n\n## Usage & cost signal (OWASP LLM10 — content-free)\n\n`
        + `**${d.usage.events}** guarded agent calls`
        + (d.usage.window.from ? `  ·  ${d.usage.window.from.slice(0, 10)} → ${d.usage.window.to.slice(0, 10)}` : "")
        + (d.usage.roughSpendUsd != null ? `  ·  rough spend ≈ **$${d.usage.roughSpendUsd}** (${d.usage.primaryModel})` : "")
        + `\n\n| Tool | Calls |\n|---|---|\n` + Object.entries(d.usage.byTool).sort((a, b) => b[1] - a[1]).map(([t, n]) => `| ${t} | ${n} |`).join("\n")
        + `\n\n${d.usage.note}` : "")
    + `\n\n---\nGenerated on-device by MoorAI. This is a content-free inventory to support GRC and EU AI Act record-keeping — not a certification.\n`;
}
function toCsv(d) {
  const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return ["type,name,detail", ...d.components.map((c) => {
    const detail = c.type === "model" ? `${c.provider || ""}${c.local ? " (local)" : ""}`
      : c.type === "mcp-server" ? `risk=${c.riskLevel}; caps=${["net", "fs", "cred"].filter((k) => c.capabilities?.[k]).join("|") || "none"}` : "";
    return [c.type, c.name, detail].map(q).join(",");
  })].join("\n") + "\n";
}

const HELP = `MoorAI AIBOM — content-free AI Bill of Materials for this machine.

Usage:
  moorai-aibom [--format json|md|csv]   (default: json)
  moorai-aibom --help

What it reads (configuration metadata ONLY — never a token value, never a prompt,
never the contents of any credential file):
  ~/.claude/settings.json                          default model for Claude Code
  ~/.codex/config.toml                             model + provider for Codex
  ~/.aider.conf.yml                                model for Aider
  ~/.claude.json                                   configured MCP servers (global + per-project)
  ~/.cursor/mcp.json                               configured MCP servers for Cursor
  ~/.ollama/models/manifests/.../library/          local Ollama model names (directory listing)
  ~/.lmstudio/models, ~/.cache/lm-studio/models    local LM Studio model names (directory listing)
  ~/.vscode/extensions, ~/.cursor/extensions, …    editor AI extensions + versions (the "harness"; dir listing)
  ~/.claude/plugins, ~/.claude/skills, ~/.claude/commands   agent skills / plugins / commands (names only)
  ~/.curaiq/agent-events.jsonl                     content-free call counts for the usage/cost signal (OWASP LLM10)

For each MCP server it infers capability scope (network / filesystem / credential)
from the launch command, its args, and environment-variable NAMES only — it never
reads an environment-variable VALUE and never opens a secret. Output is asset
names, counts, and risk levels. Nothing leaves the machine.
`;

if (process.argv.includes("--help") || process.argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }

const fmt = (process.argv.includes("--format") ? process.argv[process.argv.indexOf("--format") + 1] : "json");
const bom = buildAibom();
process.stdout.write(fmt === "md" ? toMarkdown(bom) : fmt === "csv" ? toCsv(bom) : JSON.stringify(bom, null, 2) + "\n");
