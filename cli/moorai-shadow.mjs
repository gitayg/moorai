#!/usr/bin/env node
// MoorAI — shadow-AI discovery. Answers one question: "what AI is running on this device that we did
// NOT approve?" It CONSUMES the content-free AIBOM inventory (cli/moorai-aibom.mjs) and layers a
// sanctioned-vs-unsanctioned decision on top: every model, MCP server, and editor AI extension the
// AIBOM found is checked against the org's allow-list, and the ones that are NOT on it are surfaced —
// grouped by kind, with a risk note (an unknown MCP server with network + filesystem/credential scope
// ranks highest). Read-only, no network, fail-open.
//
// Content-free by inheritance: the only inputs are AIBOM component NAMES + metadata (model names, MCP
// server names + capability scope, extension ids/versions). No prompt, file content, token, or arg
// value is ever read or shown — this layer adds a set-membership test, nothing that could leak.
//
//   node cli/moorai-shadow.mjs            # human report
//   node cli/moorai-shadow.mjs --json     # structured
//   node cli/moorai-shadow.mjs --strict   # exit non-zero if any shadow/unclassified AI is found (CI)
//
// Allow-list (the "sanctioned" set) — first source that exists wins:
//   MOORAI_SANCTIONED   env: inline JSON, or @/path/to/file.json          (override / testing)
//   --allowlist <path>  flag: JSON file                                    (override / testing)
//   config.sanctioned   ~/.moorai/config.json: { models, mcpServers, extensions }  (the org default)
// Each is { models:[], mcpServers:[], extensions:[] } (arrays of names; case-insensitive, substring-
// tolerant so "gpt-4o" sanctions "gpt-4o-mini" and a versionless id sanctions its versioned install).

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { STATE_DIR, LEGACY_DIRS } from "./state-dirs.mjs";

const SELF_DIR = dirname(fileURLToPath(import.meta.url));
const AIBOM = join(SELF_DIR, "moorai-aibom.mjs");
const VERSION = "0.62.2";

// ---- inventory: consume the AIBOM, never re-implement its collectors ----
// Default path runs the AIBOM CLI (JSON) in-process env so a test's throwaway HOME propagates. A test
// (or an offline snapshot) can instead point MOORAI_AIBOM_JSON at a pre-generated inventory file.
// Fail-open by contract: any error here yields an empty inventory and a clean partial result.
function gatherInventory() {
  try {
    const snap = process.env.MOORAI_AIBOM_JSON;
    const raw = snap
      ? readFileSync(snap, "utf8")
      : execFileSync(process.execPath, [AIBOM], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    const bom = JSON.parse(raw);
    return {
      models: [
        ...(bom.providers || []).filter((p) => p.model).map((p) => ({ name: p.model, provider: p.provider, local: false })),
        ...(bom.localModels || []).map((m) => ({ name: m.name, provider: m.runtime, local: true }))
      ],
      mcpServers: (bom.mcpServers || []).map((s) => ({ name: s.name, scope: s.scope, transport: s.transport, caps: s.caps || {}, level: s.level })),
      extensions: (bom.editorExtensions || []).map((x) => ({ name: x.id, editor: x.editor, version: x.version }))
    };
  } catch {
    return { models: [], mcpServers: [], extensions: [], degraded: true };
  }
}

// ---- allow-list resolution ----
const KINDS = ["models", "mcpServers", "extensions"];
function normList(v) { return Array.isArray(v) ? v.map((s) => String(s).trim().toLowerCase()).filter(Boolean) : []; }
function normalizeAllow(obj) {
  const a = obj && typeof obj === "object" ? (obj.sanctioned && typeof obj.sanctioned === "object" ? obj.sanctioned : obj) : {};
  const out = {};
  for (const k of KINDS) out[k] = normList(a[k]);
  return out;
}
function readAllowFromFile(path) { try { return normalizeAllow(JSON.parse(readFileSync(path, "utf8"))); } catch { return null; } }
// The org allow-list lives at config.sanctioned in ~/.moorai/config.json (loadConfig() drops unknown
// keys, so read the file directly). Same read order as the rest of the agent: new state dir, then the
// read-only legacy dirs for a pre-rebrand install.
function readAllowFromConfig() {
  for (const dir of [STATE_DIR, ...LEGACY_DIRS]) {
    try { const c = JSON.parse(readFileSync(join(dir, "config.json"), "utf8")); if (c.sanctioned) return normalizeAllow(c.sanctioned); } catch { /* try next */ }
  }
  return null;
}
function resolveAllowlist(argv) {
  const flagIdx = argv.indexOf("--allowlist");
  const flagPath = flagIdx >= 0 ? argv[flagIdx + 1] : null;
  const env = process.env.MOORAI_SANCTIONED;
  let list = null, source = "none";
  if (env) {
    if (env.startsWith("@")) list = readAllowFromFile(env.slice(1));
    else { try { list = normalizeAllow(JSON.parse(env)); } catch { list = null; } }
    if (list) source = "env";
  }
  if (!list && flagPath) { list = readAllowFromFile(flagPath); if (list) source = "flag"; }
  if (!list) { list = readAllowFromConfig(); if (list) source = "config"; }
  const configured = !!list && KINDS.some((k) => list[k].length);
  return { list: list || { models: [], mcpServers: [], extensions: [] }, source: configured ? source : "none", configured };
}

// A name is sanctioned if some allow entry equals it, or is a substring of it (versionless id / model
// family sanctions its versioned install), all case-insensitive.
function sanctioned(name, allow) {
  const n = String(name || "").toLowerCase();
  return allow.some((a) => n === a || n.includes(a));
}

// ---- risk note per unsanctioned item ----
function mcpRisk(s) {
  const c = s.caps || {};
  const reach = [c.net && "network", c.fs && "filesystem", c.cred && "credential"].filter(Boolean);
  const risk = s.level === "high" || (c.net && (c.fs || c.cred)) ? "high" : s.level === "med" || c.net || c.fs || c.cred ? "med" : "low";
  const note = reach.length
    ? `unapproved MCP server with ${reach.join(" + ")} scope`
    : "unapproved MCP server (no elevated scope inferred)";
  return { risk, note, scope: reach.join(" · ") || "—" };
}
function modelRisk(m) {
  return m.local
    ? { risk: "low", note: `unapproved local model (${m.provider}) — on-device inference, no egress` }
    : { risk: "med", note: `unapproved cloud model (${m.provider}) — prompts leave the device to this provider` };
}
function extRisk(x) {
  return { risk: "med", note: `unapproved editor AI extension (${x.editor}) — an AI harness IT did not sanction` };
}

const RISK_RANK = { high: 0, med: 1, low: 2 };
const byRisk = (a, b) => (RISK_RANK[a.risk] - RISK_RANK[b.risk]) || String(a.name).localeCompare(String(b.name));

// ---- core: classify every inventory item against the allow-list ----
function discover(inv, allowlist) {
  const shadow = [], unclassified = [];
  const push = (arr, item) => arr.push(item);
  const classify = (kind, items, allow, toItem) => {
    for (const it of items) {
      const base = toItem(it);
      if (!allowlist.configured) { push(unclassified, { kind, ...base }); continue; }
      if (sanctioned(it.name, allow)) continue;
      push(shadow, { kind, ...base });
    }
  };
  classify("model", inv.models, allowlist.list.models, (m) => ({ name: m.name, provider: m.provider, local: m.local, ...modelRisk(m) }));
  classify("mcp-server", inv.mcpServers, allowlist.list.mcpServers, (s) => ({ name: s.name, transport: s.transport, ...mcpRisk(s) }));
  classify("extension", inv.extensions, allowlist.list.extensions, (x) => ({ name: x.name, editor: x.editor, version: x.version, ...extRisk(x) }));
  shadow.sort(byRisk); unclassified.sort(byRisk);
  return { shadow, unclassified };
}

function build(argv) {
  const inv = gatherInventory();
  const allowlist = resolveAllowlist(argv);
  const { shadow, unclassified } = discover(inv, allowlist);
  const items = allowlist.configured ? shadow : unclassified;
  const tally = (arr, key) => arr.reduce((m, x) => ((m[x[key]] = (m[x[key]] || 0) + 1), m), {});
  return {
    tool: "moorai-shadow", version: VERSION, device: hostname(), generatedAt: new Date().toISOString(),
    allowlistConfigured: allowlist.configured, allowlistSource: allowlist.source,
    inventoryDegraded: !!inv.degraded,
    summary: {
      shadow: shadow.length, unclassified: unclassified.length,
      byKind: tally(items, "kind"), byRisk: tally(items, "risk")
    },
    shadow, unclassified
  };
}

// ---- renderers ----
const KIND_LABEL = { model: "models", "mcp-server": "MCP servers", extension: "editor AI extensions" };
function toHuman(d) {
  const items = d.allowlistConfigured ? d.shadow : d.unclassified;
  const head = `MoorAI shadow-AI discovery — ${d.device}  ·  ${d.generatedAt.slice(0, 19)}Z\n`;
  const degraded = d.inventoryDegraded ? "  (inventory unavailable — partial result)\n" : "";
  if (!d.allowlistConfigured) {
    const banner = `No allow-list configured — cannot say what is sanctioned. ${items.length} AI asset(s) UNCLASSIFIED.\n`
      + `Set config.sanctioned in ~/.moorai/config.json (or MOORAI_SANCTIONED) to classify these.\n`;
    return head + degraded + "\n" + banner + renderGroups(items, "unclassified");
  }
  const banner = items.length
    ? `Shadow AI found: ${items.length}  (${d.summary.byRisk.high || 0} high · ${d.summary.byRisk.med || 0} med · ${d.summary.byRisk.low || 0} low)\n`
    : `Shadow AI found: 0 — every inventoried AI asset is on the allow-list.\n`;
  return head + degraded + "\n" + banner + renderGroups(items, "shadow");
}
function renderGroups(items, mode) {
  if (!items.length) return "";
  let out = "";
  for (const kind of ["model", "mcp-server", "extension"]) {
    const g = items.filter((x) => x.kind === kind);
    if (!g.length) continue;
    out += `\n  ${KIND_LABEL[kind]}:\n`;
    for (const x of g) {
      const tag = mode === "unclassified" ? "?" : x.risk;
      const meta = x.kind === "model" ? `(${x.local ? "local" : "cloud"}, ${x.provider})`
        : x.kind === "mcp-server" ? x.scope
        : `${x.editor}${x.version ? " v" + x.version : ""}`;
      out += `    [${tag}] ${x.name}  ${meta}\n         ${x.note}\n`;
    }
  }
  return out;
}

const HELP = `MoorAI shadow — unsanctioned-AI discovery for this device (content-free).

Usage:
  moorai-shadow [--json] [--strict] [--allowlist <file>]

Consumes the content-free AIBOM inventory (models, MCP servers, editor AI extensions)
and reports the ones NOT on your org's allow-list, grouped by kind with a risk note.

  --json      structured output
  --strict    exit non-zero if any shadow (or, with no allow-list, unclassified) AI is found
  --allowlist read the allow-list from this JSON file instead of config

Allow-list source (first that exists wins):
  MOORAI_SANCTIONED   inline JSON, or @/path/to/file.json
  --allowlist <file>  a JSON file
  config.sanctioned   ~/.moorai/config.json  →  { models:[], mcpServers:[], extensions:[] }

With NO allow-list configured, nothing is assumed sanctioned: every asset is reported
as "unclassified" (never silently treated as approved). Read-only, no network, fail-open.
`;

const argv = process.argv.slice(2);
if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); process.exit(0); }

const d = build(argv);
process.stdout.write(argv.includes("--json") ? JSON.stringify(d, null, 2) + "\n" : toHuman(d));

// --strict: a device is "clean" only when an allow-list IS configured AND no shadow item was found.
// No allow-list (unclassified > 0) also fails strict — CI cannot attest a device it cannot classify.
if (argv.includes("--strict")) {
  const dirty = d.allowlistConfigured ? d.shadow.length > 0 : d.unclassified.length > 0;
  if (dirty) process.exit(1);
}
