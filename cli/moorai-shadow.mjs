#!/usr/bin/env node
// MoorAI — shadow-AI discovery. Answers one question: "what AI is running on this device that we did
// NOT approve?" It CONSUMES the content-free AIBOM inventory (cli/moorai-aibom.mjs) and layers a
// sanctioned-vs-unsanctioned decision on top: every model, MCP server, and editor AI extension the
// AIBOM found is checked against the org's allow-list, and the ones that are NOT on it are surfaced —
// grouped by kind, with a risk note (an unknown MCP server with network + filesystem/credential scope
// ranks highest). Read-only, no network, fail-open.
//
// Content-free by inheritance: the only inputs are AIBOM component NAMES + metadata (model names, MCP
// server names + capability scope, extension ids/versions, running local runtimes + ports, and AI
// provider keys at rest as provider + location class + KEYED hash). No prompt, file content, token,
// key, or arg value is ever read or shown — this layer adds a set-membership test, nothing that could leak.
//
//   node cli/moorai-shadow.mjs            # human report
//   node cli/moorai-shadow.mjs --json     # structured
//   node cli/moorai-shadow.mjs --strict   # exit non-zero if any shadow/unclassified AI is found (CI)
//
// Allow-list (the "sanctioned" set) — first source that exists wins:
//   MOORAI_SANCTIONED   env: inline JSON, or @/path/to/file.json          (override / testing)
//   --allowlist <path>  flag: JSON file                                    (override / testing)
//   config.sanctioned   ~/.moorai/config.json: { models, mcpServers, extensions }  (the org default)
// Each is { models:[], mcpServers:[], extensions:[], runtimes:[], apiKeyHashes:[] } (arrays of names;
// case-insensitive, substring-tolerant so "gpt-4o" sanctions "gpt-4o-mini" and a versionless id
// sanctions its versioned install). apiKeyHashes is EXACT-match only: the org's issued keys as the
// agent's keyed "h2:…" hash (the NO_KEY sentinel "h2:nokey" never sanctions anything).

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { STATE_DIR, LEGACY_DIRS } from "./state-dirs.mjs";
import { NO_KEY } from "./content-hash.mjs";

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
    const live = new Map((bom.localMcpListeners || []).map((m) => [`${m.scope}:${m.name}`, m.running]));
    return {
      models: [
        ...(bom.providers || []).filter((p) => p.model).map((p) => ({ name: p.model, provider: p.provider, local: false })),
        ...(bom.localModels || []).map((m) => ({ name: m.name, provider: m.runtime, local: true }))
      ],
      mcpServers: (bom.mcpServers || []).map((s) => ({ name: s.name, scope: s.scope, transport: s.transport, caps: s.caps || {}, level: s.level, running: live.has(`${s.scope}:${s.name}`) ? live.get(`${s.scope}:${s.name}`) : undefined })),
      extensions: (bom.editorExtensions || []).map((x) => ({ name: x.id, editor: x.editor, version: x.version })),
      runtimes: (bom.localRuntimes || []).map((r) => ({ name: r.runtime, ports: r.ports || [], bind: r.bind })),
      apiKeys: (bom.apiKeysAtRest || []).map((k) => ({ provider: k.provider, locationClass: k.locationClass, location: k.location, keyHash: k.keyHash }))
    };
  } catch {
    return { models: [], mcpServers: [], extensions: [], runtimes: [], apiKeys: [], degraded: true };
  }
}

// ---- allow-list resolution ----
const KINDS = ["models", "mcpServers", "extensions", "runtimes", "apiKeyHashes"];
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
  return { list: list || Object.fromEntries(KINDS.map((k) => [k, []])), source: configured ? source : "none", configured };
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
function runtimeRisk(r) {
  return r.bind === "network"
    ? { risk: "high", note: `unapproved local model server (${r.name}) listening beyond loopback — reachable from the network` }
    : { risk: "low", note: `unapproved local model server (${r.name}) running — on-device inference` };
}
function keyRisk(k) {
  return { risk: "med", note: `${k.provider} API key at rest (${k.locationClass}) that is not an org-approved key — prompts sent with it bypass org billing and controls` };
}
// A key is sanctioned only by an exact keyed-hash match; an unenrolled device's constant sentinel
// matches every key, so it can never sanction one.
const keySanctioned = (k, allow) => k.keyHash !== NO_KEY && allow.includes(String(k.keyHash).toLowerCase());
function extRisk(x) {
  return { risk: "med", note: `unapproved editor AI extension (${x.editor}) — an AI harness IT did not sanction` };
}

const RISK_RANK = { high: 0, med: 1, low: 2 };
const byRisk = (a, b) => (RISK_RANK[a.risk] - RISK_RANK[b.risk]) || String(a.name).localeCompare(String(b.name));

// ---- core: classify every inventory item against the allow-list ----
function discover(inv, allowlist) {
  const shadow = [], unclassified = [];
  const push = (arr, item) => arr.push(item);
  const classify = (kind, items, allow, toItem, isSanctioned = (it) => sanctioned(it.name, allow)) => {
    for (const it of items || []) {
      const base = toItem(it);
      if (!allowlist.configured) { push(unclassified, { kind, ...base }); continue; }
      if (isSanctioned(it)) continue;
      push(shadow, { kind, ...base });
    }
  };
  classify("model", inv.models, allowlist.list.models, (m) => ({ name: m.name, provider: m.provider, local: m.local, ...modelRisk(m) }));
  classify("mcp-server", inv.mcpServers, allowlist.list.mcpServers, (s) => ({ name: s.name, transport: s.transport, ...(s.running !== undefined ? { running: s.running } : {}), ...mcpRisk(s) }));
  classify("extension", inv.extensions, allowlist.list.extensions, (x) => ({ name: x.name, editor: x.editor, version: x.version, ...extRisk(x) }));
  classify("local-runtime", inv.runtimes, allowlist.list.runtimes, (r) => ({ name: r.name, ports: r.ports, bind: r.bind, ...runtimeRisk(r) }));
  classify("api-key", inv.apiKeys, allowlist.list.apiKeyHashes,
    (k) => ({ name: `${k.provider} key`, provider: k.provider, locationClass: k.locationClass, location: k.location, keyHash: k.keyHash, ...keyRisk(k) }),
    (k) => keySanctioned(k, allowlist.list.apiKeyHashes));
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
const KIND_LABEL = { model: "models", "mcp-server": "MCP servers", extension: "editor AI extensions", "local-runtime": "running local model servers", "api-key": "AI provider keys at rest" };
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
  for (const kind of ["model", "mcp-server", "extension", "local-runtime", "api-key"]) {
    const g = items.filter((x) => x.kind === kind);
    if (!g.length) continue;
    out += `\n  ${KIND_LABEL[kind]}:\n`;
    for (const x of g) {
      const tag = mode === "unclassified" ? "?" : x.risk;
      const meta = x.kind === "model" ? `(${x.local ? "local" : "cloud"}, ${x.provider})`
        : x.kind === "mcp-server" ? x.scope + (x.running === true ? "  (running)" : "")
        : x.kind === "local-runtime" ? `ports ${x.ports.join(",") || "—"} · ${x.bind}`
        : x.kind === "api-key" ? `${x.locationClass}${x.location ? " " + x.location : ""} · ${x.keyHash}`
        : `${x.editor}${x.version ? " v" + x.version : ""}`;
      out += `    [${tag}] ${x.name}  ${meta}\n         ${x.note}\n`;
    }
  }
  return out;
}

const HELP = `MoorAI shadow — unsanctioned-AI discovery for this device (content-free).

Usage:
  moorai-shadow [--json] [--strict] [--allowlist <file>]

Consumes the content-free AIBOM inventory (models, MCP servers, editor AI extensions,
running local model servers, AI provider keys at rest — as keyed hashes only) and reports
the ones NOT on your org's allow-list, grouped by kind with a risk note.

  --json      structured output
  --strict    exit non-zero if any shadow (or, with no allow-list, unclassified) AI is found
  --allowlist read the allow-list from this JSON file instead of config

Allow-list source (first that exists wins):
  MOORAI_SANCTIONED   inline JSON, or @/path/to/file.json
  --allowlist <file>  a JSON file
  config.sanctioned   ~/.moorai/config.json  →  { models:[], mcpServers:[], extensions:[],
                                                  runtimes:[], apiKeyHashes:["h2:…"] }
  apiKeyHashes match exactly (the agent's keyed hash of an org-issued key); "h2:nokey" never matches.

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
