// Cross-call memory for tool metadata — the half of vector 3 that no single-message scan can see.
//
// Two of the AMTSO vector-3 sub-techniques are DIFFERENCES, not strings:
//
//   tool-name-shadowing   — server B advertises a tool with the name server A already owns, so the
//                           agent's "send_email" silently becomes someone else's send_email. Nothing
//                           in B's own metadata has to look wrong for this to work.
//   capability-expansion  — the tool the operator approved at version 1.x re-advertises at 2.4.0
//                           with `cmd` and `path` added. Its description can be entirely benign;
//                           what changed is the schema, and only a BEFORE makes that visible.
//     (delayed rug-pull is the same shape with the payload in the description instead.)
//
// So the proxy needs to remember what a server advertised last time. Three constraints govern the
// shape of that memory:
//
//   CONTENT-FREE — the file holds fingerprints only (unkeyed SHA-256 prefixes, via toolIdentity).
//     No tool name, no description, no schema fragment is ever written to disk. `key` is the
//     fingerprint of the name, so lookups work without storing the name.
//   BOUNDED — MAX_ENTRIES total, evicted oldest-seen-first. A server advertising 10,000 tools
//     cannot grow this file without limit, and a corrupt/oversized file is discarded, not repaired.
//   FAIL-OPEN — every read and write is wrapped. A missing directory, a read-only home, a truncated
//     JSON file: all degrade to "no baseline", which means no drift signal. Never an exception into
//     the proxy's data path.
//
// The file is SHARED ACROSS SERVERS on purpose. One guard process proxies one MCP server, so
// shadowing — which is inherently a statement about two servers — is invisible from inside a single
// process. The shared file at ~/.moorai/mcp-tool-baseline.json is what lets process B notice that
// the name it is advertising was first seen from A.

import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "../cli/state-dirs.mjs";

export const MAX_ENTRIES = 512;
export const MAX_FILE_BYTES = 262144; // 256 KB — a baseline larger than this is treated as corrupt
export const BASELINE_FILE = "mcp-tool-baseline.json";

export function baselinePath(dir = STATE_DIR) { return join(dir, BASELINE_FILE); }

export function loadBaseline(dir = STATE_DIR) {
  try {
    const raw = readFileSync(baselinePath(dir), "utf8");
    if (raw.length > MAX_FILE_BYTES) return {};
    const j = JSON.parse(raw);
    if (!j || typeof j !== "object" || !j.tools || typeof j.tools !== "object") return {};
    return j.tools;
  } catch { return {}; }
}

export function saveBaseline(tools, dir = STATE_DIR) {
  try {
    const keys = Object.keys(tools);
    if (keys.length > MAX_ENTRIES) {
      // Oldest-seen-first eviction. `n` is a monotonic counter written on every observation, so this
      // is a real LRU and not a timestamp comparison that a clock change can invert.
      keys.sort((a, b) => (tools[a].n || 0) - (tools[b].n || 0));
      for (const k of keys.slice(0, keys.length - MAX_ENTRIES)) delete tools[k];
    }
    mkdirSync(dir, { recursive: true });
    const tmp = baselinePath(dir) + ".tmp";
    writeFileSync(tmp, JSON.stringify({ v: 1, tools }));
    renameSync(tmp, baselinePath(dir));
  } catch { /* the baseline is evidence, never enforcement — a write failure is silent */ }
}

// Compare one freshly-advertised tool against what was recorded for that name, and return the
// content-free drift signals. Pure: the caller decides what to do with them and when to persist.
//
// A FIRST sighting produces no signal. That is the honest behaviour and it is also the limit of this
// mechanism: a server that is already poisoned the first time the proxy ever sees it has no BEFORE
// to differ from, so shadowing/expansion is caught on the SECOND advertisement onward. The one-shot
// case is covered — when it is covered at all — by the text scan, not by this file.
export function driftSignals(prev, cur) {
  if (!prev) return [];
  const out = [];
  if (prev.srv !== cur.srv) {
    out.push({
      kind: "shadow",
      category: "MCP: tool name shadowed by a second server",
      riskLevel: "High",
      token: `mcp:tool:shadow:${cur.key}`
    });
    return out; // a different server is a different tool; comparing its description to A's is noise
  }
  const desc = prev.desc !== cur.desc;
  const schema = prev.schema !== cur.schema;
  if (schema) out.push({
    kind: "schema-drift",
    category: "MCP: tool schema changed after approval (capability expansion)",
    riskLevel: "High",
    token: `mcp:tool:schema-drift:${cur.key}`
  });
  if (desc) out.push({
    kind: "description-drift",
    category: "MCP: tool description changed after approval (possible rug-pull)",
    riskLevel: desc && schema ? "High" : "Medium",
    token: `mcp:tool:desc-drift:${cur.key}`
  });
  return out;
}

export function recordTool(tools, cur, n) {
  tools[cur.key] = { srv: cur.srv, desc: cur.desc, schema: cur.schema, n };
}
