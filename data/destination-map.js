// Per-agent destination map — "where did this agent actually reach?", aggregated on the device.
//
// The console already knows which MCP servers are APPROVED and which model endpoints are ALLOWED. What
// nothing answered before is the observed counterpart: for one agent/tool, the set of external
// destinations it actually touched, how often, when first and last, and whether the call was allowed or
// denied. That is the difference between a policy document and an inventory.
//
// Content-free by construction. A destination row carries a HOST (never a URL path or query string —
// data/model-endpoints.js never captures them) or an MCP SERVER NAME, plus the hook's own allow/ask/deny
// verdict for the call that reached it. There is no request body, no argument, no response, no prompt.
//
// Pure: rows in, rollup out. Storage lives in cli/signals.mjs alongside the exposure and intent ledgers.

// row = { ts:ISO, tool, kind:"host"|"mcp", name, decision:"allow"|"ask"|"deny", device, user, tenant }
export function destinationKey(row) { return `${row.tool}|${row.kind}|${row.name}`; }

function bump(agg, row) {
  const k = destinationKey(row);
  let d = agg.get(k);
  if (!d) { d = { tool: row.tool, kind: row.kind, name: row.name, count: 0, decisions: {}, firstSeen: row.ts, lastSeen: row.ts }; agg.set(k, d); }
  d.count++;
  d.decisions[row.decision] = (d.decisions[row.decision] || 0) + 1;
  if (row.ts < d.firstSeen) d.firstSeen = row.ts;
  if (row.ts > d.lastSeen) d.lastSeen = row.ts;
  return d;
}

// Grouped by agent/tool, destinations within each sorted by descending count then name, so the busiest
// destination for an agent reads first and the ordering is stable for a diff between two runs.
export function rollupDestinations(rows) {
  const agg = new Map();
  for (const r of rows || []) {
    if (!r || !r.name || !r.tool) continue;
    bump(agg, { decision: "allow", kind: "host", ...r });
  }
  const byTool = new Map();
  for (const d of agg.values()) {
    if (!byTool.has(d.tool)) byTool.set(d.tool, []);
    byTool.get(d.tool).push(d);
  }
  const agents = [...byTool.entries()].map(([tool, destinations]) => {
    destinations.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
    return {
      tool,
      destinations,
      reached: destinations.length,
      denied: destinations.filter((d) => (d.decisions.deny || 0) > 0).length
    };
  }).sort((a, b) => b.reached - a.reached || a.tool.localeCompare(b.tool));
  const ts = (rows || []).map((r) => r && r.ts).filter(Boolean).sort();
  return {
    entries: (rows || []).length,
    agents,
    destinations: agg.size,
    firstSeen: ts[0] || null,
    lastSeen: ts[ts.length - 1] || null
  };
}

// Has this exact agent→destination pair been seen before? Drives the "new destination" alert: the hook
// emits once per newly observed pair rather than once per call, so a busy agent does not flood the SOC.
export function isNewDestination(rows, row) {
  const k = destinationKey(row);
  return !(rows || []).some((r) => r && destinationKey(r) === k);
}
