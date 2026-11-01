// The stdio guard's MCP read checks, for its one server: the harvest budgets (cli/mcp-harvest.mjs) over this
// process's lifetime, and the path scope check (cli/mcp-scope.mjs) against the server's declared scope (signed
// policy roots, the client's MCP roots, or the filesystem server's own launch arguments).
//
// The guard sees what the hook cannot: the server's resources/read requests and each result's size on the wire,
// the client's roots, and the tools' annotations. State is in memory only, keyed with a random per-process key:
// nothing is written to disk and no tool name, argument, URI or result byte is kept.
import { createHmac, randomBytes } from "node:crypto";
import { mcpHarvestConfig, isMcpRead, dumpShaped, assessHarvest, harvestAlert, harvestReason, readIdentity } from "../cli/mcp-harvest.mjs";
import { declaredScope, judgeScope, decideScope, scopeAlert } from "../cli/mcp-scope.mjs";

const RANK = { allow: 1, ask: 2, deny: 3 };
const MAX_PENDING = 512;

// The JSON-RPC answer to a refused resources/read: a resources/read result must carry `contents`, so a refusal
// is an error, not a tool-style isError result.
export function resourceBlockLine(id, reason) {
  return JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32001, message: `MoorAI blocked this MCP resource read: ${reason}` } }) + "\n";
}

// server: the guard's label. decl: { command, args } the guard launched.
export function createReadGate({ server, decl }) {
  const key = randomBytes(32);
  const h = (s) => createHmac("sha256", key).update(String(s)).digest("hex").slice(0, 16);
  let state = null;
  const pending = new Map(); // response id -> the tool (or resources/read) of a counted read
  return {
    // One request. method "tools/call" (tool, args, annotation) or "resources/read" (args = { uri }).
    // → { decision: "allow"|"ask"|"deny", gate: null|"harvest"|"scope", reason, alerts: [alert body] }
    call({ policy, method = "tools/call", tool = "", args, annotation = null, clientRoots = [], id, now = Date.now() }) {
      const out = { decision: "allow", gate: null, reason: "", alerts: [] };
      try {
        const cfg = mcpHarvestConfig(policy);
        if (cfg.mode !== "off" && isMcpRead(policy, { method, server, tool, annotation })) {
          const uri = method === "resources/read" && args && typeof args.uri === "string" ? args.uri : null;
          const readKey = h(readIdentity(server, method === "resources/read" ? "resources/read" : tool, uri !== null ? uri : args));
          const r = assessHarvest(state, "proc", { pre: true, readKey, dump: method === "tools/call" && dumpShaped(args) }, now, cfg);
          state = r.state;
          if (id != null) { if (pending.size >= MAX_PENDING) pending.delete(pending.keys().next().value); pending.set(String(id), method === "resources/read" ? "resources/read" : tool); }
          const d = r.level === "block" ? "deny" : r.level;
          if (RANK[d] > RANK[out.decision]) Object.assign(out, { decision: d, gate: "harvest", reason: harvestReason(r.over) });
          for (const k of r.fresh) out.alerts.push(harvestAlert(k, { server, reads: r.reads, bytes: r.bytes, cfg, decision: d }));
        }
      } catch { /* evidence; a failed count never decides */ }
      try {
        const scope = declaredScope({ policy, label: server, decl, clientRoots });
        const judged = scope ? judgeScope(scope, tool, args, { server }) : null;
        const v = judged ? decideScope(policy, server, tool, judged) : null;
        if (v) {
          if (RANK[v.decision] > RANK[out.decision]) Object.assign(out, { decision: v.decision, gate: "scope", reason: v.reason });
          out.alerts.push(scopeAlert({ server, judged, source: scope.source, decision: v.decision }));
        }
      } catch { /* fail open */ }
      return out;
    },
    // One response. Counted only when it answers a read this gate counted. → [alert body], each with its tool
    result({ policy, id, bytes, now = Date.now() }) {
      try {
        const k = id == null ? null : String(id);
        if (k === null || !pending.has(k)) return [];
        const tool = pending.get(k);
        pending.delete(k);
        const cfg = mcpHarvestConfig(policy);
        if (cfg.mode === "off" || !(bytes > 0)) return [];
        const r = assessHarvest(state, "proc", { bytes }, now, cfg);
        state = r.state;
        return r.fresh.map((x) => ({ ...harvestAlert(x, { server, reads: r.reads, bytes: r.bytes, cfg, decision: "allow" }), readTool: tool }));
      } catch { return []; }
    },
    // A response id this gate is waiting on (for a line too large to parse).
    waiting: () => pending.size > 0
  };
}
