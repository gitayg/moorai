// The shell hook's side of session-read secret tracking (#65, cli/secret-taint.mjs): which tool results
// teach the session a secret, and the tracker the hook's secret-egress check matches against.
//
// LEARN from content the agent reads:
//   Read            the file the hook already reads to scan (PreToolUse: the Read has no PostToolUse matcher)
//   Bash/PowerShell the command's output (PostToolUse)
//   mcp__*          the tool's result (PostToolUse)
// Provider tokens and entropy-gated named assignments from any of them; every KEY=value line when the
// source is credential-like (a Read of a credential path, a command that reads one or dumps the
// environment, an MCP call whose arguments name one). WebFetch / WebSearch results never teach: a page's
// example token is not the session's secret.
// MATCH at the outbound sinks that judge egress (cli/moorai-hook.mjs checkSecretEgress): a Bash command
// with network egress, a WebFetch, an MCP tool call.
import { sessionTracker, SECRET_TAINT_FILE } from "./secret-taint.mjs";
import { learnableSecrets, isCredentialPath, isEnvDump } from "./secret-learn.mjs";
import { sessionKeyedHash, readSessionState, writeSessionState } from "./session-state.mjs";
import { sessionRiskConfig } from "../data/session-risk.js";
import { extractReadPaths } from "./hook-core.mjs";

export { SECRET_TAINT_FILE };
export const SECRET_TAINT_CAP = 64;

// The tracker's key: HMAC(session.key, label), so it is never session.key itself.
function keyBytes() {
  const h = sessionKeyedHash("moorai/secret-taint/v1", 64);
  return h ? Buffer.from(h, "hex") : null;
}
const IO = { read: readSessionState, write: writeSessionState, get keyBytes() { return keyBytes(); } };

export function ttlOf(policy) {
  try { return sessionRiskConfig(policy).windowMin * 60000; } catch { return 30 * 60000; }
}

export function hookTracker(policy, sessionId, io = IO) {
  try { return sessionTracker({ sessionId, io, ttlMs: ttlOf(policy), cap: SECRET_TAINT_CAP }); } catch { return null; }
}

// Does this tool call read a credential-like source? (KEY=value lines then count.)
export function credentialSource(tool, toolInput) {
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  if (tool === "Read") return isCredentialPath(ti.file_path);
  if (tool === "Bash" || tool === "PowerShell") {
    const cmd = typeof ti.command === "string" ? ti.command : "";
    if (isEnvDump(cmd)) return true;
    try { return extractReadPaths(cmd, tool === "PowerShell" ? { shell: "powershell" } : undefined).some(isCredentialPath); } catch { return false; }
  }
  if (tool.startsWith("mcp__")) {
    const vals = [];
    const walk = (v, d) => { if (d > 4 || vals.length > 64) return; if (typeof v === "string") vals.push(v); else if (v && typeof v === "object") for (const x of Object.values(v)) walk(x, d + 1); };
    walk(ti, 0);
    return vals.some(isCredentialPath);
  }
  return false;
}

// Learn from one tool result. Returns the tracker's learn result, or null when nothing was learnable.
export function learnFromTool({ policy, sessionId, tool, toolInput, text, io }) {
  try {
    if (!sessionId || !text) return null;
    if (!(tool === "Read" || tool === "Bash" || tool === "PowerShell" || tool.startsWith("mcp__"))) return null;
    const values = learnableSecrets(text, { kv: credentialSource(tool, toolInput) });
    if (!values.length) return null;
    const tr = hookTracker(policy, sessionId, io);
    return tr ? tr.learn(values) : null;
  } catch { return null; }
}

// The content-free alert for a cap overflow (posted once per window per session).
export function capAlert(r, tool) {
  return { threatId: 65, category: "Session secret tracking cap reached", riskLevel: "High", stage: "output", tool: `hook:${tool}`, contentHash: `secret-cap:${r.cap}`, secretTaint: { cap: r.cap, dropped: r.dropped, kept: r.size } };
}
