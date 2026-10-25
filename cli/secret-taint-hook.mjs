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
import { openSync, closeSync, unlinkSync, statSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { sessionTracker, SECRET_TAINT_FILE, POOL_CAP } from "./secret-taint.mjs";
import { learnableSecrets, isCredentialPath, isEnvDump } from "./secret-learn.mjs";
import { sessionKeyedHash, readSessionState, writeSessionState } from "./session-state.mjs";
import { STATE_DIR } from "./state-dirs.mjs";
import { sessionRiskConfig } from "../data/session-risk.js";
import { extractReadPaths } from "./hook-core.mjs";

export { SECRET_TAINT_FILE };
export const SECRET_TAINT_CAP = POOL_CAP;

// The tracker's key: HMAC(session.key, label), so it is never session.key itself.
function keyBytes() {
  const h = sessionKeyedHash("moorai/secret-taint/v1", 64);
  return h ? Buffer.from(h, "hex") : null;
}
// Read-merge-write under a lockfile (O_EXCL), so parallel hook calls never drop one another's learns. A lock
// older than LOCK_STALE_MS is a crashed holder's and is removed; past LOCK_WAIT_MS the update runs unlocked
// (one learn may then be lost, never the verdict).
export const LOCK_STALE_MS = 5000;
const LOCK_WAIT_MS = 2000;
const nap = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
export function lockedUpdate(name, fn, { dir = STATE_DIR, read = readSessionState, write = writeSessionState } = {}) {
  const lock = join(dir, `${name}.lock`);
  try { mkdirSync(dir, { recursive: true }); } catch { /* unwritable: the write below fails too */ }
  let held = false;
  for (const t0 = Date.now(); Date.now() - t0 < LOCK_WAIT_MS;) {
    try { closeSync(openSync(lock, "wx", 0o600)); held = true; break; } catch { /* held by another call */ }
    try { if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) unlinkSync(lock); } catch { /* released meanwhile */ }
    nap(2 + Math.floor(Math.random() * 4));
  }
  try { write(name, fn(read(name))); } finally { if (held) { try { unlinkSync(lock); } catch { /* already gone */ } } }
}
// The state file is read with its own size bound: 16 sessions x 128 secrets plus the evicted-until map stay
// well under it, so a full table is never read back as empty (which would drop every tracked secret).
const MAX_STATE_BYTES = 4 << 20;
function readTaint(name) {
  try {
    const p = join(STATE_DIR, name);
    if (statSync(p).size > MAX_STATE_BYTES) return null;
    const o = JSON.parse(readFileSync(p, "utf8"));
    return o && typeof o === "object" && !Array.isArray(o) ? o : null;
  } catch { return null; }
}
const IO = { read: readTaint, write: writeSessionState, update: (name, fn) => lockedUpdate(name, fn, { read: readTaint }), get keyBytes() { return keyBytes(); } };

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
    const cred = credentialSource(tool, toolInput);
    const values = learnableSecrets(text, { kv: cred });
    if (!values.length) return null;
    const tr = hookTracker(policy, sessionId, io);
    return tr ? tr.learn(values, { cred }) : null;
  } catch { return null; }
}

// The content-free alert for a cap overflow (posted once per window per session).
export function capAlert(r, tool) {
  return { threatId: 65, category: "Session secret tracking cap reached", riskLevel: "High", stage: "output", tool: `hook:${tool}`, contentHash: `secret-cap:${r.cap}`, secretTaint: secretTaintFields(r) };
}
export function secretTaintFields(r) {
  return { pool: r.pool, cap: r.cap, dropped: r.dropped, overQuota: r.overQuota, kept: r.size };
}
// The content-free alert for live sessions evicted from a full session table (they fail closed until expiry).
export function evictAlert(r, tool) {
  return { threatId: 65, category: "Session secret tracking evicted a live session", riskLevel: "High", stage: "output", tool: `hook:${tool}`, contentHash: "secret-evict", secretTaint: { evictedLive: r.evictedLive } };
}
