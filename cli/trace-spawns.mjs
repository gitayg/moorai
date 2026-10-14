// Which Task / Agent call spawned a sub-agent, so the sub-agent's records carry parentSpanId = that call's
// span (cli/trace-context.mjs). Claude Code never names a sub-agent's parent on the sub-agent's own calls
// (measured on 2.1.295: its PreToolUse payload carries session_id, agent_id and agent_type, nothing about
// the spawning call). Two facts are available, and both are used:
//
//   1. PreToolUse(Agent) in the caller: the call's tool_use_id, subagent_type and the span MoorAI gave the
//      delegation record. Recorded here as a pending spawn once the host is told it may run.
//   2. PostToolUse(Agent) in the caller: tool_response.agentId is the child. That binds the child to the
//      spawn exactly. Measured: a background spawn reports it at launch, before the child's first call; a
//      foreground spawn only after the child has finished.
//
// Until an exact binding exists, a child's first record infers its parent: the one unbound pending spawn
// in its session whose subagent_type equals the child's agent_type. With none or several (parallel spawns
// of one type), the child's records carry the session's trace and no parentSpanId.
//
// Every id in the file is keyed with the device-local session-ledger key (localHash); the span ids are
// random. The file sits in ~/.moorai, which the governed agent can write: a same-user process can make a
// child's records point at another Task span of the same session, or at none. It cannot change which
// trace a record joins (the traceId comes from the session id in the hook payload), and nothing here
// decides enforcement. Best-effort: every error leaves the record without a parentSpanId.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { localHash } from "./session-ledger.mjs";
import { validSpanId } from "./trace-context.mjs";
import { withFileLock } from "./alert-seq.mjs";

export const SPAWNS_FILE = "trace-spawns.json";
const LOCK = ".trace-spawns.lock";
export const SPAWN_TTL_MS = 24 * 3600 * 1000;
export const MAX_SPAWNS = 256;
export const MAX_BINDS = 512;
const LOCK_WAIT_MS = 100;

function read(dir) {
  try {
    const j = JSON.parse(readFileSync(join(dir, SPAWNS_FILE), "utf8"));
    return { spawns: Array.isArray(j.spawns) ? j.spawns.filter((s) => s && typeof s === "object") : [], binds: j.binds && typeof j.binds === "object" && !Array.isArray(j.binds) ? j.binds : {} };
  } catch { return { spawns: [], binds: {} }; }
}
function prune(st, now) {
  st.spawns = st.spawns.filter((s) => Number.isFinite(s.ts) && now - s.ts < SPAWN_TTL_MS).slice(-MAX_SPAWNS);
  const keep = Object.entries(st.binds).filter(([, b]) => b && Number.isFinite(b.ts) && now - b.ts < SPAWN_TTL_MS).sort((a, b) => a[1].ts - b[1].ts).slice(-MAX_BINDS);
  st.binds = Object.fromEntries(keep);
}
function write(dir, st) {
  const p = join(dir, SPAWNS_FILE);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
  renameSync(tmp, p);
}
// fn runs only while holding the lock; → fn's value, or undefined when the lock could not be had. The shared
// withFileLock bounds every wait (a symlink, a directory or a live holder at the lock path costs at most
// LOCK_WAIT_MS, never a spin) and never breaks a live holder's lock.
function locked(dir, fn) {
  try { mkdirSync(dir, { recursive: true }); } catch { /* the lock fails too */ }
  const r = withFileLock(join(dir, LOCK), fn, { waitMs: LOCK_WAIT_MS, mode: 0o600 });
  return r.held ? r.value : undefined;
}

// A Task / Agent call the host was told it may run. caller: the calling sub-agent's agent_id ("" for the
// main thread). → true when recorded.
export function recordSpawn({ sessionId, caller = "", subagentType = "", toolUseId = "", spanId }, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    if (!sessionId || !validSpanId(spanId)) return false;
    const row = { s: localHash(sessionId), c: localHash(caller), ty: localHash(subagentType || "-"), u: toolUseId ? localHash(toolUseId) : "", span: spanId, ts: now };
    return locked(dir, () => { const st = read(dir); prune(st, now); st.spawns.push(row); write(dir, st); return true; }) === true;
  } catch { return false; }
}

// PostToolUse(Agent): tool_response.agentId names the child of the call tool_use_id. → the span, or null.
export function bindSpawnResult({ sessionId, toolUseId, agentId }, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    if (!sessionId || !toolUseId || typeof agentId !== "string" || !agentId) return null;
    const s = localHash(sessionId), u = localHash(toolUseId), a = localHash(agentId);
    return locked(dir, () => {
      const st = read(dir);
      prune(st, now);
      const sp = st.spawns.find((x) => x.s === s && x.u === u && validSpanId(x.span));
      if (!sp) return null;
      for (const x of st.spawns) if (x !== sp && x.bound === a) delete x.bound;
      if (sp.bound && sp.bound !== a) delete st.binds[`${s}:${sp.bound}`];
      sp.bound = a;
      st.binds[`${s}:${a}`] = { span: sp.span, exact: true, ts: now };
      write(dir, st);
      return sp.span;
    }) ?? null;
  } catch { return null; }
}

// A sub-agent's record: the span of the call that spawned it, or null. Reads without the lock when the
// child is already bound; otherwise infers (exactly one unbound pending spawn of its type) under the lock.
export function parentSpanFor({ sessionId, agentId, agentType = "" }, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    if (!sessionId || typeof agentId !== "string" || !agentId) return null;
    const s = localHash(sessionId), a = localHash(agentId), key = `${s}:${a}`;
    const hit = (st) => { const b = st.binds[key]; return b && validSpanId(b.span) && now - b.ts < SPAWN_TTL_MS ? b.span : null; };
    const first = hit(read(dir));
    if (first) return first;
    const ty = localHash(agentType || "-");
    return locked(dir, () => {
      const st = read(dir);
      const again = hit(st);
      if (again) return again;
      prune(st, now);
      const c = st.spawns.filter((x) => x.s === s && x.ty === ty && !x.bound && validSpanId(x.span));
      if (c.length !== 1) return null;
      c[0].bound = a;
      st.binds[key] = { span: c[0].span, exact: false, ts: now };
      write(dir, st);
      return c[0].span;
    }) ?? null;
  } catch { return null; }
}
