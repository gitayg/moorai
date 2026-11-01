// Ask-outcome tracking: what became of a call MoorAI answered "ask" on (Claude Code only).
//
// Claude Code does not tell a hook who answered its permission prompt, or whether one was shown. What it
// does give: PostToolUse ("after a tool completes successfully") and PostToolUseFailure ("a tool that started
// executing fails"), each carrying the call's tool_use_id. So when MoorAI asks on a tool those events are
// registered for (ASK_TRACKED), the ask is remembered here, keyed, with the seq range of the alerts it raised:
//   - a PostToolUse with the same tool_use_id: the call ran after the ask (approved, by a person, a
//     --permission-prompt-tool or an auto-approval: not established which), basis post-after-ask;
//   - a PostToolUseFailure: it started and failed, basis failure-after-ask;
//   - Stop / SubagentStop with the ask still here: it did not run in that turn (declined, interrupted or
//     cancelled, which cannot be told apart), basis no-execution-before-stop.
// A tool with no PostToolUse matcher (Write, Edit, Read, ...) is never tracked: its ask reads
// ask-not-trackable. Widening the matchers would add a hook process per edit.
//
// Every id is keyed with the device-local session-ledger key (localHash) before it is written; the raw
// session id, tool_use_id and agent id never reach the file. The file sits in ~/.moorai at the same trust
// level as the rest of the hook state: an agent that edits it can make an ask read as resolved or not, and
// the record it produces says "inferred" or "not established" either way. Nothing here decides enforcement.
// Best-effort: every error reads as "nothing tracked".
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "./state-dirs.mjs";
import { localHash } from "./session-ledger.mjs";
import { withFileLock } from "./alert-seq.mjs";

export const ASKS_FILE = "ask-pending.json", MAX_ASKS = 256, ASK_TTL_MS = 86400000, MAX_UNRESOLVED_PER_STOP = 16;
export const ASK_TRACKED = Object.freeze({
  PostToolUse: Object.freeze(["WebFetch", "WebSearch", "Bash", "PowerShell", "Agent", "Task", "mcp__*"]),
  PostToolUseFailure: Object.freeze(["Bash", "PowerShell", "mcp__*"])
});
const LOCK = ".ask-pending.lock";
const LOCK_WAIT_MS = 100;
const TRACKED = new Set(ASK_TRACKED.PostToolUse.filter((t) => !t.endsWith("*")));

export function askTrackable(tool) {
  return typeof tool === "string" && (TRACKED.has(tool) || (tool.startsWith("mcp__") && tool.length > 5));
}

const seqOrNull = (v) => (Number.isSafeInteger(v) && v > 0 ? v : null);
function read(dir) {
  try {
    const j = JSON.parse(readFileSync(join(dir, ASKS_FILE), "utf8"));
    return Array.isArray(j && j.asks) ? j.asks.filter((a) => a && typeof a === "object" && typeof a.s === "string" && typeof a.u === "string") : [];
  } catch { return []; }
}
function write(dir, asks) {
  const p = join(dir, ASKS_FILE);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ v: 1, asks }), { mode: 0o600 });
  renameSync(tmp, p);
}
const live = (asks, now) => asks.filter((a) => Number.isFinite(a.ts) && a.ts <= now + 60000 && now - a.ts < ASK_TTL_MS);
function locked(dir, fn) {
  try { mkdirSync(dir, { recursive: true }); } catch { /* the lock fails too */ }
  const r = withFileLock(join(dir, LOCK), fn, { waitMs: LOCK_WAIT_MS, mode: 0o600 });
  return r.held ? r.value : undefined;
}

// → true when remembered.
export function recordAsk({ sessionId, agentId = "", toolUseId, seqFrom, seqTo } = {}, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    if (typeof sessionId !== "string" || !sessionId || typeof toolUseId !== "string" || !toolUseId) return false;
    const row = { s: localHash(sessionId), u: localHash(toolUseId), a: agentId ? localHash(agentId) : "", f: seqOrNull(seqFrom), t: seqOrNull(seqTo), ts: now };
    return locked(dir, () => {
      const asks = live(read(dir), now).filter((x) => !(x.s === row.s && x.u === row.u));
      asks.push(row);
      write(dir, asks.slice(-MAX_ASKS));
      return true;
    }) === true;
  } catch { return false; }
}

// One-shot: the ask for this call, removed as it is returned. → null | { seqFrom, seqTo, agentId (keyed) }.
export function takeAsk({ sessionId, toolUseId } = {}, { dir = STATE_DIR, now = Date.now() } = {}) {
  try {
    if (typeof sessionId !== "string" || !sessionId || typeof toolUseId !== "string" || !toolUseId) return null;
    const s = localHash(sessionId), u = localHash(toolUseId);
    if (!read(dir).some((x) => x.s === s && x.u === u)) return null; // the common case: nothing to take, no lock
    return locked(dir, () => {
      const asks = live(read(dir), now);
      const i = asks.findIndex((x) => x.s === s && x.u === u);
      if (i < 0) return null;
      const [hit] = asks.splice(i, 1);
      write(dir, asks);
      return { seqFrom: seqOrNull(hit.f), seqTo: seqOrNull(hit.t), agentId: typeof hit.a === "string" ? hit.a : "" };
    }) ?? null;
  } catch { return null; }
}

// Every ask of this session and thread still here, removed. → { asks: the oldest `max`, more: the rest }.
export function takeUnresolvedAsks({ sessionId, agentId = "" } = {}, { dir = STATE_DIR, now = Date.now(), max = MAX_UNRESOLVED_PER_STOP } = {}) {
  const none = { asks: [], more: 0 };
  try {
    if (typeof sessionId !== "string" || !sessionId) return none;
    const s = localHash(sessionId), a = agentId ? localHash(agentId) : "";
    if (!read(dir).some((x) => x.s === s && (x.a || "") === a)) return none;
    return locked(dir, () => {
      const asks = live(read(dir), now);
      const mine = asks.filter((x) => x.s === s && (x.a || "") === a).sort((x, y) => x.ts - y.ts);
      if (!mine.length) return none;
      write(dir, asks.filter((x) => !mine.includes(x)));
      return { asks: mine.slice(0, max).map((x) => ({ seqFrom: seqOrNull(x.f), seqTo: seqOrNull(x.t) })), more: Math.max(0, mine.length - max) };
    }) ?? none;
  } catch { return none; }
}
