// On-device, content-free signal logs. Three append-only JSONL files under the agent's config dir:
//
//   exposure-ledger.jsonl  (#5) — every time a secret/credential class is exposed to an agent, one
//     line: category, calibrated risk, stage, tool, identity, one-way content hash, timestamp. Never
//     the value, never the matched span. Answers "which credential classes were exposed to which
//     agent?" so an incident-response credential rotation is targeted, not blanket.
//   intent-log.jsonl       (#15) — every time a human overrides a finding and proceeds (with or
//     without a typed justification), one line capturing that intent signal. This is the datum
//     defenders lack: legitimate agentic use resembles attack, and a signed human "proceed" is what
//     disambiguates the two. The justification text stays on the device; only its hash leaves.
//   destinations.jsonl     — per-agent destination map: one line per (agent/tool → external
//     destination) observation, where a destination is a HOST or an MCP SERVER NAME and the row also
//     carries the hook's own allow/ask/deny verdict for that call. Answers "where did this agent
//     actually reach?" — the observed counterpart to the console's allow-lists. No URL path, no query
//     string, no argument: the host extractor never captures them.
//
// Both fail open and silent: a logging error must never affect the enforcement decision.

import { appendFileSync, closeSync, fstatSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { join, basename } from "node:path";
import { isSecretCategory } from "./hook-core.mjs";
import { STATE_DIR } from "./state-dirs.mjs";
import { stampRecord } from "./record-chain.mjs";

const DIR = STATE_DIR; // ~/.moorai (was ~/.curaiq before the rebrand)
const LEDGER = join(DIR, "exposure-ledger.jsonl");
const INTENT = join(DIR, "intent-log.jsonl");
const AGENT_EVENTS = join(DIR, "agent-events.jsonl");
const AGENT_EVENTS_CAP = 400; // rolling window; keep the file bounded
const ACTION_AUDIT = join(DIR, "action-audit.jsonl"); // #5 — searchable per-action timeline
const ACTION_CAP = 1000;
const DESTINATIONS = join(DIR, "destinations.jsonl"); // per-agent destination map — hosts / MCP servers reached
const DESTINATION_CAP = 2000;
const RULES_BASELINE = join(DIR, "rules-baseline.json"); // rules-file drift: last fingerprint per kind
const RETENTION_DAYS = Number(process.env.MOORAI_RETENTION_DAYS) || 90; // Bold B5 — you control how long on-device evidence lives (0 = keep forever)

// Every appended line is chain-stamped (record-chain.mjs): a per-record fingerprint plus the seq/prev/
// chash link, so deletion, reordering, or in-place edits of these evidence logs are detectable after
// the fact (moorai-verify-chain). Best-effort and fail-open — a chain error must never block the write
// or the enforcement decision, so the stamp is wrapped and the raw line is still written on failure.
//
// One record is one write(2) on an O_APPEND descriptor, so concurrent writers (the hook runs as many
// short-lived processes) each land a whole line at the end of the file. Returns the fstat of the file
// written to (size and inode, for recordAction's compaction trigger), or null.
function append(file, obj) {
  try {
    mkdirSync(DIR, { recursive: true });
    let line = obj;
    try { line = stampRecord(basename(file), obj, { tenant: obj && obj.tenant }); }
    catch { /* chain stamp is best-effort; fall back to the unstamped record */ }
    const buf = Buffer.from(JSON.stringify(line) + "\n");
    for (let tries = 0; tries < 3; tries++) {
      const fd = openSync(file, "a+");
      try {
        writeAll(fd, buf);
        const st = fstatSync(fd);
        if (!strandedAfterSeal(file, fd, st, buf)) return st;
      } finally { closeSync(fd); }
    }
  } catch { /* never block enforcement on a log write */ }
  return null;
}
function writeAll(fd, buf) { let o = 0; while (o < buf.length) o += writeSync(fd, buf, o); }
// A compaction (recordAction) renames a new log over the one this writer opened. A line that reached the
// old file before the compactor SEALED it is carried over by the compactor; a line that landed after the
// seal would be lost with the old file, so the writer writes it again. One stat per write when nothing
// was replaced; the read of the old file happens only on the rare write that raced a compaction.
const SEAL = Buffer.from("\n#sealed\n");
function strandedAfterSeal(file, fd, st, buf) {
  let cur = null;
  try { cur = statSync(file); } catch { /* deleted under us: nothing to rejoin */ }
  if (!cur || cur.ino === st.ino) return false;
  const old = readLines(fd, 0).buf;
  const seal = old.indexOf(SEAL);
  return seal >= 0 && old.indexOf(buf, seal) > seal;
}
// An unparseable line (torn by a crash, or edited) drops only itself. It used to make the whole file
// read as empty, and pruneByAge then wrote that empty result over the log.
function readJsonl(file) {
  let text;
  try { text = readFileSync(file, "utf8"); } catch { return []; }
  const rows = [];
  for (const l of text.split("\n")) { if (!l.trim()) continue; try { rows.push(JSON.parse(l)); } catch { /* skip the bad line */ } }
  return rows;
}

// Bold B5 — age-based retention for on-device evidence. Entry `ts` may be epoch-ms (agent events) or
// an ISO string (alerts/intent); handle both. days<=0 disables pruning (keep forever). Best-effort:
// a pruning error must never affect enforcement or drop the just-written entry silently on error.
function tsMs(e) { const t = e && e.ts; if (typeof t === "number") return t; const p = Date.parse(t); return Number.isNaN(p) ? null : p; }
export function pruneByAge(file, days = RETENTION_DAYS) {
  if (!days || days <= 0) return;
  try {
    const cut = Date.now() - days * 86400000;
    const rows = readJsonl(file).filter((e) => { const m = tsMs(e); return m == null || m >= cut; });
    writeFileSync(file, rows.length ? rows.map((r) => JSON.stringify(r)).join("\n") + "\n" : "");
  } catch { /* retention is best-effort */ }
}

// #5 — record only credential/secret-class exposures. `entry` is already content-free
// (category, riskLevel, stage, tool, contentHash, identity, ts). Non-secret findings are ignored.
export function recordExposure(entry) {
  if (!entry || !isSecretCategory(entry.category)) return;
  append(LEDGER, entry);
  pruneByAge(LEDGER);
}

// #15 — record a human's intent to proceed past findings. `entry` carries the threat ids/categories
// that were overridden and whether a justification was given (justificationHash, not the text).
export function recordIntent(entry) { append(INTENT, entry); pruneByAge(INTENT); }

// Autonomous-agent-behavior analyzer input: one content-free event per tool call/prompt
// (ts, action fingerprint, allowed?, risk, and the content-tell flags). Never any text.
// Kept as a rolling window so the on-device signature analyzer has recent context, bounded in size.
export function recordAgentEvent(entry) {
  append(AGENT_EVENTS, entry);
  try {
    const rows = readJsonl(AGENT_EVENTS);
    if (rows.length > AGENT_EVENTS_CAP) writeFileSync(AGENT_EVENTS, rows.slice(-AGENT_EVENTS_CAP).map((r) => JSON.stringify(r)).join("\n") + "\n");
  } catch { /* trimming is best-effort */ }
}
export function readAgentEvents() { return readJsonl(AGENT_EVENTS); }

// #5 — local, searchable action-audit log. Entries are already tier-gated by the caller
// (applyCaptureTier), so a content-free device's log holds only content-free fields.
//
// THE WRITE PATH IS APPEND-ONLY, O(1). recordAction used to append, read the whole file back, rewrite it
// at the 1000-row cap, then read and rewrite it again for the age prune, on every call. MEASURED, median
// per write: 0.58 ms on an empty log, 6.96 ms at the cap, 39 ms at the cap under CPU + disk load. The
// gateway calls it for every refused request on its one event loop, so a client sending junk stalled
// the gateway for every other client, and the stall grew with the ledger. A write is now one O_APPEND
// line plus a read of a small marker file. The cap and the age prune run in an occasional COMPACTION:
//
//   * when the file has grown by max(64 KiB, 25 %) since the last compaction, so each O(file)
//     compaction is paid for by at least a quarter-cap's worth of cheap appends (amortised O(1));
//   * when the oldest row the last compaction kept has passed the retention age, so expired rows leave
//     the disk on the first write after they expire, as they did when every write pruned;
//   * when there is no marker, or the log is not the inode the marker describes (first run, upgrade
//     from the rewrite-every-write version, or the file was replaced or deleted under us).
//
// COMPACTION IS ATOMIC: the kept rows go to a per-process temp file, fsync, rename over the log. A crash
// at any point leaves the old log or the new one, never a torn one. (The old writeFileSync truncated the
// log in place, so a crash mid-write left half a file, which readJsonl then read as EMPTY.) One
// compactor at a time across processes, via an O_EXCL lock file that is taken over after 30 s (a
// compactor that died holding it). Rows other processes append while a compaction runs are not lost:
// those that reach the old file before the rename are re-read just before it; a writer that opened the
// old file and writes after the rename either lands before the compactor's seal (carried over by the
// compactor) or after it (the writer sees the seal and writes its line again). Such a straggler can land
// after rows written later. The old code lost rows outright: every write read the log and then truncated
// and rewrote it over whatever other processes had appended in between.
//
// READERS: between compactions the file holds up to ~25 % more than ACTION_CAP rows. readActions() and
// cli/moorai-trace.mjs (the only readers of this file's rows) keep the newest ACTION_CAP, so they return
// what the rewrite-every-write version returned. The age limit is not re-applied at read time; it is
// enforced on disk by the trigger above, after a write, exactly as before.
const ACTION_META = ACTION_AUDIT + ".compact"; // { bytes, ino, oldest } as of the last compaction
const ACTION_LOCK = ACTION_AUDIT + ".lock";
const ACTION_TMP = ACTION_AUDIT + ".tmp-";
const COMPACT_SLACK_MIN = 64 * 1024;
const LOCK_STALE_MS = 30000;

export function recordAction(entry) {
  const st = append(ACTION_AUDIT, entry);
  if (!st) return;
  try { if (compactionDue(st, Date.now())) compactActions(st); } catch { /* best-effort */ }
}
export function readActions() { return readJsonl(ACTION_AUDIT).slice(-ACTION_CAP); }

function readMeta() {
  try { const m = JSON.parse(readFileSync(ACTION_META, "utf8")); return m && typeof m.bytes === "number" ? m : null; } catch { return null; }
}
function writeMeta(m) { try { writeFileSync(ACTION_META, JSON.stringify(m)); } catch { /* a missing marker only means the next write compacts */ } }
function compactionDue(st, now) {
  const m = readMeta();
  if (!m || m.ino !== st.ino) return true;
  if (st.size > m.bytes + Math.max(COMPACT_SLACK_MIN, m.bytes / 4)) return true;
  return RETENTION_DAYS > 0 && typeof m.oldest === "number" && m.oldest < now - RETENTION_DAYS * 86400000;
}

// The complete lines in fd from `from` to its current end, and the offset just past them. A trailing
// partial line (a torn append) is left out.
function readLines(fd, from) {
  const size = fstatSync(fd).size;
  if (size <= from) return { buf: Buffer.alloc(0), end: from };
  const buf = Buffer.alloc(size - from);
  let n = 0;
  while (n < buf.length) { const r = readSync(fd, buf, n, buf.length - n, from + n); if (!r) break; n += r; }
  const last = n ? buf.lastIndexOf(10, n - 1) : -1;
  return { buf: buf.subarray(0, last + 1), end: from + last + 1 };
}

function takeLock() {
  try { closeSync(openSync(ACTION_LOCK, "wx")); return true; } catch (e) { if (e.code !== "EEXIST") return false; }
  try {
    if (Date.now() - statSync(ACTION_LOCK).mtimeMs < LOCK_STALE_MS) return false;
    unlinkSync(ACTION_LOCK);
    closeSync(openSync(ACTION_LOCK, "wx"));
    return true;
  } catch { return false; }
}

function compactActions(st) {
  if (!takeLock()) return;
  const tmp = ACTION_TMP + process.pid;
  let src = -1, out = -1;
  try {
    // A compactor that crashed left its temp file; it may hold rows past retention.
    for (const n of readdirSync(DIR)) { const p = join(DIR, n); if (p.startsWith(ACTION_TMP) && p !== tmp) try { unlinkSync(p); } catch { /* gone */ } }
    src = openSync(ACTION_AUDIT, "a+");
    const head = readLines(src, 0);
    const cut = RETENTION_DAYS > 0 ? Date.now() - RETENTION_DAYS * 86400000 : -Infinity;
    let kept = [];
    for (const l of head.buf.toString("utf8").split("\n")) {
      if (!l.trim()) continue;
      let ms;
      try { ms = tsMs(JSON.parse(l)); } catch { continue; }
      if (ms == null || ms >= cut) kept.push([l, ms]);
    }
    kept = kept.slice(-ACTION_CAP);
    let oldest = null;
    for (const [, ms] of kept) if (ms != null && (oldest == null || ms < oldest)) oldest = ms;
    out = openSync(tmp, "w");
    writeAll(out, Buffer.from(kept.map(([l]) => l + "\n").join("")));
    fsyncSync(out);
    const late = readLines(src, head.end); // appended while we filtered and synced
    writeAll(out, late.buf);
    const ino = fstatSync(out).ino;
    closeSync(out); out = -1;
    renameSync(tmp, ACTION_AUDIT);
    // Seal the old file, then carry over every line that reached it before the seal. A writer that
    // lands after the seal sees it and writes its line again (strandedAfterSeal).
    writeAll(src, SEAL);
    const rest = readLines(src, late.end).buf;
    const at = rest.indexOf(SEAL);
    if (at > 0) appendFileSync(ACTION_AUDIT, rest.subarray(0, rest.lastIndexOf(10, at - 1) + 1));
    writeMeta({ bytes: statSync(ACTION_AUDIT).size, ino, oldest });
  } catch {
    // Retry only after more growth, so a compaction that keeps failing (say a Windows rename refused
    // while another process holds the log open) cannot turn every write back into a full read.
    writeMeta({ bytes: st.size, ino: st.ino, oldest: null });
  } finally {
    if (out >= 0) try { closeSync(out); } catch { /* closed */ }
    if (src >= 0) try { closeSync(src); } catch { /* closed */ }
    try { unlinkSync(tmp); } catch { /* renamed into place, or never made */ }
    try { unlinkSync(ACTION_LOCK); } catch { /* best-effort */ }
  }
}

// Per-agent destination map — one line per (agent/tool → external destination) observation. The row is
// a host or an MCP server name plus the hook's own verdict; there is no URL path, query string, or
// argument in it. Same append/cap/prune discipline as the action audit above.
export function recordDestination(entry) {
  append(DESTINATIONS, entry);
  try { const rows = readJsonl(DESTINATIONS); if (rows.length > DESTINATION_CAP) writeFileSync(DESTINATIONS, rows.slice(-DESTINATION_CAP).map((r) => JSON.stringify(r)).join("\n") + "\n"); } catch { /* best-effort */ }
  pruneByAge(DESTINATIONS);
}
export function readDestinations() { return readJsonl(DESTINATIONS); }

// Skill-surface drift baseline (content-free) — last-seen one-way fingerprint per skill-surface FILE.
// The key is `kind|path` (see reportSkillFile): a device has one CLAUDE.md but a dozen
// .claude/agents/*.md, so a per-KIND slot made every sibling definition look like drift from the last
// one read. The path stays here on the device; only `kind` and the fingerprint are ever emitted.
export function rulesBaseline() { try { return JSON.parse(readFileSync(RULES_BASELINE, "utf8")); } catch { return {}; } }
export function setRulesBaseline(kind, fp) { try { const b = rulesBaseline(); b[kind] = fp; mkdirSync(DIR, { recursive: true }); writeFileSync(RULES_BASELINE, JSON.stringify(b)); } catch { /* best-effort */ } }

// #3 — kill sentinel. When a "kill" verdict fires in the interactive session, the hook (a separate
// process from the Tauri host) drops a small JSON sentinel here; the host watches for it, terminates
// the live agent PTY, then clears it. Content-free: only the terminating rule ids + timestamp, never
// the tool input. A stale sentinel is ignored by the host via the timestamp.
const KILL_SENTINEL = join(DIR, "kill-session");
export function requestKill(reason) {
  try { mkdirSync(DIR, { recursive: true }); writeFileSync(KILL_SENTINEL, JSON.stringify({ ts: Date.now(), ...reason })); } catch { /* best-effort; deny already applied */ }
}
export function readKill() { try { return JSON.parse(readFileSync(KILL_SENTINEL, "utf8")); } catch { return null; } }
export const KILL_SENTINEL_PATH = KILL_SENTINEL;

export function readLedger() { return readJsonl(LEDGER); }
export function readIntent() { return readJsonl(INTENT); }
export const LEDGER_PATH = LEDGER;
export const INTENT_PATH = INTENT;
export const DESTINATIONS_PATH = DESTINATIONS;
export const AGENT_EVENTS_PATH = AGENT_EVENTS;
export const ACTION_AUDIT_CAP = ACTION_CAP;
