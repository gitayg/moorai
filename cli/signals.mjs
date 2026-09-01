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

import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
function append(file, obj) {
  try {
    mkdirSync(DIR, { recursive: true });
    let line = obj;
    try { line = stampRecord(basename(file), obj, { tenant: obj && obj.tenant }); }
    catch { /* chain stamp is best-effort; fall back to the unstamped record */ }
    appendFileSync(file, JSON.stringify(line) + "\n");
  } catch { /* never block enforcement on a log write */ }
}
function readJsonl(file) {
  try { return readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
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
export function recordAction(entry) {
  append(ACTION_AUDIT, entry);
  try { const rows = readJsonl(ACTION_AUDIT); if (rows.length > ACTION_CAP) writeFileSync(ACTION_AUDIT, rows.slice(-ACTION_CAP).map((r) => JSON.stringify(r)).join("\n") + "\n"); } catch { /* best-effort */ }
  pruneByAge(ACTION_AUDIT);
}
export function readActions() { return readJsonl(ACTION_AUDIT); }

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
