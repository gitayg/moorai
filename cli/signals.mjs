// On-device, content-free signal logs. Two append-only JSONL files under the agent's config dir:
//
//   exposure-ledger.jsonl  (#5) — every time a secret/credential class is exposed to an agent, one
//     line: category, calibrated risk, stage, tool, identity, one-way content hash, timestamp. Never
//     the value, never the matched span. Answers "which credential classes were exposed to which
//     agent?" so an incident-response credential rotation is targeted, not blanket.
//   intent-log.jsonl       (#15) — every time a human overrides a finding and proceeds (with or
//     without a typed justification), one line capturing that intent signal. This is the datum
//     defenders lack: legitimate agentic use resembles attack, and a signed human "proceed" is what
//     disambiguates the two. The justification text stays on the device; only its hash leaves.
//
// Both fail open and silent: a logging error must never affect the enforcement decision.

import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { isSecretCategory } from "./hook-core.mjs";

const DIR = join(homedir(), ".curaiq");
const LEDGER = join(DIR, "exposure-ledger.jsonl");
const INTENT = join(DIR, "intent-log.jsonl");
const AGENT_EVENTS = join(DIR, "agent-events.jsonl");
const AGENT_EVENTS_CAP = 400; // rolling window; keep the file bounded
const ACTION_AUDIT = join(DIR, "action-audit.jsonl"); // #5 — searchable per-action timeline
const ACTION_CAP = 1000;
const RETENTION_DAYS = Number(process.env.MOORAI_RETENTION_DAYS) || 90; // Bold B5 — you control how long on-device evidence lives (0 = keep forever)

function append(file, obj) {
  try { mkdirSync(DIR, { recursive: true }); appendFileSync(file, JSON.stringify(obj) + "\n"); } catch { /* never block enforcement on a log write */ }
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

export function readLedger() { return readJsonl(LEDGER); }
export function readIntent() { return readJsonl(INTENT); }
export const LEDGER_PATH = LEDGER;
export const INTENT_PATH = INTENT;
export const AGENT_EVENTS_PATH = AGENT_EVENTS;
