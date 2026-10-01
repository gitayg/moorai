// The per-invocation session ledger: one content-free row for every time the hook runs inside an agent
// session — a PreToolUse verdict, a PostToolUse scan (with the call's outcome), a PostToolUseFailure, a
// user prompt (turn boundary), a Stop / SubagentStop, a PreCompact. It is what the Stop summary counts
// and what the claimed-success check compares the agent's final message against.
//
// Content-free: the session id, agent id, command and tool_use_id are keyed with a DEVICE-LOCAL key
// (not the tenant key — an unenrolled device hashes everything to one sentinel, which would merge every
// session) and truncated. A command is reduced to a class token (verify / probe / effect / other) and a
// keyed hash used only to tell "the same command re-run" from "a different command".
//
// Best-effort and fail-open, like every other on-device log: a write error never affects a decision.

import { appendFileSync, mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHmac, randomBytes } from "node:crypto";
import { STATE_DIR } from "./state-dirs.mjs";
import { stampRecord } from "./record-chain.mjs";

export const SESSION_LEDGER_FILE = "session-ledger.jsonl";
export const SESSION_LEDGER_KEY_FILE = "session-ledger.key";
const MAX_BYTES = 1048576; // trim when the file passes ~1 MB ...
const KEEP_ROWS = 2000;    // ... down to the newest rows
const READ_ROWS = 4000;    // a reader never parses more than this many trailing lines

const ledgerPath = () => join(STATE_DIR, SESSION_LEDGER_FILE);

let _key;
function key() {
  if (_key) return _key;
  const p = join(STATE_DIR, SESSION_LEDGER_KEY_FILE);
  try { const k = readFileSync(p, "utf8").trim(); if (/^[0-9a-f]{64}$/.test(k)) return (_key = Buffer.from(k, "hex")); } catch { /* absent */ }
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    const k = randomBytes(32);
    writeFileSync(p, k.toString("hex"), { mode: 0o600, flag: "wx" });
    return (_key = k);
  } catch {
    try { const k = readFileSync(p, "utf8").trim(); if (/^[0-9a-f]{64}$/.test(k)) return (_key = Buffer.from(k, "hex")); } catch { /* unreadable */ }
    return (_key = randomBytes(32)); // per-process: rows stay content-free, they just will not join
  }
}
export function localHash(s) {
  if (s == null || s === "") return "";
  return createHmac("sha256", key()).update(String(s), "utf8").digest("hex").slice(0, 16);
}

export function recordRow(row) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    let line = row;
    try { line = stampRecord(SESSION_LEDGER_FILE, row, { tenant: row && row.tenant }); } catch { /* unstamped is fine */ }
    appendFileSync(ledgerPath(), JSON.stringify(line) + "\n");
    if (statSync(ledgerPath()).size > MAX_BYTES) {
      const rows = readFileSync(ledgerPath(), "utf8").trim().split("\n");
      writeFileSync(ledgerPath(), rows.slice(-KEEP_ROWS).join("\n") + "\n");
    }
  } catch { /* never block on a log write */ }
}

// Rows of one session (keyed), oldest first. Bounded: only the trailing READ_ROWS lines are parsed.
export function readSessionRows(sessionKey) {
  if (!sessionKey) return [];
  try {
    const lines = readFileSync(ledgerPath(), "utf8").trim().split("\n").slice(-READ_ROWS);
    const out = [];
    for (const l of lines) { try { const r = JSON.parse(l); if (r && r.s === sessionKey) out.push(r); } catch { /* skip a torn line */ } }
    return out;
  } catch { return []; }
}
