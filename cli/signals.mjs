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

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { isSecretCategory } from "./hook-core.mjs";

const DIR = join(homedir(), ".curaiq");
const LEDGER = join(DIR, "exposure-ledger.jsonl");
const INTENT = join(DIR, "intent-log.jsonl");

function append(file, obj) {
  try { mkdirSync(DIR, { recursive: true }); appendFileSync(file, JSON.stringify(obj) + "\n"); } catch { /* never block enforcement on a log write */ }
}
function readJsonl(file) {
  try { return readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
}

// #5 — record only credential/secret-class exposures. `entry` is already content-free
// (category, riskLevel, stage, tool, contentHash, identity, ts). Non-secret findings are ignored.
export function recordExposure(entry) {
  if (!entry || !isSecretCategory(entry.category)) return;
  append(LEDGER, entry);
}

// #15 — record a human's intent to proceed past findings. `entry` carries the threat ids/categories
// that were overridden and whether a justification was given (justificationHash, not the text).
export function recordIntent(entry) { append(INTENT, entry); }

export function readLedger() { return readJsonl(LEDGER); }
export function readIntent() { return readJsonl(INTENT); }
export const LEDGER_PATH = LEDGER;
export const INTENT_PATH = INTENT;
