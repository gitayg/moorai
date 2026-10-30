// #59 Lethal trifecta, enforced. data/agent-behavior.js derives three content-free legs per call (read: private
// data; ingest: untrusted content; callout: a way out) and the hook posts one report when a session first holds
// all three. That report stays the built-in default. This module is the opt-in gate on top of it: when the
// signed policy sets threatPolicy[59] to "justify" (ask) or "block" / "kill" (deny), the call that would give the
// session its third leg gets that verdict.
//
// THE SESSION RECORD is the session ledger (cli/session-ledger.mjs): each invocation's row carries its legs as
// `tl` ("r", "i", "c"), keyed by the device-local hash of the session id, and the row is chained like the other
// evidence logs (cli/record-chain.mjs). Rows that ran nothing do not count: a call MoorAI denied, and a call this
// gate held (`tg`), so retrying a held call is held again. An ask the person answered counts as having run. A
// result (a PostToolUse row) always counts, whatever its verdict: it is already in the agent's context.
//
// THE RULE, for a PreToolUse call with legs L and prior legs P (the session's counted rows):
//   * P ∪ L holds all three legs, and L adds a leg P lacks → the verdict;
//   * P already holds all three (the third leg came from a result, which a hook cannot refuse, or from calls made
//     before the policy said so) and L carries the callout leg → the verdict, so the way out stays gated.
// For a PostToolUse result whose legs complete the trifecta, the hook can only put a reason next to the result
// (the caller does that); the next outbound call is then gated by the second rule.
//
// WHAT THIS DOES NOT DEFEND: the ledger is a file in the user's state directory. The agent runs as that user and
// can delete or edit it, which clears the session's legs. The chain stamp lets `moorai-verify-chain <path>` find an
// edited, dropped or reordered row among the rows left, but nothing sends this ledger's chain head off the device,
// so deleting the file together with its head leaves nothing to compare against. The #59 report (agent-events.jsonl,
// chained the same way) has the same boundary.
import { readSessionRows } from "./session-ledger.mjs";

export const TRIFECTA_THREAT = 59;
const LEVEL = { justify: "ask", block: "deny", kill: "deny" };
const CODE = { read: "r", ingest: "i", callout: "c" };
const LEGS = Object.keys(CODE);

// "ask" | "deny" | null — from the policy's threatPolicy[59] only (no tier, no built-in: the default is report).
export function trifectaLevel(policy) {
  const a = policy && policy.threatPolicy && policy.threatPolicy[TRIFECTA_THREAT];
  return LEVEL[a] || null;
}

export const legsCode = (legs) => LEGS.filter((k) => legs && legs[k]).map((k) => CODE[k]).join("");
export const legsOf = (code) => Object.fromEntries(LEGS.map((k) => [k, typeof code === "string" && code.includes(CODE[k])]));
export function mergeLegs(code, legs) { return legsCode({ ...legsOf(code), ...Object.fromEntries(LEGS.filter((k) => legs && legs[k]).map((k) => [k, true])) }); }

export function priorLegs(rows) {
  const p = { read: false, ingest: false, callout: false };
  for (const r of rows || []) {
    if (!r || typeof r.tl !== "string" || (r.ev !== "post" && (r.tg || r.decision === "deny"))) continue;
    for (const k of LEGS) if (r.tl.includes(CODE[k])) p[k] = true;
  }
  return p;
}

// → null | { level, missing: [legs this call adds], complete: true }
export function trifectaGate({ rows, legs, level, event = "PreToolUse" }) {
  if (!level || !legs) return null;
  const p = priorLegs(rows);
  const all = (o) => LEGS.every((k) => o[k]);
  const missing = LEGS.filter((k) => legs[k] && !p[k]);
  if (all(p)) return event === "PreToolUse" && legs.callout ? { level, missing: [], complete: true } : null;
  if (!missing.length || !LEGS.every((k) => p[k] || legs[k])) return null;
  return { level, missing, complete: true };
}

// The gate for this invocation: its session's ledger rows (sessionKey: the row's `s`) and the legs so far.
export function trifectaStep({ policy, sessionKey, legs, event }) {
  const level = trifectaLevel(policy);
  if (!level || !sessionKey) return null;
  return trifectaGate({ rows: readSessionRows(sessionKey), legs, level, event });
}

export function trifectaReason(g) {
  const name = { read: "private data", ingest: "untrusted content", callout: "an outbound path" };
  return g.missing.length
    ? `lethal trifecta (#59): this call would add ${g.missing.map((k) => name[k]).join(" and ")} to a session that already holds the other legs`
    : "lethal trifecta (#59): this session already holds private data, untrusted content and an outbound path, and this call uses the outbound path";
}
