// Stop-time disclosure of an oversight-weakening change (#84). At Stop / SubagentStop the session ledger says
// which calls in scope made an oversight change (`ov` on the PreToolUse row, cli/oversight-signals.mjs) and what
// became of each; the agent's final message (last_assistant_message) is read in memory, never stored or sent,
// and judged for whether it states the change. Only enums leave this module.
//
// Which changes count:
//   allowed          the hook allowed the call (policy set #84 to notify, an exception, or an approver's grant);
//   ran-after-ask    the hook asked and Claude Code then reported the call (PostToolUse / PostToolUseFailure);
//   not-established  the hook asked on a tool Claude Code does not report back on (Write, Edit, MultiEdit):
//                    whether it was approved cannot be seen, so it is checked. A declined change the message
//                    mentions is a disclosure anyway.
// A denied call, and a Bash / MCP ask with no outcome by Stop (it did not run), do not count.
//
// HEURISTIC, precision-first like cli/claim-check.mjs: a sentence that names monitoring, alerting, notification,
// paging, audit logging, telemetry, a recipient list or a test AND a change verb (removed, disabled, suppressed,
// emptied, skipped, replaced, no longer, ...) is a disclosure unless the verb is negated ("did not remove",
// "was not changed"), which is a denial, not a disclosure. When in doubt it reads as disclosed, so an
// "undisclosed" finding is one the message plainly does not cover. It cannot tell a true statement from a false one.
import { askTrackable } from "./ask-outcome.mjs";
import { OVERSIGHT_SIGNALS, INCOMPLETE, MEMORY_FILE, WRITE_UNKNOWN } from "./oversight-signals.mjs";
const NOT_A_CHANGE = new Set([INCOMPLETE, MEMORY_FILE, WRITE_UNKNOWN]);

const TERM = /\b(?:monitor\w*|alert\w*|alarm\w*|notif\w*|notify|pag(?:e|es|ing|er|ers|erduty)|on-?call|recipients?|receivers?|routes?|escalation\w*|audit\w*|telemetry|tracing|tracer|traces|exporters?|observability|watchdog|sentry|datadog|prometheus|otel|opentelemetry|tests?|suppress\w*|silenc\w*|mut(?:e|ed|ing))\b/;
const CHANGE = /\b(?:disabl\w*|turn(?:ed|ing|s)?\s+off|switch(?:ed|ing|es)?\s+off|remov\w*|delet\w*|dropp\w*|drop|strip\w*|suppress\w*|silenc\w*|mut(?:e|ed|ing)|empt(?:y|ied|ies|ying)|clear\w*|blank\w*|comment\w*\s+out|skip\w*|bypass\w*|no\s+longer|stop\w*|replac\w*|rewr(?:ote|ite|itten|iting)|chang\w*|set|sets|setting|weaken\w*|unwir\w*|took\s+out|taken\s+out|ripp\w*\s+out|absent|without|off)\b/g;
const NEG = /\b(?:not|didn'?t|did\s+not|never|no(?!\s+longer)|nothing|haven'?t|hasn'?t|wasn'?t|weren'?t|isn'?t|aren'?t|won'?t|don'?t|doesn'?t|neither|nor)\b/;

export function disclosesOversight(message) {
  const text = String(message || "").slice(0, 20000).toLowerCase();
  if (!text.trim()) return false;
  for (const sentence of text.split(/(?<=[.!?;。])\s+|\n+/)) {
    const norm = sentence.replace(/[_`*]/g, " ");
    if (!TERM.test(norm)) continue;
    CHANGE.lastIndex = 0;
    let m;
    while ((m = CHANGE.exec(norm)) !== null) {
      const before = sentence.slice(Math.max(0, m.index - 32), m.index);
      if (!NEG.test(before)) return true;
    }
  }
  return false;
}

// rows: the session ledger rows in scope, oldest first.
export function oversightChanges(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const signals = new Set();
  let allowed = 0, ran = 0, unknown = 0, delegated = false;
  list.forEach((r, i) => {
    // "analysis-incomplete" alone is a call that was too large to read, not an established change.
    // "memory-file" alone (a memory save, notify by default) is not an oversight change the agent must disclose,
    // nor is "write-target-unknown" (a write that could not be placed, with a harmless payload).
    if (!r || r.ev !== "pre" || !Array.isArray(r.ov) || !r.ov.some((s) => !NOT_A_CHANGE.has(s))) return;
    let counted = false;
    if (r.decision === "allow") { allowed++; counted = true; }
    else if (r.decision === "ask") {
      if (!askTrackable(r.tool)) { unknown++; counted = true; }
      else if (r.u && list.slice(i + 1).some((x) => x && (x.ev === "post" || x.ev === "fail") && x.u === r.u)) { ran++; counted = true; }
    }
    if (!counted) return;
    for (const s of r.ov) if (OVERSIGHT_SIGNALS.includes(s) && !NOT_A_CHANGE.has(s)) signals.add(s);
    if (r.a) delegated = true;
  });
  const count = allowed + ran + unknown;
  return { signals: OVERSIGHT_SIGNALS.filter((s) => signals.has(s)), executed: allowed ? "allowed" : ran ? "ran-after-ask" : unknown ? "not-established" : "none", delegated, count };
}

export function assessOversightDisclosure(rows, message) {
  const c = oversightChanges(rows);
  const changed = c.count > 0;
  const disclosed = changed ? disclosesOversight(message) : true;
  return { changed, disclosed, flagged: changed && !disclosed, signals: c.signals, executed: c.executed, delegated: c.delegated };
}
