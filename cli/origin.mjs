// Where an action came from: the `origin` field on alerts and allow-trail records (Diamond Model evidence,
// victim vertex "origin of action"). Pure: no I/O, no clock.
//
// Every value says how it is known. `status` is one of
//   observed         the host's payload or MoorAI's own state says so directly;
//   inferred         MoorAI concludes it from what it saw, and something it cannot see could change it;
//   not-established  nothing on the device can tell.
// The status of each basis is fixed by ORIGIN_BASES (sanitizeOrigin re-derives kind and status from it), so
// no caller can stamp a stronger claim than the table allows. The console holds the same table and
// downgrades a sender that claims more.
//
// Content-free: enums, a keyed sub-agent type for a user-defined one (cli/subagent-type.mjs) and seq numbers.

export const ORIGIN_KINDS = Object.freeze(["agent", "approved-ask", "override", "delegated", "unknown"]);
export const ORIGIN_STATUSES = Object.freeze(["observed", "inferred", "not-established"]);
export const ORIGIN_THREADS = Object.freeze(["main", "subagent", "not-distinguishable"]);
export const ORIGIN_HOST_PROMPTS = Object.freeze(["not-shown", "unknown"]);
export const ORIGIN_PARENT_BINDINGS = Object.freeze(["exact", "inferred", "none"]);

const row = (kind, status) => Object.freeze({ kind, status });
// basis -> { kind, status }. The console's server/origin.js pins the same literal.
export const ORIGIN_BASES = Object.freeze({
  "bypass-mode": row("agent", "observed"),
  "headless": row("agent", "observed"),
  "no-moorai-ask": row("agent", "inferred"),
  "host-no-thread-id": row("agent", "inferred"),
  "subagent-id": row("delegated", "observed"),
  "policy-exception": row("override", "observed"),
  "local-exception": row("override", "inferred"),
  "break-glass": row("override", "observed"),
  "jit-elevation": row("override", "observed"),
  "guard-tty": row("override", "observed"),
  "guard-flag": row("override", "inferred"),
  "post-after-ask": row("approved-ask", "inferred"),
  "failure-after-ask": row("approved-ask", "inferred"),
  "no-execution-before-stop": row("unknown", "not-established"),
  "ask-pending": row("unknown", "not-established"),
  "ask-not-trackable": row("unknown", "not-established"),
  "unrecognised": row("unknown", "not-established")
});

const SUBAGENT_TYPE_RE = /^(?:[A-Za-z][A-Za-z0-9-]{0,63}|h2:[A-Za-z0-9:_-]{1,128})$/;
const posInt = (v) => Number.isSafeInteger(v) && v > 0;

function build(basis, { thread, hostPrompt, parentBinding, subagentType, exception, intent, resolves } = {}) {
  const b = ORIGIN_BASES[basis];
  const o = { v: 1, kind: b.kind, status: b.status, basis, thread: ORIGIN_THREADS.includes(thread) ? thread : "not-distinguishable" };
  if (ORIGIN_HOST_PROMPTS.includes(hostPrompt)) o.hostPrompt = hostPrompt;
  if (o.thread === "subagent") {
    o.parentBinding = ORIGIN_PARENT_BINDINGS.includes(parentBinding) ? parentBinding : "none";
    if (typeof subagentType === "string" && SUBAGENT_TYPE_RE.test(subagentType)) o.subagentType = subagentType;
  }
  if (o.kind === "override" && (basis === "policy-exception" || basis === "local-exception")) o.exception = basis === "policy-exception" ? "console" : "local";
  if (intent === "mismatch") o.intent = "mismatch";
  if (resolves && typeof resolves === "object" && posInt(resolves.seqFrom) && posInt(resolves.seqTo) && resolves.seqFrom <= resolves.seqTo) o.resolves = { seqFrom: resolves.seqFrom, seqTo: resolves.seqTo };
  return o;
}

// The origin of an alert or allow-trail record a hook invocation writes.
// ctx: { host, shim, agentId, agentType, permissionMode, serverMode, exception: null | "console" | "local",
//        breakGlass, jitElevation, intentMismatch, parentBinding, subagentType }
// Precedence: override, then delegated, then agent (approved-ask comes only from askOutcomeOrigin).
// `thread` is set on its own: a shim host's adapters forward no agent id, so a sub-agent's call cannot be
// told from the main agent's there; only Claude Code's payload names one.
export function originFor(ctx = {}) {
  const c = ctx && typeof ctx === "object" ? ctx : {};
  const shim = c.shim === true;
  const sub = !shim && typeof c.agentId === "string" && c.agentId !== "";
  const thread = shim ? "not-distinguishable" : sub ? "subagent" : "main";
  const bypass = !shim && c.permissionMode === "bypassPermissions";
  const hostPrompt = c.serverMode === true || bypass ? "not-shown" : "unknown";
  const extra = { thread, hostPrompt, parentBinding: c.parentBinding, subagentType: c.subagentType, intent: c.intentMismatch === true ? "mismatch" : undefined };
  let basis;
  if (c.exception === "console") basis = "policy-exception";
  else if (c.exception === "local") basis = "local-exception";
  else if (c.breakGlass === true) basis = "break-glass";
  else if (c.jitElevation === true) basis = "jit-elevation";
  else if (sub) basis = "subagent-id";
  else if (c.serverMode === true) basis = "headless";
  else if (bypass) basis = "bypass-mode";
  else if (shim) basis = "host-no-thread-id";
  else basis = "no-moorai-ask";
  return build(basis, extra);
}

// The origin on an ask-outcome record. event: "PostToolUse" | "PostToolUseFailure" | "Stop" | "SubagentStop",
// or "untracked" for an ask MoorAI cannot follow (a tool with no PostToolUse matcher, or a shim host).
export function askOutcomeOrigin({ event, thread = "main", resolves, parentBinding, subagentType } = {}) {
  const basis = event === "PostToolUse" ? "post-after-ask"
    : event === "PostToolUseFailure" ? "failure-after-ask"
    : event === "Stop" || event === "SubagentStop" ? "no-execution-before-stop"
    : "ask-not-trackable";
  return build(basis, { thread, hostPrompt: "unknown", resolves, parentBinding, subagentType });
}

// moorai-guard (the `claude -p` wrapper): a person answered MoorAI's own TTY prompt, or --decide was passed
// on the command line (by a person or a script; the guard cannot tell which).
export function guardOrigin({ interactive } = {}) {
  return build(interactive === true ? "guard-tty" : "guard-flag", { thread: "main", hostPrompt: "unknown" });
}

// Shape check before an origin goes on a record: only known keys, each in its enum; kind and status are
// taken from ORIGIN_BASES for the basis (never upgraded). → the clean origin, or undefined.
export function sanitizeOrigin(o) {
  if (!o || typeof o !== "object" || Array.isArray(o) || o.v !== 1) return undefined;
  if (typeof o.basis !== "string" || !Object.prototype.hasOwnProperty.call(ORIGIN_BASES, o.basis)) return undefined;
  if (!ORIGIN_THREADS.includes(o.thread)) return undefined;
  return build(o.basis, o);
}
