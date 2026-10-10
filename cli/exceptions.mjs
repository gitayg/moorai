// Time-boxed exceptions: "let threat #57 through for this one command for an hour", granted by a person.
//
// AN EXCEPTION is { id, threat | rule, pattern, expires } — narrow by construction: ONE threat id (or one
// tag rule id, "tag:<tag>" for a tag action) and a glob over the call's SUBJECT (subjectOf below: the
// absolute path for a file tool, the command for a shell call, the URL for a fetch, the tool name for an
// MCP call). `*` is the only wildcard and matches anything; everything else is literal; the whole subject
// must match. A live exception turns that threat's action into "notify" for the matching call only (the
// finding is still reported), or skips that tag rule. Nothing else is ever relaxed: a server allow-list,
// an envelope, an endpoint allow-list or a workload profile has no exception here — change the policy.
//
// WHERE EXCEPTIONS COME FROM — and the self-protection, stated plainly:
//   console  policy.exceptions in the VERIFIED org policy (signed when the org signs). Always honoured.
//   local    /etc/moorai/exceptions.json (%ProgramData%\MoorAI\exceptions.json on Windows), read ONLY
//            through readRootOwned: root-owned and not group/world-writable, or Administrators/SYSTEM-only
//            per its ACL. `moorai-allow` writes it, so it has to run as root (sudo) from an interactive
//            terminal. Honoured only when local exceptions are switched on:
//              enrolled device   the console policy says "localExceptions": "allow" — nothing else can
//              unenrolled device that policy, or "localExceptions": "allow" in the root-owned
//                                /etc/moorai/config.json
//            OFF BY DEFAULT on every device.
//   NEVER    a user-scope file (~/.moorai/…), a repo file or an environment variable. The hook runs as the
//            user, and so does the agent it governs: anything the user can write, the agent can write.
// So the agent cannot grant itself an exception by writing a file: the only writable stores it could reach
// are never read. What it would need is root — sudo's password, which it does not have, on a terminal it
// does not own (sudo's default per-terminal credential cache does not reach the agent's shell).
// THE RESIDUAL: a developer laptop with passwordless sudo (NOPASSWD), or a session where the agent's shell
// shares a cached sudo credential, lets the agent run `sudo moorai-allow` itself; the TTY check in the CLI
// is then only a speed bump (a pty is one `script` call away), and the hook's refusal of a shell call
// naming moorai-allow or the store (selfExceptionAttempt) is a string test an encoded command walks past.
// On such a machine local exceptions should stay off; the console path is unaffected.
import os from "node:os";
import { join, isAbsolute, resolve } from "node:path";
import { createHash } from "node:crypto";
import { readRootOwned } from "./hook-core.mjs";

export const EXCEPTIONS_FILE = process.platform === "win32"
  ? join(process.env.ProgramData || "C:\\ProgramData", "MoorAI", "exceptions.json")
  : "/etc/moorai/exceptions.json";
export const DEFAULT_TTL_MS = 3600 * 1000;
export const MAX_TTL_MS = 24 * 3600 * 1000;
export const MAX_EXCEPTIONS = 256;
const MIN_LITERAL = 4;
const RULE_ID = /^(?:tag:(?:read-private|read|write|network|exec)|[A-Za-z0-9._-]{1,64})$/;

export function parseDuration(s) {
  const m = /^\s*(\d{1,4})\s*(m|min|h|d)\s*$/i.exec(String(s ?? ""));
  if (!m) return NaN;
  const n = Number(m[1]), u = m[2].toLowerCase();
  return n * (u === "d" ? 86400000 : u === "h" ? 3600000 : 60000);
}

// A pattern is narrow when it is one line, at most 1024 characters, and keeps at least four literal
// characters around its wildcards — "*", "**/*" and "a*" are refused.
export function patternProblem(p) {
  if (typeof p !== "string" || !p) return "a pattern is required";
  if (p.length > 1024) return "the pattern is longer than 1024 characters";
  if (/[\r\n\0]/.test(p)) return "the pattern must be one line";
  if (p.replace(/[*\s\/\\.]/g, "").length < MIN_LITERAL) return `the pattern must keep at least ${MIN_LITERAL} literal characters`;
  return null;
}
export function globMatch(pattern, subject) {
  if (typeof pattern !== "string" || typeof subject !== "string") return false;
  const parts = pattern.split("*");
  if (parts.length === 1) return pattern === subject;
  if (!subject.startsWith(parts[0])) return false;
  let at = parts[0].length;
  for (let i = 1; i < parts.length - 1; i++) {
    const k = subject.indexOf(parts[i], at);
    if (k < 0) return false;
    at = k + parts[i].length;
  }
  const last = parts[parts.length - 1];
  return subject.length - last.length >= at && subject.endsWith(last);
}

// What an exception's pattern is matched against, per tool.
export function subjectOf({ tool = "", toolInput, cwd = "", home = os.homedir() } = {}) {
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  const abs = (p) => {
    if (typeof p !== "string" || !p) return "";
    if (p === "~" || p.startsWith("~/") || p.startsWith("~\\")) return join(home, p.slice(1));
    return isAbsolute(p) || !cwd ? p : resolve(cwd, p);
  };
  // A shell command with its whitespace runs collapsed, so a pattern written with single spaces matches.
  if (tool === "Bash" || tool === "PowerShell") return typeof ti.command === "string" ? ti.command.replace(/\s+/g, " ").trim() : "";
  if (["Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "NotebookRead"].includes(tool)) return abs(ti.file_path || ti.notebook_path);
  if (tool === "WebFetch") return typeof ti.url === "string" ? ti.url : "";
  if (tool === "Task" || tool === "Agent") return `${tool}:${typeof ti.subagent_type === "string" ? ti.subagent_type : ""}`;
  return tool;
}

const ts = (v) => (typeof v === "string" || typeof v === "number" ? new Date(v).getTime() : NaN);
// One exception, normalised, or null. local: also needs `created`, and at most MAX_TTL_MS between the two.
export function normaliseException(e, { now = Date.now(), local = false } = {}) {
  if (!e || typeof e !== "object" || Array.isArray(e)) return null;
  const threat = Number.isInteger(e.threat) && e.threat > 0 && e.threat < 1000 ? e.threat : null;
  const rule = typeof e.rule === "string" && RULE_ID.test(e.rule) ? e.rule : null;
  if ((threat === null) === (rule === null)) return null;
  if (patternProblem(e.pattern)) return null;
  const expires = ts(e.expires);
  if (!Number.isFinite(expires) || expires <= now) return null;
  if (local) {
    const created = ts(e.created);
    if (!Number.isFinite(created) || created > now + 60000 || expires - created > MAX_TTL_MS) return null;
  }
  const id = typeof e.id === "string" && /^[A-Za-z0-9._-]{1,64}$/.test(e.id) ? e.id : `ex-${createHash("sha256").update(`${threat}|${rule}|${e.pattern}|${expires}`).digest("hex").slice(0, 10)}`;
  return { id, ...(threat !== null ? { threat } : { rule }), pattern: e.pattern, expires, source: local ? "local" : "console" };
}

export function readExceptionStore(read = readRootOwned, path = EXCEPTIONS_FILE) {
  try { const v = JSON.parse(read(path) || "null"); return v && typeof v === "object" && Array.isArray(v.exceptions) ? v : null; } catch { return null; }
}

export function localExceptionsAllowed({ enrolled = false, policy = null, system = null } = {}) {
  if (policy && policy.localExceptions === "allow") return true;
  return !enrolled && Boolean(system && system.localExceptions === "allow");
}

// Every live exception from the console policy and, when switched on, the root-owned local store.
// ignoredLocal: ids of live local exceptions present but not honoured (local exceptions are off).
export function liveExceptions({ policy = null, system = null, store = null, enrolled = false, now = Date.now() } = {}) {
  const live = [], ignoredLocal = [];
  const con = policy && Array.isArray(policy.exceptions) ? policy.exceptions : [];
  for (const e of con.slice(0, MAX_EXCEPTIONS)) { const n = normaliseException(e, { now }); if (n) live.push(n); }
  const allowed = localExceptionsAllowed({ enrolled, policy, system });
  const loc = store && Array.isArray(store.exceptions) ? store.exceptions : [];
  for (const e of loc.slice(0, MAX_EXCEPTIONS)) {
    const n = normaliseException(e, { now, local: true });
    if (!n) continue;
    if (allowed) live.push(n); else ignoredLocal.push(n.id);
  }
  return { live, ignoredLocal, localAllowed: allowed };
}

// The exceptions that cover one call. Returns { threats: Set, rules: Set, matched: [exception] }.
export function matchExceptions(live, subject) {
  const threats = new Set(), rules = new Set(), matched = [];
  if (!subject) return { threats, rules, matched };
  for (const e of live || []) {
    if (!globMatch(e.pattern, subject)) continue;
    matched.push(e);
    if (e.threat) threats.add(e.threat); else rules.add(e.rule);
  }
  return { threats, rules, matched };
}

// The policy one call is decided under: each excepted threat resolves to "notify" (reported, allowed).
// A new object — the verified policy itself is never touched.
export function applyExceptions(policy, threats) {
  if (!threats || !threats.size) return policy;
  const base = policy && typeof policy === "object" ? policy : {};
  const tp = { ...(base.threatPolicy || {}) };
  for (const id of threats) tp[id] = "notify";
  return { ...base, threatPolicy: tp };
}

// ---- the deny / ask message: the exact exception a person can grant ----

// A pattern for this call that names no secret. File tools: the absolute path. A URL: scheme, host and
// path with `*` for the query. An MCP tool or a delegation: its name. A shell command: the command with
// every token that could be a credential (long opaque runs, quoted strings, values after "=", header and
// auth arguments) replaced by `*`, cut at its first line and at 160 characters.
const OPAQUE = /[A-Za-z0-9+\/_=-]{16,}/;
const SECRET_FLAG = /^(?:-H|--header|-u|--user|--password|--pass|--token|--auth|--oauth2-bearer|-p|--cookie|-b|--data|-d|--data-raw|--data-binary|--data-urlencode|-F|--form|--json|--body|-Body|-Headers|-Credential)$/i;
export function suggestPattern({ tool = "", toolInput, cwd = "", home = os.homedir() } = {}) {
  const subject = subjectOf({ tool, toolInput, cwd, home });
  if (!subject) return "";
  if (tool === "WebFetch") {
    try { const u = new URL(subject); return `${u.protocol}//${u.host}${u.pathname}${u.search || u.hash ? "*" : ""}`; } catch { return ""; }
  }
  if (tool !== "Bash" && tool !== "PowerShell") return subject.length > 1024 ? "" : subject;
  const raw = toolInput && typeof toolInput.command === "string" ? toolInput.command.trim() : subject;
  let cut = false;
  const line = raw.split(/\r?\n/)[0];
  if (line !== raw) cut = true;
  const out = [];
  let star = false, quote = "";
  for (const tok of line.split(/\s+/).filter(Boolean)) {
    let t = tok;
    if (quote) { t = "*"; if (tok.endsWith(quote)) quote = ""; }
    else if (star) { t = "*"; star = false; const q = /^["'`]/.exec(tok); if (q && (tok.length === 1 || !tok.endsWith(q[0]))) quote = q[0]; }
    else if (/^["'`]/.test(t)) { const q = t[0]; if (t.length === 1 || !t.endsWith(q)) quote = q; t = "*"; }
    else if (/["'`$]/.test(t)) { const q = /["'`]/.exec(t); if (q && (t.split(q[0]).length - 1) % 2 === 1) quote = q[0]; t = "*"; }
    else if (SECRET_FLAG.test(t)) star = true;
    else if (/^-(?:p|u|H|b)\S/.test(t)) t = "*";
    else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
      try { const u = new URL(t); t = `${u.protocol}//${u.host}${OPAQUE.test(u.pathname) ? "/*" : u.pathname}${u.search || u.hash ? "*" : ""}`; } catch { t = "*"; }
    }
    else if (/^-{0,2}[^=]+=/.test(t)) t = t.replace(/=.*$/, "=*");
    else if (OPAQUE.test(t)) t = "*";
    if (t === "*" && out[out.length - 1] === "*") continue;
    out.push(t);
  }
  let p = out.join(" ");
  if (p.length > 160) { p = p.slice(0, 160).replace(/\s+\S*$/, ""); cut = true; }
  if (cut && !p.endsWith("*")) p += " *";
  return patternProblem(p) ? "" : p;
}
const shq = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;

// The line appended to a deny / ask. threats: the threat ids that drove it; rules: the tag rule ids.
// Empty when there is nothing an exception could grant (the decision came from a non-threat gate) or no
// narrow pattern can be written for the call.
export function exceptionHint({ threats = [], rules = [], tool = "", toolInput, cwd = "", home = os.homedir(), enrolled = false, localAllowed = false, cli = "", platform = process.platform } = {}) {
  const ids = [...new Set(threats)].filter((n) => Number.isInteger(n) && n > 0), rs = [...new Set(rules)];
  if (!ids.length && !rs.length) return "";
  const pattern = suggestPattern({ tool, toolInput, cwd, home });
  if (!pattern) return "";
  const what = [...ids.map((n) => `--threat ${n}`), ...rs.map((r) => `--rule ${r}`)].join(" ");
  const named = [...ids.map((n) => `threat #${n}`), ...rs.map((r) => `rule ${r}`)].join(", ");
  if (localAllowed && cli) {
    const cmd = `node ${JSON.stringify(cli)} ${what} --pattern ${shq(pattern)} --for 1h`;
    const run = platform === "win32" ? `from an elevated (Administrator) terminal: ${cmd}` : `sudo ${cmd}`;
    return `Exception: a person who has reviewed this call can allow it for an hour by running, in their own terminal (not through the agent), ${run}`;
  }
  if (enrolled) return `Exception: ask your MoorAI administrator for a console exception (Policy > Exceptions): ${named}, pattern ${shq(pattern)}, for 1h. Local exceptions are off on this device.`;
  return `Exception: local exceptions are off on this device. An administrator can enable them ("localExceptions": "allow" in the root-owned machine config), then run sudo ${cli ? `node ${JSON.stringify(cli)}` : "moorai-allow"} ${what} --pattern ${shq(pattern)} --for 1h`;
}

// The agent trying to grant its own exception: a shell call that runs moorai-allow or names the store,
// or a write to the store. A string test (an encoded command walks past it) — the real boundary is the
// root-owned store; this only makes the attempt visible and refused.
const SELF_GRANT = /\bmoorai[-_ ]allow\b|[\/\\]etc[\/\\]moorai[\/\\]exceptions\.json\b|MoorAI[\/\\]+exceptions\.json\b/i;
export function selfExceptionAttempt({ tool = "", toolInput } = {}) {
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  if (tool === "Bash" || tool === "PowerShell") return typeof ti.command === "string" && SELF_GRANT.test(ti.command);
  if (["Write", "Edit", "MultiEdit", "NotebookEdit"].includes(tool)) return typeof (ti.file_path || ti.notebook_path) === "string" && SELF_GRANT.test(ti.file_path || ti.notebook_path);
  return false;
}

// ---- the store, for the CLI (pure) ----
export function addExceptions(doc, entries) {
  const prev = doc && Array.isArray(doc.exceptions) ? doc.exceptions : [];
  const now = Date.now();
  const kept = prev.filter((e) => normaliseException(e, { now, local: true }));
  return { version: 1, exceptions: [...kept, ...entries].slice(-MAX_EXCEPTIONS) };
}
export function revokeException(doc, id) {
  const prev = doc && Array.isArray(doc.exceptions) ? doc.exceptions : [];
  return { version: 1, exceptions: prev.filter((e) => e && e.id !== id) };
}
