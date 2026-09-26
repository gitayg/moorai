// Cumulative destructive volume — many small deletes that no single call gives away.
//
// The destructive-command detector (#43) judges one command at a time. An agent that empties a tree
// with forty `rm a b c` calls, or runs `rm -rf` five times in ten minutes, never looks worse on any one
// call than routine cleanup. This module sums deletions across the calls of one session and reports
// when the session crosses a volume threshold inside a sliding time window.
//
// What counts, per command segment (split on ; && || | & and newlines):
//   * a delete verb — rm, rmdir, unlink, Remove-Item/ri, del, erase, rd, `xargs rm`, `find ... -delete`
//     or `find ... -exec rm` — adds its operands (each non-option argument), or 1 when the operands are
//     not on the command line (find, xargs);
//   * `git clean` with a force flag and without a dry-run flag adds its pathspecs, or 1;
//   * any other #43 pattern (git reset --hard, DROP TABLE, TRUNCATE TABLE, mkfs, ...) adds 1.
// A segment is RECURSIVE when it is a delete verb and matches the shared RECURSIVE_FORCE_DELETE list —
// the same list #43 and #32 use, so this counter and the per-call detector cannot disagree about what
// a recursive delete is.
//
// Pure: command in, counts out; state in, state + verdict out. Counts and timestamps only — no path,
// operand or command text is ever returned or stored. The state file I/O lives in cli/drift-state.mjs.
import { RECURSIVE_FORCE_DELETE, DETECTORS } from "./detectors.js";

const DESTRUCTIVE_43 = (DETECTORS.find((d) => d.threatId === 43)?.patterns || [])
  .filter((re) => !RECURSIVE_FORCE_DELETE.includes(re));
const DELETE_VERBS = new Set(["rm", "rmdir", "unlink", "remove-item", "ri", "del", "erase", "rd"]);
const PREFIX_WORDS = new Set(["sudo", "doas", "command", "builtin", "exec", "nohup", "time", "nice", "env"]);
const QUOTE_ONLY = new Set(["echo", "printf", "print", "write-host", "write-output"]);
const PS_VALUED = new Set(["-filter", "-include", "-exclude", "-erroraction", "-ea", "-credential", "-stream"]);

function tokens(seg) { return seg.match(/"[^"]*"|'[^']*'|\S+/g) || []; }
const base = (t) => String(t).replace(/^["'(){}]+|["']+$/g, "").split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, "");

// Index of the command word in a segment: skip `sudo -u x`, `env A=b`, `nohup`, bare assignments.
function verbAt(toks) {
  let i = 0;
  while (i < toks.length) {
    const t = toks[i].replace(/^[({]+/, "");
    if (!t) { i++; continue; }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i++; continue; }
    const b = base(t);
    if (PREFIX_WORDS.has(b)) { i++; while (i < toks.length && toks[i].startsWith("-")) i += /^-[ugCcp]$/.test(toks[i]) ? 2 : 1; continue; }
    return i;
  }
  return -1;
}

function countOperands(args) {
  let n = 0, endOpts = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!endOpts && a === "--") { endOpts = true; continue; }
    if (!endOpts && PS_VALUED.has(a.toLowerCase())) { i++; continue; }
    if (!endOpts && (a.startsWith("-") || /^\/[a-z?]$/i.test(a))) continue; // POSIX / PowerShell / cmd switches
    if (/^[<>|&]|^\d?>/.test(a)) break;                                     // a redirect ends the operands
    n++;
  }
  return n;
}

// Protect `-exec rm {} \;` (and `';'`) from the segment splitter: the find patterns deliberately span it.
const splitSegments = (cmd) => cmd.replace(/\\;|';'|";"/g, " \u0000 ").split(/\r?\n|;|&&|\|\||\||&/);

export function deletionTally(command) {
  const cmd = String(command || "").slice(0, 16384);
  const out = { ops: 0, rec: 0, cmds: 0 };
  if (!cmd) return out;
  for (const raw of splitSegments(cmd)) {
    const seg = raw.replace(/\u0000/g, "\\;").trim();
    if (!seg) continue;
    const toks = tokens(seg);
    const vi = verbAt(toks);
    if (vi < 0) continue;
    let verb = base(toks[vi]), args = toks.slice(vi + 1), ops = 0, deleteVerb = false;
    if (verb === "xargs") {
      const j = args.findIndex((a) => !a.startsWith("-"));
      if (j >= 0 && DELETE_VERBS.has(base(args[j]))) { deleteVerb = true; ops = 1; }
    } else if (verb === "find") {
      if (/\s-delete(?![\w-])|\s-exec(?:dir)?\s{1,4}(?:sudo\s{1,4})?rm\b/i.test(seg)) { deleteVerb = true; ops = 1; }
    } else if (DELETE_VERBS.has(verb)) {
      deleteVerb = true; ops = countOperands(args);
    } else if (verb === "git") {
      let k = 0;
      while (k < args.length && args[k].startsWith("-")) k += /^-[Cc]$/.test(args[k]) ? 2 : 1;
      if (base(args[k] || "") === "clean") {
        const rest = args.slice(k + 1);
        const force = rest.some((a) => a === "--force" || /^-[a-zA-Z]*f[a-zA-Z]*$/.test(a));
        const dry = rest.some((a) => a === "--dry-run" || a === "--interactive" || /^-[a-zA-Z]*[ni][a-zA-Z]*$/.test(a));
        const paths = rest.filter((a, i) => !/^-[eE]$/.test(a) && !/^-[eE]$/.test(rest[i - 1] || ""));
        if (force && !dry) ops = Math.max(1, countOperands(paths));
      }
    }
    if (!deleteVerb && !ops && !QUOTE_ONLY.has(verb) && DESTRUCTIVE_43.some((re) => re.test(seg))) ops = 1;
    if (!ops) continue;
    out.ops += ops;
    out.cmds += 1;
    if (deleteVerb && RECURSIVE_FORCE_DELETE.some((re) => re.test(seg))) out.rec += 1;
  }
  return out;
}

export const DELETION_DEFAULTS = {
  mode: "ask",       // "ask" (alert + ask on the next deletion after the threshold) | "alert" | "off"
  operands: 25,      // deletion operands inside the window ...
  recursive: 5,      // ... or recursive deletes inside the window
  windowMin: 15,
  maxSessions: 32
};
const posInt = (v, d) => (Number.isFinite(v) && v >= 1 ? Math.floor(v) : d);

// policy.deletionVolume = { mode, operands, recursive, windowMin }.
export function deletionConfig(policy) {
  const p = policy && typeof policy.deletionVolume === "object" && policy.deletionVolume ? policy.deletionVolume : {};
  return {
    mode: ["ask", "alert", "off"].includes(p.mode) ? p.mode : DELETION_DEFAULTS.mode,
    operands: posInt(p.operands, DELETION_DEFAULTS.operands),
    recursive: posInt(p.recursive, DELETION_DEFAULTS.recursive),
    windowMin: posInt(p.windowMin, DELETION_DEFAULTS.windowMin),
    maxSessions: posInt(p.maxSessions, DELETION_DEFAULTS.maxSessions)
  };
}

const WIN_CAP = 256;
function cleanSessions(state) {
  const out = { v: 1, sessions: {} };
  const ss = state && typeof state === "object" && state.sessions && typeof state.sessions === "object" && !Array.isArray(state.sessions) ? state.sessions : {};
  for (const [k, s] of Object.entries(ss)) {
    if (!s || typeof s !== "object" || !Array.isArray(s.win) || typeof s.last !== "number") continue;
    const win = s.win.filter((w) => Array.isArray(w) && w.length === 3 && w.every((x) => typeof x === "number" && Number.isFinite(x)));
    out.sessions[k] = { last: s.last, alerted: s.alerted === true, armed: s.armed === true, win };
  }
  return out;
}

// One Bash call's tally against the session's window. A call with no deletion changes nothing.
//   escalate — this call is the first deletion after the session crossed the threshold (mode "ask"):
//              the caller raises allow -> ask. Consuming it clears the window, so the next ask needs
//              another full threshold's worth of deletions.
//   alert    — the session crossed the threshold for the first time: the window totals to report.
export function assessDeletionVolume(state, session, tally, now, cfg = deletionConfig(null)) {
  const s0 = cleanSessions(state);
  if (!tally || !tally.cmds) return { state: s0, alert: null, escalate: false, dirty: false };
  let s = s0.sessions[session];
  if (!s) s = s0.sessions[session] = { last: now, alerted: false, armed: false, win: [] };
  s.last = now;
  const from = now - cfg.windowMin * 60000;
  s.win = s.win.filter((w) => w[0] >= from);
  let escalate = false;
  if (s.armed) { escalate = cfg.mode === "ask"; s.armed = false; s.win = []; }
  s.win.push([now, tally.ops, tally.rec]);
  if (s.win.length > WIN_CAP) s.win = s.win.slice(-WIN_CAP);
  const totals = s.win.reduce((t, w) => ({ operands: t.operands + w[1], recursive: t.recursive + w[2], calls: t.calls + 1 }), { operands: 0, recursive: 0, calls: 0 });
  let alert = null;
  if (totals.operands >= cfg.operands || totals.recursive >= cfg.recursive) {
    if (!s.alerted) { s.alerted = true; alert = totals; }
    if (cfg.mode === "ask") s.armed = true;
  }
  const keys = Object.keys(s0.sessions);
  if (keys.length > cfg.maxSessions) {
    const others = keys.filter((k) => k !== session).sort((x, y) => s0.sessions[x].last - s0.sessions[y].last);
    for (const k of others.slice(0, keys.length - cfg.maxSessions)) delete s0.sessions[k];
  }
  return { state: s0, alert, escalate, dirty: true, totals };
}
