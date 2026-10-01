// Session-level escalation — what one call cannot show, the session can.
//
// Every detector judges one tool call. Four things only show up across the calls of a session:
//
//   taint        an injection-class finding on content the agent INGESTED (a PostToolUse result: a
//                fetched page, a command's output, an MCP result, a sub-agent report; or a PreToolUse
//                Read/Bash file read) marks the session tainted for `windowMin`. An outbound action
//                inside that window — an upload, a data-carrying request, a gist, a push to a URL, an
//                MCP write, or a credential read — is the step an injection is written to cause.
//   score        a per-session risk score, decaying with a half-life: weighted findings, which alone
//                can reach at most half the threshold, plus the behaviours below. Reported once when
//                it crosses `threshold`, and attached to every alert this module posts.
//   slow exfil   many small outbound transfers to one destination whose sum crosses a total although
//                each one is too small for the per-call DLP scan to look unusual.
//   sequences    credential read -> staged (copied, redirected or written to a file, or encoded or
//                archived) -> outbound; archive -> outbound; and a mass read (`massReads` distinct
//                files) -> an upload of 4 KB or more to a destination new to the session. Each within
//                `seqSteps` calls and `windowMin` minutes.
//
// Report-only by default (policy.sessionRisk.mode "report"): alerts, no decision change. "ask" raises
// the outbound call that completes a signal from allow to ask. The hook coaches an unenrolled device.
//
// Pure and browser-safe: classification in, counts out; state in, state + verdict out. The caller
// (cli/session-state.mjs) hashes every host and path with a device key before assessSessionRisk sees it,
// so neither the state nor an alert ever holds a host, a path, a command or a byte of content — only
// keyed hashes, flags, counts and timestamps.
import { actionTargets, siteOf } from "./intent-alignment.js";

export const TAINT_THREATS = new Set([2, 3, 40, 50, 60, 70, 72, 74]); // injection, indirect, second-order, hidden text, rules-file poisoning, AI-only cloaking, metadata, self-replication
const CRED_THREATS = new Set([39, 55]);                               // secret values, credential-file access

export const SESSION_RISK_DEFAULTS = {
  mode: "report",      // "report" | "ask" | "off"
  threshold: 12,       // decayed score that posts the threshold alert (and, in "ask", raises outbound calls)
  windowMin: 30,       // taint window, sequence window, slow-exfil window
  halfLifeMin: 15,     // score half-life
  seqSteps: 10,        // a sequence's steps must fall within this many tool calls
  massReads: 30,       // distinct files read inside the window that make a "mass read"
  slowMinCalls: 5,     // small transfers to one destination inside the window ...
  slowMinBytes: 16384, // ... whose sum reaches this many bytes
  slowChunkMax: 8192,  // a transfer above this is not "small" (the per-call scan judges it)
  maxSessions: 32
};
const posNum = (v, d) => (Number.isFinite(v) && v > 0 ? v : d);

// policy.sessionRisk = { mode, threshold, windowMin, ... }. Malformed fields fall back to the default.
export function sessionRiskConfig(policy) {
  const p = policy && typeof policy.sessionRisk === "object" && policy.sessionRisk ? policy.sessionRisk : {};
  const out = { mode: ["report", "ask", "off"].includes(p.mode) ? p.mode : SESSION_RISK_DEFAULTS.mode };
  for (const k of Object.keys(SESSION_RISK_DEFAULTS)) if (k !== "mode") out[k] = posNum(p[k], SESSION_RISK_DEFAULTS[k]);
  out.maxSessions = Math.floor(out.maxSessions);
  return out;
}

// ---- per-call classification (plaintext in, booleans + raw hosts out; the caller hashes the hosts) ----

const B = "(?<![\\w.\\/-])";
const ENCODE = new RegExp(`${B}(?:base64|base32|basenc|xxd|uuencode)(?![\\w.-])|${B}openssl\\s{1,4}(?:enc|base64)\\b|${B}gpg\\b[^;&|\\n]{0,120}?\\s(?:-c|--symmetric|-e|--encrypt)(?![\\w-])|\\b(?:b64encode|btoa)\\s*\\(|\\[Convert\\]::ToBase64String`, "i");
const ARCHIVE = new RegExp(`${B}tar(?![\\w.-])[^;&|\\n]{0,200}?(?:\\s-{0,1}[a-zA-Z]*c[a-zA-Z]*(?=\\s)|\\s--create\\b)|${B}(?:zip|7z|7za|rar)\\s+(?:-[a-zA-Z0-9]+\\s+)*(?:a\\s+)?[^\\s-]|\\bCompress-Archive\\b`);
const ENV_DUMP = new RegExp(`${B}(?:env|printenv|export\\s+-p|set)\\s*>{1,2}|\\/proc\\/(?:self|\\d+)\\/environ|\\b(?:Get-ChildItem|gci|dir|ls)\\s+env:[^|;&\\n]*(?:>|\\|\\s*(?:Out-File|Set-Content))`, "i");
// The call writes a file: a copy or move, tee, install, dd, or an output redirect (not 2>&1 / >&2).
const WRITES = new RegExp(`${B}(?:cp|mv|tee|install|dd|Copy-Item|Set-Content|Out-File)\\s|(?<![0-9&>])>{1,2}(?!&)\\s*[^\\s&|;]`, "i");
// A credential FILE named by the call itself (the Read's path, the command's text). #55 also fires on a
// file whose CONTENT mentions such a path (documentation, a detector's own source), which is not an
// access to a credential.
const CRED_PATH = /(?:^|[\s"'`=\/\\~])(?:\.env(?![\w.-]*\.(?:example|sample|template)\b)(?:\.[\w-]+)?|\.aws[\/\\](?:credentials|config)|\.ssh[\/\\]id_[a-z0-9]+|\.npmrc|\.netrc|\.git-credentials|\.pgpass|\.docker[\/\\]config\.json|\.kube[\/\\]config|\/etc\/shadow)(?=$|[\s"'`;|&<>)])/i;
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);
const GIST = /(?<![\w.\/-])gh\s+gist\s+create\b/;
const PUSH_URL = /(?<![\w.\/-])git\s+push\b[^;&|\n]{0,200}?\s(?:https?|ssh|git):\/\/(?:[^@\s\/]{1,200}@)?([a-z0-9][\w.-]{0,252})/i;
const URL_RE = /\b(?:https?|wss?):\/\/(?:[^\s\/@'"]{0,200}@)?([^\s\/:'"?#`)]{1,253})(?::\d{1,5})?([^\s'"`]*)/gi;
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1)$/i;
const INLINE_DATA = /\s(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?|--json|-F|--form(?:-string)?|--post-data|--body-data|-Body)(?:=|\s+)("([^"]*)"|'([^']*)'|(\S+))/g;

// A token that looks like data rather than a word: >= 32 characters of the base64/url alphabet with
// upper case, lower case and a digit (a commit SHA has no upper case; a slug has no digits or upper
// case), or a command substitution inside the URL.
function dataToken(s) {
  for (const t of String(s).split(/[\/&=?;,]+/)) {
    const v = t.replace(/%[0-9a-f]{2}/gi, "");
    if (v.length >= 32 && /^[A-Za-z0-9+_.-]+$/.test(v) && /[A-Z]/.test(v) && /[a-z]/.test(v) && /\d/.test(v)) return true;
  }
  return false;
}
// Hosts a URL-bearing text sends data to through the URL itself (query or path), loopback excluded.
function dataUrlHosts(text, subst) {
  const hosts = new Set();
  let bytes = 0;
  for (const m of String(text || "").matchAll(URL_RE)) {
    const host = m[1].toLowerCase();
    if (LOOPBACK.test(host)) continue;
    const rest = (m[2] || "").split("#")[0];
    if (dataToken(rest) || (subst && /\$\(|`/.test(rest))) { hosts.add(siteOf(host)); bytes += rest.length; }
  }
  return { hosts: [...hosts], bytes };
}
function inlineBytes(cmd) {
  let n = 0;
  for (const m of String(cmd).matchAll(INLINE_DATA)) {
    const v = m[2] ?? m[3] ?? m[4] ?? "";
    if (!v.startsWith("@")) n += v.length;
  }
  return n;
}
const RISK_W = { Critical: 3, Blocked: 3, High: 2, Medium: 1 };

// One tool call's classes. `identity` is what the hook's behaviour log keys the call on: the command
// for a shell, the path for a Read, the URL for a WebFetch, the tool name for an MCP call. `textLen` is
// the length of what the call read or sends (a byte estimate only). Nothing returned is content except
// `hosts`, which the caller hashes before it goes anywhere.
export function classifyEvent({ event, tool, identity, textLen = 0, findings = [], stage } = {}) {
  const fs = Array.isArray(findings) ? findings.filter((f) => f && typeof f === "object") : [];
  const ids = new Set(fs.map((f) => f.threatId));
  const inbound = event === "PostToolUse" || (event !== "PostToolUse" && stage === "file");
  const taintIds = inbound ? [...ids].filter((i) => TAINT_THREATS.has(i)).sort((a, b) => a - b) : [];
  const credFile = ids.has(55) && CRED_PATH.test(String(identity || ""));
  const secret = fs.some((f) => f.threatId === 39 && !/^clipboard/.test(String(f.detectorId || "")));
  // credFile: a credential FILE was accessed (#55, or an environment dump below). secret: a secret value
  // is in what the call reads or writes. cred (the sequence class): a credential file, or a secret being
  // written to a file. writes: the call writes a file, which stages whatever credential it carries.
  const ev = { post: event === "PostToolUse", taint: taintIds.length > 0, taintIds, credFile: false, secret: false, cred: false, writes: false, encode: false, archive: false, out: false, outKind: "", hosts: [], bytes: 0, read: false, weight: 0 };
  let w = 0;
  for (const id of ids) {
    if (TAINT_THREATS.has(id) && inbound) w += 4;
    else if (CRED_THREATS.has(id)) w += 3;
    else w += Math.max(0, ...fs.filter((f) => f.threatId === id).map((f) => RISK_W[f.riskLevel] || 0));
  }
  ev.weight = Math.min(10, w);
  if (event === "PostToolUse") return ev;
  const id = String(identity || "").slice(0, 16384);
  const t = String(tool || "");
  ev.credFile = credFile;
  ev.secret = secret;
  ev.writes = WRITE_TOOLS.has(t);
  ev.cred = credFile || (secret && ev.writes);
  if (t === "Read") { ev.read = true; return ev; }
  if (t === "Bash" || t === "PowerShell") {
    ev.writes = WRITES.test(id);
    if (ENV_DUMP.test(id)) ev.credFile = true;
    ev.cred = ev.credFile || (secret && ev.writes);
    ev.encode = ENCODE.test(id);
    ev.archive = ARCHIVE.test(id);
    const up = actionTargets(t, { command: id }, []);
    const push = id.match(PUSH_URL);
    if (up && up.cls === "egress") { ev.out = true; ev.outKind = "upload"; ev.hosts = up.sites; ev.bytes = inlineBytes(id) + textLen; }
    else if (GIST.test(id)) { ev.out = true; ev.outKind = "gist"; ev.hosts = ["gist.github.com"]; ev.bytes = textLen; }
    else if (push && !LOOPBACK.test(push[1])) { ev.out = true; ev.outKind = "push"; ev.hosts = [siteOf(push[1].toLowerCase())]; ev.bytes = textLen; }
    else {
      const d = dataUrlHosts(id, true);
      if (d.hosts.length) { ev.out = true; ev.outKind = "fetch"; ev.hosts = d.hosts; ev.bytes = d.bytes; }
    }
    return ev;
  }
  if (t === "WebFetch") {
    const d = dataUrlHosts(id, false);
    if (d.hosts.length) { ev.out = true; ev.outKind = "fetch"; ev.hosts = d.hosts; ev.bytes = d.bytes; }
    return ev;
  }
  if (t.startsWith("mcp__")) {
    const a = actionTargets(t, {}, []);
    if (a && a.cls === "mcp-write") { ev.out = true; ev.outKind = "mcp"; ev.hosts = [`mcp:${(t.split("__")[1] || "").toLowerCase()}`]; ev.bytes = textLen; }
  }
  return ev;
}

// ---- the session ----

const F_CRED = 1, F_STAGE = 2, F_ARCH = 4, F_OUT = 8;
const MAX_STEPS = 32, MAX_KEYS = 256, TTL = 24 * 3600000;
const num = (v) => typeof v === "number" && Number.isFinite(v);
const obj = (v) => v && typeof v === "object" && !Array.isArray(v);
function keyMap(m) { const o = {}; if (obj(m)) for (const [k, v] of Object.entries(m)) if (num(v)) o[k] = v; return o; }
function cap(m, n) { const ks = Object.keys(m); if (ks.length > n) for (const k of ks.sort((a, b) => m[a] - m[b]).slice(0, ks.length - n)) delete m[k]; return m; }

function cleanState(state, now) {
  const out = { v: 1, sessions: {} };
  const ss = obj(state) && obj(state.sessions) ? state.sessions : {};
  for (const [k, s] of Object.entries(ss)) {
    if (!obj(s) || !num(s.last) || !num(s.n) || !Array.isArray(s.steps) || now - s.last > TTL) continue;
    out.sessions[k] = {
      last: s.last, n: s.n,
      score: num(s.score) ? s.score : 0, sf: num(s.sf) ? s.sf : 0, sb: num(s.sb) ? s.sb : 0, at: num(s.at) ? s.at : s.last,
      taintUntil: num(s.taintUntil) ? s.taintUntil : 0, taintAt: num(s.taintAt) ? s.taintAt : 0,
      taintIds: Array.isArray(s.taintIds) ? s.taintIds.filter(num).slice(0, 16) : [],
      steps: s.steps.filter((x) => Array.isArray(x) && x.length === 3 && x.every(num)).slice(-MAX_STEPS),
      reads: keyMap(s.reads), hosts: keyMap(s.hosts),
      xfer: Array.isArray(s.xfer) ? s.xfer.filter((x) => Array.isArray(x) && x.length === 3 && num(x[0]) && typeof x[1] === "string" && num(x[2])).slice(-MAX_KEYS) : [],
      alerted: keyMap(s.alerted)
    };
  }
  return out;
}

const REASONS = {
  taint: "outbound action after untrusted content in this session",
  "cred-out": "credential read then outbound transfer in this session",
  "archive-out": "archive then outbound transfer in this session",
  "mass-read-out": "mass file read then transfer to a new destination in this session",
  "slow-exfil": "many small transfers to one destination in this session",
  score: "session risk score above threshold"
};

// ev = classifyEvent(...) plus hostKeys (keyed hashes of ev.hosts) and readKey (keyed hash of a Read's
// path, or null). Returns { state, alerts: [{ kind, alert }], escalate: null | { kind, reason }, score,
// dirty }. `alert` is the content-free body the hook posts; `escalate` is set only in mode "ask" (the
// hook also honours it when it coaches).
export function assessSessionRisk(state, session, ev, now, cfg = sessionRiskConfig(null)) {
  const st = cleanState(state, now);
  const e = ev && typeof ev === "object" ? ev : {};
  const pre = !e.post;
  let s = st.sessions[session];
  if (!s) s = st.sessions[session] = { last: now, n: 0, score: 0, sf: 0, sb: 0, at: now, taintUntil: 0, taintAt: 0, taintIds: [], steps: [], reads: {}, hosts: {}, xfer: [], alerted: {} };
  const win = cfg.windowMin * 60000;
  const hostKeys = Array.isArray(e.hostKeys) ? e.hostKeys.filter((h) => typeof h === "string") : [];
  s.last = now;
  if (pre) s.n += 1;
  const n = s.n;
  let addW = num(e.weight) ? e.weight : 0;
  let add = 0;
  const hits = [];

  const tainted = s.taintUntil > now && s.taintAt <= now;
  if (e.out || e.credFile) {
    if (tainted && !e.taint) hits.push({ kind: "taint", rule: "taint", sig: { taintIds: s.taintIds, action: e.out ? e.outKind : "credential-file", minutesSinceTaint: Math.round((now - s.taintAt) / 60000) } });
  }
  if (e.out) {
    const recent = s.steps.filter((x) => x[0] < n && n - x[0] <= cfg.seqSteps && now - x[1] <= win);
    // A credential that was read and then staged: the credential step itself wrote a file (a copy, a
    // redirect, a Write of the value), or an encode/archive step follows it. A bare read followed by an
    // upload is how a developer tests an API with the key in .env; the per-call secret-egress check
    // judges a value that is actually in the upload.
    const cred = [...recent].reverse().find((x) => (x[2] & F_CRED) && recent.some((y) => y[0] >= x[0] && (y[2] & F_STAGE)));
    if (cred) hits.push({ kind: "sequence", rule: "cred-out", sig: { rule: "cred-out", staged: true, steps: n - cred[0] } });
    const arch = [...recent].reverse().find((x) => x[2] & F_ARCH);
    if (!cred && arch) hits.push({ kind: "sequence", rule: "archive-out", sig: { rule: "archive-out", staged: true, steps: n - arch[0] } });
    const fresh = hostKeys.some((h) => !(h in s.hosts));
    const reads = Object.values(s.reads).filter((t) => now - t <= win).length;
    if (!cred && !arch && fresh && e.outKind !== "mcp" && e.bytes >= 4096 && reads >= cfg.massReads) hits.push({ kind: "sequence", rule: "mass-read-out", sig: { rule: "mass-read-out", reads, steps: 0 } });
    addW += fresh ? 2 : 1;
    const b = num(e.bytes) ? Math.max(0, Math.round(e.bytes)) : 0;
    if (b > 0 && b <= cfg.slowChunkMax && hostKeys.length) {
      s.xfer.push([now, hostKeys[0], b]);
      s.xfer = s.xfer.filter((x) => now - x[0] <= win).slice(-MAX_KEYS);
      const mine = s.xfer.filter((x) => x[1] === hostKeys[0]);
      const bytes = mine.reduce((t, x) => t + x[2], 0);
      if (mine.length >= cfg.slowMinCalls && bytes >= cfg.slowMinBytes) hits.push({ kind: "slow-exfil", rule: "slow-exfil", sig: { calls: mine.length, bytes, windowMin: cfg.windowMin, thresholds: { calls: cfg.slowMinCalls, bytes: cfg.slowMinBytes, chunkMax: cfg.slowChunkMax } } });
    }
    for (const h of hostKeys) s.hosts[h] = now;
    cap(s.hosts, MAX_KEYS);
  }
  for (const h of hits) add += h.kind === "taint" ? 4 : 6;

  // The score: two decaying parts. Weak signals (sf: findings, and outbound calls — 2 to a new
  // destination, 1 otherwise) can raise it to half the threshold and no further, so a session that only
  // reads flagged content (a security repository, a page about prompt injection) or only calls APIs
  // never crosses it. Strong signals (sb: a taint hit 4, a sequence or slow exfiltration 6) supply the
  // rest.
  const decay = Math.pow(0.5, Math.max(0, now - s.at) / (cfg.halfLifeMin * 60000));
  const before = s.score;
  const r3 = (x) => Math.round(x * 1000) / 1000;
  s.sf = r3(s.sf * decay + addW);
  s.sb = r3(s.sb * decay + Math.min(add, 20));
  s.score = r3(Math.min(s.sf, cfg.threshold / 2) + s.sb);
  s.at = now;
  if (s.score >= cfg.threshold && before < cfg.threshold) hits.push({ kind: "score", rule: "score", sig: { score: s.score, threshold: cfg.threshold } });

  if (e.taint) { s.taintUntil = now + win; s.taintAt = now; s.taintIds = [...new Set([...s.taintIds, ...e.taintIds])].sort((a, b) => a - b).slice(0, 16); }
  if (e.read && typeof e.readKey === "string") { s.reads[e.readKey] = now; cap(s.reads, MAX_KEYS); }
  const flags = (e.cred ? F_CRED : 0) | (e.encode || e.archive || (e.cred && e.writes) ? F_STAGE : 0) | (e.archive ? F_ARCH : 0) | (e.out ? F_OUT : 0);
  if (pre && flags) { s.steps.push([n, now, flags]); s.steps = s.steps.slice(-MAX_STEPS); }

  const sessionRisk = { score: s.score, threshold: cfg.threshold, mode: cfg.mode };
  const alerts = [];
  for (const h of hits) {
    const akey = h.kind === "sequence" ? `seq:${h.rule}` : h.kind;
    if (akey in s.alerted) continue;
    s.alerted[akey] = now;
    alerts.push({ kind: h.kind, alert: BODY[h.kind](h, sessionRisk) });
  }
  // "ask": the outbound call that completes a signal asks. The score asks only on an outbound or
  // credential call while it is over the threshold, never on an ordinary one.
  let escalate = null;
  if (cfg.mode === "ask" && pre) {
    const order = ["taint", "sequence", "slow-exfil"];
    const h = order.map((k) => hits.find((x) => x.kind === k)).find(Boolean);
    if (h) escalate = { kind: h.kind, reason: REASONS[h.rule] || REASONS[h.kind] };
    else if ((e.out || e.credFile) && s.score >= cfg.threshold) escalate = { kind: "score", reason: REASONS.score };
  }

  const keys = Object.keys(st.sessions);
  if (keys.length > cfg.maxSessions) {
    const others = keys.filter((k) => k !== session).sort((x, y) => st.sessions[x].last - st.sessions[y].last);
    for (const k of others.slice(0, keys.length - cfg.maxSessions)) delete st.sessions[k];
  }
  return { state: st, alerts, escalate, score: s.score, dirty: true };
}

const BODY = {
  taint: (h, sr) => ({ threatId: 59, category: "Agent behavior: outbound action after untrusted content", riskLevel: "High", stage: "behavior", contentHash: "srisk:taint", signature: h.sig, sessionRisk: sr }),
  sequence: (h, sr) => ({ threatId: 59, category: "Agent behavior: exfiltration sequence", riskLevel: "High", stage: "behavior", contentHash: `srisk:seq:${h.rule}`, signature: h.sig, sessionRisk: sr }),
  "slow-exfil": (h, sr) => ({ threatId: 59, category: "Agent behavior: slow exfiltration", riskLevel: "High", stage: "behavior", contentHash: "srisk:slow", signature: h.sig, sessionRisk: sr }),
  score: (h, sr) => ({ threatId: 0, category: "Agent behavior: session risk threshold", riskLevel: "Medium", stage: "behavior", contentHash: "srisk:score", signature: h.sig, sessionRisk: sr })
};
