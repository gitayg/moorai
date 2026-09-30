// Intent alignment — pure part. Does a risky agent action fit the task the user gave in this session?
//
// Two halves, joined only through a keyed hash the caller supplies (cli/intent-alignment.mjs):
//   taskFeatures(prompt)          — what the user's request MENTIONS: sites, paths, known service names,
//                                   and a fixed three-word label set. Plaintext, in memory only; the
//                                   caller hashes every feature before anything is written.
//   actionTargets(tool, input, …) — whether a tool call is RISKY (egress / credentials / destructive /
//                                   mcp-write) and, if so, what it targets.
//   assessAlignment(task, action) — aligned iff the targets were mentioned (or, for the non-egress
//                                   classes, the task carries the matching label).
//
// Deliberately lexical. It answers "did the user ever name this destination / file / service", not
// "does this action serve the task". An upload to a host the user named is aligned even when it is
// exfiltration to that host, and a request pasted from an untrusted source puts its hosts in scope.
// Browser-safe (no node: imports), like data/enforcement.js.

// A dotted token: a hostname, an email's domain, or a filename. Both readings are kept as features —
// an extra feature can only make an action look aligned, never flag one.
const DOTTED = /(?<![\w@-])(?:[a-z][a-z0-9+.-]{0,15}:\/\/)?(?:[^\s\/@'"`<>()]{1,64}@)?((?:[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]{0,62})(?![\w-])/gi;
// `\` separates too, so a Windows path a user types ("clean C:\repo\build") yields features the
// PowerShell tool's Remove-Item operands can match.
const PATHISH = /(?:^|[\s"'`(=:@])((?:~|\.{1,2})?[\\/]?(?:[\w.@+-]+[\\/])+[\w.@+-]*|\.[\w][\w.-]*|[\w-]+\.[a-z0-9]{1,8})(?=$|[\s"'`),;:])/gi;

// Service names worth recognising in prose (they are also common MCP server names). A fixed vocabulary:
// hashing an arbitrary word of the prompt would amount to storing a hashed bag of words.
export const SERVICE_NAMES = new Set([
  "github", "gitlab", "bitbucket", "slack", "discord", "teams", "linear", "jira", "confluence", "notion",
  "asana", "trello", "sentry", "datadog", "pagerduty", "stripe", "vercel", "netlify", "heroku", "supabase",
  "firebase", "aws", "s3", "gcp", "gcs", "azure", "cloudflare", "figma", "gmail", "google", "drive",
  "calendar", "dropbox", "box", "salesforce", "hubspot", "zendesk", "intercom", "twilio", "sendgrid",
  "postgres", "mysql", "mongodb", "redis", "snowflake", "bigquery", "airtable", "docker", "kubernetes",
  "npm", "pypi", "huggingface", "openai", "anthropic", "email", "sheets", "docs", "filesystem", "browser"
]);

// The three label classes a task can carry. Egress deliberately has no label: an exfiltration
// destination is exactly the host the user never named, and "upload the build" does not name one.
const LABEL_RULES = {
  credentials: /\b(?:credential|secret|token|api[ _-]?keys?|passw(?:or)?d|\.env\b|env(?:ironment)? var|ssh[ -]?keys?|kube ?config|keychain|vault|certificate)/i,
  // Whole word forms, not stems: measured, the stem "clear" matched "clearer" and put a whole
  // session's rm -rf in scope.
  destructive: /\b(?:delet(?:e|es|ed|ing|ion)|remov(?:e|es|ed|ing|al)|clean(?:s|ed|ing|up)?|clear(?:s|ed|ing)?|reset(?:s|ting)?|wip(?:e|es|ed|ing)|drop(?:s|ped|ping)?|prun(?:e|es|ed|ing)|purg(?:e|es|ed|ing)|uninstall\w*|revert\w*|discard\w*|nuk(?:e|es|ed|ing)|truncat\w*|overwrit\w*|force[ -]push\w*)\b|\brm -/i,
  "mcp-write": /\b(?:send|post|publish|share|notify|email|message|comment|reply|tweet|open (?:a |an )?(?:pr|pull request|issue|ticket)|file (?:a |an )?(?:bug|issue|ticket)|create (?:a |an )?(?:pr|pull request|issue|ticket|page|doc|event)|merge|invite|schedule)/i
};
export const LABELS = Object.keys(LABEL_RULES);

const SLD = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "ne", "or", "go", "gv"]);
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// Registrable-domain approximation (no public-suffix list): last two labels, or three under a
// two-letter country code with a generic second level (example.co.uk).
export function siteOf(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  if (!h || IPV4.test(h) || h.startsWith("[")) return h;
  const l = h.split(".");
  if (l.length <= 2) return h;
  const n = l.length;
  return SLD.has(l[n - 2]) && l[n - 1].length === 2 ? l.slice(-3).join(".") : l.slice(-2).join(".");
}

const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1)$/i;
const basename = (p) => String(p).replace(/[\\/]+$/, "").split(/[\\/]/).pop();
const normPath = (p) => String(p).replace(/^\.\//, "").replace(/[\\/]+$/, "");

export function taskFeatures(prompt) {
  const text = String(prompt || "").slice(0, 20000);
  const sites = new Set(), paths = new Set(), names = new Set(), labels = new Set();
  for (const m of text.matchAll(DOTTED)) { sites.add(siteOf(m[1])); paths.add(m[1]); }
  for (const m of text.matchAll(PATHISH)) {
    const p = normPath(m[1]);
    if (!p || /^[a-z][a-z0-9+.-]*:$/i.test(p)) continue;
    paths.add(p);
    const b = basename(p);
    if (b) paths.add(b);
  }
  for (const w of text.toLowerCase().match(/[a-z0-9]+/g) || []) if (SERVICE_NAMES.has(w)) names.add(w);
  for (const [l, re] of Object.entries(LABEL_RULES)) if (re.test(text)) labels.add(l);
  return { sites: [...sites], paths: [...paths], names: [...names], labels: [...labels] };
}

// ---- action side ----

// A copy or move whose operand is \\host\share. The host class excludes \\?\ and \\.\ (local device
// paths) and \\wsl$; localhost / wsl.localhost are dropped with the loopback hosts below.
const UNC_COPY = /\b(?:Copy-Item|cpi|copy|cp|Move-Item|mi|move|mv|robocopy|xcopy)\b[^\n;|&]*?[\s:]["']?\\\\[a-z0-9][\w.-]{0,252}\\/i;
const UNC_HOST = /(?:^|[\s:"'])\\\\([a-z0-9][\w.-]{0,252})\\/gi;
// A payload leaving the device. Same shape family as cli/hook-core.mjs OUTBOUND_UPLOAD (clipboard
// session rule), restricted to the forms that carry an explicit destination this module can read.
const UPLOAD = [
  /\bcurl\b[^\n;|&]*?(?:\s-(?:[a-zA-Z]*d|F|T)\b|\s--(?:data(?:-binary|-raw|-urlencode|-ascii)?|form|upload-file|json)\b|\s-X\s*(?:POST|PUT|PATCH)\b|\s--request\s+(?:POST|PUT|PATCH)\b)/i,
  /\bwget\b[^\n;|&]*?--(?:post-data|post-file|body-data|body-file|method=(?:POST|PUT))/i,
  /\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b[^\n;|&]*?(?:-Method\s+(?:Post|Put|Patch)|-InFile|-Body)\b/i,
  /\b(?:nc|ncat|netcat|socat|telnet)\b/i,
  /\b(?:scp|rsync|sftp)\b[^\n;|&]*?\s[\w.-]+@?[\w.-]+:/i,
  // PowerShell: BITS in upload mode, and a copy/move onto a UNC share (SMB egress). Same shapes as
  // cli/hook-core.mjs PS_OUTBOUND_UPLOAD.
  /\bStart-BitsTransfer\b[^\n;|&]*?\s-TransferType\s{1,4}["']?Upload/i,
  UNC_COPY
];
const URL_HOST = /\b(?:https?|ftp|wss?):\/\/(?:[^\s\/@'"]{0,200}@)?(\[[0-9a-f:]{2,39}\]|[^\s\/:'"?#`)]{1,253})/gi;
const NC_HOST = /\b(?:nc|ncat|netcat|telnet)\b(?:\s+-{1,2}[\w-]+(?:\s+\d+)?)*\s+([a-z0-9][\w.-]*\.[a-z][\w-]*|\d{1,3}(?:\.\d{1,3}){3})\b/gi;
const REMOTE_COPY = /(?:^|\s)(?:[\w.-]+@)?([a-z0-9][\w-]*(?:\.[\w-]+)+):/gi;
const SOCAT_HOST = /\btcp[46]?:([a-z0-9][\w.-]+):\d+/gi;

function egressHosts(command) {
  const c = String(command || "");
  const hosts = new Set();
  for (const re of [URL_HOST, NC_HOST, SOCAT_HOST]) for (const m of c.matchAll(re)) hosts.add(m[1].toLowerCase());
  if (/\b(?:scp|rsync|sftp)\b/i.test(c)) for (const m of c.matchAll(REMOTE_COPY)) hosts.add(m[1].toLowerCase());
  if (UNC_COPY.test(c)) for (const m of c.matchAll(UNC_HOST)) hosts.add(m[1].toLowerCase());
  return [...hosts].filter((h) => !LOOPBACK.test(h) && h !== "wsl.localhost");
}

const MCP_WRITE = /(?:^|[_-])(?:create|update|delete|remove|send|post|write|push|publish|upload|comment|merge|add|edit|put|set|insert|close|reply|share|invite|move|rename|archive|transfer|execute|run|deploy|submit|patch)(?:[_-]|$)/i;

// Operands of a destructive command that look like paths (contain a slash or a dot, or are a bare
// word following rm/rmdir/shred). Flags and the command word itself are skipped.
function commandPaths(command) {
  const out = new Set();
  for (const tok of String(command || "").split(/[\s;|&()]+/)) {
    const t = tok.replace(/^['"@]+|['"]+$/g, "");
    if (!t || t.startsWith("-") || /^[a-z][a-z0-9+.-]*:\/\//i.test(t) || /[$`*?]/.test(t)) continue;
    if (/[\\/]/.test(t) || /\.\w/.test(t) || t.startsWith("~")) out.add(normPath(t));
  }
  return [...out];
}

// The ONE class an action is judged under, highest first. An upload that also reads a credential file
// is judged by where it goes: the destination is the question the task can answer.
export function actionTargets(tool, input, findings) {
  const ti = input || {};
  const ids = new Set((findings || []).map((f) => f && f.threatId));
  if (tool === "Bash" || tool === "PowerShell") {
    const cmd = String(ti.command || "");
    if (UPLOAD.some((r) => r.test(cmd))) {
      const sites = [...new Set(egressHosts(cmd).map(siteOf))];
      if (sites.length) return { cls: "egress", sites, paths: [], names: [] };
    }
    if (ids.has(43)) return { cls: "destructive", sites: [], paths: commandPaths(cmd), names: [] };
    if (ids.has(55)) return { cls: "credentials", sites: [], paths: commandPaths(cmd), names: [] };
    return null;
  }
  if (tool === "Read") {
    if (!ids.has(55)) return null;
    const p = String(ti.file_path || "");
    return { cls: "credentials", sites: [], paths: p ? [normPath(p)] : [], names: [] };
  }
  if (typeof tool === "string" && tool.startsWith("mcp__")) {
    const [, server = "", name = ""] = tool.split("__");
    if (!MCP_WRITE.test(name)) return null;
    const words = server.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    return { cls: "mcp-write", sites: [], paths: [], names: [server.toLowerCase(), ...words] };
  }
  return null;
}

// Every feature is compared as h(`${kind}:${value}`) against the task's hashed set.
export function featureKeys(features, h) {
  const out = [];
  for (const s of features.sites || []) out.push(h(`site:${s}`));
  for (const p of features.paths || []) out.push(h(`path:${String(p).toLowerCase()}`));
  for (const n of features.names || []) out.push(h(`name:${n}`));
  for (const l of features.labels || []) out.push(h(`label:${l}`));
  return out;
}

export function assessAlignment(task, action, h) {
  const has = (k) => task.has(h(k));
  if (action.cls === "egress") {
    const unmatched = action.sites.filter((s) => !has(`site:${s}`));
    return { aligned: unmatched.length === 0, unmatched: unmatched.length, targets: action.sites.length };
  }
  const label = has(`label:${action.cls}`);
  const hit = action.paths.some((p) => has(`path:${p.toLowerCase()}`) || has(`path:${basename(p).toLowerCase()}`))
    || action.names.some((n) => has(`name:${n}`));
  const targets = action.paths.length + action.names.length;
  return { aligned: label || hit, unmatched: label || hit ? 0 : targets, targets };
}
