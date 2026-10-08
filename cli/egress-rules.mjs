// Egress rules: which binary may reach which destination, port, HTTP method and path — the per-binary
// network policy of a sandbox, judged here at the point MoorAI already judges a call (a shell command, a
// WebFetch, an MCP tool call), from the call's text.
//
// POLICY SHAPE. In the verified console policy, in the root-owned machine-wide config, and inside a
// declared workload profile (cli/workload-profile.mjs), which is where they compose:
//   egressRules:   [{ id?, binary?, host, port?, method?, path?, action: "allow"|"alert"|"block" }]
//   egressDefault: "allow" | "alert" | "block"
//   * host     exact name, or `*.suffix` (any name strictly under suffix). Nothing else: no `*`, no URL.
//   * binary   the command word (`curl`, `/usr/bin/curl`, `curl.exe` → curl), or for a non-shell call the
//              tool name (`WebFetch`, `mcp__fetch__get`). One name or a list; `*` is a glob. Case-blind.
//   * port     an integer or a list. method: one verb or a list (case-blind). path: `/exact` or `/prefix*`.
//   * A rule matches when every key it sets matches. Rules are read in order — the matched profile's,
//     then the console policy's, then the machine-wide config's — and the first match decides. No match
//     → egressDefault (the profile's, else the policy's, else the machine-wide config's, else "allow").
//     Loopback with no matching rule is allowed whatever the default.
//
// UNKNOWN FIELDS. A destination is often only partly known: `ssh host` has no path, `git clone https://…`
// has no method, a URL inside a heredoc has no binary. An `allow` rule that constrains a field the
// destination does not know does NOT match it; an `alert` or `block` rule DOES. Not knowing never widens
// what is allowed.
//
// BINARY ATTRIBUTION. A URL is attributed to the command word of the shell segment it is written in
// (after `sudo`, `env`, `xargs`, `timeout`, … and through `sh -c` / `powershell -Command` / `-EncodedCommand`
// / `$( … )`). That is the program the command line NAMES, not the process that opens the socket. So an
// `allow` rule needs the URL's own segment to name the binary, while an `alert` or `block` rule's binary
// matches when ANY command word in the call names it (`echo https://x | xargs curl …` is curl's).
//
// Content-free: alerts carry the binary, host, port and method, never a path, query, command or argument.
// Pure. Never throws to the caller (workload-profile.mjs wraps it fail-open).

export const EGRESS_RULE = "EGRESS_RULE";
export const EGRESS_ACTIONS = Object.freeze(["allow", "alert", "block"]);
export const EGRESS_CATEGORY = "Egress rule";
const RANK = { allow: 0, alert: 1, block: 2 };
const RULE_KEYS = new Set(["id", "binary", "host", "port", "method", "path", "action", "description"]);
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const RULE_HOST_RE = /^(\*\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)*)$/;
const IPV6_HOST_RE = /^\[[0-9a-f:.]+\]$/;
const BINARY_RE = /^[A-Za-z0-9_.*+:\/\\-]{1,256}$/;
const METHOD_RE = /^[A-Za-z]{1,16}$/;
const MAX_RULES = 512, MAX_LIST = 64, MAX_TARGETS = 256, MAX_HOSTS = 4096, MAX_ALERTS = 8;
const MAX_CMD = 262144, MAX_DEPTH = 3, MAX_SEGS = 256, MAX_TOKS = 256, MAX_MCP_CHARS = 1048576;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);
const BIN_ALIASES = { iwr: "invoke-webrequest", irm: "invoke-restmethod" };

// Network schemes and their default ports (null: resolved at run time, e.g. via SRV).
const SCHEME_PORTS = {
  http: 80, https: 443, ws: 80, wss: 443, ftp: 21, ftps: 990, sftp: 22, ssh: 22, scp: 22, git: 9418,
  rsync: 873, telnet: 23, ldap: 389, ldaps: 636, smtp: 25, smtps: 465, imap: 143, imaps: 993, pop3: 110,
  pop3s: 995, redis: 6379, rediss: 6379, postgres: 5432, postgresql: 5432, mysql: 3306, mariadb: 3306,
  mongodb: 27017, "mongodb+srv": null, amqp: 5672, amqps: 5671, mqtt: 1883, mqtts: 8883, nats: 4222,
  socks: 1080, socks4: 1080, socks4a: 1080, socks5: 1080, socks5h: 1080, gopher: 70, dict: 2628, tftp: 69
};
const HTTP_SCHEMES = new Set(["http", "https"]);
const URL_IN_TEXT = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,15}:\/\/[^\s"'<>`{}|^]+/g;

// ---------------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------------

export function normBinary(raw) {
  const s = String(raw || "");
  const cut = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\"));
  const w = (cut >= 0 ? s.slice(cut + 1) : s).toLowerCase().replace(/\.exe$/, "");
  return BIN_ALIASES[w] || w;
}

function asList(v) { return Array.isArray(v) ? v : [v]; }

function ruleHost(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim().toLowerCase().replace(/\.$/, "");
  if (IPV6_HOST_RE.test(s)) { try { return { exact: new URL(`http://${s}/`).hostname }; } catch { return null; } }
  const m = s.match(RULE_HOST_RE);
  if (!m) return null;
  let base;
  try { base = new URL(`http://${m[2]}/`).hostname; } catch { return null; }
  return m[1] ? { suffix: `.${base}` } : { exact: base };
}

function rulePath(raw) {
  if (typeof raw !== "string" || !raw.startsWith("/") || raw.length > 1024 || /[\s?#]/.test(raw)) return null;
  const star = raw.indexOf("*");
  if (star !== -1 && star !== raw.length - 1) return null;
  const base = star === -1 ? raw : raw.slice(0, -1);
  let norm;
  try { norm = new URL(`http://x${base}`).pathname; } catch { return null; }
  return star === -1 ? { exact: norm } : { prefix: norm };
}

function globRe(p) {
  return new RegExp(`^${p.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
}

// One rule → { rule } (normalised and compiled) or { error } (the reason; never the value).
export function validateEgressRule(r) {
  if (!r || typeof r !== "object" || Array.isArray(r)) return { error: "not an object" };
  if (Object.keys(r).some((k) => !RULE_KEYS.has(k))) return { error: "unknown key" };
  if (!EGRESS_ACTIONS.includes(r.action)) return { error: "action is not allow, alert or block" };
  if (r.id !== undefined && (typeof r.id !== "string" || !ID_RE.test(r.id))) return { error: "id is not a short slug" };
  const host = ruleHost(r.host);
  if (!host) return { error: "host is not a host name, IP or *.suffix" };
  const rule = { action: r.action, host, ...(r.id ? { id: r.id } : {}) };
  if (r.binary !== undefined) {
    const l = asList(r.binary);
    if (!l.length || l.length > MAX_LIST || l.some((b) => typeof b !== "string" || !BINARY_RE.test(b.trim()))) return { error: "binary is not a name or list of names" };
    rule.binary = l.map((b) => globRe(normBinary(b.trim())));
  }
  if (r.port !== undefined) {
    const l = asList(r.port);
    if (!l.length || l.length > MAX_LIST || l.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) return { error: "port is not an integer 1-65535 or list of them" };
    rule.port = l;
  }
  if (r.method !== undefined) {
    const l = asList(r.method);
    if (!l.length || l.length > MAX_LIST || l.some((m) => typeof m !== "string" || !METHOD_RE.test(m))) return { error: "method is not a verb or list of verbs" };
    rule.method = l.map((m) => m.toUpperCase());
  }
  if (r.path !== undefined) {
    const p = rulePath(r.path);
    if (!p) return { error: "path is not /exact or /prefix*" };
    rule.path = p;
  }
  return { rule };
}

// A whole list → { rules, errors:[{ index, id?, reason }] }. Inside a profile the caller treats any
// error as the profile's; at the top level a malformed rule is dropped and the rest apply.
export function validateEgressRules(raw) {
  if (!Array.isArray(raw)) return { rules: [], errors: [{ index: -1, reason: "egressRules is not a list" }] };
  const rules = [], errors = [];
  raw.slice(0, MAX_RULES).forEach((r, index) => {
    const v = validateEgressRule(r);
    const id = r && typeof r.id === "string" && ID_RE.test(r.id) ? r.id : undefined;
    if (v.error) errors.push({ index, ...(id ? { id } : {}), reason: `egressRules: ${v.error}` });
    else rules.push({ ...v.rule, index });
  });
  if (raw.length > MAX_RULES) errors.push({ index: MAX_RULES, reason: `egressRules: more than ${MAX_RULES} rules` });
  return { rules, errors };
}

export function validEgressDefault(v) { return EGRESS_ACTIONS.includes(v); }

// Top-level rules and defaults from the two trusted documents, in order. Malformed entries are listed
// in `rejected` in the same shape cli/workload-profile.mjs lists malformed profiles.
export function egressFrom({ policy = null, system = null } = {}) {
  const out = { sources: [], defaults: [], rejected: [] };
  for (const [source, doc] of [["policy", policy], ["system", system]]) {
    if (!doc || typeof doc !== "object") continue;
    if (doc.egressRules !== undefined && doc.egressRules !== null) {
      const v = validateEgressRules(doc.egressRules);
      for (const e of v.errors) out.rejected.push({ source, ...e });
      if (v.rules.length) out.sources.push({ source, rules: v.rules });
    }
    if (doc.egressDefault !== undefined && doc.egressDefault !== null) {
      if (validEgressDefault(doc.egressDefault)) out.defaults.push(doc.egressDefault);
      else out.rejected.push({ source, index: -1, reason: "egressDefault is not allow, alert or block" });
    }
  }
  return out;
}

const EGRESS_CACHE = new WeakMap();
const NO_DOC = {};
export function cachedEgress(policy, system) {
  const k1 = policy && typeof policy === "object" ? policy : NO_DOC, k2 = system && typeof system === "object" ? system : NO_DOC;
  let inner = EGRESS_CACHE.get(k1);
  if (!inner) EGRESS_CACHE.set(k1, (inner = new WeakMap()));
  let r = inner.get(k2);
  if (!r) inner.set(k2, (r = egressFrom({ policy, system })));
  return r;
}

// ---------------------------------------------------------------------------------------------------
// Destinations a call names
// ---------------------------------------------------------------------------------------------------

// The host the raw authority names, read the way curl reads it: up to the first / ? or # (a backslash
// is NOT a separator), after the LAST @. WHATWG URL stops at a backslash in http(s), so for
// `http://allowed\@evil/` the two disagree — measured: curl 8.7.1 resolves evil. Both are judged.
function rawAuthorityHost(s) {
  const at3 = s.indexOf("://");
  let auth = s.slice(at3 + 3).split(/[/?#]/)[0];
  auth = auth.slice(auth.lastIndexOf("@") + 1);
  let host = auth, port = "";
  if (auth.startsWith("[")) { const e = auth.indexOf("]"); host = e > 0 ? auth.slice(0, e + 1) : auth; port = e > 0 ? auth.slice(e + 2) : ""; }
  else { const c = auth.lastIndexOf(":"); if (c >= 0) { host = auth.slice(0, c); port = auth.slice(c + 1); } }
  return { host: host.toLowerCase().replace(/\.$/, ""), port: /^\d{1,5}$/.test(port) ? Number(port) : null };
}

// One URL string → targets (one, or two when the parsers disagree on the host). defaultScheme lets a
// scheme-less argument of an HTTP client (`curl example.com/x`) count; without it, it must have one.
export function urlTargets(raw, { defaultScheme = "", binary = null, method = null } = {}) {
  let s = String(raw || "").replace(TRAIL, "");
  if (!s) return [];
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(s)) {
    if (!defaultScheme) return [];
    if (s.startsWith(":")) s = `localhost${s}`; // httpie's :3000/x
    s = `${defaultScheme}://${s}`;
  }
  const scheme = s.slice(0, s.indexOf(":")).toLowerCase();
  if (!(scheme in SCHEME_PORTS)) return [];
  const m = HTTP_SCHEMES.has(scheme) ? method : scheme === "ws" || scheme === "wss" ? "GET" : null;
  const out = [];
  let u = null;
  try { u = new URL(s); } catch { u = null; }
  if (u && u.hostname) {
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    out.push({ binary, scheme, host, port: u.port ? Number(u.port) : SCHEME_PORTS[scheme], method: m, path: u.pathname || "/" });
  }
  const r = rawAuthorityHost(s);
  let rawNorm = r.host;
  try { rawNorm = new URL(`http://${r.host}/`).hostname.replace(/\.$/, ""); } catch { /* keep the raw spelling */ }
  if (r.host && (!out.length || rawNorm !== out[0].host)) {
    // The raw read has no trustworthy path (the parsers disagree about where the authority ends).
    out.push({ binary, scheme, host: r.host, port: r.port ?? SCHEME_PORTS[scheme], method: m, path: null });
  }
  return out;
}

const TRAIL = /[.,;:!?)\]}>'"]+$/;
function urlsIn(text) {
  URL_IN_TEXT.lastIndex = 0;
  return (String(text || "").match(URL_IN_TEXT) || []).map((u) => u.replace(TRAIL, "")).filter((u) => !u.endsWith("://"));
}

// ---- a small, quote-aware shell splitter (POSIX, or PowerShell with `ps`) ----
//
// Segments are split on ; | & && || newlines (and, for PowerShell, on ( ) { } so method-call arguments
// are their own segments). `$( … )` and backticks are parsed as their own commands, and the token that
// held them is left carrying a `$` (its value is unknown). Heredoc bodies are skipped: they are data, so
// any URL in them is judged without a binary (see judgeTargets). Never throws; a parse that cannot finish
// returns what it has.
function splitShell(cmd, ps, depth, acc) {
  if (depth > MAX_DEPTH) return acc;
  let cur = [], tok = "", building = false, skipNext = false, heredoc = null;
  const endTok = () => {
    if (!building) return;
    // A bare `{` / `}` word is a brace group: a segment boundary, not a token (`{}` in find -exec is a token).
    if (!ps && (tok === "{" || tok === "}")) { tok = ""; building = false; if (cur.length && acc.segs.length < MAX_SEGS) acc.segs.push({ tokens: cur, ps }); cur = []; return; }
    if (skipNext) skipNext = false;
    else if (cur.length < MAX_TOKS) cur.push(tok);
    tok = ""; building = false;
  };
  const endSeg = () => { endTok(); if (cur.length && acc.segs.length < MAX_SEGS) acc.segs.push({ tokens: cur, ps }); cur = []; skipNext = false; };
  const sub = (inner) => { splitShell(inner, ps, depth + 1, acc); tok += "$"; building = true; };
  const balanced = (i) => { // i at "(" of "$(": index of the matching ")" or -1
    let d = 0;
    for (let j = i; j < cmd.length; j++) { if (cmd[j] === "(") d++; else if (cmd[j] === ")" && --d === 0) return j; }
    return -1;
  };
  const esc = ps ? "`" : "\\";
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === esc) { if (i + 1 < cmd.length) { tok += cmd[i + 1]; building = true; i++; } continue; }
    if (c === "'") {
      const close = cmd.indexOf("'", i + 1);
      tok += close < 0 ? cmd.slice(i + 1) : cmd.slice(i + 1, close); building = true;
      if (close < 0) break;
      i = close; continue;
    }
    if (c === '"') {
      let j = i + 1;
      building = true;
      for (; j < cmd.length && cmd[j] !== '"'; j++) {
        if (cmd[j] === esc && j + 1 < cmd.length) { tok += cmd[++j]; continue; }
        if (cmd[j] === "$" && cmd[j + 1] === "(") { const e = balanced(j + 1); if (e < 0) { tok += cmd.slice(j); j = cmd.length; break; } sub(cmd.slice(j + 2, e)); j = e; continue; }
        if (!ps && cmd[j] === "`") { const e = cmd.indexOf("`", j + 1); if (e < 0) { j = cmd.length; break; } sub(cmd.slice(j + 1, e)); j = e; continue; }
        tok += cmd[j];
      }
      i = j; continue;
    }
    if (c === "$" && cmd[i + 1] === "(") { const e = balanced(i + 1); if (e < 0) { sub(cmd.slice(i + 2)); break; } sub(cmd.slice(i + 2, e)); i = e; continue; }
    if (!ps && c === "`") { const e = cmd.indexOf("`", i + 1); if (e < 0) { sub(cmd.slice(i + 1)); break; } sub(cmd.slice(i + 1, e)); i = e; continue; }
    if (ps && "(){}".includes(c)) { endSeg(); continue; }
    if (!ps && "()".includes(c) && !building) { endSeg(); continue; }
    if (c === " " || c === "\t" || c === "\r") { endTok(); continue; }
    if (c === "\n") {
      endSeg();
      if (heredoc) { // skip the body up to the delimiter line
        const re = new RegExp(`(^|\\n)[\\t ]*${heredoc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\t ]*(\\n|$)`);
        const rest = cmd.slice(i + 1), m = rest.match(re);
        const body = m ? rest.slice(0, m.index) : rest;
        acc.heredocs.push(body);
        i = m ? i + 1 + m.index + m[0].length - 1 : cmd.length;
        heredoc = null;
      }
      continue;
    }
    if (c === ";" || c === "|" || c === "&") {
      if (c === "&" && cmd[i + 1] === ">") { endTok(); skipNext = true; i++; continue; }
      if (c === "&" && cmd[i - 1] === ">") continue;
      endSeg(); if (cmd[i + 1] === c) i++; continue;
    }
    if (c === "<" && !ps) {
      endTok();
      if (cmd[i + 1] === "<" && cmd[i + 2] !== "<") { // heredoc: remember the delimiter
        let j = i + 2;
        if (cmd[j] === "-") j++;
        while (cmd[j] === " ") j++;
        const m = cmd.slice(j).match(/^(['"]?)([A-Za-z0-9_.-]+)\1/);
        if (m) { heredoc = m[2]; i = j + m[0].length - 1; continue; }
      }
      if (cmd[i + 1] === "<") { i += cmd[i + 2] === "<" ? 2 : 1; continue; } // here-string: the word is data
      skipNext = true; continue;
    }
    if (c === ">") {
      if (building && /^[0-9*]$/.test(tok)) { tok = ""; building = false; }
      endTok();
      if (cmd[i + 1] === ">") i++;
      if (cmd[i + 1] === "&") { i++; if (/[0-9-]/.test(cmd[i + 1] || "")) i++; continue; }
      skipNext = true; continue;
    }
    tok += c; building = true;
  }
  endSeg();
  return acc;
}

// Wrappers whose argument is another command; the listed flags take a value.
const WRAPPERS = {
  sudo: ["-u", "-g", "-C", "-D", "-h", "-p", "-U", "-r", "-t", "-T"], doas: ["-u", "-C"], env: ["-u", "-C", "-S"],
  command: [], builtin: [], exec: ["-a"], nohup: [], time: ["-f", "-o"], nice: ["-n"], ionice: ["-c", "-n", "-p"],
  timeout: ["-s", "-k"], stdbuf: ["-i", "-o", "-e"], xargs: ["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"],
  caffeinate: ["-t", "-w"], unbuffer: [], proxychains: ["-f"], proxychains4: ["-f"], torsocks: [], tsocks: [],
  strace: ["-o", "-e", "-p", "-s", "-u"], ltrace: ["-o", "-e", "-p", "-s", "-u"], chronic: [], flock: ["-w", "-E"],
  "start-process": [], busybox: [],
  // Shell keywords that precede a command.
  if: [], then: [], else: [], elif: [], while: [], until: [], do: [], "!": []
};
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"]);
const PWSH = new Set(["powershell", "pwsh"]);

// The command of one segment: { binary, at } after env assignments and wrappers, or null when the
// segment has no command word we can name (a bare assignment, a PowerShell method call, a URL).
function commandOf(toks, ps) {
  let i = 0;
  if (ps && toks.length > 2 && /^\$[\w:]+$/.test(toks[0]) && /^[+\-*/]?=$/.test(toks[1])) i = 2;
  for (let guard = 0; guard < 8; guard++) {
    while (i < toks.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(toks[i])) i++;
    if (i >= toks.length) return null;
    const w = normBinary(toks[i]);
    const valued = WRAPPERS[w];
    if (!valued) {
      if (!w || /^[$.[@]/.test(toks[i]) || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(toks[i])) return null;
      return { binary: w, at: i };
    }
    i++;
    if (w === "start-process") { // Start-Process -FilePath curl -ArgumentList …
      if (/^-f/i.test(toks[i] || "")) i++;
      continue;
    }
    while (i < toks.length && toks[i].startsWith("-") && toks[i] !== "-") { i += valued.includes(toks[i]) ? 2 : 1; }
    if (w === "timeout" && /^\d/.test(toks[i] || "")) i++;
  }
  return null;
}

function decodeEncoded(b64) {
  try { return Buffer.from(String(b64), "base64").toString("utf16le"); } catch { return ""; }
}

// Option scanning: which tokens are values of a flag (skipped), which are positional.
function scanArgs(rest, { shortValued = "", longValued = [], ps = false } = {}) {
  const flags = [], positional = [];
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (t === "--") { positional.push(...rest.slice(i + 1)); break; }
    if (ps && /^-[A-Za-z]/.test(t)) {
      const colon = t.indexOf(":");
      const name = (colon > 0 ? t.slice(0, colon) : t).toLowerCase();
      const takes = longValued.some((v) => v.startsWith(name) && name.length >= 3) || longValued.includes(name);
      const value = colon > 0 ? t.slice(colon + 1) : takes && i + 1 < rest.length ? rest[++i] : null;
      flags.push({ name, value });
      continue;
    }
    if (t.startsWith("--") && t.length > 2) {
      const eq = t.indexOf("=");
      const name = eq > 0 ? t.slice(0, eq) : t;
      const value = eq > 0 ? t.slice(eq + 1) : longValued.includes(name) && i + 1 < rest.length ? rest[++i] : null;
      flags.push({ name, value });
      continue;
    }
    if (t.startsWith("-") && t.length > 1 && !ps) {
      for (let k = 1; k < t.length; k++) {
        const ch = t[k];
        if (shortValued.includes(ch)) {
          const value = k + 1 < t.length ? t.slice(k + 1) : i + 1 < rest.length ? rest[++i] : null;
          flags.push({ name: `-${ch}`, value });
          break;
        }
        flags.push({ name: `-${ch}`, value: null });
      }
      continue;
    }
    positional.push(t);
  }
  return { flags, positional };
}
const has = (flags, ...names) => flags.some((f) => names.includes(f.name));
const val = (flags, ...names) => { for (let k = flags.length - 1; k >= 0; k--) if (names.includes(flags[k].name) && flags[k].value != null) return flags[k].value; return null; };

const HOSTLIKE = /^(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]*\.?(?::\d{1,5})?(?:[/?#].*)?$|^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?(?:[/?#].*)?$|^:\d{1,5}(?:[/?#].*)?$/;

// curl
const CURL_SHORT = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
const CURL_LONG = ["--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--form", "--form-string", "--json", "--header", "--output", "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--request", "--url", "--proxy", "--preproxy", "--doh-url", "--max-time", "--connect-timeout", "--retry", "--cacert", "--cert", "--key", "--config", "--resolve", "--connect-to", "--upload-file", "--write-out", "--range", "--output-dir", "--oauth2-bearer", "--interface", "--dns-servers", "--limit-rate", "--max-filesize", "--continue-at", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--netrc-file", "--proxy-user", "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "--variable", "--retry-delay", "--retry-max-time", "--aws-sigv4", "--hostpubmd5", "--pubkey", "--ciphers", "--proto", "--proto-redir", "--proto-default", "--unix-socket", "--abstract-unix-socket", "--max-redirs", "--keepalive-time", "--expect100-timeout", "--happy-eyeballs-timeout-ms", "--local-port", "--tls-max", "--curves", "--engine", "--key-type", "--cert-type", "--pass", "--capath", "--crlfile", "--mail-from", "--mail-rcpt", "--mail-auth", "--quote", "--time-cond", "--telnet-option", "--speed-limit", "--speed-time"];
function curlTargets(rest) {
  const { flags, positional } = scanArgs(rest, { shortValued: CURL_SHORT, longValued: CURL_LONG });
  let method = val(flags, "-X", "--request");
  method = method ? method.toUpperCase()
    : has(flags, "-I", "--head") ? "HEAD"
    : has(flags, "-T", "--upload-file") ? "PUT"
    : has(flags, "-G", "--get") ? "GET"
    : has(flags, "-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form", "--form-string", "--json") ? "POST" : "GET";
  const out = [];
  const req = [...positional, ...flags.filter((f) => f.name === "--url" && f.value).map((f) => f.value)];
  for (const p of req) if (p.includes("://") || HOSTLIKE.test(p)) out.push({ raw: p, method, defaultScheme: "http" });
  for (const f of flags) if (["-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname"].includes(f.name) && f.value) out.push({ raw: f.value, method: null, defaultScheme: "http" });
  const doh = val(flags, "--doh-url");
  if (doh) out.push({ raw: doh, method: "POST", defaultScheme: "https" });
  return out;
}

// wget
const WGET_SHORT = "oaeOPtTwUiBQlARDXI";
const WGET_LONG = ["--output-document", "--output-file", "--append-output", "--user-agent", "--header", "--post-data", "--post-file", "--body-data", "--body-file", "--method", "--user", "--password", "--http-user", "--http-password", "--directory-prefix", "--input-file", "--tries", "--timeout", "--wait", "--load-cookies", "--save-cookies", "--ca-certificate", "--certificate", "--private-key", "--referer", "--limit-rate", "--level", "--accept", "--reject", "--domains", "--exclude-domains", "--base", "--execute", "--quota"];
function wgetTargets(rest) {
  const { flags, positional } = scanArgs(rest, { shortValued: WGET_SHORT, longValued: WGET_LONG });
  let method = val(flags, "--method");
  method = method ? method.toUpperCase() : has(flags, "--post-data", "--post-file") ? "POST" : has(flags, "--spider") ? "HEAD" : "GET";
  return positional.filter((p) => p.includes("://") || HOSTLIKE.test(p)).map((raw) => ({ raw, method, defaultScheme: "http" }));
}

// httpie / xh
const HTTPIE_SHORT = "aAopsv";
const HTTPIE_LONG = ["--auth", "--auth-type", "--output", "--session", "--session-read-only", "--print", "--style", "--verify", "--cert", "--cert-key", "--proxy", "--timeout", "--pretty", "--format-options", "--max-redirects", "--ssl", "--ciphers", "--boundary", "--default-scheme", "--bearer"];
const VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "QUERY"]);
function httpieTargets(rest, scheme) {
  const { flags, positional } = scanArgs(rest, { shortValued: HTTPIE_SHORT, longValued: HTTPIE_LONG });
  let i = 0, method = null;
  if (positional.length > 1 && VERBS.has(positional[0].toUpperCase())) { method = positional[0].toUpperCase(); i = 1; }
  const url = positional[i];
  if (!url) return [];
  const items = positional.slice(i + 1);
  if (!method) method = has(flags, "-f", "--form", "--raw") || items.some((t) => /^[^=:@]+(?::=|=(?!=)|@)/.test(t)) ? "POST" : "GET";
  const out = [{ raw: url, method, defaultScheme: scheme }];
  const proxy = val(flags, "--proxy");
  if (proxy) out.push({ raw: proxy.replace(/^[a-z]+:(?!\/\/)/i, ""), method: null, defaultScheme: "http" });
  return out;
}

// Invoke-WebRequest / Invoke-RestMethod
const IWR_VALUED = ["-uri", "-method", "-custommethod", "-body", "-headers", "-outfile", "-infile", "-contenttype", "-useragent", "-credential", "-proxy", "-proxycredential", "-timeoutsec", "-maximumredirection", "-sessionvariable", "-websession", "-certificate", "-certificatethumbprint", "-transferencoding", "-form", "-authentication", "-token", "-httpversion", "-retryintervalsec", "-maximumretrycount", "-connectiontimeoutseconds", "-operationtimeoutseconds", "-sslprotocol", "-responseheaderstvariable", "-statuscodevariable"];
function iwrTargets(rest) {
  const { flags, positional } = scanArgs(rest, { longValued: IWR_VALUED, ps: true });
  const named = (prefix) => { for (let k = flags.length - 1; k >= 0; k--) if (prefix.startsWith(flags[k].name) && flags[k].name.length >= 3 && flags[k].value != null) return flags[k].value; return null; };
  const uri = named("-uri") ?? positional[0];
  const m = named("-custommethod") ?? named("-method");
  const out = [];
  if (uri) out.push({ raw: uri, method: m ? m.toUpperCase() : "GET", defaultScheme: "http" });
  const proxy = named("-proxy");
  if (proxy) out.push({ raw: proxy, method: null, defaultScheme: "http" });
  return out;
}

// ssh-family bare hosts: [user@]host, [user@]host:path, host::module.
function bareHost(spec, port) {
  const s = String(spec || "");
  if (!s || s.includes("$") || s.startsWith("-")) return null;
  const rest = s.replace(/^[^@:/[\]]*@/, "");
  let host = rest.startsWith("[") ? rest.slice(0, rest.indexOf("]") + 1) : rest.split(":")[0];
  host = host.toLowerCase().replace(/\.$/, "");
  if (!host || /[/\\]/.test(host) || host.length === 1) return null;
  return { scheme: "ssh", host, port, method: null, path: null };
}
const SSH_SHORT = "bBcDEeFIiJLlmOopQRSWw";
function sshTargets(rest) {
  const { flags, positional } = scanArgs(rest, { shortValued: SSH_SHORT });
  const port = Number(val(flags, "-p")) || 22;
  const out = [];
  const dest = positional[0];
  if (dest && !dest.includes("://")) { const t = bareHost(dest, port); if (t) out.push(t); }
  const jump = val(flags, "-J");
  if (jump) for (const j of jump.split(",")) { const [h, p] = j.replace(/^[^@]*@/, "").split(":"); const t = bareHost(h, Number(p) || 22); if (t) out.push(t); }
  return out;
}
function scpTargets(rest, binary) {
  const shortValued = binary === "rsync" ? "eBfT" : "cFiloPSJDXB";
  const { flags, positional } = scanArgs(rest, { shortValued, longValued: binary === "rsync" ? ["--rsh", "--port", "--password-file"] : [] });
  const rsh = val(flags, "-e", "--rsh") || "";
  const port = binary === "rsync" ? Number((rsh.match(/-p\s*(\d+)/) || [])[1]) || 22 : Number(val(flags, "-P")) || 22;
  const out = [];
  for (const p of positional) {
    if (p.includes("://")) continue;
    if (binary === "rsync" && /^[^/:]+::/.test(p)) { const t = bareHost(p.split("::")[0], Number(val(flags, "--port")) || 873); if (t) out.push({ ...t, scheme: "rsync" }); continue; }
    const scpLike = /^(?:[^@/\s]+@)?(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]{2,}):/.test(p) && !/^[A-Za-z]:[\\/]/.test(p);
    if (scpLike || (binary === "sftp" && p === positional[0])) { const t = bareHost(p, port); if (t) out.push(t); }
  }
  return out;
}
function gitTargets(rest) {
  const out = [];
  for (const p of rest) {
    if (p.startsWith("-") || p.includes("://")) continue;
    if (/^(?:[^@/\s]+@[A-Za-z0-9.-]+|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}):(?!\/\/)/.test(p)) { const t = bareHost(p, 22); if (t) out.push(t); }
  }
  return out;
}
const NC_SHORT = "psxXiqecIOTwP";
function ncTargets(rest, binary) {
  const { flags, positional } = scanArgs(rest, { shortValued: binary === "telnet" ? "lbe" : NC_SHORT, longValued: ["--proxy", "--source-port", "--source", "--wait", "--exec", "--sh-exec"] });
  if (has(flags, "-l", "--listen")) return [];
  const [h, p] = positional;
  if (!h || h.includes("$")) return [];
  const port = /^\d{1,5}$/.test(p || "") ? Number(p) : binary === "telnet" && !p ? 23 : null;
  const host = h.toLowerCase().replace(/\.$/, "");
  return [{ scheme: "tcp", host, port, method: null, path: null }];
}

// Analyse one segment: push targets attributed to its binary, recurse into nested scripts.
function segmentTargets(seg, depth, acc) {
  const toks = seg.tokens;
  const cw = commandOf(toks, seg.ps);
  const binary = cw ? cw.binary : null;
  if (binary) acc.binaries.add(binary);
  const rest = cw ? toks.slice(cw.at + 1) : toks;
  // Nested scripts: sh -c, powershell -Command / -EncodedCommand, cmd /c, eval, find -exec.
  if (cw && depth < MAX_DEPTH) {
    if (SHELLS.has(binary)) {
      const ci = rest.findIndex((t) => /^-[a-z]*c$/.test(t));
      if (ci >= 0 && rest[ci + 1] != null) { collect(rest[ci + 1], false, depth + 1, acc); return; }
    }
    if (PWSH.has(binary)) {
      const ei = rest.findIndex((t) => /^-e(nc|ncodedcommand|c)?$/i.test(t));
      if (ei >= 0 && rest[ei + 1]) { collect(decodeEncoded(rest[ei + 1]), true, depth + 1, acc); return; }
      const ci = rest.findIndex((t) => /^-c(ommand)?$/i.test(t));
      if (ci >= 0) { collect(rest.slice(ci + 1).join(" "), true, depth + 1, acc); return; }
      if (rest.length && !rest[0].startsWith("-")) { collect(rest.join(" "), true, depth + 1, acc); return; }
    }
    if (binary === "cmd") {
      const ci = rest.findIndex((t) => /^\/[ck]$/i.test(t));
      if (ci >= 0) { collect(rest.slice(ci + 1).join(" "), false, depth + 1, acc); return; }
    }
    if (binary === "eval" || binary === "invoke-expression" || binary === "iex") { collect(rest.join(" "), seg.ps || binary !== "eval", depth + 1, acc); return; }
    if (binary === "find" && rest.some((t) => /^-(exec|execdir|ok|okdir)$/.test(t))) {
      let k = 0;
      while (k < rest.length) {
        if (!/^-(exec|execdir|ok|okdir)$/.test(rest[k])) { for (const u of urlsIn(rest[k])) { acc.attributed.push(u); acc.targets.push(...urlTargets(u, { binary, method: null })); } k++; continue; }
        let end = rest.findIndex((t, j) => j > k && (t === ";" || t === "+"));
        if (end < 0) end = rest.length;
        segmentTargets({ tokens: rest.slice(k + 1, end), ps: false }, depth + 1, acc);
        k = end + 1;
      }
      return;
    }
  }
  let req = [];
  if (binary === "curl") req = curlTargets(rest);
  else if (binary === "wget" || binary === "wget2") req = wgetTargets(rest);
  else if (binary === "http" || binary === "xh") req = httpieTargets(rest, "http");
  else if (binary === "https" || binary === "xhs") req = httpieTargets(rest, "https");
  else if (binary === "invoke-webrequest" || binary === "invoke-restmethod") req = iwrTargets(rest);
  else if (binary === "ssh") for (const t of sshTargets(rest)) acc.targets.push({ ...t, binary });
  else if (binary === "scp" || binary === "sftp" || binary === "rsync") for (const t of scpTargets(rest, binary)) acc.targets.push({ ...t, binary });
  else if (binary === "git") for (const t of gitTargets(rest)) acc.targets.push({ ...t, binary });
  else if (binary === "nc" || binary === "ncat" || binary === "netcat" || binary === "telnet") for (const t of ncTargets(rest, binary)) acc.targets.push({ ...t, binary });
  // In PowerShell a bare `curl` / `wget` may be the Invoke-WebRequest alias (Windows PowerShell 5.1),
  // whose -Method curl's parser does not read: the method is unknown there.
  const aliasAmbiguous = seg.ps && cw && (binary === "curl" || binary === "wget") && !/\.exe$/i.test(toks[cw.at]);
  const reqUrls = new Set();
  for (const r of req) {
    acc.targets.push(...urlTargets(r.raw, { defaultScheme: r.defaultScheme, binary, method: aliasAmbiguous ? null : r.method }));
    for (const u of urlsIn(r.raw)) reqUrls.add(u);
  }
  // Every other URL written in the segment (an env assignment, a header, an argument) is a destination
  // of this binary, method unknown.
  toks.forEach((t, k) => {
    if (cw && k === cw.at) return;
    for (const u of urlsIn(t)) {
      acc.attributed.push(u);
      if (!reqUrls.has(u)) acc.targets.push(...urlTargets(u, { binary, method: null }));
    }
  });
}

function collect(cmd, ps, depth, acc) {
  const s = String(cmd || "").slice(0, MAX_CMD);
  const parsed = splitShell(s, ps, depth, { segs: [], heredocs: [] });
  acc.heredocs.push(...parsed.heredocs);
  for (const seg of parsed.segs) segmentTargets(seg, depth, acc);
}

// Every destination one call names. Each target: { binary, scheme, host, port, method, path } (null =
// unknown) and `binaries`, the command words of the whole call (for alert/block rules).
export function egressTargets(tool, toolInput) {
  const t = String(tool || "");
  const ti = toolInput && typeof toolInput === "object" ? toolInput : {};
  let out = [], overflow = false;
  if (t === "Bash" || t === "PowerShell") {
    const cmd = typeof ti.command === "string" ? ti.command : "";
    if (!cmd) return [];
    const acc = { targets: [], attributed: [], binaries: new Set(), heredocs: [] };
    collect(cmd, t === "PowerShell", 0, acc);
    // A URL the segment parse did not attribute (a heredoc body, a parse that stopped early) is still a
    // destination: judged with no binary. Counted per URL, so the same URL in an attributed and an
    // unattributed position is judged both ways.
    const seen = new Map();
    for (const u of acc.attributed) seen.set(u, (seen.get(u) || 0) + 1);
    for (const u of urlsIn(cmd)) {
      const n = seen.get(u) || 0;
      if (n > 0) { seen.set(u, n - 1); continue; }
      acc.targets.push(...urlTargets(u, { binary: null, method: null }));
    }
    out = acc.targets.map((x) => ({ ...x, binaries: acc.binaries }));
  } else if (t === "WebFetch") {
    const url = typeof ti.url === "string" ? ti.url : "";
    const binary = normBinary(t);
    out = urlTargets(url, { defaultScheme: "https", binary, method: "GET" }).map((x) => ({ ...x, binaries: new Set([binary]) }));
  } else if (t.startsWith("mcp__")) {
    const binary = t.toLowerCase();
    const strings = [];
    let budget = MAX_MCP_CHARS;
    const walk = (v, d) => {
      if (d > 32 || budget <= 0) { overflow = true; return; }
      if (typeof v === "string") { budget -= v.length; strings.push(v.slice(0, Math.max(0, budget + v.length))); return; }
      if (v && typeof v === "object") for (const k of Object.keys(v)) { if (typeof k === "string" && k.includes("://")) strings.push(k); walk(v[k], d + 1); }
    };
    walk(ti, 0);
    for (const s of strings) for (const u of urlsIn(s)) out.push(...urlTargets(u, { binary, method: null }).map((x) => ({ ...x, binaries: new Set([binary]) })));
  }
  // Dedupe on every judged field. Past MAX_TARGETS distinct destinations the rest are kept per binary,
  // host and port with method and path unknown (which an allow rule cannot match); past MAX_HOSTS the list
  // is marked `overflow` and judgeTargets applies the strictest action in force. Nothing is dropped
  // silently: padding a call with allowed URLs must not hide the one that is not.
  const uniq = new Map();
  for (const x of out) {
    const full = `${x.binary}|${x.scheme}|${x.host}|${x.port}|${x.method}|${x.path}`;
    if (uniq.has(full)) continue;
    if (uniq.size < MAX_TARGETS) { uniq.set(full, x); continue; }
    const coarse = `${x.binary}|${x.scheme}|${x.host}|${x.port}|null|null`;
    if (uniq.has(coarse)) continue;
    if (uniq.size >= MAX_HOSTS) { overflow = true; break; }
    uniq.set(coarse, { ...x, method: null, path: null });
  }
  const res = [...uniq.values()];
  if (overflow) res.overflow = true;
  return res;
}

// ---------------------------------------------------------------------------------------------------
// Judgement
// ---------------------------------------------------------------------------------------------------

function hostMatch(h, host) {
  return h.exact !== undefined ? host === h.exact : host.endsWith(h.suffix) && host.length > h.suffix.length;
}
function pathMatch(p, path) {
  return p.exact !== undefined ? path === p.exact : path.startsWith(p.prefix);
}

// Does one rule match one target? See UNKNOWN FIELDS and BINARY ATTRIBUTION above.
export function ruleMatches(rule, t) {
  const allow = rule.action === "allow";
  if (!hostMatch(rule.host, t.host)) return false;
  if (rule.binary) {
    if (allow) { if (!t.binary || !rule.binary.some((re) => re.test(t.binary))) return false; }
    else if (t.binary) {
      const names = t.binaries && t.binaries.size ? [...t.binaries, t.binary] : [t.binary];
      if (!rule.binary.some((re) => names.some((b) => re.test(b)))) return false;
    }
  }
  if (rule.port && (t.port == null ? allow : !rule.port.includes(t.port))) return false;
  if (rule.method && (t.method == null ? allow : !rule.method.includes(t.method))) return false;
  if (rule.path && (t.path == null ? allow : !pathMatch(rule.path, t.path))) return false;
  return true;
}

// The rule chain for a call: the matched profile's rules, then the policy's, then the system file's.
export function egressChain(profile, eg) {
  const chain = [];
  if (profile && profile.egress && profile.egress.rules.length) chain.push({ source: `profile:${profile.id}`, rules: profile.egress.rules });
  for (const s of eg.sources) chain.push(s);
  const dflt = (profile && profile.egress && profile.egress.default) || eg.defaults[0] || "allow";
  return { chain, dflt };
}

// Each target → { target, action, ref } where ref names the deciding rule ("policy#2", "profile:ci#0",
// "default", "loopback"). Returns the verdicts and the worst action.
export function judgeTargets(targets, { chain, dflt }) {
  const verdicts = [];
  let worst = "allow";
  if (targets.overflow) {
    const strictest = [dflt, ...chain.flatMap((s) => s.rules.map((r) => r.action))].reduce((a, b) => (RANK[b] > RANK[a] ? b : a), "allow");
    if (strictest !== "allow") { verdicts.push({ target: { binary: null, scheme: null, host: "*", port: null, method: null, path: null }, action: strictest, ref: "overflow" }); worst = strictest; }
  }
  for (const t of targets) {
    let v = null;
    for (const s of chain) {
      const r = s.rules.find((rule) => ruleMatches(rule, t));
      if (r) { v = { target: t, action: r.action, ref: `${s.source}#${r.index}`, ...(r.id ? { ruleId: r.id } : {}) }; break; }
    }
    if (!v) v = LOOPBACK.has(t.host) ? { target: t, action: "allow", ref: "loopback" } : { target: t, action: dflt, ref: "default" };
    verdicts.push(v);
    if (RANK[v.action] > RANK[worst]) worst = v.action;
  }
  return { verdicts, worst };
}

const SAFE_BIN = /^[a-z0-9._+:-]{1,128}$/;
const where = (t) => `${t.host}${t.port != null ? `:${t.port}` : ""}`;

// The reason the agent sees on a block (local, not telemetry): the destination and the deciding rule.
export function egressReason(v) {
  const t = v.target;
  if (v.ref === "overflow") return `egress is blocked: the call names more destinations than can be judged`;
  const by = v.ref === "default" ? "egressDefault" : `egress rule ${v.ruleId ? `"${v.ruleId}" ` : ""}(${v.ref})`;
  return `egress to ${where(t)}${t.binary ? ` by ${t.binary}` : ""} is blocked by ${by}`;
}

// Content-free alerts for alert/block verdicts, one per distinct binary/host/port/method, at most 8.
// decision: what the host was told ("deny" | "allow" | "coach").
export function egressAlerts(verdicts, { coach = false, profileId } = {}) {
  const out = [], seen = new Set();
  for (const v of verdicts) {
    if (v.action === "allow") continue;
    const t = v.target;
    const binary = t.binary ? (SAFE_BIN.test(t.binary) ? t.binary : "other") : null;
    const k = `${v.action}|${binary}|${t.host}|${t.port}|${t.method}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const blocked = v.action === "block";
    const decision = blocked ? (coach ? "coach" : "deny") : "allow";
    out.push({
      threatId: 0,
      category: EGRESS_CATEGORY,
      riskLevel: blocked && !coach ? "Blocked" : "Medium",
      stage: "egress",
      decision,
      reasonCode: EGRESS_RULE,
      ...(decision === "coach" ? { enforcement: "LIMITED" } : {}),
      egressAction: v.action,
      egressBinary: binary,
      egressHost: t.host.slice(0, 253),
      egressPort: t.port,
      egressMethod: t.method,
      egressRule: v.ref,
      ...(v.ruleId ? { egressRuleId: v.ruleId } : {}),
      ...(profileId ? { profileId } : {}),
      contentHash: `egress:${v.action}:${binary}:${t.host.slice(0, 253)}:${t.port}:${t.method}`
    });
    if (out.length >= MAX_ALERTS) break;
  }
  return out;
}
