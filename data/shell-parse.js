// A small, quote-aware shell reader shared by the egress rules (cli/egress-rules.mjs) and the
// fetch-then-execute / secret-upload / out-of-band-host detectors (data/net-exec.js). Moved here from
// cli/egress-rules.mjs unchanged in what it returns for `tokens`, so both read a command line the same
// way: segments split on ; | & && || newlines, `sh -c` and `$( … )` recursed by the caller, quoting
// honoured, heredoc bodies skipped as data (and handed to the segment that declared them).
//
// Browser-safe (no node: imports, no Buffer): data/ is bundled by the desktop app. Never throws.
//
// Each segment is { tokens, ps, reads, writes, sep }. `reads` / `writes` are the targets of `<` and
// `>` / `>>` / `&>` redirects (never in `tokens`, as before); `sep` is the operator that ENDED the
// segment ("|", "||", "&&", ";", "&", "\n", "(" / ")" or "" at the end), so a reader can tell a pipe
// from a sequence. A segment that declared a heredoc (`<<EOF`) also carries its body as `heredoc`; in
// PowerShell, a segment holding a here-string (`@'` … `'@`) carries that string's text the same way.
// Whether the body is data or code is the caller's question (data/net-exec.js).

export const MAX_CMD = 262144, MAX_DEPTH = 3, MAX_SEGS = 256, MAX_TOKS = 256;
const BIN_ALIASES = { iwr: "invoke-webrequest", irm: "invoke-restmethod" };

export function normBinary(raw) {
  const s = String(raw || "");
  const cut = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\"));
  const w = (cut >= 0 ? s.slice(cut + 1) : s).toLowerCase().replace(/\.exe$/, "");
  return BIN_ALIASES[w] || w;
}

// ---- a small, quote-aware shell splitter (POSIX, or PowerShell with `ps`) ----
//
// Segments are split on ; | & && || newlines (and, for PowerShell, on ( ) { } so method-call arguments
// are their own segments). `$( … )` and backticks are parsed as their own commands, and the token that
// held them is left carrying a `$` (its value is unknown). Heredoc bodies are skipped: they are data, so
// any URL in them is judged without a binary (see judgeTargets); the body is also set on the declaring
// segment. A PowerShell here-string is one token. Never throws; a parse that cannot finish returns what
// it has.
export function splitShell(cmd, ps, depth, acc) {
  if (depth > MAX_DEPTH) return acc;
  // skipNext: false, or "r" / "w" when the next word is the target of a `<` / `>` redirect.
  // here: what the segment being built declared (true: a heredoc whose body comes after the line; a
  // string: a here-string's text). owner: the pushed segment whose heredoc body is still to be read.
  // scope (POSIX): the subshells open around a segment — `( … )`, `$( … )` and backticks each get an id, and
  // seg.scope is their path ("" outside any). A `cd` inside a subshell does not move the shell around it.
  // arr: open `(` inside a word (`arr=(a b)`), whose `)` stays in the word.
  let cur = [], tok = "", building = false, skipNext = false, heredoc = null, reads = [], writes = [], here = null, owner = null, arr = 0;
  if (!acc.scope) acc.scope = [];
  const push = (sep) => {
    if (cur.length && acc.segs.length < MAX_SEGS) {
      const seg = { tokens: cur, ps, reads, writes, sep, scope: acc.scope.join("/") };
      if (typeof here === "string") seg.heredoc = here;
      else if (here) owner = seg;
      acc.segs.push(seg);
    }
    cur = []; reads = []; writes = []; here = null;
  };
  const endTok = () => {
    if (!building) return;
    // A bare `{` / `}` word is a brace group: a segment boundary, not a token (`{}` in find -exec is a token).
    if (!ps && (tok === "{" || tok === "}")) { tok = ""; building = false; push(tok); return; }
    if (skipNext) { if (skipNext === "r") reads.push(tok); else if (writes.length < MAX_TOKS) writes.push(tok); skipNext = false; }
    else if (cur.length < MAX_TOKS) cur.push(tok);
    tok = ""; building = false;
  };
  const endSeg = (sep = "") => { endTok(); push(sep); skipNext = false; };
  const open = () => { if (!ps) acc.scope.push(acc.nscope = (acc.nscope || 0) + 1); };
  const close = () => { if (!ps && acc.scope.length) acc.scope.pop(); };
  const sub = (inner) => { open(); splitShell(inner, ps, depth + 1, acc); close(); tok += "$"; building = true; };
  const balanced = (i) => { // i at "(" of "$(": index of the matching ")" or -1
    let d = 0;
    for (let j = i; j < cmd.length; j++) { if (cmd[j] === "(") d++; else if (cmd[j] === ")" && --d === 0) return j; }
    return -1;
  };
  const esc = ps ? "`" : "\\";
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    // An escaped line break is a line continuation: both characters go, the word goes on.
    if (c === esc && /^\r?\n/.test(cmd.slice(i + 1, i + 3))) { i += cmd[i + 1] === "\r" ? 2 : 1; continue; }
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
        if (cmd[j] === esc && /^\r?\n/.test(cmd.slice(j + 1, j + 3))) { j += cmd[j + 1] === "\r" ? 2 : 1; continue; }
        if (cmd[j] === esc && j + 1 < cmd.length) { tok += cmd[++j]; continue; }
        if (cmd[j] === "$" && cmd[j + 1] === "(") { const e = balanced(j + 1); if (e < 0) { tok += cmd.slice(j); j = cmd.length; break; } sub(cmd.slice(j + 2, e)); j = e; continue; }
        if (!ps && cmd[j] === "`") { const e = cmd.indexOf("`", j + 1); if (e < 0) { j = cmd.length; break; } sub(cmd.slice(j + 1, e)); j = e; continue; }
        tok += cmd[j];
      }
      i = j; continue;
    }
    if (c === "$" && cmd[i + 1] === "(") { const e = balanced(i + 1); if (e < 0) { sub(cmd.slice(i + 2)); break; } sub(cmd.slice(i + 2, e)); i = e; continue; }
    if (!ps && c === "`") { const e = cmd.indexOf("`", i + 1); if (e < 0) { sub(cmd.slice(i + 1)); break; } sub(cmd.slice(i + 1, e)); i = e; continue; }
    if (ps && c === "@" && !building && (cmd[i + 1] === "'" || cmd[i + 1] === '"') && /^\r?\n/.test(cmd.slice(i + 2, i + 4))) {
      // A here-string: `@'` or `@"` ending its line, closed by `'@` / `"@` at the start of a line.
      const open = i + 2 + (cmd[i + 2] === "\r" ? 2 : 1), q = cmd[i + 1];
      const m = new RegExp(`\\r?\\n${q}@`).exec(cmd.slice(open - 1));
      const close = m ? open - 1 + m.index : cmd.length;
      here = cmd.slice(open, close);
      tok += cmd.slice(i, m ? close + m[0].length : cmd.length); building = true;
      i = m ? close + m[0].length - 1 : cmd.length;
      continue;
    }
    // A `#` that starts a word starts a comment, up to the end of the line.
    if (c === "#" && !building) { const e = cmd.indexOf("\n", i); i = (e < 0 ? cmd.length : e) - 1; continue; }
    if (ps && "(){}".includes(c)) { endSeg(c); continue; }
    if (!ps && c === "(" && building) { arr++; tok += c; continue; }
    if (!ps && c === ")" && arr) { arr--; tok += c; continue; }
    if (!ps && c === "(") { endSeg(c); open(); continue; }
    if (!ps && c === ")") { endSeg(c); close(); continue; }
    if (c === " " || c === "\t" || c === "\r") { endTok(); continue; }
    if (c === "\n") {
      endSeg("\n");
      if (heredoc) { // skip the body up to the delimiter line
        const re = new RegExp(`(^|\\n)[\\t ]*${heredoc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\t ]*(\\n|$)`);
        const rest = cmd.slice(i + 1), m = rest.match(re);
        const body = m ? rest.slice(0, m.index) : rest;
        acc.heredocs.push(body);
        if (owner) owner.heredoc = body;
        i = m ? i + 1 + m.index + m[0].length - 1 : cmd.length;
        heredoc = null; owner = null;
      }
      continue;
    }
    if (c === ";" || c === "|" || c === "&") {
      if (c === "&" && cmd[i + 1] === ">") { endTok(); skipNext = "w"; i++; continue; }
      if (c === "&" && cmd[i - 1] === ">") continue;
      const dbl = cmd[i + 1] === c;
      endSeg(dbl ? c + c : c); if (dbl) i++; continue;
    }
    if (c === "<" && !ps) {
      endTok();
      if (cmd[i + 1] === "<" && cmd[i + 2] !== "<") { // heredoc: remember the delimiter
        let j = i + 2;
        if (cmd[j] === "-") j++;
        while (cmd[j] === " ") j++;
        const m = cmd.slice(j).match(/^(['"]?)([A-Za-z0-9_.-]+)\1/);
        if (m) { heredoc = m[2]; here = true; owner = null; i = j + m[0].length - 1; continue; }
      }
      if (cmd[i + 1] === "<") { i += cmd[i + 2] === "<" ? 2 : 1; continue; } // here-string: the word is data
      skipNext = "r"; continue;
    }
    if (c === ">") {
      if (building && /^[0-9*]$/.test(tok)) { tok = ""; building = false; }
      endTok();
      if (cmd[i + 1] === ">") i++;
      if (cmd[i + 1] === "&") { i++; if (/[0-9-]/.test(cmd[i + 1] || "")) i++; continue; }
      skipNext = "w"; continue;
    }
    tok += c; building = true;
  }
  endSeg();
  return acc;
}

// Wrappers whose argument is another command; the listed flags take a value.
export const WRAPPERS = {
  sudo: ["-u", "-g", "-C", "-D", "-h", "-p", "-U", "-r", "-t", "-T"], doas: ["-u", "-C"], env: ["-u", "-C", "-S"],
  command: [], builtin: [], exec: ["-a"], nohup: [], time: ["-f", "-o"], nice: ["-n"], ionice: ["-c", "-n", "-p"],
  timeout: ["-s", "-k"], stdbuf: ["-i", "-o", "-e"], xargs: ["-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a"],
  caffeinate: ["-t", "-w"], unbuffer: [], proxychains: ["-f"], proxychains4: ["-f"], torsocks: [], tsocks: [],
  strace: ["-o", "-e", "-p", "-s", "-u"], ltrace: ["-o", "-e", "-p", "-s", "-u"], chronic: [], flock: ["-w", "-E"],
  "start-process": [], busybox: [],
  // Shell keywords that precede a command.
  if: [], then: [], else: [], elif: [], while: [], until: [], do: [], "!": []
};
export const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"]);
export const PWSH = new Set(["powershell", "pwsh"]);

// The command of one segment: { binary, at } after env assignments and wrappers, or null when the
// segment has no command word we can name (a bare assignment, a PowerShell method call, a URL).
export function commandOf(toks, ps) {
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

// Option scanning: which tokens are values of a flag (skipped), which are positional.
export function scanArgs(rest, { shortValued = "", longValued = [], ps = false } = {}) {
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
export const has = (flags, ...names) => flags.some((f) => names.includes(f.name));
export const val = (flags, ...names) => { for (let k = flags.length - 1; k >= 0; k--) if (names.includes(flags[k].name) && flags[k].value != null) return flags[k].value; return null; };

export const HOSTLIKE = /^(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]*\.?(?::\d{1,5})?(?:[/?#].*)?$|^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?(?:[/?#].*)?$|^:\d{1,5}(?:[/?#].*)?$/;

// Flag tables: which short/long options take a value, so a value is never read as a URL or a path.
export const CURL_SHORT = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
export const CURL_LONG = ["--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--form", "--form-string", "--json", "--header", "--output", "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--request", "--url", "--proxy", "--preproxy", "--doh-url", "--max-time", "--connect-timeout", "--retry", "--cacert", "--cert", "--key", "--config", "--resolve", "--connect-to", "--upload-file", "--write-out", "--range", "--output-dir", "--oauth2-bearer", "--interface", "--dns-servers", "--limit-rate", "--max-filesize", "--continue-at", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--netrc-file", "--proxy-user", "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "--variable", "--retry-delay", "--retry-max-time", "--aws-sigv4", "--hostpubmd5", "--pubkey", "--ciphers", "--proto", "--proto-redir", "--proto-default", "--unix-socket", "--abstract-unix-socket", "--max-redirs", "--keepalive-time", "--expect100-timeout", "--happy-eyeballs-timeout-ms", "--local-port", "--tls-max", "--curves", "--engine", "--key-type", "--cert-type", "--pass", "--capath", "--crlfile", "--mail-from", "--mail-rcpt", "--mail-auth", "--quote", "--time-cond", "--telnet-option", "--speed-limit", "--speed-time"];
export const WGET_SHORT = "oaeOPtTwUiBQlARDXI";
export const WGET_LONG = ["--output-document", "--output-file", "--append-output", "--user-agent", "--header", "--post-data", "--post-file", "--body-data", "--body-file", "--method", "--user", "--password", "--http-user", "--http-password", "--directory-prefix", "--input-file", "--tries", "--timeout", "--wait", "--load-cookies", "--save-cookies", "--ca-certificate", "--certificate", "--private-key", "--referer", "--limit-rate", "--level", "--accept", "--reject", "--domains", "--exclude-domains", "--base", "--execute", "--quota"];
export const IWR_VALUED = ["-uri", "-method", "-custommethod", "-body", "-headers", "-outfile", "-infile", "-contenttype", "-useragent", "-credential", "-proxy", "-proxycredential", "-timeoutsec", "-maximumredirection", "-sessionvariable", "-websession", "-certificate", "-certificatethumbprint", "-transferencoding", "-form", "-authentication", "-token", "-httpversion", "-retryintervalsec", "-maximumretrycount", "-connectiontimeoutseconds", "-operationtimeoutseconds", "-sslprotocol", "-responseheaderstvariable", "-statuscodevariable"];
