// What a command line does with the network, read structurally: which files a download writes, which
// files the command then runs, and which local files a network client sends. The command detectors in
// data/detectors-net-exec.js and the hook's cross-call record (cli/fetch-exec-state.mjs) both read it.
//
// The command is split by data/shell-parse.js, the same reader the egress rules use, so `&&`, `;`, `||`,
// `|`, newlines, quoting, `$( … )`, wrappers (sudo, env, timeout, …) and `sh -c` / `bash -c` /
// `powershell -Command` / `cmd /c` / `eval` scripts are handled the way they are there. A heredoc body (or a
// PowerShell here-string) is read as a nested script when the command it feeds runs its stdin as code:
// `bash <<EOF`, `sh -s <<EOF`, `python3 - <<EOF`, `pwsh -Command - <<EOF`, `cat <<EOF | sh`,
// `@'…'@ | iex`. A body fed to anything else (`cat > file <<EOF`) stays data.
//
// Bounded: the reader caps the command (MAX_CMD), the segment count and the nesting depth. No regex runs
// over the command; every regex here is anchored over one token. Browser-safe (no node: imports). Never
// throws: every exported function catches and returns its empty result.
import { splitShell, commandOf, scanArgs, has, val, SHELLS, PWSH, MAX_CMD, MAX_DEPTH, HOSTLIKE, CURL_SHORT, CURL_LONG, WGET_SHORT, WGET_LONG, IWR_VALUED } from "./shell-parse.js";

const ROOTED = /^(?:[A-Za-z]:\/|\/|~(?:\/|$))/;

// A path as one canonical string: `\` → `/`, `.` and `..` folded, a relative path joined to `base` (the
// directory a `cd` earlier in the command, or the caller's cwd, left it in). With no base a relative
// path stays relative to "./", which is still consistent within one command.
export function normPath(p, base = "") {
  let s = String(p || "").replace(/\\/g, "/");
  if (!ROOTED.test(s) && base) s = String(base).replace(/\\/g, "/").replace(/\/*$/, "/") + s;
  const m = s.match(ROOTED);
  const root = m ? (m[0].startsWith("~") ? "~/" : m[0]) : "./";
  const parts = [];
  for (const x of (m ? s.slice(m[0].length) : s).split("/")) {
    if (!x || x === ".") continue;
    if (x === "..") { if (parts.length && parts[parts.length - 1] !== "..") parts.pop(); else if (root === "./") parts.push(".."); continue; }
    parts.push(x);
  }
  return root + parts.join("/");
}
function dirOf(p) { const i = p.lastIndexOf("/"); return i >= 0 ? p.slice(0, i + 1).replace(/(.)\/$/, "$1") : "./"; }
const usable = (t) => typeof t === "string" && !!t && t.length <= 4096 && !t.includes("$") && t !== "-" && t !== "/dev/null";

// ---- segments, with nested scripts expanded in place ----
const INTERP = /^(?:python[0-9.]*|pypy[0-9.]*|node|nodejs|perl|ruby|php|tsx|ts-node|osascript|lua|Rscript)$/i;
const INLINE_CODE = new Set(["-c", "-e", "-E", "-p", "-m", "-r", "--eval", "--print", "-Command", "-command"]);
const INTERP_VALUED = new Set(["-W", "-X", "-r", "--require", "--import", "--loader", "-I", "-M"]);
const SH_VALUED = new Set(["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]);
const READERS = new Set(["cat", "type", "get-content", "gc", "more", "less"]);
const STDIN_FILE = (t) => t === "-" || t === "/dev/stdin";

// True when no script argument is named, or the script named is stdin: the program reads its code there.
function stdinIsScript(args, valued, stop) {
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (STDIN_FILE(t)) return true;
    if (t === "--") return args[i + 1] == null || STDIN_FILE(args[i + 1]);
    if (stop.has(t)) return false;
    if (valued.has(t)) { i++; continue; }
    if (/^[-+]/.test(t)) continue;
    return false;
  }
  return true;
}
// How a command reads code from its stdin: "sh" (parsed as POSIX), "ps" (as PowerShell), or null when
// stdin is data to it.
function stdinCode(cw, rest, raw) {
  const b = cw.binary;
  if (SHELLS.has(b)) return rest.some((t) => /^-[A-Za-z]*s[A-Za-z]*$/.test(t)) || stdinIsScript(rest, SH_VALUED, new Set(["-c", "-n"])) ? "sh" : null;
  if (b === "source" || raw === ".") return STDIN_FILE(rest[0]) ? "sh" : null;
  if (PWSH.has(b)) {
    const ci = rest.findIndex((t) => /^-(?:c(?:ommand)?|f(?:ile)?)$/i.test(t));
    if (ci >= 0) return rest[ci + 1] === "-" ? "ps" : null;
    return rest.every((t) => t.startsWith("-")) ? "ps" : null;
  }
  if (b === "invoke-expression" || b === "iex") return rest.length ? null : "ps";
  if (INTERP.test(b)) return stdinIsScript(rest, INTERP_VALUED, INLINE_CODE) ? "sh" : null;
  return null;
}
// A command word for a segment. commandOf refuses a word starting with "." (a method call in PowerShell);
// `./run`, `.\a.ps1` and the `.` builtin are commands here, so they are read through a stand-in prefix
// that keeps the index.
const commandWord = (seg) => commandOf(seg.tokens.map((t) => (/^(?:\.{1,2}[/\\]|\.$)/.test(t) ? "_" + t : t)), seg.ps);

function flat(cmd, ps, depth, out) {
  const parsed = splitShell(String(cmd || "").slice(0, MAX_CMD), ps, depth, { segs: [], heredocs: [] });
  for (let k = 0; k < parsed.segs.length; k++) {
    const seg = parsed.segs[k];
    const cw = commandWord(seg);
    const rest = cw ? seg.tokens.slice(cw.at + 1) : [];
    if (cw && depth < MAX_DEPTH) {
      // The body this segment runs as code: its own heredoc, or the heredoc / here-string a reader (or a
      // bare here-string) pipes into it.
      const code = stdinCode(cw, rest, seg.tokens[cw.at]);
      const prev = parsed.segs[k - 1];
      const prevCw = prev && prev.sep === "|" && prev.heredoc != null ? commandWord(prev) : null;
      const body = seg.heredoc != null ? seg.heredoc : prev && prev.sep === "|" && prev.heredoc != null && (!prevCw || READERS.has(prevCw.binary)) ? prev.heredoc : null;
      if (code && body != null) flat(body, code === "ps", depth + 1, out);
      if (SHELLS.has(cw.binary)) {
        const ci = rest.findIndex((t) => /^-[a-z]*c$/.test(t));
        if (ci >= 0 && rest[ci + 1] != null) { flat(rest[ci + 1], false, depth + 1, out); continue; }
      }
      if (PWSH.has(cw.binary)) {
        const ci = rest.findIndex((t) => /^-c(ommand)?$/i.test(t));
        if (ci >= 0) { flat(rest.slice(ci + 1).join(" "), true, depth + 1, out); continue; }
      }
      if (cw.binary === "cmd") {
        const ci = rest.findIndex((t) => /^\/[ck]$/i.test(t));
        if (ci >= 0) { flat(rest.slice(ci + 1).join(" "), false, depth + 1, out); continue; }
      }
      if (cw.binary === "eval" || cw.binary === "invoke-expression" || cw.binary === "iex") { flat(rest.join(" "), seg.ps || cw.binary !== "eval", depth + 1, out); continue; }
    }
    out.push({ ...seg, cw, rest, raw: cw ? seg.tokens[cw.at] : "" });
  }
  return out;
}
const PS_HINT = /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\b|-OutFile\b|-InFile\b/i;
// Every reading of the command: POSIX always, and PowerShell as well when it carries PowerShell's web
// cmdlets (a detector sees text without knowing which shell it is for).
function readings(cmd, ps) {
  const s = String(cmd || "");
  if (ps) return [flat(s, true, 0, [])];
  return PS_HINT.test(s) ? [flat(s, false, 0, []), flat(s, true, 0, [])] : [flat(s, false, 0, [])];
}

// ---- downloads ----
const NET_URL = /^(?:https?|ftps?):\/\//i;
function urlArgs(list) { return list.filter((p) => NET_URL.test(p) || (!p.includes("://") && HOSTLIKE.test(p) && p.includes("."))); }
function urlBase(u, dflt = "") {
  const path = String(u).replace(/^[a-z]+:\/\/[^/?#]*/i, "").split(/[?#]/)[0];
  const b = path.slice(path.lastIndexOf("/") + 1);
  return b ? decodeURIComponentSafe(b) : dflt;
}
function decodeURIComponentSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }
const named = (flags, full) => { for (let k = flags.length - 1; k >= 0; k--) { const n = flags[k].name; if (n.length >= 3 && full.startsWith(n) && flags[k].value != null) return flags[k].value; } return null; };

// The files (and download directories) one segment writes from the network: [{ kind: "f"|"d", path }].
function fetchWrites(seg, base) {
  const b = seg.cw && seg.cw.binary;
  const out = [];
  const file = (p) => { if (usable(p)) out.push({ kind: "f", path: normPath(p, base) }); };
  // A download directory counts only when it is not the directory the command is already in: `-P .`
  // would otherwise make every later script in the project a "downloaded" one.
  const dir = (p) => { if (usable(p) && normPath(p, base) !== normPath(".", base)) out.push({ kind: "d", path: normPath(p, base) }); };
  const psAlias = seg.ps && (b === "curl" || b === "wget") && !/\.exe$/i.test(seg.raw);
  if ((b === "curl") && !psAlias) {
    const { flags, positional } = scanArgs(seg.rest, { shortValued: CURL_SHORT, longValued: CURL_LONG });
    const urls = urlArgs([...positional, ...flags.filter((f) => f.name === "--url" && f.value).map((f) => f.value)]);
    if (!urls.length) return out;
    const odir = val(flags, "--output-dir");
    const outs = flags.filter((f) => (f.name === "-o" || f.name === "--output") && f.value).map((f) => f.value);
    for (const o of outs) if (!o.includes("#")) file(odir && !ROOTED.test(o.replace(/\\/g, "/")) ? `${odir}/${o}` : o);
    if (has(flags, "-O", "--remote-name", "--remote-name-all")) for (const u of urls) { const n = urlBase(u); if (n) file(odir ? `${odir}/${n}` : n); }
    if (odir) dir(odir);
    if (!outs.length) for (const w of seg.writes) file(w);
    return out;
  }
  if ((b === "wget" || b === "wget2") && !psAlias) {
    const { flags, positional } = scanArgs(seg.rest, { shortValued: WGET_SHORT, longValued: WGET_LONG });
    const urls = urlArgs(positional);
    if (!urls.length) return out;
    const doc = val(flags, "-O", "--output-document");
    const pre = val(flags, "-P", "--directory-prefix");
    if (doc && doc !== "-") file(pre && !ROOTED.test(doc) ? `${pre}/${doc}` : doc);
    else if (doc === "-") for (const w of seg.writes) file(w);
    else for (const u of urls) file(pre ? `${pre}/${urlBase(u, "index.html")}` : urlBase(u, "index.html"));
    if (pre) dir(pre);
    return out;
  }
  if (b === "aria2c") {
    const { flags, positional } = scanArgs(seg.rest, { shortValued: "odxsjk", longValued: ["--out", "--dir"] });
    const urls = urlArgs(positional);
    if (!urls.length) return out;
    const d = val(flags, "-d", "--dir"), o = val(flags, "-o", "--out");
    if (o) file(d ? `${d}/${o}` : o); else for (const u of urls) file(d ? `${d}/${urlBase(u)}` : urlBase(u));
    if (d) dir(d);
    return out;
  }
  if (b === "invoke-webrequest" || b === "invoke-restmethod" || psAlias || b === "start-bitstransfer") {
    const { flags, positional } = scanArgs(seg.rest, { longValued: [...IWR_VALUED, "-source", "-destination"], ps: true });
    if (b === "start-bitstransfer") { const d = named(flags, "-destination") ?? positional[1]; if (d) file(d); return out; }
    const o = named(flags, "-outfile");
    if (o) file(o);
    return out;
  }
  return out;
}
const FETCHERS = new Set(["curl", "wget", "wget2", "aria2c", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer"]);

// ---- execution ----

// The script argument: the first word that is not an option. `false` when an option says the code is
// inline (`-c`, `-e`, `-m`), so neither an argument nor stdin is a script file.
function firstFile(args, valued, stop) {
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") return args[i + 1] ?? null;
    if (stop.has(t)) return false;
    if (valued.has(t)) { i++; continue; }
    if (/^[-+]/.test(t)) continue;
    return t;
  }
  return null;
}
// The local files one segment runs. `prev` is the segment before it, for `cat f | sh`.
function execTargets(seg, prev) {
  const raw = seg.raw || "";
  const b = seg.cw ? seg.cw.binary : "";
  const out = [];
  if (!seg.cw) return out;
  const stdinScript = () => {
    if (seg.reads.length) return seg.reads[0];
    if (prev && prev.sep === "|" && prev.cw && READERS.has(prev.cw.binary)) return prev.rest.find((t) => !t.startsWith("-")) || null;
    return null;
  };
  if (SHELLS.has(b)) { const f = firstFile(seg.rest, SH_VALUED, new Set(["-c", "-n"])); const p = f === null ? stdinScript() : f; if (p) out.push(p); return out; }
  if (b === "source" || raw === ".") { if (seg.rest[0]) out.push(seg.rest[0]); return out; }
  if (PWSH.has(b)) { const fi = seg.rest.findIndex((t) => /^-f(ile)?$/i.test(t)); if (fi >= 0 && seg.rest[fi + 1]) out.push(seg.rest[fi + 1]); return out; }
  if (INTERP.test(b)) { const f = firstFile(seg.rest, INTERP_VALUED, INLINE_CODE); const p = f === null ? stdinScript() : f; if (p) out.push(p); return out; }
  if ((b === "deno" || b === "bun") && seg.rest[0] === "run") { const f = firstFile(seg.rest.slice(1), INTERP_VALUED, INLINE_CODE); if (f) out.push(f); return out; }
  // Run directly: `./run`, `/tmp/run`, `.\a.ps1`, `& C:\t\a.ps1`.
  if (/[/\\]/.test(raw)) out.push(raw);
  return out;
}

function cdTarget(seg, base) {
  const b = seg.cw && seg.cw.binary;
  if (b !== "cd" && b !== "pushd" && b !== "set-location" && b !== "sl" && b !== "chdir") return undefined;
  const a = seg.rest.find((t) => !t.startsWith("-"));
  if (!a) return "~";
  return usable(a) ? normPath(a, base) : "?";
}

// One command line → { fetched: [{kind, path}], executed: [path], hit }. `hit`: a file a download in
// this command wrote (or any file in a download directory it named) is run LATER in the same command.
// `cwd` makes the paths absolute (the hook passes the agent's cwd), `home` expands a leading `~`, and
// `insensitive` lowercases them.
export function fetchExecFacts(cmd, { ps = false, cwd = "", home = "", insensitive = false } = {}) {
  const res = { fetched: [], executed: [], hit: false };
  try {
    const h = String(home || "").replace(/\\/g, "/").replace(/\/+$/, "");
    const fold = (p) => { const q = h && p.startsWith("~/") ? h + p.slice(1) : p; return insensitive ? q.toLowerCase() : q; };
    for (const segs of readings(cmd, ps)) {
      let base = cwd || "";
      const files = new Set(), dirs = new Set();
      for (let i = 0; i < segs.length; i++) {
        const seg = segs[i];
        const nb = cdTarget(seg, base);
        if (nb !== undefined) { base = nb; continue; }
        for (const p of execTargets(seg, segs[i - 1])) {
          if (!usable(p)) continue;
          const n = fold(normPath(p, base));
          if (!res.executed.includes(n)) res.executed.push(n);
          if (files.has(n) || dirs.has(fold(dirOf(n)))) res.hit = true;
        }
        let w = seg.cw && FETCHERS.has(seg.cw.binary) ? fetchWrites(seg, base) : [];
        // `curl URL | tee f`: the download lands in f.
        if (!w.length && seg.cw && seg.cw.binary === "tee" && segs[i - 1] && segs[i - 1].sep === "|" && segs[i - 1].cw && FETCHERS.has(segs[i - 1].cw.binary)) {
          w = seg.rest.filter((t) => !t.startsWith("-") && usable(t)).map((t) => ({ kind: "f", path: normPath(t, base) }));
        }
        for (const x of w) {
          const p = fold(x.path);
          (x.kind === "d" ? dirs : files).add(p);
          if (!res.fetched.some((e) => e.kind === x.kind && e.path === p)) res.fetched.push({ kind: x.kind, path: p });
        }
      }
    }
  } catch { return { fetched: [], executed: [], hit: false }; }
  return res;
}

export { dirOf };

// ---- uploads ----
const CURL_AT = new Set(["-d", "--data", "--data-binary", "--data-ascii", "--json"]);
// The local files one segment hands to a network client to send. "-" means stdin, resolved to the files
// the segment before it reads when that segment pipes into this one.
function uploadFiles(seg, prev) {
  const b = seg.cw && seg.cw.binary;
  const out = [];
  const piped = () => (prev && prev.sep === "|" && prev.cw && READERS.has(prev.cw.binary) ? prev.rest.filter((t) => !t.startsWith("-")) : []);
  const add = (p) => { if (p === "-" || p === "@-") out.push(...piped()); else if (usable(p)) out.push(p); };
  const psAlias = seg.ps && (b === "curl" || b === "wget") && !/\.exe$/i.test(seg.raw);
  if (b === "curl" && !psAlias) {
    const { flags } = scanArgs(seg.rest, { shortValued: CURL_SHORT, longValued: CURL_LONG });
    for (const f of flags) {
      if (f.value == null) continue;
      if (CURL_AT.has(f.name) && f.value.startsWith("@")) add(f.value.slice(1) || "-");
      else if (f.name === "--data-urlencode") { const at = f.value.indexOf("@"); if (at >= 0 && !f.value.slice(0, at).includes("=")) add(f.value.slice(at + 1)); }
      else if (f.name === "-F" || f.name === "--form") { const m = f.value.match(/^[^=]*=[@<]([^;]*)/); if (m) add(m[1]); }
      else if (f.name === "-T" || f.name === "--upload-file") add(f.value === "." ? "-" : f.value);
    }
    return out;
  }
  if ((b === "wget" || b === "wget2") && !psAlias) {
    const { flags } = scanArgs(seg.rest, { shortValued: WGET_SHORT, longValued: WGET_LONG });
    for (const f of flags) if ((f.name === "--post-file" || f.name === "--body-file") && f.value) add(f.value);
    return out;
  }
  if (b === "nc" || b === "ncat" || b === "netcat" || b === "telnet") {
    if (seg.rest.includes("-z")) return out;
    for (const r of seg.reads) add(r);
    out.push(...piped());
    return out;
  }
  if (b === "socat") {
    const addrs = seg.rest.filter((t) => !t.startsWith("-") || t === "-");
    if (!addrs.some((a) => /^(?:tcp[46]?|udp[46]?|openssl|ssl|sctp[46]?|proxy|socks[45]a?)[:-]/i.test(a))) return out;
    for (const a of addrs) { const m = a.match(/^(?:file|open|gopen|create):([^,]+)/i); if (m) add(m[1]); }
    if (addrs.includes("-") || addrs.some((a) => /^stdio$/i.test(a))) { for (const r of seg.reads) add(r); out.push(...piped()); }
    return out;
  }
  if (b === "invoke-webrequest" || b === "invoke-restmethod" || psAlias) {
    const { flags } = scanArgs(seg.rest, { longValued: IWR_VALUED, ps: true });
    const f = named(flags, "-infile");
    if (f) add(f);
    return out;
  }
  return out;
}

// Every local file a network client in this command sends.
export function uploadedFiles(cmd, { ps = false } = {}) {
  const out = [];
  try {
    for (const segs of readings(cmd, ps)) for (let i = 0; i < segs.length; i++) for (const p of uploadFiles(segs[i], segs[i - 1])) if (!out.includes(p)) out.push(p);
  } catch { return []; }
  return out;
}

// ---- network destinations, and whether data goes with them ----
const DNS_TOOLS = new Set(["dig", "nslookup", "host", "drill", "ping", "ping6", "resolve-dnsname", "test-connection", "test-netconnection"]);
const HTTP_TOOLS = new Set(["curl", "wget", "wget2", "http", "https", "xh", "xhs", "invoke-webrequest", "invoke-restmethod", "aria2c"]);
const SOCKET_TOOLS = new Set(["nc", "ncat", "netcat", "telnet", "socat", "openssl"]);
const URL_TOKEN = /^[a-z][a-z0-9+.-]{0,15}:\/\//i;
function hostOf(t) {
  let s = String(t);
  if (URL_TOKEN.test(s)) s = s.replace(URL_TOKEN, "");
  s = s.replace(/^[^@/]*@/, "").split(/[/?#:]/)[0];
  return s.toLowerCase().replace(/\.$/, "");
}
// Data rides on a URL when it has a query, or a `$` (a substitution) anywhere in it.
function urlCarriesData(t) { return /\?[^#]*=/.test(t) || /\$/.test(t); }

// [{ host, send }] for each destination a network client in the command names. `send`: a body, an upload,
// a non-GET method, a query string, a substituted value in the name, or input piped / redirected into a
// socket client.
export function netDestinations(cmd, { ps = false } = {}) {
  const out = [];
  try {
    for (const segs of readings(cmd, ps)) {
      for (let i = 0; i < segs.length; i++) {
        const seg = segs[i], b = seg.cw && seg.cw.binary;
        if (!b) continue;
        const prev = segs[i - 1];
        const fedIn = seg.reads.length > 0 || (prev && prev.sep === "|");
        if (HTTP_TOOLS.has(b)) {
          let send = false;
          const isPs = b === "invoke-webrequest" || b === "invoke-restmethod" || (seg.ps && (b === "curl" || b === "wget"));
          if (isPs) {
            const { flags } = scanArgs(seg.rest, { longValued: IWR_VALUED, ps: true });
            const m = named(flags, "-method");
            send = !!(named(flags, "-body") || named(flags, "-infile") || named(flags, "-form") || (m && !/^(get|head|options)$/i.test(m)));
          } else if (b === "curl") {
            const { flags } = scanArgs(seg.rest, { shortValued: CURL_SHORT, longValued: CURL_LONG });
            const m = val(flags, "-X", "--request");
            send = has(flags, "-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form", "--form-string", "--json", "-T", "--upload-file") || !!(m && !/^(get|head|options)$/i.test(m));
          } else if (b === "wget" || b === "wget2") {
            const { flags } = scanArgs(seg.rest, { shortValued: WGET_SHORT, longValued: WGET_LONG });
            const m = val(flags, "--method");
            send = has(flags, "--post-data", "--post-file", "--body-data", "--body-file") || !!(m && !/^(get|head|options)$/i.test(m));
          } else if (b !== "aria2c") {
            send = seg.rest.some((t) => /^[A-Za-z0-9_.-]+(?::=|=|@)/.test(t) && !URL_TOKEN.test(t)) || seg.rest.some((t) => /^(post|put|patch|delete)$/i.test(t));
          }
          for (const t of seg.rest) {
            if (!URL_TOKEN.test(t) && !(HOSTLIKE.test(t) && t.includes("."))) continue;
            if (/^-/.test(t)) continue;
            out.push({ host: hostOf(t), send: send || urlCarriesData(t) });
          }
          continue;
        }
        if (SOCKET_TOOLS.has(b)) {
          for (const t of seg.rest) {
            if (t.startsWith("-")) continue;
            const h = /^(?:tcp[46]?|udp[46]?|openssl|ssl|connect):/i.test(t) ? t.replace(/^[a-z0-9]+:/i, "") : t;
            if (!h.includes(".")) continue;
            out.push({ host: hostOf(h), send: fedIn || /\$/.test(t) || seg.rest.some((x) => /^(?:file|open|gopen):/i.test(x)) });
          }
          continue;
        }
        if (DNS_TOOLS.has(b)) {
          for (const t of seg.rest) if (!t.startsWith("-") && !t.startsWith("@") && t.includes(".")) out.push({ host: hostOf(t), send: /\$/.test(t) });
        }
      }
    }
  } catch { return []; }
  return out;
}

const URL_IN_TEXT = /(?<![A-Za-z0-9+.-])https?:\/\/[^\s"'<>`{}|^\\]+/gi;
// For a tool call whose text is not a command (a WebFetch URL, MCP arguments): every http(s) URL in it.
export function urlDestinations(text) {
  const out = [];
  try {
    const s = String(text || "").slice(0, MAX_CMD);
    for (const m of s.matchAll(URL_IN_TEXT)) { if (out.length >= 64) break; out.push({ host: hostOf(m[0]), send: urlCarriesData(m[0]) }); }
  } catch { return []; }
  return out;
}
