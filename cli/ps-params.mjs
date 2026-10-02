// PowerShell grammar details the read-path parser in cli/hook-core.mjs (psSegments / psSegmentPaths)
// needs and that are pure data plus a few bounded lookups: parameter-name resolution, variable and `~`
// expansion, and -EncodedCommand decoding. Nothing here reads the filesystem or the process.
//
// PARAMETER ABBREVIATION. PowerShell binds `-Pa` to `-Path` when the prefix is unique. The rule, from
// MergedCommandParameterMetadata.GetMatchingParameter (PowerShell/PowerShell, src/System.Management.
// Automation/engine): every parameter whose NAME or ALIAS starts with the prefix (case-insensitive) is a
// match, deduplicated by parameter; an exact name or alias wins outright; with more than one match,
// "Prefer parameters in the cmdlet over common parameters" — if exactly one match is declared by the
// cmdlet, it wins; otherwise PowerShell throws AmbiguousParameter and the command never runs.
// The tables below are the cmdlets the parser follows, from the PowerShell 7.5 reference pages on
// learn.microsoft.com (names and "Aliases:" rows). WhatIf/Confirm and the paging parameters bind
// outside the cmdlet's declared set, so they count as common here.

const COMMON = ["verbose|vb", "debug|db", "erroraction|ea", "warningaction|wa", "informationaction|infa", "progressaction|proga", "errorvariable|ev", "warningvariable|wv", "informationvariable|iv", "outvariable|ov", "outbuffer|ob", "pipelinevariable|pv"];
const SHOULD_PROCESS = ["whatif|wi", "confirm|cf"];
const PAGING = ["includetotalcount", "skip", "first"];
const WEB = ["allowinsecureredirect", "allowunencryptedauthentication", "authentication", "body", "certificate", "certificatethumbprint", "connectiontimeoutseconds|timeoutsec", "contenttype", "credential", "custommethod|cm", "disablekeepalive", "form", "headers", "httpversion", "infile", "maximumredirection", "maximumretrycount", "method", "noproxy", "operationtimeoutseconds", "outfile", "passthru", "preserveauthorizationonredirect", "preservehttpmethodonredirect", "proxy", "proxycredential", "proxyusedefaultcredentials", "resume", "retryintervalsec", "sessionvariable|sv", "skipcertificatecheck", "skipheadervalidation", "skiphttperrorcheck", "sslprotocol", "token", "transferencoding", "unixsocket", "uri", "usebasicparsing", "usedefaultcredentials", "useragent", "websession"];
const LITERAL = "literalpath|pspath|lp";
const CMDLETS = {
  "get-content": { declared: ["path", LITERAL, "readcount", "totalcount|first|head", "tail|last", "filter", "include", "exclude", "force", "credential", "delimiter", "wait", "raw", "encoding", "asbytestream", "stream"] },
  "select-string": { declared: ["pattern", "path", LITERAL, "culture", "simplematch", "casesensitive", "quiet", "list", "noemphasis", "include", "exclude", "notmatch", "allmatches", "encoding", "context", "inputobject", "raw"] },
  "format-hex": { declared: ["path", LITERAL, "inputobject", "encoding", "count", "offset", "raw"] },
  "import-csv": { declared: ["delimiter", "path", LITERAL, "header", "encoding", "useculture"] },
  "import-clixml": { declared: ["path", LITERAL], extra: PAGING },
  "copy-item": { declared: ["path", "destination", "container", "force", "filter", "include", "exclude", "recurse", "passthru", "credential", LITERAL, "fromsession", "tosession"], extra: SHOULD_PROCESS },
  "invoke-webrequest": { declared: WEB },
  "invoke-restmethod": { declared: [...WEB, "followrellink|fl", "maximumfollowrellink|ml", "responseheadersvariable|rhv", "statuscodevariable"] },
  "send-mailmessage": { declared: ["attachments|pspath", "bcc", "body", "bodyashtml|bah", "encoding|be", "cc", "deliverynotificationoption|dno", "from", "smtpserver|computername", "priority", "replyto", "subject|sub", "to", "credential", "usessl", "port"] },
  "invoke-expression": { declared: ["command"] },
  "new-object": { declared: ["typename", "argumentlist|args", "property", "comobject", "strict"] }
};
// Built-in aliases of those cmdlets (the reference pages' Notes). `curl`/`wget` (Invoke-WebRequest in
// Windows PowerShell 5.1) are left out: they are curl.exe/wget.exe far more often, whose flags differ.
const ALIASES = { gc: "get-content", type: "get-content", cat: "get-content", sls: "select-string", fhx: "format-hex", ipcsv: "import-csv", cpi: "copy-item", copy: "copy-item", cp: "copy-item", iwr: "invoke-webrequest", irm: "invoke-restmethod", iex: "invoke-expression" };
// Parameters of the tables above that take no value.
const SWITCHES = new Set(["force", "wait", "raw", "asbytestream", "simplematch", "casesensitive", "quiet", "list", "noemphasis", "notmatch", "allmatches", "useculture", "includetotalcount", "container", "recurse", "passthru", "allowinsecureredirect", "allowunencryptedauthentication", "disablekeepalive", "noproxy", "preserveauthorizationonredirect", "preservehttpmethodonredirect", "proxyusedefaultcredentials", "resume", "skipcertificatecheck", "skipheadervalidation", "skiphttperrorcheck", "usebasicparsing", "usedefaultcredentials", "bodyashtml", "usessl", "strict", "followrellink", "verbose", "debug", "whatif", "confirm"]);

function index(entries, declared) { return entries.map((e) => { const [name, ...aliases] = e.split("|"); return { name, keys: [name, ...aliases], declared }; }); }
const TABLES = new Map(Object.entries(CMDLETS).map(([k, v]) => [k, [...index(v.declared, true), ...index([...COMMON, ...(v.extra || [])], false)]]));

// The cmdlet a command word names (`gc` → get-content), or "" when the parser has no table for it.
export function psCmdlet(word) {
  const w = String(word || "").toLowerCase();
  return TABLES.has(w) ? w : ALIASES[w] || "";
}

// PowerShell accepts these dash characters to start a parameter (CharExtensions.IsDash).
const DASHES = "-–—―";
export function psIsParam(t) { return typeof t === "string" && t.length > 1 && DASHES.includes(t[0]) && /[A-Za-z]/.test(t[1]); }

// `name` is a parameter token without its value (`-Pa`, `–Path`). Returns
//   { name: "-path", switch }  the parameter it binds to (canonical, lowercase);
//   { ambiguous: true }        PowerShell would throw and the command would not run;
//   { name: "-pa", unknown: true }  no table for the command, or no such parameter: as typed.
export function psResolveParam(word, name) {
  const typed = `-${String(name).slice(1).toLowerCase()}`;
  const table = TABLES.get(psCmdlet(word));
  if (!table) return { name: typed, unknown: true };
  const pfx = typed.slice(1);
  const matches = [];
  for (const p of table) {
    if (p.keys.includes(pfx)) return { name: `-${p.name}`, switch: SWITCHES.has(p.name) };
    if (p.keys.some((k) => k.startsWith(pfx)) && !matches.includes(p)) matches.push(p);
  }
  let pick = matches;
  if (matches.length > 1) pick = matches.filter((p) => p.declared);
  if (pick.length === 1) return { name: `-${pick[0].name}`, switch: SWITCHES.has(pick[0].name) };
  if (matches.length === 0) return { name: typed, unknown: true };
  return { ambiguous: true };
}

// ---- variable and `~` expansion ----
//
// A `$` that PowerShell would NOT expand (inside '…', or escaped as `$) is carried through the
// tokenizer as LIT + "$", so a quoted literal can never be mistaken for a variable here, and the token
// still fails xpUsablePath (it contains `$`).
export const PS_LIT = "\u0001";
const VAR = /(?<!\u0001)\$(?:\{env:([^}\u0001]{1,255})\}|env:([A-Za-z_][A-Za-z0-9_]{0,254})|(home)(?![A-Za-z0-9_:]))/gi;

function envLookup(env, name, insensitive) {
  if (Object.prototype.hasOwnProperty.call(env, name)) return env[name];
  if (!insensitive) return undefined;
  const k = Object.keys(env).find((x) => x.toLowerCase() === name.toLowerCase());
  return k === undefined ? undefined : env[k];
}

// Expands `$env:NAME`, `${env:NAME}` and `$HOME` from `env` / `home`, and a leading `~` (alone, or
// followed by `\` or `/`) when `tilde` is set — the FileSystem provider resolves it for cmdlet paths;
// .NET methods receive it verbatim. An unset variable is left as written, so the token keeps its `$` and
// is never used. `insensitive` matches Windows, where environment names ignore case.
export function psExpand(token, { env, home, tilde = true, insensitive = false } = {}) {
  let t = String(token);
  if (env && typeof env === "object") {
    t = t.replace(VAR, (m, braced, plain, isHome) => {
      if (isHome) return typeof home === "string" && home ? home : m;
      const v = envLookup(env, braced || plain, insensitive);
      return typeof v === "string" && v ? v : m;
    });
  }
  if (tilde && typeof home === "string" && home && t[0] === "~" && (t.length === 1 || t[1] === "\\" || t[1] === "/")) t = home + t.slice(1);
  return t;
}

// The script text once PowerShell has parsed a string literal: literal-`$` markers dropped.
export function psScriptText(token) { return String(token).split(PS_LIT).join(""); }

// ---- -EncodedCommand ----
//
// powershell.exe / pwsh take `-EncodedCommand` (also `-e`, `-ec`, and any longer prefix such as `-enc`)
// followed by base64 of the script in UTF-16LE. `/` starts a parameter for these hosts as well.
export function psIsHost(word) { return /^(?:powershell|pwsh)(?:\.exe)?$/i.test(String(word || "")); }
export function psIsEncodedFlag(t) {
  const m = /^(?:--?|\/|[–—―])([A-Za-z]+)$/.exec(String(t || ""));
  if (!m) return false;
  const n = m[1].toLowerCase();
  return n === "ec" || "encodedcommand".startsWith(n);
}
// Decoded script, or "" when the value is not base64 of UTF-16LE text. Legitimate encoded commands are
// overwhelmingly ASCII; a decode that is mostly non-ASCII, or carries control characters, is not a script.
export function psDecodeEncoded(value, max) {
  const v = String(value || "");
  if (!v || v.length > max * 3 || v.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return "";
  const buf = Buffer.from(v, "base64");
  if (!buf.length || buf.length % 2 !== 0) return "";
  const s = buf.toString("utf16le");
  if (s.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(s)) return "";
  let ascii = 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ascii++; }
  return ascii * 2 >= s.length ? s : "";
}

// `System.IO.StreamReader` as PowerShell names a type (it prepends `System.` when needed).
export const PS_READER_TYPE = /^\[?(?:System\.)?IO\.StreamReader\]?$/i;
export const PS_READER_CTOR = /^\[(?:System\.)?IO\.StreamReader\]::new$/i;
