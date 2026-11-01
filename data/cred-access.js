// #55 credential access, read structurally from a shell command (Bash or PowerShell): which credential
// store a command reads, prints or copies. The cred-file-access patterns (data/detectors.js) name a fixed
// verb list and a fixed path list; this reader closes what they leave open:
//
//   * any command that takes a credential file as an argument or a `<` redirect reads it (`jq`, `awk`,
//     `sed -n`, `grep`, `cp`, `tar`, `scp`, `base64 -i`, `openssl … -in`, `sqlite3`), judged by the path
//     rules in data/cred-paths.js, which cover Windows paths and more stores; only commands that cannot
//     show the content are exempt (ls, stat, chmod, rm, mv, tee, echo, source, ssh-add, ssh-keygen,
//     `grep -q`, `sed -i`, …), and a path given to a flag that USES it (ssh -i, --kubeconfig, --env-file,
//     curl --key, openssl -inkey, …) is use, not a read;
//   * a credential directory copied, archived or searched (`tar czf x ~/.ssh`, `grep -r token ~/.aws`);
//   * a quoted path inside inline interpreter code (`python3 -c "open('/home/u/.netrc')"`, `node -e`);
//   * commands that print a stored secret: the macOS keychain (security find-*-password, dump-keychain,
//     export of private keys; docker-credential-* get; git credential fill; keyring get; secret-tool),
//     CLI access tokens (gh auth token, az account get-access-token, Get-AzAccessToken, gcloud auth
//     print-*-token, aws configure get/export-credentials, kubectl config view --raw, heroku auth:token,
//     vault print token), GnuPG secret-key export, certutil -exportPFX / Export-PfxCertificate, and the
//     password-hash stores (getent shadow, unshadow, dscl … ShadowHashData). A token piped straight into a
//     registry login's --password-stdin is use, not theft;
//   * shell history searched for a secret word (grep / rg / awk / Select-String / findstr on a history file,
//     or `history | grep -i password`); reading a history file whole is not judged (by design);
//   * a search for secrets or key files rooted at the filesystem root, a home directory or /etc
//     (`grep -r password ~`, `find / -name '*.pem'`, `Get-ChildItem -Recurse -Include *.pfx C:\`).
//
// The command is split by data/net-exec.js commandSegments (data/shell-parse.js), so quoting, wrappers,
// pipes, `sh -c`, `pwsh -Command` and heredoc scripts read as the shell runs them. Bounded by that reader's
// caps; every regex here runs over one token or one short span. Browser-safe. Never throws.
import { commandSegments } from "./net-exec.js";
import { credPathKind, credDirKind, broadRoot, credGlob, SECRET_WORD } from "./cred-paths.js";

const MAX = 262144;
// A cheap gate before any parse: the text names a credential location, a credential command or a search verb.
export const CRED_HINT = /\.ssh|\.aws|\.env|\.npmrc|\.pypirc|netrc|pgpass|credential|history|dbshell|shadow|passwd|spwd|dslocal|id_(?:rsa|dsa|ecdsa|ed25519)|ssh_host_|mylogin|msal|web data|keychain|\bsecurity\b|\bgpg2?\b|\.(?:key|p12|pfx|ppk|jks|keystore|p8|pem|pvk|pkcs12)\b|token|login data|cookies|local state|key[34]\.db|logins\.json|getent|dscl|docker-credential|keyring|secret-tool|\.kube|gcloud|\.azure|\bgh\b|\.config|\.docker|hosts\.yml|github|\.gnupg|\.claude|\.codex|\.gemini|copilot|vercel|netlify|\.fly|wrangler|supabase|firebase|ngrok|\.vault|\.s3cfg|\.boto|\.my\.cnf|htpasswd|terraform|cargo|\.gem|rclone|\.oci|snowflake|pulumi|stripe|doctl|hcloud|databricks|sentry|exportpfx|pfxcertificate|\bfind\b|\b(?:e|f|z)?grep\b|\brg\b|\bag\b|\back\b|findstr|select-string|\bsls\b|get-childitem|\bgci\b|\bdir\b|\bls\b|azaccesstoken|\bheroku\b|\bvault\b|\bkubectl\b|\baws\b|\baz\b|unshadow|private/i;

// Commands that cannot show a file's content: their path arguments are not reads.
const NON_EXPOSING = new Set(["ls", "dir", "stat", "file", "du", "df", "wc", "test", "[", "[[", "chmod", "chown", "chgrp", "chflags", "chattr",
  "lsattr", "setfacl", "getfacl", "xattr", "touch", "mkdir", "rm", "rmdir", "unlink", "shred", "srm", "mv", "ln", "realpath", "readlink", "dirname",
  "basename", "which", "whereis", "echo", "printf", "export", "unset", "source", "_.", "dotenv", "env-cmd", "ssh", "ssh-add", "ssh-keygen",
  "ssh-copy-id", "mosh", "autossh", "tee", "sponge", "truncate", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum",
  "cmp", "git-crypt", "sops", "test-path", "get-item", "get-itemproperty", "get-acl", "set-acl", "icacls", "resolve-path", "split-path", "join-path",
  "remove-item", "ri", "del", "erase", "new-item", "ni", "write-host", "write-output", "unblock-file", "get-filehash", "move-item", "mi",
  "rename-item", "get-childitem", "gci", "security"]);
// Commands that copy or archive: their LAST positional argument is a destination, not a source.
const COPIERS = new Set(["cp", "scp", "rsync", "ditto", "install", "copy-item", "cpi", "copy", "robocopy", "xcopy"]);
// Commands that read a whole directory they are given: copiers, archivers, and searchers that print lines
// (a list of file names or a count, `grep -rl` / `-c` / `-q`, is not a read; see exposing()). Whether a
// search pattern matches every line is not guessed at.
const DIR_COPIERS = new Set(["tar", "bsdtar", "gtar", "zip", "7z", "7za", "7zz", "rar", "cp", "rsync", "scp", "ditto", "copy-item", "cpi",
  "robocopy", "xcopy", "compress-archive"]);
const DIR_SEARCHERS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "select-string", "sls", "findstr"]);
const SEARCHERS = new Set(["grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack", "ack-grep", "awk", "gawk", "mawk", "nawk", "sed", "perl",
  "select-string", "sls", "findstr", "where-object", "?"]);
// Flags whose value is a file the command USES (an identity, a config, an env file), not one it shows.
const USE_FLAGS = new Set(["--kubeconfig", "--env-file", "--userconfig", "--netrc-file", "--private-key", "--key-file", "--identity-file",
  "--keyfile", "--key", "--cert", "--cacert", "--capath", "--certificate", "--ca-certificate", "-inkey", "-key", "-signkey", "-cakey", "-cert",
  "-certfile", "--config", "--ssh-key"]);
const SSH_FAMILY = new Set(["scp", "sftp", "rsync", "ssh", "autossh", "mosh", "sshfs"]);
const SSH_USE = new Set(["-i", "-F", "-o", "-S", "-e", "-J"]);
const QUIET = /^-(?:[a-z]*[qlcL][a-z]*|-quiet|-files-with-matches|-files-without-match|-count|-silent)$/;
const INTERP = /^(?:python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun|perl|ruby|php|osascript|lua)$/;
const INLINE = new Set(["-c", "-e", "-E", "-p", "-r", "--eval", "--print", "eval"]);
const LITERAL = /(["'`])([^"'`\n]{1,512})\1/g;
const CODE_FORMS = [[/\bkeyring\.get_password\b|\bSecItemCopyMatching\b|\bSecKeychainFindGenericPassword\b/, "keychain-db"], [/\bspwd\.getsp(?:all|nam)\b|\bgetspnam\b/, "shadow"]];
const REDUCERS = new Set(["wc", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum", "cmp", "test", "["]);
const HISTORY_CMDS = new Set(["history", "fc", "get-history", "h", "ghy"]);
const LOGINS = new Set(["docker", "podman", "helm", "oras", "crane", "skopeo", "nerdctl", "buildah", "finch"]);
const DOTNET_READ = /::(?:ReadAll(?:Text|Bytes|Lines)|OpenRead|OpenText|Copy)$/i;
const PS_HISTORY = /HistorySavePath|ConsoleHost_history/i;
const PS_SEARCH = /\b(?:Select-String|sls|findstr|Where-Object)\b|-match\b/i;
const PS_HINT = /\b(?:Get-Content|gc|Copy-Item|Select-String|sls|Get-ChildItem|gci|Export-PfxCertificate|certutil|Get-AzAccessToken)\b|\$env:/i;

// Commands whose job is to show, copy, search, archive or send a file they are given. A command word outside
// this list is judged only on a tool call's own shell command (ctx.shell), never in prose, where the first
// word of a sentence reads as a command.
const READERS = new Set(["cat", "less", "more", "head", "tail", "bat", "batcat", "nl", "tac", "rev", "strings", "xxd", "od", "hexdump", "hd",
  "base64", "base32", "uuencode", "jq", "yq", "gojq", "awk", "gawk", "mawk", "nawk", "sed", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack",
  "cut", "sort", "uniq", "column", "fold", "paste", "diff", "sdiff", "vi", "vim", "nvim", "nano", "emacs", "code", "subl", "open", "view", "cp",
  "scp", "rsync", "ditto", "tar", "bsdtar", "gtar", "zip", "7z", "7za", "7zz", "rar", "gzip", "bzip2", "xz", "zstd", "dd", "openssl", "sqlite3",
  "curl", "wget", "nc", "ncat", "socat", "type", "get-content", "gc", "copy-item", "cpi", "copy", "select-string", "sls", "format-hex", "fhx",
  "compress-archive", "robocopy", "xcopy", "findstr", "iconv", "chainbreaker", "plutil", "defaults", "gsutil", "rclone", "tee", "xargs"]);
const INPUT_FLAGS = new Set(["-in", "--in", "-input", "--input", "-f", "--file"]);
const URL = /^[a-z][a-z0-9+.-]*:\/\//i;
const positional = (rest) => rest.filter((t) => !t.startsWith("-"));
const nextSearch = (segs, k) => { // the segment a pipe from segs[k] feeds that searches, walking the pipeline
  for (let j = k; j < segs.length - 1 && segs[j].sep === "|"; j++) { const s = segs[j + 1]; if (s.cw && SEARCHERS.has(s.cw.binary)) return s; }
  return null;
};
const intoLogin = (segs, k) => {
  const n = segs[k].sep === "|" ? segs[k + 1] : null;
  return !!(n && n.cw && LOGINS.has(n.cw.binary) && n.rest.includes("login") && n.rest.includes("--password-stdin"));
};
const secretSearch = (seg) => !!seg && seg.rest.some((t) => !credPathKind(t) && SECRET_WORD.test(t));

// The path arguments one segment reads: positional tokens (sources only for a copier), `<` targets,
// `@file` / `if=file`, skipping values of flags that use a file.
// Each entry is { p, flagged }: `flagged` when the word follows an option of a command that is not a known
// reader, where it is most likely that option's value (`osslsigncode -pkcs12 cert.pfx` signs with the key).
function readArgs(seg) {
  const b = seg.cw.binary, out = [];
  const rest = seg.rest;
  const ssh = SSH_FAMILY.has(b), reader = READERS.has(b) || INTERP.test(b);
  const pos = [];
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (USE_FLAGS.has(t.toLowerCase()) || (ssh && SSH_USE.has(t))) { i++; continue; }
    if (t.startsWith("-")) continue;
    if (URL.test(t)) continue;
    if (t.startsWith("@")) { out.push({ p: t.slice(1) }); continue; }
    if (/^if=/.test(t)) { out.push({ p: t.slice(3) }); continue; }
    const at = t.indexOf("=@");
    if (at > 0) { out.push({ p: t.slice(at + 2) }); continue; }
    if (t.includes("=")) continue;
    const prev = rest[i - 1] || "";
    pos.push({ p: t, flagged: !reader && /^-/.test(prev) && !prev.includes("=") && !INPUT_FLAGS.has(prev.toLowerCase()) });
  }
  out.push(...(COPIERS.has(b) && pos.length > 1 ? pos.slice(0, -1) : pos));
  return out;
}

function exposing(seg) {
  const b = seg.cw.binary;
  if (NON_EXPOSING.has(b)) return false;
  if (b === "git") return ["diff", "show", "blame", "cat-file"].includes(seg.rest.find((t) => !t.startsWith("-")) || "");
  if ((b === "sed" || b === "perl") && seg.rest.some((t) => /^-[a-z]*i/.test(t))) return false;
  if (SEARCHERS.has(b) && b !== "awk" && seg.rest.some((t) => QUIET.test(t))) return false;
  return true;
}

// A command that prints or exports a stored secret without naming its file.
function commandForm(seg, segs, k) {
  const b = seg.cw.binary, rest = seg.rest, low = rest.map((t) => t.toLowerCase());
  const sub = positional(low);
  if (b === "security") {
    if (["find-generic-password", "find-internet-password", "dump-keychain"].includes(sub[0])) return "keychain-db";
    if (sub[0] === "export") { const ti = low.indexOf("-t"); const t = ti >= 0 ? low[ti + 1] : "all"; if (["privkeys", "allkeys", "identities", "all"].includes(t)) return "private-key"; }
    return null;
  }
  if (b.startsWith("docker-credential-") && low.includes("get")) return "token-store";
  if (b === "git" && ((sub[0] === "credential" && ["fill", "get"].includes(sub[1])) || (/^credential-/.test(sub[0] || "") && sub.includes("get")))) return "token-store";
  if (b.startsWith("git-credential-") && low.includes("get")) return "token-store";
  if (b === "keyring" && sub[0] === "get") return "keychain-db";
  if (b === "secret-tool" && ["lookup", "search"].includes(sub[0])) return "keychain-db";
  if ((b === "gpg" || b === "gpg2") && low.some((t) => /^--export-secret-(?:sub)?keys?$/.test(t))) return "private-key";
  if (b === "certutil" && low.includes("-exportpfx")) return "private-key";
  if (b === "export-pfxcertificate") return "private-key";
  if (b === "getent" && (sub[0] === "shadow" || sub[0] === "gshadow")) return "shadow";
  if (b === "unshadow") return "shadow";
  if (b === "dscl" && low.some((t) => /shadowhashdata/.test(t))) return "shadow";
  let tok = null;
  if (b === "gh" && sub[0] === "auth" && (sub[1] === "token" || (sub[1] === "status" && (low.includes("-t") || low.includes("--show-token"))))) tok = "token-store";
  else if (b === "az" && sub[0] === "account" && sub[1] === "get-access-token") tok = "token-store";
  else if (b === "get-azaccesstoken") tok = "token-store";
  else if (b === "gcloud" && sub.includes("auth") && sub.some((t) => t === "print-access-token" || t === "print-identity-token")) tok = "token-store";
  else if (b === "aws" && sub[0] === "configure" && ((sub[1] === "get" && /secret|session_token|access_key/.test(sub[2] || "")) || sub[1] === "export-credentials")) tok = "secret-file";
  else if (b === "kubectl" && sub[0] === "config" && sub[1] === "view" && low.includes("--raw")) tok = "secret-file";
  else if (b === "heroku" && sub[0] === "auth:token") tok = "token-store";
  else if (b === "vault" && sub[0] === "print" && sub[1] === "token") tok = "token-store";
  if (tok && !intoLogin(segs, k)) return tok;
  return null;
}

// A recursive search for secrets or key files rooted outside any project.
function broadSearch(seg) {
  const b = seg.cw.binary, rest = seg.rest;
  const roots = (list) => list.some((t) => broadRoot(t) || (/[*?]/.test(t) && broadRoot(t.replace(/[/\\][^/\\]*[*?][^/\\]*$/, ""))));
  if (["grep", "egrep", "fgrep", "zgrep"].includes(b)) {
    const rec = rest.some((t) => /^-[A-Za-z]*[rR]/.test(t) || t === "--recursive" || t === "--dereference-recursive");
    return rec && secretSearch(seg) && roots(positional(rest)) ? "secret-file" : null;
  }
  if (b === "rg" || b === "ag" || b === "ack") return secretSearch(seg) && roots(positional(rest)) ? "secret-file" : null;
  if (b === "findstr") return rest.some((t) => /^\/[a-z]*s/i.test(t)) && secretSearch(seg) && roots(rest.filter((t) => !/^\/[a-z]+$/i.test(t))) ? "secret-file" : null;
  if (b === "select-string" || b === "sls") {
    const pi = rest.findIndex((t) => /^-path$/i.test(t) || /^-literalpath$/i.test(t));
    return pi >= 0 && secretSearch(seg) && roots([rest[pi + 1] || ""]) ? "secret-file" : null;
  }
  if (b === "find") {
    const start = [];
    for (const t of rest) { if (/^[-(!]/.test(t)) break; start.push(t); }
    if (!roots(start)) return null;
    for (let i = 0; i < rest.length - 1; i++) if (/^-(?:i?name|i?path|i?wholename)$/.test(rest[i]) && credGlob(rest[i + 1])) return "private-key";
    return null;
  }
  if (seg.ps && (b === "get-childitem" || b === "gci" || b === "dir" || b === "ls")) {
    if (!rest.some((t) => /^-r(?:e(?:c(?:u(?:r(?:se?)?)?)?)?)?$/i.test(t))) return null;
    let globbed = false, rooted = false;
    for (let i = 0; i < rest.length; i++) {
      const t = rest[i], lt = t.toLowerCase();
      if ((lt === "-include" || lt === "-filter") && rest[i + 1]) { if (credGlob(rest[i + 1])) globbed = true; i++; continue; }
      if (lt === "-path" || lt === "-literalpath") { if (rest[i + 1] && roots([rest[i + 1]])) rooted = true; i++; continue; }
      if (!t.startsWith("-") && roots([t])) rooted = true;
    }
    return globbed && rooted ? "private-key" : null;
  }
  return null;
}

function inlineCode(seg) {
  const b = seg.cw.binary;
  if (!INTERP.test(b)) return null;
  const rest = seg.rest;
  for (let i = 0; i < rest.length - 1; i++) {
    if (!INLINE.has(rest[i])) continue;
    const code = String(rest[i + 1] || "").slice(0, 20000);
    for (const [re, kind] of CODE_FORMS) if (re.test(code)) return kind;
    LITERAL.lastIndex = 0;
    let m, n = 0;
    while ((m = LITERAL.exec(code)) !== null && n++ < 256) {
      const k = credPathKind(m[2]);
      if (k && k !== "history") return k;
    }
  }
  return null;
}

function segmentsHit(segs, strict) {
  for (let k = 0; k < segs.length; k++) {
    const seg = segs[k];
    // A .NET file read (`[IO.File]::ReadAllText('…')`): PowerShell's reader makes its argument list the next
    // segment, whose path would otherwise read as a command word.
    const prev = segs[k - 1];
    if (prev && prev.sep === "(" && (prev.tokens || []).some((t) => DOTNET_READ.test(t))) {
      for (const t of seg.tokens || []) { const kd = credPathKind(t); if (kd && kd !== "history") return kd; }
    }
    if (!seg.cw) continue;
    const b = seg.cw.binary;
    const form = commandForm(seg, segs, k) || broadSearch(seg) || inlineCode(seg);
    if (form) return form;
    if (HISTORY_CMDS.has(b) && secretSearch(nextSearch(segs, k))) return "history";
    // In prose a sentence starts with a capital ("Copy the file … to .env"); a command word does not, except a
    // PowerShell cmdlet (Get-Content).
    const known = (READERS.has(b) || INTERP.test(b)) && (!strict || seg.raw.includes("-") || seg.raw === seg.raw.toLowerCase());
    const show = exposing(seg) && (!strict || known);
    // A `<` redirect feeds the file to the command's stdin, which a filter (tee, cat, sort) passes on;
    // only a counter or a hash reduces it.
    if (!REDUCERS.has(b) && (!strict || known)) for (const r of seg.reads || []) { const kd = credPathKind(r); if (kd && kd !== "history") return kd; }
    for (const { p, flagged } of readArgs(seg)) {
      const kd = credPathKind(p);
      if (kd === "private-key" && flagged) continue;
      if (kd === "history") {
        if ((SEARCHERS.has(seg.cw.binary) && secretSearch(seg)) || secretSearch(nextSearch(segs, k))) return "history";
        continue;
      }
      if (kd && show) return kd;
      if (!kd && show && (DIR_COPIERS.has(b) || DIR_SEARCHERS.has(b))) { const dk = credDirKind(p); if (dk) return dk; }
    }
  }
  return null;
}

// The credential kind a command reads, or null. `ps`: the command is PowerShell; without it a command that
// looks like PowerShell is read both ways. `strict`: the text is not known to be a shell command (a prompt,
// a model's output, MCP arguments), so a path counts only as the argument of a known reader.
export function credAccessKind(cmd, { ps = false, strict = false } = {}) {
  try {
    const s = String(cmd || "");
    if (!s || s.length > MAX || !CRED_HINT.test(s)) return null;
    if (PS_HISTORY.test(s) && PS_SEARCH.test(s) && SECRET_WORD.test(s)) return "history";
    const readings = ps ? [commandSegments(s, true)] : PS_HINT.test(s) ? [commandSegments(s, false), commandSegments(s, true)] : [commandSegments(s, false)];
    for (const segs of readings) { const k = segmentsHit(segs, strict); if (k) return k; }
    return null;
  } catch { return null; }
}
