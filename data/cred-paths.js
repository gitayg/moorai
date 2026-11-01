// Where credentials live on a developer machine, as path rules: one decision shared by the #55 command
// reader (data/cred-access.js), the hook's Read / PowerShell / MCP file paths (cli/hook-core.mjs
// decideCredFileRead) and its Grep check (cli/cred-grep.mjs).
//
// credPathKind(path) names what a path holds, or null:
//   secret-file    T1552.001 Credentials In Files: env files, package-registry, database and cloud CLI
//                  credential files
//   token-store    T1528 Steal Application Access Token: a CLI's stored OAuth / access token
//   private-key    T1552.004 Private Keys: SSH keys, key containers, GnuPG secret keys, TLS key files
//   history        T1552.003 Shell History: shell and REPL history files (judged only when searched for a
//                  secret, see data/cred-access.js)
//   browser-store  T1555.003 Credentials from Web Browsers: login, cookie and key stores in a browser profile
//   keychain-db    T1555.001 Keychain: a macOS keychain database file
//   shadow         T1003.008 /etc/passwd and /etc/shadow: the password-hash stores (/etc/passwd itself holds
//                  no hash on a current system and is not one)
//
// The path is matched by its END, after `\` -> `/` and lower-casing, so `~/.npmrc`, `$HOME/.npmrc`,
// `C:\Users\bob\.npmrc` and `$env:USERPROFILE\.npmrc` read the same. Templates (.env.example / .sample /
// .template) and public halves (`*.pub`, known_hosts, authorized_keys, ssh config) are not credentials.
//
// privateKeyText(text): the text of a file IS a private key (its first non-blank line is a PEM, OpenSSH,
// PGP or PuTTY private-key header), whatever the file is called. A source file that mentions the header
// further down is not one.
//
// Browser-safe (no node: imports). Bounded: a path over 4096 characters is not classified; every regex is
// anchored at the end of one path.
const MAX_PATH = 4096;

// `\` -> `/`, lower case, `.` and `..` segments folded (`~/Library/Safari/../Cookies/x` is `~/Library/Cookies/x`).
function norm(p) {
  const s = String(p || "").replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  if (!/(?:^|\/)\.{1,2}(?:\/|$)/.test(s)) return s;
  const out = [];
  for (const x of s.split("/")) {
    if (x === ".") continue;
    if (x === ".." && out.length && out[out.length - 1] !== ".." && out[out.length - 1] !== "") { out.pop(); continue; }
    out.push(x);
  }
  return out.join("/");
}

const ENV_TEMPLATE = /\.env\.(?:example|sample|template)$/;
const SECRET_BASE = new Set([".env", ".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", "pgpass.conf", ".git-credentials", ".my.cnf",
  ".mylogin.cnf", ".vault-token", ".s3cfg", ".boto", ".dockercfg", ".htpasswd", ".databrickscfg", ".sentryclirc"]);
const SECRET_END = [
  /(?:^|\/)\.aws\/credentials$/,
  /(?:^|\/)\.kube\/config$/,
  /(?:^|\/)\.terraform\.d\/credentials\.tfrc\.json$/,
  /(?:^|\/)\.cargo\/credentials(?:\.toml)?$/,
  /(?:^|\/)\.gem\/credentials$/,
  /(?:^|\/)rclone\/rclone\.conf$/,
  /(?:^|\/)\.oci\/config$/,
  /(?:^|\/)\.snowflake\/connections\.toml$/,
  /(?:^|\/)\.pulumi\/credentials\.json$/,
  /(?:^|\/)\.config\/stripe\/config\.toml$/,
  /(?:^|\/)ngrok2?\/ngrok\.yml$/,
  /(?:^|\/)gcloud\/legacy_credentials\/[^/]+\/(?:adc\.json|\.boto)$/,
  /(?:^|\/)gcloud\/application_default_credentials\.json$/
];
const TOKEN_END = [
  /(?:^|\/)(?:\.config\/gh|github cli)\/hosts\.yml$/,
  /(?:^|\/)\.docker\/config\.json$/,
  /(?:^|\/)\.config\/hub$/,
  /(?:^|\/)gcloud\/(?:credentials|access_tokens)\.db$/,
  /(?:^|\/)\.azure\/(?:accesstokens\.json|msal_token_cache\.(?:json|bin)|service_principal_entries\.json)$/,
  /(?:^|\/)msal_token_cache(?:\.bin)?$/,
  /(?:^|\/)\.aws\/(?:sso|cli)\/cache\/[^/]+\.json$/,
  /(?:^|\/)\.claude\/\.credentials\.json$/,
  /(?:^|\/)\.codex\/auth\.json$/,
  /(?:^|\/)\.gemini\/oauth_creds\.json$/,
  /(?:^|\/)github-copilot\/(?:hosts|apps)\.json$/,
  /(?:^|\/)com\.vercel\.cli\/auth\.json$/,
  /(?:^|\/)\.vercel\/auth\.json$/,
  /(?:^|\/)\.?netlify\/config\.json$/,
  /(?:^|\/)\.fly\/config\.yml$/,
  /(?:^|\/)doctl\/config\.yaml$/,
  /(?:^|\/)hcloud\/cli\.toml$/,
  /(?:^|\/)\.?wrangler\/config\/default\.toml$/,
  /(?:^|\/)\.supabase\/access-token$/,
  /(?:^|\/)configstore\/firebase-tools\.json$/
];
const SSH_PUBLIC = new Set(["known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2", "environment", "rc"]);
const KEY_EXT = /\.(?:key|p12|pfx|ppk|jks|keystore|p8|pkcs12|pvk)$/;
const KEY_END = [
  /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?:[-_.][^/]*)?$/,
  /(?:^|\/)\.gnupg\/(?:private-keys-v1\.d\/[^/]+|secring\.gpg)$/,
  /(?:^|\/)etc\/ssl\/private\/[^/]+$/,
  /(?:^|\/)etc\/ssh\/ssh_host_[a-z0-9]+_key$/,
  /(?:^|\/)[^/]*(?:key|priv)[^/]*\.pem$/
];
const HISTORY_BASE = new Set([".bash_history", ".zsh_history", ".zhistory", ".sh_history", ".history", ".python_history", ".mysql_history",
  ".psql_history", ".node_repl_history", ".rediscli_history", ".sqlite_history", ".irb_history", ".dbshell", "fish_history", "consolehost_history.txt"]);
const BROWSER_ROOT = /(?:^|\/)(?:google\/chrome(?: beta| canary)?|google-chrome(?:-beta|-unstable)?|chromium|bravesoftware|microsoft edge|microsoft-edge(?:-beta|-dev)?|vivaldi|opera software|opera|arc\/user data|yandex\/yandexbrowser|mozilla\/firefox|\.mozilla\/firefox|firefox\/profiles|librewolf|waterfox|thunderbird)\//;
const BROWSER_STORE = new Set(["login data", "login data for account", "web data", "cookies", "local state", "key4.db", "key3.db", "logins.json",
  "cookies.sqlite", "signons.sqlite"]);
const SAFARI_COOKIES = /(?:^|\/)library\/(?:containers\/com\.apple\.safari\/data\/library\/)?cookies\/cookies\.binarycookies$/;
const KEYCHAIN = [/\.keychain(?:-db)?$/, /(?:^|\/)library\/keychains\/[^/]+\/keychain-2\.db$/];
const SHADOW = [/^\/etc\/(?:shadow|gshadow|shadow-|gshadow-|master\.passwd|spwd\.db|security\/passwd|security\/opasswd)$/, /(?:^|\/)var\/db\/dslocal\/nodes\/[^/]+\/users\/[^/]+\.plist$/];

export function credPathKind(path) {
  if (typeof path !== "string" || !path || path.length > MAX_PATH || /[\r\n]/.test(path)) return null;
  const p = norm(path);
  if (!p) return null;
  const cut = p.lastIndexOf("/");
  const base = cut >= 0 ? p.slice(cut + 1) : p;
  const parent = cut >= 0 ? p.slice(0, cut) : "";
  if (SHADOW.some((r) => r.test(p))) return "shadow";
  if (KEYCHAIN.some((r) => r.test(p))) return "keychain-db";
  if ((BROWSER_STORE.has(base) && BROWSER_ROOT.test(p)) || SAFARI_COOKIES.test(p)) return "browser-store";
  if (HISTORY_BASE.has(base)) return "history";
  if (base.endsWith(".pub")) return null;
  if (/(?:^|\/)\.ssh$/.test(parent)) return SSH_PUBLIC.has(base) || base.endsWith(".sock") || base.startsWith("agent") ? null : "private-key";
  if (KEY_EXT.test(base) || KEY_END.some((r) => r.test(p))) return "private-key";
  if (TOKEN_END.some((r) => r.test(p))) return "token-store";
  if (ENV_TEMPLATE.test(base)) return null;
  if (SECRET_BASE.has(base) || /^\.env\.[^/]+$/.test(base) || /^[^/]+\.env$/.test(base) || SECRET_END.some((r) => r.test(p))) return "secret-file";
  return null;
}

// A directory that holds nothing but credentials of one kind: searching or archiving it reads them.
const CRED_DIRS = [
  [/(?:^|\/)\.ssh$/, "private-key"], [/(?:^|\/)\.gnupg$/, "private-key"], [/(?:^|\/)etc\/ssl\/private$/, "private-key"],
  [/(?:^|\/)\.aws$/, "secret-file"], [/(?:^|\/)\.azure$/, "token-store"], [/(?:^|\/)gcloud$/, "token-store"],
  [/(?:^|\/)\.docker$/, "token-store"], [/(?:^|\/)\.kube$/, "secret-file"], [/(?:^|\/)\.config\/gh$/, "token-store"],
  [/(?:^|\/)library\/keychains$/, "keychain-db"]
];
export function credDirKind(path) {
  if (typeof path !== "string" || !path || path.length > MAX_PATH) return null;
  const p = norm(path);
  for (const [r, k] of CRED_DIRS) if (r.test(p)) return k;
  return null;
}

// A search root that is not a project: the filesystem root, a home directory, the users root, /etc.
// Searching one of these for a secret word or a key file is credential discovery; searching a project
// directory for "token" is everyday code search. `home` (optional) is the caller's home directory.
export function broadRoot(path, home = "") {
  if (typeof path !== "string" || path.length > MAX_PATH) return false;
  const raw = path.trim();
  if (/^(?:~|\$home|\$\{home\}|\$env:userprofile|\$env:home|%userprofile%|%homepath%)[/\\]?$/i.test(raw)) return true;
  const p = norm(raw);
  if (p === "" && raw.startsWith("/")) return true;
  if (home && p === norm(home)) return true;
  return /^(?:\/|\/(?:users|home|root|etc|var|opt|private|mnt|media|volumes)|\/(?:users|home)\/[^/]+|[a-z]:|[a-z]:\/users|[a-z]:\/users\/[^/]+)$/.test(p);
}

// A word a search for secrets uses, read from the search pattern itself.
export const SECRET_WORD = /\b(?:pass(?:wd|word)?|secret|token|api[_-]?key|apikey|aws_secret|access[_-]?key|private[_ -]?key|credentials?|BEGIN [A-Z ]*PRIVATE)\b/i;
// A file-name glob that only a credential file matches (find -name, Get-ChildItem -Include, a Grep glob).
export const CRED_GLOB = /^\*?\.?(?:pem|key|p12|pfx|ppk|jks|keystore|kdbx|env)$|^(?:\*\.)?(?:pem|key|p12|pfx|ppk|kdbx)$|^id_(?:rsa|dsa|ecdsa|ed25519)?\*?$|^\.?env$|^credentials$|^\.?(?:npmrc|netrc|pgpass|git-credentials)$|^\*?_?history$|^login data$|^key[34]\.db$|^logins\.json$|^\*\.keychain(?:-db)?$|^wallet\.dat$/i;
export function credGlob(glob) {
  if (typeof glob !== "string" || !glob || glob.length > 256) return false;
  return glob.split(/[,{}]/).map((g) => g.trim().replace(/^["']|["']$/g, "").replace(/^\*\*\//, "")).some((g) => g && CRED_GLOB.test(g));
}

const KEY_HEADER = /^\s*(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-\d+:)/;
export function privateKeyText(text) {
  return typeof text === "string" && KEY_HEADER.test(text.slice(0, 4096));
}
