// Agent persistence — a foothold the agent installs so its code runs again after the session ends:
//   T1053.003  Scheduled Task/Job: Cron           — crontab edits, writes to /etc/cron* or the spool
//   T1543.001  Create or Modify System Process: Launch Agent — ~/Library/LaunchAgents plists + launchctl load
//   T1546.004  Event Triggered Execution: Unix Shell Configuration Modification — an rc file made to FETCH/EXEC,
//              capture a sudo/ssh password, put a temp dir on PATH or launch from one
// plus the Windows equivalents (schtasks /create, Register-ScheduledTask, a Run-key write) and a new systemd
// --user unit. The file-writing tools reach the same classes through persistencePathKind below.
//
// Credited on threat #46 (a host-level change the hook holds for approval). The decision is persistenceHit,
// consulted once per text from a single detector. The hard part is the rc-file case: developers edit
// ~/.zshrc and ~/.bashrc constantly, so an rc WRITE on its own is NOT flagged — only an rc write whose
// content also fetches or executes (the shape a persistence implant uses). Browser-safe and bounded; every
// regex is anchored over a short span. test/agent-persistence.test.mjs holds the benign rc edits it must
// stay silent on.
const MAX = 20_000;

// Cron: install/edit a crontab, or write to a system cron location. `crontab -l` (list) is excluded.
const CRON = [
  /(?<![\w-])crontab\s+(?:-e\b|-\s*(?:$|[;&|])|["']?[^\s;|&-][^\n;|&]{0,120})/i,
  /\|\s*crontab\b(?![^\n]{0,8}-l\b)/i,
  /(?:>>?\s*\|?\s*["']?|(?<![\w-])tee\b[^\n;|&]{0,80}?)\/(?:etc\/cron[^\s;|&"']*|etc\/crontab\b|var\/spool\/cron[^\s;|&"']*)/i,
  // A file copied, linked or downloaded into a cron location, and the macOS crontab spool (/usr/lib/cron/tabs,
  // /var/at/tabs). Reading one (cat, ls, crontab -l) is not matched.
  /(?:>>?\s*\|?\s*["']?|(?<![\w-])(?:tee|cp|mv|install|ln|rsync|ditto|curl|wget|Copy-Item|Move-Item)\b[^\n;|&]{0,160}?)(?:\/private)?\/(?:etc\/cron[^\s;|&"']*|etc\/(?:ana)?crontab\b|var\/spool\/cron[^\s;|&"']*|usr\/lib\/cron\/tabs\b|var\/at\/tabs\b)/i
];
// Launch agent / daemon: write a plist into a LaunchAgents/LaunchDaemons dir, or launchctl load it.
const LAUNCH = [
  /(?<![\w-])launchctl\s+(?:load|bootstrap|enable)\b[^\n;|&]{0,200}?Launch(?:Agents|Daemons)\b/i,
  /(?:>>?\s*\|?\s*["']?|(?<![\w-])(?:tee|cp|mv|install|ditto|Copy-Item|Move-Item)\b[^\n;|&]{0,160}?)[^\s;|&"']{0,80}?Library[\/\\]Launch(?:Agents|Daemons)[\/\\][^\s;|&"']{0,80}?\.plist\b/i,
  // Created or modified another way: linked, synced or downloaded in, or edited with defaults / PlistBuddy /
  // plutil / sed -i (T1543.001 is "create or modify"); `launchctl submit` defines a job with no plist at all.
  /(?<![\w-])(?:ln|rsync|curl|wget|defaults\s+write|PlistBuddy\b[^\n;|&]{0,160}?(?:Set|Add|Merge|Import|Delete)\b|plutil\s+-(?:replace|insert|remove|convert)|sed\s+-i|perl\s+-p?i)\b[^\n;|&]{0,200}?Library[\/\\]Launch(?:Agents|Daemons)[\/\\][^\s;|&"']{0,80}?\.plist\b/i,
  /(?<![\w-])launchctl\s+submit\b/i
];
// A new user-level systemd unit enabled to start on login.
const SYSTEMD_USER = /(?<![\w-])systemctl\s+--user\s+(?:enable|--now\s+enable|enable\s+--now)\b/i;
// Windows: a scheduled task created, or a value written under a Run key.
const WINDOWS = [
  /(?<![\w-])schtasks(?:\.exe)?\b[^\n]{0,120}?\/create\b/i,
  /(?<![\w-])reg(?:\.exe)?\s+add\b[^\n]{0,160}?\\(?:CurrentVersion\\Run(?:Once)?|Run(?:Once)?)\b/i,
  /(?<![\w-])(?:New|Set)-ItemProperty\b[^\n]{0,200}?\\Run(?:Once)?\b/i,
  /(?<![\w-])Register-ScheduledTask\b/i
];

// An rc file being written AND the command fetching or executing — the persistence shape, not an ordinary
// alias/PATH edit.
const RC_WRITE = /(?:>>|(?<![\w-])tee\s+-a\b|(?<![\w-])Add-Content\b)[^\n;|&]{0,160}?(?:\.zshrc|\.bashrc|\.bash_profile|\.zprofile|\.zshenv|\.profile|\.config[\/\\]fish[\/\\]config\.fish)\b/i;
const FETCH_EXEC = /\b(?:curl|wget)\b|\beval\b|\bbase64\s+-d\b|\bpython[0-9.]*\s+-c\b|(?:source|\.)\s+<\(|<\(\s*(?:curl|wget)|\bnc\b|\|\s*(?:ba|z)?sh\b|Invoke-Expression|\bIex\b/i;
// Every startup file ATT&CK T1546.004 names (bash and zsh, login, interactive and logout, user and system-wide)
// plus fish, written by an overwrite, a plain tee, an in-place edit or a download as well as an append.
const RC_FILE = String.raw`(?:\.(?:zshrc|bashrc|bash_profile|bash_login|bash_logout|zprofile|zshenv|zlogin|zlogout|profile)\b|\.config[\/\\]fish[\/\\](?:config\.fish|conf\.d[\/\\][^\s;|&"']{1,80}?\.fish)\b|\/etc\/(?:profile\b(?:\.d\/[^\s;|&"']{1,80})?|zshenv\b|zprofile\b|zshrc\b|zlogin\b|zlogout\b|bashrc\b|bash\.bashrc\b))`;
const RC_WRITE_ANY = new RegExp(String.raw`(?:>>?\s*\|?\s*["']?|(?<![\w-])(?:tee|Add-Content|Set-Content|Out-File)\b[^\n;|&]{0,160}?|(?<![\w-])(?:sed\s+-i\S{0,8}|perl\s+-p?i\S{0,8})(?:\s+-e)?\s+(?:'[^'\n]{0,400}'|"[^"\n]{0,400}"|[^\s;|&'"]{1,200})\s+["']?|(?<![\w-])(?:curl|wget)\b[^\n;|&]{0,160}?\s-(?:o|O|-output)\s+["']?)[^\s;|&"']{0,80}?` + RC_FILE, "i");
// What a startup file is made to do, beyond fetch/exec: a security-relevant command shadowed by an alias or
// function that captures its input (the sudo password grab), a temp directory put first on PATH, a library
// injected into every process, or a program run from a temp directory or in the background on each start.
const RC_EXTRA = [
  /\b(?:alias\s+|function\s+)?(?:sudo|su|doas|ssh|scp|sftp|ssh-add|passwd|gpg|git|security|kinit)\s*(?:=|\(\s*\))[^\n]{0,400}?(?:\bread\s+-[a-z]*s|\btee\b|\bcurl\b|\bwget\b|\bnc\b|\/tmp\/|\/dev\/shm\/|\bbase64\b)/i,
  /\bPATH=["']?(?:\/private)?\/(?:tmp|var\/tmp|dev\/shm)\b[^:\s"']{0,120}:/i,
  /\b(?:LD_PRELOAD|DYLD_INSERT_LIBRARIES)=/,
  /(?:^|[;&|(`]|\$\(|\bnohup\s+|\bsetsid\s+)\s*(?:\/private)?\/(?:tmp|var\/tmp|dev\/shm)\/[^\s;&|'"]{1,200}/m,
  /\bnohup\b[^\n]{0,200}&\s*(?:disown\b|$|['"])/m
];
// FETCH_EXEC without the bare `eval` and `source <(…)`: a startup file's tool-init lines (`eval "$(pyenv init -)"`,
// `eval "$(brew shellenv)"`, `source <(fzf --zsh)`, conda's `eval "$__conda_setup"`) are what installers tell
// people to add, so those count only when what they run is a file's or a decoder's output (cat, base64, xxd …);
// a fetch, a decode or a temp-dir path in them is caught by the other checks. The shell-append path above keeps
// FETCH_EXEC whole, so no verdict it gave is lowered.
const FETCH_EXEC_RC = /\b(?:curl|wget)\b|\bbase64\s+-d\b|\bpython[0-9.]*\s+-c\b|\bnc\b|\|\s*(?:ba|z)?sh\b|Invoke-Expression|\bIex\b/i;
const EVAL_RISKY = /(?:\beval|\bsource|(?:^|[\s;&|])\.)\s+["']?(?:<\(|\$\()\s*(?:cat|head|tail|xxd|rev|openssl|echo|printf|base64|od|dd)\b/im;
// The content check on text added to a startup file (a shell append above, or a Write / Edit judged on the
// lines it adds: cli/hook-core.mjs decidePersistenceWrite).
export function rcPayloadHit(text) {
  if (typeof text !== "string" || !text) return false;
  const s = text.length > MAX ? text.slice(0, MAX) : text;
  return FETCH_EXEC_RC.test(s) || EVAL_RISKY.test(s) || RC_EXTRA.some((r) => r.test(s));
}

function any(list, s) { return list.some((r) => r.test(s)); }

export function persistenceHit(text) {
  if (typeof text !== "string" || !text) return false;
  const s = text.length > MAX ? text.slice(0, MAX) : text;
  if (any(CRON, s) || any(LAUNCH, s) || SYSTEMD_USER.test(s) || any(WINDOWS, s)) return true;
  return (RC_WRITE.test(s) && FETCH_EXEC.test(s)) || (RC_WRITE_ANY.test(s) && rcPayloadHit(s));
}

// The same footholds reached by a file-writing tool (Write / Edit / MultiEdit, an MCP filesystem write):
// the target path is all there is to read, so it is classified here and judged by cli/hook-core.mjs
// decidePersistenceWrite. "cron" and "launchd": any write is the foothold, as a shell write there is above.
// "shell-rc": only text added that rcPayloadHit flags. "ide-extension": a file written into an editor's
// extension or plugin directory (VS Code and its forks, JetBrains plugins, Eclipse dropins) is a side-load,
// T1176.002, credited on #57 with the --install-extension side-load.
const PATH_CRON = /(?:^|\/)(?:private\/)?(?:etc\/crontab|etc\/anacrontab|etc\/cron\.[a-z]{1,16}\/[^/]{1,255}|var\/spool\/cron\/(?:crontabs\/|tabs\/)?[^/]{1,255}|usr\/lib\/cron\/tabs\/[^/]{1,255}|var\/at\/tabs\/[^/]{1,255})$/i;
const PATH_LAUNCHD = /(?:^|\/)Library\/Launch(?:Agents|Daemons)\/[^/]{1,255}\.plist$/i;
const PATH_RC = /(?:^|\/)(?:\.(?:zshrc|bashrc|bash_profile|bash_login|bash_logout|zprofile|zshenv|zlogin|zlogout|profile)|\.config\/fish\/(?:config\.fish|conf\.d\/[^/]{1,255}\.fish))$|^(?:\/private)?\/etc\/(?:profile|profile\.d\/[^/]{1,255}|zshenv|zprofile|zshrc|zlogin|zlogout|bashrc|bash\.bashrc)$/i;
const PATH_IDE = /(?:^|\/)\.(?:vscode|vscode-insiders|vscode-server|vscode-server-insiders|vscode-oss|cursor|cursor-server|windsurf|windsurf-server)\/extensions\/[^/]{1,255}\/|(?:^|\/)JetBrains\/[^/]{1,80}\/plugins\/[^/]{1,255}|(?:^|\/)[^/]{0,40}eclipse[^/]{0,40}\/(?:[^/]{1,80}\/){0,3}dropins\/[^/]{1,255}/i;
export function persistencePathKind(path) {
  if (typeof path !== "string" || !path || path.length > 4096) return null;
  const p = path.replace(/\\/g, "/");
  if (PATH_CRON.test(p)) return "cron";
  if (PATH_LAUNCHD.test(p)) return "launchd";
  if (PATH_RC.test(p)) return "shell-rc";
  if (PATH_IDE.test(p)) return "ide-extension";
  return null;
}
