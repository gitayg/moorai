// Agent persistence — a foothold the agent installs so its code runs again after the session ends:
//   T1053.003  Scheduled Task/Job: Cron           — crontab edits, writes to /etc/cron* or the spool
//   T1543.001  Create or Modify System Process: Launch Agent — ~/Library/LaunchAgents plists + launchctl load
//   T1546.004  Event Triggered Execution: Unix Shell Configuration Modification — an rc file made to FETCH/EXEC
// plus the Windows equivalents (schtasks /create, a Run-key write) and a new systemd --user unit.
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
  /(?:>>?\s*\|?\s*["']?|(?<![\w-])tee\b[^\n;|&]{0,80}?)\/(?:etc\/cron[^\s;|&"']*|etc\/crontab\b|var\/spool\/cron[^\s;|&"']*)/i
];
// Launch agent / daemon: write a plist into a LaunchAgents/LaunchDaemons dir, or launchctl load it.
const LAUNCH = [
  /(?<![\w-])launchctl\s+(?:load|bootstrap|enable)\b[^\n;|&]{0,200}?Launch(?:Agents|Daemons)\b/i,
  /(?:>>?\s*\|?\s*["']?|(?<![\w-])(?:tee|cp|mv|install|ditto|Copy-Item|Move-Item)\b[^\n;|&]{0,160}?)[^\s;|&"']{0,80}?Library[\/\\]Launch(?:Agents|Daemons)[\/\\][^\s;|&"']{0,80}?\.plist\b/i
];
// A new user-level systemd unit enabled to start on login.
const SYSTEMD_USER = /(?<![\w-])systemctl\s+--user\s+(?:enable|--now\s+enable|enable\s+--now)\b/i;
// Windows: a scheduled task created, or a value written under a Run key.
const WINDOWS = [
  /(?<![\w-])schtasks(?:\.exe)?\b[^\n]{0,120}?\/create\b/i,
  /(?<![\w-])reg(?:\.exe)?\s+add\b[^\n]{0,160}?\\(?:CurrentVersion\\Run(?:Once)?|Run(?:Once)?)\b/i,
  /(?<![\w-])(?:New|Set)-ItemProperty\b[^\n]{0,200}?\\Run(?:Once)?\b/i
];

// An rc file being written AND the command fetching or executing — the persistence shape, not an ordinary
// alias/PATH edit.
const RC_WRITE = /(?:>>|(?<![\w-])tee\s+-a\b|(?<![\w-])Add-Content\b)[^\n;|&]{0,160}?(?:\.zshrc|\.bashrc|\.bash_profile|\.zprofile|\.zshenv|\.profile|\.config[\/\\]fish[\/\\]config\.fish)\b/i;
const FETCH_EXEC = /\b(?:curl|wget)\b|\beval\b|\bbase64\s+-d\b|\bpython[0-9.]*\s+-c\b|(?:source|\.)\s+<\(|<\(\s*(?:curl|wget)|\bnc\b|\|\s*(?:ba|z)?sh\b|Invoke-Expression|\bIex\b/i;

function any(list, s) { return list.some((r) => r.test(s)); }

export function persistenceHit(text) {
  if (typeof text !== "string" || !text) return false;
  const s = text.length > MAX ? text.slice(0, MAX) : text;
  if (any(CRON, s) || any(LAUNCH, s) || SYSTEMD_USER.test(s) || any(WINDOWS, s)) return true;
  return RC_WRITE.test(s) && FETCH_EXEC.test(s);
}
