// Clear Command History (ATT&CK T1070.003) and Prevent Command History Logging (T1690) issued through an
// AI coding agent's shell — the shell-history sibling of agent-history-tamper (#73), which covers the
// agent's OWN transcript stores (data/agent-state-paths.js). These are the shell's record of what the
// agent ran: clearing it, deleting or emptying the history file, or turning logging off for the session.
//
// Plain patterns (no refine), added to a detector for threat 73, like INHIBIT_RECOVERY on #43. Each is
// bounded and linear (fixed {0,N} spans, no nested unbounded quantifier). Reading, listing, copying,
// growing the history and re-enabling it stay silent — those are the hard negatives an agent runs doing
// ordinary shell work (test/shell-history-tamper.test.mjs). Content-free: the detector reports one span.
//
// The history files an interactive shell keeps, each from the shell's own documentation. `.history` alone
// is too generic to list; the specific names are not.
const HIST_FILE = String.raw`(?:\.bash_history|\.zsh_history|\.zhistory|\.sh_history|\.histfile|\.local\/share\/fish\/fish_history|fish_history|ConsoleHost_history\.txt|\.node_repl_history|\.python_history)`;

export const SHELL_HISTORY_TAMPER = [
  // Clear the in-memory history (bash/zsh builtin `history -c`; PowerShell `Clear-History`).
  /(?<![\w-])history\s+-c\b/i,
  /(?<![\w-])Clear-History\b/i,
  // Turn logging off for the session: `set +o history`, `unset HISTFILE`, HISTFILE to /dev/null or empty,
  // a zero history size (bash HISTSIZE/HISTFILESIZE, zsh SAVEHIST).
  /(?<![\w-])set\s+\+o\s+history\b/i,
  /(?<![\w-])unset\s+(?:HISTFILE|HISTSIZE|HISTFILESIZE|SAVEHIST)\b/i,
  /\bHISTFILE=(?:\/dev\/null\b|(?=[\s;|&]|$)|""|'')/i,
  /\b(?:HISTSIZE|HISTFILESIZE|SAVEHIST)=0(?![\d.])/i,
  // PowerShell PSReadLine: stop saving, or delete the saved history file by its option path.
  /\bSet-PSReadLineOption\b[^\n;|]{0,160}?-HistorySaveStyle\s+SaveNothing\b/i,
  /\bRemove-Item\b[^\n;|]{0,120}?HistorySavePath\b/i,
  // Delete, shred or truncate a history file.
  new RegExp(String.raw`(?<![\w-])(?:rm|shred|srm|unlink|truncate|Remove-Item|ri)\b[^\n;|&]{0,100}?(?<![\w.])${HIST_FILE}\b`, "i"),
  // Empty a history file by overwriting it: a bare `>` / `: >` redirect, or a known empty producer piped in.
  new RegExp(String.raw`(?:^|[;&|]\s*)(?::|true)?\s*>\s*\|?\s*["']?[^\s"';|&>]{0,120}?${HIST_FILE}\b`, "im"),
  new RegExp(String.raw`\b(?:cat\s+\/dev\/null|printf\s+["']{2}|echo\s+-n)[^\n;|&]{0,60}?>\s*\|?\s*["']?[^\s"';|&>]{0,120}?${HIST_FILE}\b`, "i")
];
