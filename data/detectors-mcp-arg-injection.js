// #54 (OWASP MCP05) — shell-command injection in an MCP tool-call ARGUMENT. A tool that builds a shell
// command from a data argument (DVMCP challenge 9: ping_host runs `ping -c N {host}` with shell=True)
// executes whatever is appended to the value. The text scan only knew reverse-shell payloads, so a host
// with `; id` appended reached the tool through every surface.
//
// The shape, read per string argument (nested objects and arrays included):
//   1. the value STARTS like a data value: one token with no whitespace (a host, an IPv4/IPv6 literal, a
//      path, a file name, an id) or nothing at all;
//   2. then a shell control operator: `;`, `&&`, `||`, `|`, a backtick, `$(`, or a line break;
//   3. then a known command word (COMMANDS), optionally behind sudo or an absolute path;
//   4. then something a command takes: a flag, a path, a number, a URL or a dotted name — or, for the
//      few commands that run bare (STANDALONE), the end of the value or another operator.
//
// Why each limit exists (#54 is a built-in block, so precision is worth more than recall):
//   * One leading token: prose has a space before its first semicolon ("Fix the bug; then …"), so a
//     sentence never matches; neither does markdown, CSS (`color: red;`) or JSON.
//   * A curated command list: `rock && roll`, `cat|dog`, `a; b` name no command.
//   * An argument-shaped first argument: "Revert; rm unused file" is a sentence, `; rm -rf /tmp/x` is not.
//   * A pipe AFTER the command word is not an ending (`| cmd | desc |` is a markdown table row).
//   * A line break only counts in a data-typed key (DATA_KEYS) or after an IP literal: multi-line text in
//     a body / content / message field is ordinary ("v1.2.3\ncurl is now required").
//   * A backtick or `$(` counts when glued to the data token, or in a data-typed key: a backtick that opens
//     a value or follows a space is markdown inline code ("Run `ls -la` to see files").
//   * A single `&` is not an operator: it is how URL query strings and "R&D" are written.
//
// Out of scope: arguments that ARE shell commands, where a separator is the command, not an injection.
//   * EXEMPT_KEYS — command / cmd / script / shell are commands by name; code and expression are program
//     text; query and sql are SQL or search syntax where `;`, `||` and `|` are grammar; pattern and regex
//     are regular expressions, where `|` is alternation; q is the usual short name of a search query.
//   * EXEMPT_TOOL — a tool whose own name says it runs a shell or a process (run_command, bash,
//     execute_shell_command, terminal_exec, eval …) takes commands in whatever argument names it uses.
//
// Content-free: the result names the argument key and the operator kind, never the value.

const COMMANDS = new Set([
  "id", "whoami", "uname", "hostname", "pwd", "env", "printenv", "ls", "dir", "ps", "ifconfig", "netstat",
  "ipconfig", "systeminfo", "cat", "tac", "head", "tail", "grep", "find", "echo", "printf",
  "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "ftp", "tftp", "nslookup", "dig",
  "ping", "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "python", "python2", "python3", "perl",
  "ruby", "php", "node", "lua", "powershell", "pwsh", "cmd", "rm", "mv", "cp", "dd", "chmod", "chown",
  "touch", "mkdir", "rmdir", "sleep", "kill", "pkill", "killall", "su", "tee", "xargs", "awk", "sed",
  "base64", "xxd", "tar", "unzip", "eval", "exec", "crontab", "useradd", "usermod", "passwd",
  "systemctl", "shutdown", "reboot", "nohup", "timeout", "mkfifo", "openssl", "certutil", "bitsadmin",
  "whoami.exe", "cmd.exe", "powershell.exe"
]);
// Commands that do their work with no argument, so the end of the value (or another operator) after
// them is enough. Every other command word needs an argument-shaped first argument.
const STANDALONE = new Set([
  "id", "whoami", "uname", "hostname", "pwd", "env", "printenv", "ls", "dir", "ps", "ifconfig", "netstat",
  "ipconfig", "systeminfo", "bash", "sh", "zsh", "dash", "ksh", "csh", "reboot", "shutdown", "whoami.exe",
  "cmd.exe", "powershell.exe", "pwsh"
]);

const EXEMPT_KEYS = new Set(["command", "cmd", "script", "shell", "code", "query", "sql", "expression", "pattern", "regex", "q"]);
const EXEMPT_TOOL = new Set([
  "shell", "bash", "sh", "zsh", "fish", "powershell", "pwsh", "cmd", "command", "exec", "execute", "terminal",
  "console", "script", "eval", "repl", "subprocess", "spawn"
]);
const DATA_KEYS = new Set([
  "host", "hostname", "ip", "ipv4", "ipv6", "addr", "address", "path", "file", "filename", "url", "uri",
  "id", "name", "target", "domain"
]);

// Every regex here stays inside src/safe-regex.js's limits (no unbounded quantifier at all, well under
// 400 characters); test/mcp-arg-command-injection.test.mjs asserts it.
// 1 = leading data token, 2 = the gap after it, 3 = operator, 4 = command word, 5 = the rest of that line.
export const SHAPE = /^[ \t]{0,16}([\w.:/~@%+=,*[\]\\-]{0,256})([ \t]{0,8})(;|&&|\|\||\||`|\$\(|\r?\n)[ \t]{0,8}(?:sudo[ \t]{1,4})?(?:(?:\/[\w.-]{1,32}){0,4}\/)?([A-Za-z][\w.-]{0,31})([^\n]{0,200})/;
// An argument a command takes: a flag, a path, a home path, a variable, a quote, a number, or a token
// with a dot, slash, colon or `=` in it (a file name, an IP, a URL, key=value).
export const ARG_LIKE = /^[ \t]{1,8}(?:[-/~.$'"\d]|[^\s;&|`]{0,64}[./:=])/;
// Ends the command word when nothing argument-shaped follows: the end, or a non-pipe operator.
export const BARE_END = /^[ \t]{0,8}(?:$|[;&`)])/;
export const IP_LITERAL = /^(?:\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\]?)$/;
export const PATTERNS = [SHAPE, ARG_LIKE, BARE_END, IP_LITERAL];

const tokens = (name) => String(name || "")
  .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
  .toLowerCase()
  .split(/[^a-z0-9]+/)
  .filter(Boolean);
const inSet = (set, toks) => toks.some((t) => set.has(t) || (t.length > 3 && t.endsWith("s") && set.has(t.slice(0, -1))));

// The bare tool name: `mcp__server__tool` → `tool`.
const bareTool = (tool) => { const s = String(tool || ""); const i = s.lastIndexOf("__"); return i >= 0 ? s.slice(i + 2) : s; };
export const isShellTool = (tool) => inSet(EXEMPT_TOOL, tokens(bareTool(tool)));
export const isCommandKey = (key) => inSet(EXEMPT_KEYS, tokens(key));

const OP_NAME = { ";": "semicolon", "&&": "and", "||": "or", "|": "pipe", "`": "backtick", "$(": "subshell" };

// One string value under one key → the operator kind if it is a data value with a command appended.
export function injectedCommand(key, value) {
  if (typeof value !== "string" || !value) return null;
  const m = SHAPE.exec(value.length > 1024 ? value.slice(0, 1024) : value);
  if (!m) return null;
  const [, prefix, gap, op, word, rest] = m;
  const cmd = word.toLowerCase();
  if (!COMMANDS.has(cmd)) return null;
  const dataKey = inSet(DATA_KEYS, tokens(key));
  const newline = op.endsWith("\n");
  if (newline && !dataKey && !IP_LITERAL.test(prefix)) return null;
  // A substitution glued to a data token (`report.pdf` + backtick) is an injection anywhere; one that
  // opens the value or follows a space is how markdown writes inline code, so only a data key counts it.
  if ((op === "`" || op === "$(") && (!prefix || gap) && !dataKey) return null;
  if (!ARG_LIKE.test(rest) && !(STANDALONE.has(cmd) && BARE_END.test(rest))) return null;
  return newline ? "newline" : OP_NAME[op];
}

const MAX_DEPTH = 8, MAX_LEAVES = 500;

// The detector: the first string argument (any depth) carrying an injected command, as { key, op },
// or null. An array's elements are read under the array's key.
export function mcpArgCommandInjection(tool, args) {
  if (isShellTool(tool) || !args || typeof args !== "object") return null;
  let leaves = 0;
  const walk = (v, key, depth) => {
    if (depth > MAX_DEPTH || leaves > MAX_LEAVES) return null;
    if (typeof v === "string") { leaves++; if (isCommandKey(key)) return null; const op = injectedCommand(key, v); return op ? { key: String(key).slice(0, 64), op } : null; }
    if (Array.isArray(v)) { for (const x of v) { const r = walk(x, key, depth + 1); if (r) return r; } return null; }
    if (v && typeof v === "object") { for (const [k, x] of Object.entries(v)) { const r = walk(x, k, depth + 1); if (r) return r; } }
    return null;
  };
  return walk(args, "", 0);
}
