// The fixed probe table of the Windows runtime validation: id, surface, Windows-only, and one sentence on
// what a pass proves. The report takes its text from here by id, never from a probe's own output.
export const PROBE_TABLE = Object.freeze([
  { id: "hook-bash-block", surface: "hook", windowsOnly: false,
    proves: "The PreToolUse hook process starts on this host and denies a reverse-shell Bash command." },
  { id: "hook-powershell-block", surface: "powershell", windowsOnly: false,
    proves: "A command sent through Claude Code's PowerShell tool is judged like Bash and the reverse shell is denied." },
  { id: "hook-powershell-allow", surface: "powershell", windowsOnly: false,
    proves: "A benign PowerShell command is allowed, so the block above is not a hook that denies everything." },
  { id: "powershell-host", surface: "powershell", windowsOnly: true,
    proves: "The hook launched through powershell.exe returns the same deny, so a PowerShell launch path does not lose the verdict." },
  { id: "mcp-gateway-hook", surface: "mcp", windowsOnly: false,
    proves: "An MCP tool call to a server outside the policy's mcpAllow list is denied by the hook." },
  { id: "mcp-gateway-http", surface: "mcp", windowsOnly: false,
    proves: "The HTTP MCP gateway process listens on loopback, refuses a tool call carrying a credential, and the remote server never sees it." },
  { id: "egress-hook", surface: "egress", windowsOnly: false,
    proves: "An egress block rule in the signed policy denies a shell command that uploads to the blocked host." },
  { id: "egress-proxy", surface: "egress", windowsOnly: false,
    proves: "The egress proxy process refuses a request to a host the signed policy blocks (HTTP 403) before any DNS lookup." },
  { id: "mxc-detect-config", surface: "mxc", windowsOnly: false,
    proves: "The MXC detector reads a Codex config that sets windows.sandbox to mxc as contained, and an unset one as not contained." },
  { id: "mxc-registry", surface: "mxc", windowsOnly: true,
    proves: "reg.exe returns this build's UBR, so mxcCapable is computed from the real registry and not left unknown." },
  { id: "mxc-enforce", surface: "mxc", windowsOnly: true,
    proves: "With containmentRequired set to block, a Codex shell command whose config does not use MXC is denied, or alerted where the build cannot run MXC." },
  { id: "alert-delivery", surface: "alerts", windowsOnly: false,
    proves: "The blocks above reached the console as alerts, and no alert carried a command, URL or argument from the probes." }
]);
export const PROBE_INFO = Object.freeze(Object.fromEntries(PROBE_TABLE.map((p) => [p.id, p])));

// What this run does not exercise, stated in every report.
export const NOT_COVERED = Object.freeze([
  { id: "clipboard-guard", why: "The clipboard guard lives in the desktop app (Rust); this validator runs the Node agent only. Check it by hand in the app." },
  { id: "nsis-upgrade", why: "Upgrading the NSIS installer over the previous release needs both installers and an interactive session. Check it by hand." },
  { id: "mxc-runtime-containment", why: "No command is run inside an MXC container here: the probes check MXC detection and the hook's verdict, not wxc-exec itself." }
]);
