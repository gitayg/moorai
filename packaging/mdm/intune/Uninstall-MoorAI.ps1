<#
.SYNOPSIS
    MoorAI silent uninstall for Intune (Windows Win32 app).

.DESCRIPTION
    Removes MoorAI's PreToolUse hook entries from the user's ~/.claude/settings.json,
    deletes the per-user enroll config, and removes the agent install directory.
    Idempotent and non-interactive.

    `moorai-hook.mjs uninstall` removes ONLY MoorAI's own hook entries — it leaves
    the rest of the user's Claude Code settings untouched.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)] [string] $MooraiHome = "$env:ProgramFiles\MoorAI"
)

$ErrorActionPreference = "SilentlyContinue"

$LogDir = Join-Path $env:ProgramData "MoorAI"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "uninstall.log"
function Write-Log { param([string]$m) Add-Content -Path $LogFile -Value ("{0}  {1}" -f (Get-Date -Format s), $m); Write-Output $m }

# De-register hooks (best-effort; needs the agent still on disk).
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
$hook = Join-Path $MooraiHome "cli\moorai-hook.mjs"
if ($node -and (Test-Path $hook)) {
    & $node $hook uninstall
    Write-Log "hooks de-registered"
}

# Remove the per-user enroll config.
$cfgDir = Join-Path $env:USERPROFILE ".curaiq"
if (Test-Path $cfgDir) { Remove-Item -Recurse -Force $cfgDir; Write-Log "removed $cfgDir" }

# Remove the agent install directory.
if (Test-Path $MooraiHome) { Remove-Item -Recurse -Force $MooraiHome; Write-Log "removed $MooraiHome" }

Write-Log "MoorAI uninstall complete."
exit 0
