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

# %ProgramData%\MoorAI is the machine-wide TRUST ANCHOR directory that cli/moorai-hook.mjs reads
# policy.pub / breakglass.pub / offline-posture from — see the long note in Install-MoorAI.ps1.
# Never CREATE it here: creating it inherits C:\ProgramData's BUILTIN\Users create-file ACE, and an
# uninstall may well run non-elevated, so it could not be hardened afterwards. A user-writable
# anchor directory left behind by an uninstall is exactly the precondition for a forged anchor.
# Log into it only if it already exists (an install created and hardened it); otherwise fall back
# to the user scope.
$AnchorDir = Join-Path $env:ProgramData "MoorAI"
if (Test-Path -LiteralPath $AnchorDir) { $LogDir = $AnchorDir }
else {
    $LogDir = Join-Path $env:TEMP "MoorAI"
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}
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
