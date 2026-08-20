<#
.SYNOPSIS
    Intune Win32-app detection rule for MoorAI.

.DESCRIPTION
    Intune considers a Win32 app "installed" when its detection script writes to
    STDOUT and exits 0. This script confirms BOTH:
      1. the agent files exist (cli\moorai-hook.mjs under MooraiHome), and
      2. the current user is enrolled (%USERPROFILE%\.curaiq\config.json has a
         non-empty serverUrl + tenant).

    If either check fails it exits 1 with no output -> Intune treats the app as not
    installed and (re)runs Install-MoorAI.ps1.

    Configure in Intune:
      Detection rules > Rules format: "Use a custom detection script"
      Script file: Detect-MoorAI.ps1
      Run as 32-bit: No   |   Enforce signature check: No (or Yes if you sign it)

    NOTE: keep $MooraiHome in sync with the -MooraiHome you pass to Install-MoorAI.ps1.
#>

$MooraiHome = Join-Path $env:ProgramFiles "MoorAI"
$hook = Join-Path $MooraiHome "cli\moorai-hook.mjs"

if (-not (Test-Path $hook)) { exit 1 }   # agent not installed

$cfgFile = Join-Path $env:USERPROFILE ".curaiq\config.json"
if (-not (Test-Path $cfgFile)) { exit 1 }  # not enrolled for this user

try {
    $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json
}
catch { exit 1 }  # malformed config

if ([string]::IsNullOrWhiteSpace($cfg.serverUrl) -or [string]::IsNullOrWhiteSpace($cfg.tenant)) {
    exit 1  # enrolled file present but not bound to a console/tenant
}

# Success — any STDOUT + exit 0 marks the app as installed in Intune.
Write-Output "MoorAI installed and enrolled: tenant=$($cfg.tenant)"
exit 0
