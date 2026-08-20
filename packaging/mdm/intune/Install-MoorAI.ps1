<#
.SYNOPSIS
    MoorAI silent install + enroll script for Microsoft Intune (Windows Win32 app).

.DESCRIPTION
    Installs the MoorAI agent, writes the per-user enrollment config
    (%USERPROFILE%\.curaiq\config.json), and registers the on-device Claude Code
    PreToolUse hooks (%USERPROFILE%\.claude\settings.json) — all non-interactively,
    so a managed Windows device is governed the moment it checks in, with no user
    pasting an install token.

    Content-free: this script only configures the device->console binding. No prompt,
    file, or agent output is collected here; policy is pulled at runtime from
    <ServerUrl>/api/policy?tenant=<Tenant>.

    Idempotent — safe to re-run. moorai-hook.mjs replaces only MoorAI's own hook
    entries; the config write is a full overwrite of config.json.

.PARAMETER ServerUrl
    MoorAI console base URL, e.g. https://console.moorai.example.com

.PARAMETER Tenant
    Tenant slug, e.g. acme-corp

.PARAMETER InstallToken
    Per-tenant enrollment token (sent as X-Install-Token). May be empty for an
    open/unauthenticated console.

.PARAMETER MooraiHome
    Install directory for the agent. Default: C:\Program Files\MoorAI

.PARAMETER PkgUrl
    Optional URL of a prebuilt agent tarball (cli/ src/ data/ scripts/ + node_modules).
    If omitted, the script clones via git (git + Node.js 18+ must be present).

.NOTES
    Intune runs the Install command in SYSTEM context by default. Because the config
    and hooks are PER-USER, this script targets the logged-on user's profile. For a
    device with no interactive user at install time, set the Win32 app to
    "install for user" OR pair it with a per-user logon task (see ..\README.md).

    EXAMPLE Intune "Install command":
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-MoorAI.ps1 ^
        -ServerUrl "https://console.moorai.example.com" -Tenant "acme-corp" ^
        -InstallToken "it_live_xxxxxxxx"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]  [string] $ServerUrl,
    [Parameter(Mandatory = $true)]  [string] $Tenant,
    [Parameter(Mandatory = $false)] [string] $InstallToken = "",
    [Parameter(Mandatory = $false)] [string] $MooraiHome  = "$env:ProgramFiles\MoorAI",
    [Parameter(Mandatory = $false)] [string] $PkgUrl      = ""
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------ logging
$LogDir = Join-Path $env:ProgramData "MoorAI"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "install.log"
function Write-Log {
    param([string] $Message)
    $line = "{0}  {1}" -f (Get-Date -Format "s"), $Message
    Add-Content -Path $LogFile -Value $line
    Write-Output $line
}

Write-Log "MoorAI install starting. ServerUrl=$ServerUrl Tenant=$Tenant MooraiHome=$MooraiHome"

# --------------------------------------------- resolve the target user profile
# In SYSTEM context $env:USERPROFILE is the SYSTEM profile, not the human user's.
# Resolve the logged-on user's profile so config + hooks land in the right place.
function Get-TargetProfile {
    $explorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($explorer) {
        $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($owner -and $owner.User) {
            $prof = (Get-CimInstance Win32_UserProfile |
                Where-Object { $_.LocalPath -and (Split-Path $_.LocalPath -Leaf) -eq $owner.User } |
                Select-Object -First 1).LocalPath
            if ($prof) { return @{ User = $owner.User; Home = $prof } }
        }
    }
    # Fallback: running interactively (Intune "install for user", or manual run).
    if ($env:USERPROFILE -and (Split-Path $env:USERPROFILE -Leaf) -ne "systemprofile") {
        return @{ User = $env:USERNAME; Home = $env:USERPROFILE }
    }
    return $null
}

# ------------------------------------------------------------- install the agent
# CHANNEL (A): a prebuilt tarball from your console/CDN via -PkgUrl.
# CHANNEL (B): git clone (git + Node.js 18+ required). Mirrors scripts/install.sh.
# For the DESKTOP app instead of the CLI agent, deploy the signed NSIS installer as
# a separate Win32 app (MoorAI_<version>_x64-setup.exe /S) — see ..\README.md.
function Install-Agent {
    $hookPath = Join-Path $MooraiHome "cli\moorai-hook.mjs"
    if (Test-Path $hookPath) { Write-Log "agent already present at $MooraiHome"; return }
    New-Item -ItemType Directory -Force -Path $MooraiHome | Out-Null

    if ($PkgUrl) {
        Write-Log "downloading agent tarball from $PkgUrl"
        $tgz = Join-Path $env:TEMP "moorai.tgz"
        Invoke-WebRequest -Uri $PkgUrl -OutFile $tgz -UseBasicParsing
        tar.exe -xzf $tgz -C $MooraiHome --strip-components=1
        Remove-Item $tgz -Force -ErrorAction SilentlyContinue
    }
    else {
        if (-not (Get-Command git  -ErrorAction SilentlyContinue)) { throw "git required for git channel; use -PkgUrl for an offline fleet." }
        if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Node.js 18+ required on the device." }
        Write-Log "cloning agent via git"
        git clone --depth 1 "https://github.com/gitayg/moorai.git" $MooraiHome
        Push-Location $MooraiHome
        try { npm ci --omit=dev 2>$null; if ($LASTEXITCODE -ne 0) { npm install --omit=dev } }
        finally { Pop-Location }
    }
    Write-Log "agent installed at $MooraiHome"
}

# -------------------------------------------------- write per-user enroll config
# JSON shape read by cli/config.mjs: { serverUrl, tenant, installToken }.
function Write-EnrollConfig {
    param([string] $Home)
    $cfgDir  = Join-Path $Home ".curaiq"
    $cfgFile = Join-Path $cfgDir "config.json"
    New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
    $cfg = [ordered]@{
        serverUrl    = $ServerUrl
        tenant       = $Tenant
        installToken = $InstallToken
    }
    # -Depth keeps nested values intact; ASCII avoids a BOM that would break JSON.parse.
    $json = $cfg | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($cfgFile, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log "wrote enroll config -> $cfgFile"
}

# ------------------------------------------------------------- register the hooks
# Runs moorai-hook.mjs as the target user so it edits that user's settings.json.
# In SYSTEM context we shell out with a scheduled-task-free `runas`-equivalent is
# unavailable non-interactively, so we register under whichever identity this
# process runs as; when Intune deploys "for user" this is already the user.
function Register-Hooks {
    param([string] $Home)
    $node = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $node) { $node = "node" }
    $hook = Join-Path $MooraiHome "cli\moorai-hook.mjs"
    if (-not (Test-Path $hook)) { Write-Log "hook script missing at $hook; skipping"; return }
    # Point HOME/USERPROFILE at the target profile so ~/.claude resolves correctly
    # even if this runs slightly out of the user's own session.
    $prev = $env:USERPROFILE
    try {
        $env:USERPROFILE = $Home
        & $node $hook install
        Write-Log "hooks registered (settings.json under $Home\.claude)"
    }
    catch { Write-Log "hook registration failed: $($_.Exception.Message)" }
    finally { $env:USERPROFILE = $prev }
}

# ------------------------------------------------------------------------- main
Install-Agent

$target = Get-TargetProfile
if ($null -eq $target) {
    Write-Log "no interactive user resolved; agent installed, per-user enroll deferred to logon task."
    # Detection rule (Detect-MoorAI.ps1) keys off the agent files, so Intune still
    # reports this install as successful; the logon task completes the per-user enroll.
    exit 0
}

Write-Log "target user: $($target.User)  home: $($target.Home)"
Write-EnrollConfig -Home $target.Home
Register-Hooks    -Home $target.Home

Write-Log "done. Policy pulled at runtime from $ServerUrl/api/policy?tenant=$Tenant"
exit 0
