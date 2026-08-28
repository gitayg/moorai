<#
.SYNOPSIS
    MoorAI silent install + enroll script for Microsoft Intune (Windows Win32 app).

.DESCRIPTION
    Installs the MoorAI agent, writes the per-user enrollment config
    (%USERPROFILE%\.moorai\config.json), and registers the on-device Claude Code
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
# The log file lives in the trust-anchor directory, which must be hardened BEFORE anything is
# written there — so lines logged during hardening are buffered until the path is known. Every
# line is also echoed to STDOUT, which Intune captures, so nothing is lost if hardening throws.
$script:LogFile   = $null
$script:LogBuffer = New-Object System.Collections.ArrayList
function Write-Log {
    param([string] $Message)
    $line = "{0}  {1}" -f (Get-Date -Format "s"), $Message
    if ($script:LogFile) {
        foreach ($buffered in $script:LogBuffer) { Add-Content -Path $script:LogFile -Value $buffered }
        $script:LogBuffer.Clear()
        Add-Content -Path $script:LogFile -Value $line
    }
    else { [void] $script:LogBuffer.Add($line) }
    Write-Output $line
}

# ------------------------------------------------- machine-wide trust anchor hardening
# %ProgramData%\MoorAI is NOT just this script's log directory. cli/moorai-hook.mjs reads
# policy.pub, breakglass.pub, offline-posture and policy-lkg.json from it as the machine-wide
# TRUST ANCHOR, and readRootOwned() trusts a file found there once icacls says its DACL grants
# write access only to administrators.
#
# C:\ProgramData carries BUILTIN\Users:(CI)(WD,AD,WEA,WA) — create-file/create-folder rights that
# every child directory inherits. Creating this directory with `New-Item -Force` and no ACL work
# therefore leaves ordinary users able to CREATE FILES in the anchor directory, which defeats the
# anchor in two ways:
#   1. DACL scrub via ownership. The user creates the anchor file, so the user is its OWNER, and
#      an owner implicitly holds WRITE_DAC — "An object's owner implicitly has WRITE_DAC access to
#      the object" (learn.microsoft.com/windows/win32/secauthz/owner-of-a-new-object). They then
#      run `icacls <file> /inheritance:r /grant SYSTEM:(F) Administrators:(F)` to strip their own
#      inherited ACE. icacls has no switch that prints an owner, so the DACL now reads clean and
#      the FORGED anchor is trusted.
#   2. Any future gap in DACL parsing.
# Hardening the DIRECTORY removes the precondition for both at zero runtime cost, which is why the
# fix lives here and not in the hook's per-invocation hot path.
#
# WELL-KNOWN SIDs, NOT NAMES: `/grant Users:...` is not portable — a German Windows has
# BUILTIN\Benutzer and a French one BUILTIN\Utilisateurs. icacls takes a literal SID when the
# principal is prefixed with `*` (icacls reference, "*Sid"). The three used here:
#   *S-1-5-18      NT AUTHORITY\SYSTEM     — the service/install identity.        FULL
#   *S-1-5-32-544  BUILTIN\Administrators  — fleet administrators.                FULL
#   *S-1-5-32-545  BUILTIN\Users           — every interactive user.        READ+EXECUTE
# Users MUST retain read: the hook runs as the user and has to READ the anchors. Locking them out
# would make every anchor unreadable and fail the device closed. What they must not have is
# create/write/delete.
# Inheritance flags: (OI) object inherit -> files below inherit; (CI) container inherit ->
# subdirectories inherit; (F) full control; (RX) read and execute. `/inheritance:r` removes the
# inherited ACEs so the ProgramData grant above cannot survive.
function Test-IsElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object System.Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# icacls reports failure through its exit code and writes the detail to stderr. PowerShell 5.1
# surfaces redirected native stderr as ErrorRecords, which $ErrorActionPreference="Stop" would
# escalate into a terminating error on even a benign warning — so relax it just for the call and
# judge the result by the exit code.
function Invoke-Icacls {
    param([string[]] $Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & icacls.exe @Arguments 2>&1 | ForEach-Object { $_.ToString() }
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = (($output) -join " | ") }
    }
    finally { $ErrorActionPreference = $previous }
}

# Verify the hardening actually took, WITHOUT parsing icacls' output: icacls prints localized
# principal names, but Get-Acl exposes the owner and the access rules as SIDs, which are not
# localized. Returns $null when the directory is safe, or a human-readable reason when it is not.
function Test-AnchorDirProblem {
    param([string] $Path)
    try { $acl = Get-Acl -Path $Path }
    catch { return "cannot read the ACL ($($_.Exception.Message))" }

    if (-not $acl.AreAccessRulesProtected) { return "inherited ACEs are still present (inheritance not removed)" }

    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    $privileged = @("S-1-5-18", "S-1-5-32-544")
    if ($privileged -notcontains $ownerSid) { return "owner is $ownerSid, and an owner implicitly holds WRITE_DAC" }

    # Any right that lets a principal place or alter a file in the directory, or re-open the DACL.
    $writeMask = 0
    foreach ($right in @("CreateFiles", "CreateDirectories", "Delete", "DeleteSubdirectoriesAndFiles",
                         "WriteAttributes", "WriteExtendedAttributes", "ChangePermissions", "TakeOwnership")) {
        $writeMask = $writeMask -bor [int]([System.Security.AccessControl.FileSystemRights] $right)
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (-not ([int] $rule.FileSystemRights -band $writeMask)) { continue }
        if ($privileged -notcontains $rule.IdentityReference.Value) {
            return "$($rule.IdentityReference.Value) is granted $($rule.FileSystemRights)"
        }
    }
    return $null
}

# Idempotent: safe to re-run, and REPAIRS a directory that already exists with weak permissions
# (the common case for anyone who installed before this hardening shipped).
function Protect-AnchorDirectory {
    param([string] $Path)

    # Record the state BEFORE touching anything, so the "this may already have been abused" warning
    # below fires only when the directory was genuinely weak — not on every routine re-run, where a
    # standing warning would be noise that trains operators to ignore it.
    $preExisting  = Test-Path -LiteralPath $Path
    $priorProblem = if ($preExisting) { Test-AnchorDirProblem -Path $Path } else { $null }
    if (-not $preExisting) { New-Item -ItemType Directory -Force -Path $Path | Out-Null }

    # 1. Take ownership of the directory and everything already in it, so a CREATOR OWNER left
    #    over from a non-elevated creation cannot re-open the DACL later. /T recurses, /C
    #    continues past individual failures, /Q suppresses per-file success chatter.
    $setOwner = Invoke-Icacls @($Path, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q")
    if ($setOwner.ExitCode -ne 0) { Write-Log "icacls /setowner exit $($setOwner.ExitCode): $($setOwner.Output)" }

    # 2. Drop the inherited BUILTIN\Users create-file ACE and write the explicit ACL.
    $grant = Invoke-Icacls @(
        $Path, "/inheritance:r",
        "/grant", "*S-1-5-18:(OI)(CI)(F)",
        "/grant", "*S-1-5-32-544:(OI)(CI)(F)",
        "/grant", "*S-1-5-32-545:(OI)(CI)(RX)"
    )
    if ($grant.ExitCode -ne 0) { throw "icacls hardening of $Path failed (exit $($grant.ExitCode)): $($grant.Output)" }

    # 3. Make anything already inside drop its own ACL and inherit the new one. Scoped to the
    #    CHILDREN ("$Path\*") on purpose — `icacls $Path /reset /T` would reset $Path itself back
    #    to inheriting from C:\ProgramData and silently undo step 2.
    $hasChildren = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count -gt 0
    if ($hasChildren) {
        $reset = Invoke-Icacls @((Join-Path $Path "*"), "/reset", "/T", "/C", "/Q")
        if ($reset.ExitCode -ne 0) { Write-Log "icacls /reset of existing children exit $($reset.ExitCode): $($reset.Output)" }
    }

    # 4. Confirm, and FAIL THE INSTALL if it did not take. A user-writable anchor directory is
    #    worse than no anchor directory at all, because the hook TRUSTS what it finds there.
    $problem = Test-AnchorDirProblem -Path $Path
    if ($problem) { throw "trust-anchor directory $Path is NOT hardened: $problem" }

    Write-Log "trust-anchor directory hardened: $Path (SYSTEM + Administrators full, Users read-only, inheritance removed, owner=BUILTIN\Administrators)"

    # Hardening fixes the future, not the past: it cannot tell a legitimately deployed anchor from
    # one an ordinary user planted while the directory was still writable.
    if ($preExisting -and $priorProblem) {
        Write-Log "WARNING: $Path already existed and was NOT hardened ($priorProblem). It has been repaired, but an ordinary user could have planted a FORGED anchor there BEFORE this run. Re-deploy the anchors from MDM and treat any anchor file you did not deploy as suspect."
        foreach ($anchor in @("policy.pub", "breakglass.pub", "offline-posture", "policy-lkg.json")) {
            if (Test-Path -LiteralPath (Join-Path $Path $anchor)) { Write-Log "  pre-existing anchor file found, verify it: $anchor" }
        }
    }
}

# ------------------------------------------------------ set up the anchor dir + log file
$AnchorDir = Join-Path $env:ProgramData "MoorAI"
if (Test-IsElevated) {
    Protect-AnchorDirectory -Path $AnchorDir
    $script:LogFile = Join-Path $AnchorDir "install.log"
}
else {
    # Deliberately do NOT create %ProgramData%\MoorAI here. Creating it is precisely the attacker's
    # precondition, and without WRITE_DAC this process could not harden it afterwards — so a
    # non-elevated run would leave behind exactly the user-writable anchor directory this change
    # exists to prevent. Leaving it absent is the safe state: the hook then finds no anchor at all
    # rather than a forgeable one. Logs go to the user scope instead.
    $userLogDir = Join-Path $env:TEMP "MoorAI"
    New-Item -ItemType Directory -Force -Path $userLogDir | Out-Null
    $script:LogFile = Join-Path $userLogDir "install.log"
    Write-Log "WARNING: not elevated - skipping trust-anchor hardening and NOT creating $AnchorDir. Machine-wide anchors (policy.pub, breakglass.pub, offline-posture) require a SYSTEM-context run; see ..\README.md."
    if (Test-Path -LiteralPath $AnchorDir) {
        $existingProblem = Test-AnchorDirProblem -Path $AnchorDir
        if ($existingProblem) {
            Write-Log "WARNING: $AnchorDir already exists and is NOT hardened ($existingProblem). Any anchor there is forgeable by an ordinary user. Re-run this installer in SYSTEM context to repair it."
        }
    }
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
    $cfgDir  = Join-Path $Home ".moorai"
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
