<#
Install moorai-guardd, the MoorAI privileged helper, as the Windows service MoorAIGuard
(docs/proposals/guardd-contract.md §4.3, §13.1 decision 2).

  pwsh -File install.ps1 -Binary C:\path\to\moorai-guardd.exe          # elevated
  pwsh -File install.ps1 -Binary C:\path\to\moorai-guardd.exe -DryRun  # print the plan, change nothing

What it does:
  * copies the binary to <Program Files>\MoorAI\moorai-guardd.exe, with the folder limited to SYSTEM and
    Administrators (full) and Users (read and execute);
  * creates <ProgramData>\MoorAI for the administrator's config.json (SYSTEM and Administrators full,
    Users read). <ProgramData> comes from HKLM ProfileList, never from %ProgramData% (§4.1). The helper
    creates its own state and run directories under it;
  * registers MoorAIGuard: auto start, LocalSystem, restart on failure three times and then every 60 s;
  * sets the service DACL so only SYSTEM and Administrators can stop, reconfigure or re-permission it,
    and any signed-in user can query its state;
  * starts it and checks that it is running.
It never writes config.json or secret.json (MDM's, §4.1).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Binary,
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'

$ServiceName = 'MoorAIGuard'
$DisplayName = 'MoorAI Guard'
$Description = 'MoorAI privileged helper: holds the device key, the policy cache and the alert queue for the MoorAI agent.'
# SY: query, start, stop, interrogate. BA: full control. AU (any signed-in user): query only.
# No ACE outside SY and BA carries RP (start), WP (stop), DC (change config), SD, WD or WO.
$ServiceSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
$Sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
$Icacls = Join-Path ([Environment]::GetFolderPath('System')) 'icacls.exe'

function Step([string]$What, [scriptblock]$Do) {
  if ($DryRun) { Write-Output "plan: $What"; return }
  & $Do
  if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "step failed ($LASTEXITCODE): $What" }
}

function Get-ProgramData {
  $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProgramData).ProgramData
  if (-not $v) { throw 'ProfileList ProgramData is empty' }
  return $v
}

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "not a file: $Binary" }
if (-not [System.IO.Path]::IsPathRooted($Binary)) { throw "the binary path must be absolute: $Binary" }

if (-not $DryRun) {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this from an elevated (Administrator) session'
  }
  # A packaged helper must not carry the test-only path injection (contract §10.2, §11.2).
  $info = (& $Binary --build-info) -join ' '
  if ($info -notmatch 'test-injection=false') { throw "refusing this binary: --build-info said '$info'" }
} else {
  Write-Output "plan: $Binary --build-info must print test-injection=false"
}

$ProgramFiles = if ($DryRun) { 'C:\Program Files' } else { [Environment]::GetFolderPath('ProgramFiles') }
$ProgramData = if ($DryRun) { 'C:\ProgramData' } else { Get-ProgramData }
$InstallDir = Join-Path $ProgramFiles 'MoorAI'
$Exe = Join-Path $InstallDir 'moorai-guardd.exe'
$DataDir = Join-Path $ProgramData 'MoorAI'

$existing = if ($DryRun) { $null } else { Get-Service -Name $ServiceName -ErrorAction SilentlyContinue }
if ($existing -and $existing.Status -ne 'Stopped') {
  Step "$Sc stop $ServiceName" { & $Sc stop $ServiceName | Out-Null; $global:LASTEXITCODE = 0; (Get-Service $ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
}

Step "create $InstallDir and copy the binary to $Exe" {
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -LiteralPath $Binary -Destination $Exe -Force
}
Step "$Icacls $InstallDir /inheritance:r /grant:r SYSTEM:F Administrators:F Users:RX" {
  & $Icacls $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
}
Step "create $DataDir; $Icacls /inheritance:r /grant:r SYSTEM:F Administrators:F Users:R" {
  New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
  & $Icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)R' | Out-Null
}

$binPath = '"' + $Exe + '"'
if ($existing) {
  Step "$Sc config $ServiceName binPath= $binPath start= auto obj= LocalSystem" { & $Sc config $ServiceName binPath= $binPath start= auto obj= LocalSystem DisplayName= $DisplayName | Out-Null }
} else {
  Step "$Sc create $ServiceName binPath= $binPath start= auto obj= LocalSystem" { & $Sc create $ServiceName binPath= $binPath start= auto obj= LocalSystem DisplayName= $DisplayName | Out-Null }
}
Step "$Sc description $ServiceName" { & $Sc description $ServiceName $Description | Out-Null }
# Restart after 1 s, then 5 s, then every 60 s (sc repeats the last action); reset the count after a day.
Step "$Sc failure $ServiceName reset= 86400 actions= restart/1000/restart/5000/restart/60000" { & $Sc failure $ServiceName reset= 86400 actions= restart/1000/restart/5000/restart/60000 | Out-Null }
Step "$Sc failureflag $ServiceName 1" { & $Sc failureflag $ServiceName 1 | Out-Null }
Step "$Sc sdset $ServiceName $ServiceSddl" { & $Sc sdset $ServiceName $ServiceSddl | Out-Null }
Step "$Sc start $ServiceName" { & $Sc start $ServiceName | Out-Null }

if (-not $DryRun) {
  try {
    (Get-Service $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
  } catch {
    & $Sc query $ServiceName
    throw "$ServiceName did not reach the Running state"
  }
  Write-Output "moorai-guardd install: $ServiceName is running"
}
