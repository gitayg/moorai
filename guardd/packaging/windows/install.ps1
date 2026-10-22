<#
Install moorai-guardd, the MoorAI privileged helper, as the Windows service MoorAIGuard
(docs/proposals/guardd-contract.md §4.3, §13.1 decision 2).

  pwsh -File install.ps1 -Binary C:\path\to\moorai-guardd.exe          # elevated
  pwsh -File install.ps1 -Binary C:\path\to\moorai-guardd.exe -DryRun  # print the plan, change nothing

What it does:
  * copies the binary to <Program Files>\MoorAI\moorai-guardd.exe, with the folder limited to SYSTEM and
    Administrators (full) and Users (read and execute);
  * refuses a pre-existing <ProgramData>\MoorAI, or anything already under it, that is a reparse point
    (junction or symbolic link), is owned by anyone but SYSTEM or Administrators, or lets anyone else add,
    change, delete or re-permission entries: such a tree may have been prepared by another user, so the
    installer stops, changes nothing, and names the entry. <ProgramData> comes from HKLM ProfileList,
    never from %ProgramData% (§4.1);
  * creates <ProgramData>\MoorAI with its DACL set at creation, then sets owner SYSTEM and replaces the
    whole DACL (protected; SYSTEM and Administrators full, inherited below; Users read on the folder
    itself only, never inherited, so nothing created under it later is readable by Users), and resets
    every ACL under it so it inherits that DACL;
  * gives the helper's directories the contract §4.2 DACLs, replacing the whole DACL, so neither depends
    on the helper: state (owner SYSTEM, protected, SYSTEM full only; device.key and the alert queue live
    here) and run (owner SYSTEM, protected, SYSTEM and Administrators full, Users read, for device.pub);
  * gives an existing secret.json the §4.1 DACL (owner SYSTEM, protected, SYSTEM and Administrators
    full) and warns when it was readable by anyone else before this run; gives each existing public admin
    input the agent reads as the signed-in user (config.json, policy.pub, breakglass.pub, offline-posture,
    policy-hwm.json, policy-lkg.json, exceptions.json, decoys.json) an explicit Users read. A public input
    MDM writes after this run needs that grant from MDM, because the folder no longer hands Users read
    down;
  * registers MoorAIGuard: auto start, LocalSystem, restart on failure three times and then every 60 s;
  * sets the service DACL so only SYSTEM and Administrators can stop, reconfigure or re-permission it,
    and any signed-in user can query its state;
  * starts it and checks that it is running.
It never writes the content of config.json or secret.json (MDM's, §4.1).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Binary,
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'acl-checks.ps1')

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

# Contract §4.1 and §4.2 DACLs, each applied as the WHOLE DACL (Set-ExactDacl), never with icacls /grant:r,
# which rewrites only the named principals' entries and keeps every other one. D:P = protected (nothing
# inherited from the parent). FA = full; 0x120089 = read (FILE_GENERIC_READ). OICI = inherited by the files
# and folders below; no flags = this object only. SY SYSTEM, BA Administrators, BU Users.
$DataDirSddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120089;;;BU)'
$StateDirSddl = 'D:P(A;OICI;FA;;;SY)'
$RunDirSddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x120089;;;BU)'
$SecretSddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)'
# Admin inputs the agent reads as the signed-in user (cli/machine-dir.mjs). Never secret.json.
$PublicInputs = @('config.json', 'policy.pub', 'breakglass.pub', 'offline-posture', 'policy-hwm.json', 'policy-lkg.json', 'exceptions.json', 'decoys.json')

function Invoke-Icacls {
  & $Icacls @args | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls $($args -join ' ') failed ($LASTEXITCODE)" }
}

function Test-IsReparsePoint($Item) {
  return [bool]($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Get-LiveSddl([string]$Path) {
  return (Get-Acl -LiteralPath $Path).Sddl
}

# Refuse a pre-existing tree another principal could have prepared (contract §4.2): the path itself and
# everything under it must be no reparse point, owned by SYSTEM or Administrators, and writable by no one
# else (acl-checks.ps1 Get-SquatProblem). Get-ChildItem -Recurse does not descend into a junction or
# symbolic link (no -FollowSymlink), and one it lists is refused before its ACL is read. An ACL the
# installer cannot read is an error too.
function Assert-NotSquatted([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $items = @(Get-Item -LiteralPath $Path -Force)
  if (-not (Test-IsReparsePoint $items[0])) { $items += @(Get-ChildItem -LiteralPath $Path -Recurse -Force) }
  foreach ($i in $items) {
    $why = if (Test-IsReparsePoint $i) { 'is a reparse point (junction or symbolic link)' } else { Get-SquatProblem (Get-LiveSddl $i.FullName) }
    if ($why) {
      throw "refusing to install over $($i.FullName): it $why. Its ACLs were not changed. Check it, remove $Path if no administrator created it, and run the installer again."
    }
  }
}

function New-SecurityObject([string]$Sddl, [bool]$Directory) {
  $sec = if ($Directory) { New-Object System.Security.AccessControl.DirectorySecurity } else { New-Object System.Security.AccessControl.FileSecurity }
  $sec.SetSecurityDescriptorSddlForm($Sddl, [System.Security.AccessControl.AccessControlSections]::Access)
  return $sec
}

# Replace the whole DACL. Only the DACL section is written (with its protected flag); the owner is set with
# icacls /setowner, which enables the privilege an administrator needs to make SYSTEM the owner.
function Set-ExactDacl([string]$Path, [string]$Sddl) {
  $item = Get-Item -LiteralPath $Path -Force
  if (Test-IsReparsePoint $item) { throw "refusing to set the ACL of $($Path): it is a reparse point" }
  $sec = New-SecurityObject $Sddl ($item -is [System.IO.DirectoryInfo])
  if ($item.PSObject.Methods['SetAccessControl']) { $item.SetAccessControl($sec) }
  else { [System.IO.FileSystemAclExtensions]::SetAccessControl($item, $sec) }
}

# Create a missing directory with its DACL in place from the first instant, so no other user can add an
# entry to it before the DACL is set (ProgramData lets Users create folders and files).
function New-DirWithDacl([string]$Path, [string]$Sddl) {
  $sec = New-SecurityObject $Sddl $true
  if ([System.IO.Directory].GetMethod('CreateDirectory', [type[]]@([string], [System.Security.AccessControl.DirectorySecurity]))) {
    [System.IO.Directory]::CreateDirectory($Path, $sec) | Out-Null
  } else {
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $sec)
  }
}

function Reset-ChildAcls([string]$Path) {
  if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) { Invoke-Icacls (Join-Path $Path '*') /reset /T /Q }
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
$StateDir = Join-Path $DataDir 'state'
$RunDir = Join-Path $DataDir 'run'

$SecretPath = Join-Path $DataDir 'secret.json'

# Refuse a prepared tree before anything changes, the service included.
$SecretWasExposed = $null
if ($DryRun) {
  Write-Output "plan: refuse $DataDir if it, or anything under it, is a reparse point, is not owned by SYSTEM or Administrators, or is writable by anyone else"
} else {
  Assert-NotSquatted $DataDir
  if (Test-Path -LiteralPath $SecretPath -PathType Leaf) { $SecretWasExposed = Get-AccessProblem (Get-LiveSddl $SecretPath) $script:AdminSids }
}

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
Step "create $DataDir with its DACL; re-check it; owner SYSTEM; replace its DACL with $DataDirSddl; reset every ACL under it" {
  if (-not (Test-Path -LiteralPath $DataDir)) { New-DirWithDacl $DataDir $DataDirSddl }
  # Another user could have created it between the first check and here.
  Assert-NotSquatted $DataDir
  Set-ExactDacl $DataDir $DataDirSddl
  Invoke-Icacls $DataDir /setowner '*S-1-5-18'
  # Every entry under it drops its own ACEs and inherits the DACL above (SYSTEM and Administrators only), so
  # whatever an earlier install or tool granted below is gone; the state and run directories get their own
  # protected DACLs next. Scoped to the children: a /reset of $DataDir itself would re-inherit ProgramData's.
  Reset-ChildAcls $DataDir
}
# Contract §4.2: SYSTEM only. Set after the reset above, which would otherwise undo it.
Step "create $StateDir; replace its DACL with $StateDirSddl; owner SYSTEM; reset every ACL under it" {
  if (-not (Test-Path -LiteralPath $StateDir)) { New-DirWithDacl $StateDir $StateDirSddl }
  Set-ExactDacl $StateDir $StateDirSddl
  Invoke-Icacls $StateDir /setowner '*S-1-5-18' /T /Q
  Reset-ChildAcls $StateDir
}
Step "create $RunDir; replace its DACL with $RunDirSddl; owner SYSTEM; reset every ACL under it" {
  if (-not (Test-Path -LiteralPath $RunDir)) { New-DirWithDacl $RunDir $RunDirSddl }
  Set-ExactDacl $RunDir $RunDirSddl
  Invoke-Icacls $RunDir /setowner '*S-1-5-18' /T /Q
  Reset-ChildAcls $RunDir
}
# Contract §4.1: secret.json is owner SYSTEM with a protected DACL, SYSTEM and Administrators only.
Step "if $SecretPath is present: replace its DACL with $SecretSddl; owner SYSTEM" {
  if (Test-Path -LiteralPath $SecretPath -PathType Leaf) {
    Set-ExactDacl $SecretPath $SecretSddl
    Invoke-Icacls $SecretPath /setowner '*S-1-5-18'
  }
}
# Users read on the public admin inputs only, one file at a time and never inherited.
Step "give each present public admin input ($($PublicInputs -join ', ')) an explicit Users read" {
  foreach ($n in $PublicInputs) {
    $p = Join-Path $DataDir $n
    if (Test-Path -LiteralPath $p -PathType Leaf) { Invoke-Icacls $p /grant '*S-1-5-32-545:(R)' }
  }
}

if (-not $DryRun) {
  $want = [ordered]@{ $DataDir = $DataDirSddl; $StateDir = $StateDirSddl; $RunDir = $RunDirSddl }
  foreach ($d in $want.Keys) {
    $why = Get-DaclMismatch (Get-LiveSddl $d) $want[$d] 'S-1-5-18'
    if ($why) { throw "$d $why" }
  }
  foreach ($i in @(Get-ChildItem -LiteralPath $StateDir -Recurse -Force)) {
    $why = Get-AccessProblem (Get-LiveSddl $i.FullName) @('S-1-5-18')
    if ($why) { throw "$($i.FullName) $why" }
  }
  if (Test-Path -LiteralPath $SecretPath -PathType Leaf) {
    $why = Get-DaclMismatch (Get-LiveSddl $SecretPath) $SecretSddl 'S-1-5-18'
    if ($why) { throw "$SecretPath $why" }
  }
  if ($SecretWasExposed) {
    Write-Warning "$SecretPath was not limited to SYSTEM and Administrators before this run (it $SecretWasExposed). It is now; treat the install token and enrolment secret in it as exposed and issue new ones."
  }
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
