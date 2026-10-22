<#
ACL checks for install.ps1 (docs/proposals/guardd-contract.md §4.1, §4.2). Each function takes an SDDL
string and returns $null or a reason; none touches a file. install.ps1 feeds them the live descriptor from
Get-Acl. Windows only: .NET's security-descriptor types throw PlatformNotSupportedException elsewhere.
#>

# NT AUTHORITY\SYSTEM and BUILTIN\Administrators: the only principals that may own, create, change or
# re-permission anything under <ProgramData>\MoorAI.
$script:AdminSids = @('S-1-5-18', 'S-1-5-32-544')

# PowerShell 7 resolves these types only once their assemblies are loaded; Windows PowerShell 5.1 has them
# in mscorlib and no assembly by these names.
foreach ($a in 'System.Security.AccessControl', 'System.IO.FileSystem.AccessControl') {
  try { Add-Type -AssemblyName $a -ErrorAction Stop } catch { }
}

# FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY, FILE_WRITE_EA, FILE_DELETE_CHILD,
# FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE.
$script:WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

function ConvertTo-Sd([string]$Sddl) {
  return New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
}

function Get-NullDaclProblem($Sd) {
  $present = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
  if (-not ($Sd.ControlFlags -band $present) -or $null -eq $Sd.DiscretionaryAcl) { return 'has no DACL (everyone has full control)' }
  return $null
}

# A pre-existing directory or file another principal could have prepared: owned by anyone but SYSTEM or
# Administrators (an owner can always rewrite the DACL), or granting anyone else a right to add, change,
# delete or re-permission entries (inherit-only ACEs count: they reach whatever is created below).
function Get-SquatProblem([string]$Sddl) {
  $sd = ConvertTo-Sd $Sddl
  if ($null -eq $sd.Owner -or $script:AdminSids -notcontains $sd.Owner.Value) { return "is owned by $($sd.Owner), not SYSTEM or Administrators" }
  $nd = Get-NullDaclProblem $sd
  if ($nd) { return $nd }
  foreach ($ace in $sd.DiscretionaryAcl) {
    if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
    if ($script:AdminSids -contains $ace.SecurityIdentifier.Value) { continue }
    if ($ace.AccessMask -band $script:WriteMask) { return ('grants {0} write access (0x{1:x})' -f $ace.SecurityIdentifier.Value, $ace.AccessMask) }
  }
  return $null
}

# Any access at all for a principal outside $Sids (secret.json: SYSTEM and Administrators; the state
# directory's contents: SYSTEM), or an owner outside SYSTEM and Administrators.
function Get-AccessProblem([string]$Sddl, [string[]]$Sids) {
  $sd = ConvertTo-Sd $Sddl
  if ($null -eq $sd.Owner -or $script:AdminSids -notcontains $sd.Owner.Value) { return "is owned by $($sd.Owner), not SYSTEM or Administrators" }
  $nd = Get-NullDaclProblem $sd
  if ($nd) { return $nd }
  foreach ($ace in $sd.DiscretionaryAcl) {
    if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
    if ($Sids -notcontains $ace.SecurityIdentifier.Value -and $ace.AccessMask -ne 0) { return "grants $($ace.SecurityIdentifier.Value) access" }
  }
  return $null
}

# The live descriptor matches the one install.ps1 set: owner $OwnerSid, protected DACL (nothing inherited)
# and exactly the ACEs of $WantSddl, same principal, rights and inheritance flags, nothing extra.
function Get-DaclMismatch([string]$Sddl, [string]$WantSddl, [string]$OwnerSid) {
  $sd = ConvertTo-Sd $Sddl
  $want = ConvertTo-Sd $WantSddl
  if ($null -eq $sd.Owner -or $sd.Owner.Value -ne $OwnerSid) { return "is owned by $($sd.Owner), not $OwnerSid" }
  $nd = Get-NullDaclProblem $sd
  if ($nd) { return $nd }
  $protected = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
  if (-not ($sd.ControlFlags -band $protected)) { return 'inherits ACEs from its parent (DACL not protected)' }
  $key = { param($a) '{0}|{1}|0x{2:x}|{3}' -f $a.AceQualifier, $a.SecurityIdentifier.Value, $a.AccessMask, ([int]$a.AceFlags -band 0x0F) }
  $have = @($sd.DiscretionaryAcl | ForEach-Object { & $key $_ } | Sort-Object)
  $need = @($want.DiscretionaryAcl | ForEach-Object { & $key $_ } | Sort-Object)
  if (($have -join ',') -ne ($need -join ',')) { return "has ACEs [$($have -join ', ')], expected [$($need -join ', ')]" }
  return $null
}
