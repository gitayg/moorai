<#
Stop and remove the MoorAIGuard service and its binary. Keeps <ProgramData>\MoorAI (the administrator's
config and the helper's state, including the device key and undelivered alerts). Run elevated.
#>
[CmdletBinding()]
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'
$ServiceName = 'MoorAIGuard'
$Sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
$InstallDir = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'MoorAI'
if ($DryRun) {
  Write-Output "plan: $Sc stop $ServiceName"
  Write-Output "plan: $Sc delete $ServiceName"
  Write-Output "plan: remove $InstallDir\moorai-guardd.exe"
  return
}
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  & $Sc stop $ServiceName | Out-Null
  & $Sc delete $ServiceName | Out-Null
}
Remove-Item -LiteralPath (Join-Path $InstallDir 'moorai-guardd.exe') -Force -ErrorAction SilentlyContinue
Write-Output "moorai-guardd uninstall: removed; ProgramData\MoorAI was kept"
