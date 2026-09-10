[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$destination = 'D:\scaping'
if (-not (Test-Path -LiteralPath 'D:\' -PathType Container)) { throw 'Drive D: is unavailable.' }
$sourceBinary = Join-Path $packageRoot 'scaping.exe'
if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) { throw 'Incomplete package: scaping.exe is missing.' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$targetBinary = Join-Path $destination 'scaping.exe'
if ([IO.Path]::GetFullPath($sourceBinary) -eq [IO.Path]::GetFullPath($targetBinary)) { Write-Host 'The executable is already at the required destination.'; return }
if (Test-Path -LiteralPath $targetBinary) { throw 'D:\scaping\scaping.exe already exists. Close SCAPING and keep a backup before updating it.' }
Copy-Item -LiteralPath $sourceBinary -Destination $targetBinary
Write-Host 'Deployed to D:\scaping\scaping.exe. Configure the application through its settings window.'
