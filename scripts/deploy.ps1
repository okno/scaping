[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$destination = 'D:\scaping'
if (-not (Test-Path -LiteralPath 'D:\' -PathType Container)) { throw 'Il disco D: non e disponibile.' }
$sourceBinary = Join-Path $packageRoot 'scaping.exe'
if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) { throw 'Pacchetto incompleto: scaping.exe assente.' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$targetBinary = Join-Path $destination 'scaping.exe'
if ([IO.Path]::GetFullPath($sourceBinary) -eq [IO.Path]::GetFullPath($targetBinary)) { Write-Host 'Eseguibile gia nella destinazione richiesta.'; return }
if (Test-Path -LiteralPath $targetBinary) { throw 'D:\scaping\scaping.exe esiste gia. Chiudere SCAPING e conservare una copia prima di aggiornarlo.' }
Copy-Item -LiteralPath $sourceBinary -Destination $targetBinary
Write-Host 'Distribuito in D:\scaping\scaping.exe. La configurazione verra creata tramite la UI.'
