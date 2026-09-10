[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$requiredRoot = 'D:\scaping'
$binary = Join-Path $requiredRoot 'scaping.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Eseguibile assente: D:\scaping\scaping.exe. Compilare o distribuire il pacchetto prima di avviarlo.'
}
Start-Process -FilePath $binary -WorkingDirectory $requiredRoot -WindowStyle Hidden
