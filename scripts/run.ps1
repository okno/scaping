[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$requiredRoot = 'D:\scaping'
$binary = Join-Path $requiredRoot 'scaping.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Executable missing: D:\scaping\scaping.exe. Build or deploy the package before starting it.'
}
Start-Process -FilePath $binary -WorkingDirectory $requiredRoot -WindowStyle Hidden
