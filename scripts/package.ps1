[CmdletBinding()]
param([switch]$SkipBuild)
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $SkipBuild) { & (Join-Path $PSScriptRoot 'build.ps1') -Configuration Release }
$dist = Join-Path $ProjectRoot 'dist'
$stage = Join-Path $dist ('package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
# Explicit allow-list. Never recursively copy the working tree or local data.
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'build\Release\scaping.exe') -Destination (Join-Path $stage 'scaping.exe')
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'README.md'), (Join-Path $ProjectRoot 'README.it.md') -Destination $stage
New-Item -ItemType Directory -Path (Join-Path $stage 'resources'), (Join-Path $stage 'scripts'), (Join-Path $stage 'docs') | Out-Null
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'resources\config.example.ini') -Destination (Join-Path $stage 'resources')
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'scripts\run.ps1'), (Join-Path $ProjectRoot 'scripts\deploy.ps1') -Destination (Join-Path $stage 'scripts')
foreach ($document in @('DEPENDENCIES.md','SECURITY.md','VERIFICATION.md','DEPENDENCIES.it.md','SECURITY.it.md','VERIFICATION.it.md')) {
    Copy-Item -LiteralPath (Join-Path $ProjectRoot ('docs\' + $document)) -Destination (Join-Path $stage 'docs')
}
$hash = Get-FileHash -LiteralPath (Join-Path $stage 'scaping.exe') -Algorithm SHA256
[IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS.txt'), $hash.Hash.ToLowerInvariant() + '  scaping.exe' + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$archive = Join-Path $dist 'scaping-1.1.0-windows-x64.zip'
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
Write-Host "Package: $archive"
Write-Host "Executable SHA256: $($hash.Hash)"
