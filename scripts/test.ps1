[CmdletBinding()]
param([ValidateSet('Release','Debug')][string]$Configuration = 'Release', [switch]$SkipBuild)
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $SkipBuild) { & (Join-Path $PSScriptRoot 'build.ps1') -Configuration $Configuration }
$cmake = Find-CMake
$ctest = Join-Path (Split-Path -Parent $cmake) 'ctest.exe'
Invoke-Checked $ctest @('--test-dir', (Join-Path $ProjectRoot 'build'), '-C', $Configuration, '--output-on-failure')
