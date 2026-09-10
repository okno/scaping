[CmdletBinding()]
param([ValidateSet('Release','Debug')][string]$Configuration = 'Release')
. (Join-Path $PSScriptRoot 'common.ps1')
$cmake = Find-CMake
$build = Join-Path $ProjectRoot 'build'
Invoke-Checked $cmake @('-S', $ProjectRoot, '-B', $build, '-G', 'Visual Studio 17 2022', '-A', 'x64', '-DBUILD_TESTING=ON')
Invoke-Checked $cmake @('--build', $build, '--config', $Configuration, '--parallel', '4')
if ($Configuration -eq 'Release') {
    $binary = Join-Path $build 'Release\scaping.exe'
    $destination = Join-Path $ProjectRoot 'scaping.exe'
    Copy-Item -LiteralPath $binary -Destination $destination -Force
    Write-Host "Eseguibile: $destination"
}
