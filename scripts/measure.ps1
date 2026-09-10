[CmdletBinding()]
param([Parameter(Mandatory)][int]$ProcessId, [ValidateRange(10,3600)][int]$Seconds = 60, [string]$Condition = 'monitoring only')
. (Join-Path $PSScriptRoot 'common.ps1')
$process = Get-Process -Id $ProcessId
if ($process.ProcessName -ne 'scaping') { throw 'The selected process is not SCAPING.' }
$startCpu = $process.TotalProcessorTime.TotalMilliseconds
$logicalCpus = [Environment]::ProcessorCount
$watch = [Diagnostics.Stopwatch]::StartNew()
$samples = [Collections.Generic.List[long]]::new()
for ($index = 0; $index -lt $Seconds; $index++) {
    Start-Sleep -Seconds 1
    $process.Refresh()
    if ($process.HasExited) { throw 'SCAPING exited during the measurement.' }
    $samples.Add($process.PrivateMemorySize64)
}
$watch.Stop()
$cpuPercent = ($process.TotalProcessorTime.TotalMilliseconds - $startCpu) / $watch.Elapsed.TotalMilliseconds / $logicalCpus * 100
$result = [pscustomobject]@{
    condition = $Condition; seconds = [math]::Round($watch.Elapsed.TotalSeconds, 3)
    logicalProcessors = $logicalCpus; averageTotalMachineCpuPercent = [math]::Round($cpuPercent, 4)
    averagePrivateBytes = [long](($samples | Measure-Object -Average).Average)
    peakPrivateBytes = ($samples | Measure-Object -Maximum).Maximum
    scanProcessesIncluded = $false
}
$data = Join-Path $ProjectRoot 'data'
New-Item -ItemType Directory -Path $data -Force | Out-Null
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $data ('measurement-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')) -Encoding UTF8
$result
