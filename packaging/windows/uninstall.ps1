#requires -RunAsAdministrator
param([switch]$Purge)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$paths = Get-SensorPaths
Assert-SensorTree $paths.App
Assert-SensorTree $paths.Data
$service = Get-Service -Name 'SentinelIPSensor' -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name 'SentinelIPSensor'
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(120))
    # Fixed service identity; no free-form service name or command.
    & (Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe') delete SentinelIPSensor
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove SentinelIPSensor service.' }
}
foreach ($name in @('sensor', 'services')) {
    $target = Join-Path $paths.App $name
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
foreach ($name in @('SentinelIPSensorService.py', 'sensor_launcher.py', 'sentinelip-sensor.ps1', 'common.ps1', 'python-path.txt')) {
    $target = Join-Path $paths.App $name
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
}
if ($Purge) {
    foreach ($name in @('config.json', 'grants.json', 'config.example.json', 'grants.example.json')) {
        $target = Join-Path $paths.Data $name
        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    }
}
Write-Output 'Sensor service/runtime removed. Configuration is preserved unless -Purge was explicitly used.'
