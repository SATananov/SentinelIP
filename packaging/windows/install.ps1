#requires -RunAsAdministrator
param(
    [ValidateSet('Install', 'Start', 'Stop', 'Restart', 'Status')][string]$Action = 'Install',
    [string]$PythonPath,
    [string]$NmapPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$paths = Get-SensorPaths
$serviceName = 'SentinelIPSensor'

if ($Action -ne 'Install') {
    switch ($Action) {
        'Start' { Start-Service -Name $serviceName }
        'Stop' { Stop-Service -Name $serviceName }
        'Restart' { Restart-Service -Name $serviceName }
        'Status' { Get-Service -Name $serviceName }
    }
    return
}
if (-not $PythonPath) { throw 'Supply the full path to an all-users Python 3.10+ python.exe with pywin32 installed.' }
Assert-TrustedExecutable $PythonPath 'python.exe'
& $PythonPath -I -c 'import sys, win32service, win32security, servicemanager; assert sys.version_info >= (3, 10)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ and pywin32 are required; install prerequisites explicitly.' }
if ($NmapPath) { Assert-TrustedExecutable $NmapPath 'nmap.exe' }
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') { throw 'Stop the sensor service before reinstalling.' }
Assert-SensorTree $paths.App
Assert-SensorTree $paths.Data
Set-SensorDirectoryAcl (Split-Path -Parent $paths.App) $false
Set-SensorDirectoryAcl $paths.App $false
Set-SensorDirectoryAcl (Split-Path -Parent $paths.Data) $true
Set-SensorDirectoryAcl $paths.Data $true
Set-SensorDirectoryAcl (Join-Path $paths.Data 'state') $true
foreach ($directory in @('sensor', 'services', 'services\scanner_adapters')) {
    Set-SensorDirectoryAcl (Join-Path $paths.App $directory) $false
}
$sensorModules = @('__init__', '__main__', 'client', 'config', 'runtime', 'state', 'version', 'platforms', 'windows_security', 'windows_service')
$serviceModules = @('__init__', 'remote_sensor_executor', 'windows_sensor_executor', 'remote_sensor_models', 'scan_models', 'scanner', 'host_discovery', 'service_discovery', 'service_models', 'service_fingerprint', 'target_policy', 'public_target_policy', 'sensor_transport')
foreach ($name in $sensorModules) {
    Copy-Item -LiteralPath (Join-Path $source "sensor\$name.py") -Destination (Join-Path $paths.App "sensor\$name.py") -Force
}
foreach ($name in $serviceModules) {
    Copy-Item -LiteralPath (Join-Path $source "services\$name.py") -Destination (Join-Path $paths.App "services\$name.py") -Force
}
foreach ($name in @('__init__.py', 'nmap_adapter.py')) {
    Copy-Item -LiteralPath (Join-Path $source "services\scanner_adapters\$name") -Destination (Join-Path $paths.App "services\scanner_adapters\$name") -Force
}
foreach ($name in @('SentinelIPSensorService.py', 'sensor_launcher.py', 'sentinelip-sensor.ps1', 'common.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $paths.App $name) -Force
}
Set-Content -LiteralPath (Join-Path $paths.App 'python-path.txt') -Value $PythonPath -Encoding UTF8
foreach ($file in Get-ChildItem -LiteralPath $paths.App -File -Recurse) {
    Set-SensorFileAcl $file.FullName $false
}
foreach ($name in @('config', 'grants')) {
    $target = Join-Path $paths.Data "$name.example.json"
    if (-not (Test-Path -LiteralPath $target)) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "example-$name.json") -Destination $target
    }
    Set-SensorFileAcl $target $true
    $active = Join-Path $paths.Data "$name.json"
    if (Test-Path -LiteralPath $active) { Set-SensorFileAcl $active $true }
}
$previous = $env:SENTINEL_SENSOR_NMAP
try {
    if ($NmapPath) { $env:SENTINEL_SENSOR_NMAP = $NmapPath }
    & $PythonPath -I (Join-Path $paths.App 'SentinelIPSensorService.py') install
    if ($LASTEXITCODE -ne 0) { throw 'Service registration failed; verify the Nmap and Python installations.' }
} finally { $env:SENTINEL_SENSOR_NMAP = $previous }
Write-Output 'Installed SentinelIPSensor as LocalService (manual start). Enroll, refresh grant, self-test, then start explicitly.'
