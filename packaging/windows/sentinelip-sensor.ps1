Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$pythonPath = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'python-path.txt') -Raw).Trim()
Assert-TrustedExecutable $pythonPath 'python.exe'
# No shell interpolation: arguments are passed to the shared CLI's closed parser.
& $pythonPath -I (Join-Path $PSScriptRoot 'sensor_launcher.py') @args
exit $LASTEXITCODE
