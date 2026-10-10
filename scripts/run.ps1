
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH=Join-Path $root 'src'
Set-Location $root
python -m sentinelmesh.cli @Arguments
exit $LASTEXITCODE
