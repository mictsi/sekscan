# Run on a connected machine with a supported Go installation.
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    & go run ./scripts/moduleupdate --yes @args
    if ($LASTEXITCODE -ne 0) { throw "Module upgrade/validation failed (exit $LASTEXITCODE)." }
} finally { Pop-Location }
