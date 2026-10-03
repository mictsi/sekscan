# Usage: .\scripts\build-release.ps1 --version 0.4.0-preview --targets all
# Arguments are passed as discrete argv values; no command-string evaluation.
$ErrorActionPreference = 'Stop'
$releaseArgs = $args
$root = Split-Path -Parent $PSScriptRoot
$oldLocation = Get-Location
$oldWork = $env:GOWORK
$oldFlags = $env:GOFLAGS
$exitCode = 1
try {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'Go is not available. Install the toolchain required by go.mod first.'
    }
    Set-Location (Join-Path $root 'scripts/release')
    $env:GOWORK = 'off'
    $env:GOFLAGS = '-mod=readonly'
    & go run . --root $root @releaseArgs
    $exitCode = $LASTEXITCODE
} finally {
    Set-Location $oldLocation
    if ($null -eq $oldWork) { Remove-Item Env:GOWORK -ErrorAction SilentlyContinue } else { $env:GOWORK = $oldWork }
    if ($null -eq $oldFlags) { Remove-Item Env:GOFLAGS -ErrorAction SilentlyContinue } else { $env:GOFLAGS = $oldFlags }
}
exit $exitCode
