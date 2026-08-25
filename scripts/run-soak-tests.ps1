[CmdletBinding()]
param(
    [ValidateRange(1, 10000)]
    [int]$Iterations = 100,
    [string]$BuildDirectory = (Join-Path $PSScriptRoot "..\out\build\windows-vs2022-x64")
)

$ErrorActionPreference = "Stop"
$resolvedBuild = (Resolve-Path -LiteralPath $BuildDirectory).Path
ctest --test-dir $resolvedBuild -C Release -R "WebServer.StabilityIntegration" --repeat "until-fail:$Iterations" --output-on-failure
if ($LASTEXITCODE -ne 0) {
    throw "Stability soak test failed."
}
