[CmdletBinding()]
param(
    [string]$Executable = (Join-Path $PSScriptRoot "..\out\build\windows-vs2022-x64\Release\WebServer.exe")
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path -LiteralPath $Executable).Path
$process = Start-Process -FilePath $resolved -ArgumentList "--uninstall-service" -Verb RunAs -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "Service removal failed with exit code $($process.ExitCode)."
}
Write-Host "WebServer service removed."
