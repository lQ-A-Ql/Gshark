param(
	[switch]$NoClean,
	[switch]$CleanGoCache
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."

Write-Host "[gshark] desktop-only mode enabled; delegating to Wails dev" -ForegroundColor Green
$forward = @{}
if ($NoClean) {
	$forward.NoClean = $true
}
if ($CleanGoCache) {
	$forward.CleanGoCache = $true
}
& "$root\scripts\start-wails-dev.ps1" @forward
