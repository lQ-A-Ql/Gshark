$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."

Write-Host "[gshark] desktop-only mode enabled; delegating to Wails dev" -ForegroundColor Green
& "$root\scripts\start-wails-dev.ps1"
