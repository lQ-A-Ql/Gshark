$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Write-Host "[meow-traffic] backend binary bundling is retired for Wails desktop; syncing non-binary assets only." -ForegroundColor DarkYellow
powershell -ExecutionPolicy Bypass -File (Join-Path $root 'scripts/sync-wails-assets.ps1')
