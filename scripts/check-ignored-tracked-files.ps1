$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
  $ignoredTracked = git ls-files -ci --exclude-standard
  if ($ignoredTracked) {
    Write-Host "Tracked files now match .gitignore and should be removed from git index:" -ForegroundColor Red
    $ignoredTracked | ForEach-Object { Write-Host "  $_" }
    throw "ignored tracked files detected"
  }
  Write-Host "Ignored tracked file check passed." -ForegroundColor Green
} finally {
  Pop-Location
}

