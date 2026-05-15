$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$requiredAssets = @(
  @{
    Name = "bundled backend binary"
    Path = Join-Path $root "frontend/dist/sentinel-backend.exe"
  },
  @{
    Name = "bundled YARA default rule"
    Path = Join-Path $root "frontend/dist/rules/yara/default.yar"
  }
)

$missing = @()
foreach ($asset in $requiredAssets) {
  if (-not (Test-Path -LiteralPath $asset.Path -PathType Leaf)) {
    $missing += "$($asset.Name): $($asset.Path)"
  }
}

if ($missing.Count -gt 0) {
  Write-Host "Desktop asset check failed. Run 'cd frontend && pnpm run build:wails' before Wails desktop or release smoke." -ForegroundColor Red
  foreach ($item in $missing) {
    Write-Host "missing: $item" -ForegroundColor Red
  }
  throw "required desktop assets are missing"
}

Write-Host "Desktop asset check: ok" -ForegroundColor Green
