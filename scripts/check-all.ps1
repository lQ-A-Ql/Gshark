$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Action
  )

  Write-Host ""
  Write-Host "==> $Name" -ForegroundColor Cyan
  & $Action
}

Invoke-Step "Desktop shell tests" {
  Set-Location $root
  go test ./...
}

Invoke-Step "Backend fmt check" {
  Set-Location (Join-Path $root "backend")
  $unformatted = gofmt -l .
  if ($unformatted) {
    Write-Host $unformatted
    throw "backend contains unformatted Go files"
  }
}

Invoke-Step "Backend tests" {
  Set-Location (Join-Path $root "backend")
  go test ./...
}

Invoke-Step "Frontend tests" {
  Set-Location (Join-Path $root "frontend")
  npm run test
}

Invoke-Step "Frontend build" {
  Set-Location (Join-Path $root "frontend")
  npm run build
}

Write-Host ""
Write-Host "All checks passed." -ForegroundColor Green
