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

Invoke-Step "Desktop assets build for embed tests" {
  Set-Location (Join-Path $root "frontend")
  pnpm run build:wails
}

Invoke-Step "Desktop shell dev-tag tests" {
  Set-Location $root
  go test -tags dev ./...
}

Invoke-Step "Desktop shell production-tag tests" {
  Set-Location $root
  go test -tags production ./...
}

Invoke-Step "Backend fmt check" {
  Set-Location (Join-Path $root "backend")
  $unformatted = gofmt -l .
  if ($unformatted) {
    Write-Host $unformatted
    throw "backend contains unformatted Go files"
  }
}

Invoke-Step "Backend boundary check" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v
}

Invoke-Step "Backend focused contracts" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/engine -run "TestGatherEvidence|Test.*InvestigationReport|TestBundledPublic" -count=1 -v
}

Invoke-Step "Backend governance register check" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/governance -run "Test.*Defect|Test.*Report|Test.*Archive" -count=1 -v
}

Invoke-Step "Backend tests" {
  Set-Location (Join-Path $root "backend")
  go test ./...
}

Invoke-Step "Frontend package manager check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run package-manager:check
}

Invoke-Step "Frontend tests" {
  Set-Location (Join-Path $root "frontend")
  pnpm run test:run
}

Invoke-Step "Frontend typecheck" {
  Set-Location (Join-Path $root "frontend")
  pnpm run typecheck
}

Invoke-Step "Frontend lint" {
  Set-Location (Join-Path $root "frontend")
  pnpm run lint
}

Invoke-Step "Frontend format check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run format:check
}

Invoke-Step "Frontend size check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run size:check
}

Invoke-Step "Frontend boundary check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run boundary:check
}

Invoke-Step "Frontend client any check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run client:any:check
}

Invoke-Step "Frontend mapper any check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run mapper:any:check
}

Invoke-Step "Frontend wire any check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run wire:any:check
}

Invoke-Step "Frontend Wails build and desktop asset check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run build:wails
}

Write-Host ""
Write-Host "All checks passed." -ForegroundColor Green
