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

Invoke-Step "Backend foundational contracts" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/servicecontract ./internal/report ./internal/mcp -count=1 -v
}

Invoke-Step "Backend API contract suite" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/transport -run "TestRegisteredAPIRoutesHaveContractCases|Test.*Contract|TestHandle.*Context|TestHandle.*Method|TestHandle.*Invalid" -count=1 -v
}

Invoke-Step "Backend governance register check" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/governance -run "Test.*Defect|Test.*Report|Test.*Archive" -count=1 -v
}

Invoke-Step "Backend feature gap remediation tests" {
  Set-Location (Join-Path $root "backend")
  go test ./internal/engine -run "TestDNP3|TestIEC104|TestRTP|TestIOC|TestMITRE|TestRuleManager|TestMalleable|TestBruteForce|TestDataExfiltration|TestDNSTunnel|TestPlaybook" -count=1 -v
}

Invoke-Step "Backend tests" {
  Set-Location (Join-Path $root "backend")
  go test ./...
}

Invoke-Step "Backend coverage report" {
  Set-Location (Join-Path $root "backend")
  $coveragePath = Join-Path $env:TEMP "gshark-backend-cover.out"
  go test ./... -covermode=count -coverprofile="$coveragePath"
  go tool cover -func="$coveragePath"
}

Invoke-Step "Frontend quality checks" {
  Set-Location (Join-Path $root "frontend")
  pnpm run ci:quality
}

Invoke-Step "Frontend boundary checks" {
  Set-Location (Join-Path $root "frontend")
  pnpm run ci:boundaries
}

Invoke-Step "Frontend desktop IPC checks" {
  Set-Location (Join-Path $root "frontend")
  pnpm run ci:desktop
}

Invoke-Step "Frontend tests and build" {
  Set-Location (Join-Path $root "frontend")
  pnpm run ci:test-build
}

Invoke-Step "Frontend Wails build and desktop asset check" {
  Set-Location (Join-Path $root "frontend")
  pnpm run build:wails
}

Invoke-Step "Ignored tracked files check" {
  Set-Location $root
  powershell -ExecutionPolicy Bypass -File (Join-Path $root "scripts\check-ignored-tracked-files.ps1")
}

Write-Host ""
Write-Host "All checks passed." -ForegroundColor Green
