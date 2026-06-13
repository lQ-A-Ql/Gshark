$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Set-Location (Join-Path $root 'backend')
$binDir = Join-Path $root 'build/bin'
if (-not (Test-Path $binDir)) {
  New-Item -Path $binDir -ItemType Directory -Force | Out-Null
}
$backendExe = Join-Path $binDir 'sentinel-backend.exe'
go build -o $backendExe ./cmd/sentinel

$distDir = Join-Path $root 'frontend/dist'
if (-not (Test-Path $distDir)) {
  New-Item -Path $distDir -ItemType Directory -Force | Out-Null
}
Copy-Item -Path $backendExe -Destination (Join-Path $distDir 'sentinel-backend.exe') -Force

$rulesSrc = Join-Path $root 'backend/rules'
if (Test-Path $rulesSrc) {
  $rulesDst = Join-Path $distDir 'rules'
  if (Test-Path $rulesDst) {
    Remove-Item -Path $rulesDst -Recurse -Force
  }
  Copy-Item -Path $rulesSrc -Destination $rulesDst -Recurse -Force
}
