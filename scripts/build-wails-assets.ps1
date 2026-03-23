$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Set-Location (Join-Path $root 'frontend')
npm run build

Set-Location (Join-Path $root 'backend')
$binDir = Join-Path $root 'build/bin'
if (-not (Test-Path $binDir)) {
  New-Item -Path $binDir -ItemType Directory -Force | Out-Null
}
go build -o (Join-Path $binDir 'sentinel-backend.exe') ./cmd/sentinel
