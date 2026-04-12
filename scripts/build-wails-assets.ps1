$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Set-Location (Join-Path $root 'frontend')
pnpm run build

Set-Location $root
powershell -ExecutionPolicy Bypass -File (Join-Path $root 'scripts/build-backend-binary.ps1')
