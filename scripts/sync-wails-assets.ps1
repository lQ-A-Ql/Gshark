$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$distDir = Join-Path $root 'frontend/dist'
if (-not (Test-Path $distDir)) {
  New-Item -Path $distDir -ItemType Directory -Force | Out-Null
}

$rulesSrc = Join-Path $root 'backend/rules'
if (Test-Path $rulesSrc) {
  $rulesDst = Join-Path $distDir 'rules'
  if (Test-Path $rulesDst) {
    Remove-Item -Path $rulesDst -Recurse -Force
  }
  Copy-Item -Path $rulesSrc -Destination $rulesDst -Recurse -Force
}

$staleBackend = Join-Path $distDir 'sentinel-backend.exe'
if (Test-Path -LiteralPath $staleBackend -PathType Leaf) {
  Remove-Item -LiteralPath $staleBackend -Force
}
