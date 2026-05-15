param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [string]$AssetName = "",
  [string]$Repo = "lQ-A-Ql/Gshark",
  [string]$Channel = "stable",
  [string]$Notes = "",
  [string]$NotesFile = "",
  [string]$SourceExePath = "",
  [string]$OutputDir = "",
  [string]$ReleaseUrl = "",
  [string]$AssetUrl = "",
  [switch]$SkipBuild,
  [switch]$NoRepoManifestUpdate
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bundledBackendPath = Join-Path $root "frontend/dist/sentinel-backend.exe"
$bundledRulePath = Join-Path $root "frontend/dist/rules/yara/default.yar"

if ([string]::IsNullOrWhiteSpace($AssetName)) {
  $AssetName = "gshark.$Version.exe"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $OutputDir = Join-Path $root "release/out/$Version"
}

if (-not (Test-Path $OutputDir)) {
  New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

Set-Location $root

if (-not $SkipBuild) {
  Write-Host "[gshark] building desktop release with wails build" -ForegroundColor Cyan
  wails build
}

& powershell -ExecutionPolicy Bypass -File (Join-Path $root "scripts/check-desktop-assets.ps1")

if (-not (Test-Path $bundledBackendPath)) {
  throw "required bundled backend is missing: $bundledBackendPath"
}
if (-not (Test-Path $bundledRulePath)) {
  throw "required bundled rules are missing: $bundledRulePath"
}

if ([string]::IsNullOrWhiteSpace($SourceExePath)) {
  $SourceExePath = Join-Path $root "build/bin/gshark-sentinel.exe"
}

$resolvedSourceExe = (Resolve-Path -Path $SourceExePath).Path
if (-not (Test-Path $resolvedSourceExe)) {
  throw "source exe not found: $SourceExePath"
}

$releaseExePath = Join-Path $OutputDir $AssetName
Copy-Item -LiteralPath $resolvedSourceExe -Destination $releaseExePath -Force
Write-Host "[gshark] release asset prepared: $releaseExePath" -ForegroundColor Green

if ([string]::IsNullOrWhiteSpace($ReleaseUrl)) {
  $ReleaseUrl = "https://github.com/$Repo/releases/tag/$Version"
}

if ([string]::IsNullOrWhiteSpace($AssetUrl)) {
  $AssetUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"
}

$manifestPath = Join-Path $OutputDir "version.json"
$manifestArgs = @(
  "-ExecutionPolicy", "Bypass",
  "-File", (Join-Path $root "scripts/generate-update-manifest.ps1"),
  "-Version", $Version,
  "-AssetName", $AssetName,
  "-AssetPath", $releaseExePath,
  "-AssetUrl", $AssetUrl,
  "-ReleaseUrl", $ReleaseUrl,
  "-Repo", $Repo,
  "-Channel", $Channel,
  "-OutputPath", $manifestPath
)

if (-not [string]::IsNullOrWhiteSpace($NotesFile)) {
  $manifestArgs += @("-NotesFile", $NotesFile)
} elseif (-not [string]::IsNullOrWhiteSpace($Notes)) {
  $manifestArgs += @("-Notes", $Notes)
}

& powershell @manifestArgs

if (-not $NoRepoManifestUpdate) {
  $repoManifestPath = Join-Path $root "release/version.json"
  Copy-Item -LiteralPath $manifestPath -Destination $repoManifestPath -Force
  Write-Host "[gshark] repository manifest updated: $repoManifestPath" -ForegroundColor Green
}

Write-Host "[gshark] running release smoke check" -ForegroundColor Cyan
$previousSmokeCheck = $env:GSHARK_RELEASE_SMOKE_CHECK
$previousSmokeResultPath = $env:GSHARK_RELEASE_SMOKE_RESULT_PATH
$smokeResultPath = Join-Path $OutputDir "release-smoke-result.txt"
$smokeStdoutPath = Join-Path $OutputDir "release-smoke-stdout.txt"
$smokeStderrPath = Join-Path $OutputDir "release-smoke-stderr.txt"
if (Test-Path -LiteralPath $smokeResultPath) {
  Remove-Item -LiteralPath $smokeResultPath -Force
}
if (Test-Path -LiteralPath $smokeStdoutPath) {
  Remove-Item -LiteralPath $smokeStdoutPath -Force
}
if (Test-Path -LiteralPath $smokeStderrPath) {
  Remove-Item -LiteralPath $smokeStderrPath -Force
}
try {
  $env:GSHARK_RELEASE_SMOKE_CHECK = "1"
  $env:GSHARK_RELEASE_SMOKE_RESULT_PATH = $smokeResultPath
  $smokeProcess = Start-Process -FilePath $releaseExePath -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $smokeStdoutPath -RedirectStandardError $smokeStderrPath
  $smokeExitCode = $smokeProcess.ExitCode
} finally {
  if ($null -eq $previousSmokeCheck) {
    Remove-Item Env:\GSHARK_RELEASE_SMOKE_CHECK -ErrorAction SilentlyContinue
  } else {
    $env:GSHARK_RELEASE_SMOKE_CHECK = $previousSmokeCheck
  }
  if ($null -eq $previousSmokeResultPath) {
    Remove-Item Env:\GSHARK_RELEASE_SMOKE_RESULT_PATH -ErrorAction SilentlyContinue
  } else {
    $env:GSHARK_RELEASE_SMOKE_RESULT_PATH = $previousSmokeResultPath
  }
}
$smokeText = ""
if (Test-Path -LiteralPath $smokeStdoutPath) {
  $smokeText = $smokeText + (Get-Content -LiteralPath $smokeStdoutPath -Raw)
}
if (Test-Path -LiteralPath $smokeStderrPath) {
  $smokeText = $smokeText + "`n" + (Get-Content -LiteralPath $smokeStderrPath -Raw)
}
if (Test-Path -LiteralPath $smokeResultPath) {
  $smokeText = $smokeText + "`n" + (Get-Content -LiteralPath $smokeResultPath -Raw)
}
if ($smokeExitCode -ne 0) {
  throw "release smoke check failed with exit code ${smokeExitCode}: $smokeText"
}
if (-not $smokeText.Contains("release smoke check: ok")) {
  throw "release smoke check did not confirm bundled backend bootstrap: $smokeText"
}
Write-Host "release smoke check: ok" -ForegroundColor Green

Write-Host "[gshark] release package ready" -ForegroundColor Green
Write-Host "[gshark] asset: $releaseExePath" -ForegroundColor Cyan
Write-Host "[gshark] manifest: $manifestPath" -ForegroundColor Cyan
Write-Host "[gshark] next step: upload $AssetName to GitHub Release $Version, then commit release/version.json" -ForegroundColor Yellow
