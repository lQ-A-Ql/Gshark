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

Write-Host "[gshark] release package ready" -ForegroundColor Green
Write-Host "[gshark] asset: $releaseExePath" -ForegroundColor Cyan
Write-Host "[gshark] manifest: $manifestPath" -ForegroundColor Cyan
Write-Host "[gshark] next step: upload $AssetName to GitHub Release $Version, then commit release/version.json" -ForegroundColor Yellow
