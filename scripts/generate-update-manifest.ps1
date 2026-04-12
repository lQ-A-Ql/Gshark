param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [Parameter(Mandatory = $true)]
  [string]$AssetName,

  [string]$AssetUrl = "",
  [string]$AssetPath = "",
  [string]$ReleaseUrl = "",
  [string]$Name = "",
  [string]$Notes = "",
  [string]$NotesFile = "",
  [string]$Repo = "lQ-A-Ql/Gshark",
  [string]$Channel = "stable",
  [string]$OS = "windows",
  [string]$Arch = "amd64",
  [string]$ContentType = "application/vnd.microsoft.portable-executable",
  [string]$PublishedAt = "",
  [string]$OutputPath = ""
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($PublishedAt)) {
  $PublishedAt = [DateTime]::UtcNow.ToString("o")
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $root "release/version.json"
}

if ([string]::IsNullOrWhiteSpace($Name)) {
  $Name = "Gshark $Version"
}

if ([string]::IsNullOrWhiteSpace($AssetUrl)) {
  $AssetUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"
}

if ([string]::IsNullOrWhiteSpace($ReleaseUrl)) {
  $ReleaseUrl = "https://github.com/$Repo/releases/tag/$Version"
}

if (-not [string]::IsNullOrWhiteSpace($NotesFile)) {
  $Notes = Get-Content -Path $NotesFile -Encoding UTF8 -Raw
}

$size = 0
$sha256 = ""
if (-not [string]::IsNullOrWhiteSpace($AssetPath)) {
  $resolvedAssetPath = (Resolve-Path -Path $AssetPath).Path
  $item = Get-Item -LiteralPath $resolvedAssetPath
  $size = [int64]$item.Length
  $sha256 = (Get-FileHash -LiteralPath $resolvedAssetPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest = [ordered]@{
  version      = $Version
  name         = $Name
  published_at = $PublishedAt
  release_url  = $ReleaseUrl
  notes        = $Notes
  channel      = $Channel
  generated_at = [DateTime]::UtcNow.ToString("o")
  assets       = @(
    [ordered]@{
      name         = $AssetName
      download_url = $AssetUrl
      size         = $size
      content_type = $ContentType
      sha256       = $sha256
      os           = $OS
      arch         = $Arch
    }
  )
}

$outputDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outputDir)) {
  New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
}

$json = $manifest | ConvertTo-Json -Depth 6
Set-Content -Path $OutputPath -Value $json -Encoding UTF8

Write-Host "[gshark] update manifest written to $OutputPath" -ForegroundColor Green
Write-Host "[gshark] manifest asset: $AssetName" -ForegroundColor Cyan
if ($sha256) {
  Write-Host "[gshark] manifest sha256: $sha256" -ForegroundColor Cyan
}
