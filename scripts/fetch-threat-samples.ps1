param(
    [string]$ManifestPath = "samples/threat-pcaps/manifest.json",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ResolvedManifest = Join-Path $RepoRoot $ManifestPath
$AllowedExtensions = @(".pcap", ".pcapng", ".cap")
$MaxBytes = 200MB

function Resolve-RepoPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $RepoRoot $Path
}

function Get-RelativePath([string]$Path) {
    $root = (Resolve-Path -LiteralPath $RepoRoot).Path.TrimEnd("\")
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if ($resolved.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $resolved.Substring($root.Length).TrimStart("\") -replace "\\", "/"
    }
    return $resolved -replace "\\", "/"
}

function Assert-SafeArchiveEntry([string]$EntryName, [int64]$EntryBytes) {
    $extension = [System.IO.Path]::GetExtension($EntryName).ToLowerInvariant()
    if ($AllowedExtensions -notcontains $extension) {
        throw "archive entry rejected: $EntryName"
    }
    if ($EntryBytes -gt $MaxBytes) {
        throw "archive entry exceeds max bytes: $EntryName"
    }
}

function Test-CaptureReadable([string]$Path) {
    $capinfos = Get-Command capinfos -ErrorAction SilentlyContinue
    if ($capinfos) {
        & $capinfos.Source -c -M $Path | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "capinfos failed for $Path"
        }
    }

    $tshark = Get-Command tshark -ErrorAction SilentlyContinue
    if ($tshark) {
        & $tshark.Source -r $Path -c 5 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "tshark failed for $Path"
        }
    }
}

function Set-JsonProperty($Object, [string]$Name, $Value) {
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $Object.$Name = $Value
    } else {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

if (!(Test-Path -LiteralPath $ResolvedManifest)) {
    throw "manifest not found: $ResolvedManifest"
}

$manifest = Get-Content -Encoding UTF8 -Raw -LiteralPath $ResolvedManifest | ConvertFrom-Json
foreach ($sample in $manifest.samples) {
    if ($sample.status -eq "pending" -and !$sample.sourceUrl) {
        continue
    }
    if ($sample.status -eq "downloaded" -and (Test-Path -LiteralPath (Resolve-RepoPath $sample.localPath))) {
        continue
    }
    if (!$sample.sourceUrl) {
        $sample.status = "skipped"
        $sample.skippedReason = "missing sourceUrl"
        continue
    }

    try {
        $targetPath = Resolve-RepoPath $sample.localPath
        $targetDir = Split-Path -Parent $targetPath
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

        $sourceExt = [System.IO.Path]::GetExtension(([Uri]$sample.sourceUrl).AbsolutePath).ToLowerInvariant()
        if ($sourceExt -ne ".zip" -and $AllowedExtensions -notcontains $sourceExt) {
            throw "source extension rejected: $sourceExt"
        }

        if ($DryRun) {
            $sample.status = "dry-run"
            $sample.skippedReason = "dry run only"
            continue
        }

        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("gshark-threat-" + [Guid]::NewGuid().ToString() + $sourceExt)
        Invoke-WebRequest -UseBasicParsing -Uri $sample.sourceUrl -OutFile $tempFile -TimeoutSec 180
        $tempInfo = Get-Item -LiteralPath $tempFile
        if ($tempInfo.Length -gt $MaxBytes) {
            throw "download exceeds max bytes"
        }

        if ($sourceExt -eq ".zip") {
            if (!$sample.archivePassword) {
                throw "archivePassword required for zip source"
            }
            $list = & 7z l "-p$($sample.archivePassword)" $tempFile
            if ($LASTEXITCODE -ne 0) {
                throw "7z list failed"
            }
            $entryNames = @()
            foreach ($line in $list) {
                if ($line -match "^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(\d+)\s+\d+\s+(.+)$") {
                    $entryBytes = [int64]$Matches[1]
                    $entryName = $Matches[2].Trim()
                    $entryExt = [System.IO.Path]::GetExtension($entryName).ToLowerInvariant()
                    if ($AllowedExtensions -notcontains $entryExt) {
                        continue
                    }
                    Assert-SafeArchiveEntry $entryName $entryBytes
                    $entryNames += $entryName
                }
            }
            if ($entryNames.Count -ne 1) {
                throw "expected exactly one PCAP entry, got $($entryNames.Count)"
            }
            $extractDir = Join-Path ([System.IO.Path]::GetTempPath()) ("gshark-threat-extract-" + [Guid]::NewGuid().ToString())
            New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
            & 7z x "-p$($sample.archivePassword)" "-o$extractDir" -y $tempFile | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "7z extract failed"
            }
            $extracted = Join-Path $extractDir $entryNames[0]
            Move-Item -LiteralPath $extracted -Destination $targetPath -Force
            Remove-Item -LiteralPath $extractDir -Recurse -Force
        } else {
            Copy-Item -LiteralPath $tempFile -Destination $targetPath -Force
        }

        Test-CaptureReadable $targetPath
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $targetPath
        $info = Get-Item -LiteralPath $targetPath
        Set-JsonProperty $sample "localPath" (Get-RelativePath $targetPath)
        Set-JsonProperty $sample "sha256" $hash.Hash.ToLowerInvariant()
        Set-JsonProperty $sample "bytes" $info.Length
        Set-JsonProperty $sample "status" "downloaded"
        Set-JsonProperty $sample "downloadedAt" (Get-Date).ToString("o")
        Set-JsonProperty $sample "skippedReason" ""
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    } catch {
        Set-JsonProperty $sample "status" "failed"
        Set-JsonProperty $sample "skippedReason" $_.Exception.Message
    }
}

$json = $manifest | ConvertTo-Json -Depth 16
if (!$DryRun) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ResolvedManifest, $json, $utf8NoBom)
}
$json
