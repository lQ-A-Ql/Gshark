param(
	[switch]$NoClean,
	[switch]$CleanGoCache
)

$ErrorActionPreference = "Stop"

function Stop-PortProcess($port) {
	$connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
	if (-not $connections) {
		return
	}

	$pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
	foreach ($processId in $pids) {
		if ($processId -and $processId -ne $PID) {
			try {
				Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
				Write-Host "[gshark] released port $port (pid=$processId)" -ForegroundColor Yellow
			} catch {
				Write-Host "[gshark] failed to stop pid=$processId on port $port" -ForegroundColor DarkYellow
			}
		}
	}
}

function Write-PortProbeSummary($port) {
	$connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
	if (-not $connections) {
		Write-Host "[gshark] probe: port $port is free" -ForegroundColor DarkGray
		return
	}

	foreach ($connection in $connections) {
		$process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
		$name = if ($process) { $process.ProcessName } else { "unknown" }
		Write-Host "[gshark] probe: port $port still owned by pid=$($connection.OwningProcess) process=$name" -ForegroundColor DarkYellow
	}
}

function Remove-FileIfExists($path, $label) {
	$target = [System.IO.Path]::GetFullPath($path)
	if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
		return
	}
	Remove-Item -LiteralPath $target -Force
	Write-Host "[gshark] removed stale $label`: $target" -ForegroundColor DarkYellow
}

function Remove-DirectoryIfExists($path, $label, $allowedRoot) {
	$target = [System.IO.Path]::GetFullPath($path)
	if (-not (Test-Path -LiteralPath $target -PathType Container)) {
		return
	}
	$allowed = [System.IO.Path]::GetFullPath($allowedRoot)
	if (-not $target.StartsWith($allowed, [System.StringComparison]::OrdinalIgnoreCase)) {
		throw "Refusing to remove $label outside allowed root: $target"
	}
	Remove-Item -LiteralPath $target -Recurse -Force
	Write-Host "[gshark] removed stale $label`: $target" -ForegroundColor DarkYellow
}

function Clear-WailsBackendCaches {
	$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
	$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())

	Remove-FileIfExists (Join-Path $root "frontend\dist\sentinel-backend.exe") "frontend backend asset"
	Remove-FileIfExists (Join-Path $root "build\bin\sentinel-backend.exe") "build backend binary"
	Remove-DirectoryIfExists (Join-Path $tempRoot "gshark-sentinel\backend") "extracted backend cache" $tempRoot

	if ($CleanGoCache) {
		Write-Host "[gshark] clearing Go build cache" -ForegroundColor DarkYellow
		go clean -cache
	}
}

Stop-PortProcess 34115
Stop-PortProcess 17891
Write-PortProbeSummary 34115
Write-PortProbeSummary 17891

Set-Location "$PSScriptRoot\.."
if (-not $NoClean) {
	Clear-WailsBackendCaches
} else {
	Write-Host "[gshark] backend cache cleanup skipped (-NoClean)" -ForegroundColor DarkYellow
}

Write-Host "[gshark] probe: Wails runtime snapshot uses desktop IPC first; HTTP is fallback for non-Wails browser mode." -ForegroundColor DarkGray
Write-Host "[gshark] probe: if old 'tshark capability:' log text appears, a stale backend binary/process is still running." -ForegroundColor DarkGray
Write-Host "[gshark] starting wails dev mode" -ForegroundColor Cyan
wails dev
