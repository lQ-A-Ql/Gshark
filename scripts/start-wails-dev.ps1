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

Stop-PortProcess 34115
Stop-PortProcess 17891

Set-Location "$PSScriptRoot\.."
Write-Host "[gshark] starting wails dev mode" -ForegroundColor Cyan
wails dev
