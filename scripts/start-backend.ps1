$ErrorActionPreference = "Stop"

function Stop-PortProcess($port) {
	$connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
	if (-not $connections) {
		return
	}

	$processIds = $connections | Select-Object -ExpandProperty OwningProcess -Unique
	foreach ($processId in $processIds) {
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

Stop-PortProcess 17891

Set-Location "$PSScriptRoot\..\backend"
Write-Host "[gshark] starting backend on :17891" -ForegroundColor Cyan
go run ./cmd/sentinel serve :17891
