$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."

Write-Host "[gshark] launching backend and frontend terminals" -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$root\scripts\start-backend.ps1`""
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$root\scripts\start-frontend.ps1`""
Write-Host "[gshark] both processes launched" -ForegroundColor Green
