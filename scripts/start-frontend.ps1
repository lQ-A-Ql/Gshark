$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\..\frontend"
Write-Host "[gshark] starting frontend dev server" -ForegroundColor Cyan
npm run dev
