param(
  [Parameter(Mandatory = $true)]
  [string]$Id,

  [Parameter(Mandatory = $true)]
  [string]$Title,

  [ValidateSet("javascript", "python")]
  [string]$Runtime = "javascript",

  [string]$OutputDir = "",

  [switch]$Zip
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $OutputDir = Join-Path $root "examples\misc-modules"
}

if ($Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
  throw "Invalid module id: $Id"
}

$moduleDir = Join-Path $OutputDir $Id
if (Test-Path $moduleDir) {
  throw "Target directory already exists: $moduleDir"
}

New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null

$entryFile = if ($Runtime -eq "python") { "backend.py" } else { "backend.js" }
$hostBridge = if ($Runtime -eq "python") { "true" } else { "false" }

$manifest = @"
{
  "id": "$Id",
  "title": "$Title",
  "summary": "Describe what this module does.",
  "version": "0.1.0",
  "author": "User",
  "tags": ["Custom"],
  "requires_capture": false,
  "backend": "$entryFile",
  "api": "api.json",
  "form": "form.json"
}
"@

$api = @"
{
  "method": "POST",
  "entry": "$entryFile",
  "host_bridge": $hostBridge
}
"@

$form = @"
{
  "description": "This module uses the unified MISC card template.",
  "submit_label": "Run Module",
  "result_title": "Module Result",
  "fields": [
    {
      "name": "message",
      "label": "Message",
      "type": "textarea",
      "rows": 8,
      "placeholder": "Enter your input"
    }
  ]
}
"@

$backendJs = @"
export function onRequest(input, ctx) {
  const message = String(input.values.message || "");

  let capturePreview = "";
  if (input.capture_path) {
    const scan = ctx.scanFields(["frame.number", "_ws.col.Protocol"]);
    if (scan.rows.length > 0) {
      capturePreview = " first-frame=" + String(scan.rows[0]["frame.number"] || "");
    }
  }

  return {
    message: "Module finished",
    text: message + capturePreview,
    output: {
      capture_path: input.capture_path || "",
      tshark_path: input.tshark_path || "",
      python_path: input.python_path || ""
    }
  };
}
"@

$backendPy = @"
from gshark_misc_host import run, scan_fields

def on_request(payload):
    message = str(payload.get("values", {}).get("message", ""))
    rows = []
    if payload.get("capture_path"):
        rows = scan_fields(["frame.number", "_ws.col.Protocol"]).get("rows", [])

    table_rows = []
    if rows:
        first = rows[0]
        table_rows.append({
            "frame": str(first.get("frame.number", "")),
            "protocol": str(first.get("_ws.col.Protocol", ""))
        })

    return {
        "message": "Module finished",
        "text": message,
        "table": {
            "columns": [
                {"key": "frame", "label": "Frame"},
                {"key": "protocol", "label": "Protocol"}
            ],
            "rows": table_rows
        },
        "output": {
            "capture_path": str(payload.get("capture_path", "")),
            "tshark_path": str(payload.get("tshark_path", "")),
            "python_path": str(payload.get("python_path", ""))
        }
    }

if __name__ == "__main__":
    run(on_request)
"@

Set-Content -LiteralPath (Join-Path $moduleDir "manifest.json") -Value $manifest -Encoding utf8
Set-Content -LiteralPath (Join-Path $moduleDir "api.json") -Value $api -Encoding utf8
Set-Content -LiteralPath (Join-Path $moduleDir "form.json") -Value $form -Encoding utf8
Set-Content -LiteralPath (Join-Path $moduleDir $entryFile) -Value ($(if ($Runtime -eq "python") { $backendPy } else { $backendJs })) -Encoding utf8

$zipPath = ""
if ($Zip) {
  $zipPath = Join-Path $OutputDir "$Id.zip"
  if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
  }
  Compress-Archive -Path $moduleDir -DestinationPath $zipPath
}

Write-Host "Module scaffold created: $moduleDir"
if ($zipPath) {
  Write-Host "Zip package created: $zipPath"
}
