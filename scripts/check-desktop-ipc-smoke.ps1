param(
  [string]$CapturePath,
  [string]$OutputDir,
  [int]$BackendPort = 17891,
  [int]$FrontendPort = 5174,
  [int]$TimeoutSeconds = 180,
  [switch]$SkipDesktop,
  [switch]$SkipBrowserDev,
  [switch]$DisableGenericIpcAdapterExperiment
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $CapturePath) {
  $CapturePath = Join-Path $root "http.pcap"
}
$CapturePath = [System.IO.Path]::GetFullPath($CapturePath)
if (-not $OutputDir) {
  $OutputDir = Join-Path $root "output\desktop-ipc-smoke"
}
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$MiscPackageRoot = [System.IO.Path]::GetFullPath((Join-Path $OutputDir "misc-packages"))
$SmokeRunId = [Guid]::NewGuid().ToString("N")

function Stop-ProcessTree([int]$ProcessId) {
  if ($ProcessId -le 0) {
    return
  }
  $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if (-not $process) {
    return
  }
  & taskkill /PID $ProcessId /T /F | Out-Null
}

function Stop-PortProcess([int]$Port) {
  $listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  foreach ($listener in $listeners) {
    if ($listener.OwningProcess -and $listener.OwningProcess -ne $PID) {
      Stop-ProcessTree $listener.OwningProcess
    }
  }
}

function Restore-EnvValue([string]$Name, [object]$Value) {
  if ($null -eq $Value) {
    Remove-Item "Env:\$Name" -ErrorAction SilentlyContinue
    return
  }
  Set-Item "Env:\$Name" $Value
}

function Assert-IsSmokeMiscPackageDir([string]$Path, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "$Label MISC package dir is empty"
  }
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $rootPath = [System.IO.Path]::GetFullPath($MiscPackageRoot)
  $rootPrefix = $rootPath
  if (-not $rootPrefix.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) {
    $rootPrefix = $rootPrefix + [string][System.IO.Path]::DirectorySeparatorChar
  }
  if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label MISC package dir is outside smoke output root: $fullPath"
  }
  Assert-Condition (Test-Path -LiteralPath $fullPath -PathType Container) "$Label MISC package dir does not exist: $fullPath"
  return $fullPath
}

function New-SmokeMiscPackageDir([string]$Name) {
  $path = [System.IO.Path]::GetFullPath((Join-Path $MiscPackageRoot "$Name-$SmokeRunId"))
  New-Item -ItemType Directory -Force -Path $path | Out-Null
  $resolved = Assert-IsSmokeMiscPackageDir $path $Name
  return $resolved
}

function Assert-SamePath([string]$Actual, [string]$Expected, [string]$Label) {
  $actualFull = [System.IO.Path]::GetFullPath($Actual)
  $expectedFull = [System.IO.Path]::GetFullPath($Expected)
  if (-not [string]::Equals($actualFull, $expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label path mismatch: actual=$actualFull expected=$expectedFull"
  }
}

function Wait-HttpOk([string]$Url, [int]$Timeout) {
  $deadline = (Get-Date).AddSeconds($Timeout)
  do {
    try {
      $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
      if ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 300) {
        return $response
      }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  } while ((Get-Date) -lt $deadline)
  throw "Timed out waiting for HTTP OK: $Url"
}

function Invoke-SmokeJson(
  [string]$Method,
  [string]$Url,
  [hashtable]$Headers,
  [object]$Body = $null
) {
  $options = @{
    Method     = $Method
    Uri        = $Url
    Headers    = $Headers
    TimeoutSec = 30
  }
  if ($null -ne $Body) {
    $options.ContentType = "application/json"
    $options.Body = ($Body | ConvertTo-Json -Depth 10)
  }
  Invoke-RestMethod @options
}

function Assert-Condition([bool]$Condition, [string]$Message) {
  if (-not $Condition) {
    throw $Message
  }
}

$DesktopReleaseMiscPackageDir = New-SmokeMiscPackageDir "desktop-release"
$DesktopWebviewMiscPackageDir = New-SmokeMiscPackageDir "desktop-webview"
$BrowserDevMiscPackageDir = New-SmokeMiscPackageDir "browser-dev"

function Wait-CaptureReady([string]$BaseUrl, [hashtable]$Headers, [int]$Timeout) {
  $deadline = (Get-Date).AddSeconds($Timeout)
  $lastStatus = $null
  do {
    $lastStatus = Invoke-SmokeJson "GET" "$BaseUrl/api/capture/status" $Headers
    if ($lastStatus.has_capture -and [int]$lastStatus.packet_count -gt 0) {
      return $lastStatus
    }
    Start-Sleep -Milliseconds 750
  } while ((Get-Date) -lt $deadline)
  $encoded = $lastStatus | ConvertTo-Json -Depth 8
  throw "Timed out waiting for capture readiness: $encoded"
}

function Test-EventStreamReady([string]$EventsUrl) {
  $client = [System.Net.Http.HttpClient]::new()
  $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $EventsUrl)
  try {
    $response = $client.SendAsync(
      $request,
      [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
    ).GetAwaiter().GetResult()
    Assert-Condition $response.IsSuccessStatusCode "SSE endpoint returned $([int]$response.StatusCode)"
    $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $reader = [System.IO.StreamReader]::new($stream)
    $lineTask = $reader.ReadLineAsync()
    if (-not $lineTask.Wait(3000)) {
      throw "Timed out waiting for SSE ready event"
    }
    $line = [string]$lineTask.Result
    Assert-Condition ($line -eq "event: ready") "Unexpected first SSE line: $line"
    return $line
  } finally {
    $request.Dispose()
    $client.Dispose()
  }
}

function Invoke-DesktopReleaseSmoke {
  Stop-PortProcess $BackendPort
  $resultPath = Join-Path $OutputDir "wails-release-smoke-result.txt"
  $logPath = Join-Path $OutputDir "wails-release-smoke.log"
  $stdoutPath = Join-Path $OutputDir "wails-release-smoke.out.log"
  $stderrPath = Join-Path $OutputDir "wails-release-smoke.err.log"
  Remove-Item -LiteralPath $resultPath, $logPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

  $previousSmokeCheck = $env:MEOW_TRAFFIC_RELEASE_SMOKE_CHECK
  $previousSmokeResultPath = $env:MEOW_TRAFFIC_RELEASE_SMOKE_RESULT_PATH
  $previousMiscPackageDir = $env:MEOW_TRAFFIC_MISC_PACKAGE_DIR
  try {
    $env:MEOW_TRAFFIC_RELEASE_SMOKE_CHECK = "1"
    $env:MEOW_TRAFFIC_RELEASE_SMOKE_RESULT_PATH = $resultPath
    $env:MEOW_TRAFFIC_MISC_PACKAGE_DIR = $DesktopReleaseMiscPackageDir
    $process = Start-Process -FilePath "go" -ArgumentList @("run", "-tags", "dev", ".") -WorkingDirectory $root -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $exitCode = $process.ExitCode
  } finally {
    Restore-EnvValue "MEOW_TRAFFIC_RELEASE_SMOKE_CHECK" $previousSmokeCheck
    Restore-EnvValue "MEOW_TRAFFIC_RELEASE_SMOKE_RESULT_PATH" $previousSmokeResultPath
    Restore-EnvValue "MEOW_TRAFFIC_MISC_PACKAGE_DIR" $previousMiscPackageDir
    Stop-PortProcess $BackendPort
  }

  $logText = ""
  if (Test-Path -LiteralPath $logPath) {
    $logText = Get-Content -LiteralPath $logPath -Raw
  }
  if (Test-Path -LiteralPath $stdoutPath) {
    $logText = $logText + (Get-Content -LiteralPath $stdoutPath -Raw)
  }
  if (Test-Path -LiteralPath $stderrPath) {
    $logText = $logText + "`n" + (Get-Content -LiteralPath $stderrPath -Raw)
  }
  $logText | Set-Content -LiteralPath $logPath -Encoding UTF8
  $resultText = ""
  if (Test-Path -LiteralPath $resultPath) {
    $resultText = Get-Content -LiteralPath $resultPath -Raw
  }

  Assert-Condition ($exitCode -eq 0) "Desktop Wails release smoke exited with code ${exitCode}: $logText"
  Assert-Condition (($logText + $resultText).Contains("release smoke check: ok")) "Desktop release smoke did not report success"
  Assert-Condition ($logText.Contains("Environment created successfully")) "Desktop release smoke did not create WebView2 environment"
  Assert-Condition ($logText.Contains("sentinel backend listening on 127.0.0.1:$BackendPort")) "Desktop release smoke did not start embedded backend"

  [ordered]@{
    ok = $true
    log = $logPath
    result = $resultPath
    miscPackageDir = $DesktopReleaseMiscPackageDir
  }
}

function Invoke-DesktopWebviewTypedSmoke {
  Assert-Condition (Test-Path -LiteralPath $CapturePath -PathType Leaf) "Capture file not found: $CapturePath"
  Stop-PortProcess $BackendPort
  $resultPath = Join-Path $OutputDir "wails-webview-typed-smoke-result.json"
  $logPath = Join-Path $OutputDir "wails-webview-typed-smoke.log"
  $stdoutPath = Join-Path $OutputDir "wails-webview-typed-smoke.out.log"
  $stderrPath = Join-Path $OutputDir "wails-webview-typed-smoke.err.log"
  Remove-Item -LiteralPath $resultPath, $logPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

  $previousResultPath = $env:MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_RESULT_PATH
  $previousCapturePath = $env:MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_CAPTURE_PATH
  $previousSmokeMiscPackageDir = $env:MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_MISC_PACKAGE_DIR
  $previousMiscPackageDir = $env:MEOW_TRAFFIC_MISC_PACKAGE_DIR
  $previousDisableExperiment = $env:MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT
  $process = $null
  try {
    $env:MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_RESULT_PATH = $resultPath
    $env:MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_CAPTURE_PATH = $CapturePath
    $env:MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_MISC_PACKAGE_DIR = $DesktopWebviewMiscPackageDir
    $env:MEOW_TRAFFIC_MISC_PACKAGE_DIR = $DesktopWebviewMiscPackageDir
    if ($DisableGenericIpcAdapterExperiment) {
      $env:MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT = "1"
    } else {
      Remove-Item "Env:\MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT" -ErrorAction SilentlyContinue
    }
    $process = Start-Process -FilePath "go" -ArgumentList @("run", "-tags", "dev", ".") -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
      if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
        break
      }
      if ($process.HasExited) {
        break
      }
      Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    Assert-Condition (Test-Path -LiteralPath $resultPath -PathType Leaf) "Desktop WebView typed smoke did not write result file before timeout"
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    Assert-Condition ($result.ok -eq $true) "Desktop WebView typed smoke failed: $($result | ConvertTo-Json -Depth 8)"
    Assert-Condition ([int]$result.capturePackets -gt 0) "Desktop WebView typed smoke returned no capture packets"
    Assert-Condition ([int]$result.packetPageTotal -gt 0) "Desktop WebView typed smoke returned no packet page rows"
    Assert-Condition ([int]$result.sampledPacketId -gt 0) "Desktop WebView typed smoke returned no sampled packet id"
    Assert-Condition ($result.locatedPacketFound -eq $true) "Desktop WebView typed smoke did not locate sampled packet"
    Assert-Condition ([int]$result.huntingPrefixCount -gt 0) "Desktop WebView typed smoke returned no hunting prefixes"
    Assert-Condition ([int]$result.vehicleDBCProfileCount -ge 0) "Desktop WebView typed smoke returned invalid vehicle DBC profile count"
    Assert-Condition ([int]$result.pluginCount -ge 0) "Desktop WebView typed smoke returned invalid plugin count"
    Assert-Condition ([int]$result.miscModuleCount -ge 0) "Desktop WebView typed smoke returned invalid MISC module count"
    Assert-Condition ($result.miscImportBindingAvailable -eq $true) "Desktop WebView typed smoke did not confirm ImportMiscModulePackageFromPath binding availability"
    Assert-Condition ($result.miscDeleteBindingAvailable -eq $true) "Desktop WebView typed smoke did not confirm DeleteMiscModulePackage binding availability"
    Assert-Condition ($result.miscRunBindingAvailable -eq $true) "Desktop WebView typed smoke did not confirm RunMiscModulePackage binding availability"
    Assert-IsSmokeMiscPackageDir ([string]$result.miscPackageIsolationDir) "Desktop WebView typed smoke" | Out-Null
    Assert-SamePath ([string]$result.miscPackageIsolationDir) $DesktopWebviewMiscPackageDir "Desktop WebView typed smoke MISC package dir"
    Assert-IsSmokeMiscPackageDir ([string]$result.backendMiscPackageDir) "Desktop WebView backend" | Out-Null
    Assert-SamePath ([string]$result.backendMiscPackageDir) $DesktopWebviewMiscPackageDir "Desktop WebView backend MISC package dir"
    Assert-Condition ([int]$result.httpStreams -gt 0) "Desktop WebView typed smoke returned no HTTP streams"
    Assert-Condition ([int]$result.objectCount -gt 0) "Desktop WebView typed smoke returned no objects"
    Assert-Condition ([int]$result.network.directBackendApiRequestCount -eq 0) "Desktop WebView directly requested backend /api routes: $($result.network.directBackendApiRequests | ConvertTo-Json -Depth 6)"
    if ($DisableGenericIpcAdapterExperiment) {
      Assert-Condition ($result.genericIpcDisableExperimentRequested -eq $true) "Desktop WebView typed smoke did not receive generic IPC disable experiment request"
      Assert-Condition ($result.genericIpcDisableExperimentBuildFlag -eq $true) "Desktop WebView typed smoke requested generic IPC disable experiment, but frontend assets were not built with VITE_DESKTOP_DISABLE_GENERIC_IPC=1"
    }
  } finally {
    Restore-EnvValue "MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_RESULT_PATH" $previousResultPath
    Restore-EnvValue "MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_CAPTURE_PATH" $previousCapturePath
    Restore-EnvValue "MEOW_TRAFFIC_DESKTOP_WEBVIEW_SMOKE_MISC_PACKAGE_DIR" $previousSmokeMiscPackageDir
    Restore-EnvValue "MEOW_TRAFFIC_MISC_PACKAGE_DIR" $previousMiscPackageDir
    Restore-EnvValue "MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT" $previousDisableExperiment
    if ($process -and -not $process.HasExited) {
      Stop-ProcessTree $process.Id
    }
    Stop-PortProcess $BackendPort
  }

  $logText = ""
  if (Test-Path -LiteralPath $stdoutPath) {
    $logText = $logText + (Get-Content -LiteralPath $stdoutPath -Raw)
  }
  if (Test-Path -LiteralPath $stderrPath) {
    $logText = $logText + "`n" + (Get-Content -LiteralPath $stderrPath -Raw)
  }
  $logText | Set-Content -LiteralPath $logPath -Encoding UTF8

  [ordered]@{
    ok = $true
    log = $logPath
    result = $resultPath
    miscPackageDir = [string]$result.miscPackageIsolationDir
    backendMiscPackageDir = [string]$result.backendMiscPackageDir
    capturePackets = [int]$result.capturePackets
    packetPageTotal = [int]$result.packetPageTotal
    sampledPacketId = [int]$result.sampledPacketId
    locatedPacketFound = [bool]$result.locatedPacketFound
    locatedPacketCursor = [int]$result.locatedPacketCursor
    packetDetailProtocol = [string]$result.packetDetailProtocol
    threatHitCount = [int]$result.threatHitCount
    huntingPrefixCount = [int]$result.huntingPrefixCount
    huntingYaraEnabled = [bool]$result.huntingYaraEnabled
    vehicleDBCProfileCount = [int]$result.vehicleDBCProfileCount
    pluginCount = [int]$result.pluginCount
    miscModuleCount = [int]$result.miscModuleCount
    miscImportBindingAvailable = [bool]$result.miscImportBindingAvailable
    miscDeleteBindingAvailable = [bool]$result.miscDeleteBindingAvailable
    miscRunBindingAvailable = [bool]$result.miscRunBindingAvailable
    httpStreams = [int]$result.httpStreams
    tcpStreams = [int]$result.tcpStreams
    udpStreams = [int]$result.udpStreams
    sampledHttpStream = [int]$result.sampledHttpStream
    sampledHttpStreamChunks = [int]$result.sampledHttpStreamChunks
    sampledTcpStream = [int]$result.sampledTcpStream
    sampledRawStreamChunks = [int]$result.sampledRawStreamChunks
    mediaTotalPackets = [int]$result.mediaTotalPackets
    mediaSessionCount = [int]$result.mediaSessionCount
    objectCount = [int]$result.objectCount
    objectEvidenceCount = [int]$result.objectEvidenceCount
    directBackendApiRequestCount = [int]$result.network.directBackendApiRequestCount
    totalInstrumentedNetworkRequests = [int]$result.network.totalRequests
    genericIpcPolicy = [string]$result.genericIpcPolicy
    genericIpcDisableExperimentRequested = [bool]$result.genericIpcDisableExperimentRequested
    genericIpcDisableExperimentBuildFlag = [bool]$result.genericIpcDisableExperimentBuildFlag
  }
}

function Invoke-BrowserDevSmoke {
  Assert-Condition (Test-Path -LiteralPath $CapturePath -PathType Leaf) "Capture file not found: $CapturePath"
  Stop-PortProcess $BackendPort
  Stop-PortProcess $FrontendPort

  $token = "codex-ipc-smoke-token"
  $backendOut = Join-Path $OutputDir "browser-backend.out.log"
  $backendErr = Join-Path $OutputDir "browser-backend.err.log"
  $viteOut = Join-Path $OutputDir "browser-vite.out.log"
  $viteErr = Join-Path $OutputDir "browser-vite.err.log"
  Remove-Item -LiteralPath $backendOut, $backendErr, $viteOut, $viteErr -Force -ErrorAction SilentlyContinue

  $backendCmd = "`$env:MEOW_TRAFFIC_BACKEND_TOKEN='$token'; `$env:MEOW_TRAFFIC_MISC_PACKAGE_DIR='$BrowserDevMiscPackageDir'; Set-Location '$root\backend'; go run ./cmd/sentinel serve 127.0.0.1:$BackendPort"
  $viteCmd = "`$env:VITE_BACKEND_TOKEN='$token'; `$env:VITE_BACKEND_URL='http://127.0.0.1:$BackendPort'; Set-Location '$root\frontend'; pnpm exec vite --host 127.0.0.1 --port $FrontendPort --strictPort"
  $backendProcess = $null
  $viteProcess = $null
  try {
    $backendProcess = Start-Process -FilePath "powershell" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $backendCmd) -WindowStyle Hidden -PassThru -RedirectStandardOutput $backendOut -RedirectStandardError $backendErr
    Wait-HttpOk "http://127.0.0.1:$BackendPort/health" $TimeoutSeconds | Out-Null

    $viteProcess = Start-Process -FilePath "powershell" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $viteCmd) -WindowStyle Hidden -PassThru -RedirectStandardOutput $viteOut -RedirectStandardError $viteErr
    $frontendResponse = Wait-HttpOk "http://127.0.0.1:$FrontendPort/" $TimeoutSeconds

    $baseUrl = "http://127.0.0.1:$BackendPort"
    $headers = @{ Authorization = "Bearer $token" }
    $health = Invoke-SmokeJson "GET" "$baseUrl/health" $headers
    $identity = Invoke-SmokeJson "GET" "$baseUrl/api/runtime/identity" $headers
    Assert-IsSmokeMiscPackageDir ([string]$identity.misc_package_dir) "Browser-dev backend" | Out-Null
    Assert-SamePath ([string]$identity.misc_package_dir) $BrowserDevMiscPackageDir "Browser-dev backend MISC package dir"
    $runtimeFast = Invoke-SmokeJson "GET" "$baseUrl/api/tools/runtime-config?probe=fast" $headers
    $mcp = Invoke-SmokeJson "GET" "$baseUrl/api/mcp/config" $headers
    $tls = Invoke-SmokeJson "GET" "$baseUrl/api/tls" $headers
    $eventLine = Test-EventStreamReady "$baseUrl/api/events?access_token=$token"

    Invoke-SmokeJson "POST" "$baseUrl/api/capture/prepare-replacement" $headers | Out-Null
    Invoke-SmokeJson "POST" "$baseUrl/api/capture/start" $headers @{
      file_path = $CapturePath
      display_filter = ""
      max_packets = 0
      emit_packets = $false
      fast_list = $true
      list_profile = "first_screen"
      enable_enrichment = $true
    } | Out-Null
    $capture = Wait-CaptureReady $baseUrl $headers $TimeoutSeconds

    $packetPage = Invoke-SmokeJson "GET" "$baseUrl/api/packets/page?cursor=0&limit=5" $headers
    $httpIndex = Invoke-SmokeJson "GET" "$baseUrl/api/streams/index?protocol=HTTP" $headers
    $tcpIndex = Invoke-SmokeJson "GET" "$baseUrl/api/streams/index?protocol=TCP" $headers
    $udpIndex = Invoke-SmokeJson "GET" "$baseUrl/api/streams/index?protocol=UDP" $headers
    Assert-Condition ([int]$packetPage.total -gt 0) "Packet page returned no packets"
    Assert-Condition ([int]$httpIndex.total -gt 0) "HTTP stream index returned no streams"

    $firstHttpStreamId = [int]@($httpIndex.ids)[0]
    $httpStream = Invoke-SmokeJson "GET" "$baseUrl/api/streams/http?streamId=$firstHttpStreamId" $headers
    $industrial = Invoke-SmokeJson "GET" "$baseUrl/api/analysis/industrial" $headers
    $evidence = Invoke-SmokeJson "GET" "$baseUrl/api/evidence?modules=object" $headers
    $objects = Invoke-SmokeJson "GET" "$baseUrl/api/objects" $headers
    $httpLogin = Invoke-SmokeJson "GET" "$baseUrl/api/tools/http-login-analysis" $headers

    Assert-Condition ($health.status -eq "ok") "Unexpected health status"
    Assert-Condition ($identity.auth_enabled -eq $true) "Browser-dev backend auth was not enabled"
    Assert-Condition ([string]$identity.service -eq "meow-traffic") "Unexpected backend service identity"
    Assert-Condition ($eventLine -eq "event: ready") "SSE did not return ready event"
    Assert-Condition ([int]$capture.packet_count -gt 0) "Capture status returned no packets"

    [ordered]@{
      ok = $true
      frontendStatus = [int]$frontendResponse.StatusCode
      health = $health.status
      service = $identity.service
      authEnabled = $identity.auth_enabled
      miscPackageDir = [string]$identity.misc_package_dir
      runtimeProbeMode = $runtimeFast.probe_mode
      mcpEnabled = $mcp.enabled
      tlsConfigured = $tls.configured
      sseFirstLine = $eventLine
      captureFile = $capture.file_path
      capturePackets = [int]$capture.packet_count
      packetPageTotal = [int]$packetPage.total
      httpStreams = [int]$httpIndex.total
      tcpStreams = [int]$tcpIndex.total
      udpStreams = [int]$udpIndex.total
      sampledHttpStream = $firstHttpStreamId
      sampledHttpStreamChunks = @($httpStream.chunks).Count
      objectCount = @($objects).Count
      objectEvidenceCount = @($evidence.records).Count
      industrialKeys = @($industrial.PSObject.Properties.Name)
      httpLoginKeys = @($httpLogin.PSObject.Properties.Name)
      backendLog = $backendErr
      viteLog = $viteOut
    }
  } finally {
    if ($viteProcess) {
      Stop-ProcessTree $viteProcess.Id
    }
    if ($backendProcess) {
      Stop-ProcessTree $backendProcess.Id
    }
    Stop-PortProcess $FrontendPort
    Stop-PortProcess $BackendPort
  }
}

$summary = [ordered]@{
  updatedAt = (Get-Date).ToString("o")
  capturePath = $CapturePath
  outputDir = $OutputDir
  genericIpcDisableExperiment = [bool]$DisableGenericIpcAdapterExperiment
  desktopRelease = if ($SkipDesktop) { [ordered]@{ skipped = $true } } else { Invoke-DesktopReleaseSmoke }
  desktopWebviewTyped = if ($SkipDesktop) { [ordered]@{ skipped = $true } } else { Invoke-DesktopWebviewTypedSmoke }
  browserDev = if ($SkipBrowserDev) { [ordered]@{ skipped = $true } } else { Invoke-BrowserDevSmoke }
}

$summaryPath = Join-Path $OutputDir "desktop-ipc-smoke-summary.json"
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "[desktop-ipc-smoke] summary: $summaryPath" -ForegroundColor Green
Write-Host ($summary | ConvertTo-Json -Depth 8)
