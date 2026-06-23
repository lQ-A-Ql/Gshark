import { isDesktopGenericIpcDisabled, resolveDesktopGenericIpcPolicy } from "./integrations/desktopGenericIpcPolicy";

type DesktopSmokeBinding = {
  GetDesktopWebviewSmokeConfig?: () => Promise<unknown>;
  WriteDesktopWebviewSmokeResult?: (payload: unknown) => Promise<void>;
  IsBackendReady?: () => Promise<boolean>;
  PingBackendDataPlane?: () => Promise<unknown>;
  GetToolRuntimeSnapshotFast?: () => Promise<unknown>;
  GetMCPStatus?: () => Promise<unknown>;
  GetTLSConfig?: () => Promise<unknown>;
  PrepareCaptureReplacement?: () => Promise<void>;
  StartCapture?: (filePath: string, filter: string) => Promise<void>;
  GetCaptureStatus?: () => Promise<unknown>;
  ListPacketsPage?: (cursor: number, limit: number, filter: string) => Promise<unknown>;
  LocatePacketPage?: (packetId: number, limit: number, filter: string) => Promise<unknown>;
  GetPacket?: (packetId: number) => Promise<unknown>;
  ListThreatHits?: (prefixes: string[]) => Promise<unknown>;
  GetHuntingRuntimeConfig?: () => Promise<unknown>;
  ListVehicleDBCProfiles?: () => Promise<unknown>;
  ListMiscModules?: () => Promise<unknown>;
  SelectMiscModulePackage?: () => Promise<unknown>;
  ImportMiscModulePackageFromPath?: (path: string) => Promise<unknown>;
  DeleteMiscModulePackage?: (id: string) => Promise<unknown>;
  RunMiscModulePackage?: (id: string, values: Record<string, string>) => Promise<unknown>;
  ListStreamIDs?: (protocol: string) => Promise<unknown>;
  GetHttpStream?: (streamId: number) => Promise<unknown>;
  GetRawStreamPage?: (protocol: string, streamId: number, cursor: number, limit: number) => Promise<unknown>;
  GetIndustrialAnalysis?: () => Promise<unknown>;
  GetMediaAnalysis?: (forceRefresh: boolean) => Promise<unknown>;
  GetEvidenceWithFilter?: (modules: string[]) => Promise<unknown>;
  ListObjects?: () => Promise<unknown>;
  GetHTTPLoginAnalysis?: () => Promise<unknown>;
};

type NetworkProbe = {
  kind: string;
  url: string;
};

const DIRECT_BACKEND_API_PATTERN = /^https?:\/\/127\.0\.0\.1:17891\/api\//i;

export async function runDesktopWebviewSmokeIfEnabled(): Promise<boolean> {
  const desktopApp = getDesktopAppBinding();
  if (!desktopApp?.GetDesktopWebviewSmokeConfig || !desktopApp.WriteDesktopWebviewSmokeResult) {
    return false;
  }

  const config = (await desktopApp.GetDesktopWebviewSmokeConfig()) as {
    enabled?: unknown;
    capture_path?: unknown;
    misc_package_dir?: unknown;
    generic_ipc_disable_experiment?: unknown;
  };
  if (!config?.enabled) {
    return false;
  }

  const networkProbes = installNetworkProbe();
  const startedAt = Date.now();
  try {
    const summary = await runDesktopTypedSmoke(
      desktopApp,
      String(config.capture_path ?? ""),
      String(config.misc_package_dir ?? ""),
    );
    await desktopApp.WriteDesktopWebviewSmokeResult({
      ok: true,
      updatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      genericIpcPolicy: resolveDesktopGenericIpcPolicy(),
      genericIpcDisableExperimentRequested: Boolean(config.generic_ipc_disable_experiment),
      genericIpcDisableExperimentBuildFlag: isGenericIpcDisableExperimentBuildEnabled(),
      network: summarizeNetworkProbes(networkProbes),
      ...summary,
    });
  } catch (error) {
    await desktopApp.WriteDesktopWebviewSmokeResult({
      ok: false,
      updatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      genericIpcPolicy: resolveDesktopGenericIpcPolicy(),
      genericIpcDisableExperimentRequested: Boolean(config.generic_ipc_disable_experiment),
      genericIpcDisableExperimentBuildFlag: isGenericIpcDisableExperimentBuildEnabled(),
      error: error instanceof Error ? error.message : String(error),
      network: summarizeNetworkProbes(networkProbes),
    });
  }
  return true;
}

async function runDesktopTypedSmoke(
  desktopApp: DesktopSmokeBinding,
  capturePath: string,
  miscPackageIsolationDir: string,
) {
  assertBinding(desktopApp.GetToolRuntimeSnapshotFast, "GetToolRuntimeSnapshotFast");
  assertBinding(desktopApp.IsBackendReady, "IsBackendReady");
  assertBinding(desktopApp.GetMCPStatus, "GetMCPStatus");
  assertBinding(desktopApp.GetTLSConfig, "GetTLSConfig");
  assertBinding(desktopApp.PrepareCaptureReplacement, "PrepareCaptureReplacement");
  assertBinding(desktopApp.StartCapture, "StartCapture");
  assertBinding(desktopApp.GetCaptureStatus, "GetCaptureStatus");
  assertBinding(desktopApp.ListPacketsPage, "ListPacketsPage");
  assertBinding(desktopApp.LocatePacketPage, "LocatePacketPage");
  assertBinding(desktopApp.GetPacket, "GetPacket");
  assertBinding(desktopApp.ListThreatHits, "ListThreatHits");
  assertBinding(desktopApp.GetHuntingRuntimeConfig, "GetHuntingRuntimeConfig");
  assertBinding(desktopApp.ListVehicleDBCProfiles, "ListVehicleDBCProfiles");
  assertBinding(desktopApp.ListMiscModules, "ListMiscModules");
  assertBinding(desktopApp.SelectMiscModulePackage, "SelectMiscModulePackage");
  assertBinding(desktopApp.ImportMiscModulePackageFromPath, "ImportMiscModulePackageFromPath");
  assertBinding(desktopApp.DeleteMiscModulePackage, "DeleteMiscModulePackage");
  assertBinding(desktopApp.RunMiscModulePackage, "RunMiscModulePackage");
  assertBinding(desktopApp.ListStreamIDs, "ListStreamIDs");
  assertBinding(desktopApp.GetHttpStream, "GetHttpStream");
  assertBinding(desktopApp.GetRawStreamPage, "GetRawStreamPage");
  assertBinding(desktopApp.GetIndustrialAnalysis, "GetIndustrialAnalysis");
  assertBinding(desktopApp.GetMediaAnalysis, "GetMediaAnalysis");
  assertBinding(desktopApp.GetEvidenceWithFilter, "GetEvidenceWithFilter");
  assertBinding(desktopApp.ListObjects, "ListObjects");
  assertBinding(desktopApp.GetHTTPLoginAnalysis, "GetHTTPLoginAnalysis");
  if (!capturePath.trim()) {
    throw new Error("desktop WebView smoke capture path is empty");
  }
  if (!miscPackageIsolationDir.trim()) {
    throw new Error("desktop WebView smoke MISC package isolation dir is empty");
  }

  const backendProbe = await waitDesktopBackendReady(desktopApp);
  const backendMiscPackageDir = String(backendProbe.misc_package_dir ?? "");
  if (backendMiscPackageDir && !samePath(backendMiscPackageDir, miscPackageIsolationDir)) {
    throw new Error(
      `desktop WebView smoke MISC package dir mismatch: backend=${backendMiscPackageDir} config=${miscPackageIsolationDir}`,
    );
  }
  const runtimeFast = await desktopApp.GetToolRuntimeSnapshotFast!();
  const mcp = await desktopApp.GetMCPStatus!();
  const tls = await desktopApp.GetTLSConfig!();

  await desktopApp.PrepareCaptureReplacement!();
  await desktopApp.StartCapture!(capturePath, "");
  const capture = await waitCaptureReady(desktopApp);
  const packetPage = asRecord(await desktopApp.ListPacketsPage!(0, 5, ""));
  const httpIndex = asRecord(await desktopApp.ListStreamIDs!("HTTP"));
  const tcpIndex = asRecord(await desktopApp.ListStreamIDs!("TCP"));
  const udpIndex = asRecord(await desktopApp.ListStreamIDs!("UDP"));

  const httpIds = asNumberList(httpIndex.ids);
  const tcpIds = asNumberList(tcpIndex.ids);
  const udpIds = asNumberList(udpIndex.ids);
  if (Number(packetPage.total ?? 0) <= 0) {
    throw new Error("desktop typed packet page returned no packets");
  }
  if (httpIds.length === 0) {
    throw new Error("desktop typed HTTP stream index returned no streams");
  }

  const sampledHttpStream = httpIds[0] ?? 0;
  const sampledTcpStream = tcpIds[0] ?? sampledHttpStream;
  const sampledPacket = asRecord(asList(packetPage.items)[0]);
  const sampledPacketId = Number(sampledPacket.id ?? 0);
  if (sampledPacketId <= 0) {
    throw new Error("desktop typed packet page returned an invalid packet id");
  }
  const packetLocate = asRecord(await desktopApp.LocatePacketPage!(sampledPacketId, 5, ""));
  const packetDetail = asRecord(await desktopApp.GetPacket!(sampledPacketId));
  const threatHits = await desktopApp.ListThreatHits!(["flag{", "ctf{"]);
  const huntingConfig = asRecord(await desktopApp.GetHuntingRuntimeConfig!());
  const dbcProfiles = await desktopApp.ListVehicleDBCProfiles!();
  const miscModules = await desktopApp.ListMiscModules!();
  const httpStream = asRecord(await desktopApp.GetHttpStream!(sampledHttpStream));
  const rawStreamPage = asRecord(await desktopApp.GetRawStreamPage!("TCP", sampledTcpStream, 0, 1));
  const industrial = asRecord(await desktopApp.GetIndustrialAnalysis!());
  const media = asRecord(await desktopApp.GetMediaAnalysis!(false));
  const evidence = asRecord(await desktopApp.GetEvidenceWithFilter!(["object"]));
  const objects = await desktopApp.ListObjects!();
  const httpLogin = asRecord(await desktopApp.GetHTTPLoginAnalysis!());

  return {
    capturePath,
    miscPackageIsolationDir,
    backendMiscPackageDir,
    runtimeProbeMode: String(asRecord(runtimeFast).probe_mode ?? ""),
    mcpEnabled: Boolean(asRecord(mcp).enabled),
    tlsConfigured: asRecord(tls).configured ?? null,
    capturePackets: Number(asRecord(capture).packet_count ?? 0),
    packetPageTotal: Number(packetPage.total ?? 0),
    sampledPacketId,
    locatedPacketFound: Boolean(packetLocate.found),
    locatedPacketCursor: Number(packetLocate.cursor ?? 0),
    packetDetailProtocol: String(packetDetail.display_protocol ?? packetDetail.protocol ?? ""),
    threatHitCount: asList(threatHits).length,
    huntingPrefixCount: asList(huntingConfig.prefixes).length,
    huntingYaraEnabled: Boolean(huntingConfig.yara_enabled),
    vehicleDBCProfileCount: asList(dbcProfiles).length,
    miscModuleCount: asList(miscModules).length,
    miscImportBindingAvailable: true,
    miscDeleteBindingAvailable: true,
    miscRunBindingAvailable: true,
    httpStreams: httpIds.length,
    tcpStreams: tcpIds.length,
    udpStreams: udpIds.length,
    sampledHttpStream,
    sampledHttpStreamChunks: asList(httpStream.chunks).length,
    sampledTcpStream,
    sampledRawStreamChunks: asList(rawStreamPage.chunks).length,
    mediaTotalPackets: Number(media.total_media_packets ?? 0),
    mediaSessionCount: asList(media.sessions).length,
    objectCount: asList(objects).length,
    objectEvidenceCount: asList(evidence.records).length,
    industrialKeys: Object.keys(industrial),
    httpLoginKeys: Object.keys(httpLogin),
  };
}

async function waitDesktopBackendReady(desktopApp: DesktopSmokeBinding): Promise<Record<string, unknown>> {
  const deadline = Date.now() + 90_000;
  let lastStatus = "";
  while (Date.now() < deadline) {
    try {
      if (await desktopApp.IsBackendReady!()) {
        if (!desktopApp.PingBackendDataPlane) {
          return {};
        }
        const probe = asRecord(await desktopApp.PingBackendDataPlane());
        if (probe.ready) {
          return probe;
        }
        lastStatus = String(probe.message ?? JSON.stringify(probe));
      }
    } catch (error) {
      lastStatus = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => window.setTimeout(resolve, 500));
  }
  throw new Error(`desktop backend did not become ready for WebView smoke: ${lastStatus}`);
}

function isGenericIpcDisableExperimentBuildEnabled(): boolean {
  return isDesktopGenericIpcDisabled();
}

function samePath(left: string, right: string): boolean {
  return normalizePath(left) === normalizePath(right);
}

function normalizePath(value: string): string {
  return value.trim().replaceAll("\\", "/").replace(/\/+$/, "").toLowerCase();
}

async function waitCaptureReady(desktopApp: DesktopSmokeBinding): Promise<unknown> {
  const deadline = Date.now() + 180_000;
  let lastStatus: unknown = null;
  while (Date.now() < deadline) {
    lastStatus = await desktopApp.GetCaptureStatus!();
    const status = asRecord(lastStatus);
    if (status.has_capture && Number(status.packet_count ?? 0) > 0) {
      return status;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 750));
  }
  throw new Error(`desktop typed capture did not become ready: ${JSON.stringify(lastStatus)}`);
}

function installNetworkProbe(): NetworkProbe[] {
  const probes: NetworkProbe[] = [];
  const originalFetch = window.fetch.bind(window);
  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    probes.push({ kind: "fetch", url: requestURL(input) });
    return originalFetch(input, init);
  }) as typeof window.fetch;

  const originalXHROpen = window.XMLHttpRequest.prototype.open;
  window.XMLHttpRequest.prototype.open = function open(
    method: string,
    url: string | URL,
    async?: boolean,
    username?: string | null,
    password?: string | null,
  ) {
    probes.push({ kind: "xhr", url: String(url) });
    return originalXHROpen.call(this, method, url, async ?? true, username ?? null, password ?? null);
  };

  const OriginalEventSource = window.EventSource;
  if (typeof OriginalEventSource === "function") {
    window.EventSource = class SmokeEventSource extends OriginalEventSource {
      constructor(url: string | URL, eventSourceInitDict?: EventSourceInit) {
        probes.push({ kind: "eventsource", url: String(url) });
        super(url, eventSourceInitDict);
      }
    };
  }
  return probes;
}

function summarizeNetworkProbes(probes: NetworkProbe[]) {
  const directBackendApiRequests = probes.filter((probe) => DIRECT_BACKEND_API_PATTERN.test(probe.url));
  return {
    totalRequests: probes.length,
    directBackendApiRequests,
    directBackendApiRequestCount: directBackendApiRequests.length,
    allRequests: probes,
  };
}

function getDesktopAppBinding(): DesktopSmokeBinding | undefined {
  const w = window as unknown as { go?: { main?: { DesktopApp?: DesktopSmokeBinding } } };
  return w.go?.main?.DesktopApp;
}

function assertBinding(value: unknown, name: string): asserts value is (...args: unknown[]) => Promise<unknown> {
  if (typeof value !== "function") {
    throw new Error(`desktop WebView smoke missing Wails binding: ${name}`);
  }
}

function requestURL(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asNumberList(value: unknown): number[] {
  return asList(value)
    .map((item) => Number(item))
    .filter((item) => Number.isFinite(item));
}
