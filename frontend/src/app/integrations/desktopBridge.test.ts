import { afterEach, describe, expect, it, vi } from "vitest";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createDesktopBridge, resolveDesktopGenericIpcPolicy } from "./desktopBridge";
import { EventsOn } from "../../../wailsjs/runtime";

vi.mock("../../../wailsjs/runtime", () => ({
  EventsOn: vi.fn(() => vi.fn()),
}));

function createFallbackBridge(overrides: Partial<BackendBridge> = {}): BackendBridge {
  const fallback: Partial<BackendBridge> = {
    isAvailable: vi.fn(async () => false),
    getDesktopBackendStatus: vi.fn(async () => "fallback-status"),
    getToolRuntimeSnapshot: vi.fn(async () => ({
      config: {
        tsharkPath: "fallback-tshark",
        ffmpegPath: "",
        pythonPath: "",
        voskModelPath: "",
        yaraEnabled: false,
        yaraBin: "",
        yaraRules: "",
        yaraTimeoutMs: 25000,
      },
      tshark: { available: false, path: "", message: "", usingCustomPath: false },
      ffmpeg: { available: false, path: "", message: "", usingCustomPath: false },
      speech: {
        available: false,
        engine: "",
        language: "",
        pythonAvailable: false,
        ffmpegAvailable: false,
        voskAvailable: false,
        modelAvailable: false,
        message: "",
      },
      yara: {
        available: false,
        enabled: false,
        message: "",
        usingCustomBin: false,
        usingCustomRules: false,
        timeoutMs: 25000,
      },
    })),
    updateToolRuntimeConfig: vi.fn(),
    setTSharkPath: vi.fn(),
    startStreamingPackets: vi.fn(),
    stopStreamingPackets: vi.fn(),
    prepareCaptureReplacement: vi.fn(),
    closeCapture: vi.fn(),
    getCaptureStatus: vi.fn(async () => ({
      filePath: "fallback.pcapng",
      hasCapture: true,
      packetCount: 7,
    })),
    getTLSConfig: vi.fn(),
    updateTLSConfig: vi.fn(),
    listPacketsPage: vi.fn(),
    locatePacketPage: vi.fn(),
    getPacket: vi.fn(),
    listThreatHits: vi.fn(),
    getHuntingRuntimeConfig: vi.fn(),
    updateHuntingRuntimeConfig: vi.fn(),
    listVehicleDBCProfiles: vi.fn(),
    addVehicleDBC: vi.fn(),
    removeVehicleDBC: vi.fn(),
    getRawStreamPage: vi.fn(),
    getIndustrialAnalysis: vi.fn(),
    getMediaAnalysis: vi.fn(),
    transcribeMediaArtifact: vi.fn(),
    startMediaBatchTranscription: vi.fn(),
    getMediaBatchTranscriptionStatus: vi.fn(),
    cancelMediaBatchTranscription: vi.fn(),
    exportMediaBatchTranscription: vi.fn(),
    downloadMediaArtifact: vi.fn(),
    getMediaPlaybackBlob: vi.fn(),
    getHTTPLoginAnalysis: vi.fn(),
    getEvidenceWithFilter: vi.fn(),
    subscribeEvents: vi.fn(() => vi.fn()),
    ...overrides,
  };

  return fallback as BackendBridge;
}

describe("createDesktopBridge", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
    vi.clearAllMocks();
  });

  it("routes supported desktop control-plane calls through Wails IPC", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const desktopApp: DesktopTransportBinding = {
      IsBackendReady: vi.fn(async () => true),
      BackendStatus: vi.fn(async () => " running (reused-existing) "),
      StartCapture: vi.fn(async () => undefined),
      GetCaptureStatus: vi.fn(async () => ({
        file_path: "C:/cases/sample.pcapng",
        has_capture: true,
        packet_count: 42,
      })),
      GetTLSConfig: vi.fn(async () => ({
        ssl_key_log_file: "C:/keys/ssl.log",
      })),
      UpdateTLSConfig: vi.fn(async () => undefined),
      GetToolRuntimeSnapshot: vi.fn(async () => ({
        config: { tshark_path: "C:/Tools/tshark.exe", yara_timeout_ms: 30000 },
        tshark: { available: true, path: "C:/Tools/tshark.exe", message: "ok" },
        ffmpeg: { available: false, path: "", message: "" },
        speech: { available: false, message: "" },
        yara: { enabled: false, message: "", timeout_ms: 30000 },
      })),
    };
    const fallbackBridge = createFallbackBridge({
      isAvailable: vi.fn(async () => true),
    });
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await expect(bridge.isAvailable()).resolves.toBe(true);
    await expect(bridge.getDesktopBackendStatus()).resolves.toBe("running (reused-existing)");
    await bridge.startStreamingPackets("C:/cases/sample.pcapng", "tcp");
    await expect(bridge.getCaptureStatus()).resolves.toEqual({
      filePath: "C:/cases/sample.pcapng",
      hasCapture: true,
      packetCount: 42,
    });
    await expect(bridge.getToolRuntimeSnapshot()).resolves.toMatchObject({
      config: { tsharkPath: "C:/Tools/tshark.exe", yaraTimeoutMs: 30000 },
      tshark: { available: true, path: "C:/Tools/tshark.exe" },
    });
    await expect(bridge.getTLSConfig()).resolves.toMatchObject({
      sslKeyLogPath: "C:/keys/ssl.log",
    });
    await bridge.updateTLSConfig({
      sslKeyLogPath: "C:/keys/ssl.log",
      privateKeyPath: "",
      privateKeyIpPort: "",
    });

    expect(desktopApp.StartCapture).toHaveBeenCalledWith("C:/cases/sample.pcapng", "tcp");
    expect(fallbackBridge.isAvailable).toHaveBeenCalledTimes(1);
    expect(desktopApp.UpdateTLSConfig).toHaveBeenCalledWith({
      ssl_key_log_file: "C:/keys/ssl.log",
      rsa_private_key: "",
      target_ip_port: "",
    });
    expect(fallbackBridge.startStreamingPackets).not.toHaveBeenCalled();
    expect(fallbackBridge.getCaptureStatus).not.toHaveBeenCalled();
    expect(fallbackBridge.getToolRuntimeSnapshot).not.toHaveBeenCalled();
    expect(fallbackBridge.getTLSConfig).not.toHaveBeenCalled();
  });

  it("does not report desktop availability until the HTTP data-plane probe passes", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge({
      isAvailable: vi.fn(async () => false),
    });
    const bridge = createDesktopBridge({
      desktopApp: { IsBackendReady: vi.fn(async () => true) },
      fallbackBridge,
    });

    await expect(bridge.isAvailable()).resolves.toBe(false);

    expect(fallbackBridge.isAvailable).toHaveBeenCalledTimes(1);
  });

  it("skips HTTP data-plane probes while the desktop backend is not ready", async () => {
    const fallbackBridge = createFallbackBridge({
      isAvailable: vi.fn(async () => true),
    });
    const desktopApp: DesktopTransportBinding = {
      IsBackendReady: vi.fn(async () => false),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await expect(bridge.isAvailable()).resolves.toBe(false);

    expect(fallbackBridge.isAvailable).not.toHaveBeenCalled();
  });

  it("fails missing typed data-plane calls but keeps events on Wails runtime", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const unsubscribe = vi.fn();
    const fallbackBridge = createFallbackBridge({
      listPacketsPage: vi.fn(async () => ({
        items: [],
        nextCursor: 100,
        total: 200,
        hasMore: true,
      })),
      getRawStreamPage: vi.fn(async () => ({
        id: 3,
        protocol: "TCP" as const,
        from: "10.0.0.1:1234",
        to: "10.0.0.2:80",
        chunks: [],
      })),
      getIndustrialAnalysis: vi.fn(async () => ({
        totalIndustrialPackets: 0,
        protocols: [],
        conversations: [],
        modbus: {
          totalFrames: 0,
          requests: 0,
          responses: 0,
          exceptions: 0,
          functionCodes: [],
          unitIds: [],
          referenceHits: [],
          exceptionCodes: [],
          transactions: [],
        },
        details: [],
        notes: [],
        report: { summary: [], evidence: [], details: [], recommendations: [] },
      })),
      getHTTPLoginAnalysis: vi.fn(async () => ({
        totalAttempts: 1,
        candidateEndpoints: 1,
        successCount: 0,
        failureCount: 1,
        uncertainCount: 0,
        bruteforceCount: 0,
        endpoints: [],
        attempts: [],
        notes: [],
        report: {
          summary: [{ title: "候选端点", summary: "1 个端点 / 1 次尝试" }],
          evidence: [],
          details: [],
          recommendations: [],
        },
      })),
      getEvidenceWithFilter: vi.fn(async () => [
        {
          id: "vehicle-1",
          module: "vehicle" as const,
          sourceType: "uds",
          summary: "UDS 负响应",
          confidenceLabel: "high" as const,
          severity: "high" as const,
          tags: ["UDS"],
          caveats: [],
        },
      ]),
      subscribeEvents: vi.fn(() => unsubscribe),
    });
    const bridge = createDesktopBridge({
      desktopApp: { StartCapture: vi.fn(async () => undefined) },
      fallbackBridge,
    });

    await expect(bridge.listPacketsPage(100, 50, "http")).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/packets/page?cursor=100&limit=50&filter=http",
      transport: "desktop-ipc",
    });
    await expect(bridge.getRawStreamPage("TCP", 3, 0, 4096)).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/streams/raw/page?protocol=TCP&streamId=3&cursor=0&limit=4096",
      transport: "desktop-ipc",
    });
    await expect(bridge.getIndustrialAnalysis()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/analysis/industrial",
      transport: "desktop-ipc",
    });
    await expect(bridge.getHTTPLoginAnalysis()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/tools/http-login-analysis",
      transport: "desktop-ipc",
    });
    await expect(bridge.getEvidenceWithFilter(["vehicle"])).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/evidence?modules=vehicle",
      transport: "desktop-ipc",
    });
    const stop = bridge.subscribeEvents({ status: vi.fn() });
    stop();

    expect(fallbackBridge.listPacketsPage).not.toHaveBeenCalled();
    expect(fallbackBridge.getRawStreamPage).not.toHaveBeenCalled();
    expect(fallbackBridge.getIndustrialAnalysis).not.toHaveBeenCalled();
    expect(fallbackBridge.getHTTPLoginAnalysis).not.toHaveBeenCalled();
    expect(fallbackBridge.getEvidenceWithFilter).not.toHaveBeenCalled();
    expect(fallbackBridge.subscribeEvents).not.toHaveBeenCalled();
    expect(EventsOn).toHaveBeenCalledWith("meow:backend:packet", expect.any(Function));
    expect(EventsOn).toHaveBeenCalledWith("meow:backend:status", expect.any(Function));
    expect(EventsOn).toHaveBeenCalledWith("meow:backend:error", expect.any(Function));
    expect(unsubscribe).not.toHaveBeenCalled();
  });

  it("fails fast when a data-plane typed binding is missing instead of using generic IPC", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge({
      getIndustrialAnalysis: vi.fn(),
      getEvidenceWithFilter: vi.fn(),
      listMiscModules: vi.fn(),
    });
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    await expect(bridge.getIndustrialAnalysis()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/analysis/industrial",
      transport: "desktop-ipc",
    });
    await expect(bridge.getEvidenceWithFilter(["vehicle"])).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/evidence?modules=vehicle",
      transport: "desktop-ipc",
    });
    await expect(bridge.listMiscModules()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/tools/misc/modules",
      transport: "desktop-ipc",
    });
    expect(fallbackBridge.getIndustrialAnalysis).not.toHaveBeenCalled();
    expect(fallbackBridge.getEvidenceWithFilter).not.toHaveBeenCalled();
    expect(fallbackBridge.listMiscModules).not.toHaveBeenCalled();
  });

  it("routes migrated packet/hunting/vehicle-dbc/plugin/misc/stream/object/tooling/analysis/media domains through typed Wails IPC before generic IPC", async () => {
    const fallbackBridge = createFallbackBridge({
      locatePacketPage: vi.fn(),
      getPacket: vi.fn(),
      listThreatHits: vi.fn(),
      getHuntingRuntimeConfig: vi.fn(),
      updateHuntingRuntimeConfig: vi.fn(),
      listVehicleDBCProfiles: vi.fn(),
      addVehicleDBC: vi.fn(),
      removeVehicleDBC: vi.fn(),
      listMiscModules: vi.fn(),
      selectMiscModulePackage: vi.fn(),
      importMiscModulePackageFromPath: vi.fn(),
      deleteMiscModule: vi.fn(),
      runMiscModule: vi.fn(),
      getHttpStream: vi.fn(),
      listObjects: vi.fn(),
      getHTTPLoginAnalysis: vi.fn(),
      getEvidenceWithFilter: vi.fn(),
      getMediaAnalysis: vi.fn(),
      transcribeMediaArtifact: vi.fn(),
      startMediaBatchTranscription: vi.fn(),
      getMediaBatchTranscriptionStatus: vi.fn(),
      cancelMediaBatchTranscription: vi.fn(),
    });
    const desktopApp: DesktopTransportBinding = {
      LocatePacketPage: vi.fn(async () => ({ packet_id: 42, cursor: 100, total: 200, found: true })),
      GetPacket: vi.fn(async () => ({
        id: 42,
        source_ip: "10.0.0.1",
        dest_ip: "10.0.0.2",
        protocol: "TCP",
        display_protocol: "HTTP",
        length: 128,
      })),
      ListThreatHits: vi.fn(async () => [
        {
          id: 7,
          packet_id: 99,
          category: "CTF",
          rule: "Flag",
          level: "high",
          preview: "flag{demo}",
          match: "flag{",
        },
      ]),
      GetHuntingRuntimeConfig: vi.fn(async () => ({
        prefixes: ["flag{", "ctf{"],
        yara_enabled: false,
        yara_bin: "C:/Tools/yara.exe",
        yara_rules: "C:/rules",
        yara_timeout_ms: 15000,
      })),
      UpdateHuntingRuntimeConfig: vi.fn(async () => ({
        prefixes: ["flag{"],
        yara_enabled: true,
        yara_bin: "",
        yara_rules: "",
        yara_timeout_ms: 25000,
      })),
      ListVehicleDBCProfiles: vi.fn(async () => [{ path: "car.dbc", name: "car", message_count: 2, signal_count: 8 }]),
      AddVehicleDBC: vi.fn(async () => [{ path: "truck.dbc", name: "truck", message_count: 3, signal_count: 12 }]),
      RemoveVehicleDBC: vi.fn(async () => []),
      ListMiscModules: vi.fn(async () => [
        {
          id: "webshell.decoder",
          kind: "decoder",
          title: "WebShell Decoder",
          summary: "decode payload",
          tags: ["webshell"],
        },
      ]),
      SelectMiscModulePackage: vi.fn(async () => ({
        filePath: "C:/modules/module.zip",
        fileName: "module.zip",
        fileSize: 9,
      })),
      ImportMiscModulePackageFromPath: vi.fn(async () => ({
        module: { id: "imported.module", title: "Imported Module" },
        installed_path: "C:/modules/imported.module",
        message: "模块包导入成功",
      })),
      DeleteMiscModulePackage: vi.fn(async () => ({ id: "webshell.decoder", deleted: true })),
      RunMiscModulePackage: vi.fn(async () => ({
        message: "module complete",
        text: "ok",
        table: { columns: [{ key: "name", label: "Name" }], rows: [{ name: "cmd.exe" }] },
      })),
      GetHttpStream: vi.fn(async () => ({
        stream_id: 4,
        chunks: [],
      })),
      ListObjects: vi.fn(async () => []),
      GetHTTPLoginAnalysis: vi.fn(async () => ({
        total_attempts: 0,
        candidate_endpoints: 0,
        success_count: 0,
        failure_count: 0,
        uncertain_count: 0,
        bruteforce_count: 0,
        endpoints: [],
        attempts: [],
        notes: [],
        report: { summary: [], evidence: [], details: [], recommendations: [] },
      })),
      GetEvidenceWithFilter: vi.fn(async () => ({ records: [] })),
      GetMediaAnalysis: vi.fn(async () => ({ total_media_packets: 3, sessions: [] })),
      TranscribeMediaArtifact: vi.fn(async () => ({ token: "tok", status: "completed", text: "ok" })),
      StartMediaBatchTranscription: vi.fn(async () => ({ task_id: "task-1", queued: 1, done: false })),
      GetMediaBatchTranscriptionStatus: vi.fn(async () => ({ task_id: "task-1", completed: 1, done: true })),
      CancelMediaBatchTranscription: vi.fn(async () => ({ task_id: "task-1", cancelled: true, done: true })),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await expect(bridge.locatePacketPage(42, 50, "http")).resolves.toEqual({
      packetId: 42,
      cursor: 100,
      total: 200,
      found: true,
    });
    await expect(bridge.getPacket(42)).resolves.toMatchObject({
      id: 42,
      src: "10.0.0.1",
      dst: "10.0.0.2",
      displayProtocol: "HTTP",
    });
    await expect(bridge.listThreatHits(["flag{"])).resolves.toEqual([
      {
        id: 7,
        packetId: 99,
        category: "CTF",
        rule: "Flag",
        level: "high",
        preview: "flag{demo}",
        match: "flag{",
      },
    ]);
    await expect(bridge.getHuntingRuntimeConfig()).resolves.toEqual({
      prefixes: ["flag{", "ctf{"],
      yaraEnabled: false,
      yaraBin: "C:/Tools/yara.exe",
      yaraRules: "C:/rules",
      yaraTimeoutMs: 15000,
    });
    await expect(
      bridge.updateHuntingRuntimeConfig({
        prefixes: ["flag{"],
        yaraEnabled: true,
        yaraBin: "",
        yaraRules: "",
        yaraTimeoutMs: 25000,
      }),
    ).resolves.toEqual({
      prefixes: ["flag{"],
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    });
    await expect(bridge.listVehicleDBCProfiles()).resolves.toEqual([
      { path: "car.dbc", name: "car", messageCount: 2, signalCount: 8 },
    ]);
    await expect(bridge.addVehicleDBC("truck.dbc")).resolves.toEqual([
      { path: "truck.dbc", name: "truck", messageCount: 3, signalCount: 12 },
    ]);
    await expect(bridge.removeVehicleDBC("truck.dbc")).resolves.toEqual([]);
    await expect(bridge.listMiscModules()).resolves.toMatchObject([
      { id: "webshell.decoder", title: "WebShell Decoder", tags: ["webshell"] },
    ]);
    await expect(bridge.selectMiscModulePackage?.()).resolves.toMatchObject({
      filePath: "C:/modules/module.zip",
      fileName: "module.zip",
      fileSize: 9,
    });
    await expect(bridge.importMiscModulePackageFromPath?.("C:/modules/module.zip")).resolves.toMatchObject({
      module: { id: "imported.module", title: "Imported Module" },
      message: "模块包导入成功",
    });
    await expect(bridge.deleteMiscModule("webshell.decoder")).resolves.toBeUndefined();
    await expect(bridge.runMiscModule("webshell.decoder", { keyword: "cmd.exe" })).resolves.toMatchObject({
      message: "module complete",
      text: "ok",
      table: { columns: [{ key: "name", label: "Name" }], rows: [{ name: "cmd.exe" }] },
    });
    await bridge.getHttpStream(4);
    await bridge.listObjects();
    await bridge.getHTTPLoginAnalysis();
    await bridge.getEvidenceWithFilter(["vehicle"]);
    await expect(bridge.getMediaAnalysis(true)).resolves.toMatchObject({ totalMediaPackets: 3 });
    await expect(bridge.transcribeMediaArtifact("tok", true)).resolves.toMatchObject({
      token: "tok",
      status: "completed",
    });
    await expect(bridge.startMediaBatchTranscription(false)).resolves.toMatchObject({
      taskId: "task-1",
      queued: 1,
    });
    await expect(bridge.getMediaBatchTranscriptionStatus()).resolves.toMatchObject({
      taskId: "task-1",
      completed: 1,
      done: true,
    });
    await expect(bridge.cancelMediaBatchTranscription()).resolves.toMatchObject({
      taskId: "task-1",
      cancelled: true,
    });

    expect(desktopApp.LocatePacketPage).toHaveBeenCalledWith(42, 50, "http");
    expect(desktopApp.GetPacket).toHaveBeenCalledWith(42);
    expect(desktopApp.ListThreatHits).toHaveBeenCalledWith(["flag{"]);
    expect(desktopApp.GetHuntingRuntimeConfig).toHaveBeenCalledTimes(1);
    expect(desktopApp.UpdateHuntingRuntimeConfig).toHaveBeenCalledWith({
      prefixes: ["flag{"],
      yara_enabled: true,
      yara_bin: "",
      yara_rules: "",
      yara_timeout_ms: 25000,
    });
    expect(desktopApp.ListVehicleDBCProfiles).toHaveBeenCalledTimes(1);
    expect(desktopApp.AddVehicleDBC).toHaveBeenCalledWith("truck.dbc");
    expect(desktopApp.RemoveVehicleDBC).toHaveBeenCalledWith("truck.dbc");
    expect(desktopApp.ListMiscModules).toHaveBeenCalledTimes(1);
    expect(desktopApp.SelectMiscModulePackage).toHaveBeenCalledTimes(1);
    expect(desktopApp.ImportMiscModulePackageFromPath).toHaveBeenCalledWith("C:/modules/module.zip");
    expect(desktopApp.DeleteMiscModulePackage).toHaveBeenCalledWith("webshell.decoder");
    expect(desktopApp.RunMiscModulePackage).toHaveBeenCalledWith("webshell.decoder", { keyword: "cmd.exe" });
    expect(desktopApp.GetHttpStream).toHaveBeenCalledWith(4);
    expect(desktopApp.ListObjects).toHaveBeenCalledTimes(1);
    expect(desktopApp.GetHTTPLoginAnalysis).toHaveBeenCalledTimes(1);
    expect(desktopApp.GetEvidenceWithFilter).toHaveBeenCalledWith(["vehicle"]);
    expect(desktopApp.GetMediaAnalysis).toHaveBeenCalledWith(true);
    expect(desktopApp.TranscribeMediaArtifact).toHaveBeenCalledWith("tok", true);
    expect(desktopApp.StartMediaBatchTranscription).toHaveBeenCalledWith(false);
    expect(desktopApp.GetMediaBatchTranscriptionStatus).toHaveBeenCalledTimes(1);
    expect(desktopApp.CancelMediaBatchTranscription).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.locatePacketPage).not.toHaveBeenCalled();
    expect(fallbackBridge.getPacket).not.toHaveBeenCalled();
    expect(fallbackBridge.listThreatHits).not.toHaveBeenCalled();
    expect(fallbackBridge.getHuntingRuntimeConfig).not.toHaveBeenCalled();
    expect(fallbackBridge.updateHuntingRuntimeConfig).not.toHaveBeenCalled();
    expect(fallbackBridge.listVehicleDBCProfiles).not.toHaveBeenCalled();
    expect(fallbackBridge.addVehicleDBC).not.toHaveBeenCalled();
    expect(fallbackBridge.removeVehicleDBC).not.toHaveBeenCalled();
    expect(fallbackBridge.listMiscModules).not.toHaveBeenCalled();
    expect(fallbackBridge.selectMiscModulePackage).not.toHaveBeenCalled();
    expect(fallbackBridge.importMiscModulePackageFromPath).not.toHaveBeenCalled();
    expect(fallbackBridge.deleteMiscModule).not.toHaveBeenCalled();
    expect(fallbackBridge.runMiscModule).not.toHaveBeenCalled();
    expect(fallbackBridge.getHttpStream).not.toHaveBeenCalled();
    expect(fallbackBridge.listObjects).not.toHaveBeenCalled();
    expect(fallbackBridge.getHTTPLoginAnalysis).not.toHaveBeenCalled();
    expect(fallbackBridge.getEvidenceWithFilter).not.toHaveBeenCalled();
    expect(fallbackBridge.getMediaAnalysis).not.toHaveBeenCalled();
    expect(fallbackBridge.transcribeMediaArtifact).not.toHaveBeenCalled();
    expect(fallbackBridge.startMediaBatchTranscription).not.toHaveBeenCalled();
    expect(fallbackBridge.getMediaBatchTranscriptionStatus).not.toHaveBeenCalled();
    expect(fallbackBridge.cancelMediaBatchTranscription).not.toHaveBeenCalled();
  });

  it("routes migrated media blob calls through typed Wails IPC before generic IPC", async () => {
    const originalCreateObjectURL = URL.createObjectURL;
    const originalRevokeObjectURL = URL.revokeObjectURL;
    const originalAnchorClick = HTMLAnchorElement.prototype.click;
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: vi.fn(() => "blob:desktop-media"),
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      value: vi.fn(),
    });
    Object.defineProperty(HTMLAnchorElement.prototype, "click", {
      configurable: true,
      value: vi.fn(),
    });
    const fallbackBridge = createFallbackBridge({
      exportMediaBatchTranscription: vi.fn(),
      downloadMediaArtifact: vi.fn(),
      getMediaPlaybackBlob: vi.fn(),
    });
    const typedBlob = {
      data_base64: btoa("media"),
      content_type: "audio/wav",
      size: 5,
    };
    const desktopApp: DesktopTransportBinding = {
      ExportMediaBatchTranscription: vi.fn(async () => typedBlob),
      DownloadMediaArtifact: vi.fn(async () => typedBlob),
      GetMediaPlaybackBlob: vi.fn(async () => typedBlob),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    try {
      await bridge.exportMediaBatchTranscription("json");
      await bridge.downloadMediaArtifact("tok/1", "call.wav");
      await expect(bridge.getMediaPlaybackBlob("tok/1")).resolves.toMatchObject({ type: "audio/wav" });

      expect(desktopApp.ExportMediaBatchTranscription).toHaveBeenCalledWith("json");
      expect(desktopApp.DownloadMediaArtifact).toHaveBeenCalledWith("tok/1");
      expect(desktopApp.GetMediaPlaybackBlob).toHaveBeenCalledWith("tok/1");
      expect(fallbackBridge.exportMediaBatchTranscription).not.toHaveBeenCalled();
      expect(fallbackBridge.downloadMediaArtifact).not.toHaveBeenCalled();
      expect(fallbackBridge.getMediaPlaybackBlob).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(URL, "createObjectURL", {
        configurable: true,
        value: originalCreateObjectURL,
      });
      Object.defineProperty(URL, "revokeObjectURL", {
        configurable: true,
        value: originalRevokeObjectURL,
      });
      Object.defineProperty(HTMLAnchorElement.prototype, "click", {
        configurable: true,
        value: originalAnchorClick,
      });
    }
  });

  it("does not restore generic IPC when compat policy is set and a migrated typed binding is missing", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge({
      listObjects: vi.fn(),
    });
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    await expect(bridge.listObjects()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/objects",
      transport: "desktop-ipc",
    });

    expect(resolveDesktopGenericIpcPolicy()).toBe("compat");
    expect(fallbackBridge.listObjects).not.toHaveBeenCalled();
  });

  it("fails fast instead of using generic IPC or HTTP when the disable experiment is enabled", async () => {
    vi.stubEnv("VITE_DESKTOP_DISABLE_GENERIC_IPC", "1");
    const fallbackBridge = createFallbackBridge({
      listObjects: vi.fn(async () => []),
    });
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    await expect(bridge.listObjects()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/objects",
      transport: "desktop-ipc",
    });
    expect(fallbackBridge.listObjects).not.toHaveBeenCalled();
  });

  it("fails fast through the explicit generic IPC disabled policy preflight switch", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "disabled");
    const fallbackBridge = createFallbackBridge({
      listObjects: vi.fn(async () => []),
    });
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    await expect(bridge.listObjects()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/objects",
      transport: "desktop-ipc",
    });
    expect(resolveDesktopGenericIpcPolicy()).toBe("disabled");
    expect(fallbackBridge.listObjects).not.toHaveBeenCalled();
  });

  it("keeps explicit compat policy as a documented no-op after adapter removal", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    vi.stubEnv("VITE_DESKTOP_DISABLE_GENERIC_IPC", "1");
    const fallbackBridge = createFallbackBridge({
      listObjects: vi.fn(),
    });
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    await expect(bridge.listObjects()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/objects",
      transport: "desktop-ipc",
    });

    expect(resolveDesktopGenericIpcPolicy()).toBe("compat");
    expect(fallbackBridge.listObjects).not.toHaveBeenCalled();
  });

  it("keeps typed desktop bindings working when the generic IPC disable experiment is enabled", async () => {
    vi.stubEnv("VITE_DESKTOP_DISABLE_GENERIC_IPC", "1");
    const fallbackBridge = createFallbackBridge({
      listObjects: vi.fn(async () => {
        throw new Error("HTTP fallback should not run");
      }),
    });
    const desktopApp: DesktopTransportBinding = {
      ListObjects: vi.fn(async () => []),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await expect(bridge.listObjects()).resolves.toEqual([]);

    expect(desktopApp.ListObjects).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.listObjects).not.toHaveBeenCalled();
  });

  it("keeps desktop event subscription on Wails runtime when the generic IPC disable experiment is enabled", () => {
    vi.stubEnv("VITE_DESKTOP_DISABLE_GENERIC_IPC", "1");
    const fallbackUnsubscribe = vi.fn();
    const fallbackBridge = createFallbackBridge({
      subscribeEvents: vi.fn(() => fallbackUnsubscribe),
    });
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    const stop = bridge.subscribeEvents({ status: vi.fn() });
    stop();

    expect(EventsOn).toHaveBeenCalledWith("meow:backend:packet", expect.any(Function));
    expect(EventsOn).toHaveBeenCalledWith("meow:backend:status", expect.any(Function));
    expect(EventsOn).toHaveBeenCalledWith("meow:backend:error", expect.any(Function));
    expect(fallbackBridge.subscribeEvents).not.toHaveBeenCalled();
    expect(fallbackUnsubscribe).not.toHaveBeenCalled();
  });

  it("uses Wails IPC for packet pages and falls back to HTTP with transport metadata", async () => {
    const fallbackBridge = createFallbackBridge({
      listPacketsPage: vi.fn(async () => ({
        items: [],
        nextCursor: 0,
        total: 0,
        hasMore: false,
      })),
    });
    const desktopApp: DesktopTransportBinding = {
      ListPacketsPage: vi.fn(async () => ({
        items: [],
        next_cursor: 50,
        total: 120,
        has_more: true,
      })),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    const page = await bridge.listPacketsPage(0, 50, "tcp");

    expect(desktopApp.ListPacketsPage).toHaveBeenCalledWith(0, 50, "tcp");
    expect(fallbackBridge.listPacketsPage).not.toHaveBeenCalled();
    expect(page).toMatchObject({ nextCursor: 50, total: 120, hasMore: true });
    expect(page.transport).toBe("desktop-ipc");
  });

  it("surfaces Wails packet page IPC errors instead of silently falling back to browser HTTP", async () => {
    const fallbackBridge = createFallbackBridge({
      listPacketsPage: vi.fn(async () => ({
        items: [],
        nextCursor: 10,
        total: 10,
        hasMore: false,
      })),
    });
    const bridge = createDesktopBridge({
      desktopApp: {
        ListPacketsPage: vi.fn(async () => {
          throw new Error("ipc unavailable");
        }),
      },
      fallbackBridge,
    });

    await expect(bridge.listPacketsPage(0, 50, "")).rejects.toThrow("ipc unavailable");
    expect(fallbackBridge.listPacketsPage).not.toHaveBeenCalled();
  });

  it("times out typed capture status IPC calls instead of pending forever", async () => {
    vi.useFakeTimers();
    const fallbackBridge = createFallbackBridge({
      getCaptureStatus: vi.fn(async () => ({
        filePath: "fallback.pcapng",
        hasCapture: true,
        packetCount: 1,
      })),
    });
    const bridge = createDesktopBridge({
      desktopApp: {
        GetCaptureStatus: vi.fn(async () => new Promise<unknown>(() => undefined)),
      },
      fallbackBridge,
    });

    const request = bridge.getCaptureStatus();
    const expectation = expect(request).rejects.toMatchObject({
      code: "ipc_timeout",
      endpoint: "DesktopApp.GetCaptureStatus",
      transport: "desktop-ipc",
    });
    await vi.advanceTimersByTimeAsync(10000);

    await expectation;
    expect(fallbackBridge.getCaptureStatus).not.toHaveBeenCalled();
  });

  it("fails with generic_ipc_disabled instead of invoking legacy adapter failures", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge();
    const bridge = createDesktopBridge({
      desktopApp: {},
      fallbackBridge,
    });

    await expect(bridge.getIndustrialAnalysis()).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/analysis/industrial",
      transport: "desktop-ipc",
    });
  });

  it("lets packet page callers abort typed IPC without browser HTTP fallback", async () => {
    const fallbackBridge = createFallbackBridge({
      listPacketsPage: vi.fn(async () => ({
        items: [],
        nextCursor: 0,
        total: 0,
        hasMore: false,
      })),
    });
    const controller = new AbortController();
    const bridge = createDesktopBridge({
      desktopApp: {
        ListPacketsPage: vi.fn(async () => new Promise<unknown>(() => undefined)),
      },
      fallbackBridge,
    });

    const request = bridge.listPacketsPage(0, 50, "", controller.signal);
    controller.abort();

    await expect(request).rejects.toMatchObject({ name: "AbortError" });
    expect(fallbackBridge.listPacketsPage).not.toHaveBeenCalled();
  });

  it("falls back per method when a desktop control-plane binding is missing", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge({
      startStreamingPackets: vi.fn(async () => undefined),
      getCaptureStatus: vi.fn(async () => ({
        filePath: "http-fallback.pcapng",
        hasCapture: true,
        packetCount: 12,
      })),
    });
    const bridge = createDesktopBridge({
      desktopApp: { BackendStatus: vi.fn(async () => "running") },
      fallbackBridge,
    });

    await bridge.startStreamingPackets("C:/cases/no-ipc.pcapng", "");
    await expect(bridge.getCaptureStatus()).resolves.toEqual({
      filePath: "http-fallback.pcapng",
      hasCapture: true,
      packetCount: 12,
    });

    expect(fallbackBridge.startStreamingPackets).toHaveBeenCalledWith("C:/cases/no-ipc.pcapng", "");
    expect(fallbackBridge.getCaptureStatus).toHaveBeenCalled();
  });

  it("keeps abortable runtime snapshot calls on Wails IPC when the binding exists", async () => {
    const controller = new AbortController();
    const fallbackBridge = createFallbackBridge();
    const desktopApp: DesktopTransportBinding = {
      GetToolRuntimeSnapshot: vi.fn(async () => ({
        config: { tshark_path: "desktop-tshark" },
      })),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await bridge.getToolRuntimeSnapshot(controller.signal);

    expect(desktopApp.GetToolRuntimeSnapshot).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.getToolRuntimeSnapshot).not.toHaveBeenCalled();
  });

  it("falls back to HTTP when Wails runtime snapshot IPC fails", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge();
    const desktopApp: DesktopTransportBinding = {
      GetToolRuntimeSnapshot: vi.fn(async () => {
        throw new Error("runtime ipc unavailable");
      }),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    const snapshot = await bridge.getToolRuntimeSnapshot(new AbortController().signal);

    expect(desktopApp.GetToolRuntimeSnapshot).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.getToolRuntimeSnapshot).toHaveBeenCalledWith(expect.any(AbortSignal), "full");
    expect(snapshot.config.tsharkPath).toBe("fallback-tshark");
    expect(snapshot.transport).toBe("http-fallback");
    expect(snapshot.transportError).toContain("runtime ipc unavailable");
  });

  it("falls back to HTTP fast snapshot when Wails IPC does not return within the fast budget", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    vi.useFakeTimers();
    try {
      const fallbackBridge = createFallbackBridge();
      const desktopApp: DesktopTransportBinding = {
        GetToolRuntimeSnapshotFast: vi.fn(async () => new Promise<unknown>(() => undefined)),
      };
      const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

      const snapshotPromise = bridge.getToolRuntimeSnapshot(undefined, "fast");
      await vi.advanceTimersByTimeAsync(2000);
      const snapshot = await snapshotPromise;

      expect(desktopApp.GetToolRuntimeSnapshotFast).toHaveBeenCalledTimes(1);
      expect(fallbackBridge.getToolRuntimeSnapshot).toHaveBeenCalledWith(undefined, "fast");
      expect(snapshot.transport).toBe("http-fallback");
      expect(snapshot.transportError).toContain("GetToolRuntimeSnapshot");
    } finally {
      vi.useRealTimers();
    }
  });

  it("falls back to HTTP instead of generic IPC when a typed fast runtime snapshot binding fails", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge({
      getToolRuntimeSnapshot: vi.fn(async () => createFallbackBridge().getToolRuntimeSnapshot(undefined, "fast")),
    });
    const desktopApp: DesktopTransportBinding = {
      GetToolRuntimeSnapshotFast: vi.fn(async () => {
        throw "typed runtime bridge missing";
      }),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    const snapshot = await bridge.getToolRuntimeSnapshot(undefined, "fast");
    expect(snapshot).toMatchObject({ config: { tsharkPath: "fallback-tshark" } });
    expect(snapshot.transport).toBe("http-fallback");
    expect(snapshot.transportError).toContain("typed runtime bridge missing");

    expect(desktopApp.GetToolRuntimeSnapshotFast).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.getToolRuntimeSnapshot).toHaveBeenCalledWith(undefined, "fast");
  });

  it("keeps abortable runtime config updates on Wails IPC when the binding exists", async () => {
    const controller = new AbortController();
    const fallbackBridge = createFallbackBridge({
      updateToolRuntimeConfig: vi.fn(async () => createFallbackBridge().getToolRuntimeSnapshot()),
    });
    const desktopApp: DesktopTransportBinding = {
      UpdateToolRuntimeConfig: vi.fn(async () => ({
        config: { tshark_path: "desktop-tshark", yara_timeout_ms: 25000 },
        tshark: { available: true, path: "desktop-tshark", message: "ok" },
        ffmpeg: { available: true, path: "ffmpeg", message: "ok" },
        speech: { available: false, message: "model missing" },
        yara: { enabled: true, available: true, timeout_ms: 25000 },
      })),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await bridge.updateToolRuntimeConfig(
      {
        tsharkPath: "desktop-tshark",
        ffmpegPath: "",
        pythonPath: "",
        voskModelPath: "",
        yaraEnabled: true,
        yaraBin: "",
        yaraRules: "",
        yaraTimeoutMs: 25000,
      },
      controller.signal,
    );

    expect(desktopApp.UpdateToolRuntimeConfig).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.updateToolRuntimeConfig).not.toHaveBeenCalled();
  });

  it("falls back to HTTP when Wails runtime config update IPC fails", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const fallbackBridge = createFallbackBridge({
      updateToolRuntimeConfig: vi.fn(async () => createFallbackBridge().getToolRuntimeSnapshot()),
    });
    const desktopApp: DesktopTransportBinding = {
      UpdateToolRuntimeConfig: vi.fn(async () => {
        throw new Error("runtime config ipc unavailable");
      }),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });
    const config = {
      tsharkPath: "desktop-tshark",
      ffmpegPath: "",
      pythonPath: "",
      voskModelPath: "",
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    };

    const snapshot = await bridge.updateToolRuntimeConfig(config, new AbortController().signal);

    expect(desktopApp.UpdateToolRuntimeConfig).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.updateToolRuntimeConfig).toHaveBeenCalledWith(config, expect.any(AbortSignal), "full");
    expect(snapshot.transport).toBe("http-fallback");
    expect(snapshot.transportError).toContain("runtime config ipc unavailable");
  });

  it("uses typed Wails IPC for MCP status and config when available", async () => {
    const fallbackBridge = createFallbackBridge({
      getMCPStatus: vi.fn(async () => ({
        config: { enabled: false },
        enabled: false,
        endpoint: "fallback",
        transport: "http-fallback",
        authRequired: false,
        readOnly: true,
        remoteSupported: false,
        stdioSupported: false,
      })),
      updateMCPConfig: vi.fn(async () => ({
        config: { enabled: false },
        enabled: false,
        endpoint: "fallback",
        transport: "http-fallback",
        authRequired: false,
        readOnly: true,
        remoteSupported: false,
        stdioSupported: false,
      })),
    });
    const desktopApp: DesktopTransportBinding = {
      GetMCPStatus: vi.fn(async () => ({
        config: { enabled: true },
        enabled: true,
        endpoint: "http://127.0.0.1:17891/api/mcp",
        transport: "streamable-http",
        auth_required: true,
        read_only: true,
        remote_supported: false,
        stdio_supported: false,
      })),
      UpdateMCPConfig: vi.fn(async () => ({
        config: { enabled: false },
        enabled: false,
        endpoint: "http://127.0.0.1:17891/api/mcp",
        transport: "streamable-http",
        auth_required: true,
        read_only: true,
        remote_supported: false,
        stdio_supported: false,
      })),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    await expect(bridge.getMCPStatus()).resolves.toMatchObject({
      enabled: true,
      config: { enabled: true },
      transport: "streamable-http",
    });
    await expect(bridge.updateMCPConfig({ enabled: false })).resolves.toMatchObject({
      enabled: false,
      config: { enabled: false },
    });

    expect(desktopApp.GetMCPStatus).toHaveBeenCalledTimes(1);
    expect(desktopApp.UpdateMCPConfig).toHaveBeenCalledWith({ enabled: false });
    expect(fallbackBridge.getMCPStatus).not.toHaveBeenCalled();
    expect(fallbackBridge.updateMCPConfig).not.toHaveBeenCalled();
  });

  it("normalizes MCP status consistently across HTTP fallback and Wails IPC", async () => {
    vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat");
    const expectedStatus = {
      config: { enabled: true },
      enabled: true,
      endpoint: "http://127.0.0.1:17891/api/mcp",
      transport: "streamable-http",
      authRequired: true,
      readOnly: true,
      remoteSupported: false,
      stdioSupported: false,
    };
    const fallbackBridge = createFallbackBridge({
      getMCPStatus: vi.fn(async () => expectedStatus),
      updateMCPConfig: vi.fn(async () => ({ ...expectedStatus, config: { enabled: false }, enabled: false })),
    });
    const desktopApp: DesktopTransportBinding = {
      GetMCPStatus: vi.fn(async () => ({
        config: { enabled: true },
        enabled: true,
        endpoint: "http://127.0.0.1:17891/api/mcp",
        transport: "streamable-http",
        auth_required: true,
        read_only: true,
        remote_supported: false,
        stdio_supported: false,
      })),
      UpdateMCPConfig: vi.fn(async () => ({
        config: { enabled: false },
        enabled: false,
        endpoint: "http://127.0.0.1:17891/api/mcp",
        transport: "streamable-http",
        auth_required: true,
        read_only: true,
        remote_supported: false,
        stdio_supported: false,
      })),
    };
    const ipcBridge = createDesktopBridge({ desktopApp, fallbackBridge });
    const httpBridge = createDesktopBridge({ desktopApp: {}, fallbackBridge });

    await expect(ipcBridge.getMCPStatus()).resolves.toEqual(expectedStatus);
    await expect(httpBridge.getMCPStatus()).resolves.toEqual(expectedStatus);
    await expect(ipcBridge.updateMCPConfig({ enabled: false })).resolves.toEqual({
      ...expectedStatus,
      config: { enabled: false },
      enabled: false,
    });
    await expect(httpBridge.updateMCPConfig({ enabled: false })).resolves.toEqual({
      ...expectedStatus,
      config: { enabled: false },
      enabled: false,
    });
  });
});
