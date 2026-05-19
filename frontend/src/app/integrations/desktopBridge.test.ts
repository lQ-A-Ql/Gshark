import { afterEach, describe, expect, it, vi } from "vitest";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createDesktopBridge } from "./desktopBridge";

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
    getRawStreamPage: vi.fn(),
    getIndustrialAnalysis: vi.fn(),
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
  });

  it("routes supported desktop control-plane calls through Wails IPC", async () => {
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

  it("keeps packet, stream, analysis, and event data-plane calls on HTTP only when generic IPC is missing", async () => {
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

    await bridge.listPacketsPage(100, 50, "http");
    await bridge.getRawStreamPage("TCP", 3, 0, 4096);
    await bridge.getIndustrialAnalysis();
    await expect(bridge.getHTTPLoginAnalysis()).resolves.toMatchObject({
      report: { summary: [{ title: "候选端点", summary: "1 个端点 / 1 次尝试" }] },
    });
    await expect(bridge.getEvidenceWithFilter(["vehicle"])).resolves.toMatchObject([
      { id: "vehicle-1", module: "vehicle", summary: "UDS 负响应" },
    ]);
    const stop = bridge.subscribeEvents({ status: vi.fn() });
    stop();

    expect(fallbackBridge.listPacketsPage).toHaveBeenCalledWith(100, 50, "http");
    expect(fallbackBridge.getRawStreamPage).toHaveBeenCalledWith("TCP", 3, 0, 4096);
    expect(fallbackBridge.getIndustrialAnalysis).toHaveBeenCalledWith();
    expect(fallbackBridge.getHTTPLoginAnalysis).toHaveBeenCalledWith();
    expect(fallbackBridge.getEvidenceWithFilter).toHaveBeenCalledWith(["vehicle"]);
    expect(fallbackBridge.subscribeEvents).toHaveBeenCalled();
    expect(unsubscribe).toHaveBeenCalled();
  });

  it("routes long-tail page data through generic Wails IPC when the binding exists", async () => {
    const fallbackBridge = createFallbackBridge({
      getIndustrialAnalysis: vi.fn(),
      getEvidenceWithFilter: vi.fn(),
      listMiscModules: vi.fn(),
    });
    const invokeBackendJSON = vi.fn(async (request: unknown) => {
      const path = String((request as { path?: unknown }).path ?? "");
      switch (path) {
        case "/api/analysis/industrial":
          return {
            total_industrial_packets: 0,
            protocols: [],
            conversations: [],
            modbus: {
              total_frames: 0,
              requests: 0,
              responses: 0,
              exceptions: 0,
              function_codes: [],
              unit_ids: [],
              reference_hits: [],
              exception_codes: [],
              transactions: [],
            },
            details: [],
            notes: [],
            report: { summary: [], evidence: [], details: [], recommendations: [] },
          };
        case "/api/evidence?modules=vehicle":
          return { records: [] };
        case "/api/tools/misc/modules":
          return [];
        default:
          throw new Error(`unexpected IPC path: ${path}`);
      }
    });
    const bridge = createDesktopBridge({
      desktopApp: {
        InvokeBackendJSON: invokeBackendJSON,
        InvokeBackendBlob: vi.fn(),
        InvokeBackendText: vi.fn(),
      },
      fallbackBridge,
    });

    await bridge.getIndustrialAnalysis();
    await bridge.getEvidenceWithFilter(["vehicle"]);
    await bridge.listMiscModules();

    expect(invokeBackendJSON).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "GET",
        path: "/api/analysis/industrial",
        body_kind: "none",
      }),
    );
    expect(invokeBackendJSON).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "GET",
        path: "/api/evidence?modules=vehicle",
        body_kind: "none",
      }),
    );
    expect(invokeBackendJSON).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "GET",
        path: "/api/tools/misc/modules",
        body_kind: "none",
      }),
    );
    expect(fallbackBridge.getIndustrialAnalysis).not.toHaveBeenCalled();
    expect(fallbackBridge.getEvidenceWithFilter).not.toHaveBeenCalled();
    expect(fallbackBridge.listMiscModules).not.toHaveBeenCalled();
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
        InvokeBackendJSON: vi.fn(),
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

  it("preserves string IPC errors in wrapped desktop data-plane failures", async () => {
    const fallbackBridge = createFallbackBridge();
    const bridge = createDesktopBridge({
      desktopApp: {
        InvokeBackendJSON: vi.fn(async () => {
          throw "backend token expired";
        }),
      },
      fallbackBridge,
    });

    await expect(bridge.getIndustrialAnalysis()).rejects.toThrow("backend token expired");
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
        InvokeBackendJSON: vi.fn(),
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

  it("falls back through generic desktop IPC when typed fast runtime snapshot fails", async () => {
    const fallbackBridge = createFallbackBridge({
      getToolRuntimeSnapshot: vi.fn(),
    });
    const invokeBackendJSON = vi.fn(async (request: unknown) => {
      expect(request).toMatchObject({
        method: "GET",
        path: "/api/tools/runtime-config?probe=fast",
        body_kind: "none",
      });
      return {
        config: { tshark_path: "ipc-data-plane-tshark", yara_timeout_ms: 25000 },
        tshark: { available: true, path: "ipc-data-plane-tshark", message: "ok" },
        ffmpeg: { available: false, path: "", message: "" },
        speech: { available: false, message: "" },
        yara: { enabled: false, message: "", timeout_ms: 25000 },
      };
    });
    const desktopApp: DesktopTransportBinding = {
      InvokeBackendJSON: invokeBackendJSON,
      GetToolRuntimeSnapshotFast: vi.fn(async () => {
        throw "typed runtime bridge missing";
      }),
    };
    const bridge = createDesktopBridge({ desktopApp, fallbackBridge });

    const snapshot = await bridge.getToolRuntimeSnapshot(undefined, "fast");

    expect(desktopApp.GetToolRuntimeSnapshotFast).toHaveBeenCalledTimes(1);
    expect(invokeBackendJSON).toHaveBeenCalledTimes(1);
    expect(fallbackBridge.getToolRuntimeSnapshot).not.toHaveBeenCalled();
    expect(snapshot.config.tsharkPath).toBe("ipc-data-plane-tshark");
    expect(snapshot.transport).toBe("http-fallback");
    expect(snapshot.transportError).toContain("typed runtime bridge missing");
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
});
