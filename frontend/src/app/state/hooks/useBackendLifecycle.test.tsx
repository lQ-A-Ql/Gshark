import { act, renderHook, waitFor } from "@testing-library/react";
import { useRef, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DecryptionConfig, Packet, ToolRuntimeSnapshot } from "../../core/types";
import type { EventHandlers } from "../../integrations/clients/eventClient";
import {
  EMPTY_MEDIA_ANALYSIS_PROGRESS,
  EMPTY_THREAT_ANALYSIS_PROGRESS,
  type MediaAnalysisProgress,
  type ThreatAnalysisProgress,
} from "./useAnalysisProgress";
import { loadStartupToolRuntime } from "./backendLifecycleStartup";
import { useBackendLifecycle } from "./useBackendLifecycle";
import { readToolRuntimeConfig } from "../toolRuntimeStorage";

const bridgeMocks = vi.hoisted(() => {
  let handlers: EventHandlers | null = null;
  return {
    get handlers() {
      return handlers;
    },
    clearHandlers() {
      handlers = null;
    },
    isAvailable: vi.fn(),
    getDesktopBackendStatus: vi.fn(),
    updateToolRuntimeConfig: vi.fn(),
    getTLSConfig: vi.fn(),
    updateTLSConfig: vi.fn(),
    subscribeEvents: vi.fn((nextHandlers: EventHandlers) => {
      handlers = nextHandlers;
      return vi.fn();
    }),
    setTSharkPath: vi.fn(),
    getToolRuntimeSnapshot: vi.fn(),
  };
});

vi.mock("../../integrations/backendClients", () => ({
  backendClients: {
    runtime: {
      isAvailable: bridgeMocks.isAvailable,
      getDesktopBackendStatus: bridgeMocks.getDesktopBackendStatus,
      updateToolRuntimeConfig: bridgeMocks.updateToolRuntimeConfig,
      setTSharkPath: bridgeMocks.setTSharkPath,
      getToolRuntimeSnapshot: bridgeMocks.getToolRuntimeSnapshot,
      subscribeEvents: bridgeMocks.subscribeEvents,
    },
    securityMaterial: { getTLSConfig: bridgeMocks.getTLSConfig, updateTLSConfig: bridgeMocks.updateTLSConfig },
  },
}));

function createToolRuntimeSnapshot(): ToolRuntimeSnapshot {
  return {
    config: {
      tsharkPath: "",
      ffmpegPath: "",
      pythonPath: "",
      voskModelPath: "",
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    },
    tshark: {
      available: true,
      path: "C:/Tools/tshark.exe",
      message: "ok",
      customPath: "",
      usingCustomPath: false,
    },
    ffmpeg: {
      available: false,
      path: "",
      message: "ffmpeg unavailable",
      customPath: "",
      usingCustomPath: false,
    },
    speech: {
      available: false,
      engine: "vosk",
      language: "zh-CN",
      pythonAvailable: false,
      ffmpegAvailable: false,
      voskAvailable: false,
      modelAvailable: false,
      message: "speech unavailable",
    },
    yara: {
      available: false,
      enabled: true,
      message: "yara unavailable",
      usingCustomBin: false,
      usingCustomRules: false,
      timeoutMs: 25000,
    },
  };
}

function createEnvConfiguredToolRuntimeSnapshot(): ToolRuntimeSnapshot {
  const snapshot = createToolRuntimeSnapshot();
  snapshot.config = {
    tsharkPath: "",
    ffmpegPath: "C:/Env/ffmpeg.exe",
    pythonPath: "C:/Env/python.exe",
    voskModelPath: "C:/Env/vosk-model",
    yaraEnabled: true,
    yaraBin: "C:/Env/yara.exe",
    yaraRules: "C:/Env/default.yar",
    yaraTimeoutMs: 45000,
  };
  snapshot.ffmpeg = {
    available: true,
    path: "C:/Env/ffmpeg.exe",
    message: "ok",
    customPath: "C:/Env/ffmpeg.exe",
    usingCustomPath: true,
  };
  snapshot.speech = {
    ...snapshot.speech,
    available: true,
    pythonAvailable: true,
    pythonCommand: "C:/Env/python.exe",
    ffmpegAvailable: true,
    voskAvailable: true,
    modelAvailable: true,
    modelPath: "C:/Env/vosk-model",
    message: "ok",
  };
  snapshot.yara = {
    available: true,
    enabled: true,
    path: "C:/Env/yara.exe",
    rulePath: "C:/Env/default.yar",
    message: "ok",
    usingCustomBin: true,
    usingCustomRules: true,
    timeoutMs: 45000,
  };
  return snapshot;
}

function createPacket(id: number): Packet {
  return {
    id,
    time: "2026-05-08 19:20:00",
    src: "10.0.0.1",
    srcPort: 12345,
    dst: "10.0.0.2",
    dstPort: 443,
    proto: "TCP",
    length: 64,
    info: `packet-${id}`,
    payload: "",
  };
}

interface HarnessOptions {
  activeCapturePath?: string;
  preloading?: boolean;
}

function useBackendLifecycleHarness(options: HarnessOptions = {}) {
  const activeCapturePathRef = useRef(options.activeCapturePath ?? "");
  const captureWaitersRef = useRef(new Set<() => void>());
  const parseFinishedRef = useRef(false);
  const parseErrorRef = useRef("");
  const preloadingRef = useRef(options.preloading ?? false);
  const scheduleLoadMoreRef = useRef(vi.fn());
  const refreshAnalysisResultRef = useRef(vi.fn(async () => undefined));
  const updateProgressFromStatusRef = useRef(vi.fn(() => true));
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [mediaAnalysisProgress, setMediaAnalysisProgress] =
    useState<MediaAnalysisProgress>(EMPTY_MEDIA_ANALYSIS_PROGRESS);
  const [threatAnalysisProgress, setThreatAnalysisProgress] =
    useState<ThreatAnalysisProgress>(EMPTY_THREAT_ANALYSIS_PROGRESS);
  const [isThreatAnalysisLoading, setIsThreatAnalysisLoading] = useState(false);

  const lifecycle = useBackendLifecycle({
    activeCapturePathRef,
    captureWaitersRef,
    parseFinishedRef,
    parseErrorRef,
    preloadingRef,
    scheduleLoadMoreRef,
    refreshAnalysisResultRef,
    updateProgressFromStatusRef,
    setSelectedPacketId,
    setMediaAnalysisProgress,
    setThreatAnalysisProgress,
    setIsThreatAnalysisLoading,
  });

  return {
    ...lifecycle,
    activeCapturePathRef,
    captureWaitersRef,
    parseFinishedRef,
    parseErrorRef,
    preloadingRef,
    scheduleLoadMore: scheduleLoadMoreRef.current,
    refreshAnalysisResult: refreshAnalysisResultRef.current,
    updateProgressFromStatus: updateProgressFromStatusRef.current,
    selectedPacketId,
    mediaAnalysisProgress,
    threatAnalysisProgress,
    isThreatAnalysisLoading,
  };
}

async function renderConnectedLifecycle(options?: HarnessOptions) {
  const result = renderHook(() => useBackendLifecycleHarness(options));
  await waitFor(() => {
    expect(result.result.current.backendConnected).toBe(true);
  });
  await waitFor(() => {
    expect(bridgeMocks.handlers).not.toBeNull();
  });
  return result;
}

function installRuntimeLocalStorage() {
  const values = new Map<string, string>();
  vi.spyOn(window.localStorage, "getItem").mockImplementation((key) => values.get(key) ?? null);
  vi.spyOn(window.localStorage, "setItem").mockImplementation((key, value) => {
    values.set(key, value);
  });
  vi.spyOn(window.localStorage, "removeItem").mockImplementation((key) => {
    values.delete(key);
  });
  vi.spyOn(window.localStorage, "clear").mockImplementation(() => values.clear());
  return values;
}

describe("useBackendLifecycle", () => {
  beforeEach(() => {
    vi.useRealTimers();
    window.localStorage.clear();
    bridgeMocks.clearHandlers();
    bridgeMocks.isAvailable.mockResolvedValue(true);
    bridgeMocks.getDesktopBackendStatus.mockResolvedValue("");
    bridgeMocks.updateToolRuntimeConfig.mockResolvedValue(createToolRuntimeSnapshot());
    bridgeMocks.getTLSConfig.mockResolvedValue({
      sslKeyLogPath: "C:/logs/ssl.log",
      privateKeyPath: "C:/keys/server.pem",
      privateKeyIpPort: "10.0.0.1:443",
    } satisfies DecryptionConfig);
    bridgeMocks.updateTLSConfig.mockResolvedValue(undefined);
    bridgeMocks.setTSharkPath.mockResolvedValue(createToolRuntimeSnapshot().tshark);
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(createToolRuntimeSnapshot());
    bridgeMocks.subscribeEvents.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.clearAllMocks();
    bridgeMocks.clearHandlers();
  });

  it("loads runtime status and TLS config when the backend is available", async () => {
    const { result, unmount } = await renderConnectedLifecycle();

    expect(result.current.backendStatus).toBe("后端已连接，等待打开文件");
    expect(result.current.tsharkStatus).toMatchObject({
      available: true,
      path: "C:/Tools/tshark.exe",
      message: "ok",
    });
    expect(result.current.toolRuntimeProbeState).toBe("ready");
    expect(result.current.lastToolRuntimeProbeError).toBe("");
    expect(result.current.decryptionConfig).toEqual({
      sslKeyLogPath: "C:/logs/ssl.log",
      privateKeyPath: "C:/keys/server.pem",
      privateKeyIpPort: "10.0.0.1:443",
    });
    expect(bridgeMocks.getToolRuntimeSnapshot).toHaveBeenCalledWith(expect.any(AbortSignal), "fast");
    expect(bridgeMocks.getToolRuntimeSnapshot).toHaveBeenCalledWith(expect.any(AbortSignal), "full");
    expect(bridgeMocks.updateToolRuntimeConfig).not.toHaveBeenCalled();
    expect(bridgeMocks.subscribeEvents).toHaveBeenCalledTimes(1);

    unmount();
  });

  it("keeps backend connected and exposes a probe failure when the startup snapshot fails", async () => {
    bridgeMocks.getToolRuntimeSnapshot.mockRejectedValue(new Error("unauthorized"));
    const result = renderHook(() => useBackendLifecycleHarness());

    await waitFor(() => {
      expect(result.result.current.backendConnected).toBe(true);
    });
    await waitFor(() => {
      expect(result.result.current.toolRuntimeProbeState).toBe("failed");
    });

    expect(result.result.current.toolRuntimeCheckDegraded).toBe(true);
    expect(result.result.current.lastToolRuntimeProbeError).toContain("token 不匹配");
    expect(result.result.current.backendStatus).toContain("运行时组件检测失败");

    result.unmount();
  });

  it("syncs saved runtime config after the initial startup snapshot when it differs", async () => {
    const storedConfig = JSON.stringify({
      tsharkPath: "C:/Saved/tshark.exe",
      ffmpegPath: "",
      pythonPath: "",
      voskModelPath: "",
      yaraEnabled: true,
      yaraBin: "",
      yaraRules: "",
      yaraTimeoutMs: 25000,
    });
    const getItemSpy = vi.spyOn(window.localStorage, "getItem").mockImplementation((key: string) => {
      return key === "gshark.tool-runtime.v1" ? storedConfig : null;
    });
    const syncedSnapshot = createToolRuntimeSnapshot();
    syncedSnapshot.config.tsharkPath = "C:/Saved/tshark.exe";
    syncedSnapshot.tshark = {
      available: true,
      path: "C:/Saved/tshark.exe",
      message: "ok",
      customPath: "C:/Saved/tshark.exe",
      usingCustomPath: true,
    };
    bridgeMocks.updateToolRuntimeConfig.mockResolvedValue(syncedSnapshot);
    expect(readToolRuntimeConfig().tsharkPath).toBe("C:/Saved/tshark.exe");

    const setTsharkStatus = vi.fn();

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus,
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    await waitFor(() => {
      expect(bridgeMocks.updateToolRuntimeConfig).toHaveBeenCalledWith(
        expect.objectContaining({ tsharkPath: "C:/Saved/tshark.exe" }),
        expect.any(AbortSignal),
        "fast",
      );
    });
    expect(setTsharkStatus).toHaveBeenCalledWith(
      expect.objectContaining({
        available: true,
        path: "C:/Saved/tshark.exe",
        usingCustomPath: true,
      }),
    );
    getItemSpy.mockRestore();
  });

  it("trusts the backend env snapshot on first startup instead of posting empty defaults", async () => {
    installRuntimeLocalStorage();
    const envSnapshot = createEnvConfiguredToolRuntimeSnapshot();
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(envSnapshot);

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus: vi.fn(),
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    expect(bridgeMocks.updateToolRuntimeConfig).not.toHaveBeenCalled();
    expect(readToolRuntimeConfig()).toEqual(envSnapshot.config);
  });

  it("keeps TShark capability metadata from the startup runtime snapshot", async () => {
    installRuntimeLocalStorage();
    const snapshot = createToolRuntimeSnapshot();
    snapshot.tshark = {
      ...snapshot.tshark,
      version: "TShark 4.6.5",
      fieldProfile: "compat",
      fieldCount: 3600,
      missingOptionalFields: ["usbms.scsi.opcode"],
      capabilityMessage: "optional fields missing",
      capabilityCheckDegraded: true,
    };
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(snapshot);
    const setTsharkStatus = vi.fn();

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus,
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    expect(setTsharkStatus).toHaveBeenCalledWith(
      expect.objectContaining({
        available: true,
        fieldProfile: "compat",
        missingOptionalFields: ["usbms.scsi.opcode"],
        capabilityCheckDegraded: true,
      }),
    );
    expect(bridgeMocks.updateToolRuntimeConfig).not.toHaveBeenCalled();
  });

  it("migrates legacy all-empty runtime storage without clearing backend env config", async () => {
    installRuntimeLocalStorage();
    window.localStorage.setItem("gshark.tool-runtime.v1", JSON.stringify(createToolRuntimeSnapshot().config));
    const envSnapshot = createEnvConfiguredToolRuntimeSnapshot();
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(envSnapshot);

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus: vi.fn(),
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    expect(bridgeMocks.updateToolRuntimeConfig).not.toHaveBeenCalled();
    expect(readToolRuntimeConfig()).toEqual(envSnapshot.config);
  });

  it("merges legacy tshark storage with the backend env config during startup sync", async () => {
    installRuntimeLocalStorage();
    window.localStorage.setItem("gshark.tshark-path.v1", "C:/Legacy/tshark.exe");
    const envSnapshot = createEnvConfiguredToolRuntimeSnapshot();
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(envSnapshot);
    bridgeMocks.updateToolRuntimeConfig.mockResolvedValue({
      ...envSnapshot,
      config: {
        ...envSnapshot.config,
        tsharkPath: "C:/Legacy/tshark.exe",
      },
      tshark: {
        ...envSnapshot.tshark,
        path: "C:/Legacy/tshark.exe",
        customPath: "C:/Legacy/tshark.exe",
        usingCustomPath: true,
      },
    });

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus: vi.fn(),
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    await waitFor(() => {
      expect(bridgeMocks.updateToolRuntimeConfig).toHaveBeenCalledWith(
        {
          ...envSnapshot.config,
          tsharkPath: "C:/Legacy/tshark.exe",
        },
        expect.any(AbortSignal),
        "fast",
      );
    });
  });

  it("lets a stored complete runtime config override backend env config", async () => {
    installRuntimeLocalStorage();
    window.localStorage.setItem(
      "gshark.tool-runtime.v1",
      JSON.stringify({
        tsharkPath: "C:/Stored/tshark.exe",
        ffmpegPath: "C:/Stored/ffmpeg.exe",
        pythonPath: "C:/Stored/python.exe",
        voskModelPath: "C:/Stored/vosk-model",
        yaraEnabled: false,
        yaraBin: "C:/Stored/yara.exe",
        yaraRules: "C:/Stored/rules",
        yaraTimeoutMs: 32000,
      }),
    );
    const envSnapshot = createEnvConfiguredToolRuntimeSnapshot();
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(envSnapshot);

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus: vi.fn(),
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    await waitFor(() => {
      expect(bridgeMocks.updateToolRuntimeConfig).toHaveBeenCalledWith(
        expect.objectContaining({
          tsharkPath: "C:/Stored/tshark.exe",
          ffmpegPath: "C:/Stored/ffmpeg.exe",
          pythonPath: "C:/Stored/python.exe",
          voskModelPath: "C:/Stored/vosk-model",
          yaraEnabled: false,
        }),
        expect.any(AbortSignal),
        "fast",
      );
    });
  });

  it("lets v2 explicit empty fields clear backend env config without clearing other env fields", async () => {
    installRuntimeLocalStorage();
    const envSnapshot = createEnvConfiguredToolRuntimeSnapshot();
    window.localStorage.setItem(
      "gshark.tool-runtime.v1",
      JSON.stringify({
        version: 2,
        source: "stored-runtime-config",
        config: { ...envSnapshot.config, ffmpegPath: "" },
        explicitFields: { ffmpegPath: true },
      }),
    );
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(envSnapshot);

    await loadStartupToolRuntime({
      isCancelled: () => false,
      setBackendStatus: vi.fn(),
      setIsTSharkChecking: vi.fn(),
      setIsToolRuntimeLoading: vi.fn(),
      setToolRuntimeCheckDegraded: vi.fn(),
      setToolRuntimeSnapshot: vi.fn(),
      setTsharkStatus: vi.fn(),
      setToolRuntimeProbeState: vi.fn(),
      setToolRuntimeProbeTransport: vi.fn(),
      setLastToolRuntimeProbeError: vi.fn(),
    });

    await waitFor(() => {
      expect(bridgeMocks.updateToolRuntimeConfig).toHaveBeenCalledWith(
        {
          ...envSnapshot.config,
          ffmpegPath: "",
        },
        expect.any(AbortSignal),
        "fast",
      );
    });
  });

  it("manual runtime save only marks dirty fields as explicit overrides", async () => {
    installRuntimeLocalStorage();
    const envSnapshot = createEnvConfiguredToolRuntimeSnapshot();
    bridgeMocks.getToolRuntimeSnapshot.mockResolvedValue(envSnapshot);
    bridgeMocks.updateToolRuntimeConfig.mockResolvedValue({
      ...envSnapshot,
      config: {
        ...envSnapshot.config,
        ffmpegPath: "",
      },
    });
    const { result, unmount } = await renderConnectedLifecycle();

    await act(async () => {
      await result.current.saveToolRuntimeConfig(
        {
          ...envSnapshot.config,
          ffmpegPath: "",
        },
        { ffmpegPath: true },
      );
    });

    expect(bridgeMocks.updateToolRuntimeConfig).toHaveBeenCalledWith(
      {
        ...envSnapshot.config,
        ffmpegPath: "",
      },
      expect.any(AbortSignal),
      "fast",
    );
    const stored = JSON.parse(window.localStorage.getItem("gshark.tool-runtime.v1") || "{}");
    expect(stored.source).toBe("stored-runtime-config");
    expect(stored.explicitFields).toEqual({ ffmpegPath: true });
    unmount();
  });

  it("schedules packet pagination and debounced analysis refresh outside preload", async () => {
    const { result, unmount } = await renderConnectedLifecycle();
    vi.useFakeTimers();

    act(() => {
      bridgeMocks.handlers?.packet?.(createPacket(42));
    });

    expect(result.current.scheduleLoadMore).toHaveBeenCalledTimes(1);
    expect(result.current.refreshAnalysisResult).not.toHaveBeenCalled();
    expect(result.current.selectedPacketId).toBe(42);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    expect(result.current.refreshAnalysisResult).toHaveBeenCalledTimes(1);

    unmount();
  });

  it("skips packet pagination and refresh while preloading", async () => {
    const { result, unmount } = await renderConnectedLifecycle({ preloading: true });
    vi.useFakeTimers();

    act(() => {
      bridgeMocks.handlers?.packet?.(createPacket(7));
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    expect(result.current.selectedPacketId).toBe(7);
    expect(result.current.scheduleLoadMore).not.toHaveBeenCalled();
    expect(result.current.refreshAnalysisResult).not.toHaveBeenCalled();

    unmount();
  });

  it("wakes capture waiters and forwards progress statuses for active captures", async () => {
    const { result, unmount } = await renderConnectedLifecycle({
      activeCapturePath: "C:/captures/sample.pcapng",
    });
    const waiter = vi.fn();
    act(() => {
      result.current.captureWaitersRef.current.add(waiter);
      bridgeMocks.handlers?.status?.("__progress__:counting:1:10");
    });

    expect(result.current.updateProgressFromStatus).toHaveBeenCalledWith("__progress__:counting:1:10");
    expect(waiter).toHaveBeenCalledTimes(1);
    expect(result.current.backendStatus).toBe("后端已连接，等待打开文件");

    unmount();
  });

  it("forwards preload progress before the first capture has an active path", async () => {
    const { result, unmount } = await renderConnectedLifecycle({ preloading: true });
    const waiter = vi.fn();

    act(() => {
      result.current.captureWaitersRef.current.add(waiter);
      bridgeMocks.handlers?.status?.("__progress__:parsing:7:10");
    });

    expect(result.current.updateProgressFromStatus).toHaveBeenCalledWith("__progress__:parsing:7:10");
    expect(waiter).toHaveBeenCalledTimes(1);

    unmount();
  });

  it("marks first-capture parsing complete before the active path is committed", async () => {
    const { result, unmount } = await renderConnectedLifecycle({ preloading: true });

    act(() => {
      result.current.parseFinishedRef.current = false;
      bridgeMocks.handlers?.status?.("解析完成");
    });

    expect(result.current.parseFinishedRef.current).toBe(true);
    expect(result.current.parseErrorRef.current).toBe("");
    expect(result.current.backendStatus).toBe("解析完成");

    unmount();
  });

  it("marks parse errors from preload error events and resets threat loading", async () => {
    const { result, unmount } = await renderConnectedLifecycle({
      activeCapturePath: "C:/captures/sample.pcapng",
      preloading: true,
    });

    act(() => {
      result.current.parseFinishedRef.current = false;
      result.current.parseErrorRef.current = "";
      bridgeMocks.handlers?.error?.("威胁分析失败: yara timeout");
    });

    expect(result.current.parseFinishedRef.current).toBe(true);
    expect(result.current.parseErrorRef.current).toBe("威胁分析失败: yara timeout");
    expect(result.current.threatAnalysisProgress).toEqual(EMPTY_THREAT_ANALYSIS_PROGRESS);
    expect(result.current.isThreatAnalysisLoading).toBe(false);
    expect(result.current.backendStatus).toBe("威胁分析失败: yara timeout");

    unmount();
  });

  it("updates TLS config with the merged current values", async () => {
    const { result, unmount } = await renderConnectedLifecycle();

    act(() => {
      result.current.updateDecryptionConfig({ sslKeyLogPath: "D:/next/ssl.log" });
    });

    await waitFor(() => {
      expect(bridgeMocks.updateTLSConfig).toHaveBeenCalledWith({
        sslKeyLogPath: "D:/next/ssl.log",
        privateKeyPath: "C:/keys/server.pem",
        privateKeyIpPort: "10.0.0.1:443",
      });
    });
    expect(result.current.decryptionConfig.sslKeyLogPath).toBe("D:/next/ssl.log");

    unmount();
  });
});
