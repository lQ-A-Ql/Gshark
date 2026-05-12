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
import { useBackendLifecycle } from "./useBackendLifecycle";

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
    expect(result.current.decryptionConfig).toEqual({
      sslKeyLogPath: "C:/logs/ssl.log",
      privateKeyPath: "C:/keys/server.pem",
      privateKeyIpPort: "10.0.0.1:443",
    });
    expect(bridgeMocks.updateToolRuntimeConfig).toHaveBeenCalledTimes(1);
    expect(bridgeMocks.subscribeEvents).toHaveBeenCalledTimes(1);

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
