import { act, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StartupGate } from "./App";

const sentinelState = vi.hoisted(() => ({
  backendConnected: true,
  backendStatus: "后端已连接",
  tsharkStatus: {
    available: false,
    path: "",
    message: "未检测到 TShark，可在设置中配置",
    customPath: "",
    usingCustomPath: false,
    missingOptionalFields: undefined as string[] | undefined,
    capabilityCheckDegraded: undefined as boolean | undefined,
  },
  isTSharkChecking: true,
  toolRuntimeCheckDegraded: false,
  toolRuntimeProbeState: "ready",
  toolRuntimeProbeTransport: "desktop-ipc",
  lastToolRuntimeProbeError: "",
  setTSharkPath: vi.fn(),
  toolRuntimeSnapshot: {
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
      path: "C:/Program Files/Wireshark/tshark.exe",
      message: "ok",
      usingCustomPath: false,
    },
    ffmpeg: {
      available: true,
      path: "C:/ffmpeg/bin/ffmpeg.exe",
      message: "ok",
      usingCustomPath: false,
    },
    speech: {
      available: false,
      engine: "vosk",
      language: "zh-CN",
      pythonAvailable: true,
      pythonCommand: "python",
      ffmpegAvailable: true,
      voskAvailable: true,
      modelAvailable: false,
      message: "未检测到 Vosk 中文模型",
    },
    yara: {
      available: true,
      enabled: true,
      message: "ok",
      usingCustomBin: false,
      usingCustomRules: false,
      timeoutMs: 25000,
    },
  },
  isToolRuntimeLoading: false,
  refreshToolRuntimeSnapshot: vi.fn(),
}));

vi.mock("react-router", () => ({
  RouterProvider: () => <div data-testid="main-app" />,
}));

vi.mock("./routes", () => ({
  router: {},
}));

vi.mock("./state/SentinelContext", () => ({
  useSentinel: () => sentinelState,
  SentinelProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

function createToolRuntimeSnapshot() {
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
      path: "C:/Program Files/Wireshark/tshark.exe",
      message: "ok",
      usingCustomPath: false,
    },
    ffmpeg: {
      available: true,
      path: "C:/ffmpeg/bin/ffmpeg.exe",
      message: "ok",
      usingCustomPath: false,
    },
    speech: {
      available: false,
      engine: "vosk",
      language: "zh-CN",
      pythonAvailable: true,
      pythonCommand: "python",
      ffmpegAvailable: true,
      voskAvailable: true,
      modelAvailable: false,
      message: "未检测到 Vosk 中文模型",
    },
    yara: {
      available: true,
      enabled: true,
      message: "ok",
      usingCustomBin: false,
      usingCustomRules: false,
      timeoutMs: 25000,
    },
  };
}

describe("StartupGate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    sentinelState.backendConnected = true;
    sentinelState.isTSharkChecking = true;
    sentinelState.tsharkStatus.available = false;
    sentinelState.tsharkStatus.message = "未检测到 TShark，可在设置中配置";
    sentinelState.tsharkStatus.path = "";
    sentinelState.tsharkStatus.missingOptionalFields = undefined;
    sentinelState.tsharkStatus.capabilityCheckDegraded = undefined;
    sentinelState.toolRuntimeSnapshot = createToolRuntimeSnapshot();
    sentinelState.toolRuntimeSnapshot.ffmpeg.available = true;
    sentinelState.toolRuntimeSnapshot.speech.pythonAvailable = true;
    sentinelState.toolRuntimeSnapshot.speech.modelAvailable = false;
    sentinelState.isToolRuntimeLoading = false;
    sentinelState.toolRuntimeProbeState = "ready";
    sentinelState.toolRuntimeProbeTransport = "desktop-ipc";
    sentinelState.lastToolRuntimeProbeError = "";
    sentinelState.refreshToolRuntimeSnapshot.mockResolvedValue(sentinelState.toolRuntimeSnapshot);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("enters the main app after backend connection even while TShark probing is degraded or slow", async () => {
    render(<StartupGate />);

    expect(screen.getByText("启动中")).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });

    expect(screen.getByTestId("main-app")).toBeInTheDocument();
  });

  it("offers a manual runtime tool probe while the startup gate is visible", async () => {
    sentinelState.isTSharkChecking = false;
    sentinelState.tsharkStatus.available = true;
    sentinelState.tsharkStatus.path = "C:/Program Files/Wireshark/tshark.exe";

    render(<StartupGate />);

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /重新探测工具/ }));
      await Promise.resolve();
    });

    expect(sentinelState.refreshToolRuntimeSnapshot).toHaveBeenCalledTimes(1);
    expect(screen.getByText("已重新探测工具状态。")).toBeInTheDocument();
  });

  it("shows TShark compat as degraded instead of unavailable", () => {
    sentinelState.isTSharkChecking = false;
    sentinelState.tsharkStatus.available = true;
    sentinelState.tsharkStatus.path = "C:/Program Files/Wireshark/tshark.exe";
    sentinelState.tsharkStatus.capabilityCheckDegraded = true;
    sentinelState.tsharkStatus.missingOptionalFields = ["usbms.scsi.opcode"];

    render(<StartupGate />);

    expect(screen.getByText(/可用，部分分析降级/)).toBeInTheDocument();
    expect(screen.getByText(/缺少可选字段：usbms.scsi.opcode/)).toBeInTheDocument();
  });

  it("shows runtime probe failures instead of reporting every tool as missing", () => {
    sentinelState.isTSharkChecking = false;
    sentinelState.toolRuntimeSnapshot = null as any;
    sentinelState.toolRuntimeProbeState = "failed";
    sentinelState.toolRuntimeProbeTransport = "desktop-ipc";
    sentinelState.lastToolRuntimeProbeError = "Wails IPC runtime snapshot failed";

    render(<StartupGate />);

    expect(screen.getByText(/探测失败 · Wails IPC：Wails IPC runtime snapshot failed/)).toBeInTheDocument();
    expect(screen.getByText(/FFmpeg：探测失败/)).toBeInTheDocument();
  });
});
