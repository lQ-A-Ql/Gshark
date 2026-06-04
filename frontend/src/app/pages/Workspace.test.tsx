import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCapturePreloadDiagnostics, type CapturePreloadDiagnostics } from "../state/capturePreloadDiagnostics";
import Workspace from "./Workspace";

const sentinelState = vi.hoisted(() => ({
  displayFilter: "",
  setDisplayFilter: vi.fn(),
  applyFilter: vi.fn(),
  clearFilter: vi.fn(),
  filteredPackets: [],
  totalPackets: 0,
  currentPage: 1,
  totalPages: 1,
  isPreloadingCapture: false,
  preloadProcessed: 0,
  preloadTotal: 0,
  hasMorePackets: false,
  hasPrevPackets: false,
  isPageLoading: false,
  isFilterLoading: false,
  packetPageError: "",
  captureTransaction: {
    phase: "idle",
    reason: "",
    message: "",
    pendingCaptureName: "",
    pendingCapturePath: "",
    hasActiveCapture: false,
  },
  loadMorePackets: vi.fn(),
  loadPrevPackets: vi.fn(),
  jumpToPage: vi.fn(),
  retryPacketPage: vi.fn(),
  locatePacketById: vi.fn(),
  selectedPacket: null,
  selectedPacketRawHex: "",
  selectedPacketId: null,
  selectPacket: vi.fn(),
  protocolTree: [],
  fileMeta: { name: "", sizeBytes: 0, path: "" },
  capturePreloadDiagnostics: null as CapturePreloadDiagnostics | null,
  openCapture: vi.fn(),
  stopCapture: vi.fn(),
  retryCapturePreloadConfirm: vi.fn(async () => true),
  setActiveStream: vi.fn(),
  backendConnected: true,
  backendStatus: "正在预加载 sample.pcapng",
  tsharkStatus: { available: true, path: "tshark", message: "ok" },
}));

vi.mock("../state/contexts/BackendContext", () => ({
  useBackend: () => ({
    backendConnected: sentinelState.backendConnected,
    backendStatus: sentinelState.backendStatus,
    tsharkStatus: sentinelState.tsharkStatus,
  }),
}));

vi.mock("../state/contexts/CaptureContext", () => ({
  useCapture: () => ({
    isPreloadingCapture: sentinelState.isPreloadingCapture,
    preloadProcessed: sentinelState.preloadProcessed,
    preloadTotal: sentinelState.preloadTotal,
    capturePreloadDiagnostics: sentinelState.capturePreloadDiagnostics,
    captureTransaction: sentinelState.captureTransaction,
    fileMeta: sentinelState.fileMeta,
    openCapture: sentinelState.openCapture,
    stopCapture: sentinelState.stopCapture,
    retryCapturePreloadConfirm: sentinelState.retryCapturePreloadConfirm,
  }),
}));

vi.mock("../state/contexts/PacketContext", () => ({
  usePacket: () => ({
    filteredPackets: sentinelState.filteredPackets,
    totalPackets: sentinelState.totalPackets,
    currentPage: sentinelState.currentPage,
    totalPages: sentinelState.totalPages,
    hasMorePackets: sentinelState.hasMorePackets,
    hasPrevPackets: sentinelState.hasPrevPackets,
    isPageLoading: sentinelState.isPageLoading,
    isFilterLoading: sentinelState.isFilterLoading,
    packetPageError: sentinelState.packetPageError,
    loadMorePackets: sentinelState.loadMorePackets,
    loadPrevPackets: sentinelState.loadPrevPackets,
    jumpToPage: sentinelState.jumpToPage,
    retryPacketPage: sentinelState.retryPacketPage,
    locatePacketById: sentinelState.locatePacketById,
    selectedPacket: sentinelState.selectedPacket,
    selectedPacketRawHex: sentinelState.selectedPacketRawHex,
    selectedPacketId: sentinelState.selectedPacketId,
    selectPacket: sentinelState.selectPacket,
    protocolTree: sentinelState.protocolTree,
  }),
}));

vi.mock("../state/contexts/StreamContext", () => ({
  useStream: () => ({
    setActiveStream: sentinelState.setActiveStream,
  }),
}));

vi.mock("../state/contexts/FilterContext", () => ({
  useFilter: () => ({
    displayFilter: sentinelState.displayFilter,
    setDisplayFilter: sentinelState.setDisplayFilter,
    applyFilter: sentinelState.applyFilter,
    clearFilter: sentinelState.clearFilter,
  }),
}));

vi.mock("../state/contexts/AnalysisContext", () => ({
  useAnalysis: () => ({}),
}));

describe("Workspace", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sentinelState.fileMeta = { name: "", sizeBytes: 0, path: "" };
    sentinelState.isPreloadingCapture = false;
    sentinelState.capturePreloadDiagnostics = null;
    sentinelState.captureTransaction = {
      phase: "idle",
      reason: "",
      message: "",
      pendingCaptureName: "",
      pendingCapturePath: "",
      hasActiveCapture: false,
    };
  });

  it("leaves the welcome screen while a first capture is pending preload", () => {
    sentinelState.isPreloadingCapture = true;
    sentinelState.preloadProcessed = 18;
    sentinelState.preloadTotal = 100;
    sentinelState.captureTransaction = {
      phase: "pending",
      reason: "",
      message: "",
      pendingCaptureName: "sample.pcapng",
      pendingCapturePath: "C:/captures/sample.pcapng",
      hasActiveCapture: false,
    };

    render(
      <MemoryRouter>
        <Workspace />
      </MemoryRouter>,
    );

    expect(screen.queryByText(/MEOW~TRAFFIC QUICK START/)).not.toBeInTheDocument();
    expect(screen.getByText("流量工作区")).toBeInTheDocument();
    expect(screen.getByText("正在预加载全部流量")).toBeInTheDocument();
  });

  it("shows preload confirmation diagnostics and lets the user retry confirmation", () => {
    sentinelState.isPreloadingCapture = true;
    sentinelState.capturePreloadDiagnostics = createCapturePreloadDiagnostics({
      phase: "status_failed",
      openedPath: "C:/captures/sample.pcapng",
      page: { items: [{} as never], nextCursor: 1, total: 12, hasMore: true },
      statusTransport: "desktop-ipc",
      lastStatusError: "确认状态超时",
      now: () => new Date("2026-05-16T00:00:00.000Z"),
    });
    sentinelState.captureTransaction = {
      phase: "pending",
      reason: "",
      message: "",
      pendingCaptureName: "sample.pcapng",
      pendingCapturePath: "C:/captures/sample.pcapng",
      hasActiveCapture: false,
    };

    render(
      <MemoryRouter>
        <Workspace />
      </MemoryRouter>,
    );

    expect(screen.getByText("状态确认失败：确认状态超时")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /重新确认/ }));
    expect(sentinelState.retryCapturePreloadConfirm).toHaveBeenCalledTimes(1);
  });

  it("explains empty page/status as an active backend parse when load status is present", () => {
    sentinelState.isPreloadingCapture = true;
    sentinelState.capturePreloadDiagnostics = createCapturePreloadDiagnostics({
      phase: "backend_parsing",
      openedPath: "C:/captures/sample.pcapng",
      page: { items: [], nextCursor: 0, total: 0, hasMore: false, transport: "desktop-ipc" },
      status: {
        filePath: "",
        hasCapture: false,
        packetCount: 0,
        transport: "desktop-ipc",
        load: {
          runId: 4,
          filePath: "C:/captures/sample.pcapng",
          phase: "parsing",
          parserProfile: "first_screen",
          estimatedTotal: 100,
          processed: 40,
          accepted: 38,
          stagedCount: 32,
          lastError: "",
          startedAt: "",
          updatedAt: "",
          completedAt: "",
        },
      },
      now: () => new Date("2026-05-16T00:00:00.000Z"),
    });
    sentinelState.captureTransaction = {
      phase: "pending",
      reason: "",
      message: "",
      pendingCaptureName: "sample.pcapng",
      pendingCapturePath: "C:/captures/sample.pcapng",
      hasActiveCapture: false,
    };

    render(
      <MemoryRouter>
        <Workspace />
      </MemoryRouter>,
    );

    expect(screen.getByText(/后端正在解析，尚未提交首屏数据/)).toBeInTheDocument();
  });
});
