import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createUSBAnalysis,
  createUSBHidAnalysis,
  createUSBMassStorageAnalysis,
  createUSBOtherAnalysis,
} from "./UsbAnalysis.testFixtures";

const mocks = vi.hoisted(() => ({
  getUSBAnalysis: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: {
      path: "C:/captures/usb.pcapng",
      name: "usb.pcapng",
      sizeBytes: 2048,
    },
    totalPackets: 128,
    captureRevision: 1,
  },
}));

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../integrations/wailsBridge", () => ({
  backendClients: {
    analysis: {
      getUSBAnalysis: mocks.getUSBAnalysis,
    },
  },
}));

import UsbAnalysis from "./UsbAnalysis";

describe("UsbAnalysis", () => {
  let renderSeed = 0;

  beforeEach(() => {
    renderSeed += 1;
    mocks.sentinelState.totalPackets = 128 + renderSeed;
    mocks.sentinelState.fileMeta = {
      ...mocks.sentinelState.fileMeta,
      path: `C:/captures/usb-${renderSeed}.pcapng`,
      name: `usb-${renderSeed}.pcapng`,
    };
    mocks.sentinelState.captureRevision = renderSeed;
    mocks.getUSBAnalysis.mockReset();
    mocks.getUSBAnalysis.mockResolvedValue(createUSBAnalysis());
  });

  it("defaults to the first top-level tab that has data", async () => {
    mocks.getUSBAnalysis.mockResolvedValue(createUSBMassStorageAnalysis());

    render(<UsbAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("总存储包")).toBeInTheDocument();
    });
    expect(screen.getByText("读请求数")).toBeInTheDocument();
  });

  it("switches between HID keyboard and mouse subpages", async () => {
    mocks.getUSBAnalysis.mockResolvedValue(createUSBHidAnalysis());

    render(<UsbAnalysis />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "键盘" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "鼠标" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "键盘" }));
    await waitFor(() => {
      expect(screen.getByText("完整文本流")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "鼠标" }));

    await waitFor(() => {
      expect(screen.getByText("行为明细表 (1)")).toBeInTheDocument();
    });
  });

  it("switches between Mass Storage overview, read, and write subpages", async () => {
    mocks.getUSBAnalysis.mockResolvedValue(createUSBMassStorageAnalysis());

    render(<UsbAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("总存储包")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "读请求" }));
    await waitFor(() => {
      expect(screen.getAllByText("READ(10)").length).toBeGreaterThan(0);
    });

    fireEvent.click(screen.getByRole("button", { name: "写请求" }));
    await waitFor(() => {
      expect(screen.getAllByText("WRITE(10)").length).toBeGreaterThan(0);
    });
  });

  it("switches between 其他 overview, control requests, and raw records", async () => {
    mocks.getUSBAnalysis.mockResolvedValue(createUSBOtherAnalysis());

    render(<UsbAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("设备分布")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "控制请求" }));
    await waitFor(() => {
      expect(screen.getByText("GET_DESCRIPTOR")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "原始记录" }));
    await waitFor(() => {
      expect(screen.getByText("raw record")).toBeInTheDocument();
    });
  });

  it("shows empty states for subpages when no USB data exists", async () => {
    render(<UsbAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("当前抓包未识别到可展示的 USB 行为。")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "原始记录" }));
    await waitFor(() => {
      expect(screen.getByText("暂无其他 USB 记录")).toBeInTheDocument();
    });
  });
});
