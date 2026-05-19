import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createUSBAnalysis, createUSBHidAnalysis } from "./UsbAnalysis.testFixtures";

const mocks = vi.hoisted(() => ({
  getUSBAnalysis: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: { path: "C:/captures/hid.pcapng", name: "hid.pcapng", sizeBytes: 2048 },
    totalPackets: 256,
    captureRevision: 1,
  },
}));

vi.mock("../state/SentinelContext", () => ({ useSentinel: () => mocks.sentinelState }));
vi.mock("../integrations/backendClients", () => ({
  backendClients: { analysis: { getUSBAnalysis: mocks.getUSBAnalysis } },
}));

import UsbAnalysis from "./UsbAnalysis";

describe("UsbAnalysis HID panel", () => {
  beforeEach(() => {
    mocks.sentinelState.captureRevision += 1;
    mocks.getUSBAnalysis.mockReset();
    mocks.getUSBAnalysis.mockResolvedValue(createUSBAnalysis());
  });

  it("renders keyboard, styled source selector, limit control, and truncation warning", async () => {
    mocks.getUSBAnalysis.mockResolvedValue(createUSBHidAnalysis());
    render(<UsbAnalysis />);

    await waitFor(() => expect(screen.getByRole("button", { name: "鼠标" })).toBeInTheDocument());
    expect(screen.getByText("编辑后文本")).toBeInTheDocument();
    expect(screen.getByText("删除字符")).toBeInTheDocument();
    expect(screen.getByText("AC")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "鼠标" }));
    await expectMousePanelReady();

    mocks.getUSBAnalysis.mockResolvedValue(createUSBHidAnalysis({ hidSourceMode: "usbhid" }));
    fireEvent.pointerDown(screen.getByRole("combobox", { name: "数据源" }), { button: 0, pointerType: "mouse" });
    fireEvent.keyDown(await screen.findByRole("option", { name: /usbhid\.data/ }), { key: "Enter" });
    await waitFor(() => expect(mocks.getUSBAnalysis).toHaveBeenLastCalledWith(expect.any(AbortSignal), "usbhid", 20000));

    mocks.getUSBAnalysis.mockResolvedValue(
      createUSBHidAnalysis({
        hidEventLimit: 45000,
        hidEventsTruncated: true,
        hidMouseEventsTotal: 47000,
        hidKeyboardEventsTotal: 1800,
      }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "HID 事件上限" }), { target: { value: "45000" } });
    fireEvent.blur(screen.getByRole("textbox", { name: "HID 事件上限" }));
    await waitFor(() => expect(mocks.getUSBAnalysis).toHaveBeenLastCalledWith(expect.any(AbortSignal), "usbhid", 45000));
    expect(await screen.findByText(/HID 事件已达到当前上限 45000/)).toBeInTheDocument();
    expect(screen.getByText(/鼠标总事件 47,000/)).toBeInTheDocument();
    expect(screen.getByText(/键盘总事件 1,800/)).toBeInTheDocument();
    expect(screen.getByText("轨迹已按事件上限截断")).toBeInTheDocument();
  });
});

async function expectMousePanelReady() {
  await waitFor(() => expect(screen.getByText("行为明细表 (4)")).toBeInTheDocument());
  expect(screen.getByText("HID 数据源")).toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: "数据源" })).toHaveTextContent("自动");
  expect(screen.getByRole("textbox", { name: "HID 事件上限" })).toHaveValue("20000");
  ["混合轨迹图", "左键轨迹图", "右键轨迹图", "无按键轨迹图"].forEach((label) => {
    expect(screen.getByText(label)).toBeInTheDocument();
  });
  ["候选：usbhid.data / usb.capdata", "Y 轴已取反", "左键", "右键", "无按键", "点阵轨迹", "等比例缩放"].forEach(
    (label) => expect(screen.getAllByText(label, { exact: false }).length).toBeGreaterThan(0),
  );
}
