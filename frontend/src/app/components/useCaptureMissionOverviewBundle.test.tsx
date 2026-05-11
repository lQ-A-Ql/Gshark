import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useCaptureMissionOverviewBundle } from "./useCaptureMissionOverviewBundle";

const bridgeMocks = vi.hoisted(() => ({
  getGlobalTrafficStats: vi.fn(),
  getIndustrialAnalysis: vi.fn(),
  getVehicleAnalysis: vi.fn(),
  getMediaAnalysis: vi.fn(),
  getUSBAnalysis: vi.fn(),
}));

vi.mock("../integrations/wailsBridge", () => ({
  bridge: bridgeMocks,
}));

describe("useCaptureMissionOverviewBundle", () => {
  beforeEach(() => {
    Object.values(bridgeMocks).forEach((mock) => mock.mockReset());
    bridgeMocks.getGlobalTrafficStats.mockResolvedValue({ totalPackets: 10 });
    bridgeMocks.getIndustrialAnalysis.mockResolvedValue({ transactions: [] });
    bridgeMocks.getVehicleAnalysis.mockResolvedValue({ messages: [] });
    bridgeMocks.getMediaAnalysis.mockResolvedValue({ sessions: [] });
    bridgeMocks.getUSBAnalysis.mockResolvedValue({ devices: [] });
  });

  it("loads overview analysis once per capture key and reuses cache", async () => {
    const { result, unmount } = renderHook(
      (props: { captureKey: string }) =>
        useCaptureMissionOverviewBundle({ backendConnected: true, captureKey: props.captureKey, isPreloadingCapture: false }),
      { initialProps: { captureKey: "sample.pcapng::10" } },
    );

    await waitFor(() => expect(result.current.overviewBundle?.stats).toEqual({ totalPackets: 10 }));
    expect(result.current.overviewLoading).toBe(false);
    expect(result.current.overviewBundle?.stats).toEqual({ totalPackets: 10 });
    expect(bridgeMocks.getGlobalTrafficStats).toHaveBeenCalledTimes(1);
    unmount();

    const cached = renderHook(() => useCaptureMissionOverviewBundle({
      backendConnected: true,
      captureKey: "sample.pcapng::10",
      isPreloadingCapture: false,
    }));

    expect(cached.result.current.overviewBundle?.stats).toEqual({ totalPackets: 10 });
    expect(bridgeMocks.getGlobalTrafficStats).toHaveBeenCalledTimes(1);
  });

  it("clears overview state while capture is unavailable", async () => {
    const { result, rerender } = renderHook(
      (props: { backendConnected: boolean; captureKey: string }) =>
        useCaptureMissionOverviewBundle({ backendConnected: props.backendConnected, captureKey: props.captureKey, isPreloadingCapture: false }),
      { initialProps: { backendConnected: true, captureKey: "other.pcap::5" } },
    );

    await waitFor(() => expect(result.current.overviewBundle).not.toBeNull());

    act(() => {
      rerender({ backendConnected: false, captureKey: "other.pcap::5" });
    });

    expect(result.current.overviewBundle).toBeNull();
    expect(result.current.overviewLoading).toBe(false);
  });
});
