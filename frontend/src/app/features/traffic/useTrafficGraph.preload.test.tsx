import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { backendClients } from "../../integrations/backendClients";
import { trafficStatsPreloadContract, resetTrafficStatsPreloadForTest, useTrafficGraph } from "./useTrafficGraph";

vi.mock("../../integrations/backendClients", () => ({
  backendClients: {
    analysis: { getGlobalTrafficStats: vi.fn() },
    packet: { listPackets: vi.fn() },
  },
}));

const stats = {
  totalPackets: 3,
  protocolKinds: 1,
  timeline: [],
  protocolDist: [],
  topTalkers: [],
  topConversations: [],
  topHostnames: [],
  topDomains: [],
  topSrcIPs: [],
  topDstIPs: [],
  topComputerNames: [],
  topDestPorts: [],
  topSrcPorts: [],
  protocolHierarchy: [],
};

describe("traffic stats preload contract", () => {
  afterEach(() => {
    resetTrafficStatsPreloadForTest();
    vi.mocked(backendClients.analysis.getGlobalTrafficStats).mockReset();
    vi.mocked(backendClients.packet.listPackets).mockReset();
  });

  it("prefetches global stats only and page hook reuses cache", async () => {
    vi.mocked(backendClients.analysis.getGlobalTrafficStats).mockResolvedValue(stats);
    const input = { backendConnected: true, filePath: "capture.pcapng", totalPackets: 3, captureRevision: 1 };

    await trafficStatsPreloadContract.prefetch(input, new AbortController().signal);
    const { result } = renderHook(() => useTrafficGraph({ ...input, isPreloadingCapture: false }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.stats).toEqual(stats);
    expect(backendClients.analysis.getGlobalTrafficStats).toHaveBeenCalledTimes(1);
    expect(backendClients.packet.listPackets).not.toHaveBeenCalled();
  });

  it("does not fall back to listPackets from background prefetch", async () => {
    vi.mocked(backendClients.analysis.getGlobalTrafficStats).mockRejectedValue(new Error("boom"));

    await expect(
      trafficStatsPreloadContract.prefetch(
        { backendConnected: true, filePath: "capture.pcapng", totalPackets: 3, captureRevision: 1 },
        new AbortController().signal,
      ),
    ).rejects.toThrow("boom");

    expect(backendClients.packet.listPackets).not.toHaveBeenCalled();
  });
});
