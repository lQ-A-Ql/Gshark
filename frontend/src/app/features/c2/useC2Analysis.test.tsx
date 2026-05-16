import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useC2Analysis } from "./useC2Analysis";

vi.mock("../../integrations/backendClients", () => ({
  backendClients: {
    analysis: {
      getC2SampleAnalysis: vi.fn(),
    },
  },
}));

import { backendClients } from "../../integrations/backendClients";

describe("useC2Analysis", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("leaves loading state when an HTTP data-plane request times out", async () => {
    vi.mocked(backendClients.analysis.getC2SampleAnalysis).mockRejectedValueOnce(
      new Error("后端请求超时（30000ms）：/api/c2-analysis。后端可能正在计算或端口被旧实例占用。"),
    );

    const { result } = renderHook(() =>
      useC2Analysis({
        backendConnected: true,
        isPreloadingCapture: false,
        filePath: "sample.pcapng",
        totalPackets: 42,
        captureRevision: 991,
      }),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.error).toContain("后端请求超时");
    expect(backendClients.analysis.getC2SampleAnalysis).toHaveBeenCalledTimes(1);
  });
});
