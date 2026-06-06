import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { backendClients } from "../../integrations/backendClients";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { evidencePreloadContract, resetEvidencePreloadForTest, useEvidence } from "./useEvidence";

vi.mock("../../integrations/backendClients", () => ({
  backendClients: {
    evidence: { getEvidenceWithFilter: vi.fn() },
  },
}));

const records: UnifiedEvidenceRecord[] = [
  {
    id: "hunt:1",
    module: "hunting",
    sourceType: "rule",
    summary: "hit",
    severity: "low",
    packetId: 1,
    confidenceLabel: "low",
    caveats: [],
    tags: ["hunting"],
  },
];

describe("evidence preload contract", () => {
  afterEach(() => {
    resetEvidencePreloadForTest();
    vi.mocked(backendClients.evidence.getEvidenceWithFilter).mockReset();
  });

  it("requires explicit modules for background prefetch", async () => {
    await expect(
      evidencePreloadContract.prefetch(
        { backendConnected: true, filePath: "capture.pcapng", totalPackets: 3, captureRevision: 1 },
        new AbortController().signal,
      ),
    ).rejects.toThrow("evidence preload requires explicit modules");

    expect(backendClients.evidence.getEvidenceWithFilter).not.toHaveBeenCalled();
  });

  it("prefetches hunting module and hook reuses cache for same key", async () => {
    vi.mocked(backendClients.evidence.getEvidenceWithFilter).mockResolvedValue(records);
    const input = {
      backendConnected: true,
      filePath: "capture.pcapng",
      totalPackets: 3,
      captureRevision: 1,
      modules: ["hunting"],
    };

    await evidencePreloadContract.prefetch(input, new AbortController().signal);
    const { result } = renderHook(() => useEvidence({ ...input, isPreloadingCapture: false }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.evidence).toEqual(records);
    expect(backendClients.evidence.getEvidenceWithFilter).toHaveBeenCalledTimes(1);
    expect(backendClients.evidence.getEvidenceWithFilter).toHaveBeenCalledWith(["hunting"], expect.anything());
  });
});
