import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { PacketsPageResult } from "../../integrations/clients/captureClient";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { usePacketPageLoad } from "./usePacketPageLoad";

function page(): PacketsPageResult {
  return { items: [], nextCursor: 100, total: 1, hasMore: false };
}

describe("usePacketPageLoad", () => {
  it("loads packet pages through the pure page load workflow", async () => {
    const commitPacketPage = vi.fn();
    const listPacketsPage = vi.fn(async () => page());
    const { result } = renderHook(() => {
      const activeCapturePathRef = useRef("sample.pcapng");
      const captureTaskScopeRef = useRef(createCaptureTaskScope());
      const packetPageSeqRef = useRef(0);
      const [backendStatus, setBackendStatus] = useState("");
      const [isFilterLoading, setIsFilterLoading] = useState(true);
      const [isPageLoading, setIsPageLoading] = useState(false);
      const [packetPageError, setPacketPageError] = useState("");
      const loadPacketPage = usePacketPageLoad({
        activeCapturePathRef,
        backendConnected: true,
        captureTaskScopeRef,
        commitPacketPage,
        displayFilter: "tcp",
        listPacketsPage,
        packetPageSeqRef,
        pageSize: 100,
        setBackendStatus,
        setIsFilterLoading,
        setIsPageLoading,
        setPacketPageError,
      });
      return { backendStatus, isFilterLoading, isPageLoading, loadPacketPage, packetPageError };
    });

    await act(async () => {
      await result.current.loadPacketPage(12.8, "udp", { finishFilterLoading: true });
    });

    expect(listPacketsPage).toHaveBeenCalledWith(12, 100, "udp", expect.any(AbortSignal));
    expect(commitPacketPage).toHaveBeenCalledWith(12, page());
    expect(result.current.isPageLoading).toBe(false);
    expect(result.current.isFilterLoading).toBe(false);
    expect(result.current.packetPageError).toBe("");
    expect(result.current.backendStatus).toBe("");
  });
});
