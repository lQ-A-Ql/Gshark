import { act, renderHook, waitFor } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { PacketsPageResult } from "../../integrations/clients/captureClient";
import { useDisplayFilterWorkflow } from "./useDisplayFilterWorkflow";

function createPage(): PacketsPageResult {
  return { items: [], nextCursor: 0, total: 0, hasMore: false, filtering: false };
}

describe("useDisplayFilterWorkflow", () => {
  it("applies explicit filters and clears filters through packet filter action", async () => {
    const loadPacketPage = vi.fn(async () => createPage());
    const resetPacketViewport = vi.fn();
    const setBackendStatus = vi.fn();
    const { result } = renderHook(() => {
      const activeCapturePathRef = useRef("C:/capture.pcap");
      const filterSeqRef = useRef(0);
      const [displayFilter, setDisplayFilter] = useState("tcp.port == 80");
      const [isFilterLoading, setIsFilterLoading] = useState(false);
      const [packetPageError, setPacketPageError] = useState("");
      const workflow = useDisplayFilterWorkflow({
        activeCapturePathRef,
        backendConnected: true,
        displayFilter,
        isPreloadingCapture: false,
        filterSeqRef,
        loadPacketPage,
        resetPacketViewport,
        setDisplayFilter,
        setIsFilterLoading,
        setPacketPageError,
        setBackendStatus,
      });
      return { ...workflow, displayFilter, filterSeqRef, isFilterLoading, packetPageError };
    });

    act(() => result.current.applyFilter("http.request"));

    await waitFor(() => expect(loadPacketPage).toHaveBeenCalledWith(0, "http.request"));
    expect(result.current.displayFilter).toBe("http.request");
    expect(result.current.filterSeqRef.current).toBe(1);
    expect(resetPacketViewport).toHaveBeenCalledTimes(1);

    act(() => result.current.clearFilter());

    await waitFor(() => expect(loadPacketPage).toHaveBeenLastCalledWith(0, ""));
    expect(result.current.displayFilter).toBe("");
    expect(result.current.filterSeqRef.current).toBe(2);
    expect(result.current.isFilterLoading).toBe(false);
    expect(result.current.packetPageError).toBe("");
  });

  it("keeps display filter local and skips backend work when no capture is active", async () => {
    const loadPacketPage = vi.fn(async () => createPage());
    const { result } = renderHook(() => {
      const activeCapturePathRef = useRef("");
      const filterSeqRef = useRef(0);
      const [displayFilter, setDisplayFilter] = useState("tcp.port == 80");
      return {
        ...useDisplayFilterWorkflow({
          activeCapturePathRef,
          backendConnected: true,
          displayFilter,
          isPreloadingCapture: false,
          filterSeqRef,
          loadPacketPage,
          resetPacketViewport: vi.fn(),
          setDisplayFilter,
          setIsFilterLoading: vi.fn(),
          setPacketPageError: vi.fn(),
          setBackendStatus: vi.fn(),
        }),
        displayFilter,
        filterSeqRef,
      };
    });

    act(() => result.current.applyFilter("udp"));

    await waitFor(() => expect(result.current.displayFilter).toBe("udp"));
    expect(result.current.filterSeqRef.current).toBe(0);
    expect(loadPacketPage).not.toHaveBeenCalled();
  });
});
