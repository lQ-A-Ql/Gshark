import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { CaptureScopedTask } from "../../utils/captureTaskScope";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { createStreamSwitchSequences } from "../streamSwitchSequence";
import { useFrontendCaptureTaskReset } from "./useFrontendCaptureTaskReset";

describe("useFrontendCaptureTaskReset", () => {
  it("wires capture task reset refs and clears page loading state", () => {
    const clearScheduledLoadMore = vi.fn();
    const { result } = renderHook(() => {
      const captureTaskScopeRef = useRef(createCaptureTaskScope());
      const staleTaskRef = useRef<CaptureScopedTask | null>(null);
      staleTaskRef.current ??= captureTaskScopeRef.current.beginTask("packet-page");
      const packetPageSeqRef = useRef(2);
      const threatAnalysisSeqRef = useRef(7);
      const streamSwitchSequencesRef = useRef(createStreamSwitchSequences());
      const httpPrefetchInFlightRef = useRef(new Set([1]));
      const tcpPrefetchInFlightRef = useRef(new Set([2]));
      const udpPrefetchInFlightRef = useRef(new Set([3]));
      const loadMoreScheduledRef = useRef<number | null>(99);
      const [isPageLoading, setIsPageLoading] = useState(true);
      const [packetPageError, setPacketPageError] = useState("stale error");
      const resetFrontendCaptureTasks = useFrontendCaptureTaskReset({
        captureTaskScopeRef,
        packetPageSeqRef,
        threatAnalysisSeqRef,
        streamSwitchSequencesRef,
        httpPrefetchInFlightRef,
        tcpPrefetchInFlightRef,
        udpPrefetchInFlightRef,
        loadMoreScheduledRef,
        clearScheduledLoadMore,
        setIsPageLoading,
        setPacketPageError,
      });
      return {
        resetFrontendCaptureTasks,
        staleTask: staleTaskRef.current,
        packetPageSeqRef,
        threatAnalysisSeqRef,
        streamSwitchSequencesRef,
        httpPrefetchInFlightRef,
        tcpPrefetchInFlightRef,
        udpPrefetchInFlightRef,
        loadMoreScheduledRef,
        isPageLoading,
        packetPageError,
      };
    });

    act(() => result.current.resetFrontendCaptureTasks());

    expect(result.current.staleTask.isCurrent()).toBe(false);
    expect(result.current.packetPageSeqRef.current).toBe(3);
    expect(result.current.threatAnalysisSeqRef.current).toBe(8);
    expect(result.current.streamSwitchSequencesRef.current.HTTP).toBe(1);
    expect(result.current.httpPrefetchInFlightRef.current.size).toBe(0);
    expect(result.current.tcpPrefetchInFlightRef.current.size).toBe(0);
    expect(result.current.udpPrefetchInFlightRef.current.size).toBe(0);
    expect(clearScheduledLoadMore).toHaveBeenCalledWith(99);
    expect(result.current.loadMoreScheduledRef.current).toBeNull();
    expect(result.current.isPageLoading).toBe(false);
    expect(result.current.packetPageError).toBe("");
  });
});
