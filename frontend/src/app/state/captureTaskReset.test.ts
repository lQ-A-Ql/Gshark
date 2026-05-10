import { describe, expect, it, vi } from "vitest";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { createStreamSwitchSequences } from "./streamSwitchSequence";
import { cancelFrontendCaptureTasks } from "./captureTaskReset";

describe("captureTaskReset", () => {
  it("invalidates capture tasks, bumps request sequences, clears prefetch state, and cancels scheduled loading", () => {
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const staleTask = captureTaskScopeRef.current.beginTask("packet-page");
    const packetPageSeqRef = { current: 4 };
    const threatAnalysisSeqRef = { current: 9 };
    const streamSwitchSequences = createStreamSwitchSequences();
    const httpPrefetchInFlight = new Set([1, 2]);
    const tcpPrefetchInFlight = new Set([3]);
    const udpPrefetchInFlight = new Set([4]);
    const loadMoreScheduledRef = { current: 42 };
    const clearScheduledLoadMore = vi.fn();
    const setIsPageLoading = vi.fn();
    const setPacketPageError = vi.fn();

    cancelFrontendCaptureTasks({
      captureTaskScopeRef,
      packetPageSeqRef,
      threatAnalysisSeqRef,
      streamSwitchSequences,
      httpPrefetchInFlight,
      tcpPrefetchInFlight,
      udpPrefetchInFlight,
      loadMoreScheduledRef,
      clearScheduledLoadMore,
      setIsPageLoading,
      setPacketPageError,
    });

    expect(staleTask.isCurrent()).toBe(false);
    expect(packetPageSeqRef.current).toBe(5);
    expect(threatAnalysisSeqRef.current).toBe(10);
    expect(streamSwitchSequences.HTTP).toBe(1);
    expect(streamSwitchSequences.TCP).toBe(1);
    expect(streamSwitchSequences.UDP).toBe(1);
    expect(httpPrefetchInFlight.size).toBe(0);
    expect(tcpPrefetchInFlight.size).toBe(0);
    expect(udpPrefetchInFlight.size).toBe(0);
    expect(clearScheduledLoadMore).toHaveBeenCalledWith(42);
    expect(loadMoreScheduledRef.current).toBeNull();
    expect(setIsPageLoading).toHaveBeenCalledWith(false);
    expect(setPacketPageError).toHaveBeenCalledWith("");
  });

  it("skips timer clearing when no load-more task is scheduled", () => {
    const loadMoreScheduledRef = { current: null };
    const clearScheduledLoadMore = vi.fn();

    cancelFrontendCaptureTasks({
      captureTaskScopeRef: { current: createCaptureTaskScope() },
      packetPageSeqRef: { current: 0 },
      threatAnalysisSeqRef: { current: 0 },
      streamSwitchSequences: createStreamSwitchSequences(),
      httpPrefetchInFlight: new Set(),
      tcpPrefetchInFlight: new Set(),
      udpPrefetchInFlight: new Set(),
      loadMoreScheduledRef,
      clearScheduledLoadMore,
      setIsPageLoading: vi.fn(),
      setPacketPageError: vi.fn(),
    });

    expect(clearScheduledLoadMore).not.toHaveBeenCalled();
    expect(loadMoreScheduledRef.current).toBeNull();
  });
});
