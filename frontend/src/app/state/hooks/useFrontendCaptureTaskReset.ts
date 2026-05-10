import { useCallback } from "react";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { cancelFrontendCaptureTasks } from "../captureTaskReset";
import type { StreamSwitchSequences } from "../streamSwitchSequence";

type Ref<T> = { current: T };

type UseFrontendCaptureTaskResetOptions = {
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly packetPageSeqRef: Ref<number>;
  readonly threatAnalysisSeqRef: Ref<number>;
  readonly streamSwitchSequencesRef: Ref<StreamSwitchSequences>;
  readonly httpPrefetchInFlightRef: Ref<Set<number>>;
  readonly tcpPrefetchInFlightRef: Ref<Set<number>>;
  readonly udpPrefetchInFlightRef: Ref<Set<number>>;
  readonly loadMoreScheduledRef: Ref<number | null>;
  readonly clearScheduledLoadMore?: (handle: number) => void;
  readonly setIsPageLoading: (value: boolean) => void;
  readonly setPacketPageError: (value: string) => void;
};

export function useFrontendCaptureTaskReset({
  captureTaskScopeRef,
  packetPageSeqRef,
  threatAnalysisSeqRef,
  streamSwitchSequencesRef,
  httpPrefetchInFlightRef,
  tcpPrefetchInFlightRef,
  udpPrefetchInFlightRef,
  loadMoreScheduledRef,
  clearScheduledLoadMore = window.clearTimeout,
  setIsPageLoading,
  setPacketPageError,
}: UseFrontendCaptureTaskResetOptions) {
  return useCallback(() => {
    cancelFrontendCaptureTasks({
      captureTaskScopeRef,
      packetPageSeqRef,
      threatAnalysisSeqRef,
      streamSwitchSequences: streamSwitchSequencesRef.current,
      httpPrefetchInFlight: httpPrefetchInFlightRef.current,
      tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
      udpPrefetchInFlight: udpPrefetchInFlightRef.current,
      loadMoreScheduledRef,
      clearScheduledLoadMore,
      setIsPageLoading,
      setPacketPageError,
    });
  }, [
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
  ]);
}
