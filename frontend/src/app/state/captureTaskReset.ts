import type { CaptureTaskScope } from "../utils/captureTaskScope";
import { clearStreamPrefetchInFlight } from "./streamRuntimeReset";
import { bumpAllStreamSwitchSequences, type StreamSwitchSequences } from "./streamSwitchSequence";

type Ref<T> = { current: T };

interface CancelFrontendCaptureTasksOptions {
  readonly captureTaskScopeRef: Ref<CaptureTaskScope>;
  readonly packetPageSeqRef: Ref<number>;
  readonly threatAnalysisSeqRef: Ref<number>;
  readonly streamSwitchSequences: StreamSwitchSequences;
  readonly httpPrefetchInFlight: Set<number>;
  readonly tcpPrefetchInFlight: Set<number>;
  readonly udpPrefetchInFlight: Set<number>;
  readonly loadMoreScheduledRef: Ref<number | null>;
  readonly clearScheduledLoadMore: (handle: number) => void;
  readonly setIsPageLoading: (value: boolean) => void;
  readonly setPacketPageError: (value: string) => void;
}

export function cancelFrontendCaptureTasks({
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
}: CancelFrontendCaptureTasksOptions): void {
  captureTaskScopeRef.current.invalidate();
  packetPageSeqRef.current += 1;
  threatAnalysisSeqRef.current += 1;
  bumpAllStreamSwitchSequences(streamSwitchSequences);
  clearStreamPrefetchInFlight({
    httpPrefetchInFlight,
    tcpPrefetchInFlight,
    udpPrefetchInFlight,
  });
  if (loadMoreScheduledRef.current != null) {
    clearScheduledLoadMore(loadMoreScheduledRef.current);
    loadMoreScheduledRef.current = null;
  }
  setIsPageLoading(false);
  setPacketPageError("");
}
