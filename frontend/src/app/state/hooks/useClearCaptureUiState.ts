import { useCallback, useRef } from "react";
import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../../core/types";
import { clearCaptureUiStateData } from "../captureClearState";
import type { CaptureFileMeta } from "../captureOpenState";
import type { CaptureTransactionStatus } from "../sentinelTypes";
import type { StreamSwitchDurations, StreamSwitchHits } from "../streamRuntimeReset";
import type { StreamIds } from "../streamState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

type UseClearCaptureUiStateOptions = {
  readonly pageStartRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly activeCapturePathRef: Ref<string>;
  readonly httpStreamCacheRef: Ref<Map<number, HttpStream>>;
  readonly tcpStreamCacheRef: Ref<Map<number, BinaryStream>>;
  readonly udpStreamCacheRef: Ref<Map<number, BinaryStream>>;
  readonly httpPrefetchInFlightRef: Ref<Set<number>>;
  readonly tcpPrefetchInFlightRef: Ref<Set<number>>;
  readonly udpPrefetchInFlightRef: Ref<Set<number>>;
  readonly streamSwitchDurationsRef: Ref<StreamSwitchDurations>;
  readonly streamSwitchHitsRef: Ref<StreamSwitchHits>;
  readonly setPackets: Setter<Packet[]>;
  readonly setTotalPackets: Setter<number>;
  readonly setPageStart: Setter<number>;
  readonly setHasPrevPackets: Setter<boolean>;
  readonly setHasMorePackets: Setter<boolean>;
  readonly setSelectedPacketId: Setter<number | null>;
  readonly setSelectedPacketDetail: Setter<Packet | null>;
  readonly setSelectedPacketRawHex: Setter<string>;
  readonly setSelectedPacketLayers: Setter<Record<string, unknown> | null>;
  readonly setPreloadProcessed: Setter<number>;
  readonly setPreloadTotal: Setter<number>;
  readonly resetAnalysisState: () => void;
  readonly setHttpStream: Setter<HttpStream>;
  readonly setTcpStream: Setter<BinaryStream>;
  readonly setUdpStream: Setter<BinaryStream>;
  readonly setStreamIds: Setter<StreamIds>;
  readonly setStreamSwitchMetrics: Setter<StreamSwitchMetrics>;
  readonly setFileMeta: Setter<CaptureFileMeta>;
  readonly setPacketPageError: Setter<string>;
  readonly setCaptureTransaction: Setter<CaptureTransactionStatus>;
  readonly setCaptureRevision: Setter<number>;
};

export function useClearCaptureUiState(options: UseClearCaptureUiStateOptions) {
  const optionsRef = useRef(options);
  optionsRef.current = options;

  return useCallback(() => {
    const {
      httpStreamCacheRef,
      tcpStreamCacheRef,
      udpStreamCacheRef,
      httpPrefetchInFlightRef,
      tcpPrefetchInFlightRef,
      udpPrefetchInFlightRef,
      streamSwitchDurationsRef,
      streamSwitchHitsRef,
      ...staticOptions
    } = optionsRef.current;

    clearCaptureUiStateData({
      ...staticOptions,
      switchDurationsRef: streamSwitchDurationsRef,
      switchHitsRef: streamSwitchHitsRef,
      httpCache: httpStreamCacheRef.current,
      tcpCache: tcpStreamCacheRef.current,
      udpCache: udpStreamCacheRef.current,
      httpPrefetchInFlight: httpPrefetchInFlightRef.current,
      tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
      udpPrefetchInFlight: udpPrefetchInFlightRef.current,
    });
  }, []);
}
