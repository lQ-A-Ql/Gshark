import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../core/types";
import { createClosedCaptureFileMeta, type CaptureFileMeta } from "./captureOpenState";
import { resetPreloadCounterState, resetPacketViewportState } from "./captureResetState";
import { createIdleCaptureTransactionStatus } from "./captureTransactionStatus";
import { resetStreamRuntimeRefs, type StreamSwitchDurations, type StreamSwitchHits } from "./streamRuntimeReset";
import {
  EMPTY_BINARY_STREAM,
  EMPTY_HTTP_STREAM,
  EMPTY_SWITCH_METRICS,
  createEmptyStreamIds,
  createEmptyUdpStream,
  type StreamIds,
} from "./streamState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface CaptureClearStateOptions {
  readonly pageStartRef: Ref<number>;
  readonly hasMorePacketsRef: Ref<boolean>;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly activeCapturePathRef: Ref<string>;
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly httpPrefetchInFlight: Set<number>;
  readonly tcpPrefetchInFlight: Set<number>;
  readonly udpPrefetchInFlight: Set<number>;
  readonly switchDurationsRef: Ref<StreamSwitchDurations>;
  readonly switchHitsRef: Ref<StreamSwitchHits>;
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
  readonly setCaptureTransaction: Setter<ReturnType<typeof createIdleCaptureTransactionStatus>>;
  readonly setCaptureRevision: Setter<number>;
}

export function clearCaptureUiStateData({
  pageStartRef,
  hasMorePacketsRef,
  preloadProcessedRef,
  preloadTotalRef,
  activeCapturePathRef,
  httpCache,
  tcpCache,
  udpCache,
  httpPrefetchInFlight,
  tcpPrefetchInFlight,
  udpPrefetchInFlight,
  switchDurationsRef,
  switchHitsRef,
  setPackets,
  setTotalPackets,
  setPageStart,
  setHasPrevPackets,
  setHasMorePackets,
  setSelectedPacketId,
  setSelectedPacketDetail,
  setSelectedPacketRawHex,
  setSelectedPacketLayers,
  setPreloadProcessed,
  setPreloadTotal,
  resetAnalysisState,
  setHttpStream,
  setTcpStream,
  setUdpStream,
  setStreamIds,
  setStreamSwitchMetrics,
  setFileMeta,
  setPacketPageError,
  setCaptureTransaction,
  setCaptureRevision,
}: CaptureClearStateOptions): void {
  resetPacketViewportState({
    pageStartRef,
    hasMorePacketsRef,
    setPackets,
    setTotalPackets,
    setPageStart,
    setHasPrevPackets,
    setHasMorePackets,
    setSelectedPacketId,
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
  });
  resetPreloadCounterState({
    preloadProcessedRef,
    preloadTotalRef,
    setPreloadProcessed,
    setPreloadTotal,
  });
  resetAnalysisState();
  setHttpStream(EMPTY_HTTP_STREAM);
  setTcpStream(EMPTY_BINARY_STREAM);
  setUdpStream(createEmptyUdpStream());
  setStreamIds(createEmptyStreamIds());
  resetStreamRuntimeRefs({
    httpCache,
    tcpCache,
    udpCache,
    httpPrefetchInFlight,
    tcpPrefetchInFlight,
    udpPrefetchInFlight,
    switchDurationsRef,
    switchHitsRef,
  });
  setStreamSwitchMetrics(EMPTY_SWITCH_METRICS);
  setFileMeta(createClosedCaptureFileMeta());
  setPacketPageError("");
  setCaptureTransaction(createIdleCaptureTransactionStatus(false));
  activeCapturePathRef.current = "";
  setCaptureRevision((prev) => prev + 1);
}
