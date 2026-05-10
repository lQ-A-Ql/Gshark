import { useCallback, type MutableRefObject } from "react";
import type { BinaryStream, HttpStream, StreamProtocol } from "../../core/types";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { RAW_STREAM_PAGE_SIZE } from "../captureConstants";
import { prefetchAdjacentStreamsState } from "../streamAdjacentPrefetch";
import type { StreamIds } from "../streamState";

interface UseStreamAdjacentPrefetchOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly fetchHttpStream: (streamId: number, signal: AbortSignal) => Promise<HttpStream>;
  readonly fetchRawStreamPage: (
    protocol: "TCP" | "UDP",
    streamId: number,
    cursor: number,
    limit: number,
    signal: AbortSignal,
  ) => Promise<BinaryStream>;
  readonly httpCacheRef: MutableRefObject<Map<number, HttpStream>>;
  readonly httpPrefetchInFlightRef: MutableRefObject<Set<number>>;
  readonly prefetchLimit: number;
  readonly streamIds: StreamIds;
  readonly tcpCacheRef: MutableRefObject<Map<number, BinaryStream>>;
  readonly tcpPrefetchInFlightRef: MutableRefObject<Set<number>>;
  readonly udpCacheRef: MutableRefObject<Map<number, BinaryStream>>;
  readonly udpPrefetchInFlightRef: MutableRefObject<Set<number>>;
}

export function useStreamAdjacentPrefetch(options: UseStreamAdjacentPrefetchOptions) {
  const {
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream,
    fetchRawStreamPage,
    httpCacheRef,
    httpPrefetchInFlightRef,
    prefetchLimit,
    streamIds,
    tcpCacheRef,
    tcpPrefetchInFlightRef,
    udpCacheRef,
    udpPrefetchInFlightRef,
  } = options;

  return useCallback(
    (protocol: StreamProtocol, currentStreamId: number): number =>
      prefetchAdjacentStreamsState({
        backendConnected,
        activeCapturePath: activeCapturePathRef.current,
        protocol,
        currentStreamId,
        limit: prefetchLimit,
        streamIds,
        httpCache: httpCacheRef.current,
        tcpCache: tcpCacheRef.current,
        udpCache: udpCacheRef.current,
        httpInFlight: httpPrefetchInFlightRef.current,
        tcpInFlight: tcpPrefetchInFlightRef.current,
        udpInFlight: udpPrefetchInFlightRef.current,
        beginTask: captureTaskScopeRef.current.beginTask,
        fetchHttpStream,
        fetchRawTcpStream: (id, signal) => fetchRawStreamPage("TCP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        fetchRawUdpStream: (id, signal) => fetchRawStreamPage("UDP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
      }),
    [
      activeCapturePathRef,
      backendConnected,
      captureTaskScopeRef,
      fetchHttpStream,
      fetchRawStreamPage,
      httpCacheRef,
      httpPrefetchInFlightRef,
      prefetchLimit,
      streamIds,
      tcpCacheRef,
      tcpPrefetchInFlightRef,
      udpCacheRef,
      udpPrefetchInFlightRef,
    ],
  );
}
