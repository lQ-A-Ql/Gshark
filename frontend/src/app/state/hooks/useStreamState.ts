import { useRef, useState, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { BinaryStream, HttpStream, StreamProtocol } from "../../core/types";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { STREAM_PREFETCH_LIMIT } from "../captureConstants";
import { EMPTY_BINARY_STREAM, EMPTY_HTTP_STREAM, createEmptyStreamIds, createEmptyUdpStream } from "../streamState";
import { createStreamSwitchSequences } from "../streamSwitchSequence";
import { useActiveStreamSwitch } from "./useActiveStreamSwitch";
import { useStreamAdjacentPrefetch } from "./useStreamAdjacentPrefetch";
import { useStreamIndexRefresh } from "./useStreamIndexRefresh";
import { useStreamPayloadPersistence } from "./useStreamPayloadPersistence";
import { useStreamSwitchMetrics } from "./useStreamSwitchMetrics";

type RawStreamProtocol = "TCP" | "UDP";

interface UseStreamStateOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly fetchHttpStream: (streamId: number, signal: AbortSignal) => Promise<HttpStream>;
  readonly fetchRawStreamPage: (
    protocol: RawStreamProtocol,
    streamId: number,
    cursor: number,
    limit: number,
    signal: AbortSignal,
  ) => Promise<BinaryStream>;
  readonly listStreamIds: (protocol: StreamProtocol, signal: AbortSignal) => Promise<number[]>;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly updateStreamPayloads: (
    protocol: StreamProtocol,
    streamId: number,
    patches: Array<{ index: number; body: string }>,
  ) => Promise<unknown>;
}

export function useStreamState({
  activeCapturePathRef,
  backendConnected,
  captureTaskScopeRef,
  fetchHttpStream,
  fetchRawStreamPage,
  listStreamIds,
  setBackendStatus,
  updateStreamPayloads,
}: UseStreamStateOptions) {
  const [httpStream, setHttpStream] = useState<HttpStream>(EMPTY_HTTP_STREAM);
  const [tcpStream, setTcpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
  const [udpStream, setUdpStream] = useState<BinaryStream>(createEmptyUdpStream);
  const [streamIds, setStreamIds] = useState(createEmptyStreamIds);

  const httpStreamCacheRef = useRef<Map<number, HttpStream>>(new Map());
  const tcpStreamCacheRef = useRef<Map<number, BinaryStream>>(new Map());
  const udpStreamCacheRef = useRef<Map<number, BinaryStream>>(new Map());
  const httpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const tcpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const udpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const streamSwitchSequencesRef = useRef(createStreamSwitchSequences());
  const {
    streamSwitchMetrics,
    setStreamSwitchMetrics,
    streamSwitchDurationsRef,
    streamSwitchHitsRef,
    recordStreamSwitchMetric,
  } = useStreamSwitchMetrics();

  const refreshStreamIndex = useStreamIndexRefresh({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    listStreamIds,
    setBackendStatus,
    setStreamIds,
  });

  const prefetchAdjacentStreams = useStreamAdjacentPrefetch({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream,
    fetchRawStreamPage,
    httpCacheRef: httpStreamCacheRef,
    httpPrefetchInFlightRef,
    prefetchLimit: STREAM_PREFETCH_LIMIT,
    streamIds,
    tcpCacheRef: tcpStreamCacheRef,
    tcpPrefetchInFlightRef,
    udpCacheRef: udpStreamCacheRef,
    udpPrefetchInFlightRef,
  });

  const setActiveStream = useActiveStreamSwitch({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream,
    fetchRawStreamPage,
    httpCacheRef: httpStreamCacheRef,
    prefetchAdjacentStreams,
    recordStreamSwitchMetric,
    setBackendStatus,
    setHttpStream,
    setTcpStream,
    setUdpStream,
    streamSwitchSequencesRef,
    tcpCacheRef: tcpStreamCacheRef,
    udpCacheRef: udpStreamCacheRef,
  });

  const persistStreamPayloads = useStreamPayloadPersistence({
    backendConnected,
    httpCacheRef: httpStreamCacheRef,
    setHttpStream,
    setTcpStream,
    setUdpStream,
    tcpCacheRef: tcpStreamCacheRef,
    udpCacheRef: udpStreamCacheRef,
    updateStreamPayloads,
  });

  return {
    httpStream,
    setHttpStream,
    tcpStream,
    setTcpStream,
    udpStream,
    setUdpStream,
    streamIds,
    setStreamIds,
    httpStreamCacheRef,
    tcpStreamCacheRef,
    udpStreamCacheRef,
    httpPrefetchInFlightRef,
    tcpPrefetchInFlightRef,
    udpPrefetchInFlightRef,
    streamSwitchSequencesRef,
    streamSwitchMetrics,
    setStreamSwitchMetrics,
    streamSwitchDurationsRef,
    streamSwitchHitsRef,
    refreshStreamIndex,
    setActiveStream,
    persistStreamPayloads,
  };
}
