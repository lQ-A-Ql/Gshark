import { startTransition, useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { BinaryStream, HttpStream, StreamProtocol } from "../../core/types";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { RAW_STREAM_PAGE_SIZE } from "../captureConstants";
import type { StreamSwitchSequences } from "../streamSwitchSequence";
import { setActiveStreamState } from "../streamSwitchWorkflow";

interface UseActiveStreamSwitchOptions {
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
  readonly prefetchAdjacentStreams: (protocol: StreamProtocol, currentStreamId: number) => void;
  readonly recordStreamSwitchMetric: (protocol: StreamProtocol, elapsedMs: number, cacheHit: boolean) => void;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setHttpStream: Dispatch<SetStateAction<HttpStream>>;
  readonly setTcpStream: Dispatch<SetStateAction<BinaryStream>>;
  readonly setUdpStream: Dispatch<SetStateAction<BinaryStream>>;
  readonly streamSwitchSequencesRef: MutableRefObject<StreamSwitchSequences>;
  readonly tcpCacheRef: MutableRefObject<Map<number, BinaryStream>>;
  readonly udpCacheRef: MutableRefObject<Map<number, BinaryStream>>;
}

export function useActiveStreamSwitch(options: UseActiveStreamSwitchOptions) {
  const {
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream,
    fetchRawStreamPage,
    httpCacheRef,
    prefetchAdjacentStreams,
    recordStreamSwitchMetric,
    setBackendStatus,
    setHttpStream,
    setTcpStream,
    setUdpStream,
    streamSwitchSequencesRef,
    tcpCacheRef,
    udpCacheRef,
  } = options;

  return useCallback(
    async (protocol: StreamProtocol, streamId: number): Promise<void> => {
      await setActiveStreamState({
        backendConnected,
        activeCapturePath: activeCapturePathRef.current,
        protocol,
        streamId,
        streamSwitchSequences: streamSwitchSequencesRef.current,
        captureTaskScope: captureTaskScopeRef.current,
        httpCache: httpCacheRef.current,
        tcpCache: tcpCacheRef.current,
        udpCache: udpCacheRef.current,
        applyHttpStream: (next) => startTransition(() => setHttpStream(next)),
        applyTcpStream: (next) => startTransition(() => setTcpStream(next)),
        applyUdpStream: (next) => startTransition(() => setUdpStream(next)),
        fetchHttpStream,
        fetchRawTcpStream: (id, signal) => fetchRawStreamPage("TCP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        fetchRawUdpStream: (id, signal) => fetchRawStreamPage("UDP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        recordMetric: recordStreamSwitchMetric,
        prefetchAdjacentStreams,
        setBackendStatus,
      });
    },
    [
      activeCapturePathRef,
      backendConnected,
      captureTaskScopeRef,
      fetchHttpStream,
      fetchRawStreamPage,
      httpCacheRef,
      prefetchAdjacentStreams,
      recordStreamSwitchMetric,
      setBackendStatus,
      setHttpStream,
      setTcpStream,
      setUdpStream,
      streamSwitchSequencesRef,
      tcpCacheRef,
      udpCacheRef,
    ],
  );
}
