import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { resetStreamSwitchSequences, type StreamSwitchSequences } from "./streamSwitchSequence";

export type StreamSwitchSampleBucket = "ALL" | StreamProtocol;
export type StreamSwitchDurations = Record<StreamSwitchSampleBucket, number[]>;
export type StreamSwitchHits = Record<StreamSwitchSampleBucket, number>;

interface StreamRuntimeRefs {
  readonly httpCache: Map<number, HttpStream>;
  readonly tcpCache: Map<number, BinaryStream>;
  readonly udpCache: Map<number, BinaryStream>;
  readonly httpPrefetchInFlight: Set<number>;
  readonly tcpPrefetchInFlight: Set<number>;
  readonly udpPrefetchInFlight: Set<number>;
  readonly switchDurationsRef: { current: StreamSwitchDurations };
  readonly switchHitsRef: { current: StreamSwitchHits };
  readonly switchSequences?: StreamSwitchSequences;
}

export function createEmptyStreamSwitchDurations(): StreamSwitchDurations {
  return {
    ALL: [],
    HTTP: [],
    TCP: [],
    UDP: [],
  };
}

export function createEmptyStreamSwitchHits(): StreamSwitchHits {
  return {
    ALL: 0,
    HTTP: 0,
    TCP: 0,
    UDP: 0,
  };
}

export function clearStreamPrefetchInFlight({
  httpPrefetchInFlight,
  tcpPrefetchInFlight,
  udpPrefetchInFlight,
}: Pick<StreamRuntimeRefs, "httpPrefetchInFlight" | "tcpPrefetchInFlight" | "udpPrefetchInFlight">): void {
  httpPrefetchInFlight.clear();
  tcpPrefetchInFlight.clear();
  udpPrefetchInFlight.clear();
}

export function resetStreamRuntimeRefs({
  httpCache,
  tcpCache,
  udpCache,
  switchSequences,
  switchDurationsRef,
  switchHitsRef,
  ...prefetchRefs
}: StreamRuntimeRefs): void {
  httpCache.clear();
  tcpCache.clear();
  udpCache.clear();
  clearStreamPrefetchInFlight(prefetchRefs);
  if (switchSequences) {
    resetStreamSwitchSequences(switchSequences);
  }
  switchDurationsRef.current = createEmptyStreamSwitchDurations();
  switchHitsRef.current = createEmptyStreamSwitchHits();
}
