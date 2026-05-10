import { useCallback, useRef, useState, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import type { StreamProtocol, StreamSwitchMetrics } from "../../core/types";
import { EMPTY_SWITCH_METRICS } from "../streamState";
import {
  createEmptyStreamSwitchDurations,
  createEmptyStreamSwitchHits,
  type StreamSwitchDurations,
  type StreamSwitchHits,
} from "../streamRuntimeReset";
import { recordStreamSwitchMetricSample } from "../streamSwitchMetrics";

export function useStreamSwitchMetrics(): {
  streamSwitchMetrics: StreamSwitchMetrics;
  setStreamSwitchMetrics: Dispatch<SetStateAction<StreamSwitchMetrics>>;
  streamSwitchDurationsRef: MutableRefObject<StreamSwitchDurations>;
  streamSwitchHitsRef: MutableRefObject<StreamSwitchHits>;
  recordStreamSwitchMetric: (protocol: StreamProtocol, elapsedMs: number, cacheHit: boolean) => void;
} {
  const [streamSwitchMetrics, setStreamSwitchMetrics] = useState<StreamSwitchMetrics>(EMPTY_SWITCH_METRICS);
  const streamSwitchDurationsRef = useRef(createEmptyStreamSwitchDurations());
  const streamSwitchHitsRef = useRef(createEmptyStreamSwitchHits());

  const recordStreamSwitchMetric = useCallback((protocol: StreamProtocol, elapsedMs: number, cacheHit: boolean) => {
    setStreamSwitchMetrics(
      recordStreamSwitchMetricSample({
        protocol,
        elapsedMs,
        cacheHit,
        switchDurationsRef: streamSwitchDurationsRef,
        switchHitsRef: streamSwitchHitsRef,
      }),
    );
  }, []);

  return {
    streamSwitchMetrics,
    setStreamSwitchMetrics,
    streamSwitchDurationsRef,
    streamSwitchHitsRef,
    recordStreamSwitchMetric,
  };
}
