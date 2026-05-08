import type { StreamProtocol, StreamSwitchMetrics } from "../core/types";
import { SWITCH_SAMPLE_LIMIT, buildSwitchStat } from "./streamState";
import type { StreamSwitchDurations, StreamSwitchHits } from "./streamRuntimeReset";

interface StreamSwitchMetricRefs {
  readonly switchDurationsRef: { current: StreamSwitchDurations };
  readonly switchHitsRef: { current: StreamSwitchHits };
}

interface RecordStreamSwitchMetricInput extends StreamSwitchMetricRefs {
  readonly protocol: StreamProtocol;
  readonly elapsedMs: number;
  readonly cacheHit: boolean;
}

export function recordStreamSwitchMetricSample({
  protocol,
  elapsedMs,
  cacheHit,
  switchDurationsRef,
  switchHitsRef,
}: RecordStreamSwitchMetricInput): StreamSwitchMetrics {
  const elapsed = Number.isFinite(elapsedMs) ? Math.max(0, elapsedMs) : 0;

  appendSwitchMetricSample("ALL", elapsed, cacheHit, switchDurationsRef.current, switchHitsRef.current);
  appendSwitchMetricSample(protocol, elapsed, cacheHit, switchDurationsRef.current, switchHitsRef.current);

  return buildStreamSwitchMetrics(switchDurationsRef.current, switchHitsRef.current);
}

export function buildStreamSwitchMetrics(
  durations: StreamSwitchDurations,
  hits: StreamSwitchHits,
): StreamSwitchMetrics {
  return {
    overall: buildSwitchStat(durations.ALL, hits.ALL),
    byProtocol: {
      HTTP: buildSwitchStat(durations.HTTP, hits.HTTP),
      TCP: buildSwitchStat(durations.TCP, hits.TCP),
      UDP: buildSwitchStat(durations.UDP, hits.UDP),
    },
  };
}

function appendSwitchMetricSample(
  bucket: "ALL" | StreamProtocol,
  elapsed: number,
  cacheHit: boolean,
  durations: StreamSwitchDurations,
  hits: StreamSwitchHits,
): void {
  const samples = durations[bucket];
  samples.push(elapsed);
  if (samples.length > SWITCH_SAMPLE_LIMIT) {
    samples.splice(0, samples.length - SWITCH_SAMPLE_LIMIT);
  }
  if (cacheHit) {
    hits[bucket] += 1;
  }
}
