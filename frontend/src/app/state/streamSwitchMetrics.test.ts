import { describe, expect, it } from "vitest";
import {
  createEmptyStreamSwitchDurations,
  createEmptyStreamSwitchHits,
  type StreamSwitchDurations,
  type StreamSwitchHits,
} from "./streamRuntimeReset";
import { recordStreamSwitchMetricSample } from "./streamSwitchMetrics";
import { SWITCH_SAMPLE_LIMIT } from "./streamState";

function createRefs(durations?: StreamSwitchDurations, hits?: StreamSwitchHits) {
  return {
    switchDurationsRef: { current: durations ?? createEmptyStreamSwitchDurations() },
    switchHitsRef: { current: hits ?? createEmptyStreamSwitchHits() },
  };
}

describe("streamSwitchMetrics", () => {
  it("records samples into the overall and protocol buckets", () => {
    const refs = createRefs();

    const metrics = recordStreamSwitchMetricSample({
      protocol: "TCP",
      elapsedMs: 12.34,
      cacheHit: true,
      ...refs,
    });

    expect(refs.switchDurationsRef.current.ALL).toEqual([12.34]);
    expect(refs.switchDurationsRef.current.TCP).toEqual([12.34]);
    expect(refs.switchDurationsRef.current.HTTP).toEqual([]);
    expect(refs.switchHitsRef.current.ALL).toBe(1);
    expect(refs.switchHitsRef.current.TCP).toBe(1);
    expect(metrics.overall).toMatchObject({ count: 1, lastMs: 12.3, cacheHitRate: 100 });
    expect(metrics.byProtocol.TCP).toMatchObject({ count: 1, lastMs: 12.3, cacheHitRate: 100 });
    expect(metrics.byProtocol.HTTP.count).toBe(0);
  });

  it("normalizes invalid elapsed values to zero", () => {
    const refs = createRefs();

    const metrics = recordStreamSwitchMetricSample({
      protocol: "HTTP",
      elapsedMs: Number.NaN,
      cacheHit: false,
      ...refs,
    });

    expect(refs.switchDurationsRef.current.ALL).toEqual([0]);
    expect(refs.switchDurationsRef.current.HTTP).toEqual([0]);
    expect(metrics.overall).toMatchObject({ count: 1, lastMs: 0, cacheHitRate: 0 });
  });

  it("keeps only the latest bounded sample window", () => {
    const refs = createRefs();

    for (let index = 0; index < SWITCH_SAMPLE_LIMIT + 2; index += 1) {
      recordStreamSwitchMetricSample({
        protocol: "UDP",
        elapsedMs: index,
        cacheHit: index % 2 === 0,
        ...refs,
      });
    }

    expect(refs.switchDurationsRef.current.ALL).toHaveLength(SWITCH_SAMPLE_LIMIT);
    expect(refs.switchDurationsRef.current.UDP).toHaveLength(SWITCH_SAMPLE_LIMIT);
    expect(refs.switchDurationsRef.current.ALL[0]).toBe(2);
    expect(refs.switchDurationsRef.current.UDP[0]).toBe(2);
  });
});
