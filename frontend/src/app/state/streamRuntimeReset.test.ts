import { describe, expect, it } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import {
  clearStreamPrefetchInFlight,
  createEmptyStreamSwitchDurations,
  createEmptyStreamSwitchHits,
  resetStreamRuntimeRefs,
} from "./streamRuntimeReset";
import { createStreamSwitchSequences } from "./streamSwitchSequence";

function createHttpStream(id: number): HttpStream {
  return {
    id,
    client: "",
    server: "",
    request: "",
    response: "",
    chunks: [],
  };
}

function createBinaryStream(id: number, protocol: "TCP" | "UDP"): BinaryStream {
  return {
    id,
    protocol,
    from: "",
    to: "",
    chunks: [],
  };
}

describe("streamRuntimeReset", () => {
  it("creates fresh switch sample buckets", () => {
    const durations = createEmptyStreamSwitchDurations();
    const hits = createEmptyStreamSwitchHits();

    expect(durations).toEqual({ ALL: [], HTTP: [], TCP: [], UDP: [] });
    expect(hits).toEqual({ ALL: 0, HTTP: 0, TCP: 0, UDP: 0 });
    expect(durations.HTTP).not.toBe(createEmptyStreamSwitchDurations().HTTP);
  });

  it("clears prefetch in-flight sets without touching caches", () => {
    const httpPrefetchInFlight = new Set([1]);
    const tcpPrefetchInFlight = new Set([2]);
    const udpPrefetchInFlight = new Set([3]);

    clearStreamPrefetchInFlight({
      httpPrefetchInFlight,
      tcpPrefetchInFlight,
      udpPrefetchInFlight,
    });

    expect(httpPrefetchInFlight.size).toBe(0);
    expect(tcpPrefetchInFlight.size).toBe(0);
    expect(udpPrefetchInFlight.size).toBe(0);
  });

  it("resets stream caches, prefetch sets, switch sequences, and metrics samples", () => {
    const sequences = createStreamSwitchSequences();
    sequences.HTTP = 7;
    sequences.TCP = 8;
    sequences.UDP = 9;
    const switchDurationsRef = { current: { ALL: [1], HTTP: [2], TCP: [3], UDP: [4] } };
    const switchHitsRef = { current: { ALL: 4, HTTP: 1, TCP: 2, UDP: 3 } };
    const httpCache = new Map<number, HttpStream>([[1, createHttpStream(1)]]);
    const tcpCache = new Map<number, BinaryStream>([[2, createBinaryStream(2, "TCP")]]);
    const udpCache = new Map<number, BinaryStream>([[3, createBinaryStream(3, "UDP")]]);
    const httpPrefetchInFlight = new Set([1]);
    const tcpPrefetchInFlight = new Set([2]);
    const udpPrefetchInFlight = new Set([3]);

    resetStreamRuntimeRefs({
      httpCache,
      tcpCache,
      udpCache,
      httpPrefetchInFlight,
      tcpPrefetchInFlight,
      udpPrefetchInFlight,
      switchSequences: sequences,
      switchDurationsRef,
      switchHitsRef,
    });

    expect(httpCache.size).toBe(0);
    expect(tcpCache.size).toBe(0);
    expect(udpCache.size).toBe(0);
    expect(httpPrefetchInFlight.size).toBe(0);
    expect(tcpPrefetchInFlight.size).toBe(0);
    expect(udpPrefetchInFlight.size).toBe(0);
    expect(sequences).toEqual({ HTTP: 0, TCP: 0, UDP: 0 });
    expect(switchDurationsRef.current).toEqual({ ALL: [], HTTP: [], TCP: [], UDP: [] });
    expect(switchHitsRef.current).toEqual({ ALL: 0, HTTP: 0, TCP: 0, UDP: 0 });
  });
});
