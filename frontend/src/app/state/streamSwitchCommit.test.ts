import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream, StreamProtocol } from "../core/types";
import { commitLoadedStreamSwitch } from "./streamSwitchCommit";

function createHttpStream(id: number, cacheHit = false): HttpStream {
  return {
    id,
    client: "client",
    server: "server",
    request: "",
    response: "",
    chunks: [],
    loadMeta: cacheHit ? { source: "cache", cacheHit: true } : { source: "network" },
  };
}

function createTcpStream(id: number): BinaryStream {
  return {
    id,
    protocol: "TCP",
    from: "1.1.1.1",
    to: "2.2.2.2",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
    loadMeta: { source: "network" },
  };
}

describe("streamSwitchCommit helpers", () => {
  it("commits stream payload, metrics, and prefetch with requested stream id", () => {
    const stream = createTcpStream(17);
    const cache = new Map<number, BinaryStream>();
    const apply = vi.fn();
    const recordMetric = vi.fn();
    const prefetchAdjacentStreams = vi.fn();

    commitLoadedStreamSwitch({
      protocol: "TCP",
      requestedStreamId: 13,
      stream,
      cache,
      apply,
      startedAt: 100,
      now: () => 160,
      recordMetric,
      prefetchAdjacentStreams,
    });

    expect(cache.get(17)).toBe(stream);
    expect(apply).toHaveBeenCalledWith(stream);
    expect(recordMetric).toHaveBeenCalledWith("TCP", 60, false);
    expect(prefetchAdjacentStreams).toHaveBeenCalledWith("TCP", 13);
  });

  it("marks metric cacheHit when loadMeta reports a fast path", () => {
    const stream = createHttpStream(9, true);
    const cache = new Map<number, HttpStream>();
    const apply = vi.fn();
    const recordMetric = vi.fn();
    const prefetchAdjacentStreams = vi.fn();

    commitLoadedStreamSwitch({
      protocol: "HTTP" satisfies StreamProtocol,
      requestedStreamId: 9,
      stream,
      cache,
      apply,
      startedAt: 0,
      now: () => 22.5,
      recordMetric,
      prefetchAdjacentStreams,
    });

    expect(recordMetric).toHaveBeenCalledWith("HTTP", 22.5, true);
  });
});
