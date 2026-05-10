import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { prefetchAdjacentStreamsState, type PrefetchAdjacentStreamsOptions } from "./streamAdjacentPrefetch";

function httpStream(id: number): HttpStream {
  return { id, client: "", server: "", request: "", response: "", chunks: [] };
}

function rawStream(protocol: "TCP" | "UDP", id: number): BinaryStream {
  return { id, protocol, from: "", to: "", chunks: [], nextCursor: 0, totalChunks: 0, hasMore: false };
}

function createOptions(overrides: Partial<PrefetchAdjacentStreamsOptions> = {}): PrefetchAdjacentStreamsOptions {
  return {
    backendConnected: true,
    activeCapturePath: "sample.pcapng",
    protocol: "HTTP",
    currentStreamId: 2,
    limit: 2,
    streamIds: { http: [1, 2, 3], tcp: [10, 11], udp: [20, 21] },
    httpCache: new Map(),
    tcpCache: new Map(),
    udpCache: new Map(),
    httpInFlight: new Set(),
    tcpInFlight: new Set(),
    udpInFlight: new Set(),
    beginTask: vi.fn(() => ({ signal: new AbortController().signal, isCurrent: () => true, finish: vi.fn() })),
    fetchHttpStream: vi.fn(async (streamId) => httpStream(streamId)),
    fetchRawTcpStream: vi.fn(async (streamId) => rawStream("TCP", streamId)),
    fetchRawUdpStream: vi.fn(async (streamId) => rawStream("UDP", streamId)),
    ...overrides,
  };
}

describe("streamAdjacentPrefetch", () => {
  it("skips when backend, capture, stream id, or limit is invalid", () => {
    for (const overrides of [
      { backendConnected: false },
      { activeCapturePath: "" },
      { currentStreamId: -1 },
      { limit: 0 },
    ]) {
      const options = createOptions(overrides);

      expect(prefetchAdjacentStreamsState(options)).toBe(0);
      expect(options.beginTask).not.toHaveBeenCalled();
    }
  });

  it("schedules adjacent HTTP targets and fills cache when fetch resolves", async () => {
    const options = createOptions();

    expect(prefetchAdjacentStreamsState(options)).toBe(2);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(options.beginTask).toHaveBeenCalledWith("prefetch-http-3");
    expect(options.beginTask).toHaveBeenCalledWith("prefetch-http-1");
    expect(options.fetchHttpStream).toHaveBeenCalledWith(3, expect.any(AbortSignal));
    expect(options.fetchHttpStream).toHaveBeenCalledWith(1, expect.any(AbortSignal));
    expect(options.httpCache.get(3)?.id).toBe(3);
    expect(options.httpCache.get(1)?.id).toBe(1);
    expect(options.httpInFlight.size).toBe(0);
  });

  it("uses protocol-specific raw stream fetchers", () => {
    const tcpOptions = createOptions({ protocol: "TCP", currentStreamId: 10, limit: 1 });
    const udpOptions = createOptions({ protocol: "UDP", currentStreamId: 20, limit: 1 });

    expect(prefetchAdjacentStreamsState(tcpOptions)).toBe(1);
    expect(prefetchAdjacentStreamsState(udpOptions)).toBe(1);

    expect(tcpOptions.beginTask).toHaveBeenCalledWith("prefetch-tcp-11");
    expect(tcpOptions.fetchRawTcpStream).toHaveBeenCalledWith(11, expect.any(AbortSignal));
    expect(udpOptions.beginTask).toHaveBeenCalledWith("prefetch-udp-21");
    expect(udpOptions.fetchRawUdpStream).toHaveBeenCalledWith(21, expect.any(AbortSignal));
  });

  it("does not schedule cached or in-flight targets", () => {
    const options = createOptions({
      httpCache: new Map([[3, httpStream(3)]]),
      httpInFlight: new Set([1]),
    });

    expect(prefetchAdjacentStreamsState(options)).toBe(0);
    expect(options.beginTask).not.toHaveBeenCalled();
  });
});
