import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { createStreamSwitchSequences } from "./streamSwitchSequence";
import { setActiveStreamState, type SetActiveStreamOptions } from "./streamSwitchWorkflow";

function httpStream(id: number): HttpStream {
  return { id, client: "c", server: "s", request: "", response: "", chunks: [] };
}

function rawStream(protocol: "TCP" | "UDP", id: number): BinaryStream {
  return { id, protocol, from: "a", to: "b", chunks: [], nextCursor: 0, totalChunks: 0, hasMore: false };
}

function createOptions(overrides: Partial<SetActiveStreamOptions> = {}): SetActiveStreamOptions {
  return {
    backendConnected: true,
    activeCapturePath: "sample.pcapng",
    protocol: "HTTP",
    streamId: 7,
    streamSwitchSequences: createStreamSwitchSequences(),
    captureTaskScope: createCaptureTaskScope(),
    httpCache: new Map(),
    tcpCache: new Map(),
    udpCache: new Map(),
    applyHttpStream: vi.fn(),
    applyTcpStream: vi.fn(),
    applyUdpStream: vi.fn(),
    fetchHttpStream: vi.fn(async (streamId) => httpStream(streamId)),
    fetchRawTcpStream: vi.fn(async (streamId) => rawStream("TCP", streamId)),
    fetchRawUdpStream: vi.fn(async (streamId) => rawStream("UDP", streamId)),
    recordMetric: vi.fn(),
    prefetchAdjacentStreams: vi.fn(),
    setBackendStatus: vi.fn(),
    now: vi.fn().mockReturnValueOnce(10).mockReturnValue(25),
    ...overrides,
  };
}

describe("streamSwitchWorkflow", () => {
  it("skips invalid switch requests", async () => {
    for (const overrides of [{ backendConnected: false }, { activeCapturePath: "" }, { streamId: -1 }]) {
      const options = createOptions(overrides);

      await setActiveStreamState(options);

      expect(options.fetchHttpStream).not.toHaveBeenCalled();
      expect(options.applyHttpStream).not.toHaveBeenCalled();
    }
  });

  it("applies cached streams and records a cache metric", async () => {
    const options = createOptions({ httpCache: new Map([[7, httpStream(7)]]) });

    await setActiveStreamState(options);

    expect(options.applyHttpStream).toHaveBeenCalledWith(
      expect.objectContaining({ id: 7, loadMeta: expect.objectContaining({ cacheHit: true }) }),
    );
    expect(options.fetchHttpStream).not.toHaveBeenCalled();
    expect(options.recordMetric).toHaveBeenCalledWith("HTTP", 15, true);
    expect(options.prefetchAdjacentStreams).toHaveBeenCalledWith("HTTP", 7);
  });

  it("applies loading state, fetches, commits, and prefetches", async () => {
    const loaded = rawStream("TCP", 12);
    const options = createOptions({
      protocol: "TCP",
      streamId: 12,
      fetchRawTcpStream: vi.fn(async () => loaded),
    });

    await setActiveStreamState(options);

    expect(options.applyTcpStream).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ id: 12, loadMeta: expect.objectContaining({ loading: true }) }),
    );
    expect(options.applyTcpStream).toHaveBeenNthCalledWith(2, loaded);
    expect(options.tcpCache.get(12)).toBe(loaded);
    expect(options.recordMetric).toHaveBeenCalledWith("TCP", 15, false);
    expect(options.prefetchAdjacentStreams).toHaveBeenCalledWith("TCP", 12);
  });

  it("reports non-abort fetch failures", async () => {
    const options = createOptions({
      fetchHttpStream: vi.fn(async () => {
        throw new Error("stream unavailable");
      }),
    });

    await setActiveStreamState(options);

    expect(options.setBackendStatus).toHaveBeenCalledWith("stream unavailable");
  });
});
