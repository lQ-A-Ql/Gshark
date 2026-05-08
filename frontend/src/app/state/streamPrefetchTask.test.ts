import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { resolveStreamPrefetchTask } from "./streamPrefetchTask";

function createHttpStream(id: number): HttpStream {
  return {
    id,
    client: "127.0.0.1:50000",
    server: "127.0.0.1:17891",
    request: "",
    response: "",
    chunks: [],
    loadMeta: { source: "network" },
  };
}

function createBinaryStream(id: number, protocol: "TCP" | "UDP"): BinaryStream {
  return {
    id,
    protocol,
    from: "127.0.0.1:50000",
    to: "127.0.0.1:17891",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
    loadMeta: { source: "network" },
  };
}

describe("streamPrefetchTask", () => {
  it("resolves HTTP prefetch task with matching task key and stores", async () => {
    const httpCache = new Map<number, HttpStream>();
    const tcpCache = new Map<number, BinaryStream>();
    const udpCache = new Map<number, BinaryStream>();
    const httpInFlight = new Set<number>();
    const tcpInFlight = new Set<number>();
    const udpInFlight = new Set<number>();
    const fetchHttpStream = vi.fn(async () => createHttpStream(11));
    const fetchRawTcpStream = vi.fn(async () => createBinaryStream(11, "TCP"));
    const fetchRawUdpStream = vi.fn(async () => createBinaryStream(11, "UDP"));

    const resolved = resolveStreamPrefetchTask({
      protocol: "HTTP",
      targetId: 11,
      httpCache,
      tcpCache,
      udpCache,
      httpInFlight,
      tcpInFlight,
      udpInFlight,
      fetchHttpStream,
      fetchRawTcpStream,
      fetchRawUdpStream,
    });

    expect(resolved.taskKey).toBe("prefetch-http-11");
    expect(resolved.cache).toBe(httpCache);
    expect(resolved.inFlight).toBe(httpInFlight);

    await resolved.fetchStream(11, new AbortController().signal);
    expect(fetchHttpStream).toHaveBeenCalledTimes(1);
    expect(fetchRawTcpStream).not.toHaveBeenCalled();
    expect(fetchRawUdpStream).not.toHaveBeenCalled();
  });

  it("resolves TCP prefetch task with matching task key and stores", async () => {
    const httpCache = new Map<number, HttpStream>();
    const tcpCache = new Map<number, BinaryStream>();
    const udpCache = new Map<number, BinaryStream>();
    const httpInFlight = new Set<number>();
    const tcpInFlight = new Set<number>();
    const udpInFlight = new Set<number>();
    const fetchHttpStream = vi.fn(async () => createHttpStream(13));
    const fetchRawTcpStream = vi.fn(async () => createBinaryStream(13, "TCP"));
    const fetchRawUdpStream = vi.fn(async () => createBinaryStream(13, "UDP"));

    const resolved = resolveStreamPrefetchTask({
      protocol: "TCP",
      targetId: 13,
      httpCache,
      tcpCache,
      udpCache,
      httpInFlight,
      tcpInFlight,
      udpInFlight,
      fetchHttpStream,
      fetchRawTcpStream,
      fetchRawUdpStream,
    });

    expect(resolved.taskKey).toBe("prefetch-tcp-13");
    expect(resolved.cache).toBe(tcpCache);
    expect(resolved.inFlight).toBe(tcpInFlight);

    await resolved.fetchStream(13, new AbortController().signal);
    expect(fetchRawTcpStream).toHaveBeenCalledTimes(1);
    expect(fetchHttpStream).not.toHaveBeenCalled();
    expect(fetchRawUdpStream).not.toHaveBeenCalled();
  });

  it("resolves UDP prefetch task with matching task key and stores", async () => {
    const httpCache = new Map<number, HttpStream>();
    const tcpCache = new Map<number, BinaryStream>();
    const udpCache = new Map<number, BinaryStream>();
    const httpInFlight = new Set<number>();
    const tcpInFlight = new Set<number>();
    const udpInFlight = new Set<number>();
    const fetchHttpStream = vi.fn(async () => createHttpStream(17));
    const fetchRawTcpStream = vi.fn(async () => createBinaryStream(17, "TCP"));
    const fetchRawUdpStream = vi.fn(async () => createBinaryStream(17, "UDP"));

    const resolved = resolveStreamPrefetchTask({
      protocol: "UDP",
      targetId: 17,
      httpCache,
      tcpCache,
      udpCache,
      httpInFlight,
      tcpInFlight,
      udpInFlight,
      fetchHttpStream,
      fetchRawTcpStream,
      fetchRawUdpStream,
    });

    expect(resolved.taskKey).toBe("prefetch-udp-17");
    expect(resolved.cache).toBe(udpCache);
    expect(resolved.inFlight).toBe(udpInFlight);

    await resolved.fetchStream(17, new AbortController().signal);
    expect(fetchRawUdpStream).toHaveBeenCalledTimes(1);
    expect(fetchHttpStream).not.toHaveBeenCalled();
    expect(fetchRawTcpStream).not.toHaveBeenCalled();
  });
});
