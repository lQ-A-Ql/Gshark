import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { resolveStreamSwitchTask } from "./streamSwitchTask";

function createHttpStream(id: number): HttpStream {
  return {
    id,
    client: "client",
    server: "server",
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
    from: "1.1.1.1",
    to: "2.2.2.2",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
    loadMeta: { source: "network" },
  };
}

describe("streamSwitchTask", () => {
  it("resolves HTTP task with loading placeholder and fetch mapping", async () => {
    const httpCache = new Map<number, HttpStream>();
    const tcpCache = new Map<number, BinaryStream>();
    const udpCache = new Map<number, BinaryStream>();
    const applyHttpStream = vi.fn();
    const applyTcpStream = vi.fn();
    const applyUdpStream = vi.fn();
    const fetchHttpStream = vi.fn(async () => createHttpStream(9));
    const fetchRawTcpStream = vi.fn(async () => createBinaryStream(9, "TCP"));
    const fetchRawUdpStream = vi.fn(async () => createBinaryStream(9, "UDP"));

    const resolved = resolveStreamSwitchTask({
      protocol: "HTTP",
      streamId: 9,
      httpCache,
      tcpCache,
      udpCache,
      applyHttpStream,
      applyTcpStream,
      applyUdpStream,
      fetchHttpStream,
      fetchRawTcpStream,
      fetchRawUdpStream,
    });

    expect(resolved.protocol).toBe("HTTP");
    expect(resolved.cache).toBe(httpCache);
    expect(resolved.loadingStream.id).toBe(9);
    expect(resolved.loadingStream.loadMeta?.loading).toBe(true);
    resolved.applyStream(createHttpStream(9));
    expect(applyHttpStream).toHaveBeenCalledTimes(1);
    expect(applyTcpStream).not.toHaveBeenCalled();
    expect(applyUdpStream).not.toHaveBeenCalled();
    await resolved.fetchStream(9, new AbortController().signal);
    expect(fetchHttpStream).toHaveBeenCalledTimes(1);
    expect(fetchRawTcpStream).not.toHaveBeenCalled();
    expect(fetchRawUdpStream).not.toHaveBeenCalled();
  });

  it("resolves TCP task with loading placeholder and fetch mapping", async () => {
    const httpCache = new Map<number, HttpStream>();
    const tcpCache = new Map<number, BinaryStream>();
    const udpCache = new Map<number, BinaryStream>();
    const applyHttpStream = vi.fn();
    const applyTcpStream = vi.fn();
    const applyUdpStream = vi.fn();
    const fetchHttpStream = vi.fn(async () => createHttpStream(12));
    const fetchRawTcpStream = vi.fn(async () => createBinaryStream(12, "TCP"));
    const fetchRawUdpStream = vi.fn(async () => createBinaryStream(12, "UDP"));

    const resolved = resolveStreamSwitchTask({
      protocol: "TCP",
      streamId: 12,
      httpCache,
      tcpCache,
      udpCache,
      applyHttpStream,
      applyTcpStream,
      applyUdpStream,
      fetchHttpStream,
      fetchRawTcpStream,
      fetchRawUdpStream,
    });

    expect(resolved.protocol).toBe("TCP");
    expect(resolved.cache).toBe(tcpCache);
    expect("protocol" in resolved.loadingStream ? resolved.loadingStream.protocol : null).toBe("TCP");
    expect(resolved.loadingStream.loadMeta?.loading).toBe(true);
    resolved.applyStream(createBinaryStream(12, "TCP"));
    expect(applyTcpStream).toHaveBeenCalledTimes(1);
    expect(applyHttpStream).not.toHaveBeenCalled();
    expect(applyUdpStream).not.toHaveBeenCalled();
    await resolved.fetchStream(12, new AbortController().signal);
    expect(fetchRawTcpStream).toHaveBeenCalledTimes(1);
    expect(fetchHttpStream).not.toHaveBeenCalled();
    expect(fetchRawUdpStream).not.toHaveBeenCalled();
  });

  it("resolves UDP task with loading placeholder and fetch mapping", async () => {
    const httpCache = new Map<number, HttpStream>();
    const tcpCache = new Map<number, BinaryStream>();
    const udpCache = new Map<number, BinaryStream>();
    const applyHttpStream = vi.fn();
    const applyTcpStream = vi.fn();
    const applyUdpStream = vi.fn();
    const fetchHttpStream = vi.fn(async () => createHttpStream(21));
    const fetchRawTcpStream = vi.fn(async () => createBinaryStream(21, "TCP"));
    const fetchRawUdpStream = vi.fn(async () => createBinaryStream(21, "UDP"));

    const resolved = resolveStreamSwitchTask({
      protocol: "UDP",
      streamId: 21,
      httpCache,
      tcpCache,
      udpCache,
      applyHttpStream,
      applyTcpStream,
      applyUdpStream,
      fetchHttpStream,
      fetchRawTcpStream,
      fetchRawUdpStream,
    });

    expect(resolved.protocol).toBe("UDP");
    expect(resolved.cache).toBe(udpCache);
    expect("protocol" in resolved.loadingStream ? resolved.loadingStream.protocol : null).toBe("UDP");
    expect(resolved.loadingStream.loadMeta?.loading).toBe(true);
    resolved.applyStream(createBinaryStream(21, "UDP"));
    expect(applyUdpStream).toHaveBeenCalledTimes(1);
    expect(applyHttpStream).not.toHaveBeenCalled();
    expect(applyTcpStream).not.toHaveBeenCalled();
    await resolved.fetchStream(21, new AbortController().signal);
    expect(fetchRawUdpStream).toHaveBeenCalledTimes(1);
    expect(fetchHttpStream).not.toHaveBeenCalled();
    expect(fetchRawTcpStream).not.toHaveBeenCalled();
  });
});
