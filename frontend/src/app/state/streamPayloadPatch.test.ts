import { describe, expect, it } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { commitProtocolStreamPayloadPatches, commitStreamPayloadPatches } from "./streamPayloadPatch";

function createHttpStream(id: number, body = "body"): HttpStream {
  return {
    id,
    client: "127.0.0.1:12345",
    server: "127.0.0.1:8080",
    request: "",
    response: body,
    chunks: [{ packetId: 1, direction: "server", body }],
    loadMeta: { source: "network" },
  };
}

function createTcpStream(id: number, body = "payload"): BinaryStream {
  return {
    id,
    protocol: "TCP",
    from: "10.0.0.2:50555",
    to: "10.0.0.5:80",
    chunks: [{ packetId: 1, direction: "server", body }],
    nextCursor: 0,
    totalChunks: 1,
    hasMore: false,
    loadMeta: { source: "network" },
  };
}

describe("streamPayloadPatch", () => {
  it("patches active stream state and matching cache record", () => {
    const streamId = 11;
    const patches = [{ index: 0, body: "patched" }];
    let active = createHttpStream(streamId, "before");
    const cache = new Map<number, HttpStream>([[streamId, createHttpStream(streamId, "cache-before")]]);

    commitStreamPayloadPatches({
      streamId,
      patches,
      setStream: (updater) => {
        active = updater(active);
      },
      cache,
    });

    expect(active.chunks[0]?.body).toBe("patched");
    expect(cache.get(streamId)?.chunks[0]?.body).toBe("patched");
  });

  it("keeps non-target active stream untouched and skips missing cache entries", () => {
    const streamId = 41;
    const patches = [{ index: 0, body: "patched" }];
    let active = createTcpStream(7, "still-original");
    const cache = new Map<number, BinaryStream>();

    commitStreamPayloadPatches({
      streamId,
      patches,
      setStream: (updater) => {
        active = updater(active);
      },
      cache,
    });

    expect(active.chunks[0]?.body).toBe("still-original");
    expect(cache.size).toBe(0);
  });

  it("routes protocol payload patches to the matching stream and cache", () => {
    const patches = [{ index: 0, body: "udp-patched" }];
    let httpStream = createHttpStream(1, "http-original");
    let tcpStream = createTcpStream(2, "tcp-original");
    let udpStream: BinaryStream = { ...createTcpStream(3, "udp-original"), protocol: "UDP" };
    const httpCache = new Map<number, HttpStream>([[1, createHttpStream(1, "http-cache")]]);
    const tcpCache = new Map<number, BinaryStream>([[2, createTcpStream(2, "tcp-cache")]]);
    const udpCache = new Map<number, BinaryStream>([[3, { ...createTcpStream(3, "udp-cache"), protocol: "UDP" }]]);

    commitProtocolStreamPayloadPatches({
      protocol: "UDP",
      streamId: 3,
      patches,
      setHttpStream: (updater) => {
        httpStream = updater(httpStream);
      },
      setTcpStream: (updater) => {
        tcpStream = updater(tcpStream);
      },
      setUdpStream: (updater) => {
        udpStream = updater(udpStream);
      },
      httpCache,
      tcpCache,
      udpCache,
    });

    expect(httpStream.chunks[0]?.body).toBe("http-original");
    expect(tcpStream.chunks[0]?.body).toBe("tcp-original");
    expect(udpStream.chunks[0]?.body).toBe("udp-patched");
    expect(httpCache.get(1)?.chunks[0]?.body).toBe("http-cache");
    expect(tcpCache.get(2)?.chunks[0]?.body).toBe("tcp-cache");
    expect(udpCache.get(3)?.chunks[0]?.body).toBe("udp-patched");
  });
});
