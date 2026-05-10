import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { persistStreamPayloadsState } from "./streamPayloadPersist";

function createHttpStream(id: number, body = "body"): HttpStream {
  return {
    id,
    client: "",
    server: "",
    request: "",
    response: body,
    chunks: [{ packetId: 1, direction: "server", body }],
  };
}

function createTcpStream(id: number, body = "body"): BinaryStream {
  return {
    id,
    protocol: "TCP",
    from: "",
    to: "",
    chunks: [{ packetId: 1, direction: "server", body }],
    nextCursor: 0,
    totalChunks: 1,
    hasMore: false,
  };
}

function createOptions(overrides: Partial<Parameters<typeof persistStreamPayloadsState>[0]> = {}) {
  let httpStream = createHttpStream(1, "http");
  let tcpStream = createTcpStream(2, "tcp");
  let udpStream: BinaryStream = { ...createTcpStream(3, "udp"), protocol: "UDP" };
  return {
    protocol: "HTTP" as const,
    streamId: 1,
    patches: [{ index: 0, body: "patched" }],
    backendConnected: true,
    updateStreamPayloads: vi.fn(async () => undefined),
    startTransition: vi.fn((callback: () => void) => callback()),
    setHttpStream: vi.fn((updater: (prev: HttpStream) => HttpStream) => {
      httpStream = updater(httpStream);
    }),
    setTcpStream: vi.fn((updater: (prev: BinaryStream) => BinaryStream) => {
      tcpStream = updater(tcpStream);
    }),
    setUdpStream: vi.fn((updater: (prev: BinaryStream) => BinaryStream) => {
      udpStream = updater(udpStream);
    }),
    httpCache: new Map<number, HttpStream>([[1, createHttpStream(1, "http-cache")]]),
    tcpCache: new Map<number, BinaryStream>([[2, createTcpStream(2, "tcp-cache")]]),
    udpCache: new Map<number, BinaryStream>([[3, { ...createTcpStream(3, "udp-cache"), protocol: "UDP" }]]),
    getStreams: () => ({ httpStream, tcpStream, udpStream }),
    ...overrides,
  };
}

describe("streamPayloadPersist", () => {
  it("updates backend payloads before patching active stream and cache", async () => {
    const options = createOptions();

    await persistStreamPayloadsState(options);

    expect(options.updateStreamPayloads).toHaveBeenCalledWith("HTTP", 1, [{ index: 0, body: "patched" }]);
    expect(options.startTransition).toHaveBeenCalledTimes(1);
    expect(options.getStreams().httpStream.chunks[0]?.body).toBe("patched");
    expect(options.httpCache.get(1)?.chunks[0]?.body).toBe("patched");
  });

  it("skips work when disconnected, stream id is invalid, or patches are empty", async () => {
    for (const overrides of [{ backendConnected: false }, { streamId: -1 }, { patches: [] }] satisfies Array<
      Partial<Parameters<typeof persistStreamPayloadsState>[0]>
    >) {
      const options = createOptions(overrides);

      await persistStreamPayloadsState(options);

      expect(options.updateStreamPayloads).not.toHaveBeenCalled();
      expect(options.startTransition).not.toHaveBeenCalled();
    }
  });

  it("does not patch local state when backend update fails", async () => {
    const options = createOptions({
      updateStreamPayloads: vi.fn(async () => {
        throw new Error("persist failed");
      }),
    });

    await expect(persistStreamPayloadsState(options)).rejects.toThrow("persist failed");

    expect(options.startTransition).not.toHaveBeenCalled();
    expect(options.getStreams().httpStream.chunks[0]?.body).toBe("http");
  });
});
