import { describe, expect, it } from "vitest";
import { asBinaryStream, asHttpStream } from "./streamMapper";

describe("streamMapper", () => {
  it("normalizes HTTP stream chunks and load metadata", () => {
    const stream = asHttpStream({
      stream_id: 4,
      from: "10.0.0.1:50000",
      to: "10.0.0.2:80",
      request: "GET / HTTP/1.1",
      response: "HTTP/1.1 200 OK",
      chunks: [{ packet_id: 10, direction: "server", body: "HTTP/1.1 200 OK" }],
      load_meta: {
        source: "tshark",
        loading: false,
        cache_hit: true,
        index_hit: true,
        file_fallback: false,
        tshark_ms: 12,
        override_count: 2,
      },
    });

    expect(stream).toMatchObject({
      id: 4,
      client: "10.0.0.1:50000",
      server: "10.0.0.2:80",
      request: "GET / HTTP/1.1",
      response: "HTTP/1.1 200 OK",
      chunks: [{ packetId: 10, direction: "server", body: "HTTP/1.1 200 OK" }],
      loadMeta: {
        source: "tshark",
        loading: false,
        cacheHit: true,
        indexHit: true,
        fileFallback: false,
        tsharkMs: 12,
        overrideCount: 2,
      },
    });
  });

  it("normalizes binary stream pagination", () => {
    const stream = asBinaryStream(
      {
        stream_id: 8,
        from: "client",
        to: "server",
        chunks: [{ packet_id: 3, direction: "client", body: "abc" }],
        next_cursor: 1,
        total: 4,
        has_more: true,
      },
      "TCP",
    );

    expect(stream).toMatchObject({
      id: 8,
      protocol: "TCP",
      from: "client",
      to: "server",
      chunks: [{ packetId: 3, direction: "client", body: "abc" }],
      nextCursor: 1,
      totalChunks: 4,
      hasMore: true,
    });
  });
});
