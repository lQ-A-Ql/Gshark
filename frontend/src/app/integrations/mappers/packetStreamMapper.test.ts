import { describe, expect, it } from "vitest";
import { asBinaryStream, asHttpStream, asPacket, asThreatHit } from "./packetStreamMapper";

describe("packetStreamMapper", () => {
  it("maps packet fields and normalizes time", () => {
    const result = asPacket({
      id: 7,
      timestamp: 1715000000123,
      source_ip: "10.0.0.1",
      source_port: 1234,
      dest_ip: "10.0.0.2",
      dest_port: 80,
      protocol: "TCP",
      display_protocol: " HTTP ",
      length: 99,
      info: "GET /",
      payload: "abc",
      raw_hex: "deadbeef",
      stream_id: 12,
      ip_header_len: 20,
      l4_header_len: 20,
      color_features: {
        tcp_syn: true,
        has_smb: true,
        ipv4_ttl: 64,
      },
    });

    expect(result).toMatchObject({
      id: 7,
      time: expect.stringMatching(/^\d{2}:\d{2}:\d{2}\.\d{3}$/),
      src: "10.0.0.1",
      dstPort: 80,
      displayProtocol: "HTTP",
      rawHex: "deadbeef",
      streamId: 12,
      colorFeatures: {
        tcpSyn: true,
        hasSmb: true,
        ipv4Ttl: 64,
      },
    });
  });

  it("maps http stream with fallback chunks and load meta", () => {
    const result = asHttpStream({
      stream_id: 5,
      from: "client",
      to: "server",
      request: "GET /",
      response: "HTTP/1.1 200 OK",
      load_meta: {
        source: "cache",
        loading: 1,
        cache_hit: 1,
        index_hit: 0,
        file_fallback: 1,
        tshark_ms: 12,
        override_count: 3,
      },
    });

    expect(result.chunks).toEqual([
      { packetId: 0, direction: "client", body: "GET /" },
      { packetId: 0, direction: "server", body: "HTTP/1.1 200 OK" },
    ]);
    expect(result.loadMeta).toMatchObject({
      source: "cache",
      loading: true,
      cacheHit: true,
      fileFallback: true,
      tsharkMs: 12,
      overrideCount: 3,
    });
  });

  it("maps binary stream chunks and threat levels", () => {
    const stream = asBinaryStream(
      {
        stream_id: 9,
        from: "10.0.0.3",
        to: "10.0.0.4",
        chunks: [{ packet_id: 11, direction: "server", body: "reply" }],
        next_cursor: 20,
        total: 21,
        has_more: true,
      },
      "UDP",
    );
    const threat = asThreatHit({
      id: 3,
      packet_id: 44,
      category: "Anomaly",
      rule: "rule",
      level: "critical",
      preview: "p",
      match: "m",
    });

    expect(stream).toMatchObject({
      id: 9,
      protocol: "UDP",
      nextCursor: 20,
      totalChunks: 21,
      hasMore: true,
      chunks: [{ packetId: 11, direction: "server", body: "reply" }],
    });
    expect(threat).toMatchObject({
      id: 3,
      packetId: 44,
      level: "critical",
    });
  });
});
