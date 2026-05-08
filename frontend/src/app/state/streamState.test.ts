import { describe, expect, it } from "vitest";
import {
  applyStreamChunkPatches,
  buildLoadingBinaryStream,
  buildLoadingHttpStream,
  buildSwitchStat,
  createEmptyStreamIds,
  createEmptyUdpStream,
  getStreamIdsForProtocol,
  isFastPathLoad,
  markCachedLoad,
  prettySize,
} from "./streamState";
import type { HttpStream } from "../core/types";

describe("streamState helpers", () => {
  it("builds empty UDP stream and stream id state", () => {
    expect(createEmptyUdpStream()).toMatchObject({
      id: -1,
      protocol: "UDP",
      chunks: [],
      nextCursor: 0,
      totalChunks: 0,
      hasMore: false,
    });

    const ids = createEmptyStreamIds();
    expect(ids).toEqual({ http: [], tcp: [], udp: [] });
    expect(createEmptyStreamIds()).not.toBe(ids);
    expect(createEmptyStreamIds().http).not.toBe(ids.http);
  });

  it("selects stream ids by protocol", () => {
    const streamIds = { http: [1], tcp: [2], udp: [3] };
    expect(getStreamIdsForProtocol(streamIds, "HTTP")).toEqual([1]);
    expect(getStreamIdsForProtocol(streamIds, "TCP")).toEqual([2]);
    expect(getStreamIdsForProtocol(streamIds, "UDP")).toEqual([3]);
  });

  it("builds stable loading placeholders", () => {
    expect(buildLoadingHttpStream(5)).toMatchObject({ id: 5, loadMeta: { source: "loading", loading: true } });
    expect(buildLoadingBinaryStream("TCP", 7)).toMatchObject({
      id: 7,
      protocol: "TCP",
      loadMeta: { source: "loading", loading: true },
    });
  });

  it("computes stream switch metrics from sampled durations", () => {
    expect(buildSwitchStat([10, 20, 30], 2)).toEqual({
      count: 3,
      lastMs: 30,
      p50Ms: 20,
      p95Ms: 30,
      cacheHitRate: 66.7,
    });
  });

  it("marks cache hits and recognizes fast-path load metadata", () => {
    const cached = markCachedLoad(buildLoadingHttpStream(9));
    expect(cached.loadMeta?.cacheHit).toBe(true);
    expect(isFastPathLoad(cached.loadMeta)).toBe(true);
    expect(isFastPathLoad({ source: "tshark" })).toBe(false);
  });

  it("patches HTTP chunks and rebuilds request/response previews", () => {
    const patched = applyStreamChunkPatches(
      {
        id: 1,
        client: "",
        server: "",
        request: "old",
        response: "old",
        chunks: [
          { packetId: 1, direction: "client", body: "GET /" },
          { packetId: 2, direction: "server", body: "HTTP/1.1 200" },
        ],
      } satisfies HttpStream,
      [{ index: 0, body: "POST /login" }],
    );

    expect(patched.request).toBe("POST /login");
    expect(patched.response).toBe("HTTP/1.1 200");
  });

  it("formats byte counts in MB", () => {
    expect(prettySize(2 * 1024 * 1024)).toBe("2.0 MB");
  });
});
