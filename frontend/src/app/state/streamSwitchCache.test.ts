import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../core/types";
import { applyCachedStreamSwitch } from "./streamSwitchCache";

function createHttpStream(id: number): HttpStream {
  return {
    id,
    client: "client",
    server: "server",
    request: "",
    response: "",
    chunks: [],
  };
}

function createBinaryStream(id: number): BinaryStream {
  return {
    id,
    protocol: "TCP",
    from: "1.1.1.1",
    to: "2.2.2.2",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
  };
}

describe("streamSwitchCache helpers", () => {
  it("applies marked cached stream when cache hit and request is latest", () => {
    const cache = new Map<number, HttpStream>([[7, createHttpStream(7)]]);
    const apply = vi.fn();
    const hit = applyCachedStreamSwitch({
      cache,
      streamId: 7,
      isLatest: () => true,
      apply,
    });

    expect(hit).toBe(true);
    expect(apply).toHaveBeenCalledTimes(1);
    const applied = apply.mock.calls[0][0] as HttpStream;
    expect(applied.id).toBe(7);
    expect(applied.loadMeta?.cacheHit).toBe(true);
    expect(applied.loadMeta?.source).toBe("cache");
  });

  it("does not apply when stream is missing or request is stale", () => {
    const binaryCache = new Map<number, BinaryStream>([[9, createBinaryStream(9)]]);
    const apply = vi.fn();

    const stale = applyCachedStreamSwitch({
      cache: binaryCache,
      streamId: 9,
      isLatest: () => false,
      apply,
    });
    const missing = applyCachedStreamSwitch({
      cache: binaryCache,
      streamId: 11,
      isLatest: () => true,
      apply,
    });

    expect(stale).toBe(false);
    expect(missing).toBe(false);
    expect(apply).not.toHaveBeenCalled();
  });
});
