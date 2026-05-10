import { act, renderHook } from "@testing-library/react";
import { useRef } from "react";
import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useStreamAdjacentPrefetch } from "./useStreamAdjacentPrefetch";

const httpStream = (id: number): HttpStream => ({ id, client: "", server: "", request: "", response: "", chunks: [] });
const rawStream = (protocol: "TCP" | "UDP", id: number): BinaryStream => ({
  id,
  protocol,
  from: "",
  to: "",
  chunks: [],
  nextCursor: 0,
  totalChunks: 0,
  hasMore: false,
});

describe("useStreamAdjacentPrefetch", () => {
  it("binds provider stream refs, task scope, and bridge fetchers to adjacent prefetch state", async () => {
    const fetchHttpStream = vi.fn(async (id: number) => httpStream(id));
    const fetchRawStreamPage = vi.fn(async (protocol: "TCP" | "UDP", id: number) => rawStream(protocol, id));
    const { result } = renderHook(() =>
      useStreamAdjacentPrefetch({
        activeCapturePathRef: useRef("sample.pcapng"),
        backendConnected: true,
        captureTaskScopeRef: useRef(createCaptureTaskScope()),
        fetchHttpStream,
        fetchRawStreamPage,
        httpCacheRef: useRef(new Map<number, HttpStream>()),
        httpPrefetchInFlightRef: useRef(new Set<number>()),
        prefetchLimit: 2,
        streamIds: { http: [1, 2, 3], tcp: [10, 11], udp: [20, 21] },
        tcpCacheRef: useRef(new Map<number, BinaryStream>()),
        tcpPrefetchInFlightRef: useRef(new Set<number>()),
        udpCacheRef: useRef(new Map<number, BinaryStream>()),
        udpPrefetchInFlightRef: useRef(new Set<number>()),
      }),
    );

    let scheduled = 0;
    await act(async () => {
      scheduled = result.current("HTTP", 2);
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(scheduled).toBe(2);
    expect(fetchHttpStream).toHaveBeenCalledWith(3, expect.any(AbortSignal));
    expect(fetchHttpStream).toHaveBeenCalledWith(1, expect.any(AbortSignal));

    await act(async () => {
      result.current("TCP", 10);
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(fetchRawStreamPage).toHaveBeenCalledWith("TCP", 11, 0, 96, expect.any(AbortSignal));
  });
});
