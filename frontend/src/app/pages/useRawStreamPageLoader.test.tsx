import { act, renderHook } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { type RawStreamViewState } from "./RawStreamViewState";
import { useRawStreamPageLoader, type FetchRawStreamPage } from "./useRawStreamPageLoader";

function makeStreamView(overrides: Partial<RawStreamViewState> = {}): RawStreamViewState {
  return {
    id: 1,
    protocol: "TCP",
    from: "10.0.0.1:1234",
    to: "10.0.0.2:443",
    chunks: [{ packetId: 1, direction: "client", body: "first" }],
    nextCursor: 1,
    totalChunks: 2,
    hasMore: true,
    ...overrides,
  };
}

describe("useRawStreamPageLoader", () => {
  it("appends a matching raw stream page", async () => {
    const fetchRawStreamPage: FetchRawStreamPage = vi.fn(async () => ({
      id: 1,
      protocol: "TCP" as const,
      from: "10.0.0.1:1234",
      to: "10.0.0.2:443",
      chunks: [{ packetId: 2, direction: "server" as const, body: "second" }],
      nextCursor: 2,
      totalChunks: 2,
      hasMore: false,
    }));
    const { result } = renderHook(() => {
      const [streamView, setStreamView] = useState(() => makeStreamView());
      const loader = useRawStreamPageLoader({ fetchRawStreamPage, pageSize: 96, protocol: "TCP", setStreamView, streamView });
      return { streamView, ...loader };
    });

    await act(async () => {
      await result.current.loadMore();
    });

    expect(fetchRawStreamPage).toHaveBeenCalledWith("TCP", 1, 1, 96);
    expect(result.current.streamView.chunks.map((chunk) => chunk.body)).toEqual(["first", "second"]);
    expect(result.current.streamView.hasMore).toBe(false);
  });

  it("ignores a stale page for a different stream id", async () => {
    const fetchRawStreamPage: FetchRawStreamPage = vi.fn(async () => ({
      id: 9,
      protocol: "TCP" as const,
      from: "",
      to: "",
      chunks: [{ packetId: 9, direction: "server" as const, body: "stale" }],
      hasMore: false,
    }));
    const { result } = renderHook(() => {
      const [streamView, setStreamView] = useState(() => makeStreamView());
      const loader = useRawStreamPageLoader({ fetchRawStreamPage, pageSize: 96, protocol: "TCP", setStreamView, streamView });
      return { streamView, ...loader };
    });

    await act(async () => {
      await result.current.loadMore();
    });

    expect(result.current.streamView.chunks.map((chunk) => chunk.body)).toEqual(["first"]);
    expect(result.current.streamView.hasMore).toBe(true);
  });

  it("records load errors and clears them when stream changes", async () => {
    const fetchRawStreamPage = vi.fn().mockRejectedValue(new Error("boom")) as FetchRawStreamPage;
    const { result } = renderHook(() => {
      const [streamView, setStreamView] = useState(() => makeStreamView());
      const loader = useRawStreamPageLoader({ fetchRawStreamPage, pageSize: 96, protocol: "TCP", setStreamView, streamView });
      return { setStreamView, streamView, ...loader };
    });

    await act(async () => {
      await result.current.loadMore();
    });
    expect(result.current.loadError).toBe("boom");

    act(() => {
      result.current.setStreamView(makeStreamView({ id: 2 }));
    });
    expect(result.current.loadError).toBe("");
  });
});
