import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useStreamState } from "./useStreamState";

const httpStream = (id: number): HttpStream => ({
  id,
  client: "client",
  server: "server",
  request: "",
  response: "",
  chunks: [{ packetId: 1, direction: "server", body: "old" }],
});

const rawStream = (protocol: "TCP" | "UDP", id: number): BinaryStream => ({
  id,
  protocol,
  from: "a",
  to: "b",
  chunks: [],
  nextCursor: 0,
  totalChunks: 0,
  hasMore: false,
});

describe("useStreamState", () => {
  it("owns stream index, active stream switching, metrics, and payload persistence", async () => {
    const activeCapturePathRef = { current: "sample.pcapng" };
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const fetchHttpStream = vi.fn(async (id: number) => httpStream(id));
    const fetchRawStreamPage = vi.fn(async (protocol: "TCP" | "UDP", id: number) => rawStream(protocol, id));
    const listStreamIds = vi.fn(async (protocol: "HTTP" | "TCP" | "UDP") => {
      if (protocol === "HTTP") return [7];
      if (protocol === "TCP") return [12];
      return [3];
    });
    const setBackendStatus = vi.fn();
    const updateStreamPayloads = vi.fn(async () => undefined);

    const { result } = renderHook(() =>
      useStreamState({
        activeCapturePathRef,
        backendConnected: true,
        captureTaskScopeRef,
        fetchHttpStream,
        fetchRawStreamPage,
        listStreamIds,
        setBackendStatus,
        updateStreamPayloads,
      }),
    );

    await act(async () => {
      await result.current.refreshStreamIndex();
      await result.current.setActiveStream("HTTP", 7);
      await result.current.persistStreamPayloads("HTTP", 7, [{ index: 0, body: "new" }]);
    });

    expect(result.current.streamIds).toEqual({ http: [7], tcp: [12], udp: [3] });
    expect(result.current.httpStream.id).toBe(7);
    expect(result.current.httpStream.chunks[0]?.body).toBe("new");
    expect(result.current.streamSwitchMetrics.byProtocol.HTTP.count).toBe(1);
    expect(fetchHttpStream).toHaveBeenCalledWith(7, expect.any(AbortSignal));
    expect(updateStreamPayloads).toHaveBeenCalledWith("HTTP", 7, [{ index: 0, body: "new" }]);
    expect(setBackendStatus).not.toHaveBeenCalled();
  });
});
