import { renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useRawStreamRouteSelection, type RawStreamProtocol } from "./useRawStreamRouteSelection";

interface HarnessProps {
  locationState: unknown;
  protocol: RawStreamProtocol;
  selectedPacketStreamId?: number | null;
  setActiveStream: (protocol: RawStreamProtocol, streamId: number) => void;
  streamList: number[];
  streamViewId: number;
}

describe("useRawStreamRouteSelection", () => {
  it("consumes a route stream id once", () => {
    const setActiveStream = vi.fn();
    const props: HarnessProps = {
      locationState: { streamId: 7 },
      protocol: "TCP",
      selectedPacketStreamId: -1,
      setActiveStream,
      streamList: [7],
      streamViewId: -1,
    };

    const { rerender } = renderHook((hookProps: HarnessProps) => useRawStreamRouteSelection(hookProps), {
      initialProps: props,
    });
    rerender(props);

    expect(setActiveStream).toHaveBeenCalledTimes(1);
    expect(setActiveStream).toHaveBeenCalledWith("TCP", 7);
  });

  it("falls back to selected packet stream when no stream is active", () => {
    const setActiveStream = vi.fn();
    renderHook(() =>
      useRawStreamRouteSelection({
        locationState: null,
        protocol: "UDP",
        selectedPacketStreamId: 3,
        setActiveStream,
        streamList: [1, 3, 5],
        streamViewId: -1,
      }),
    );

    expect(setActiveStream).toHaveBeenCalledWith("UDP", 3);
  });

  it("ignores stream ids missing from the current protocol list", () => {
    const setActiveStream = vi.fn();
    renderHook(() =>
      useRawStreamRouteSelection({
        locationState: { streamId: 9 },
        protocol: "TCP",
        selectedPacketStreamId: 4,
        setActiveStream,
        streamList: [1, 2, 3],
        streamViewId: -1,
      }),
    );

    expect(setActiveStream).not.toHaveBeenCalled();
  });

  it("does not re-select the active stream", () => {
    const setActiveStream = vi.fn();
    renderHook(() =>
      useRawStreamRouteSelection({
        locationState: { streamId: 2 },
        protocol: "TCP",
        selectedPacketStreamId: 2,
        setActiveStream,
        streamList: [2],
        streamViewId: 2,
      }),
    );

    expect(setActiveStream).not.toHaveBeenCalled();
  });
});
