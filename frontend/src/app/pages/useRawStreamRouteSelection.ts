import { useEffect, useRef } from "react";

export type RawStreamProtocol = "TCP" | "UDP";

interface UseRawStreamRouteSelectionOptions {
  locationState: unknown;
  protocol: RawStreamProtocol;
  selectedPacketStreamId?: number | null;
  setActiveStream: (protocol: RawStreamProtocol, streamId: number) => void | Promise<void>;
  streamList: number[];
  streamViewId: number;
}

export function useRawStreamRouteSelection({
  locationState,
  protocol,
  selectedPacketStreamId,
  setActiveStream,
  streamList,
  streamViewId,
}: UseRawStreamRouteSelectionOptions) {
  const consumedRouteStreamIdRef = useRef<number | null>(null);

  useEffect(() => {
    const routeStreamId = readRouteStreamId(locationState);
    const selectedStreamId = Number(selectedPacketStreamId ?? -1);
    const hasPendingRouteStream = routeStreamId >= 0 && routeStreamId !== consumedRouteStreamIdRef.current;
    const streamId = hasPendingRouteStream ? routeStreamId : streamViewId < 0 ? selectedStreamId : -1;
    if (streamId < 0 || !streamList.includes(streamId) || streamViewId === streamId) {
      return;
    }
    if (hasPendingRouteStream) {
      consumedRouteStreamIdRef.current = routeStreamId;
    }
    void setActiveStream(protocol, streamId);
  }, [locationState, protocol, selectedPacketStreamId, setActiveStream, streamList, streamViewId]);
}

function readRouteStreamId(locationState: unknown): number {
  if (!locationState || typeof locationState !== "object" || !("streamId" in locationState)) {
    return -1;
  }
  return Number((locationState as { streamId?: unknown }).streamId ?? -1);
}
