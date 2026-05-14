import type { Dispatch, MutableRefObject, SetStateAction } from "react";
import { backendClients } from "../../integrations/backendClients";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { usePacketPageState } from "./usePacketPageState";
import { useStreamState } from "./useStreamState";

interface UseSentinelPacketStreamBundleOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly backendConnected: boolean;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly displayFilter: string;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setDisplayFilter: Dispatch<SetStateAction<string>>;
}

export function useSentinelPacketStreamBundle({
  activeCapturePathRef,
  backendConnected,
  captureTaskScopeRef,
  displayFilter,
  setBackendStatus,
  setDisplayFilter,
}: UseSentinelPacketStreamBundleOptions) {
  const streamState = useStreamState({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream: backendClients.stream.getHttpStream,
    fetchRawStreamPage: backendClients.stream.getRawStreamPage,
    listStreamIds: backendClients.stream.listStreamIds,
    setBackendStatus,
    updateStreamPayloads: backendClients.stream.updateStreamPayloads,
  });

  const packetPageState = usePacketPageState({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    displayFilter,
    listPacketsPage: backendClients.packet.listPacketsPage,
    locatePacketPage: backendClients.packet.locatePacketPage,
    loadPacket: backendClients.packet.getPacket,
    loadRawHex: backendClients.packet.getPacketRawHex,
    loadLayers: backendClients.packet.getPacketLayers,
    setBackendStatus,
    setDisplayFilter,
  });

  return { packetPageState, streamState };
}
