import type { Dispatch, MutableRefObject, SetStateAction } from "react";
import type { Packet } from "../../core/types";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { shouldLoadSelectedPacketArtifacts, shouldLoadSelectedPacketDetail } from "../selectedPacketState";
import { useSelectedPacketArtifact } from "./useSelectedPacketArtifact";
import { useSelectedPacketDetail } from "./useSelectedPacketDetail";

interface UseSelectedPacketResourcesOptions {
  readonly selectedPacketId: number | null;
  readonly selectedPacket: Packet | null;
  readonly selectedPacketDetail: Packet | null;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly loadPacket: (packetId: number, signal: AbortSignal) => Promise<Packet>;
  readonly loadRawHex: (packetId: number, signal: AbortSignal) => Promise<string>;
  readonly loadLayers: (packetId: number, signal: AbortSignal) => Promise<Record<string, unknown> | null>;
  readonly setSelectedPacketDetail: Dispatch<SetStateAction<Packet | null>>;
  readonly setSelectedPacketRawHex: Dispatch<SetStateAction<string>>;
  readonly setSelectedPacketLayers: Dispatch<SetStateAction<Record<string, unknown> | null>>;
}

export function useSelectedPacketResources({
  selectedPacketId,
  selectedPacket,
  selectedPacketDetail,
  captureTaskScopeRef,
  loadPacket,
  loadRawHex,
  loadLayers,
  setSelectedPacketDetail,
  setSelectedPacketRawHex,
  setSelectedPacketLayers,
}: UseSelectedPacketResourcesOptions) {
  useSelectedPacketDetail({
    selectedPacketId,
    shouldLoad: shouldLoadSelectedPacketDetail(selectedPacketId, selectedPacketDetail),
    captureTaskScopeRef,
    loadPacket,
    setSelectedPacketDetail,
  });

  const shouldLoadArtifacts = shouldLoadSelectedPacketArtifacts(selectedPacketId, selectedPacket);
  useSelectedPacketArtifact<string>({
    selectedPacketId,
    selectedPacket,
    shouldLoad: shouldLoadArtifacts,
    taskKey: "packet-raw-hex",
    captureTaskScopeRef,
    loadArtifact: loadRawHex,
    setValue: setSelectedPacketRawHex,
    resetValue: "",
  });
  useSelectedPacketArtifact<Record<string, unknown> | null>({
    selectedPacketId,
    selectedPacket,
    shouldLoad: shouldLoadArtifacts,
    taskKey: "packet-layers",
    captureTaskScopeRef,
    loadArtifact: loadLayers,
    setValue: setSelectedPacketLayers,
    resetValue: null,
  });
}
