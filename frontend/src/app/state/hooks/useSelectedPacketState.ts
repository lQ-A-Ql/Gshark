import { useState, type MutableRefObject } from "react";
import type { Packet } from "../../core/types";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";
import { useSelectedPacketAction } from "./useSelectedPacketAction";
import { useSelectedPacketResources } from "./useSelectedPacketResources";
import { useSentinelDerivedView } from "./useSentinelDerivedView";

interface UseSelectedPacketStateOptions {
  readonly packets: Packet[];
  readonly pageStart: number;
  readonly totalPackets: number;
  readonly pageSize: number;
  readonly captureTaskScopeRef: MutableRefObject<CaptureTaskScope>;
  readonly loadPacket: (packetId: number, signal: AbortSignal) => Promise<Packet>;
  readonly loadRawHex: (packetId: number, signal: AbortSignal) => Promise<string>;
  readonly loadLayers: (packetId: number, signal: AbortSignal) => Promise<Record<string, unknown> | null>;
}

export function useSelectedPacketState({
  packets,
  pageStart,
  totalPackets,
  pageSize,
  captureTaskScopeRef,
  loadPacket,
  loadRawHex,
  loadLayers,
}: UseSelectedPacketStateOptions) {
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [selectedPacketDetail, setSelectedPacketDetail] = useState<Packet | null>(null);
  const [selectedPacketRawHex, setSelectedPacketRawHex] = useState("");
  const [selectedPacketLayers, setSelectedPacketLayers] = useState<Record<string, unknown> | null>(null);

  const derivedView = useSentinelDerivedView({
    packets,
    selectedPacketId,
    selectedPacketDetail,
    selectedPacketLayers,
    pageStart,
    totalPackets,
    pageSize,
  });

  useSelectedPacketResources({
    selectedPacketId,
    selectedPacket: derivedView.selectedPacket,
    selectedPacketDetail,
    captureTaskScopeRef,
    loadPacket,
    loadRawHex,
    loadLayers,
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
  });

  const selectPacket = useSelectedPacketAction({
    setSelectedPacketId,
    setSelectedPacketDetail,
  });

  return {
    ...derivedView,
    selectedPacketId,
    selectedPacketRawHex,
    selectPacket,
    setSelectedPacketId,
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
  };
}
